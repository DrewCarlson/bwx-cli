use crate::common::{register_user, BwxHarness};
use crate::skip_if_no_vaultwarden;

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn exec_injects_password_field() {
    let server = skip_if_no_vaultwarden!();

    let email = "exec@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register user");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();

    // Two distinct entries so we can verify multi-binding.
    let out =
        harness.run_with_stdin(&["add", "db.example"], b"db-secret\n\n\n");
    assert!(
        out.status.success(),
        "add db.example failed: stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );
    let out = harness.run_with_stdin(
        &["add", "api.example", "alice"],
        b"api-secret\n\n\n",
    );
    assert!(
        out.status.success(),
        "add api.example failed: stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );

    // Default field is `password`; explicit `#username` resolves a
    // different field on the same / another entry.
    let printed = harness.check(&[
        "exec",
        "--env",
        "DB_PW=db.example",
        "--env",
        "API_USER=api.example#username",
        "--env",
        "API_PW=api.example#password",
        "--",
        "/bin/sh",
        "-c",
        "printf 'DB=%s\\nAPI_USER=%s\\nAPI_PW=%s\\n' \"$DB_PW\" \"$API_USER\" \"$API_PW\"",
    ]);

    assert!(
        printed.contains("DB=db-secret"),
        "missing DB_PW; got:\n{printed}"
    );
    assert!(
        printed.contains("API_USER=alice"),
        "missing API_USER; got:\n{printed}"
    );
    assert!(
        printed.contains("API_PW=api-secret"),
        "missing API_PW; got:\n{printed}"
    );
}

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn exec_propagates_child_exit_code() {
    let server = skip_if_no_vaultwarden!();

    let email = "exec-exit@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register user");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();

    let out = harness.run_with_stdin(&["add", "exit.example"], b"pw\n\n\n");
    assert!(out.status.success());

    let res = harness.run(&[
        "exec",
        "--env",
        "FOO=exit.example",
        "--",
        "/bin/sh",
        "-c",
        "exit 42",
    ]);
    assert_eq!(
        res.status.code(),
        Some(42),
        "expected exit 42; stderr={}",
        String::from_utf8_lossy(&res.stderr),
    );
}

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn exec_errors_when_entry_missing() {
    let server = skip_if_no_vaultwarden!();

    let email = "exec-missing@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register user");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();

    let res = harness.run(&[
        "exec",
        "--env",
        "FOO=does-not-exist",
        "--",
        "/bin/true",
    ]);
    assert!(!res.status.success(), "expected non-zero exit");
    let err = String::from_utf8_lossy(&res.stderr);
    assert!(
        err.contains("does-not-exist") || err.contains("no entry found"),
        "stderr should mention missing entry; got:\n{err}",
    );
}

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn exec_does_not_leak_value_when_unbound_var_referenced() {
    // Sanity check: a variable that isn't bound by --env stays unset in
    // the child even if a similarly-named vault entry exists.
    let server = skip_if_no_vaultwarden!();

    let email = "exec-unbound@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register user");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();

    let out = harness
        .run_with_stdin(&["add", "secret.example"], b"top-secret\n\n\n");
    assert!(out.status.success());

    let printed = harness.check(&[
        "exec",
        "--env",
        "BOUND=secret.example",
        "--",
        "/bin/sh",
        "-c",
        "printf 'unbound=[%s]\\n' \"${UNBOUND-}\"",
    ]);
    assert!(
        printed.contains("unbound=[]"),
        "UNBOUND should be empty; got:\n{printed}"
    );
    assert!(
        !printed.contains("top-secret"),
        "secret leaked into output:\n{printed}"
    );
}

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn exec_rejects_duplicate_var_bindings() {
    let server = skip_if_no_vaultwarden!();

    let email = "exec-dup@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register user");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();

    let out = harness.run_with_stdin(&["add", "a.example"], b"a\n\n\n");
    assert!(out.status.success());
    let out = harness.run_with_stdin(&["add", "b.example"], b"b\n\n\n");
    assert!(out.status.success());

    let res = harness.run(&[
        "exec",
        "--env",
        "X=a.example",
        "--env",
        "X=b.example",
        "--",
        "/bin/true",
    ]);
    assert!(!res.status.success(), "expected non-zero exit");
    let err = String::from_utf8_lossy(&res.stderr);
    assert!(
        err.contains("duplicate"),
        "stderr should mention duplicate; got:\n{err}",
    );
}
