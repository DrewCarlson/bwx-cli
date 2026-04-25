use crate::common::{register_user, BwxHarness};
use crate::skip_if_no_vaultwarden;

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn lock_then_unlock_again() {
    let server = skip_if_no_vaultwarden!();

    let email = "lock@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register user");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();

    let out =
        harness.run_with_stdin(&["add", "before.lock"], b"pre-lock-pw\n\n\n");
    assert!(out.status.success(), "pre-lock add failed");

    assert!(harness.run(&["unlocked"]).status.success());

    // Lock seals the vault but the agent keeps running.
    assert!(harness.run(&["lock"]).status.success(), "lock failed");

    let u = harness.run(&["unlocked"]);
    assert!(
        !u.status.success(),
        "unlocked returned 0 after lock; stderr={}",
        String::from_utf8_lossy(&u.stderr),
    );

    harness.check(&["unlock"]);
    assert_eq!(
        harness.check(&["get", "before.lock"]).trim_end(),
        "pre-lock-pw"
    );
}
