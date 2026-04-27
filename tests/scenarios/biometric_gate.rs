//! Exercise the biometric gate. In debug builds `bwx::biometric` honours
//! `BWX_BIOMETRIC_TEST_BYPASS=allow|deny` and skips the real `LAContext` FFI,
//! letting CI assert gate semantics without Touch ID hardware. macOS only.

#![cfg(target_os = "macos")]

use crate::common::{register_user, BwxHarness};
use crate::skip_if_no_vaultwarden;

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn gate_off_skips_biometric() {
    let server = skip_if_no_vaultwarden!();
    let email = "tid_off@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();

    harness
        .run_with_stdin(&["add", "e1"], b"pw\n\n\n")
        .status
        .success()
        .then_some(())
        .expect("add");

    // gate=off: even bypass=deny must let `get` through, proving the gate
    // path wasn't consulted.
    let out = harness
        .cmd()
        .env("BWX_BIOMETRIC_TEST_BYPASS", "deny")
        .args(["get", "e1"])
        .output()
        .expect("spawn");
    assert!(
        out.status.success(),
        "get failed with gate=off: stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim_end(), "pw");
}

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn gate_all_bypass_allow_succeeds() {
    let server = skip_if_no_vaultwarden!();
    let email = "tid_allow@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();
    harness
        .run_with_stdin(&["add", "e1"], b"pw\n\n\n")
        .status
        .success()
        .then_some(())
        .expect("add");

    // The bypass env must reach the *agent* (where the gate runs); the
    // CLI inherits the env and respawns the agent on next invocation.
    harness.check(&["config", "set", "biometric_gate", "all"]);

    let out = harness
        .cmd()
        .env("BWX_BIOMETRIC_TEST_BYPASS", "allow")
        .args(["get", "e1"])
        .output()
        .expect("spawn");
    assert!(
        out.status.success(),
        "bypass=allow rejected get: stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim_end(), "pw");
}

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn gate_all_bypass_deny_blocks() {
    let server = skip_if_no_vaultwarden!();
    let email = "tid_deny@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();
    harness
        .run_with_stdin(&["add", "e1"], b"pw\n\n\n")
        .status
        .success()
        .then_some(())
        .expect("add");
    harness.check(&["config", "set", "biometric_gate", "all"]);

    let out = harness
        .cmd()
        .env("BWX_BIOMETRIC_TEST_BYPASS", "deny")
        .args(["get", "e1"])
        .output()
        .expect("spawn");
    assert!(
        !out.status.success(),
        "bypass=deny unexpectedly allowed get"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("denied") || stderr.contains("Touch ID"),
        "expected a denial error message, got:\n{stderr}"
    );
}

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn gate_signing_spares_vault_reads() {
    let server = skip_if_no_vaultwarden!();
    let email = "tid_sign@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();
    harness
        .run_with_stdin(&["add", "e1"], b"pw\n\n\n")
        .status
        .success()
        .then_some(())
        .expect("add");
    harness.check(&["config", "set", "biometric_gate", "signing"]);

    // gate=signing excludes VaultSecret from the gate; bypass=deny must
    // still let `get` succeed.
    let out = harness
        .cmd()
        .env("BWX_BIOMETRIC_TEST_BYPASS", "deny")
        .args(["get", "e1"])
        .output()
        .expect("spawn");
    assert!(
        out.status.success(),
        "gate=signing blocked a vault read: stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );
}
