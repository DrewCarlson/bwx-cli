//! `bwx config set` must reject values its key-specific parser can't handle
//! rather than silently coercing them. Covers `biometric_gate` and
//! `ssh_confirm_sign`.

use crate::common::{register_user, BwxHarness};
use crate::skip_if_no_vaultwarden;

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn bad_biometric_gate_and_bool_rejected() {
    let server = skip_if_no_vaultwarden!();
    let email = "bad-config@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register user");

    let harness = BwxHarness::new(&server, email, password);

    // --- unknown `biometric_gate` value ---
    let out = harness.run(&["config", "set", "biometric_gate", "maybe"]);
    assert!(
        !out.status.success(),
        "bad biometric_gate accepted; stdout={}",
        String::from_utf8_lossy(&out.stdout),
    );
    let gate_after = harness.check(&["config", "show", "biometric_gate"]);
    assert_eq!(gate_after.trim(), "off");

    // --- non-bool `ssh_confirm_sign` ---
    let out =
        harness.run(&["config", "set", "ssh_confirm_sign", "yes-please"]);
    assert!(
        !out.status.success(),
        "bad ssh_confirm_sign accepted; stdout={}",
        String::from_utf8_lossy(&out.stdout),
    );
    let cfg_show = harness.check(&["config", "show"]);
    assert!(
        !cfg_show.contains("yes-please"),
        "bogus ssh_confirm_sign value leaked into config:\n{cfg_show}"
    );

    // --- unknown key ---
    let out = harness.run(&["config", "set", "no_such_key", "anything"]);
    assert!(
        !out.status.success(),
        "unknown config key accepted; stdout={}",
        String::from_utf8_lossy(&out.stdout),
    );
}
