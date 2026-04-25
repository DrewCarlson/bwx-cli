//! Large-payload roundtrip: a notes body crossing many AES blocks and the
//! 4 KiB `locked::FixedVec` boundary, to catch truncation in the encrypt /
//! IPC / decrypt path.

use std::fmt::Write as _;

use crate::common::{register_user, BwxHarness};
use crate::skip_if_no_vaultwarden;

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn large_notes_survive_roundtrip() {
    let server = skip_if_no_vaultwarden!();
    let email = "longnotes@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register user");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();

    // Vaultwarden's 10 000-char `notes` cap applies to the *encrypted*
    // stored value (base64 ciphertext+envelope ≈ 1.37× plaintext + ~80 B).
    // Aim for ~5 KiB plaintext to cross the 4 KiB FixedVec boundary while
    // staying under the server cap. A truncation bug surfaces as a missing
    // `line 0099:` tail.
    let mut notes = String::new();
    for i in 0..100 {
        writeln!(notes, "line {i:04}: abcdefghijklmnopqrstuvwxyz0123456789")
            .unwrap();
    }
    let ciphertext_budget = (notes.len() * 4 / 3) + 80;
    assert!(
        notes.len() > 4 * 1024 && ciphertext_budget < 10_000,
        "test needs >4 KiB plaintext and <10 KiB ciphertext (vaultwarden \
         cap); plaintext={}, ~ciphertext={ciphertext_budget}",
        notes.len()
    );

    let mut stdin = Vec::new();
    stdin.extend_from_slice(b"pw-longnotes\n\n");
    stdin.extend_from_slice(notes.as_bytes());

    let out = harness.run_with_stdin(&["add", "longnotes.example"], &stdin);
    assert!(
        out.status.success(),
        "bwx add failed: stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );

    let full = harness.check(&["get", "--full", "longnotes.example"]);
    assert!(
        full.contains("line 0000:"),
        "first notes line missing; got {} bytes",
        full.len()
    );
    assert!(
        full.contains("line 0099:"),
        "last notes line missing; got {} bytes (truncation somewhere?)",
        full.len()
    );
}
