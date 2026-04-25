//! `bwx get <uuid>` resolves by UUID; `list --fields id,name` exposes them.

use crate::common::{register_user, BwxHarness};
use crate::skip_if_no_vaultwarden;

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn get_by_uuid_matches_get_by_name() {
    let server = skip_if_no_vaultwarden!();
    let email = "uuid@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register user");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();

    harness.run_with_stdin(&["add", "uuid.target"], b"uuid-pw\n\n\n");

    // `list --fields id,name` produces `<uuid>\t<name>` lines.
    let listing = harness.check(&["list", "--fields", "id,name"]);
    let uuid = listing
        .lines()
        .find_map(|l| {
            let (id, name) = l.split_once('\t')?;
            (name.trim() == "uuid.target").then(|| id.trim().to_string())
        })
        .unwrap_or_else(|| {
            panic!("uuid for 'uuid.target' not in listing:\n{listing}")
        });
    assert_eq!(uuid.len(), 36, "expected a canonical UUID, got {uuid:?}");

    let by_name = harness.check(&["get", "uuid.target"]);
    let by_uuid = harness.check(&["get", &uuid]);
    assert_eq!(
        by_name.trim_end(),
        by_uuid.trim_end(),
        "password mismatch between name-lookup and uuid-lookup"
    );
    assert_eq!(by_name.trim_end(), "uuid-pw");
}
