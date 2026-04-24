use std::process::Command;

use crate::common::{register_user, RbwHarness};
use crate::skip_if_no_vaultwarden;

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn rbw_profile_isolates_state() {
    let server = skip_if_no_vaultwarden!();

    let email = "iso@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register user");

    let harness = RbwHarness::new(&server, email, password);

    // Populate the default profile.
    harness.login_and_unlock();
    harness
        .run_with_stdin(&["add", "profile.a.entry"], b"pw\n\n\n")
        .status
        .success()
        .then_some(())
        .expect("add in default profile failed");

    // A command run under `RBW_PROFILE=other` sees a fresh, empty data dir.
    // It won't even know which server to talk to — `rbw config show` is the
    // safest probe because it doesn't require the agent.
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rbw"));
    cmd.env("RBW_PROFILE", "other")
        .env("XDG_CONFIG_HOME", &harness.config_home)
        .env("XDG_CACHE_HOME", &harness.cache_home)
        .env("XDG_DATA_HOME", &harness.data_home)
        .env("XDG_RUNTIME_DIR", &harness.runtime_dir)
        .env("HOME", &harness.home)
        .env("RBW_AGENT", env!("CARGO_BIN_EXE_rbw-agent"))
        .arg("config")
        .arg("show");
    let out = cmd.output().expect("spawn rbw under RBW_PROFILE=other");

    // The alternate profile's config should not contain the default
    // profile's email, proving state didn't bleed across.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains(email),
        "alt profile leaked default-profile config; got:\n{stdout}"
    );
}
