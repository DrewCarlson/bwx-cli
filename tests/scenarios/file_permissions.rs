//! Verifies that rbw writes its on-disk state with tight Unix modes.
//! Regression test for `SECURITY_AUDIT.md` items M1/M2 — those fixes are
//! easy to undo accidentally (e.g. swapping `OpenOptions` back to
//! `File::create`) and the mode bits are invisible outside of `ls -l`.

use crate::common::{register_user, RbwHarness};
use crate::skip_if_no_vaultwarden;

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn sensitive_files_and_dirs_have_tight_modes() {
    use std::os::unix::fs::PermissionsExt as _;

    let server = skip_if_no_vaultwarden!();
    let email = "perms@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register user");

    let harness = RbwHarness::new(&server, email, password);
    harness.login_and_unlock();
    // Put something in the vault so db.json exists on disk.
    harness.run_with_stdin(&["add", "perms.example"], b"pw\n\n\n");
    harness.check(&["sync"]);

    // Resolve rbw's on-disk roots from the harness env. The harness
    // points `XDG_CONFIG_HOME` / `XDG_DATA_HOME` at tempdir children
    // on Linux; macOS rbw ignores XDG and uses `$HOME/Library/...`
    // regardless.
    let env: std::collections::HashMap<_, _> = harness
        .cmd()
        .get_envs()
        .filter_map(|(k, v)| Some((k.to_os_string(), v?.to_os_string())))
        .collect();
    let get = |k: &str| -> std::path::PathBuf {
        let v = env
            .get(std::ffi::OsStr::new(k))
            .unwrap_or_else(|| panic!("{k} not set on harness env"));
        std::path::PathBuf::from(v)
    };
    let cfg_abs = if cfg!(target_os = "macos") {
        get("HOME").join("Library/Application Support/rbw")
    } else {
        get("XDG_CONFIG_HOME").join("rbw")
    };
    let data_abs = if cfg!(target_os = "macos") {
        get("HOME").join("Library/Application Support/rbw")
    } else {
        get("XDG_DATA_HOME").join("rbw")
    };

    let check_mode = |path: &std::path::Path, expected: u32| {
        let meta = std::fs::metadata(path)
            .unwrap_or_else(|e| panic!("stat {}: {e}", path.display()));
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode,
            expected,
            "unexpected mode on {}: got 0o{mode:o}, want 0o{expected:o}",
            path.display()
        );
    };

    // Sensitive files must be 0o600 regardless of caller umask.
    check_mode(&cfg_abs.join("config.json"), 0o600);
    // db.json filename is `db_<server-slug>_<email>.json`; find via
    // directory listing so we don't have to reconstruct the slug.
    let db_file = std::fs::read_dir(&data_abs)
        .expect("read data_dir")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            name.starts_with("db_")
                && p.extension().and_then(|e| e.to_str()) == Some("json")
        })
        .expect("expected a db_*.json file after sync");
    check_mode(&db_file, 0o600);

    // Enclosing dirs should be 0o700. rbw::dirs::make_all() creates
    // these during startup.
    check_mode(&cfg_abs, 0o700);
    check_mode(&data_abs, 0o700);
}
