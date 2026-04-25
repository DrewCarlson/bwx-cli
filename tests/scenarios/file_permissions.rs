//! Regression test for `SECURITY_AUDIT.md` items M1/M2: bwx must write its
//! on-disk state with tight Unix modes (config 0o600, dirs 0o700).

use crate::common::{register_user, BwxHarness};
use crate::skip_if_no_vaultwarden;

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn sensitive_files_and_dirs_have_tight_modes() {
    use std::os::unix::fs::PermissionsExt as _;

    let server = skip_if_no_vaultwarden!();
    let email = "perms@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register user");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();
    // Put something in the vault so the cache db file exists on disk.
    harness.run_with_stdin(&["add", "perms.example"], b"pw\n\n\n");
    harness.check(&["sync"]);

    // macOS bwx ignores XDG and uses `$HOME/Library/...`; Linux follows XDG.
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
        get("HOME").join("Library/Application Support/bwx")
    } else {
        get("XDG_CONFIG_HOME").join("bwx")
    };
    // db cache lives in `cache_dir`, not `data_dir`; filename is
    // `<server>:<email>.json`.
    let cache_abs = if cfg!(target_os = "macos") {
        get("HOME").join("Library/Caches/bwx")
    } else {
        get("XDG_CACHE_HOME").join("bwx")
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

    // Trigger a bwx-driven `Config::save()` so the assertion exercises bwx's
    // writer rather than the harness's pre-created config.json mode.
    harness.check(&["config", "set", "lock_timeout", "1800"]);

    check_mode(&cfg_abs.join("config.json"), 0o600);
    let db_file = std::fs::read_dir(&cache_abs)
        .unwrap_or_else(|e| panic!("read {}: {e}", cache_abs.display()))
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            p.extension().and_then(|e| e.to_str()) == Some("json")
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.contains(':'))
        })
        .unwrap_or_else(|| {
            panic!("expected a db cache file under {}", cache_abs.display())
        });
    check_mode(&db_file, 0o600);

    check_mode(&cfg_abs, 0o700);
    check_mode(&cache_abs, 0o700);
}
