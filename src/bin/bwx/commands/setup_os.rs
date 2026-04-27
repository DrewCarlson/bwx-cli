use crate::bin_error;

#[cfg(target_os = "macos")]
pub fn setup_os(force: bool) -> bin_error::Result<()> {
    do_setup_macos(force)
}

#[cfg(target_os = "macos")]
pub fn teardown_os() -> bin_error::Result<()> {
    do_teardown_macos()
}

#[cfg(target_os = "windows")]
pub fn setup_os(force: bool) -> bin_error::Result<()> {
    do_setup_windows(force)
}

#[cfg(target_os = "windows")]
pub fn teardown_os() -> bin_error::Result<()> {
    do_teardown_windows()
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn setup_os(_force: bool) -> bin_error::Result<()> {
    println!(
        "per-platform setup is not implemented for {} yet",
        std::env::consts::OS
    );
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn teardown_os() -> bin_error::Result<()> {
    println!(
        "per-platform teardown is not implemented for {} yet",
        std::env::consts::OS
    );
    Ok(())
}

#[cfg(target_os = "macos")]
const LAUNCHAGENT_LABEL: &str = "drews.website.bwx.ssh-auth-sock";
#[cfg(target_os = "macos")]
const AGENT_LAUNCHAGENT_LABEL: &str = "drews.website.bwx.agent";

#[cfg(target_os = "macos")]
fn do_setup_macos(force: bool) -> bin_error::Result<()> {
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .ok_or_else(|| bin_error::Error::msg("$HOME not set"))?;
    let bwx_bin = std::env::current_exe()
        .map_err(|e| bin_error::Error::msg(format!("current_exe: {e}")))?;
    let helper_dir = home.join("bin");
    let helper = helper_dir.join("bwx-set-ssh-sock");
    let launch_agents = home.join("Library/LaunchAgents");
    let plist = launch_agents.join(format!("{LAUNCHAGENT_LABEL}.plist"));
    let agent_plist =
        launch_agents.join(format!("{AGENT_LAUNCHAGENT_LABEL}.plist"));
    // `bwx-agent` binary lives next to `bwx` in the same install dir.
    let agent_bin = bwx_bin
        .parent()
        .map(|d| d.join("bwx-agent"))
        .ok_or_else(|| {
            bin_error::Error::msg("couldn't resolve bwx-agent path")
        })?;

    if (helper.exists() || plist.exists() || agent_plist.exists()) && !force {
        return Err(bin_error::Error::msg(format!(
            "setup already exists ({} / {} / {}); pass --force to overwrite",
            helper.display(),
            plist.display(),
            agent_plist.display(),
        )));
    }

    std::fs::create_dir_all(&helper_dir).map_err(|e| {
        bin_error::Error::msg(format!("mkdir {}: {e}", helper_dir.display()))
    })?;
    std::fs::create_dir_all(&launch_agents).map_err(|e| {
        bin_error::Error::msg(format!(
            "mkdir {}: {e}",
            launch_agents.display()
        ))
    })?;

    let helper_body = format!(
        "#!/bin/sh\n\
         # Managed by `bwx setup-os`. Edit the bwx binary path if \
         you move it.\n\
         exec /bin/launchctl setenv SSH_AUTH_SOCK \"$({bwx} ssh-socket)\"\n",
        bwx = bwx_bin.display(),
    );
    std::fs::write(&helper, helper_body).map_err(|e| {
        bin_error::Error::msg(format!("write {}: {e}", helper.display()))
    })?;
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut perms = std::fs::metadata(&helper)
            .map_err(|e| bin_error::Error::msg(e.to_string()))?
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&helper, perms)
            .map_err(|e| bin_error::Error::msg(e.to_string()))?;
    }

    let plist_body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\"\n  \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n  \
         <key>Label</key><string>{LAUNCHAGENT_LABEL}</string>\n  \
         <key>RunAtLoad</key><true/>\n  \
         <key>ProgramArguments</key>\n  \
         <array>\n    \
         <string>{helper}</string>\n  \
         </array>\n\
         </dict>\n\
         </plist>\n",
        helper = helper.display(),
    );
    std::fs::write(&plist, plist_body).map_err(|e| {
        bin_error::Error::msg(format!("write {}: {e}", plist.display()))
    })?;

    // Second LaunchAgent: keep bwx-agent running so SSH_AUTH_SOCK points
    // at a live socket at all times. launchd respawns it if it crashes
    // or exits after lock_timeout. Route stdio to files under the data
    // dir so a crash-on-boot is debuggable without digging through
    // `log show`.
    let data_dir = bwx::dirs::agent_stdout_file().parent().map_or_else(
        || home.join(".cache/bwx"),
        std::path::Path::to_path_buf,
    );
    std::fs::create_dir_all(&data_dir).ok();
    let agent_stdout = data_dir.join("launchd-agent.out");
    let agent_stderr = data_dir.join("launchd-agent.err");
    let agent_plist_body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\"\n  \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n  \
         <key>Label</key><string>{AGENT_LAUNCHAGENT_LABEL}</string>\n  \
         <key>RunAtLoad</key><true/>\n  \
         <key>KeepAlive</key><true/>\n  \
         <key>StandardOutPath</key><string>{stdout}</string>\n  \
         <key>StandardErrorPath</key><string>{stderr}</string>\n  \
         <key>ProgramArguments</key>\n  \
         <array>\n    \
         <string>{agent}</string>\n    \
         <string>--no-daemonize</string>\n  \
         </array>\n\
         </dict>\n\
         </plist>\n",
        agent = agent_bin.display(),
        stdout = agent_stdout.display(),
        stderr = agent_stderr.display(),
    );
    std::fs::write(&agent_plist, agent_plist_body).map_err(|e| {
        bin_error::Error::msg(format!("write {}: {e}", agent_plist.display()))
    })?;

    let uid = rustix::process::getuid().as_raw();
    // Unload any stale copies. On first-time install nothing is loaded,
    // so bootout exits non-zero with "Boot-out failed: No such process";
    // expected, squelch.
    for label in [LAUNCHAGENT_LABEL, AGENT_LAUNCHAGENT_LABEL] {
        let _ = std::process::Command::new("/bin/launchctl")
            .args(["bootout", &format!("gui/{uid}/{label}")])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
    for pl in [&plist, &agent_plist] {
        let status = std::process::Command::new("/bin/launchctl")
            .args(["bootstrap", &format!("gui/{uid}"), &pl.to_string_lossy()])
            .status()
            .map_err(|e| {
                bin_error::Error::msg(format!("launchctl bootstrap: {e}"))
            })?;
        if !status.success() {
            return Err(bin_error::Error::msg(format!(
                "launchctl bootstrap {} exited {status}",
                pl.display()
            )));
        }
    }

    // Also set for the current session so the user doesn't have to log
    // out. Invoke `bwx ssh-socket` via current_exe to avoid depending on
    // PATH.
    let socket = std::process::Command::new(&bwx_bin)
        .arg("ssh-socket")
        .output()
        .map_err(|e| bin_error::Error::msg(format!("bwx ssh-socket: {e}")))?;
    let socket = String::from_utf8_lossy(&socket.stdout).trim().to_string();
    let _ = std::process::Command::new("/bin/launchctl")
        .args(["setenv", "SSH_AUTH_SOCK", &socket])
        .status();

    println!("Installed LaunchAgents:");
    println!("  {} (sets SSH_AUTH_SOCK)", plist.display());
    println!("  {} (keeps bwx-agent running)", agent_plist.display());
    println!("Helper script:         {}", helper.display());
    println!("SSH_AUTH_SOCK:         {socket}");
    println!();
    println!(
        "GUI apps that were already running won't pick this up until \
         they are fully quit (Cmd-Q) and relaunched. Terminal sessions \
         started after this point will see SSH_AUTH_SOCK automatically."
    );
    println!("Append to your bashrc/zshrc:\n\n export SSH_AUTH_SOCK=\"$(bwx ssh-socket)\"");
    Ok(())
}

#[cfg(target_os = "macos")]
fn do_teardown_macos() -> bin_error::Result<()> {
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .ok_or_else(|| bin_error::Error::msg("$HOME not set"))?;
    let helper = home.join("bin/bwx-set-ssh-sock");
    let plist =
        home.join(format!("Library/LaunchAgents/{LAUNCHAGENT_LABEL}.plist"));
    let agent_plist = home.join(format!(
        "Library/LaunchAgents/{AGENT_LAUNCHAGENT_LABEL}.plist"
    ));
    let uid = rustix::process::getuid().as_raw();

    // Best-effort unload. bootout returns non-zero when nothing is
    // loaded; squelch the "No such process" stderr.
    for label in [LAUNCHAGENT_LABEL, AGENT_LAUNCHAGENT_LABEL] {
        let _ = std::process::Command::new("/bin/launchctl")
            .args(["bootout", &format!("gui/{uid}/{label}")])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
    let _ = std::process::Command::new("/bin/launchctl")
        .args(["unsetenv", "SSH_AUTH_SOCK"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    let mut removed = Vec::new();
    for path in [&plist, &agent_plist, &helper] {
        match std::fs::remove_file(path) {
            Ok(()) => removed.push(path.display().to_string()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(bin_error::Error::msg(format!(
                    "remove {}: {e}",
                    path.display()
                )));
            }
        }
    }
    if removed.is_empty() {
        println!("nothing to remove — `bwx setup-os` wasn't active");
    } else {
        println!("removed:");
        for p in removed {
            println!("  {p}");
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
const WINDOWS_TASK_NAME: &str = "bwx-agent-autostart";

#[cfg(target_os = "windows")]
fn windows_ssh_pipe_name() -> String {
    match std::env::var("BWX_PROFILE") {
        Ok(p) if !p.is_empty() => {
            format!(r"\\.\pipe\openssh-ssh-agent-{p}")
        }
        _ => r"\\.\pipe\openssh-ssh-agent".to_string(),
    }
}

#[cfg(target_os = "windows")]
use bwx::win::wide::str_to_utf16_nul as to_utf16_nul;

#[cfg(target_os = "windows")]
fn do_setup_windows(_force: bool) -> bin_error::Result<()> {
    // `--force` is honored automatically: schtasks /F overwrites the
    // task, and the registry write is idempotent.
    let bwx_bin = std::env::current_exe()
        .map_err(|e| bin_error::Error::msg(format!("current_exe: {e}")))?;
    let agent_bin = bwx_bin
        .parent()
        .map(|d| d.join("bwx-agent.exe"))
        .ok_or_else(|| {
            bin_error::Error::msg("couldn't resolve bwx-agent.exe path")
        })?;

    let action = format!("{} --no-daemonize", agent_bin.display());
    let output = std::process::Command::new("schtasks.exe")
        .args([
            "/Create",
            "/TN",
            WINDOWS_TASK_NAME,
            "/SC",
            "ONLOGON",
            "/TR",
            &action,
            "/F",
            "/RL",
            "LIMITED",
        ])
        .output()
        .map_err(|e| bin_error::Error::msg(format!("schtasks.exe: {e}")))?;
    if !output.status.success() {
        return Err(bin_error::Error::msg(format!(
            "schtasks /Create exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    let pipe = windows_ssh_pipe_name();
    write_user_env_var("SSH_AUTH_SOCK", &pipe)?;
    broadcast_environment_change();

    println!("Registered Scheduled Task:");
    println!("  Name:   {WINDOWS_TASK_NAME}");
    println!("  Action: {action}");
    println!("Set user environment variable:");
    println!("  SSH_AUTH_SOCK={pipe}");
    println!();
    println!(
        "The Scheduled Task starts bwx-agent at next logon. For the \
         current session, run `bwx-agent` manually, or log out and back \
         in. Already-running processes won't see SSH_AUTH_SOCK until \
         they are restarted."
    );
    Ok(())
}

#[cfg(target_os = "windows")]
fn do_teardown_windows() -> bin_error::Result<()> {
    let mut removed: Vec<String> = Vec::new();

    let output = std::process::Command::new("schtasks.exe")
        .args(["/Delete", "/TN", WINDOWS_TASK_NAME, "/F"])
        .output()
        .map_err(|e| bin_error::Error::msg(format!("schtasks.exe: {e}")))?;
    if output.status.success() {
        removed.push(format!("Scheduled Task: {WINDOWS_TASK_NAME}"));
    } else {
        // Non-zero is expected when the task doesn't exist; surface
        // anything else to the user but don't abort teardown.
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("cannot find") && !stderr.contains("does not exist")
        {
            eprintln!("schtasks /Delete: {}", stderr.trim());
        }
    }

    match delete_user_env_var("SSH_AUTH_SOCK") {
        Ok(true) => removed.push("user env var: SSH_AUTH_SOCK".to_string()),
        Ok(false) => {}
        Err(e) => return Err(e),
    }
    broadcast_environment_change();

    if removed.is_empty() {
        println!("nothing to remove — `bwx setup-os` wasn't active");
    } else {
        println!("removed:");
        for p in removed {
            println!("  {p}");
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn write_user_env_var(name: &str, value: &str) -> bin_error::Result<()> {
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, GetLastError};
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE, REG_EXPAND_SZ, RegCloseKey,
        RegOpenKeyExW, RegSetValueExW,
    };

    let subkey = to_utf16_nul("Environment");
    let name_w = to_utf16_nul(name);
    let value_w: Vec<u16> = to_utf16_nul(value);

    let mut hkey: HKEY = std::ptr::null_mut();
    // SAFETY: subkey is a NUL-terminated UTF-16 string; hkey out-param.
    let rc = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            KEY_SET_VALUE,
            &mut hkey,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(bin_error::Error::msg(format!(
            "RegOpenKeyExW(Environment) failed: error {rc}"
        )));
    }

    let byte_len = value_w
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| bin_error::Error::msg("env var too long"))?;
    // SAFETY: hkey valid; name_w NUL-terminated; data points at byte_len bytes.
    let rc = unsafe {
        RegSetValueExW(
            hkey,
            name_w.as_ptr(),
            0,
            REG_EXPAND_SZ,
            value_w.as_ptr().cast::<u8>(),
            byte_len,
        )
    };
    // SAFETY: hkey opened above.
    unsafe { RegCloseKey(hkey) };
    if rc != ERROR_SUCCESS {
        // SAFETY: GetLastError reads thread-local error state.
        let code = unsafe { GetLastError() };
        return Err(bin_error::Error::msg(format!(
            "RegSetValueExW({name}) failed: error {rc} (last_error {code})"
        )));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn delete_user_env_var(name: &str) -> bin_error::Result<bool> {
    use windows_sys::Win32::Foundation::{
        ERROR_FILE_NOT_FOUND, ERROR_SUCCESS,
    };
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE, RegCloseKey, RegDeleteValueW,
        RegOpenKeyExW,
    };

    let subkey = to_utf16_nul("Environment");
    let name_w = to_utf16_nul(name);

    let mut hkey: HKEY = std::ptr::null_mut();
    // SAFETY: subkey is NUL-terminated UTF-16; hkey out-param.
    let rc = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            KEY_SET_VALUE,
            &mut hkey,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(bin_error::Error::msg(format!(
            "RegOpenKeyExW(Environment) failed: error {rc}"
        )));
    }
    // SAFETY: hkey valid; name_w NUL-terminated.
    let rc = unsafe { RegDeleteValueW(hkey, name_w.as_ptr()) };
    // SAFETY: hkey opened above.
    unsafe { RegCloseKey(hkey) };
    match rc {
        ERROR_SUCCESS => Ok(true),
        ERROR_FILE_NOT_FOUND => Ok(false),
        other => Err(bin_error::Error::msg(format!(
            "RegDeleteValueW({name}) failed: error {other}"
        ))),
    }
}

#[cfg(target_os = "windows")]
fn broadcast_environment_change() {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        HWND_BROADCAST, SMTO_ABORTIFHUNG, SendMessageTimeoutW, WM_SETTINGCHANGE,
    };

    let param = to_utf16_nul("Environment");
    let mut result: usize = 0;
    // SAFETY: HWND_BROADCAST + WM_SETTINGCHANGE; lParam is NUL-terminated UTF-16.
    unsafe {
        SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            param.as_ptr() as isize,
            SMTO_ABORTIFHUNG,
            5000,
            &mut result,
        );
    }
}
