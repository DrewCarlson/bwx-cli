use crate::bin_error;

pub fn setup_macos(force: bool) -> bin_error::Result<()> {
    do_setup_macos(force)
}

pub fn teardown_macos() -> bin_error::Result<()> {
    do_teardown_macos()
}

const LAUNCHAGENT_LABEL: &str = "drews.website.bwx.ssh-auth-sock";
const AGENT_LAUNCHAGENT_LABEL: &str = "drews.website.bwx.agent";

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
         # Managed by `bwx setup-macos`. Edit the bwx binary path if \
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
        println!("nothing to remove — `bwx setup-macos` wasn't active");
    } else {
        println!("removed:");
        for p in removed {
            println!("  {p}");
        }
    }
    Ok(())
}
