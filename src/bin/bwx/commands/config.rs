use super::auth::stop_agent;
use super::util::print_opt;
use crate::bin_error::{self, ContextExt as _};

pub fn config_show(key: Option<&str>) -> bin_error::Result<()> {
    let config = bwx::config::Config::load()?;

    let Some(key) = key else {
        serde_json::to_writer_pretty(std::io::stdout(), &config)
            .context("failed to write config to stdout")?;
        println!();
        return Ok(());
    };

    match key {
        "email" => print_opt(config.email.as_deref()),
        "sso_id" => print_opt(config.sso_id.as_deref()),
        "base_url" => print_opt(config.base_url.as_deref()),
        "identity_url" => print_opt(config.identity_url.as_deref()),
        "ui_url" => print_opt(config.ui_url.as_deref()),
        "notifications_url" => print_opt(config.notifications_url.as_deref()),
        "client_cert_path" => print_opt(
            config.client_cert_path.as_deref().and_then(|p| p.to_str()),
        ),
        "lock_timeout" => println!("{}", config.lock_timeout),
        "sync_interval" => println!("{}", config.sync_interval),
        "pinentry" => println!("{}", config.pinentry),
        "ssh_confirm_sign" => println!("{}", config.ssh_confirm_sign),
        "macos_unlock_dialog" => println!("{}", config.macos_unlock_dialog),
        "touchid_gate" => println!("{}", config.touchid_gate),
        other => {
            return Err(crate::bin_error::err!(
                "invalid config key: {other}"
            ));
        }
    }
    Ok(())
}

pub fn config_set(key: &str, value: &str) -> bin_error::Result<()> {
    let mut config = bwx::config::Config::load()
        .unwrap_or_else(|_| bwx::config::Config::new());
    match key {
        "email" => config.email = Some(value.to_string()),
        "sso_id" => config.sso_id = Some(value.to_string()),
        "base_url" => config.base_url = Some(value.to_string()),
        "identity_url" => config.identity_url = Some(value.to_string()),
        "ui_url" => config.ui_url = Some(value.to_string()),
        "notifications_url" => {
            config.notifications_url = Some(value.to_string());
        }
        "client_cert_path" => {
            config.client_cert_path =
                Some(std::path::PathBuf::from(value.to_string()));
        }
        "lock_timeout" => {
            let timeout = value
                .parse()
                .context("failed to parse value for lock_timeout")?;
            if timeout == 0 {
                log::error!("lock_timeout must be greater than 0");
            } else {
                config.lock_timeout = timeout;
            }
        }
        "sync_interval" => {
            let interval = value
                .parse()
                .context("failed to parse value for sync_interval")?;
            config.sync_interval = interval;
        }
        "pinentry" => config.pinentry = value.to_string(),
        "ssh_confirm_sign" => {
            config.ssh_confirm_sign = value
                .parse()
                .context("ssh_confirm_sign must be 'true' or 'false'")?;
        }
        "macos_unlock_dialog" => {
            config.macos_unlock_dialog = value
                .parse()
                .context("macos_unlock_dialog must be 'true' or 'false'")?;
        }
        "touchid_gate" => {
            let gate: bwx::touchid::Gate =
                value.parse().map_err(crate::bin_error::Error::msg)?;
            #[cfg(not(target_os = "macos"))]
            if !matches!(gate, bwx::touchid::Gate::Off) {
                return Err(crate::bin_error::Error::msg(
                    "touchid_gate is only supported on macOS; the only \
                     accepted value on this platform is 'off'",
                ));
            }
            config.touchid_gate = gate;
        }
        _ => return Err(crate::bin_error::err!("invalid config key: {key}")),
    }
    config.save()?;

    // drop in-memory keys, since they will be different if the email or url
    // changed. not using lock() because we don't want to require the agent to
    // be running (since this may be the user running `bwx config set
    // base_url` as the first operation), and stop_agent() already handles the
    // agent not running case gracefully.
    stop_agent()?;

    Ok(())
}

pub fn config_unset(key: &str) -> bin_error::Result<()> {
    let mut config = bwx::config::Config::load()
        .unwrap_or_else(|_| bwx::config::Config::new());
    match key {
        "email" => config.email = None,
        "sso_id" => config.sso_id = None,
        "base_url" => config.base_url = None,
        "identity_url" => config.identity_url = None,
        "ui_url" => config.ui_url = None,
        "notifications_url" => config.notifications_url = None,
        "client_cert_path" => config.client_cert_path = None,
        "lock_timeout" => {
            config.lock_timeout = bwx::config::default_lock_timeout();
        }
        "pinentry" => config.pinentry = bwx::config::default_pinentry(),
        "ssh_confirm_sign" => config.ssh_confirm_sign = false,
        "macos_unlock_dialog" => {
            config.macos_unlock_dialog =
                bwx::config::default_macos_unlock_dialog();
        }
        "touchid_gate" => config.touchid_gate = bwx::touchid::Gate::Off,
        _ => return Err(crate::bin_error::err!("invalid config key: {key}")),
    }
    config.save()?;

    // drop in-memory keys, since they will be different if the email or url
    // changed. not using lock() because we don't want to require the agent to
    // be running (since this may be the user running `bwx config set
    // base_url` as the first operation), and stop_agent() already handles the
    // agent not running case gracefully.
    stop_agent()?;

    Ok(())
}
