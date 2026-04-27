use crate::prelude::*;

use std::io::{Read as _, Write as _};
use std::sync::{Arc, OnceLock};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

static CACHED: OnceLock<Arc<Config>> = OnceLock::new();

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Config {
    pub email: Option<String>,
    pub sso_id: Option<String>,
    pub base_url: Option<String>,
    pub identity_url: Option<String>,
    pub ui_url: Option<String>,
    pub notifications_url: Option<String>,
    #[serde(default = "default_lock_timeout")]
    pub lock_timeout: u64,
    #[serde(default = "default_sync_interval")]
    pub sync_interval: u64,
    #[serde(default = "default_pinentry")]
    pub pinentry: String,
    pub client_cert_path: Option<std::path::PathBuf>,
    #[serde(default)]
    pub ssh_confirm_sign: bool,
    /// On macOS, controls how the master-password prompt is shown at unlock
    /// time. Default `true` renders a native modal (works from daemonized
    /// contexts — ssh-sign, Finder-launched GUI git, etc.). Set `false` to
    /// fall back to pinentry. No effect on other platforms.
    #[serde(default = "default_macos_unlock_dialog")]
    pub macos_unlock_dialog: bool,
    #[serde(default = "default_logging")]
    pub logging: bool,
    #[serde(
        default,
        with = "biometric_gate_serde",
        skip_serializing_if = "is_biometric_gate_off"
    )]
    pub biometric_gate: crate::biometric::Gate,
    // backcompat, no longer generated in new configs
    #[serde(skip_serializing)]
    pub device_id: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            email: None,
            sso_id: None,
            base_url: None,
            identity_url: None,
            ui_url: None,
            notifications_url: None,
            lock_timeout: default_lock_timeout(),
            sync_interval: default_sync_interval(),
            pinentry: default_pinentry(),
            client_cert_path: None,
            ssh_confirm_sign: false,
            macos_unlock_dialog: default_macos_unlock_dialog(),
            logging: default_logging(),
            biometric_gate: crate::biometric::Gate::Off,
            device_id: None,
        }
    }
}

pub fn default_lock_timeout() -> u64 {
    3600
}

pub fn default_sync_interval() -> u64 {
    3600
}

pub fn default_pinentry() -> String {
    "pinentry".to_string()
}

pub const fn default_macos_unlock_dialog() -> bool {
    cfg!(target_os = "macos")
}

pub const fn default_logging() -> bool {
    false
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_biometric_gate_off(g: &crate::biometric::Gate) -> bool {
    matches!(g, crate::biometric::Gate::Off)
}

mod biometric_gate_serde {
    use std::str::FromStr as _;

    use serde::{Deserialize as _, Deserializer, Serializer};

    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn serialize<S: Serializer>(
        g: &crate::biometric::Gate,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        s.serialize_str(&g.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<crate::biometric::Gate, D::Error> {
        let s = String::deserialize(d)?;
        crate::biometric::Gate::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl Config {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load() -> Result<Self> {
        let file = crate::dirs::config_file();
        let mut fh = std::fs::File::open(&file).map_err(|source| {
            Error::LoadConfig {
                source,
                file: file.clone(),
            }
        })?;
        let mut json = String::new();
        fh.read_to_string(&mut json)
            .map_err(|source| Error::LoadConfig {
                source,
                file: file.clone(),
            })?;
        let mut slf: Self = serde_json::from_str(&json)
            .map_err(|source| Error::LoadConfigJson { source, file })?;
        if slf.lock_timeout == 0 {
            log::warn!("lock_timeout must be greater than 0");
            slf.lock_timeout = default_lock_timeout();
        }
        Ok(slf)
    }

    pub async fn load_async() -> Result<Self> {
        let file = crate::dirs::config_file();
        let mut fh =
            tokio::fs::File::open(&file).await.map_err(|source| {
                Error::LoadConfigAsync {
                    source,
                    file: file.clone(),
                }
            })?;
        let mut json = String::new();
        fh.read_to_string(&mut json).await.map_err(|source| {
            Error::LoadConfigAsync {
                source,
                file: file.clone(),
            }
        })?;
        let mut slf: Self = serde_json::from_str(&json)
            .map_err(|source| Error::LoadConfigJson { source, file })?;
        if slf.lock_timeout == 0 {
            log::warn!("lock_timeout must be greater than 0");
            slf.lock_timeout = default_lock_timeout();
        }
        Ok(slf)
    }

    pub fn save(&self) -> Result<()> {
        #[cfg(unix)]
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
        let file = crate::dirs::config_file();
        // unwrap is safe here because Self::filename is explicitly
        // constructed as a filename in a directory
        std::fs::create_dir_all(file.parent().unwrap()).map_err(
            |source| Error::SaveConfig {
                source,
                file: file.clone(),
            },
        )?;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let fh = opts.open(&file).map_err(|source| Error::SaveConfig {
            source,
            file: file.clone(),
        })?;
        // On Unix, `OpenOptions::mode` only applies on creation; tighten
        // unconditionally so a pre-existing loose-mode file is corrected
        // on every write. On Windows, the parent directory's per-user
        // DACL (see dirs.rs) provides equivalent isolation.
        #[cfg(unix)]
        fh.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|source| Error::SaveConfig {
                source,
                file: file.clone(),
            })?;
        let mut fh = fh;
        fh.write_all(
            serde_json::to_string(self)
                .map_err(|source| Error::SaveConfigJson {
                    source,
                    file: file.clone(),
                })?
                .as_bytes(),
        )
        .map_err(|source| Error::SaveConfig { source, file })?;
        Ok(())
    }

    /// Load once per process and reuse on subsequent calls. Safe for the
    /// short-lived `bwx` CLI where the config file isn't mutated mid-run.
    /// Mutating commands (`bwx config set`/`unset`) must keep using
    /// `load()` so they see fresh state.
    pub fn load_cached() -> Result<Arc<Self>> {
        if let Some(c) = CACHED.get() {
            return Ok(Arc::clone(c));
        }
        let loaded = Arc::new(Self::load()?);
        Ok(Arc::clone(CACHED.get_or_init(|| loaded)))
    }

    pub fn validate() -> Result<()> {
        let config = Self::load_cached()?;
        if config.email.is_none() {
            return Err(Error::ConfigMissingEmail);
        }
        Ok(())
    }

    pub fn base_url(&self) -> String {
        self.base_url.clone().map_or_else(
            || "https://api.bitwarden.com".to_string(),
            |url| {
                let clean_url = url.trim_end_matches('/');
                if clean_url == "https://api.bitwarden.eu" {
                    "https://api.bitwarden.eu".to_string()
                } else {
                    format!("{clean_url}/api")
                }
            },
        )
    }

    pub fn identity_url(&self) -> String {
        self.identity_url.clone().unwrap_or_else(|| {
            self.base_url.clone().map_or_else(
                || "https://identity.bitwarden.com".to_string(),
                |url| {
                    let clean_url = url.trim_end_matches('/');
                    if clean_url == "https://api.bitwarden.eu" {
                        "https://identity.bitwarden.eu".to_string()
                    } else {
                        format!("{clean_url}/identity")
                    }
                },
            )
        })
    }

    pub fn ui_url(&self) -> String {
        self.ui_url.clone().unwrap_or_else(|| {
            self.base_url.clone().map_or_else(
                || "https://vault.bitwarden.com".to_string(),
                |url| {
                    let clean_url = url.trim_end_matches('/');
                    if clean_url == "https://api.bitwarden.eu" {
                        "https://vault.bitwarden.eu".to_string()
                    } else {
                        clean_url.to_string()
                    }
                },
            )
        })
    }

    pub fn notifications_url(&self) -> String {
        self.notifications_url.clone().unwrap_or_else(|| {
            self.base_url.clone().map_or_else(
                || "https://notifications.bitwarden.com".to_string(),
                |url| {
                    let clean_url = url.trim_end_matches('/');
                    if clean_url == "https://api.bitwarden.eu" {
                        "https://notifications.bitwarden.eu".to_string()
                    } else {
                        format!("{clean_url}/notifications")
                    }
                },
            )
        })
    }

    pub fn client_cert_path(&self) -> Option<&std::path::Path> {
        self.client_cert_path.as_deref()
    }

    pub fn server_name(&self) -> String {
        self.base_url
            .clone()
            .unwrap_or_else(|| "default".to_string())
    }
}

pub async fn device_id(config: &Config) -> Result<String> {
    let file = crate::dirs::device_id_file();
    if let Ok(mut fh) = tokio::fs::File::open(&file).await {
        let mut s = String::new();
        fh.read_to_string(&mut s)
            .await
            .map_err(|e| Error::LoadDeviceId {
                source: e,
                file: file.clone(),
            })?;
        Ok(s.trim().to_string())
    } else {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt as _;
        let id = config.device_id.as_ref().map_or_else(
            || crate::uuid::new_v4().to_string(),
            String::to_string,
        );
        let mut opts = tokio::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let mut fh =
            opts.open(&file).await.map_err(|e| Error::LoadDeviceId {
                source: e,
                file: file.clone(),
            })?;
        // Unix: tighten in case the file pre-existed with loose mode.
        // Windows: the parent dir's per-user DACL covers isolation.
        #[cfg(unix)]
        fh.set_permissions(std::fs::Permissions::from_mode(0o600))
            .await
            .map_err(|e| Error::LoadDeviceId {
                source: e,
                file: file.clone(),
            })?;
        fh.write_all(id.as_bytes()).await.map_err(|e| {
            Error::LoadDeviceId {
                source: e,
                file: file.clone(),
            }
        })?;
        Ok(id)
    }
}
