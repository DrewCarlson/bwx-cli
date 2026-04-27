mod auth;
mod cipher;
mod config;
mod crud;
mod decrypt;
mod entry;
mod exec;
mod field;
mod find;
mod setup_os;
mod ssh;
mod totp;
#[cfg(target_os = "macos")]
mod biometric;
mod util;

#[cfg(test)]
mod tests;

pub use auth::{
    lock, login, purge, register, stop_agent, sync, unlock, unlocked,
};
pub use config::{config_set, config_show, config_unset};
pub use crud::{add, edit, generate, remove};
pub use entry::{code, get, history, list, search};
pub use exec::exec;
pub use find::{parse_needle, Needle};
pub use setup_os::{setup_os, teardown_os};
pub use ssh::{ssh_allowed_signers, ssh_public_key, ssh_socket};
#[cfg(target_os = "macos")]
pub use biometric::{biometric_disable, biometric_enroll, biometric_status};
