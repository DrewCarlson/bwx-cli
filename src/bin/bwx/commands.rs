mod auth;
mod cipher;
mod config;
mod crud;
mod decrypt;
mod entry;
mod exec;
mod field;
mod find;
#[cfg(target_os = "macos")]
mod macos;
mod ssh;
mod totp;
#[cfg(target_os = "macos")]
mod touchid;
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
#[cfg(target_os = "macos")]
pub use macos::{setup_macos, teardown_macos};
pub use ssh::{ssh_allowed_signers, ssh_public_key, ssh_socket};
#[cfg(target_os = "macos")]
pub use touchid::{touchid_disable, touchid_enroll, touchid_status};
