//! Cross-platform secret storage for bwx's biometric wrapper key.
//!
//! The module is named `keychain` for historical reasons (it began as a
//! macOS-only Keychain wrapper). On macOS it still maps to
//! `Security.framework`'s generic-password Keychain. On Windows it maps
//! to a CNG (TPM-preferred) persisted AES key with `NCRYPT_UI_PROTECT_KEY_FLAG`,
//! falling back to DPAPI-NG when no CNG provider is available.
//!
//! Public surface — `store`, `load`, `delete`, `exists`, and the `Error`
//! enum — is platform-neutral; callers don't need to cfg-gate.

use std::fmt;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

#[derive(Debug)]
pub enum Error {
    /// The biometric user cancelled the prompt or authentication failed.
    UserCancelled,
    /// Auth failed in a way the OS distinguishes from a plain cancel
    /// (e.g. macOS `errSecAuthFailed`, Windows biometric set changed).
    Invalidated,
    /// The stored entry doesn't exist.
    NotFound,
    /// Any other error surfaced by the underlying OS API.
    Os(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UserCancelled => f.write_str("keychain: cancelled"),
            Self::Invalidated => f.write_str("keychain: auth failed"),
            Self::NotFound => f.write_str("keychain: item not found"),
            Self::Os(s) => write!(f, "keychain: {s}"),
        }
    }
}

impl std::error::Error for Error {}

/// Store `secret` under the given label.
#[cfg(target_os = "macos")]
pub fn store(label: &str, secret: &[u8]) -> Result<(), Error> {
    macos::store(label, secret)
}

/// Load the bytes stored under `label`. `prompt` is shown by the OS
/// when biometric consent is required.
#[cfg(target_os = "macos")]
pub fn load(label: &str, prompt: &str) -> Result<crate::locked::Vec, Error> {
    macos::load(label, prompt)
}

/// Delete the item under `label`. Idempotent: returns `Ok(())` whether
/// or not the item existed.
#[cfg(target_os = "macos")]
pub fn delete(label: &str) -> Result<(), Error> {
    macos::delete(label)
}

/// Check whether an item exists under `label` without triggering a
/// biometric prompt.
#[cfg(target_os = "macos")]
pub fn exists(label: &str) -> Result<bool, Error> {
    macos::exists(label)
}

#[cfg(target_os = "windows")]
pub fn store(label: &str, secret: &[u8]) -> Result<(), Error> {
    windows::store(label, secret)
}

#[cfg(target_os = "windows")]
pub fn load(label: &str, prompt: &str) -> Result<crate::locked::Vec, Error> {
    windows::load(label, prompt)
}

#[cfg(target_os = "windows")]
pub fn delete(label: &str) -> Result<(), Error> {
    windows::delete(label)
}

#[cfg(target_os = "windows")]
pub fn exists(label: &str) -> Result<bool, Error> {
    windows::exists(label)
}
