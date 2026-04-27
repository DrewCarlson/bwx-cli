//! Touch ID / biometric authorization gate.
//!
//! On macOS, calls `LAContext::evaluate_policy` via
//! `objc2-local-authentication`. On other platforms `require_presence` is a
//! stub that always returns `Ok(true)`, so callers need no cfg gating.

pub mod blob;
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub mod keychain;

use std::fmt;
use std::str::FromStr;

/// Which categories of operation should require biometric confirmation.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum Gate {
    /// No biometric prompt. Always the value on non-macOS builds.
    #[default]
    Off,
    /// Only ssh-agent sign requests and `bwx code` TOTP generation.
    Signing,
    /// Every response carrying plaintext secret material.
    All,
}

impl FromStr for Gate {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "off" | "false" => Ok(Self::Off),
            "signing" => Ok(Self::Signing),
            "all" | "true" => Ok(Self::All),
            other => Err(format!(
                "invalid biometric_gate value {other:?} (expected \
                 off/signing/all)"
            )),
        }
    }
}

impl fmt::Display for Gate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Off => "off",
            Self::Signing => "signing",
            Self::All => "all",
        })
    }
}

/// Category of operation a call site represents. Used with a `Gate` to
/// decide whether a biometric prompt is required.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// SSH-agent sign request.
    SshSign,
    /// `bwx code` TOTP generation.
    TotpCode,
    /// Agent `Decrypt` / `Encrypt` / clipboard response carrying vault
    /// secret material.
    VaultSecret,
}

#[must_use]
pub fn gate_applies(gate: Gate, kind: Kind) -> bool {
    match gate {
        Gate::Off => false,
        Gate::Signing => matches!(kind, Kind::SshSign | Kind::TotpCode),
        Gate::All => true,
    }
}

/// Await a biometric confirmation from the user.
///
/// `Ok(true)` on success, `Ok(false)` on cancel, `Err(..)` for unexpected
/// failures. On non-macOS builds always returns `Ok(true)`.
#[cfg(target_os = "macos")]
pub async fn require_presence(reason: &str) -> Result<bool, Error> {
    macos::require_presence(reason).await
}

#[cfg(target_os = "windows")]
pub async fn require_presence(reason: &str) -> Result<bool, Error> {
    windows_uc::require_presence(reason).await
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
#[allow(clippy::unused_async)]
pub async fn require_presence(_reason: &str) -> Result<bool, Error> {
    Ok(true)
}

#[derive(Debug)]
pub enum Error {
    /// Biometry is not available on this machine (no hardware, lid
    /// closed, or the user has disabled Touch ID for this app).
    Unavailable(String),
    /// Something else went wrong talking to the OS.
    Os(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(s) => {
                write!(f, "biometry unavailable: {s}")
            }
            Self::Os(s) => write!(f, "LocalAuthentication error: {s}"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(target_os = "macos")]
mod macos {
    use block2::RcBlock;
    use objc2::rc::Retained;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};

    use super::Error;

    /// Test bypass for e2e scenarios. If `BWX_BIOMETRIC_TEST_BYPASS` is
    /// "allow"/"deny" AND debug assertions are enabled, the FFI call is
    /// skipped. Ignored in release builds.
    fn debug_bypass() -> Option<bool> {
        if !cfg!(debug_assertions) {
            return None;
        }
        match std::env::var("BWX_BIOMETRIC_TEST_BYPASS").ok().as_deref() {
            Some("allow") => Some(true),
            Some("deny") => Some(false),
            _ => None,
        }
    }

    /// Synchronous setup: create the `LAContext`, install the completion
    /// handler, kick off `evaluatePolicy`. All objc types are confined to
    /// this function so they never cross an `.await`, keeping the outer
    /// async future `Send`.
    fn begin_presence_check(
        reason: &str,
    ) -> Result<tokio::sync::oneshot::Receiver<Result<bool, Error>>, Error>
    {
        // SAFETY: LAContext::new is a +1-retain convenience constructor.
        let ctx: Retained<LAContext> = unsafe { LAContext::new() };
        let policy = LAPolicy::DeviceOwnerAuthenticationWithBiometrics;

        if let Err(err) = unsafe { ctx.canEvaluatePolicy_error(policy) } {
            return Err(Error::Unavailable(
                err.localizedDescription().to_string(),
            ));
        }

        let (tx, rx) = tokio::sync::oneshot::channel::<Result<bool, Error>>();
        let tx = std::sync::Mutex::new(Some(tx));
        let block = RcBlock::new(move |success: Bool, err: *mut NSError| {
            let claimed = tx.lock().unwrap().take();
            if let Some(tx) = claimed {
                let res = if success.as_bool() {
                    Ok(true)
                } else if err.is_null() {
                    Ok(false)
                } else {
                    // SAFETY: the framework passes a retained NSError live
                    // for the duration of the callback.
                    let desc =
                        unsafe { (*err).localizedDescription().to_string() };
                    let code = unsafe { (*err).code() };
                    if code == -2 || code == -4 {
                        // LAError.userCancel = -2; LAError.systemCancel = -4
                        Ok(false)
                    } else {
                        Err(Error::Os(format!("code={code}: {desc}")))
                    }
                };
                let _ = tx.send(res);
            }
        });

        let reason_ns = NSString::from_str(reason);
        unsafe {
            ctx.evaluatePolicy_localizedReason_reply(
                policy, &reason_ns, &block,
            );
        }
        Ok(rx)
    }

    pub async fn require_presence(reason: &str) -> Result<bool, Error> {
        if let Some(v) = debug_bypass() {
            return Ok(v);
        }
        let rx = begin_presence_check(reason)?;
        rx.await.map_err(|_| Error::Os("reply dropped".into()))?
    }
}

#[cfg(target_os = "windows")]
mod windows_uc {
    use windows::Security::Credentials::UI::{
        UserConsentVerificationResult, UserConsentVerifier,
        UserConsentVerifierAvailability,
    };
    use windows::core::HSTRING;

    use super::Error;

    pub async fn require_presence(reason: &str) -> Result<bool, Error> {
        let reason = reason.to_owned();
        // Mirror the macOS path: hop the blocking WinRT calls onto a
        // worker thread so the agent's async runtime keeps running.
        tokio::task::spawn_blocking(move || run(&reason))
            .await
            .map_err(|e| Error::Os(format!("spawn_blocking: {e}")))?
    }

    fn run(reason: &str) -> Result<bool, Error> {
        let availability = UserConsentVerifier::CheckAvailabilityAsync()
            .map_err(|e| Error::Os(format!("CheckAvailability: {e}")))?
            .join()
            .map_err(|e| Error::Os(format!("CheckAvailability join: {e}")))?;
        if availability != UserConsentVerifierAvailability::Available {
            return Err(Error::Unavailable(format!(
                "UserConsentVerifierAvailability = {availability:?}"
            )));
        }
        let result = UserConsentVerifier::RequestVerificationAsync(
            &HSTRING::from(reason),
        )
        .map_err(|e| Error::Os(format!("RequestVerification: {e}")))?
        .join()
        .map_err(|e| Error::Os(format!("RequestVerification join: {e}")))?;
        match result {
            UserConsentVerificationResult::Verified => Ok(true),
            UserConsentVerificationResult::Canceled => Ok(false),
            other => Err(Error::Os(format!(
                "UserConsentVerificationResult = {other:?}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{gate_applies, Gate, Kind};

    #[test]
    fn gate_off_never_applies() {
        for k in [Kind::SshSign, Kind::TotpCode, Kind::VaultSecret] {
            assert!(!gate_applies(Gate::Off, k));
        }
    }

    #[test]
    fn gate_signing_matches_only_signing_kinds() {
        assert!(gate_applies(Gate::Signing, Kind::SshSign));
        assert!(gate_applies(Gate::Signing, Kind::TotpCode));
        assert!(!gate_applies(Gate::Signing, Kind::VaultSecret));
    }

    #[test]
    fn gate_all_applies_everywhere() {
        for k in [Kind::SshSign, Kind::TotpCode, Kind::VaultSecret] {
            assert!(gate_applies(Gate::All, k));
        }
    }

    #[test]
    fn gate_parse_roundtrip() {
        for g in [Gate::Off, Gate::Signing, Gate::All] {
            let s = g.to_string();
            let parsed: Gate = s.parse().expect("parse");
            assert_eq!(g, parsed);
        }
    }

    #[test]
    fn gate_parse_rejects_garbage() {
        assert!("maybe".parse::<Gate>().is_err());
    }
}
