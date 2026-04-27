//! Same-team code-requirement check for IPC peers (macOS).
//!
//! `check_peer_uid` already blocks cross-user clients. On macOS, when
//! the agent itself is signed with a Team Identifier (Developer ID or
//! Apple Development), this module additionally requires the peer to
//! be signed by the same team — closing the "another process running
//! as my uid that's signed by some other identity" gap.
//!
//! Ad-hoc and unsigned agent builds (local dev, forks without a paid
//! Apple cert) have no team id, so the check is a no-op and the agent
//! continues to accept any same-uid peer. That keeps `cargo install`,
//! `cargo run`, and fork builds working without ceremony.

use crate::bin_error;

#[cfg(target_os = "macos")]
mod imp {
    use core_foundation::base::TCFType as _;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::number::CFNumber;
    use core_foundation::string::CFString;
    use core_foundation_sys::base::{CFRelease, OSStatus};
    use core_foundation_sys::dictionary::{
        CFDictionaryGetValue, CFDictionaryRef,
    };
    use core_foundation_sys::string::CFStringRef;
    use security_framework_sys::code_signing::{
        kSecGuestAttributePid, SecCSFlags, SecCodeCheckValidity,
        SecCodeCopyGuestWithAttributes, SecCodeCopySelf, SecCodeRef,
        SecRequirementCreateWithString, SecRequirementRef,
    };
    use std::sync::OnceLock;

    use crate::bin_error;

    const K_SEC_CS_DEFAULT_FLAGS: SecCSFlags = 0;
    /// `kSecCSSigningInformation` from `<Security/SecCode.h>`. Tells
    /// `SecCodeCopySigningInformation` to populate signing-identity
    /// fields (`TeamIdentifier`, signing certs) in the returned dict.
    const K_SEC_CS_SIGNING_INFORMATION: SecCSFlags = 1 << 1;

    // security-framework-sys doesn't export these; declare them
    // manually. Both are stable Security.framework exports.
    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        fn SecCodeCopySigningInformation(
            code: SecCodeRef,
            flags: SecCSFlags,
            information: *mut CFDictionaryRef,
        ) -> OSStatus;
        static kSecCodeInfoTeamIdentifier: CFStringRef;
    }

    /// Team Identifier of this agent process, captured once at first
    /// call. `None` when the agent is ad-hoc/unsigned (typical for
    /// local dev and forks without a Developer ID).
    pub fn agent_team_id() -> Option<&'static str> {
        static ID: OnceLock<Option<String>> = OnceLock::new();
        ID.get_or_init(detect_self_team_id).as_deref()
    }

    fn detect_self_team_id() -> Option<String> {
        unsafe {
            let mut self_code: SecCodeRef = std::ptr::null_mut();
            if SecCodeCopySelf(K_SEC_CS_DEFAULT_FLAGS, &raw mut self_code)
                != 0
                || self_code.is_null()
            {
                return None;
            }
            let mut info: CFDictionaryRef = std::ptr::null();
            let s = SecCodeCopySigningInformation(
                self_code,
                K_SEC_CS_SIGNING_INFORMATION,
                &raw mut info,
            );
            CFRelease(self_code.cast());
            if s != 0 || info.is_null() {
                return None;
            }
            let team = team_id_from_info(info);
            CFRelease(info.cast());
            team
        }
    }

    unsafe fn team_id_from_info(info: CFDictionaryRef) -> Option<String> {
        let key = unsafe { kSecCodeInfoTeamIdentifier };
        let value = unsafe { CFDictionaryGetValue(info, key.cast()) };
        if value.is_null() {
            return None;
        }
        // Value is a +0 (get-rule) CFString owned by `info`; retain
        // through wrap_under_get_rule before stringifying.
        let cfstr = unsafe { CFString::wrap_under_get_rule(value.cast()) };
        let s = cfstr.to_string();
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }

    /// Verify that the process at `peer_pid` is signed under `expected`
    /// team identifier. Used only when the agent itself has a team id
    /// to compare against.
    pub fn verify_peer_team(
        peer_pid: i32,
        expected: &str,
    ) -> bin_error::Result<()> {
        unsafe {
            let pid_key =
                CFString::wrap_under_get_rule(kSecGuestAttributePid);
            let pid_num = CFNumber::from(i64::from(peer_pid));
            let attrs = CFDictionary::from_CFType_pairs(&[(
                pid_key.as_CFType(),
                pid_num.as_CFType(),
            )]);

            let mut peer_code: SecCodeRef = std::ptr::null_mut();
            let s = SecCodeCopyGuestWithAttributes(
                std::ptr::null_mut(),
                attrs.as_concrete_TypeRef(),
                K_SEC_CS_DEFAULT_FLAGS,
                &raw mut peer_code,
            );
            if s != 0 || peer_code.is_null() {
                return Err(bin_error::Error::msg(format!(
                    "SecCodeCopyGuestWithAttributes(pid={peer_pid}) \
                     status {s}"
                )));
            }

            // Apple Developer ID / Apple Development certs both put the
            // team id in the leaf certificate's OU, anchored at Apple.
            let req_text = CFString::new(&format!(
                r#"anchor apple generic and certificate leaf[subject.OU] = "{expected}""#
            ));
            let mut req: SecRequirementRef = std::ptr::null_mut();
            let s = SecRequirementCreateWithString(
                req_text.as_concrete_TypeRef(),
                K_SEC_CS_DEFAULT_FLAGS,
                &raw mut req,
            );
            if s != 0 || req.is_null() {
                CFRelease(peer_code.cast());
                return Err(bin_error::Error::msg(format!(
                    "SecRequirementCreateWithString status {s}"
                )));
            }

            let s =
                SecCodeCheckValidity(peer_code, K_SEC_CS_DEFAULT_FLAGS, req);
            CFRelease(peer_code.cast());
            CFRelease(req.cast());
            if s == 0 {
                Ok(())
            } else {
                Err(bin_error::Error::msg(format!(
                    "peer pid {peer_pid} does not satisfy team \"{expected}\" \
                     code requirement (status {s})"
                )))
            }
        }
    }
}

/// Run the same-team code-requirement check on a peer. No-op when the
/// agent itself has no team identifier to compare against (ad-hoc /
/// unsigned / non-macOS) so dev and fork builds keep working.
#[cfg(target_os = "macos")]
pub fn check_peer_team(peer_pid: Option<i32>) -> bin_error::Result<()> {
    let Some(team) = imp::agent_team_id() else {
        return Ok(());
    };
    let Some(pid) = peer_pid else {
        return Err(bin_error::Error::msg(
            "agent is signed but peer pid is unavailable; \
             refusing connection",
        ));
    };
    imp::verify_peer_team(pid, team)
}

#[cfg(windows)]
mod imp_win {
    //! Authenticode-based peer-publisher check for Windows.
    //!
    //! Mirrors the macOS team-id flow: cache the agent's own signing
    //! identity (Subject CN + leaf-cert SHA-256 thumbprint) on first
    //! call. Reject peers whose Authenticode leaf does not match.
    //! Unsigned/dev builds yield `None` and the check becomes a no-op.
    use std::sync::OnceLock;

    use windows_sys::core::GUID;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::Cryptography::{
        CertGetNameStringW, CryptHashCertificate, CALG_SHA_256,
        CERT_CONTEXT, CERT_NAME_ATTR_TYPE,
    };
    use windows_sys::Win32::Security::WinTrust::{
        WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain,
        WTHelperProvDataFromStateData, WinVerifyTrust,
        WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
        WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOKE_NONE,
        WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    use crate::bin_error;

    /// `(common_name, sha256_thumbprint_hex)` of the leaf signing cert.
    pub type Publisher = (String, String);

    pub fn agent_publisher() -> Option<&'static Publisher> {
        static ID: OnceLock<Option<Publisher>> = OnceLock::new();
        ID.get_or_init(detect_self_publisher).as_ref()
    }

    fn detect_self_publisher() -> Option<Publisher> {
        let exe = std::env::current_exe().ok()?;
        publisher_of_path(&exe)
    }

    /// Run `WinVerifyTrust` on `path`, walk to the leaf cert, return
    /// `(CN, SHA256)`. `None` if the file is unsigned or any step
    /// fails. The caller treats `None` as "no policy to enforce".
    fn publisher_of_path(path: &std::path::Path) -> Option<Publisher> {
        let wide = bwx::win::wide::os_str_to_utf16_nul(path.as_os_str());
        let mut file = WINTRUST_FILE_INFO {
            cbStruct: u32::try_from(std::mem::size_of::<WINTRUST_FILE_INFO>())
                .ok()?,
            pcwszFilePath: wide.as_ptr(),
            hFile: std::ptr::null_mut(),
            pgKnownSubject: std::ptr::null_mut(),
        };
        let mut wtd: WINTRUST_DATA = unsafe { std::mem::zeroed() };
        wtd.cbStruct = u32::try_from(std::mem::size_of::<WINTRUST_DATA>())
            .ok()?;
        wtd.dwUIChoice = WTD_UI_NONE;
        wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
        wtd.dwUnionChoice = WTD_CHOICE_FILE;
        wtd.dwStateAction = WTD_STATEACTION_VERIFY;
        wtd.Anonymous = WINTRUST_DATA_0 { pFile: &mut file };

        let mut action: GUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        // SAFETY: action and wtd are stack locals; HWND null is documented.
        let status = unsafe {
            WinVerifyTrust(
                std::ptr::null_mut(),
                &mut action,
                std::ptr::from_mut::<WINTRUST_DATA>(&mut wtd).cast(),
            )
        };

        let result = if status == 0 {
            extract_leaf_publisher(wtd.hWVTStateData)
        } else {
            None
        };

        // Always close state to avoid leaks even on failure.
        wtd.dwStateAction = WTD_STATEACTION_CLOSE;
        // SAFETY: same wtd struct, just toggling the state action.
        let _ = unsafe {
            WinVerifyTrust(
                std::ptr::null_mut(),
                &mut action,
                std::ptr::from_mut::<WINTRUST_DATA>(&mut wtd).cast(),
            )
        };
        result
    }

    fn extract_leaf_publisher(state: HANDLE) -> Option<Publisher> {
        if state.is_null() {
            return None;
        }
        // SAFETY: state came from a successful WinVerifyTrust call.
        let prov = unsafe { WTHelperProvDataFromStateData(state) };
        if prov.is_null() {
            return None;
        }
        // SAFETY: prov is owned by WinTrust until we issue STATEACTION_CLOSE.
        let signer = unsafe { WTHelperGetProvSignerFromChain(prov, 0, 0, 0) };
        if signer.is_null() {
            return None;
        }
        // SAFETY: signer is valid; csCertChain is its stored count.
        let chain_len = unsafe { (*signer).csCertChain };
        if chain_len == 0 {
            return None;
        }
        // The leaf is index 0 (signing cert); walking to chain_len-1 is
        // the root. We want the leaf to match macOS team-id semantics.
        // SAFETY: idxcert in [0, csCertChain).
        let cert_wrap = unsafe { WTHelperGetProvCertFromChain(signer, 0) };
        if cert_wrap.is_null() {
            return None;
        }
        // SAFETY: cert_wrap is valid; pCert is its CERT_CONTEXT pointer.
        let cert: *const CERT_CONTEXT = unsafe { (*cert_wrap).pCert };
        if cert.is_null() {
            return None;
        }
        let cn = cert_subject_cn(cert)?;
        let thumb = cert_sha256_thumbprint(cert)?;
        Some((cn, thumb))
    }

    fn cert_subject_cn(cert: *const CERT_CONTEXT) -> Option<String> {
        let mut buf = [0u16; 256];
        // SAFETY: cert is valid; buf is sized for the documented call.
        let n = unsafe {
            CertGetNameStringW(
                cert,
                CERT_NAME_ATTR_TYPE,
                0,
                windows_sys::Win32::Security::Cryptography::szOID_COMMON_NAME
                    .cast::<core::ffi::c_void>(),
                buf.as_mut_ptr(),
                u32::try_from(buf.len()).ok()?,
            )
        };
        if n == 0 {
            return None;
        }
        // n includes the trailing NUL.
        let len = (n as usize).saturating_sub(1);
        let s = String::from_utf16(&buf[..len]).ok()?;
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }

    fn cert_sha256_thumbprint(cert: *const CERT_CONTEXT) -> Option<String> {
        // SAFETY: cert is valid; pbCertEncoded/cbCertEncoded describe
        // the DER bytes of the cert.
        let (encoded, len) = unsafe {
            ((*cert).pbCertEncoded, (*cert).cbCertEncoded)
        };
        if encoded.is_null() || len == 0 {
            return None;
        }
        let mut hash = [0u8; 32];
        let mut hash_len = u32::try_from(hash.len()).ok()?;
        // SAFETY: documented hash-by-algid entry point.
        let ok = unsafe {
            CryptHashCertificate(
                0,
                CALG_SHA_256,
                0,
                encoded,
                len,
                hash.as_mut_ptr(),
                &mut hash_len,
            )
        };
        if ok == 0 {
            return None;
        }
        let mut hex = String::with_capacity(usize::try_from(hash_len).ok()? * 2);
        use std::fmt::Write as _;
        for b in &hash[..hash_len as usize] {
            write!(&mut hex, "{b:02x}").ok()?;
        }
        Some(hex)
    }

    pub fn verify_peer_publisher(
        peer_pid: i32,
        expected: &Publisher,
    ) -> bin_error::Result<()> {
        let path = peer_image_path(peer_pid)?;
        match publisher_of_path(&path) {
            Some(got) if &got == expected => Ok(()),
            Some(got) => Err(bin_error::Error::msg(format!(
                "peer pid {peer_pid} publisher {got:?} does not match \
                 expected {expected:?}; refusing connection"
            ))),
            None => Err(bin_error::Error::msg(format!(
                "peer pid {peer_pid} is not Authenticode-signed; \
                 refusing connection (agent is signed as {expected:?})"
            ))),
        }
    }

    fn peer_image_path(pid: i32) -> bin_error::Result<std::path::PathBuf> {
        let pid_u = u32::try_from(pid).map_err(|_| {
            bin_error::Error::msg(format!("invalid peer pid {pid}"))
        })?;
        // SAFETY: PROCESS_QUERY_LIMITED_INFORMATION is sufficient.
        let h = unsafe {
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid_u)
        };
        if h.is_null() {
            return Err(bin_error::Error::msg(format!(
                "OpenProcess(pid={pid}) failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        let mut buf = [0u16; 32768];
        let mut size = u32::try_from(buf.len()).expect("32k fits in u32");
        // SAFETY: h is valid; buf sized via size in/out.
        let ok = unsafe {
            QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut size)
        };
        // SAFETY: h closed exactly once.
        unsafe {
            CloseHandle(h);
        }
        if ok == 0 {
            return Err(bin_error::Error::msg(format!(
                "QueryFullProcessImageNameW(pid={pid}) failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        use std::os::windows::ffi::OsStringExt as _;
        let s = std::ffi::OsString::from_wide(&buf[..size as usize]);
        Ok(std::path::PathBuf::from(s))
    }
}

#[cfg(windows)]
pub fn check_peer_team(peer_pid: Option<i32>) -> bin_error::Result<()> {
    let Some(expected) = imp_win::agent_publisher() else {
        return Ok(());
    };
    let Some(pid) = peer_pid else {
        return Err(bin_error::Error::msg(
            "agent is signed but peer pid is unavailable; \
             refusing connection",
        ));
    };
    imp_win::verify_peer_publisher(pid, expected)
}

// Result return kept for cross-platform signature parity with the
// macOS implementation.
#[cfg(not(any(target_os = "macos", windows)))]
#[allow(clippy::unnecessary_wraps)]
pub fn check_peer_team(_peer_pid: Option<i32>) -> bin_error::Result<()> {
    Ok(())
}
