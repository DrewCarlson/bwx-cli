//! Windows secret-storage backend for the biometric wrapper key.
//!
//! Strategy: a per-enrollment AES persisted key in CNG, created with
//! `NCRYPT_UI_PROTECT_KEY_FLAG` so the platform prompts for consent on
//! every use. Provider preference order:
//!
//!   1. `MS_PLATFORM_KEY_STORAGE_PROVIDER` — TPM-backed.
//!   2. `MS_KEY_STORAGE_PROVIDER` — software, but still gated by the
//!      UI-protect ACL.
//!   3. DPAPI-NG (`NCryptCreateProtectionDescriptor("LOCAL=user")`)
//!      fallback when neither CNG provider is available. This loses the
//!      biometric ACL but keeps user-scope encryption; the agent logs a
//!      warning at `store` time.
//!
//! Wrapping uses `NCryptEncrypt` (AES, block padding); the resulting
//! ciphertext is written to `<data_dir>/biometric-<label>.bin`. The
//! file's first byte is a version tag identifying which protection path
//! produced it: `0x01` = CNG persisted-key, `0x02` = DPAPI-NG.
//!
//! `require_presence` (in the parent module) holds the
//! `UserConsentVerifier` gate; this module's job is wrap/unwrap, not
//! presence verification — the platform will additionally prompt at
//! `NCryptDecrypt` time on the CNG path.

#![allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use std::ffi::c_void;
use std::path::PathBuf;
use std::ptr;

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::NCRYPT_DESCRIPTOR_HANDLE;
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_AES_ALGORITHM, MS_KEY_STORAGE_PROVIDER,
    MS_PLATFORM_KEY_STORAGE_PROVIDER, NCRYPT_KEY_HANDLE,
    NCRYPT_OVERWRITE_KEY_FLAG, NCRYPT_PROV_HANDLE, NCRYPT_UI_POLICY,
    NCRYPT_UI_POLICY_PROPERTY, NCRYPT_UI_PROTECT_KEY_FLAG,
    NCryptCreatePersistedKey, NCryptCreateProtectionDescriptor, NCryptDecrypt,
    NCryptDeleteKey, NCryptEncrypt, NCryptFinalizeKey, NCryptFreeObject,
    NCryptOpenKey, NCryptOpenStorageProvider, NCryptProtectSecret,
    NCryptSetProperty, NCryptUnprotectSecret,
};

use super::Error;

/// Block-padding flag for AES `NCryptEncrypt` / `NCryptDecrypt`.
const BCRYPT_BLOCK_PADDING: u32 = 0x0000_0001;

/// `HRESULT` for "the user cancelled the operation". Maps to
/// `Error::UserCancelled` like macOS `errSecUserCanceled`.
const NTE_USER_CANCELLED: i32 = 0x8009_0036_u32 as i32;
/// `HRESULT` for "keyset not found" — surfaces as `Error::NotFound`.
const NTE_BAD_KEYSET: i32 = 0x8009_0016_u32 as i32;
const NTE_NOT_FOUND: i32 = 0x8009_0011_u32 as i32;

const VERSION_CNG: u8 = 0x01;
const VERSION_DPAPI_NG: u8 = 0x02;

fn ciphertext_path(label: &str) -> PathBuf {
    let p = crate::dirs::agent_stdout_file();
    let dir = p.parent().map_or_else(
        || std::path::PathBuf::from("."),
        std::path::Path::to_path_buf,
    );
    dir.join(format!("biometric-{label}.bin"))
}

use crate::win::wide::str_to_utf16_nul as wide;

fn map_hresult(api: &str, hr: i32) -> Error {
    match hr {
        NTE_USER_CANCELLED => Error::UserCancelled,
        NTE_BAD_KEYSET | NTE_NOT_FOUND => Error::NotFound,
        other => Error::Os(format!("{api}: HRESULT 0x{:08x}", other as u32)),
    }
}

/// RAII wrapper for an `NCRYPT_HANDLE`; `NCryptFreeObject` accepts both
/// provider and key handles.
struct NCryptHandle(usize);

impl NCryptHandle {
    fn raw(&self) -> usize {
        self.0
    }
}

impl Drop for NCryptHandle {
    fn drop(&mut self) {
        if self.0 != 0 {
            // SAFETY: handle is non-null and was returned by NCrypt; freeing once on drop.
            unsafe {
                NCryptFreeObject(self.0);
            }
        }
    }
}

fn open_provider() -> Result<(NCryptHandle, bool), Error> {
    let mut prov: NCRYPT_PROV_HANDLE = 0;
    // SAFETY: out-pointer is valid; provider name is a static null-terminated PCWSTR.
    let hr = unsafe {
        NCryptOpenStorageProvider(
            &raw mut prov,
            MS_PLATFORM_KEY_STORAGE_PROVIDER,
            0,
        )
    };
    if hr == 0 {
        return Ok((NCryptHandle(prov), true));
    }
    log::warn!(
        "biometric: TPM provider unavailable (HRESULT 0x{:08x}); falling \
         back to software key storage provider",
        hr as u32
    );
    let mut prov2: NCRYPT_PROV_HANDLE = 0;
    // SAFETY: same as above for the software fallback provider.
    let hr2 = unsafe {
        NCryptOpenStorageProvider(&raw mut prov2, MS_KEY_STORAGE_PROVIDER, 0)
    };
    if hr2 == 0 {
        Ok((NCryptHandle(prov2), false))
    } else {
        Err(map_hresult("NCryptOpenStorageProvider", hr2))
    }
}

fn create_ui_protected_key(
    prov: &NCryptHandle,
    label: &str,
) -> Result<NCryptHandle, Error> {
    let label_w = wide(label);
    let mut key: NCRYPT_KEY_HANDLE = 0;
    // SAFETY: provider handle is live; out-pointer and PCWSTRs are valid for the call.
    let hr = unsafe {
        NCryptCreatePersistedKey(
            prov.raw(),
            &raw mut key,
            BCRYPT_AES_ALGORITHM,
            label_w.as_ptr(),
            0,
            NCRYPT_OVERWRITE_KEY_FLAG,
        )
    };
    if hr != 0 {
        return Err(map_hresult("NCryptCreatePersistedKey", hr));
    }
    let key = NCryptHandle(key);

    let title = wide("bwx biometric");
    let friendly = wide("bwx biometric wrapper key");
    let desc = wide("Authorize bwx to unlock your vault");
    let policy = NCRYPT_UI_POLICY {
        dwVersion: 1,
        dwFlags: NCRYPT_UI_PROTECT_KEY_FLAG,
        pszCreationTitle: title.as_ptr(),
        pszFriendlyName: friendly.as_ptr(),
        pszDescription: desc.as_ptr(),
    };
    // SAFETY: policy struct, key handle, and property name are all valid for the call.
    let hr = unsafe {
        NCryptSetProperty(
            key.raw(),
            NCRYPT_UI_POLICY_PROPERTY,
            (&raw const policy).cast::<u8>(),
            size_of::<NCRYPT_UI_POLICY>() as u32,
            0,
        )
    };
    if hr != 0 {
        return Err(map_hresult("NCryptSetProperty(UI policy)", hr));
    }

    // SAFETY: key handle is live and not yet finalized.
    let hr = unsafe { NCryptFinalizeKey(key.raw(), 0) };
    if hr != 0 {
        return Err(map_hresult("NCryptFinalizeKey", hr));
    }
    Ok(key)
}

fn open_key(
    prov: &NCryptHandle,
    label: &str,
) -> Result<NCryptHandle, Error> {
    let label_w = wide(label);
    let mut key: NCRYPT_KEY_HANDLE = 0;
    // SAFETY: provider handle is live; out-pointer and PCWSTR are valid for the call.
    let hr = unsafe {
        NCryptOpenKey(prov.raw(), &raw mut key, label_w.as_ptr(), 0, 0)
    };
    if hr != 0 {
        return Err(map_hresult("NCryptOpenKey", hr));
    }
    Ok(NCryptHandle(key))
}

fn cng_encrypt(key: &NCryptHandle, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out_len: u32 = 0;
    // SAFETY: probe call to discover output length; output pointer is null as documented.
    let hr = unsafe {
        NCryptEncrypt(
            key.raw(),
            plaintext.as_ptr(),
            plaintext.len() as u32,
            ptr::null(),
            ptr::null_mut(),
            0,
            &raw mut out_len,
            BCRYPT_BLOCK_PADDING,
        )
    };
    if hr != 0 {
        return Err(map_hresult("NCryptEncrypt(size)", hr));
    }
    let mut buf = vec![0u8; out_len as usize];
    // SAFETY: buf has capacity out_len; key handle is live for the duration of the call.
    let hr = unsafe {
        NCryptEncrypt(
            key.raw(),
            plaintext.as_ptr(),
            plaintext.len() as u32,
            ptr::null(),
            buf.as_mut_ptr(),
            buf.len() as u32,
            &raw mut out_len,
            BCRYPT_BLOCK_PADDING,
        )
    };
    if hr != 0 {
        return Err(map_hresult("NCryptEncrypt", hr));
    }
    buf.truncate(out_len as usize);
    Ok(buf)
}

fn cng_decrypt(
    key: &NCryptHandle,
    ciphertext: &[u8],
) -> Result<crate::locked::Vec, Error> {
    let mut out_len: u32 = 0;
    // SAFETY: probe call to discover output length; output pointer is null as documented.
    let hr = unsafe {
        NCryptDecrypt(
            key.raw(),
            ciphertext.as_ptr(),
            ciphertext.len() as u32,
            ptr::null(),
            ptr::null_mut(),
            0,
            &raw mut out_len,
            BCRYPT_BLOCK_PADDING,
        )
    };
    if hr != 0 {
        return Err(map_hresult("NCryptDecrypt(size)", hr));
    }
    let mut buf = vec![0u8; out_len as usize];
    // SAFETY: buf has capacity out_len; key handle is live for the duration of the call.
    let hr = unsafe {
        NCryptDecrypt(
            key.raw(),
            ciphertext.as_ptr(),
            ciphertext.len() as u32,
            ptr::null(),
            buf.as_mut_ptr(),
            buf.len() as u32,
            &raw mut out_len,
            BCRYPT_BLOCK_PADDING,
        )
    };
    if hr != 0 {
        return Err(map_hresult("NCryptDecrypt", hr));
    }
    let mut locked = crate::locked::Vec::new();
    locked.extend(buf[..out_len as usize].iter().copied());
    // Best-effort wipe of the transient buffer before drop.
    for b in &mut buf {
        *b = 0;
    }
    Ok(locked)
}

/// DPAPI-NG protection scoped to the current user. Returns the
/// protected blob, ready to be persisted.
fn dpapi_protect(plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let descriptor_w = wide("LOCAL=user");
    let mut descriptor: NCRYPT_DESCRIPTOR_HANDLE = ptr::null_mut();
    // SAFETY: descriptor string is valid PCWSTR; out-pointer is valid.
    let hr = unsafe {
        NCryptCreateProtectionDescriptor(
            descriptor_w.as_ptr(),
            0,
            &raw mut descriptor,
        )
    };
    if hr != 0 {
        return Err(map_hresult("NCryptCreateProtectionDescriptor", hr));
    }
    let mut blob_ptr: *mut u8 = ptr::null_mut();
    let mut blob_len: u32 = 0;
    // SAFETY: descriptor is live; plaintext pointer/len is valid; out-pointers are valid.
    let hr = unsafe {
        NCryptProtectSecret(
            descriptor,
            0,
            plaintext.as_ptr(),
            plaintext.len() as u32,
            ptr::null(),
            ptr::null_mut(),
            &raw mut blob_ptr,
            &raw mut blob_len,
        )
    };
    // SAFETY: descriptor handle was successfully allocated above.
    unsafe {
        NCryptFreeObject(descriptor.addr());
    }
    if hr != 0 {
        return Err(map_hresult("NCryptProtectSecret", hr));
    }
    // SAFETY: NCrypt allocates blob_ptr with LocalAlloc; we copy then LocalFree it.
    let copied = unsafe {
        std::slice::from_raw_parts(blob_ptr, blob_len as usize).to_vec()
    };
    // SAFETY: blob_ptr came from NCrypt's LocalAlloc-equivalent; freeing once.
    unsafe {
        LocalFree(blob_ptr.cast::<c_void>());
    }
    Ok(copied)
}

fn dpapi_unprotect(ciphertext: &[u8]) -> Result<crate::locked::Vec, Error> {
    let mut descriptor: NCRYPT_DESCRIPTOR_HANDLE = ptr::null_mut();
    let mut blob_ptr: *mut u8 = ptr::null_mut();
    let mut blob_len: u32 = 0;
    // SAFETY: ciphertext slice is valid; out-pointers are valid for the call.
    let hr = unsafe {
        NCryptUnprotectSecret(
            &raw mut descriptor,
            0,
            ciphertext.as_ptr(),
            ciphertext.len() as u32,
            ptr::null(),
            ptr::null_mut(),
            &raw mut blob_ptr,
            &raw mut blob_len,
        )
    };
    if !descriptor.is_null() {
        // SAFETY: descriptor was populated by NCryptUnprotectSecret on success.
        unsafe {
            NCryptFreeObject(descriptor.addr());
        }
    }
    if hr != 0 {
        return Err(map_hresult("NCryptUnprotectSecret", hr));
    }
    let mut locked = crate::locked::Vec::new();
    // SAFETY: NCrypt allocated blob_ptr; we copy then LocalFree it.
    unsafe {
        let slice = std::slice::from_raw_parts(blob_ptr, blob_len as usize);
        locked.extend(slice.iter().copied());
        // Wipe the OS-allocated buffer before freeing.
        for i in 0..blob_len as usize {
            *blob_ptr.add(i) = 0;
        }
        LocalFree(blob_ptr.cast::<c_void>());
    }
    Ok(locked)
}

pub fn store(label: &str, secret: &[u8]) -> Result<(), Error> {
    let path = ciphertext_path(label);
    if let Some(parent) = path.parent() {
        let _ = crate::dirs::make_all();
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::Os(format!("mkdir: {e}")))?;
    }

    // CNG path first (TPM, then software KSP).
    if let Ok((prov, tpm_backed)) = open_provider() {
        if !tpm_backed {
            log::warn!(
                "biometric: storing wrapper key under software KSP \
                 (no TPM); biometric ACL still applies"
            );
        }
        // Best-effort: delete any prior key under this label so create
        // with OVERWRITE doesn't strand old material in an unfinalized
        // state. Errors here are swallowed — overwrite covers the
        // happy-path.
        if let Ok(existing) = open_key(&prov, label) {
            // SAFETY: existing key handle is live; deleting it consumes the handle.
            unsafe {
                NCryptDeleteKey(existing.raw(), 0);
            }
            std::mem::forget(existing); // delete consumes the handle
        }
        let key = create_ui_protected_key(&prov, label)?;
        let mut blob = cng_encrypt(&key, secret)?;
        let mut out = Vec::with_capacity(blob.len() + 1);
        out.push(VERSION_CNG);
        out.append(&mut blob);
        write_file(&path, &out)?;
        return Ok(());
    }

    // DPAPI-NG fallback — no biometric ACL, just user-scope encryption.
    log::warn!(
        "biometric: no CNG provider available; falling back to DPAPI-NG \
         (no biometric ACL — UserConsentVerifier still gates use)"
    );
    let blob = dpapi_protect(secret)?;
    let mut out = Vec::with_capacity(blob.len() + 1);
    out.push(VERSION_DPAPI_NG);
    out.extend_from_slice(&blob);
    write_file(&path, &out)?;
    Ok(())
}

pub fn load(label: &str, _prompt: &str) -> Result<crate::locked::Vec, Error> {
    let path = ciphertext_path(label);
    let bytes = std::fs::read(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            Error::NotFound
        } else {
            Error::Os(format!("read {}: {e}", path.display()))
        }
    })?;
    let (&tag, rest) = bytes
        .split_first()
        .ok_or_else(|| Error::Os("empty ciphertext file".into()))?;
    match tag {
        VERSION_CNG => {
            let (prov, _tpm) = open_provider()?;
            let key = open_key(&prov, label)?;
            cng_decrypt(&key, rest)
        }
        VERSION_DPAPI_NG => dpapi_unprotect(rest),
        other => Err(Error::Os(format!(
            "unknown biometric blob version tag 0x{other:02x}"
        ))),
    }
}

pub fn delete(label: &str) -> Result<(), Error> {
    let path = ciphertext_path(label);
    let tag = std::fs::read(&path).ok().and_then(|b| b.first().copied());
    if matches!(tag, Some(VERSION_CNG)) {
        if let Ok((prov, _tpm)) = open_provider() {
            if let Ok(key) = open_key(&prov, label) {
                // SAFETY: key handle is live; NCryptDeleteKey consumes it.
                let hr = unsafe { NCryptDeleteKey(key.raw(), 0) };
                std::mem::forget(key); // consumed by delete
                if hr != 0 && hr != NTE_BAD_KEYSET && hr != NTE_NOT_FOUND {
                    log::warn!(
                        "biometric: NCryptDeleteKey failed: HRESULT 0x{:08x}",
                        hr as u32
                    );
                }
            }
        }
    }
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::Os(format!("remove {}: {e}", path.display()))),
    }
}

pub fn exists(label: &str) -> Result<bool, Error> {
    Ok(ciphertext_path(label).exists())
}

fn write_file(path: &std::path::Path, bytes: &[u8]) -> Result<(), Error> {
    use std::io::Write as _;
    let mut fh = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|e| Error::Os(format!("open {}: {e}", path.display())))?;
    fh.write_all(bytes)
        .map_err(|e| Error::Os(format!("write {}: {e}", path.display())))?;
    Ok(())
}
