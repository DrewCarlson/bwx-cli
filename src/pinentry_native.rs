//! Native secure-text prompt for the master password and other short
//! inputs (2FA codes, etc.).
//!
//! On macOS, shells out to `/usr/bin/osascript` with `display dialog`. On
//! Windows, calls `CredUIPromptForWindowsCredentialsW`. Unlike pinentry,
//! these need no TTY or X11/DBus session, so the dialog appears even for
//! daemonized callers (GUI git signing, ssh-agent from a Finder-launched IDE).
//! On other platforms the function returns an error so callers can fall back
//! to pinentry without cfg-guarding every call site.
#![allow(clippy::doc_markdown)]

use crate::locked;
use crate::prelude::Error;

/// Whether the dialog should mask typed characters.
#[derive(Copy, Clone, Debug)]
pub enum InputKind {
    Secret,
    Visible,
}

/// Blocks the calling thread until the user dismisses the dialog. Callers
/// should wrap in `tokio::task::spawn_blocking` to avoid stalling the tokio
/// runtime.
pub fn prompt(
    title: &str,
    message: &str,
    button: &str,
    kind: InputKind,
) -> Result<locked::Password, Error> {
    #[cfg(target_os = "macos")]
    {
        imp::prompt(title, message, button, kind)
    }
    #[cfg(target_os = "windows")]
    {
        let _ = button;
        imp_win::prompt(title, message, kind)
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = (title, message, button, kind);
        Err(Error::NativePromptUnsupported)
    }
}

pub fn prompt_master_password(
    title: &str,
    message: &str,
) -> Result<locked::Password, Error> {
    prompt(title, message, "Unlock", InputKind::Secret)
}

#[cfg(target_os = "macos")]
mod imp {
    use std::process::Command;

    use zeroize::Zeroize as _;

    use super::{locked, Error, InputKind};

    /// AppleScript double-quoted-string escape: backslash + double quote.
    /// `title` and `message` are composed from profile names / error
    /// messages, so escape even though no attacker-controlled input reaches
    /// here today.
    fn escape(s: &str) -> String {
        let mut out = String::with_capacity(s.len() + 2);
        out.push('"');
        for ch in s.chars() {
            match ch {
                '\\' | '"' => {
                    out.push('\\');
                    out.push(ch);
                }
                _ => out.push(ch),
            }
        }
        out.push('"');
        out
    }

    const MARKER: &str = ", text returned:";

    pub fn prompt(
        title: &str,
        message: &str,
        button: &str,
        kind: InputKind,
    ) -> Result<locked::Password, Error> {
        let hidden = match kind {
            InputKind::Secret => "with hidden answer",
            InputKind::Visible => "",
        };
        let script = format!(
            "display dialog {msg} with title {title} \
             default answer \"\" {hidden} \
             buttons {{\"Cancel\", {btn}}} default button {btn} \
             with icon caution",
            msg = escape(message),
            title = escape(title),
            btn = escape(button),
        );

        let mut output = Command::new("/usr/bin/osascript")
            .arg("-e")
            .arg(&script)
            .output()
            .map_err(|e| Error::NativePromptFailed {
                code: e.raw_os_error().unwrap_or(-1),
                stage: "osascript spawn",
            })?;

        // Zero the stdout buffer (which contains the typed password on the
        // success path) before `output` drops, regardless of which branch
        // exits.
        let result = extract_password(&output);
        output.stdout.zeroize();
        output.stderr.zeroize();
        result
    }

    fn extract_password(
        output: &std::process::Output,
    ) -> Result<locked::Password, Error> {
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("User canceled") || stderr.contains("-128") {
                return Err(Error::PinentryCancelled);
            }
            return Err(Error::NativePromptFailed {
                code: output.status.code().unwrap_or(-1),
                stage: "osascript exit",
            });
        }

        // osascript writes one line of the form
        //   "button returned:Unlock, text returned:<value>\n"
        // to stdout. Take everything after the text-returned marker.
        let Ok(stdout) = std::str::from_utf8(&output.stdout) else {
            return Err(Error::NativePromptFailed {
                code: 0,
                stage: "osascript stdout utf8",
            });
        };
        let value_str = stdout
            .find(MARKER)
            .map(|idx| stdout[idx + MARKER.len()..].trim_end_matches('\n'))
            .ok_or(Error::NativePromptFailed {
                code: 0,
                stage: "osascript stdout parse",
            })?;

        let mut buf = locked::Vec::new();
        buf.extend(value_str.as_bytes().iter().copied());
        Ok(locked::Password::new(buf))
    }
}

#[cfg(target_os = "windows")]
mod imp_win {
    use std::ffi::c_void;
    use std::ptr;

    use windows_sys::Win32::Foundation::{ERROR_CANCELLED, ERROR_INSUFFICIENT_BUFFER};
    use windows_sys::Win32::Security::Credentials::{
        CredPackAuthenticationBufferW, CredUIPromptForWindowsCredentialsW,
        CredUnPackAuthenticationBufferW, CREDUIWIN_GENERIC, CREDUI_INFOW,
        CRED_PACK_GENERIC_CREDENTIALS,
    };
    use windows_sys::Win32::System::Com::CoTaskMemFree;

    use super::{locked, Error, InputKind};

    use crate::win::wide::str_to_utf16_nul as to_wide;

    /// Volatile-write zero loop. `windows-sys` doesn't expose
    /// `SecureZeroMemory`, but a `write_volatile` byte loop is equivalent
    /// and won't be optimized away.
    unsafe fn secure_zero(ptr: *mut u8, len: usize) {
        for i in 0..len {
            // SAFETY: caller guarantees `ptr..ptr+len` is a valid writable range.
            unsafe { ptr::write_volatile(ptr.add(i), 0) };
        }
    }

    fn u32_to_usize(n: u32) -> usize {
        usize::try_from(n).unwrap_or(usize::MAX)
    }

    pub fn prompt(
        title: &str,
        message: &str,
        kind: InputKind,
    ) -> Result<locked::Password, Error> {
        // Visible-mode prompts (2FA codes) aren't naturally supported by the
        // Windows credential UI; fall back to pinentry/console at the caller.
        if matches!(kind, InputKind::Visible) {
            return Err(Error::NativePromptUnsupported);
        }

        let wide_title = to_wide(title);
        let wide_message = to_wide(message);

        let info = CREDUI_INFOW {
            cbSize: u32::try_from(std::mem::size_of::<CREDUI_INFOW>()).unwrap_or(0),
            hwndParent: ptr::null_mut(),
            pszMessageText: wide_message.as_ptr(),
            pszCaptionText: wide_title.as_ptr(),
            hbmBanner: ptr::null_mut(),
        };

        // Pre-pack an empty username so the dialog doesn't try to populate
        // the field from the current logged-in user; we ignore whatever
        // username comes back.
        let mut empty_user = to_wide("");
        let mut empty_pass = to_wide("");
        let mut in_buf_size: u32 = 0;
        // SAFETY: first call with null output to query required buffer size.
        unsafe {
            CredPackAuthenticationBufferW(
                CRED_PACK_GENERIC_CREDENTIALS,
                empty_user.as_mut_ptr(),
                empty_pass.as_mut_ptr(),
                ptr::null_mut(),
                &raw mut in_buf_size,
            );
        }
        let mut in_buf: Vec<u8> = vec![0u8; u32_to_usize(in_buf_size)];
        let in_buf_ptr: *mut c_void = if in_buf.is_empty() {
            ptr::null_mut()
        } else {
            in_buf.as_mut_ptr().cast::<c_void>()
        };
        if !in_buf.is_empty() {
            // SAFETY: second call fills `in_buf` with `in_buf_size` bytes.
            unsafe {
                CredPackAuthenticationBufferW(
                    CRED_PACK_GENERIC_CREDENTIALS,
                    empty_user.as_mut_ptr(),
                    empty_pass.as_mut_ptr(),
                    in_buf.as_mut_ptr(),
                    &raw mut in_buf_size,
                );
            }
        }

        let mut auth_package: u32 = 0;
        let mut out_buf: *mut c_void = ptr::null_mut();
        let mut out_size: u32 = 0;
        let mut save: i32 = 0;

        // SAFETY: `info` is a valid CREDUI_INFOW; out pointers are owned locals.
        let r = unsafe {
            CredUIPromptForWindowsCredentialsW(
                &raw const info,
                0,
                &raw mut auth_package,
                in_buf_ptr,
                in_buf_size,
                &raw mut out_buf,
                &raw mut out_size,
                &raw mut save,
                CREDUIWIN_GENERIC,
            )
        };

        if r == ERROR_CANCELLED {
            return Err(Error::PinentryCancelled);
        }
        if r != 0 {
            return Err(Error::NativePromptFailed {
                code: i32::try_from(r).unwrap_or(-1),
                stage: "CredUIPromptForWindowsCredentialsW",
            });
        }

        let result = extract_password(out_buf, out_size);

        if !out_buf.is_null() {
            // SAFETY: `out_buf` is `out_size` bytes allocated by the OS for us.
            unsafe {
                secure_zero(out_buf.cast::<u8>(), u32_to_usize(out_size));
                CoTaskMemFree(out_buf);
            }
        }

        result
    }

    fn extract_password(
        out_buf: *mut c_void,
        out_size: u32,
    ) -> Result<locked::Password, Error> {
        if out_buf.is_null() || out_size == 0 {
            return Err(Error::NativePromptFailed {
                code: 0,
                stage: "CredUIPromptForWindowsCredentialsW empty",
            });
        }

        // First call: probe sizes (in characters incl. NUL).
        let mut user_len: u32 = 0;
        let mut domain_len: u32 = 0;
        let mut pass_len: u32 = 0;
        // SAFETY: probe call with null output buffers; sets *_len on failure.
        unsafe {
            CredUnPackAuthenticationBufferW(
                0,
                out_buf,
                out_size,
                ptr::null_mut(),
                &raw mut user_len,
                ptr::null_mut(),
                &raw mut domain_len,
                ptr::null_mut(),
                &raw mut pass_len,
            );
        }
        let last = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if i64::from(last) != i64::from(ERROR_INSUFFICIENT_BUFFER) && pass_len == 0 {
            return Err(Error::NativePromptFailed {
                code: last,
                stage: "CredUnPackAuthenticationBufferW probe",
            });
        }

        let mut user_buf: Vec<u16> = vec![0u16; u32_to_usize(user_len.max(1))];
        let mut domain_buf: Vec<u16> = vec![0u16; u32_to_usize(domain_len.max(1))];
        let mut pass_buf: Vec<u16> = vec![0u16; u32_to_usize(pass_len.max(1))];

        // SAFETY: buffers sized per probe call above.
        let ok = unsafe {
            CredUnPackAuthenticationBufferW(
                0,
                out_buf,
                out_size,
                user_buf.as_mut_ptr(),
                &raw mut user_len,
                domain_buf.as_mut_ptr(),
                &raw mut domain_len,
                pass_buf.as_mut_ptr(),
                &raw mut pass_len,
            )
        };
        if ok == 0 {
            // Scrub anything that may have been written.
            zero_u16(&mut pass_buf);
            return Err(Error::NativePromptFailed {
                code: std::io::Error::last_os_error().raw_os_error().unwrap_or(-1),
                stage: "CredUnPackAuthenticationBufferW",
            });
        }

        // Drop NUL terminator from the count if present.
        let pass_chars = u32_to_usize(pass_len);
        let pass_chars = if pass_chars > 0
            && pass_buf.get(pass_chars.saturating_sub(1)).copied() == Some(0)
        {
            pass_chars - 1
        } else {
            pass_chars
        };

        let mut buf = locked::Vec::new();
        // Encode UTF-16 -> UTF-8 manually into mlocked storage so the
        // intermediate `String` never holds the secret.
        for ch in std::char::decode_utf16(pass_buf[..pass_chars].iter().copied()) {
            let c = ch.unwrap_or(std::char::REPLACEMENT_CHARACTER);
            let mut tmp = [0u8; 4];
            let s = c.encode_utf8(&mut tmp);
            buf.extend(s.as_bytes().iter().copied());
            // Scrub the stack scratch.
            for b in &mut tmp {
                // SAFETY: `tmp` lives on the stack; volatile write to local.
                unsafe { ptr::write_volatile(b, 0) };
            }
        }

        zero_u16(&mut pass_buf);
        zero_u16(&mut user_buf);
        zero_u16(&mut domain_buf);

        Ok(locked::Password::new(buf))
    }

    fn zero_u16(buf: &mut [u16]) {
        for w in buf.iter_mut() {
            // SAFETY: `w` is a valid mutable reference for the slice lifetime.
            unsafe { ptr::write_volatile(w, 0) };
        }
    }
}
