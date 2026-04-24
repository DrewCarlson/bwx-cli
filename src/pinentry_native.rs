//! Native macOS secure-text prompt for the master password.
//!
//! Shells out to `/usr/bin/osascript` with `display dialog` + `with
//! hidden answer` to render the modern Aqua system dialog (proper
//! Apple-native buttons, shadow, rounded corners, automatic dark-mode
//! theming). Unlike pinentry, it doesn't need a TTY or X11/DBus
//! session; the dialog is rendered by `WindowServer` and will appear
//! even for daemonized callers (GUI git signing, ssh-agent from a
//! Finder-launched IDE).
//!
//! On non-macOS builds this module exposes the same function
//! signature but returns an error, so callers can fall back to
//! pinentry without cfg-guarding every call site.
#![allow(clippy::doc_markdown)]

use crate::locked;
use crate::prelude::Error;

/// Blocks the calling thread until the user dismisses the dialog.
/// Callers should wrap in `tokio::task::spawn_blocking` to avoid
/// stalling the tokio runtime.
///
/// `title` is the bold first line of the dialog; `message` is the body
/// text shown beneath it.
pub fn prompt_master_password(
    title: &str,
    message: &str,
) -> Result<locked::Password, Error> {
    #[cfg(target_os = "macos")]
    {
        imp::prompt_master_password(title, message)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (title, message);
        Err(Error::NativePromptUnsupported)
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use std::process::Command;

    use super::{locked, Error};

    /// AppleScript double-quoted-string escape: backslash + double
    /// quote. We never interpolate user-attacker-controlled strings
    /// here, but harden anyway because the `title` and `message`
    /// arguments are composed from profile names / error messages.
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

    pub fn prompt_master_password(
        title: &str,
        message: &str,
    ) -> Result<locked::Password, Error> {
        // `display dialog` renders the modern Aqua secure-input dialog;
        // `with icon caution` gives it the system-warning styling so it
        // visually cues that it's an authentication prompt.
        let script = format!(
            "display dialog {msg} with title {title} \
             default answer \"\" with hidden answer \
             buttons {{\"Cancel\", \"Unlock\"}} default button \"Unlock\" \
             with icon caution",
            msg = escape(message),
            title = escape(title),
        );

        let output = Command::new("/usr/bin/osascript")
            .arg("-e")
            .arg(&script)
            .output()
            .map_err(|e| Error::NativePromptFailed {
                code: e.raw_os_error().unwrap_or(-1),
                stage: "osascript spawn",
            })?;

        if !output.status.success() {
            // osascript exits non-zero on Cancel. Distinguish that
            // (very common) case from a real failure.
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
        //   "button returned:Unlock, text returned:<password>\n"
        // to stdout. Find the text-returned marker and take everything
        // after it (stripping the trailing newline). This is robust
        // against passwords containing commas because the marker is a
        // unique substring.
        let Ok(stdout) = std::str::from_utf8(&output.stdout) else {
            return Err(Error::NativePromptFailed {
                code: 0,
                stage: "osascript stdout utf8",
            });
        };
        let password_str = stdout
            .find(MARKER)
            .map(|idx| stdout[idx + MARKER.len()..].trim_end_matches('\n'))
            .ok_or(Error::NativePromptFailed {
                code: 0,
                stage: "osascript stdout parse",
            })?;

        let mut buf = locked::Vec::new();
        buf.extend(password_str.as_bytes().iter().copied());
        Ok(locked::Password::new(buf))
    }
}
