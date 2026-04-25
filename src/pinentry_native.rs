//! Native macOS secure-text prompt for the master password and other short
//! inputs (2FA codes, etc.).
//!
//! Shells out to `/usr/bin/osascript` with `display dialog`. Unlike pinentry
//! it needs no TTY or X11/DBus session, so the dialog appears even for
//! daemonized callers (GUI git signing, ssh-agent from a Finder-launched IDE).
//! On non-macOS builds the function returns an error so callers can fall back
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
    #[cfg(not(target_os = "macos"))]
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
