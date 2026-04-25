use zeroize::Zeroize as _;

use super::find::{find_entry, parse_needle};
use super::util::load_db;
use crate::bin_error::{self, ContextExt as _};

/// Parsed `--env VAR=ENTRY[#FIELD]` argument for `bwx exec`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvSpec {
    pub var: String,
    pub entry: String,
    pub field: Option<String>,
}

impl EnvSpec {
    /// Parse a single `VAR=ENTRY[#FIELD]` literal.
    ///
    /// `VAR` is a POSIX-style identifier (`[A-Za-z_][A-Za-z0-9_]*`).
    /// `ENTRY` is whatever `bwx get` accepts: name, UUID, or URI. The
    /// field defaults to `password` when the `#FIELD` suffix is absent.
    pub fn parse(spec: &str) -> bin_error::Result<Self> {
        let (var, rest) = spec.split_once('=').ok_or_else(|| {
            crate::bin_error::err!(
                "bad --env spec '{spec}': expected VAR=ENTRY[#FIELD]"
            )
        })?;
        if var.is_empty() {
            crate::bin_error::bail!(
                "bad --env spec '{spec}': empty env var name"
            );
        }
        let mut chars = var.chars();
        let first = chars.next().expect("non-empty checked above");
        if !(first.is_ascii_alphabetic() || first == '_')
            || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            crate::bin_error::bail!(
                "bad --env spec '{spec}': '{var}' is not a valid env var name"
            );
        }
        let (entry, field) = match rest.rsplit_once('#') {
            Some((e, f)) if !f.is_empty() => (e, Some(f.to_string())),
            _ => (rest, None),
        };
        if entry.is_empty() {
            crate::bin_error::bail!(
                "bad --env spec '{spec}': empty entry name"
            );
        }
        Ok(Self {
            var: var.to_string(),
            entry: entry.to_string(),
            field,
        })
    }

    fn descriptor(&self) -> String {
        self.field.as_deref().map_or_else(
            || self.entry.clone(),
            |f| format!("{}#{f}", self.entry),
        )
    }
}

/// Run `<command>` with vault fields injected as environment variables.
///
/// Each `--env VAR=ENTRY[#FIELD]` resolves the field (defaulting to
/// `password`) on the named vault entry and adds it to the child's env
/// only — the value is never written to disk and is zeroized from the
/// parent's heap as soon as the child has been spawned.
pub fn exec(
    specs: &[String],
    folder: Option<&str>,
    ignore_case: bool,
    command: &[String],
) -> bin_error::Result<()> {
    if command.is_empty() {
        crate::bin_error::bail!(
            "no command given; usage: bwx exec --env VAR=ENTRY[#FIELD] -- <cmd> [args...]"
        );
    }
    let parsed: Vec<EnvSpec> = specs
        .iter()
        .map(|s| EnvSpec::parse(s))
        .collect::<bin_error::Result<_>>()?;

    let mut seen = std::collections::HashSet::new();
    for s in &parsed {
        if !seen.insert(s.var.clone()) {
            crate::bin_error::bail!(
                "duplicate --env binding for '{}'",
                s.var
            );
        }
    }

    super::auth::unlock()?;
    let db = load_db()?;

    let mut values: Vec<(String, String)> = Vec::with_capacity(parsed.len());
    for spec in &parsed {
        let needle = parse_needle(&spec.entry).expect("infallible");
        let (_, decrypted) =
            find_entry(&db, needle, None, folder, ignore_case).with_context(
                || format!("couldn't find entry for '{}'", spec.descriptor()),
            )?;
        let field = spec.field.as_deref().unwrap_or("password");
        let value = decrypted.field_value(field).ok_or_else(|| {
            crate::bin_error::err!(
                "field '{field}' not found on entry '{}'",
                spec.entry
            )
        })?;
        values.push((spec.var.clone(), value));
    }

    let mut cmd = std::process::Command::new(&command[0]);
    cmd.args(&command[1..]);
    for (k, v) in &values {
        cmd.env(k, v);
    }
    let status = cmd
        .status()
        .with_context(|| format!("failed to spawn '{}'", &command[0]))?;

    // Best-effort scrub of in-process plaintext copies. The child has
    // already received its own copy of the env via execve(); nothing the
    // parent can do about that.
    for (_, v) in &mut values {
        v.zeroize();
    }
    drop(values);

    if let Some(code) = status.code() {
        std::process::exit(code);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        if let Some(sig) = status.signal() {
            // Shell convention: 128 + signal number.
            std::process::exit(128 + sig);
        }
    }
    std::process::exit(1);
}
