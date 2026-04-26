//! Stderr logger gated by a single config boolean.
//!
//! When `logging` is `true` (the default), records from our crates at level
//! `debug` and above (`debug`/`warn`/`error`) are written to stderr. When
//! `false`, nothing is emitted. Output is restricted to our crates so
//! third-party libraries don't pollute the terminal.
//!
//! `RUST_LOG` is still honored when set — useful for ad-hoc debugging — and
//! is parsed as an `env_logger`-style spec with the configured baseline as
//! the fallback default.

use std::io::Write as _;
use std::sync::OnceLock;

use log::{Level, LevelFilter, Log, Metadata, Record};

/// Crate-name prefixes whose log records should be emitted by default.
/// Anything else only emits when `RUST_LOG` explicitly opts it in.
const OUR_CRATES: &[&str] = &["bwx", "bwx_agent"];

struct Logger {
    default: LevelFilter,
    modules: Vec<(String, LevelFilter)>,
}

impl Logger {
    fn level_for(&self, target: &str) -> LevelFilter {
        let mut best: Option<(usize, LevelFilter)> = None;
        for (module, lvl) in &self.modules {
            let matches = target == module
                || (target.starts_with(module)
                    && target.as_bytes().get(module.len()) == Some(&b':'));
            if matches && best.is_none_or(|(len, _)| module.len() > len) {
                best = Some((module.len(), *lvl));
            }
        }
        best.map_or(self.default, |(_, l)| l)
    }
}

impl Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        self.level_for(metadata.target()) >= metadata.level()
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let stderr = std::io::stderr();
        let mut h = stderr.lock();
        let _ = match record.level() {
            Level::Error => writeln!(h, "error: {}", record.args()),
            Level::Warn => writeln!(h, "warning: {}", record.args()),
            // Info shouldn't normally fire (we don't ship info-level
            // sources), but render it cleanly if some dependency does.
            Level::Info => writeln!(h, "{}", record.args()),
            Level::Debug => {
                writeln!(h, "debug [{}] {}", record.target(), record.args())
            }
            Level::Trace => {
                writeln!(h, "trace [{}] {}", record.target(), record.args())
            }
        };
    }

    fn flush(&self) {
        let _ = std::io::stderr().flush();
    }
}

static LOGGER: OnceLock<Logger> = OnceLock::new();

fn parse_level(s: &str) -> Option<LevelFilter> {
    match s.trim().to_ascii_lowercase().as_str() {
        "off" => Some(LevelFilter::Off),
        "error" => Some(LevelFilter::Error),
        "warn" => Some(LevelFilter::Warn),
        "info" => Some(LevelFilter::Info),
        "debug" => Some(LevelFilter::Debug),
        "trace" => Some(LevelFilter::Trace),
        _ => None,
    }
}

fn parse_spec(
    spec: &str,
    fallback: LevelFilter,
) -> (LevelFilter, Vec<(String, LevelFilter)>) {
    let mut default = fallback;
    let mut modules = Vec::new();
    for part in spec.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        if let Some((module, lvl)) = part.split_once('=') {
            if let Some(lvl) = parse_level(lvl) {
                modules.push((module.trim().to_string(), lvl));
            }
        } else if let Some(lvl) = parse_level(part) {
            default = lvl;
        }
    }
    (default, modules)
}

/// Initialize the global logger.
///
/// `enabled` is the configured baseline: `true` emits records at `debug`
/// and above from our crates, `false` silences everything. `RUST_LOG`, if
/// set, takes precedence and is parsed as an `env_logger`-style spec
/// using the configured baseline as the default level.
pub fn init(enabled: bool) {
    let baseline = if enabled {
        LevelFilter::Debug
    } else {
        LevelFilter::Off
    };
    let env = std::env::var("RUST_LOG").unwrap_or_default();
    let (default, modules) = if env.trim().is_empty() {
        let modules = OUR_CRATES
            .iter()
            .map(|c| ((*c).to_string(), baseline))
            .collect();
        (LevelFilter::Off, modules)
    } else {
        parse_spec(&env, baseline)
    };

    let max = modules
        .iter()
        .map(|(_, l)| *l)
        .chain(std::iter::once(default))
        .max()
        .unwrap_or(LevelFilter::Off);

    let logger = LOGGER.get_or_init(|| Logger { default, modules });

    let _ = log::set_logger(logger);
    log::set_max_level(max);
}

/// Format a `Duration` in a friendly form: `523ms`, `2.341s`, `1m 32s`, `5m`.
#[must_use]
pub fn format_duration(d: std::time::Duration) -> String {
    let secs = d.as_secs();
    let millis = d.subsec_millis();
    if secs >= 60 {
        let m = secs / 60;
        let s = secs % 60;
        if s == 0 {
            format!("{m}m")
        } else {
            format!("{m}m {s}s")
        }
    } else if secs > 0 {
        if millis == 0 {
            format!("{secs}s")
        } else {
            format!("{secs}.{millis:03}s")
        }
    } else {
        format!("{millis}ms")
    }
}

/// Time `$body` and emit a debug record with the elapsed duration.
///
/// When debug is disabled the body runs without any timing instrumentation —
/// no `Instant`, no string formatting — so this is safe on hot paths.
#[macro_export]
macro_rules! debug_time {
    ($label:expr, $body:expr $(,)?) => {{
        if ::log::log_enabled!(::log::Level::Debug) {
            let __bwx_start = ::std::time::Instant::now();
            let __bwx_result = $body;
            ::log::debug!(
                "{} ({})",
                $label,
                $crate::logger::format_duration(__bwx_start.elapsed()),
            );
            __bwx_result
        } else {
            $body
        }
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_level() {
        let (d, m) = parse_spec("debug", LevelFilter::Info);
        assert_eq!(d, LevelFilter::Debug);
        assert!(m.is_empty());
    }

    #[test]
    fn default_and_modules() {
        let (d, m) = parse_spec("info,bwx=debug", LevelFilter::Warn);
        assert_eq!(d, LevelFilter::Info);
        assert_eq!(m, vec![("bwx".to_string(), LevelFilter::Debug)]);
    }

    #[test]
    fn trailing_default() {
        let (d, m) = parse_spec("bwx_agent=trace,warn", LevelFilter::Info);
        assert_eq!(d, LevelFilter::Warn);
        assert_eq!(m, vec![("bwx_agent".to_string(), LevelFilter::Trace)]);
    }

    #[test]
    fn empty_uses_fallback() {
        let (d, m) = parse_spec("", LevelFilter::Info);
        assert_eq!(d, LevelFilter::Info);
        assert!(m.is_empty());
    }

    #[test]
    fn level_for_module_prefix() {
        let logger = Logger {
            default: LevelFilter::Off,
            modules: vec![("bwx".to_string(), LevelFilter::Debug)],
        };
        assert_eq!(logger.level_for("bwx"), LevelFilter::Debug);
        assert_eq!(logger.level_for("bwx::config"), LevelFilter::Debug);
        assert_eq!(logger.level_for("other"), LevelFilter::Off);
        assert_eq!(logger.level_for("bwxx"), LevelFilter::Off);
    }

    #[test]
    fn duration_formatting() {
        use std::time::Duration;
        assert_eq!(format_duration(Duration::from_millis(523)), "523ms");
        assert_eq!(format_duration(Duration::from_millis(2341)), "2.341s");
        assert_eq!(format_duration(Duration::from_secs(5)), "5s");
        assert_eq!(format_duration(Duration::from_secs(92)), "1m 32s");
        assert_eq!(format_duration(Duration::from_secs(300)), "5m");
    }
}
