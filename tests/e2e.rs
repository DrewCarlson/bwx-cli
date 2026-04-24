//! End-to-end integration tests for rbw against a real Vaultwarden server.
//!
//! # Running
//!
//! These tests are marked `#[ignore]` so the default `cargo test` run stays
//! fast. To run them you need a `vaultwarden` binary installed locally:
//!
//! ```sh
//! cargo install --git https://github.com/dani-garcia/vaultwarden \
//!     --features sqlite --locked
//! ```
//!
//! Then run with:
//!
//! ```sh
//! cargo test --test e2e -- --ignored --test-threads=1
//! ```
//!
//! Tests currently require `--test-threads=1`. Running fully parallel
//! occasionally surfaces a race in `rbw-agent` startup (child processes
//! forked across threads sometimes fail to answer the first message on the
//! IPC socket). The tests themselves are isolated at the filesystem + port
//! layer; the bug is in the product, not the harness. Fix the race in a
//! follow-up and drop this restriction.
//!
//! By default the harness looks up `vaultwarden` on `$PATH`. Override with
//! `VAULTWARDEN_BIN=/path/to/vaultwarden` if it lives elsewhere. If the binary
//! cannot be found the scenarios print a helpful message and exit early
//! (tests still report as passing because they are `#[ignore]`-only).
//!
//! Each scenario spins up its own isolated Vaultwarden instance on an
//! ephemeral port and its own tempdir acting as `XDG_*` for rbw, so tests can
//! run in parallel without stomping on each other.

mod common;
mod scenarios;
