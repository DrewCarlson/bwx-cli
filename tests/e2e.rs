//! End-to-end integration tests for bwx against a real Vaultwarden server.
//!
//! Tests are marked `#[ignore]`; run with `cargo test --test e2e -- --ignored`
//! after installing a `vaultwarden` binary (override location with
//! `VAULTWARDEN_BIN`). Each scenario owns an ephemeral Vaultwarden instance
//! and isolated XDG dirs so they run in parallel without collisions.

mod common;
mod scenarios;
