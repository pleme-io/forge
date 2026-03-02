//! CI test runner (nextest with fallback to cargo test)
//!
//! Replaces product-sdlc.nix::test:ci.

use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::Command;
use tracing::info;

/// Run tests in CI mode: prefer cargo-nextest, fall back to cargo test.
pub fn execute(working_dir: &str, threads: u32) -> Result<()> {
    let dir = Path::new(working_dir);
    if !dir.exists() {
        bail!("Working directory not found: {}", working_dir);
    }

    if which::which("cargo-nextest").is_ok() {
        info!("Running tests with cargo nextest (threads={})...", threads);
        let status = Command::new("cargo")
            .args([
                "nextest",
                "run",
                "--profile",
                "ci",
                "--test-threads",
                &threads.to_string(),
            ])
            .current_dir(dir)
            .status()
            .context("Failed to run cargo nextest")?;

        if !status.success() {
            bail!("cargo nextest run failed");
        }
    } else {
        info!("cargo-nextest not found, falling back to cargo test (threads={})...", threads);
        let status = Command::new("cargo")
            .args([
                "test",
                "--no-fail-fast",
                "--",
                "--test-threads",
                &threads.to_string(),
            ])
            .current_dir(dir)
            .status()
            .context("Failed to run cargo test")?;

        if !status.success() {
            bail!("cargo test failed");
        }
    }

    info!("All tests passed");
    Ok(())
}

/// Run tests with coverage via cargo-tarpaulin.
pub fn coverage(working_dir: &str, format: &str) -> Result<()> {
    let dir = Path::new(working_dir);
    if !dir.exists() {
        bail!("Working directory not found: {}", working_dir);
    }

    if which::which("cargo-tarpaulin").is_err() {
        info!("Installing cargo-tarpaulin...");
        let status = Command::new("cargo")
            .args(["install", "cargo-tarpaulin"])
            .status()
            .context("Failed to install cargo-tarpaulin")?;

        if !status.success() {
            bail!("cargo install cargo-tarpaulin failed");
        }
    }

    info!("Running coverage with cargo tarpaulin (format={})...", format);
    let status = Command::new("cargo")
        .args(["tarpaulin", "--out", format])
        .current_dir(dir)
        .status()
        .context("Failed to run cargo tarpaulin")?;

    if !status.success() {
        bail!("cargo tarpaulin failed");
    }

    info!("Coverage report generated ({})", format);
    Ok(())
}
