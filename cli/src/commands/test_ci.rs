//! CI test runner (nextest with fallback to cargo test)
//!
//! Replaces product-sdlc.nix::test:ci.

use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::Command;
use tracing::info;

use crate::repo::get_tool_path;

/// Run tests in CI mode: prefer cargo-nextest, fall back to cargo test.
pub fn execute(working_dir: &str, threads: u32) -> Result<()> {
    let dir = Path::new(working_dir);
    if !dir.exists() {
        bail!("Working directory not found: {}", working_dir);
    }

    let cargo = get_tool_path("CARGO", "cargo");

    if which::which("cargo-nextest").is_ok() {
        info!("Running tests with cargo nextest (threads={})...", threads);
        let status = Command::new(&cargo)
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
        let status = Command::new(&cargo)
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

    let cargo = get_tool_path("CARGO", "cargo");

    if which::which("cargo-tarpaulin").is_err() {
        info!("Installing cargo-tarpaulin...");
        let status = Command::new(&cargo)
            .args(["install", "cargo-tarpaulin"])
            .status()
            .context("Failed to install cargo-tarpaulin")?;

        if !status.success() {
            bail!("cargo install cargo-tarpaulin failed");
        }
    }

    info!("Running coverage with cargo tarpaulin (format={})...", format);
    let status = Command::new(&cargo)
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

#[cfg(test)]
mod tests {
    /// Whole-module shield: no raw `Command::new("cargo")` may live in
    /// this module's non-test body. Every `cargo` spawn in
    /// `commands/test_ci.rs` — the four sites in `execute` (nextest and
    /// the cargo-test fallback) and `coverage` (the tarpaulin install
    /// gate and the tarpaulin run itself) — must first resolve `CARGO`
    /// via [`crate::repo::get_tool_path`], the canonical env-var
    /// override every other cargo-invocation site in forge honors
    /// (`commands/bootstrap.rs:639`, `commands/pangea.rs:473`,
    /// `graphql_schema.rs:193`; the doc-comment idiom lives at
    /// `repo.rs:92`).
    ///
    /// Pre-lift each of the four sites spelled `Command::new("cargo")`
    /// verbatim and ignored `CARGO`. `test:ci` is invoked from
    /// `product-sdlc.nix` under a hermetic-runner sandbox that exports
    /// `CARGO=/nix/store/...-cargo/bin/cargo`; pre-lift the CI runner
    /// silently fell through to whatever `cargo` the wrapper's PATH
    /// found first — the same silent-PATH-fallback bug class the
    /// `developer_tools.rs` CARGO lift (8687093), the `NIX_BIN`
    /// migration (4dfb2b3), and the `KUBECTL_BIN`/`GIT_BIN` migrations
    /// (5bb7cff, 818ed9a) closed on their respective spawn surfaces.
    ///
    /// The scan bounds on the whole-module boundary (from the file
    /// start to the `\n#[cfg(test)]\nmod tests {` marker above) so
    /// this shield's own docstring mentions of `Command::new("cargo")`
    /// (which live inside this `#[cfg(test)] mod tests` block) stay
    /// out of scope AND every current or future cargo-spawning helper
    /// landing anywhere in the top-level module body cannot silently
    /// ride along without going through `CARGO`. Mirrors the sibling
    /// `CARGO` shield in `commands/developer_tools.rs` (8687093) and
    /// the whole-module-boundary scan discipline pioneered on
    /// `commands/supergraph_verification.rs` (65283fb).
    #[test]
    fn test_test_ci_routes_cargo_through_cargo_env_not_raw_command() {
        let source = include_str!("test_ci.rs");
        let cutoff = source.find("\n#[cfg(test)]\nmod tests {").expect(
            "test_ci.rs must have a `#[cfg(test)] mod tests {` marker \
             — the shield's scan boundary depends on it",
        );
        let body = &source[..cutoff];
        assert!(
            !body.contains("Command::new(\"cargo\")"),
            "commands/test_ci.rs must not spawn `cargo` via the bare literal — \
             every `cargo` spawn must resolve `CARGO` via \
             `crate::repo::get_tool_path(\"CARGO\", \"cargo\")` first. \
             A raw `Command::new(\"cargo\")` bypasses the hermetic-runner \
             contract substrate's mkRuntimeToolsEnv exports."
        );
    }
}
