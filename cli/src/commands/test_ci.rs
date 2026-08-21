//! CI test runner (nextest with fallback to cargo test)
//!
//! Replaces product-sdlc.nix::test:ci.

use anyhow::{bail, Result};
use std::path::Path;
use std::process::Command;
use tracing::info;

use crate::repo::get_tool_path;
use crate::retry::run_inherited_status_sync;

/// Resolve the `cargo` binary via `CARGO`, falling back to PATH. Every
/// `cargo` spawn in this module reads through this sigil so the resolve
/// happens in exactly one place — mirrors the `cargo_bin()` sigil at
/// `commands/prerelease.rs:102` (79e03a5) and the sibling `crossplane_bin()`
/// / `cosign_bin()` / `jsonnet_bin()` sigil discipline on other command
/// modules (6b3ac16 / a070a3c / a826ac0). Solve-once at the sigil
/// (THEORY §I.5 — duplication budget zero; every recurring shape becomes
/// a generator or helper before it becomes duplicated code) means a
/// future added `cargo` spawn cannot silently repeat the two-argument
/// resolve string and drift away from `CARGO` at exactly the tier the
/// hermetic-runner contract binds. The whole-module shield below asserts
/// both the sigil's existence and its unique resolve — the pre-lift form
/// scattered the resolve across two sites (`execute` at the nextest /
/// cargo-test fallback pair, `coverage` at the tarpaulin install-gate /
/// tarpaulin run pair), each carrying its own copy of the fallback
/// string.
fn cargo_bin() -> String {
    get_tool_path("CARGO", "cargo")
}

/// Run tests in CI mode: prefer cargo-nextest, fall back to cargo test.
pub fn execute(working_dir: &str, threads: u32) -> Result<()> {
    let dir = Path::new(working_dir);
    if !dir.exists() {
        bail!("Working directory not found: {}", working_dir);
    }

    let cargo = cargo_bin();

    if which::which("cargo-nextest").is_ok() {
        info!("Running tests with cargo nextest (threads={})...", threads);
        let mut cmd = Command::new(&cargo);
        cmd.args([
            "nextest",
            "run",
            "--profile",
            "ci",
            "--test-threads",
            &threads.to_string(),
        ])
        .current_dir(dir);
        run_inherited_status_sync(cmd, "cargo nextest run")?;
    } else {
        info!(
            "cargo-nextest not found, falling back to cargo test (threads={})...",
            threads
        );
        let mut cmd = Command::new(&cargo);
        cmd.args([
            "test",
            "--no-fail-fast",
            "--",
            "--test-threads",
            &threads.to_string(),
        ])
        .current_dir(dir);
        run_inherited_status_sync(cmd, "cargo test")?;
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

    let cargo = cargo_bin();

    if which::which("cargo-tarpaulin").is_err() {
        info!("Installing cargo-tarpaulin...");
        let mut cmd = Command::new(&cargo);
        cmd.args(["install", "cargo-tarpaulin"]);
        run_inherited_status_sync(cmd, "cargo install cargo-tarpaulin")?;
    }

    info!(
        "Running coverage with cargo tarpaulin (format={})...",
        format
    );
    let mut cmd = Command::new(&cargo);
    cmd.args(["tarpaulin", "--out", format]).current_dir(dir);
    run_inherited_status_sync(cmd, "cargo tarpaulin")?;

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
    /// via the `cargo_bin()` sigil, which delegates to
    /// [`crate::repo::get_tool_path`] in exactly one place — the
    /// canonical env-var override every other cargo-invocation site in
    /// forge honors (`commands/bootstrap.rs:639`, `commands/pangea.rs`,
    /// `graphql_schema.rs`; the sibling sigil lives at
    /// `commands/prerelease.rs::cargo_bin`; the doc-comment idiom lives
    /// at `repo.rs:92`).
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
    /// The subsequent lift consolidates the two `execute` / `coverage`
    /// resolves onto a single `cargo_bin()` sigil (mirrors the recent
    /// `crossplane_bin()` sigil at 6b3ac16 and the `cargo_bin()` sigil
    /// at `commands/prerelease.rs:102`, 79e03a5). The shield below then
    /// asserts three invariants: (a) no bare `Command::new("cargo")`
    /// literal in the body, (b) `fn cargo_bin()` is defined, and (c)
    /// the two-argument resolve string appears in EXACTLY one place in
    /// the module body — only the sigil definition — so a future added
    /// spawn cannot silently re-copy the resolve inline and drift away
    /// from `cargo_bin()`'s single point of truth. THEORY §I.5:
    /// duplication budget zero.
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
    fn test_test_ci_routes_cargo_through_cargo_bin_sigil_not_raw_command() {
        crate::test_support::assert_source_routes_bare_spawn_through_sigil_bin_fn_at_exactly_one_resolve(
            include_str!("test_ci.rs"),
            "commands/test_ci.rs",
            "cargo",
            "CARGO",
        );
    }

    /// Whole-module shield: no inline `.status()` builder-terminator may
    /// live in this module's non-test body. Every status-only spawn in
    /// `commands/test_ci.rs` — the four sites in `execute` (nextest
    /// branch, cargo-test fallback branch) and `coverage` (tarpaulin
    /// install gate, tarpaulin run itself) — must route through
    /// [`crate::retry::run_inherited_status_sync`], which carries the
    /// exit code into the canonical
    /// `retry::classify_inherited_status` failure envelope
    /// (`"{op} failed (exit {code})"` on non-zero exit and
    /// `"{op} failed (killed by signal)"` on
    /// `status.code() == None`).
    ///
    /// Pre-lift each site spelled the same four-line stanza verbatim:
    ///
    /// ```text
    /// let status = Command::new(&cargo)
    ///     .args([...]).current_dir(dir)
    ///     .status()
    ///     .context("Failed to run …")?;
    /// if !status.success() { bail!("… failed"); }
    /// ```
    ///
    /// with a per-site ad-hoc bail message (`"cargo nextest run
    /// failed"`, `"cargo test failed"`, `"cargo install
    /// cargo-tarpaulin failed"`, `"cargo tarpaulin failed"`) that
    /// **dropped the exit code entirely** — precisely the regression
    /// [`crate::retry::run_inherited_status_sync`] was written to
    /// close. Post-lift the operator log line for a failed
    /// `test_ci::execute` (or `coverage`) invocation now reads
    /// e.g. `"cargo nextest run failed (exit 1)"` by construction at
    /// the primitive's ONE body, matching the envelope every other
    /// migrated command module already emits.
    ///
    /// Sibling of `commands/e2e.rs`'s
    /// `test_e2e_status_spawns_route_through_run_inherited_status_sync`
    /// (5faeecb), `commands/tool.rs`'s
    /// `test_tool_status_spawns_route_through_run_inherited_status_sync`
    /// (a3d51eb), `commands/infra.rs`'s
    /// `test_infra_status_spawns_route_through_run_inherited_status_sync`
    /// (27896e4), `commands/gem.rs`'s
    /// `test_gem_status_spawns_route_through_run_inherited_status_sync`
    /// (9072905), `commands/pangea_infra.rs`'s
    /// `test_pangea_infra_status_spawns_route_through_run_inherited_status_sync`
    /// (a6e9b96), and `commands/crossplane.rs`'s
    /// `test_crossplane_status_spawns_route_through_run_inherited_status_sync`
    /// (6cb9442). Same three-primitive discipline: negative side
    /// forbids the inline `.status()` builder-terminator at any code
    /// line in the module body; positive side pins that
    /// `run_inherited_status_sync(` appears at ≥4 code lines (one per
    /// pre-lift spawn), so a regression that dropped every delegation
    /// cannot leave the negative scan trivially satisfied by absence.
    /// Both hits route through [`crate::test_support::code_line_hits`]
    /// for anti-docstring-self-match discipline. Scan bounds from
    /// file start to the FIRST `\n#[cfg(test)]\n` marker so this
    /// shield's own body — the `".status()"` literal passed to
    /// `code_line_hits` and the assertion message that names the
    /// forbidden terminator — stays out of scope.
    #[test]
    fn test_test_ci_status_spawns_route_through_run_inherited_status_sync() {
        crate::test_support::assert_source_routes_status_only_spawns_through_run_inherited_status_sync(
            include_str!("test_ci.rs"),
            "commands/test_ci.rs",
            4,
            "all four status-only spawns (`cargo nextest run` / \
             `cargo test` in `execute`, `cargo install cargo-tarpaulin` \
             / `cargo tarpaulin` in `coverage`)",
        );
    }
}
