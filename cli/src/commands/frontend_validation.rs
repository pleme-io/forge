//! Frontend Validation Gates
//!
//! This module provides pre-release validation for frontend code:
//! - TypeScript type checking (tsc --noEmit)
//! - Lint validation (biome or eslint, configurable)
//! - Unit tests (vitest)
//!
//! Part of the pre-release gate system.

use anyhow::Result;
use colored::Colorize;
use std::path::Path;
use std::time::Instant;
use tokio::process::Command;

use crate::repo::get_tool_path;

use crate::config::FrontendGatesConfig;

/// Resolve the `bun` binary via the `BUN_BIN` env override, falling
/// back to PATH. Every `bun` spawn in this module reads through this
/// sigil so the resolve happens in exactly one place — mirrors the
/// `cargo_bin()` sigil at `commands/test_ci.rs:28` (916f1a4),
/// `commands/prerelease.rs:109` (79e03a5),
/// `commands/developer_tools.rs:36` (534ef48), and
/// `commands/e2e.rs:87` (170ecac), and the sibling `docker_bin()` /
/// `crossplane_bin()` / `cosign_bin()` / `jsonnet_bin()` sigil
/// discipline on other command modules (23241a6 / 6b3ac16 /
/// a070a3c / a826ac0). Solve-once at the sigil (THEORY §I.5 —
/// duplication budget zero; every recurring shape becomes a helper
/// before it becomes duplicated code) means a future added `bun`
/// spawn cannot silently re-copy the two-argument resolve and drift
/// away from the `BUN_BIN` override at exactly the tier the
/// hermetic-runner contract binds — the surface `forge prerelease`
/// invokes on every pre-release run to type-check / lint / test the
/// frontend, where a wrong-`bun` resolve produces a G* verdict
/// attributed to whichever `bun` PATH resolved first rather than to
/// the substrate-pinned `bun` derivation the flake declared.
///
/// Pre-lift the five consumer sites — `run_type_check`, ESLint arm
/// of `run_lint_with_config`, `run_biome_lint` (auto-fix + verify
/// share one `let bun = ...` binding), `run_unit_tests`, and
/// `validate_frontend_with_config`'s `bun install --frozen-lockfile`
/// preamble — each spelled the two-argument resolve verbatim,
/// ignoring `BUN_BIN` at every one had a future edit ever needed to
/// widen the resolve (a per-spawn env-injection hook, a
/// substrate-path validation step, or a telemetry sigil on the
/// resolved path). Post-lift each site collapses to `let bun =
/// bun_bin();` and the resolve appears exactly once.
fn bun_bin() -> String {
    get_tool_path("BUN_BIN", "bun")
}

/// Async captured-output `bun` spawn that BAILS ON SPAWN ERROR ONLY
/// and returns the raw [`std::process::Output`] with `output.status`
/// intact for the caller to inspect. The bun-frontier sibling of
/// [`crate::infrastructure::kubectl::kubectl_output_spawn_anyhow`]
/// (kubectl frontier, added at commit `0e2d0cf`), specialised on the
/// `.current_dir(cwd)` variant every consumer here needs — a bun
/// spawn in this module ALWAYS lands in the target web project's
/// `web_dir`, never in the caller's cwd, so the primitive folds the
/// `.current_dir(cwd)` into its body rather than making every call
/// site spell it.
///
/// # Fusion of six occurrences past three-is-a-law
///
/// Pre-lift each of six consumer sites — `run_type_check` (`bun run
/// type-check`), the ESLint arm of `run_lint_with_config` (`bun run
/// lint`), `run_biome_lint`'s auto-fix (`bun x biome check --write
/// src`) and verify (`bun x biome check src`) branches,
/// `run_unit_tests` (`bun run test -- --run`), and
/// `validate_frontend_with_config`'s `bun install --frozen-lockfile`
/// preamble — spelled the same seven-line stanza verbatim modulo the
/// argv and per-site `.with_context` string:
///
/// ```text
/// let bun = bun_bin();
/// let output = Command::new(&bun)
///     .args([...])
///     .current_dir(web_dir)
///     .output()
///     .await
///     .with_context(|| format!("Failed to run <op> in {}", web_dir.display()))?;
/// // caller then inspects `output.status.success()` to decide next step
/// ```
///
/// Six occurrences past THEORY.md §VI.1's three-times threshold ("two
/// occurrences is a coincidence; three is a law"). Each pre-lift site
/// was one place a future consumer could drift: forget the
/// `.current_dir(web_dir)` and spawn `bun` in the caller's cwd
/// (silently discovering the wrong `package.json` if `forge
/// prerelease` were ever invoked with a working directory that
/// happened to contain a stray package manifest), forget the
/// `.with_context(...)` and lose the operator's ability to tell WHICH
/// bun invocation failed, or spell the context string inconsistently
/// across sites and hide the site from a fleet-wide grep on a
/// canonical envelope. Post-lift each site collapses to a
/// `bun_output_at(&[...], web_dir, "bun <op>").await?` delegation and
/// both disciplines (`BUN_BIN` routing via `bun_bin()`, canonical
/// `"Failed to spawn {op}: {io_error}"` envelope via
/// [`crate::retry::classify_spawn_anyhow`]) are inherited by
/// construction.
///
/// # Envelope shape by construction
///
/// - Spawn `Err` (e.g., `BUN_BIN` resolves to an absent path on a
///   Nix-hermetic runner) → `"Failed to spawn {op}: {io_error}"` via
///   the shared [`crate::retry::classify_spawn_anyhow`] classifier,
///   the same envelope the sibling
///   [`crate::infrastructure::kubectl::kubectl_output_spawn_anyhow`]
///   emits on the kubectl frontier.
/// - Spawn `Ok(output)` → `Ok(output)`, byte-verbatim on stdout AND
///   stderr, with `output.status` (success OR non-zero exit OR signal
///   termination) preserved for the caller. The bun-frontier callers
///   drive downstream verdict-parsing off `output.status.success()`
///   and per-tool stdout heuristics (`error TS` counting,
///   vitest's `Tests  N passed` line, biome's `✖` markers), so the
///   pass-through semantic is load-bearing — a bail-on-non-zero
///   primitive would collapse every gate failure into the canonical
///   envelope and discard the per-tool details the operator report
///   depends on.
async fn bun_output_at(args: &[&str], cwd: &Path, op: &str) -> Result<std::process::Output> {
    crate::retry::classify_spawn_anyhow(
        Command::new(bun_bin())
            .args(args)
            .current_dir(cwd)
            .output()
            .await,
        op,
    )
}

/// Result of frontend validation
#[derive(Debug)]
pub struct FrontendValidationResult {
    /// Type check passed
    pub type_check_passed: bool,
    /// ESLint passed
    pub lint_passed: bool,
    /// Unit tests passed
    pub tests_passed: bool,
    /// Number of tests run
    pub test_count: Option<usize>,
    /// Errors encountered
    pub errors: Vec<String>,
    /// Detailed lines from type-check failures
    pub type_check_details: Vec<String>,
    /// Detailed lines from lint failures
    pub lint_details: Vec<String>,
    /// Detailed lines from test failures
    pub test_details: Vec<String>,
}

impl FrontendValidationResult {
    pub fn is_valid(&self) -> bool {
        self.type_check_passed && self.lint_passed && self.tests_passed
    }
}

/// Run TypeScript type checking
///
/// Executes `bun run type-check` or `tsc --noEmit` to verify type safety.
/// Returns (passed, detail_lines).
pub async fn run_type_check(web_dir: &Path) -> Result<(bool, Vec<String>)> {
    println!("{}", "Running TypeScript type check...".bold());
    let start = Instant::now();

    // Try bun run type-check first (defined in package.json)
    let output = bun_output_at(&["run", "type-check"], web_dir, "bun run type-check").await?;

    let duration = start.elapsed();

    if output.status.success() {
        println!(
            "   {} Type check passed ({:.1}s)",
            "✅".green(),
            duration.as_secs_f64()
        );
        Ok((true, Vec::new()))
    } else {
        let (stdout, stderr) = crate::repo::utf8_lossy_streams(&output);

        // Count errors
        let error_count = stdout.matches("error TS").count() + stderr.matches("error TS").count();

        println!(
            "   {} Type check failed ({} errors, {:.1}s)",
            "❌".red(),
            error_count,
            duration.as_secs_f64()
        );

        // Collect error lines for summary details
        let combined = format!("{}\n{}", stderr, stdout);
        let mut details = Vec::new();
        for line in combined.lines().take(20) {
            if line.contains("error") || line.contains("Error") {
                println!("   {}", line.red());
                details.push(line.to_string());
            }
        }

        if error_count > 20 {
            println!("   ... and {} more errors", error_count - 20);
            details.push(format!("... and {} more errors", error_count - 20));
        }

        Ok((false, details))
    }
}

/// Run lint validation using configured linter
///
/// Executes `bun run lint` to check code quality and style.
/// Supports biome (default) or eslint based on configuration.
pub async fn run_lint(web_dir: &Path) -> Result<(bool, Vec<String>)> {
    run_lint_with_config(web_dir, "biome").await
}

/// Run lint validation with specific linter
///
/// Supports "biome" or "eslint" linters.
/// For biome: runs auto-fix first, then checks (like cargo fmt pattern)
/// For eslint: runs via bun run lint
pub async fn run_lint_with_config(web_dir: &Path, linter: &str) -> Result<(bool, Vec<String>)> {
    let linter_name = if linter == "biome" { "Biome" } else { "ESLint" };
    println!("{}", format!("Running {}...", linter_name).bold());
    let start = Instant::now();

    if linter == "biome" {
        // Run biome directly with auto-fix first, then check
        return run_biome_lint(web_dir).await;
    }

    // ESLint: run via package.json script
    let output = bun_output_at(&["run", "lint"], web_dir, "bun run lint").await?;

    let duration = start.elapsed();

    if output.status.success() {
        println!(
            "   {} {} passed ({:.1}s)",
            "✅".green(),
            linter_name,
            duration.as_secs_f64()
        );
        Ok((true, Vec::new()))
    } else {
        let (stdout, stderr) = crate::repo::utf8_lossy_streams(&output);
        let combined = format!("{}\n{}", stderr, stdout);

        // ESLint outputs: "X error" or "X errors"
        let error_count = combined.matches(" error").count();
        let warning_count = combined.matches(" warning").count();

        println!(
            "   {} {} failed ({} errors, {} warnings, {:.1}s)",
            "❌".red(),
            linter_name,
            error_count,
            warning_count,
            duration.as_secs_f64()
        );

        // Collect error/warning lines for summary details
        let mut details = Vec::new();
        for line in combined.lines().take(15) {
            if line.contains("error") || line.contains("warning") || line.contains("✖") {
                println!("   {}", line);
                details.push(line.to_string());
            }
        }

        Ok((false, details))
    }
}

/// Run biome lint with auto-fix then verify
///
/// Pattern: First auto-fix safely, then run check to verify.
/// This mirrors the cargo fmt approach in backend gates.
async fn run_biome_lint(web_dir: &Path) -> Result<(bool, Vec<String>)> {
    let start = Instant::now();

    // First, run biome auto-fix (safe fixes only by default)
    println!("   Running Biome auto-fix...");
    let fix_output = bun_output_at(
        &["x", "biome", "check", "--write", "src"],
        web_dir,
        "bun x biome check --write src",
    )
    .await?;

    // Auto-fix may report issues it couldn't fix - that's OK
    // We'll catch those in the verification step

    if !fix_output.status.success() {
        let stderr = crate::repo::utf8_lossy_borrow(&fix_output.stderr);
        // Check if it's a real error or just unfixable issues
        if stderr.contains("Could not resolve") || stderr.contains("ENOENT") {
            println!(
                "   {} Biome auto-fix failed - biome may not be installed ({:.1}s)",
                "❌".red(),
                start.elapsed().as_secs_f64()
            );
            for line in stderr.lines().take(5) {
                println!("   {}", line);
            }
            return Ok((
                false,
                stderr.lines().take(5).map(|l| l.to_string()).collect(),
            ));
        }
        // Otherwise, continue to check step - unfixable issues will be caught there
    }

    println!("   Auto-fix complete, verifying...");

    // Then verify with biome check (no --write)
    let check_output = bun_output_at(
        &["x", "biome", "check", "src"],
        web_dir,
        "bun x biome check src",
    )
    .await?;

    let duration = start.elapsed();

    if check_output.status.success() {
        println!(
            "   {} Biome lint applied and verified ({:.1}s)",
            "✅".green(),
            duration.as_secs_f64()
        );
        Ok((true, Vec::new()))
    } else {
        let (stdout, stderr) = crate::repo::utf8_lossy_streams(&check_output);
        let combined = format!("{}\n{}", stderr, stdout);

        // Count errors and warnings from biome output
        let errors = combined.matches("error").count().max(
            combined
                .lines()
                .filter(|l| l.contains("✖") || l.contains("error"))
                .count(),
        );
        let warnings = combined
            .lines()
            .filter(|l| l.contains("warning") || l.contains("⚠"))
            .count();

        println!(
            "   {} Biome check failed ({} errors, {} warnings, {:.1}s)",
            "❌".red(),
            errors,
            warnings,
            duration.as_secs_f64()
        );

        // Collect error lines for summary details
        let mut details = Vec::new();
        for line in combined.lines().take(15) {
            if line.contains("error") || line.contains("warning") || line.contains("✖") {
                println!("   {}", line);
                details.push(line.to_string());
            }
        }

        Ok((false, details))
    }
}

/// Run unit tests
///
/// Executes `bun run test` (vitest) to verify unit test coverage.
pub async fn run_unit_tests(web_dir: &Path) -> Result<(bool, Option<usize>, Vec<String>)> {
    println!("{}", "Running unit tests...".bold());
    let start = Instant::now();

    let output = bun_output_at(
        &["run", "test", "--", "--run"], // --run for non-watch mode
        web_dir,
        "bun run test -- --run",
    )
    .await?;

    let duration = start.elapsed();
    let (stdout, stderr) = crate::repo::utf8_lossy_streams(&output);
    let combined = format!("{}\n{}", stderr, stdout);

    // Parse test count from vitest output
    let test_count = parse_test_count(&combined);

    if output.status.success() {
        println!(
            "   {} Unit tests passed ({} tests, {:.1}s)",
            "✅".green(),
            test_count.unwrap_or(0),
            duration.as_secs_f64()
        );
        Ok((true, test_count, Vec::new()))
    } else {
        // Check if tests actually failed or if there are no tests
        let has_failures = combined.contains("FAIL") || combined.contains("failed");
        let no_tests = combined.contains("No test files found") || test_count == Some(0);

        if no_tests {
            println!(
                "   {} No unit tests found ({:.1}s)",
                "⚠️".yellow(),
                duration.as_secs_f64()
            );
            // Consider no tests as passing (not all projects have tests)
            Ok((true, Some(0), Vec::new()))
        } else if has_failures {
            println!(
                "   {} Unit tests failed ({:.1}s)",
                "❌".red(),
                duration.as_secs_f64()
            );

            // Collect failure lines for summary details
            let mut details = Vec::new();
            let lines: Vec<&str> = combined.lines().collect();
            for line in lines.iter().take(20) {
                if line.contains("FAIL") || line.contains("Error") || line.contains("✕") {
                    println!("   {}", line.red());
                    details.push(line.to_string());
                }
            }

            Ok((false, test_count, details))
        } else {
            // Unknown error
            println!(
                "   {} Test execution failed ({:.1}s)",
                "❌".red(),
                duration.as_secs_f64()
            );
            let details: Vec<String> = combined.lines().take(10).map(|l| l.to_string()).collect();
            println!("   {}", details.join("\n   "));
            Ok((false, test_count, details))
        }
    }
}

/// Parse test count from vitest output
fn parse_test_count(output: &str) -> Option<usize> {
    // Look for patterns like "Tests  42 passed" or "42 passed"
    for line in output.lines() {
        // Vitest format: "Tests  42 passed (42)"
        if line.contains("passed") {
            // Extract number before "passed"
            let parts: Vec<&str> = line.split_whitespace().collect();
            for (i, part) in parts.iter().enumerate() {
                if *part == "passed" && i > 0 {
                    if let Ok(count) = parts[i - 1].parse::<usize>() {
                        return Some(count);
                    }
                }
            }
        }
    }

    None
}

/// Run all frontend validation gates (using default config)
///
/// Executes type checking, linting, and unit tests.
/// Returns comprehensive validation result.
pub async fn validate_frontend(web_dir: &Path) -> Result<FrontendValidationResult> {
    validate_frontend_with_config(web_dir, &FrontendGatesConfig::default()).await
}

/// Run frontend validation with custom configuration
///
/// Allows enabling/disabling individual gates and configuring the linter.
pub async fn validate_frontend_with_config(
    web_dir: &Path,
    config: &FrontendGatesConfig,
) -> Result<FrontendValidationResult> {
    let mut errors = Vec::new();
    let mut type_check_passed = true;
    let mut type_check_details = Vec::new();
    let mut lint_passed = true;
    let mut lint_details = Vec::new();
    let mut tests_passed = true;
    let mut test_details = Vec::new();
    let mut test_count = None;

    // Ensure dependencies are installed
    println!("{}", "Ensuring dependencies are installed...".bold());
    let install = bun_output_at(
        &["install", "--frozen-lockfile"],
        web_dir,
        "bun install --frozen-lockfile",
    )
    .await?;

    if !install.status.success() {
        let stderr = crate::repo::utf8_lossy_borrow(&install.stderr);
        errors.push(format!("bun install failed: {}", stderr));
        return Ok(FrontendValidationResult {
            type_check_passed: false,
            lint_passed: false,
            tests_passed: false,
            test_count: None,
            errors,
            type_check_details: Vec::new(),
            lint_details: Vec::new(),
            test_details: Vec::new(),
        });
    }

    println!("   {} Dependencies installed", "✓".green());
    println!();

    // Run type check if enabled
    if config.type_check {
        let (passed, details) = run_type_check(web_dir).await?;
        type_check_passed = passed;
        type_check_details = details;
        if !type_check_passed {
            errors.push("TypeScript type check failed".to_string());
        }
        println!();
    }

    // Run lint if enabled
    if config.lint {
        let (passed, details) = run_lint_with_config(web_dir, &config.linter).await?;
        lint_passed = passed;
        lint_details = details;
        if !lint_passed {
            let linter_name = if config.linter == "biome" {
                "Biome"
            } else {
                "ESLint"
            };
            errors.push(format!("{} validation failed", linter_name));
        }
        println!();
    }

    // Run unit tests if enabled
    if config.unit_tests {
        let (passed, count, details) = run_unit_tests(web_dir).await?;
        tests_passed = passed;
        test_count = count;
        test_details = details;
        if !tests_passed {
            errors.push("Unit tests failed".to_string());
        }
    }

    Ok(FrontendValidationResult {
        type_check_passed,
        lint_passed,
        tests_passed,
        test_count,
        errors,
        type_check_details,
        lint_details,
        test_details,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whole-module shield: no raw `Command::new("bun")` may live in
    /// this module's non-test body, `fn bun_bin()` must be defined,
    /// and the two-argument resolve
    /// `get_tool_path("BUN_BIN", "bun")` must appear exactly ONCE
    /// (only in the sigil body).
    ///
    /// Pre-lift the five consumer sites — `run_type_check`, ESLint
    /// arm of `run_lint_with_config`, `run_biome_lint` (auto-fix +
    /// verify share one binding), `run_unit_tests`, and
    /// `validate_frontend_with_config`'s `bun install
    /// --frozen-lockfile` preamble — each spelled `let bun =
    /// get_tool_path("BUN_BIN", "bun");` verbatim. Post-lift each
    /// consumer routes through `bun_bin()` and the two-argument
    /// resolve appears in exactly ONE place (the sigil body). The
    /// `resolve_count == 1` assertion fails-before at 5,
    /// passes-after at 1 — the canonical fail-before-pass-after arc
    /// matching the sibling `cargo_bin()` shield discipline landed
    /// on `commands/developer_tools.rs` (534ef48),
    /// `commands/prerelease.rs` (79e03a5), `commands/test_ci.rs`
    /// (916f1a4), and `commands/e2e.rs` (170ecac).
    ///
    /// The scan bounds on the whole-module boundary (from the file
    /// start to the `\n#[cfg(test)]\nmod tests {` marker above) so
    /// this shield's own docstring mentions of the forbidden literal
    /// stay out of scope AND every current or future bun-spawning
    /// helper landing anywhere in the top-level module body cannot
    /// silently ride along without going through `bun_bin()`.
    /// Mirrors the whole-module-boundary scan discipline pioneered
    /// on `commands/supergraph_verification.rs` (65283fb) and
    /// replicated across the `cargo_bin()` shield family. The
    /// two-argument-resolve needle is reconstructed via `format!`
    /// inside
    /// [`crate::test_support::get_tool_path_two_arg_call_needle`],
    /// so this shield's own source never contains the literal
    /// `get_tool_path("BUN_BIN", "bun")` string and cannot
    /// false-match itself on the count-eq-1 assertion.
    ///
    /// A Nix-hermetic runner whose derivation exports
    /// `BUN_BIN=/nix/store/…-bun/bin/bun` but omits `bun` from PATH
    /// silently fell through to whatever `bun` was first on PATH at
    /// each pre-lift site — every pre-release frontend verdict
    /// (type-check, lint, tests, install) was attributed to whichever
    /// `bun` PATH resolved first, not to the substrate-pinned bun
    /// derivation the flake declared. Same silent-PATH-fallback bug
    /// class the sibling `CARGO` / `DOCKER_BIN` / `KUBECTL_BIN` /
    /// `GIT_BIN` / `NIX_BIN` / `HELM_BIN` migrations closed on their
    /// respective spawn surfaces.
    #[test]
    fn test_frontend_validation_routes_bun_through_bun_bin_sigil_not_raw_command() {
        let body = crate::test_support::module_body_before_tests(
            include_str!("frontend_validation.rs"),
            "commands/frontend_validation.rs",
        );
        assert!(
            !body.contains("Command::new(\"bun\")"),
            "commands/frontend_validation.rs must not spawn `bun` via the bare \
             literal — every `bun` spawn must resolve `BUN_BIN` via `bun_bin()` \
             first. A raw `Command::new(\"bun\")` bypasses the hermetic-runner \
             contract substrate's mkRuntimeToolsEnv exports."
        );
        assert!(
            body.contains("fn bun_bin()"),
            "commands/frontend_validation.rs must define `bun_bin()` — the \
             sigil function that resolves the tools-registry `BUN_BIN` \
             override for every bun spawn. Mirrors the `cargo_bin()` sigil \
             discipline at `commands/test_ci.rs:28`, \
             `commands/prerelease.rs:109`, `commands/developer_tools.rs:36`, \
             and `commands/e2e.rs:87`."
        );
        let two_arg_needle =
            crate::test_support::get_tool_path_two_arg_call_needle("BUN_BIN", "bun");
        let resolve_count = body.matches(two_arg_needle.as_str()).count();
        assert_eq!(
            resolve_count, 1,
            "the two-argument resolve `{two_arg_needle}` must appear \
             exactly ONCE in the module body (only in the `bun_bin()` \
             sigil), not {resolve_count} times — every consumer must route \
             through `bun_bin()`, not re-copy the resolve inline"
        );
    }

    /// Whole-module shield: every captured-output `bun` spawn in this
    /// module MUST route through the `bun_output_at` fusion primitive
    /// — the bun-frontier sibling of
    /// [`crate::infrastructure::kubectl::kubectl_output_spawn_anyhow`]
    /// added at commit `0e2d0cf`. The shield closes the composition
    /// discipline the sibling `test_frontend_validation_routes_bun_through_bun_bin_sigil_not_raw_command`
    /// (BUN_BIN routing at the sigil) leaves open: even after the
    /// sigil ensures every spawn resolves the substrate-pinned `bun`
    /// derivation, a call site could still (a) forget the
    /// `.current_dir(web_dir)` and spawn `bun` in the caller's cwd,
    /// (b) forget the `.with_context(...)` and lose the operator's
    /// ability to tell WHICH bun invocation spawn-failed, or (c) spell
    /// the context string inconsistently across sites and hide the
    /// site from a fleet-wide grep on the canonical
    /// `"Failed to spawn {op}: {io_error}"` envelope.
    ///
    /// # Two-arm pin
    ///
    /// Negative side pins that `.output()` appears exactly ONCE in
    /// the module body — the fusion primitive's ONE body. Any new
    /// bun spawn that hand-rolls the `.output().await` chain lands
    /// as a second hit and trips the shield. Positive side pins ≥6
    /// `bun_output_at(` delegation calls — a regression that dropped
    /// every delegation could not leave the negative scan trivially
    /// satisfied by absence. Both hits route through
    /// [`crate::test_support::code_line_hits`] so this shield's own
    /// docstring mentions of `.output()` and `bun_output_at(` (living
    /// in `///`-prefixed comment lines) never self-match.
    ///
    /// # Boundary marker
    ///
    /// [`crate::test_support::module_body_before_tests`] slices from
    /// file start to the `\n#[cfg(test)]\nmod tests {` marker above,
    /// so this shield's own docstring stays out of scope AND every
    /// current or future bun-spawning helper landing anywhere in the
    /// top-level module body cannot silently ride along without
    /// going through the fusion.
    ///
    /// # Fail-before-pass-after
    ///
    /// Pre-lift the six consumer sites (`run_type_check`, ESLint arm
    /// of `run_lint_with_config`, `run_biome_lint` auto-fix + verify,
    /// `run_unit_tests`, and `validate_frontend_with_config`'s `bun
    /// install --frozen-lockfile` preamble) each spelled
    /// `.output().await.with_context(...)?` verbatim — the shield's
    /// `.output()` count-eq-1 assertion fails-before at 6+1=7 and
    /// passes-after at 1. Mirrors the sibling shield discipline the
    /// `run_inherited_status_sync` migrations landed across
    /// `commands/{crossplane, e2e, gem, infra, pangea_infra, test_ci,
    /// tool, local}.rs`.
    #[test]
    fn test_frontend_validation_bun_captured_spawns_route_through_bun_output_at() {
        let body = crate::test_support::module_body_before_tests(
            include_str!("frontend_validation.rs"),
            "commands/frontend_validation.rs",
        );
        let output_hits = crate::test_support::code_line_hits(body, ".output()");
        assert_eq!(
            output_hits.len(),
            1,
            "commands/frontend_validation.rs must carry exactly ONE \
             `.output()` code-line hit in the module body — the `bun_output_at` \
             fusion primitive's ONE body — not {} hit(s). Every captured-output \
             `bun` spawn must route through the fusion so the canonical \
             `\"Failed to spawn {{op}}: {{io_error}}\"` envelope (via \
             `crate::retry::classify_spawn_anyhow`) and the `.current_dir(cwd)` \
             discipline are inherited by construction. A raw \
             `Command::new(&bun).args(...).current_dir(cwd).output().await.with_context(...)` \
             stanza reopens the drift that pre-lift six sites spelled verbatim. \
             Found: {output_hits:?}",
            output_hits.len(),
        );
        let delegations = crate::test_support::code_line_hits(body, "bun_output_at(").len();
        assert!(
            delegations >= 6,
            "commands/frontend_validation.rs must route captured-output \
             `bun` spawns through the `bun_output_at` fusion — found only \
             {delegations} delegation call(s); a dropped call would leave \
             the negative `.output()`-count-eq-1 scan trivially satisfied \
             by absence."
        );
    }

    #[test]
    fn test_parse_test_count() {
        assert_eq!(parse_test_count("Tests  42 passed (42)"), Some(42));
        assert_eq!(parse_test_count(" 156 passed"), Some(156));
        assert_eq!(parse_test_count("No tests found"), None);
    }

    #[test]
    fn test_frontend_validation_result() {
        let result = FrontendValidationResult {
            type_check_passed: true,
            lint_passed: true,
            tests_passed: true,
            test_count: Some(42),
            errors: vec![],
            type_check_details: vec![],
            lint_details: vec![],
            test_details: vec![],
        };
        assert!(result.is_valid());

        let failed_result = FrontendValidationResult {
            type_check_passed: true,
            lint_passed: false,
            tests_passed: true,
            test_count: Some(42),
            errors: vec!["ESLint failed".to_string()],
            type_check_details: vec![],
            lint_details: vec![],
            test_details: vec![],
        };
        assert!(!failed_result.is_valid());
    }
}
