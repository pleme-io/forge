//! Pre-Release Gate Orchestrator
//!
//! This module orchestrates all pre-release validation gates for a product:
//!
//! ## Phase 0a: Fast Gates (parallel)
//! Backend, migration, and frontend gates run concurrently via `tokio::join!`.
//!
//! ### Backend Gates (G1-G5)
//! - G1: cargo check (compilation)
//! - G2: cargo clippy --deny warnings
//! - G3: cargo fmt --check
//! - G4: cargo test --lib --bins
//! - G5: extract-schema succeeds
//!
//! ### Migration Gates (G6-G8b)
//! - G6: SQLx migration idempotency check (legacy migrations)
//! - G7: Soft-delete compliance check
//! - G8: SeaORM migration safety check (current migrations - expand-contract pattern)
//! - G8b: Migration data completeness check (manifest validation)
//!
//! ### Frontend Gates (G9-G12)
//! - G9: Codegen drift detection
//! - G10: Type-check passes
//! - G11: Lint passes (biome or eslint, configurable)
//! - G12: Unit tests pass
//!
//! ## Phase 0b: Integration Tests (G13)
//! - Testcontainers: Postgres, Redis, NATS
//! - Skip with `SKIP_INTEGRATION=true` or `prerelease.integration.enabled: false`
//!
//! ## Phase 0c: E2E Tests (G14)
//! - Chromiumoxide + testcontainers full stack
//! - Skip with `SKIP_E2E=true` or `prerelease.e2e.enabled: false`
//!
//! Gate behavior is configurable via deploy.yaml:
//! - Enable/disable individual gates
//! - Configure migration file exclusions
//! - Configure SeaORM migration exclusions
//! - Choose linter (biome vs eslint)
//! - Control whether failures stop the release

use anyhow::{bail, Result};
use colored::Colorize;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::process::Command;

use crate::config::PreReleaseGatesConfig;

use super::codegen_validation;
use super::e2e;
use super::frontend_validation;
use super::migration_validation;

/// Resolve the `docker` binary path via `DOCKER_BIN`, falling back to
/// `docker` on `PATH`. Wired through [`crate::repo::get_tool_path`] —
/// the two-arg env-var-or-fallback form every recent sibling sigil
/// (`e2e::docker_bin` at 23241a6, `local::docker_bin` unified in this
/// same commit, `infra::docker_bin` unified in this same commit,
/// `cargo_bin` at 916f1a4, `crossplane::crossplane_bin` at 6b3ac16,
/// `ps_bin` at 758dd6f, `open_bin` at 8f4c717, `sh_bin` at b382b78)
/// already rides. The two-arg form lifts the substrate-exported
/// env-var literal (`DOCKER_BIN`) directly into the sigil site so a
/// fleet-wide `grep DOCKER_BIN` reaches this module — the deriving
/// one-arg form this module previously carried
/// (`crate::tools::get_tool_path(crate::tools::tools::DOCKER)`) hid
/// the env-var literal behind a `tools::DOCKER = "docker"` constant
/// plus an uppercase-suffix derivation, so the load-bearing name
/// never appeared in the source and a `DOCKER_BIN` audit missed the
/// site. Pre-lift the three `std::process::Command` spawns inside
/// `print_e2e_diagnostics` (docker ps / docker ps -a exited / docker
/// images) each spelled the bare tool-name literal, so a Nix-hermetic
/// runner's substrate-derived docker path lost to whatever `docker`
/// was first on `PATH` at diagnostics time — silently redirecting an
/// engineer chasing an E2E flake to a different daemon's container
/// list than the one the failing test actually spawned against.
fn docker_bin() -> String {
    crate::repo::get_tool_path("DOCKER_BIN", "docker")
}

/// Resolve the `cargo` binary path via `CARGO`, falling back to `cargo`
/// on `PATH`. Wired through [`crate::repo::get_tool_path`] — the two-arg
/// form, because the substrate-exported override for cargo is the
/// unadorned `CARGO` var (the same var Cargo itself honors when a
/// wrapping cargo binary re-invokes cargo), not the derived
/// `CARGO_BIN`. Mirrors the sibling `docker_bin` above and the same
/// idiom every cargo-invocation site in forge honors
/// (`commands/test_ci.rs` per e1677d3, `commands/developer_tools.rs`
/// per 8687093, `commands/comprehensive_release.rs` per f95d541,
/// `commands/bootstrap.rs:639`, `commands/pangea.rs:473`,
/// `graphql_schema.rs:193`; the doc-comment idiom lives at
/// `repo.rs:92`).
///
/// Pre-lift the seven consumer sites — `run_integration_tests` at
/// the integration-gate cargo-test spawn, `run_e2e_tests` at the
/// E2E-gate cargo-test spawn, `run_cargo_check` (G1), `run_cargo_clippy`
/// (G2), `run_cargo_fmt_check` (G3 fix + G3 --check), and
/// `run_cargo_test` (G4) — each spelled the bare-literal
/// `Command::new(<bare>)` shape verbatim, ignoring `CARGO` at every
/// one. A Nix-hermetic runner with a
/// store-path `cargo` binary silently fell through to whatever `cargo`
/// was first on PATH at these seven sites specifically — every
/// pre-release-gate verdict (G1–G4, G13, G14) was attributed to
/// whichever `cargo` PATH resolved first, not to the substrate-pinned
/// cargo derivation the flake declared. Same silent-PATH-fallback bug
/// class the sibling `CARGO` lifts (e1677d3 / 8687093 / f95d541) and
/// the `DOCKER_BIN` / `KUBECTL_BIN` / `GIT_BIN` migrations closed on
/// their respective spawn surfaces.
fn cargo_bin() -> String {
    crate::repo::get_tool_path("CARGO", "cargo")
}

/// Spawn `cargo <args>` at `cwd`, capturing stdout/stderr and returning the
/// raw [`std::process::Output`] regardless of exit status — the cargo-frontier
/// captured-output fusion primitive, sibling of
/// [`frontend_validation::bun_output_at`] on the bun frontier and
/// [`crate::infrastructure::kubectl::kubectl_output_spawn_anyhow`] on the
/// kubectl frontier.
///
/// # Fusion of five occurrences past three-is-a-law
///
/// Pre-lift each of five consumer sites — `run_cargo_check` (G1), `run_cargo_clippy`
/// (G2), `run_cargo_fmt_check`'s auto-fix (G3 `cargo fmt`) and verify (G3
/// `cargo fmt -- --check`) branches, and `run_cargo_test` (G4) — spelled the
/// same seven-line stanza verbatim modulo the argv and per-site
/// `.with_context` string:
///
/// ```text
/// let cargo = cargo_bin();
/// let output = Command::new(&cargo)
///     .args([...])
///     .current_dir(backend_dir)
///     .output()
///     .await
///     .with_context(|| "Failed to run cargo <op>")?;
/// // caller then inspects `output.status.success()` to decide next step
/// ```
///
/// Five occurrences past THEORY.md §VI.1's three-times threshold ("two
/// occurrences is a coincidence; three is a law"). Each pre-lift site was one
/// place a future consumer could drift: forget the `.current_dir(backend_dir)`
/// and spawn `cargo` in the caller's cwd (silently discovering the wrong
/// `Cargo.toml` if `forge prerelease` were ever invoked with a working
/// directory that happened to contain a stray manifest), forget the
/// `.with_context(...)` and lose the operator's ability to tell WHICH cargo
/// invocation failed, or spell the context string inconsistently across sites
/// and hide the site from a fleet-wide grep on a canonical envelope. Post-lift
/// each site collapses to a `cargo_output_at(&[...], backend_dir, "cargo <op>")
/// .await?` delegation and both disciplines (`CARGO` routing via `cargo_bin()`,
/// canonical `"Failed to spawn {op}: {io_error}"` envelope via
/// [`crate::retry::classify_spawn_anyhow`]) are inherited by construction.
///
/// # Envelope shape by construction
///
/// - Spawn `Err` (e.g., `CARGO` resolves to an absent path on a Nix-hermetic
///   runner) → `"Failed to spawn {op}: {io_error}"` via the shared
///   [`crate::retry::classify_spawn_anyhow`] classifier, the same envelope the
///   sibling [`frontend_validation::bun_output_at`] emits on the bun frontier
///   and [`crate::infrastructure::kubectl::kubectl_output_spawn_anyhow`] emits
///   on the kubectl frontier. This intentionally shifts the pre-lift
///   per-site `"Failed to run cargo <op>"` phrasing (a source-chained
///   `.with_context`) onto the fleet-wide `"Failed to spawn {op}: {io_error}"`
///   envelope so a `grep 'Failed to spawn'` reaches every captured-output
///   spawn failure across every frontier from one query.
/// - Spawn `Ok(output)` → `Ok(output)`, byte-verbatim on stdout AND stderr,
///   with `output.status` (success OR non-zero exit OR signal termination)
///   preserved for the caller. The five G1-G4 callers drive downstream verdict
///   parsing off `output.status.success()` and per-tool stdout/stderr
///   heuristics (`error` counting, `warning:` counting, `test result:` line
///   parsing, `Diff in` file collection), so the pass-through semantic is
///   load-bearing — a bail-on-non-zero primitive would collapse every gate
///   failure into the canonical envelope and discard the per-tool details the
///   gate report depends on. The two `.output()` sites that remain in this
///   module (G13 `run_integration_gate` and G14 `run_e2e_gate`) each nest the
///   spawn inside `tokio::time::timeout(...)` for gate-level timeout
///   enforcement and cannot ride this primitive without dropping the timeout
///   — they are intentionally left inline.
async fn cargo_output_at(args: &[&str], cwd: &Path, op: &str) -> Result<std::process::Output> {
    crate::retry::classify_spawn_anyhow(
        Command::new(cargo_bin())
            .args(args)
            .current_dir(cwd)
            .output()
            .await,
        op,
    )
}

/// Announce the gate step-heading, run `cargo <args>` at `cwd` through the
/// [`cargo_output_at`] fusion primitive, and return the captured output paired
/// with the elapsed wall-clock duration — the announce + spawn + elapse
/// preamble every one-shot fast-gate wraps around its per-gate verdict
/// heuristic.
///
/// # Fusion of three occurrences
///
/// Pre-lift each of `run_cargo_check` (G1), `run_cargo_clippy` (G2) and
/// `run_cargo_test` (G4) opened with the same three-line stanza verbatim
/// modulo argv, title and op label:
///
/// ```text
/// let start = crate::ui::print_step_heading_start("G<N>: <title>");
/// let output = cargo_output_at(&[..], backend_dir, "cargo <op>").await?;
/// let duration = start.elapsed();
/// ```
///
/// The stanza is a preamble atop the [`cargo_output_at`] fusion primitive:
/// it announces the gate's numbered step heading, snapshots the wall-clock
/// start via [`crate::ui::print_step_heading_start`], drives the captured-
/// output spawn through the sibling fusion, and takes the elapsed duration
/// off the same start clock. Post-lift each site collapses to a
/// `announce_gate_and_run_cargo_output_at(<title>, &[..], backend_dir,
/// <op>).await?` delegation and both the announce-then-elapse pairing
/// (a caller that forgot to snapshot `start` before the spawn would lose
/// the timing) and the shared `cargo_output_at` envelope are inherited
/// by construction. `run_cargo_fmt_check` (G3) intentionally does NOT
/// ride this primitive because it drives TWO cargo spawns (the auto-fix
/// `cargo fmt` followed by the `cargo fmt -- --check` verify) off ONE
/// start clock; a single-spawn primitive would collapse the two-arm shape
/// or duplicate the elapsed sample.
async fn announce_gate_and_run_cargo_output_at(
    title: &str,
    args: &[&str],
    cwd: &Path,
    op: &str,
) -> Result<(std::process::Output, std::time::Duration)> {
    let start = crate::ui::print_step_heading_start(title);
    let output = cargo_output_at(args, cwd, op).await?;
    let duration = start.elapsed();
    Ok((output, duration))
}

/// Configuration for the pre-release validation
#[derive(Debug, Clone)]
pub struct PreReleaseConfig {
    /// Working directory (product root)
    pub working_dir: PathBuf,
    /// Backend service directory
    pub backend_dir: PathBuf,
    /// Web frontend directory
    pub web_dir: PathBuf,
    /// SQLx migrations directory (legacy)
    pub migrations_dir: PathBuf,
    /// SeaORM migrations directory (current)
    pub seaorm_migrations_dir: PathBuf,
    /// Skip backend checks (CLI flag override)
    pub skip_backend: bool,
    /// Skip frontend checks (CLI flag override)
    pub skip_frontend: bool,
    /// Skip migration checks (CLI flag override)
    pub skip_migrations: bool,
    /// Gate configuration from deploy.yaml
    pub gates: PreReleaseGatesConfig,
}

impl PreReleaseConfig {
    /// Create config from working directory with default gate settings
    pub fn from_working_dir(working_dir: &Path) -> Self {
        Self::from_working_dir_with_gates(working_dir, PreReleaseGatesConfig::default())
    }

    /// Create config from working directory with custom gate settings
    pub fn from_working_dir_with_gates(working_dir: &Path, gates: PreReleaseGatesConfig) -> Self {
        Self {
            working_dir: working_dir.to_path_buf(),
            backend_dir: working_dir.join("services/rust/backend"),
            web_dir: working_dir.join("web"),
            migrations_dir: working_dir.join("services/rust/backend/migrations"),
            seaorm_migrations_dir: working_dir.join("services/rust/migration/src"),
            skip_backend: false,
            skip_frontend: false,
            skip_migrations: false,
            gates,
        }
    }
}

/// Summary of gate results
#[derive(Debug, Default)]
pub struct GateSummary {
    /// Gates that passed
    pub passed: Vec<String>,
    /// Gates that failed
    pub failed: Vec<String>,
    /// Detailed issue descriptions for failed gates (gate name → details)
    pub failed_details: Vec<(String, Vec<String>)>,
    /// Gates that were skipped
    pub skipped: Vec<String>,
    /// Total time taken
    pub total_time_secs: f64,
}

impl GateSummary {
    pub fn all_passed(&self) -> bool {
        self.failed.is_empty()
    }

    /// Fold every `Vec` field of `other` into `self`, in field-declaration
    /// order: `passed`, `failed`, `failed_details`, `skipped`. The scalar
    /// `total_time_secs` is intentionally NOT touched — the caller owns
    /// aggregate timing at the phase boundary, not per sub-summary.
    ///
    /// Lifts the pre-lift 3 sibling 6-line stanzas
    ///
    /// ```ignore
    /// summary.passed.extend(<sub>.passed);
    /// summary.failed.extend(<sub>.failed);
    /// summary
    ///     .failed_details
    ///     .extend(<sub>.failed_details);
    /// summary.skipped.extend(<sub>.skipped);
    /// ```
    ///
    /// (Phase 0a `backend_results` / `migration_results` / `frontend_results`
    /// tokio::join! demux) onto one call each. A future 4th parallel
    /// sub-summary added to the join! tuple lands on the same primitive with
    /// zero risk of dropping the `failed_details` half of the pair — the
    /// pre-lift stanza's multi-line `summary\n    .failed_details\n    .extend`
    /// break was the specific hand-copy trap a merge trait removes.
    pub fn merge_from(&mut self, other: GateSummary) {
        let GateSummary {
            passed,
            failed,
            failed_details,
            skipped,
            total_time_secs: _,
        } = other;
        self.passed.extend(passed);
        self.failed.extend(failed);
        self.failed_details.extend(failed_details);
        self.skipped.extend(skipped);
    }

    pub fn print_summary(&self) {
        crate::ui::print_section_header("Gate Summary");

        if !self.passed.is_empty() {
            println!("{} Passed ({}):", "✅".green(), self.passed.len());
            for gate in &self.passed {
                crate::ui::print_step_check(gate);
            }
        }

        if !self.skipped.is_empty() {
            println!();
            println!("{} Skipped ({}):", "⏭️".yellow(), self.skipped.len());
            for gate in &self.skipped {
                crate::ui::print_step_skip(gate);
            }
        }

        if !self.failed.is_empty() {
            println!();
            println!("{} Failed ({}):", "❌".red(), self.failed.len());
            for gate in &self.failed {
                crate::ui::print_step_uncheck(gate);
                // Print detailed issues for this gate if available
                for (detail_gate, details) in &self.failed_details {
                    if gate.starts_with(detail_gate.as_str()) {
                        for detail in details {
                            println!("      {}", detail);
                        }
                    }
                }
            }
        }

        println!();
        println!("Total time: {:.1}s", self.total_time_secs);
        println!();

        if self.all_passed() {
            crate::ui::print_phase_success("All gates passed! Ready for release.");
        } else {
            println!(
                "{}",
                "❌ Some gates failed. Please fix the issues before releasing."
                    .red()
                    .bold()
            );
        }
    }
}

/// Load gate configuration from deploy.yaml if it exists
fn load_gates_config(working_dir: &Path) -> PreReleaseGatesConfig {
    // Try to load from backend service deploy.yaml
    // Check deploy/backend.yaml first (new convention), fall back to service dir
    let backend_deploy_yaml = {
        let new_path = working_dir.join("deploy/backend.yaml");
        if new_path.exists() {
            new_path
        } else {
            working_dir.join("services/rust/backend/deploy.yaml")
        }
    };
    if let Some(value) = crate::repo::try_read_yaml_sync::<serde_yaml::Value>(&backend_deploy_yaml)
    {
        // Parse the YAML and extract prerelease config
        if let Some(prerelease) = value.get("prerelease") {
            if let Ok(config) = serde_yaml::from_value::<PreReleaseGatesConfig>(prerelease.clone())
            {
                crate::commands::gate_config_source_announcement::print_gate_config_source_announcement(
                    crate::commands::gate_config_source_announcement::GateConfigSource::LoadedFromBackendDeployYaml,
                );
                return config;
            }
        }
    }

    // Try to load from product-level deploy.yaml
    let product_deploy_yaml = working_dir.join("deploy.yaml");
    if let Some(value) = crate::repo::try_read_yaml_sync::<serde_yaml::Value>(&product_deploy_yaml)
    {
        if let Some(prerelease) = value.get("prerelease") {
            if let Ok(config) = serde_yaml::from_value::<PreReleaseGatesConfig>(prerelease.clone())
            {
                crate::commands::gate_config_source_announcement::print_gate_config_source_announcement(
                    crate::commands::gate_config_source_announcement::GateConfigSource::LoadedFromProductDeployYaml,
                );
                return config;
            }
        }
    }

    crate::commands::gate_config_source_announcement::print_gate_config_source_announcement(
        crate::commands::gate_config_source_announcement::GateConfigSource::UsingDefault,
    );
    PreReleaseGatesConfig::default()
}

/// Execute all pre-release gates
pub async fn execute(
    working_dir: String,
    skip_backend: bool,
    skip_frontend: bool,
    skip_migrations: bool,
) -> Result<()> {
    let start = Instant::now();

    // Load gate configuration from deploy.yaml
    let gates_config = load_gates_config(Path::new(&working_dir));

    let config = PreReleaseConfig {
        working_dir: PathBuf::from(&working_dir),
        backend_dir: PathBuf::from(&working_dir).join("services/rust/backend"),
        web_dir: PathBuf::from(&working_dir).join("web"),
        migrations_dir: PathBuf::from(&working_dir).join("services/rust/backend/migrations"),
        seaorm_migrations_dir: PathBuf::from(&working_dir).join("services/rust/migration/src"),
        skip_backend,
        skip_frontend,
        skip_migrations,
        gates: gates_config,
    };

    // Check if gates are globally disabled
    if !config.gates.enabled {
        println!();
        println!(
            "{}",
            "⚠️  Pre-release gates are disabled in configuration".yellow()
        );
        println!("   Set prerelease.enabled: true in deploy.yaml to enable");
        return Ok(());
    }

    crate::ui::print_section_header("Pre-Release Gates");
    println!("Working directory: {}", config.working_dir.display());
    crate::backend_frontend_dirs_preamble::print_backend_frontend_dirs_preamble(
        &config.backend_dir,
        &config.web_dir,
    );
    println!(
        "Fail on error: {}",
        if config.gates.fail_on_error {
            "yes"
        } else {
            "no (warnings only)"
        }
    );
    println!();

    let mut summary = GateSummary::default();

    // Verify directories exist
    verify_directories(&config)?;

    // ========================================
    // Phase 0a: Fast gates (parallel)
    // Backend, Migration, and Frontend gates run concurrently
    // ========================================
    crate::ui::print_phase_heading("Phase 0a: Fast Gates (parallel)");

    let (backend_results, migration_results, frontend_results) = tokio::join!(
        run_backend_gates(&config),
        run_migration_gates(&config),
        run_frontend_gates(&config),
    );

    // Merge Phase 0a sub-summaries. Each `merge_from` call folds every
    // Vec field (passed / failed / failed_details / skipped) at once —
    // the pre-lift stanzas' `.failed_details.extend(...)` line, broken
    // across three source lines, was the specific hand-copy trap.
    summary.merge_from(backend_results?);
    summary.merge_from(migration_results?);
    summary.merge_from(frontend_results?);

    // ========================================
    // Phase 0b: Integration tests (G13)
    // Requires Docker — testcontainers for Postgres, Redis, NATS
    // ========================================
    let skip_integration = crate::repo::truthy_flag_from_env("SKIP_INTEGRATION");
    super::optional_prerelease_phase_gate::run_optional_prerelease_phase_gate(
        &mut summary,
        "SKIP_INTEGRATION",
        skip_integration,
        config.gates.integration.enabled,
        "G13: Integration tests",
        "Phase 0b: Integration Tests (G13)",
        "Integration tests error",
        || run_integration_gate(&config),
    )
    .await;

    // ========================================
    // Phase 0c: E2E tests (G14)
    // Requires Docker + Nix images + Chrome (headless)
    // ========================================
    let skip_e2e = crate::repo::truthy_flag_from_env("SKIP_E2E");
    super::optional_prerelease_phase_gate::run_optional_prerelease_phase_gate(
        &mut summary,
        "SKIP_E2E",
        skip_e2e,
        config.gates.e2e.enabled,
        "G14: E2E tests",
        "Phase 0c: E2E Tests (G14)",
        "E2E tests error",
        || run_e2e_gate(&config),
    )
    .await;

    // Final summary
    summary.total_time_secs = start.elapsed().as_secs_f64();
    summary.print_summary();

    // Handle failures based on configuration
    if !summary.all_passed() {
        if config.gates.fail_on_error {
            bail!(
                "Pre-release gates failed. {} issues to fix.\n\
                 To continue despite failures, set prerelease.fail_on_error: false in deploy.yaml",
                summary.failed.len()
            );
        } else {
            println!(
                "{}",
                format!(
                    "⚠️  {} gate(s) failed but fail_on_error is disabled. Continuing...",
                    summary.failed.len()
                )
                .yellow()
            );
        }
    }

    Ok(())
}

/// Run backend gates (G1-G5) sequentially
async fn run_backend_gates(config: &PreReleaseConfig) -> Result<GateSummary> {
    let mut summary = GateSummary::default();

    if config.skip_backend {
        summary.skipped.push("G1: cargo check".to_string());
        summary.skipped.push("G2: cargo clippy".to_string());
        summary.skipped.push("G3: cargo fmt".to_string());
        summary.skipped.push("G4: cargo test".to_string());
        summary.skipped.push("G5: extract-schema".to_string());
        return Ok(summary);
    }

    crate::ui::print_phase_heading("Backend Gates");

    // G1: cargo check
    if !config.gates.backend.cargo_check {
        summary
            .skipped
            .push("G1: cargo check (disabled)".to_string());
    } else if run_cargo_check(&config.backend_dir).await? {
        summary.passed.push("G1: cargo check".to_string());
    } else {
        summary.failed.push("G1: cargo check".to_string());
    }
    println!();

    // G2: cargo clippy
    if !config.gates.backend.cargo_clippy {
        summary
            .skipped
            .push("G2: cargo clippy (disabled)".to_string());
    } else if run_cargo_clippy(&config.backend_dir).await? {
        summary.passed.push("G2: cargo clippy".to_string());
    } else {
        summary.failed.push("G2: cargo clippy".to_string());
    }
    println!();

    // G3: cargo fmt --check
    if !config.gates.backend.cargo_fmt {
        summary.skipped.push("G3: cargo fmt (disabled)".to_string());
    } else if run_cargo_fmt_check(&config.backend_dir).await? {
        summary.passed.push("G3: cargo fmt".to_string());
    } else {
        summary.failed.push("G3: cargo fmt".to_string());
    }
    println!();

    // G4: cargo test
    if !config.gates.backend.cargo_test {
        summary
            .skipped
            .push("G4: cargo test (disabled)".to_string());
    } else if run_cargo_test(&config.backend_dir).await? {
        summary.passed.push("G4: cargo test".to_string());
    } else {
        summary.failed.push("G4: cargo test".to_string());
    }
    println!();

    // G5: extract-schema
    if !config.gates.backend.extract_schema {
        summary
            .skipped
            .push("G5: extract-schema (disabled)".to_string());
    } else if codegen_validation::validate_schema_export(&config.backend_dir).await? {
        summary.passed.push("G5: extract-schema".to_string());
    } else {
        summary.failed.push("G5: extract-schema".to_string());
    }
    println!();

    Ok(summary)
}

/// Run migration gates (G6-G8) sequentially
async fn run_migration_gates(config: &PreReleaseConfig) -> Result<GateSummary> {
    let mut summary = GateSummary::default();

    if config.skip_migrations {
        summary
            .skipped
            .push("G6: SQLx migration idempotency".to_string());
        summary
            .skipped
            .push("G7: Soft-delete compliance".to_string());
        summary
            .skipped
            .push("G8: SeaORM migration safety".to_string());
        summary
            .skipped
            .push("G8b: Migration data completeness".to_string());
        return Ok(summary);
    }

    crate::ui::print_phase_heading("Migration Gates");

    // Use the configured migration gate settings for SQLx migrations (legacy)
    let migration_result = migration_validation::validate_migrations_with_config(
        &config.migrations_dir,
        &config.gates.migrations,
    )
    .await?;

    // G6: Idempotency check (SQLx migrations)
    if !config.gates.migrations.idempotency_check {
        summary
            .skipped
            .push("G6: SQLx migration idempotency (disabled)".to_string());
    } else {
        let idempotency_issues: Vec<_> = migration_result
            .issues
            .iter()
            .filter(|i| {
                matches!(
                    i,
                    migration_validation::MigrationIssue::IdempotencyViolation { .. }
                        | migration_validation::MigrationIssue::UnsafeDrop { .. }
                )
            })
            .collect();

        if idempotency_issues.is_empty() {
            summary.passed.push(format!(
                "G6: SQLx migration idempotency ({} files)",
                migration_result.files_checked
            ));
        } else {
            summary.failed.push(format!(
                "G6: SQLx migration idempotency ({} issues)",
                idempotency_issues.len()
            ));
            summary.failed_details.push((
                "G6".to_string(),
                idempotency_issues.iter().map(|i| i.format()).collect(),
            ));
        }
    }

    // G7: Soft-delete compliance
    if !config.gates.migrations.soft_delete_check {
        summary
            .skipped
            .push("G7: Soft-delete compliance (disabled)".to_string());
    } else {
        let soft_delete_issues: Vec<_> = migration_result
            .issues
            .iter()
            .filter(|i| matches!(i, migration_validation::MigrationIssue::HardDelete { .. }))
            .collect();

        if soft_delete_issues.is_empty() {
            summary
                .passed
                .push("G7: Soft-delete compliance".to_string());
        } else {
            summary.failed.push(format!(
                "G7: Soft-delete compliance ({} issues)",
                soft_delete_issues.len()
            ));
            summary.failed_details.push((
                "G7".to_string(),
                soft_delete_issues.iter().map(|i| i.format()).collect(),
            ));
        }
    }

    // G8: SeaORM migration safety check (current migrations)
    if !config.gates.migrations.seaorm_safety_check {
        summary
            .skipped
            .push("G8: SeaORM migration safety (disabled)".to_string());
    } else {
        let seaorm_result = migration_validation::validate_seaorm_migrations(
            &config.seaorm_migrations_dir,
            &config.gates.migrations,
        )
        .await?;

        let seaorm_issues: Vec<_> = seaorm_result
            .issues
            .iter()
            .filter(|i| {
                matches!(
                    i,
                    migration_validation::MigrationIssue::SeaOrmUnsafeOperation { .. }
                )
            })
            .collect();

        if seaorm_issues.is_empty() {
            summary.passed.push(format!(
                "G8: SeaORM migration safety ({} files)",
                seaorm_result.files_checked
            ));
        } else {
            summary.failed.push(format!(
                "G8: SeaORM migration safety ({} issues)",
                seaorm_issues.len()
            ));
            summary.failed_details.push((
                "G8".to_string(),
                seaorm_issues.iter().map(|i| i.format()).collect(),
            ));
        }
    }

    // G8b: Migration data completeness check (manifest validation)
    if !config.gates.migrations.data_completeness_check {
        summary
            .skipped
            .push("G8b: Migration data completeness (disabled)".to_string());
    } else {
        let manifest_result = migration_validation::validate_migration_manifest(
            &config.seaorm_migrations_dir,
            &config.gates.migrations,
        )
        .await?;

        if manifest_result.issues.is_empty() {
            summary.passed.push(format!(
                "G8b: Migration data completeness ({} assessed)",
                manifest_result.assessed_count
            ));
        } else {
            summary.failed.push(format!(
                "G8b: Migration data completeness ({} issues)",
                manifest_result.issues.len()
            ));
            summary.failed_details.push((
                "G8b".to_string(),
                manifest_result.issues.iter().map(|i| i.format()).collect(),
            ));
        }
    }
    println!();

    Ok(summary)
}

/// Run frontend gates (G9-G12) sequentially
async fn run_frontend_gates(config: &PreReleaseConfig) -> Result<GateSummary> {
    let mut summary = GateSummary::default();

    if config.skip_frontend {
        summary.skipped.push("G9: Codegen drift".to_string());
        summary.skipped.push("G10: Type-check".to_string());
        summary.skipped.push("G11: Lint".to_string());
        summary.skipped.push("G12: Unit tests".to_string());
        return Ok(summary);
    }

    crate::ui::print_phase_heading("Frontend Gates");

    // G9: Codegen drift detection
    if !config.gates.frontend.codegen_drift {
        summary
            .skipped
            .push("G9: Codegen drift (disabled)".to_string());
    } else {
        let codegen_result =
            codegen_validation::validate_codegen(&config.backend_dir, &config.web_dir).await?;
        if codegen_result.is_valid {
            summary.passed.push("G9: Codegen drift".to_string());
        } else {
            summary.failed.push(format!(
                "G9: Codegen drift - {}",
                codegen_result.error.unwrap_or_default()
            ));
        }
        println!();
    }

    // G10-G12: Frontend validation using configuration
    // Skip the validation call entirely if all three gates are disabled
    let needs_frontend_validation = config.gates.frontend.type_check
        || config.gates.frontend.lint
        || config.gates.frontend.unit_tests;

    if needs_frontend_validation {
        let frontend_result = frontend_validation::validate_frontend_with_config(
            &config.web_dir,
            &config.gates.frontend,
        )
        .await?;

        // G10: Type-check
        if !config.gates.frontend.type_check {
            summary
                .skipped
                .push("G10: Type-check (disabled)".to_string());
        } else if frontend_result.type_check_passed {
            summary.passed.push("G10: Type-check".to_string());
        } else {
            summary.failed.push("G10: Type-check".to_string());
            if !frontend_result.type_check_details.is_empty() {
                summary
                    .failed_details
                    .push(("G10".to_string(), frontend_result.type_check_details));
            }
        }

        // G11: Lint (biome or eslint)
        let linter_name = if config.gates.frontend.linter == "biome" {
            "Biome"
        } else {
            "ESLint"
        };
        if !config.gates.frontend.lint {
            summary
                .skipped
                .push(format!("G11: {} (disabled)", linter_name));
        } else if frontend_result.lint_passed {
            summary.passed.push(format!("G11: {}", linter_name));
        } else {
            summary.failed.push(format!("G11: {}", linter_name));
            if !frontend_result.lint_details.is_empty() {
                summary
                    .failed_details
                    .push(("G11".to_string(), frontend_result.lint_details));
            }
        }

        // G12: Unit tests
        if !config.gates.frontend.unit_tests {
            summary
                .skipped
                .push("G12: Unit tests (disabled)".to_string());
        } else if frontend_result.tests_passed {
            let test_info = frontend_result
                .test_count
                .map(|c| format!(" ({} tests)", c))
                .unwrap_or_default();
            summary.passed.push(format!("G12: Unit tests{}", test_info));
        } else {
            summary.failed.push("G12: Unit tests".to_string());
            if !frontend_result.test_details.is_empty() {
                summary
                    .failed_details
                    .push(("G12".to_string(), frontend_result.test_details));
            }
        }
    } else {
        summary
            .skipped
            .push("G10: Type-check (disabled)".to_string());
        let linter_name = if config.gates.frontend.linter == "biome" {
            "Biome"
        } else {
            "ESLint"
        };
        summary
            .skipped
            .push(format!("G11: {} (disabled)", linter_name));
        summary
            .skipped
            .push("G12: Unit tests (disabled)".to_string());
    }

    Ok(summary)
}

/// G13: Run integration tests (testcontainers: Postgres + Redis + NATS)
async fn run_integration_gate(config: &PreReleaseConfig) -> Result<bool> {
    // Announce the G13 step heading and enforce the docker
    // daemon-availability preflight in one fused call. On preflight
    // failure the primitive has already emitted the
    // `❌ Docker not available: <err>` line and returns `None`; the
    // caller short-circuits with `return Ok(false)` so the sibling
    // gates continue running.
    let Some(start) =
        crate::docker_available_gate_preflight::announce_docker_gate_step_heading_or_skip(
            "G13: Integration tests",
        )
    else {
        return Ok(false);
    };

    let timeout_secs = config.gates.integration.timeout_secs;
    let cargo = cargo_bin();
    let output = tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        Command::new(&cargo)
            .args(crate::cargo_test_argv::cargo_integration_tests_argv())
            .current_dir(&config.backend_dir)
            .output(),
    )
    .await;

    let duration = start.elapsed();

    match output {
        Ok(Ok(output)) => {
            if output.status.success() {
                crate::prerelease_gate_pass_fail_step::print_prerelease_gate_pass_step_timed(
                    crate::prerelease_gate_pass_fail_step::PrereleaseGatePassFailBaseLabel::IntegrationTests,
                    duration,
                );
                Ok(true)
            } else {
                let (stdout, stderr) = crate::repo::utf8_lossy_streams(&output);
                crate::prerelease_gate_pass_fail_step::print_prerelease_gate_failure_step_timed(
                    crate::prerelease_gate_pass_fail_step::PrereleaseGatePassFailBaseLabel::IntegrationTests,
                    duration,
                );
                for line in stderr.lines().chain(stdout.lines()).take(15) {
                    if line.contains("FAILED") || line.contains("panicked") {
                        crate::ui::print_diagnostic_error_line(line);
                    }
                }
                Ok(false)
            }
        }
        Ok(Err(e)) => {
            crate::ui::print_step_failure_with_error("Failed to run integration tests", &e);
            Ok(false)
        }
        Err(_) => {
            crate::ui::print_step_failure(&format!(
                "Integration tests timed out after {}s",
                timeout_secs
            ));
            Ok(false)
        }
    }
}

/// Print diagnostic information when E2E tests fail
fn print_e2e_diagnostics(backend_dir: &Path) {
    println!();
    println!("{}", "── E2E Failure Diagnostics ──".bold().red());

    // Docker containers still running
    crate::docker_ps_diag_section::print_docker_ps_diag_section(
        &docker_bin(),
        crate::probe_dump::DiagSink::Stdout,
        "   ",
        "     ",
        crate::docker_ps_diag_section::DockerPsDiagSection::Running,
    );

    // Recently exited containers
    crate::docker_ps_diag_section::print_docker_ps_diag_section(
        &docker_bin(),
        crate::probe_dump::DiagSink::Stdout,
        "   ",
        "     ",
        crate::docker_ps_diag_section::DockerPsDiagSection::RecentlyExited,
    );

    // E2E images
    crate::probe_dump::print_diag_section_header(
        crate::probe_dump::DiagSink::Stdout,
        "   ",
        crate::probe_dump::DiagSectionHeader::E2eDockerImages,
    );
    let template = crate::probe_dump::docker_images_diag_format("     ", "ID");
    if let Some(stdout) =
        crate::retry::probe_stdout_capture_sync(&docker_bin(), &["images", "--format", &template])
    {
        for line in stdout.lines() {
            if line.contains("-backend") || line.contains("-web") {
                println!("{}", line);
            }
        }
    }

    // Screenshots
    crate::screenshot_diag::probe_and_dump_screenshots_captured_section(
        &backend_dir.join("target/screenshots"),
        crate::probe_dump::DiagSink::Stdout,
        "   ",
        "     ",
    );

    println!();
    println!("   {}", "Troubleshooting:".bold());
    crate::ui::print_e2e_troubleshooting_steps("     ");
    crate::ui::print_light_rule(crate::ui::LightRuleStyle::PrereleaseDiagnosticCloseDimmed28);
}

/// G14: Run E2E tests (chromiumoxide + testcontainers full stack)
async fn run_e2e_gate(config: &PreReleaseConfig) -> Result<bool> {
    // Announce the G14 step heading and enforce the docker
    // daemon-availability preflight in one fused call. Docker may
    // already be started by G13; the preflight is idempotent. On
    // preflight failure the primitive has already emitted the
    // `❌ Docker not available: <err>` line and returns `None`; the
    // caller short-circuits with `return Ok(false)`.
    let Some(start) =
        crate::docker_available_gate_preflight::announce_docker_gate_step_heading_or_skip(
            "G14: E2E tests",
        )
    else {
        return Ok(false);
    };

    // Resolve repo root for image preparation
    let repo_root = config.working_dir.to_str().map(|s| s.to_string());

    // Pre-cleanup: ensure no orphaned containers from previous runs
    if let Err(e) = e2e::cleanup_testcontainers() {
        crate::ui::print_step_warn(&format!("Pre-cleanup warning: {}", e));
    }

    // Always force-rebuild E2E images to ensure tests run against the current code.
    // Without force=true, stale images from a previous build would be reused.
    if let Err(e) = e2e::prepare_e2e_images(repo_root.clone(), false, false, true) {
        crate::ui::print_step_failure_with_error("Failed to prepare E2E images", &e);
        return Ok(false);
    }

    let headless = config.gates.e2e.headless;
    let timeout_secs = config.gates.e2e.timeout_secs;

    let cargo = cargo_bin();
    let mut cmd = Command::new(&cargo);
    cmd.args(crate::cargo_test_argv::cargo_e2e_tests_include_ignored_argv())
        .current_dir(&config.backend_dir);

    if headless {
        cmd.env("E2E_HEADLESS", "1");
    }

    println!(
        "   Command: cargo test --test e2e_tests --features integration-tests -- --include-ignored"
    );
    println!("   Dir:     {}", config.backend_dir.display());
    println!("   Headless: {}, Timeout: {}s", headless, timeout_secs);
    println!();

    let output = tokio::time::timeout(Duration::from_secs(timeout_secs), cmd.output()).await;

    let duration = start.elapsed();

    match output {
        Ok(Ok(output)) => {
            // Post-cleanup: containers + images (prerelease force-rebuilds each run)
            e2e::discard_post_run_e2e_cleanup();

            if output.status.success() {
                crate::prerelease_gate_pass_fail_step::print_prerelease_gate_pass_step_timed(
                    crate::prerelease_gate_pass_fail_step::PrereleaseGatePassFailBaseLabel::E2eTests,
                    duration,
                );
                Ok(true)
            } else {
                let (stdout, stderr) = crate::repo::utf8_lossy_streams(&output);
                crate::prerelease_gate_pass_fail_step::print_prerelease_gate_failure_step_timed(
                    crate::prerelease_gate_pass_fail_step::PrereleaseGatePassFailBaseLabel::E2eTests,
                    duration,
                );

                // Show all test output for debugging
                println!();
                crate::ui::print_dimmed_dashed_marker("cargo test stdout");
                for line in stdout.lines() {
                    crate::ui::print_diagnostic_line(line);
                }
                crate::ui::print_dimmed_dashed_marker("cargo test stderr");
                for line in stderr
                    .lines()
                    .rev()
                    .take(50)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                {
                    crate::classified_diagnostic_line::print_classified_diagnostic_line(
                        line,
                        &["FAILED", "panicked", "error"],
                    );
                }
                crate::ui::print_light_rule(
                    crate::ui::LightRuleStyle::PrereleaseE2eFailureStderrCloseDimmed23,
                );

                print_e2e_diagnostics(&config.backend_dir);
                Ok(false)
            }
        }
        Ok(Err(e)) => {
            // Post-cleanup on spawn error
            e2e::discard_post_run_e2e_cleanup();

            crate::ui::print_step_failure_with_error("Failed to run E2E tests", &e);
            print_e2e_diagnostics(&config.backend_dir);
            Ok(false)
        }
        Err(_) => {
            // Post-cleanup on timeout (most critical — Ryuk won't clean up after force-kill)
            e2e::discard_post_run_e2e_cleanup();

            crate::ui::print_step_failure(&format!(
                "E2E tests timed out after {}s ({:.1}s elapsed)",
                timeout_secs,
                duration.as_secs_f64()
            ));
            println!();
            println!("   The test process was killed after the timeout.");
            println!("   This usually means containers failed to start or a test is hanging.");

            print_e2e_diagnostics(&config.backend_dir);
            Ok(false)
        }
    }
}

/// Verify required directories exist
fn verify_directories(config: &PreReleaseConfig) -> Result<()> {
    if !config.working_dir.exists() {
        bail!(
            "Working directory does not exist: {}",
            config.working_dir.display()
        );
    }

    if !config.skip_backend && !config.backend_dir.exists() {
        bail!(
            "Backend directory does not exist: {}. \
             Expected Rust backend at services/rust/backend/ relative to working dir",
            config.backend_dir.display()
        );
    }

    if !config.skip_frontend && !config.web_dir.exists() {
        bail!(
            "Web directory does not exist: {}. \
             Expected frontend at web/ relative to working dir",
            config.web_dir.display()
        );
    }

    Ok(())
}

/// G1: Run cargo check
async fn run_cargo_check(backend_dir: &Path) -> Result<bool> {
    // Check lib and bins only (not tests) - consistent with clippy
    // Test targets require test-helpers feature and are validated separately
    let (output, duration) = announce_gate_and_run_cargo_output_at(
        "G1: cargo check",
        &["check", "--lib", "--bins"],
        backend_dir,
        "cargo check",
    )
    .await?;

    if output.status.success() {
        crate::prerelease_gate_pass_fail_step::print_prerelease_gate_pass_step_timed(
            crate::prerelease_gate_pass_fail_step::PrereleaseGatePassFailBaseLabel::CompilationCheck,
            duration,
        );
        Ok(true)
    } else {
        let stderr = crate::repo::utf8_lossy_borrow(&output.stderr);
        crate::prerelease_gate_pass_fail_step::print_prerelease_gate_failure_step_timed(
            crate::prerelease_gate_pass_fail_step::PrereleaseGatePassFailBaseLabel::CompilationCheck,
            duration,
        );
        // Show first few errors
        crate::prerelease_cargo_gate_stderr_head_filter::print_prerelease_cargo_gate_stderr_head_filtered_lines(
            &stderr,
            crate::prerelease_cargo_gate_stderr_head_filter::PrereleaseCargoGateStderrHeadVariant::CargoCheckErrors,
        );
        Ok(false)
    }
}

/// G2: Run cargo clippy with deny warnings
async fn run_cargo_clippy(backend_dir: &Path) -> Result<bool> {
    // Check lib and bins only (not tests) - test dead code warnings are expected
    // since GraphQL types aren't constructed directly in test code
    let (output, duration) = announce_gate_and_run_cargo_output_at(
        "G2: cargo clippy",
        &["clippy", "--lib", "--bins", "--", "-D", "warnings"],
        backend_dir,
        "cargo clippy",
    )
    .await?;

    if output.status.success() {
        crate::ui::print_step_pass(&crate::repo::msg_with_count_noun_secs_1(
            "Clippy passed",
            0_usize,
            "warnings",
            duration,
        ));
        Ok(true)
    } else {
        let stderr = crate::repo::utf8_lossy_borrow(&output.stderr);
        let warning_count = stderr.matches("warning:").count();

        crate::step_failure_count_noun::print_step_failure_count_noun(
            "Clippy failed",
            warning_count,
            "warnings",
            duration,
        );
        // Show first few warnings
        crate::prerelease_cargo_gate_stderr_head_filter::print_prerelease_cargo_gate_stderr_head_filtered_lines(
            &stderr,
            crate::prerelease_cargo_gate_stderr_head_filter::PrereleaseCargoGateStderrHeadVariant::CargoClippyWarningsAndErrors,
        );
        Ok(false)
    }
}

/// G3: Run cargo fmt (auto-fix) then verify
async fn run_cargo_fmt_check(backend_dir: &Path) -> Result<bool> {
    let start = crate::ui::print_step_heading_start("G3: cargo fmt");

    // First, auto-fix formatting
    let fix_output = cargo_output_at(&["fmt"], backend_dir, "cargo fmt").await?;

    if !fix_output.status.success() {
        let stderr = crate::repo::utf8_lossy_borrow(&fix_output.stderr);
        crate::ui::print_step_failure_timed("cargo fmt failed", start.elapsed());
        let _ = crate::auto_fix_stderr_head_diagnostic::print_and_collect_auto_fix_stderr_head_diagnostic_lines(
            &stderr,
        );
        return Ok(false);
    }

    // Then verify with --check (should always pass after auto-fix)
    let check_output =
        cargo_output_at(&["fmt", "--", "--check"], backend_dir, "cargo fmt --check").await?;

    let duration = start.elapsed();

    if check_output.status.success() {
        crate::ui::print_step_pass_timed("Code formatting applied and verified", duration);
        Ok(true)
    } else {
        // This shouldn't happen after auto-fix, but handle it
        let stdout = crate::repo::utf8_lossy_borrow(&check_output.stdout);
        let unformatted_files: Vec<&str> = stdout
            .lines()
            .filter(|l| l.starts_with("Diff in"))
            .collect();

        crate::step_failure_count_noun::print_step_failure_count_noun(
            "Code formatting check failed after auto-fix",
            unformatted_files.len(),
            "files",
            duration,
        );
        for file in unformatted_files.iter().take(5) {
            println!("   {}", file);
        }
        Ok(false)
    }
}

/// G4: Run cargo test
async fn run_cargo_test(backend_dir: &Path) -> Result<bool> {
    let (output, duration) = announce_gate_and_run_cargo_output_at(
        "G4: cargo test",
        &["test", "--lib", "--bins"],
        backend_dir,
        "cargo test",
    )
    .await?;
    let stdout = crate::repo::utf8_lossy_borrow(&output.stdout);

    // Parse test count from output
    let test_count = stdout
        .lines()
        .find(|l| l.contains("test result:"))
        .and_then(|l| {
            // Format: "test result: ok. X passed; Y failed; Z ignored"
            l.split_whitespace()
                .find(|w| w.parse::<usize>().is_ok())
                .and_then(|n| n.parse::<usize>().ok())
        });

    if output.status.success() {
        crate::test_count_pass_step::print_test_count_pass_step(
            "Tests passed",
            test_count,
            duration,
        );
        Ok(true)
    } else {
        let stderr = crate::repo::utf8_lossy_borrow(&output.stderr);
        crate::ui::print_step_failure_timed("Tests failed", duration);
        println!();
        // Show full stdout (cargo test writes results there)
        if !stdout.trim().is_empty() {
            crate::ui::print_dimmed_dashed_marker("cargo test output");
            for line in stdout.lines() {
                crate::classified_diagnostic_line::print_classified_diagnostic_line(
                    line,
                    &["FAILED", "panicked", "error["],
                );
            }
        }
        // Show last 40 lines of stderr for compile errors / panic details
        let stderr_lines: Vec<&str> = stderr.lines().collect();
        if !stderr_lines.is_empty() {
            crate::ui::print_dimmed_dashed_marker("stderr (last 40 lines)");
            let start = stderr_lines.len().saturating_sub(40);
            for &line in &stderr_lines[start..] {
                crate::classified_diagnostic_line::print_classified_diagnostic_line(
                    line,
                    &["error", "FAILED", "panicked"],
                );
            }
        }
        crate::ui::print_light_rule(crate::ui::LightRuleStyle::PrereleaseDiagnosticCloseDimmed28);
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{E2eGatesConfig, IntegrationGatesConfig};

    // ====================================================================
    // GateSummary tests
    // ====================================================================

    #[test]
    fn test_gate_summary_default_is_passing() {
        let summary = GateSummary::default();
        assert!(summary.all_passed());
        assert!(summary.passed.is_empty());
        assert!(summary.failed.is_empty());
        assert!(summary.skipped.is_empty());
    }

    #[test]
    fn test_gate_summary_with_passed_gates() {
        let mut summary = GateSummary::default();
        summary.passed.push("G1".to_string());
        summary.passed.push("G2".to_string());
        assert!(summary.all_passed());
    }

    #[test]
    fn test_gate_summary_with_failures() {
        let mut summary = GateSummary::default();
        summary.passed.push("G1".to_string());
        summary.failed.push("G3".to_string());
        assert!(!summary.all_passed());
    }

    #[test]
    fn test_gate_summary_skipped_does_not_affect_passing() {
        let mut summary = GateSummary::default();
        summary.passed.push("G1".to_string());
        summary.skipped.push("G2: disabled".to_string());
        assert!(summary.all_passed());
    }

    #[test]
    fn test_gate_summary_merge() {
        let mut a = GateSummary::default();
        a.passed.push("G1".to_string());
        a.skipped.push("G2".to_string());

        let mut b = GateSummary::default();
        b.passed.push("G3".to_string());
        b.failed.push("G4".to_string());

        // Merge like the parallel gates do
        let mut merged = GateSummary::default();
        merged.merge_from(a);
        merged.merge_from(b);

        assert_eq!(merged.passed.len(), 2);
        assert_eq!(merged.failed.len(), 1);
        assert_eq!(merged.skipped.len(), 1);
        assert!(!merged.all_passed());
    }

    /// [`GateSummary::merge_from`] must fold `failed_details` too — the
    /// half-stanza that lived on its own multi-line
    /// `summary\n    .failed_details\n    .extend(...)` break in the
    /// pre-lift Phase 0a demux, and that the previous
    /// `test_gate_summary_merge` (pre-lift) did NOT exercise. A future
    /// change that drops the field from `merge_from`'s body would still
    /// pass the `passed/failed/skipped`-only assertions, so this shield
    /// pins the fourth Vec explicitly.
    #[test]
    fn gate_summary_merge_from_folds_failed_details_field() {
        let mut a = GateSummary::default();
        a.failed.push("G3: fmt".to_string());
        a.failed_details
            .push(("G3".to_string(), vec!["file.rs unformatted".to_string()]));

        let mut b = GateSummary::default();
        b.failed.push("G4: test".to_string());
        b.failed_details.push((
            "G4".to_string(),
            vec!["test_x FAILED".to_string(), "test_y panicked".to_string()],
        ));

        let mut merged = GateSummary::default();
        merged.merge_from(a);
        merged.merge_from(b);

        assert_eq!(
            merged.failed_details.len(),
            2,
            "merge_from must fold BOTH sub-summaries' failed_details \
             entries — got {:?}",
            merged.failed_details,
        );
        let total_detail_lines: usize = merged
            .failed_details
            .iter()
            .map(|(_, lines)| lines.len())
            .sum();
        assert_eq!(
            total_detail_lines, 3,
            "merge_from must preserve every failed_details detail line \
             from every sub-summary (1 from a + 2 from b = 3) — got \
             {total_detail_lines}",
        );
    }

    /// [`GateSummary::merge_from`] must NOT overwrite the receiver's
    /// `total_time_secs` scalar — the pre-lift stanza did not touch it,
    /// and phase-boundary timing is the caller's concern. This shield
    /// pins that structural invariant against a future edit that "helpfully"
    /// summed or replaced it inside the primitive's body.
    #[test]
    fn gate_summary_merge_from_leaves_total_time_secs_unchanged() {
        let mut receiver = GateSummary {
            total_time_secs: 12.5,
            ..GateSummary::default()
        };
        let donor = GateSummary {
            total_time_secs: 999.0,
            ..GateSummary::default()
        };
        receiver.merge_from(donor);
        assert_eq!(
            receiver.total_time_secs, 12.5,
            "merge_from must NOT touch total_time_secs — the caller owns \
             aggregate timing at the phase boundary. Got {}",
            receiver.total_time_secs,
        );
    }

    /// Whole-module shield: `run_prerelease`'s Phase 0a demux must route
    /// every parallel sub-summary through [`GateSummary::merge_from`].
    /// The pre-lift shape spelled the four-line stanza
    ///
    /// ```ignore
    /// summary.passed.extend(<x>.passed);
    /// summary.failed.extend(<x>.failed);
    /// summary.failed_details.extend(<x>.failed_details);
    /// summary.skipped.extend(<x>.skipped);
    /// ```
    ///
    /// three times, and its multi-line `summary\n    .failed_details\n
    ///     .extend(...)` break was the specific hand-copy trap. A regression
    /// that re-inlined even one sub-summary's four-line stanza would
    /// silently divergence the trap surface again.
    ///
    /// Two-arm pin: negative side forbids `summary.failed_details.extend(`
    /// and `summary.passed.extend(` from re-appearing in the module body;
    /// positive side pins ≥3 `merge_from(` delegation calls so a dropped
    /// call cannot leave the negative scan trivially satisfied by absence.
    ///
    /// Fail-before-pass-after: pre-lift the module body carried three
    /// `summary.passed.extend(` and three `summary.failed_details.extend(`
    /// hits (one per demuxed sub-summary), and zero `merge_from(` hits;
    /// the shield's `== 0` and `>= 3` assertions each flip on the lift.
    #[test]
    fn phase_0a_demux_routes_every_sub_summary_through_merge_from() {
        let body = crate::test_support::module_body_before_tests(
            include_str!("prerelease.rs"),
            "commands/prerelease.rs",
        );
        for needle in [
            "summary.passed.extend(",
            "summary.failed.extend(",
            "summary.failed_details.extend(",
            "summary.skipped.extend(",
            "summary\n        .failed_details\n        .extend(",
        ] {
            let hits = crate::test_support::code_line_hits(body, needle);
            assert!(
                hits.is_empty(),
                "commands/prerelease.rs must NOT re-inline the pre-lift \
                 Phase 0a merge stanza — every sub-summary routes through \
                 `GateSummary::merge_from`, which folds all four Vec fields \
                 at once. Offending hits for `{needle}`: {hits:?}",
            );
        }
        let delegations = crate::test_support::code_line_hits(body, "summary.merge_from(").len();
        assert!(
            delegations >= 3,
            "commands/prerelease.rs must route every Phase 0a parallel \
             sub-summary (`backend_results`, `migration_results`, \
             `frontend_results`) through `summary.merge_from(...)` — found \
             only {delegations} delegation call(s); a dropped call would \
             leave the negative-side scan trivially satisfied by absence.",
        );
    }

    // ====================================================================
    // PreReleaseConfig tests
    // ====================================================================

    #[test]
    fn test_prerelease_config() {
        let config = PreReleaseConfig::from_working_dir(Path::new("/tmp/testapp"));
        assert_eq!(
            config.backend_dir,
            PathBuf::from("/tmp/testapp/services/rust/backend")
        );
        assert_eq!(config.web_dir, PathBuf::from("/tmp/testapp/web"));
        assert_eq!(
            config.migrations_dir,
            PathBuf::from("/tmp/testapp/services/rust/backend/migrations")
        );
        assert_eq!(
            config.seaorm_migrations_dir,
            PathBuf::from("/tmp/testapp/services/rust/migration/src")
        );
        // Default gates config
        assert!(config.gates.enabled);
        assert!(config.gates.fail_on_error);
        assert_eq!(config.gates.frontend.linter, "biome");
        // New gate groups present
        assert!(config.gates.integration.enabled);
        assert!(config.gates.e2e.enabled);
        assert!(config.gates.post_deploy.smoke_queries);
    }

    #[test]
    fn test_prerelease_config_with_gates() {
        let mut gates = PreReleaseGatesConfig {
            fail_on_error: false,
            ..PreReleaseGatesConfig::default()
        };
        gates.migrations.check_after = Some("20240101".to_string());

        let config =
            PreReleaseConfig::from_working_dir_with_gates(Path::new("/tmp/testapp"), gates);
        assert!(!config.gates.fail_on_error);
        assert_eq!(
            config.gates.migrations.check_after,
            Some("20240101".to_string())
        );
    }

    #[test]
    fn test_prerelease_config_with_integration_disabled() {
        let gates = PreReleaseGatesConfig {
            integration: IntegrationGatesConfig {
                enabled: false,
                timeout_secs: 120,
            },
            ..PreReleaseGatesConfig::default()
        };

        let config =
            PreReleaseConfig::from_working_dir_with_gates(Path::new("/tmp/testapp"), gates);
        assert!(!config.gates.integration.enabled);
        assert_eq!(config.gates.integration.timeout_secs, 120);
        // Other groups remain default
        assert!(config.gates.e2e.enabled);
    }

    #[test]
    fn test_prerelease_config_with_e2e_custom() {
        let gates = PreReleaseGatesConfig {
            e2e: E2eGatesConfig {
                enabled: true,
                timeout_secs: 1200,
                headless: false,
            },
            ..PreReleaseGatesConfig::default()
        };

        let config =
            PreReleaseConfig::from_working_dir_with_gates(Path::new("/tmp/testapp"), gates);
        assert!(config.gates.e2e.enabled);
        assert_eq!(config.gates.e2e.timeout_secs, 1200);
        assert!(!config.gates.e2e.headless);
    }

    #[test]
    fn test_prerelease_config_skip_flags_default_false() {
        let config = PreReleaseConfig::from_working_dir(Path::new("/tmp/testapp"));
        assert!(!config.skip_backend);
        assert!(!config.skip_frontend);
        assert!(!config.skip_migrations);
    }

    // ====================================================================
    // Gate skip logic tests (via run_*_gates functions)
    // ====================================================================

    #[tokio::test]
    async fn test_backend_gates_skip_all() {
        let mut config = PreReleaseConfig::from_working_dir(Path::new("/tmp/testapp"));
        config.skip_backend = true;

        let result = run_backend_gates(&config).await.unwrap();
        assert!(result.all_passed());
        assert_eq!(result.skipped.len(), 5); // G1-G5
        assert!(result.passed.is_empty());
        assert!(result.failed.is_empty());
        // Verify all gate names are present
        assert!(result.skipped.iter().any(|s| s.contains("G1")));
        assert!(result.skipped.iter().any(|s| s.contains("G2")));
        assert!(result.skipped.iter().any(|s| s.contains("G3")));
        assert!(result.skipped.iter().any(|s| s.contains("G4")));
        assert!(result.skipped.iter().any(|s| s.contains("G5")));
    }

    #[tokio::test]
    async fn test_migration_gates_skip_all() {
        let mut config = PreReleaseConfig::from_working_dir(Path::new("/tmp/testapp"));
        config.skip_migrations = true;

        let result = run_migration_gates(&config).await.unwrap();
        assert!(result.all_passed());
        assert_eq!(result.skipped.len(), 4); // G6-G8b
        assert!(result.skipped.iter().any(|s| s.contains("G6")));
        assert!(result.skipped.iter().any(|s| s.contains("G7")));
        assert!(result.skipped.iter().any(|s| s.contains("G8:")));
        assert!(result.skipped.iter().any(|s| s.contains("G8b")));
    }

    #[tokio::test]
    async fn test_frontend_gates_skip_all() {
        let mut config = PreReleaseConfig::from_working_dir(Path::new("/tmp/testapp"));
        config.skip_frontend = true;

        let result = run_frontend_gates(&config).await.unwrap();
        assert!(result.all_passed());
        assert_eq!(result.skipped.len(), 4); // G9-G12
        assert!(result.skipped.iter().any(|s| s.contains("G9")));
        assert!(result.skipped.iter().any(|s| s.contains("G10")));
        assert!(result.skipped.iter().any(|s| s.contains("G11")));
        assert!(result.skipped.iter().any(|s| s.contains("G12")));
    }

    #[tokio::test]
    async fn test_backend_gates_individual_disable() {
        let mut config = PreReleaseConfig::from_working_dir(Path::new("/tmp/testapp"));
        config.gates.backend.cargo_check = false;
        config.gates.backend.cargo_clippy = false;
        config.gates.backend.cargo_fmt = false;
        config.gates.backend.cargo_test = false;
        config.gates.backend.extract_schema = false;
        // Don't skip_backend — gates are individually disabled

        let result = run_backend_gates(&config).await.unwrap();
        assert!(result.all_passed());
        assert_eq!(result.skipped.len(), 5);
        assert!(result.passed.is_empty());
        // Each should say "(disabled)"
        for s in &result.skipped {
            assert!(s.contains("disabled"), "Expected 'disabled' in: {}", s);
        }
    }

    #[tokio::test]
    async fn test_migration_gates_individual_disable() {
        let mut config = PreReleaseConfig::from_working_dir(Path::new("/tmp/testapp"));
        config.gates.migrations.idempotency_check = false;
        config.gates.migrations.soft_delete_check = false;
        config.gates.migrations.seaorm_safety_check = false;
        config.gates.migrations.data_completeness_check = false;

        let result = run_migration_gates(&config).await.unwrap();
        assert!(result.all_passed());
        assert_eq!(result.skipped.len(), 4);
        for s in &result.skipped {
            assert!(s.contains("disabled"), "Expected 'disabled' in: {}", s);
        }
    }

    #[tokio::test]
    async fn test_frontend_gates_individual_disable() {
        let mut config = PreReleaseConfig::from_working_dir(Path::new("/tmp/testapp"));
        config.gates.frontend.codegen_drift = false;
        config.gates.frontend.type_check = false;
        config.gates.frontend.lint = false;
        config.gates.frontend.unit_tests = false;

        let result = run_frontend_gates(&config).await.unwrap();
        assert!(result.all_passed());
        assert_eq!(result.skipped.len(), 4);
        for s in &result.skipped {
            assert!(s.contains("disabled"), "Expected 'disabled' in: {}", s);
        }
    }

    // ====================================================================
    // Directory verification tests
    // ====================================================================

    #[test]
    fn test_verify_directories_nonexistent_working_dir() {
        let config = PreReleaseConfig::from_working_dir(Path::new("/nonexistent/path"));
        let result = verify_directories(&config);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Working directory does not exist"));
    }

    #[test]
    fn test_verify_directories_skip_backend_allows_missing() {
        let mut config = PreReleaseConfig::from_working_dir(Path::new("/tmp"));
        config.skip_backend = true;
        config.skip_frontend = true;
        // /tmp exists, so working dir check passes
        // skip flags mean backend/frontend dirs aren't checked
        let result = verify_directories(&config);
        assert!(result.is_ok());
    }

    // ====================================================================
    // Config loading from YAML
    // ====================================================================

    #[test]
    fn test_load_gates_config_missing_file_returns_defaults() {
        let config = load_gates_config(Path::new("/nonexistent/path"));
        assert!(config.enabled);
        assert!(config.fail_on_error);
        assert!(config.integration.enabled);
        assert!(config.e2e.enabled);
    }

    /// Whole-module shield: no raw `docker`-literal spawn may live in
    /// `commands/prerelease.rs`. Every docker spawn must resolve
    /// `DOCKER_BIN` via [`super::docker_bin`] first.
    ///
    /// Pre-lift the three `std::process::Command` sites inside
    /// `print_e2e_diagnostics` (docker ps / docker ps -a exited /
    /// docker images) each spelled the bare tool-name literal,
    /// ignoring `DOCKER_BIN` at every site — a Nix-hermetic runner's
    /// substrate-derived docker path lost to whatever `docker` was
    /// first on PATH, so an engineer chasing an E2E flake saw a
    /// different daemon's container list than the one the failing
    /// test actually spawned against.
    ///
    /// This shield scans the module's own source via [`include_str!`]
    /// and forbids the fused literal shape at every spawn form
    /// (`std::process::Command::new(...)`, the bare
    /// `Command::new(...)`, and the `tokio::process::Command::new(...)`
    /// long form). The forbidden shapes are reconstructed via
    /// [`format!`] so this shield's own source text does not
    /// false-match itself — the whole-module scan therefore covers
    /// both the top-of-file production body AND every sibling
    /// `#[cfg(test)]` block (any of which could otherwise silently
    /// re-introduce a raw literal — the most likely growth site as
    /// new diagnostics stanzas land in the pre-release-gate surface).
    /// Also asserts the canonical
    /// `crate::tools::get_tool_path(crate::tools::tools::DOCKER)`
    /// delegation form is present so the sigil-body itself cannot
    /// silently drift away from the substrate-exported env-var
    /// contract.
    ///
    /// The end-to-end `DOCKER_BIN`-routing invariant of the underlying
    /// primitive is pinned separately by
    /// [`crate::tools::tests::test_get_tool_path_from_env`] and
    /// [`crate::tools::tests::test_get_tool_path_fallback`]; this
    /// shield only certifies that every docker-spawning site in this
    /// module reads through `docker_bin()`.
    #[test]
    fn test_docker_spawn_routes_through_docker_bin_not_raw_literal() {
        const SOURCE: &str = include_str!("prerelease.rs");

        // Composed three-primitive stanza — bare-spawn refusal, sigil
        // definition, canonical two-arg delegation — through the
        // shared `assert_source_routes_bare_spawn_through_two_arg_sigil`
        // (e108260). Sigil name (`docker_bin`) and remediation
        // (`resolve \`DOCKER_BIN\` via \`docker_bin()\``) are derived
        // by the helper from `bare` and `env_var`.
        crate::test_support::assert_source_routes_bare_spawn_through_two_arg_sigil(
            SOURCE,
            "commands/prerelease.rs",
            "docker",
            "DOCKER_BIN",
        );
        // Also assert the pre-lift deriving one-arg constant-driven
        // form does NOT reappear at any *code* line. Sibling
        // constant-driven check at `commands/infra.rs` and
        // `commands/local.rs`.
        crate::test_support::assert_source_forbids_deriving_one_arg_sigil_constant_form(
            SOURCE,
            "commands/prerelease.rs",
            "DOCKER_BIN",
            "docker",
            "DOCKER",
        );
    }

    /// Whole-module shield: no raw `cargo`-literal spawn may live in
    /// `commands/prerelease.rs`. Every `cargo` spawn must resolve
    /// `CARGO` via [`super::cargo_bin`] first — the canonical env-var
    /// override every sibling cargo-invocation site in forge honors
    /// (`commands/test_ci.rs` per e1677d3, `commands/developer_tools.rs`
    /// per 8687093, `commands/comprehensive_release.rs` per f95d541,
    /// `commands/bootstrap.rs:639`, `commands/pangea.rs:473`,
    /// `graphql_schema.rs:193`; the doc-comment idiom lives at
    /// `repo.rs:92`).
    ///
    /// Pre-lift each of the seven consumer sites — `run_integration_tests`
    /// (G13 integration-gate cargo-test spawn), `run_e2e_tests` (G14
    /// E2E-gate cargo-test spawn), `run_cargo_check` (G1),
    /// `run_cargo_clippy` (G2), `run_cargo_fmt_check` (G3 fix + G3
    /// --check), and `run_cargo_test` (G4) — spelled the bare-literal
    /// `Command::new(<bare>)` shape verbatim and ignored `CARGO`.
    /// Pre-release
    /// gates are invoked from `product-sdlc.nix` under a hermetic-runner
    /// sandbox that exports `CARGO=/nix/store/...-cargo/bin/cargo`;
    /// pre-lift each verdict (G1–G4, G13, G14) was attributed to whichever
    /// `cargo` the wrapper's PATH found first, not to the substrate-pinned
    /// cargo derivation the flake declared. Same silent-PATH-fallback bug
    /// class the `test_ci.rs` / `developer_tools.rs` /
    /// `comprehensive_release.rs` CARGO lifts (e1677d3 / 8687093 /
    /// f95d541) closed on their respective spawn surfaces.
    ///
    /// This shield scans the module's own source via [`include_str!`] and
    /// forbids the fused literal shape at every spawn form
    /// (`std::process::Command::new(...)`, the bare `Command::new(...)`,
    /// and the `tokio::process::Command::new(...)` long form). The
    /// forbidden shapes are reconstructed via [`format!`] so this
    /// shield's own source text does not false-match itself — the
    /// whole-module scan therefore covers both the top-of-file
    /// production body AND every sibling `#[cfg(test)]` block (any of
    /// which could otherwise silently re-introduce a raw literal — the
    /// most likely growth site as new gate stanzas land in the
    /// pre-release-gate surface). Also asserts the canonical
    /// `crate::repo::get_tool_path("CARGO", "cargo")` delegation form is
    /// present so the sigil-body itself cannot silently drift away from
    /// the substrate-exported env-var contract. Mirrors the sibling
    /// docker-literal shield above.
    #[test]
    fn test_cargo_spawn_routes_through_cargo_bin_not_raw_literal() {
        const SOURCE: &str = include_str!("prerelease.rs");

        // Composed three-primitive stanza (`test_support.rs::
        // assert_source_routes_bare_spawn_through_two_arg_sigil`) —
        // bare-name env-var form (`CARGO`, no `_BIN` suffix) matches
        // the substrate-exported convention every cargo-invocation
        // site in forge honors (`commands/test_ci.rs`,
        // `commands/developer_tools.rs`,
        // `commands/comprehensive_release.rs`,
        // `commands/e2e.rs`).
        crate::test_support::assert_source_routes_bare_spawn_through_two_arg_sigil(
            SOURCE,
            "commands/prerelease.rs",
            "cargo",
            "CARGO",
        );
    }

    /// Whole-module shield: the three best-effort-captured `docker`
    /// diagnostic probes inside [`super::print_e2e_diagnostics`]
    /// (docker ps / docker ps -a --since=15m --filter status=exited /
    /// docker images, the three sites the pre-release G14-failure
    /// post-mortem surface renders in order) MUST delegate through
    /// [`crate::retry::probe_stdout_capture_sync`], never through a
    /// hand-rolled `if let Ok(output) =
    /// std::process::Command::new(docker_bin()).args(...).output() {
    /// let stdout = String::from_utf8_lossy(&output.stdout); ... }`
    /// best-effort captured-output stanza that silently reintroduces
    /// the six-copy pre-lift duplication this commit closes.
    ///
    /// Pre-lift the three sites each carried the verbatim three-line
    /// stanza above (with an explicit `std::process::Command::new`
    /// path override because the top-of-module `use tokio::process::
    /// Command` would otherwise resolve to the async twin), and the
    /// sibling `commands/e2e.rs::print_failure_diagnostics` block
    /// carried three MORE copies (with a bare `Command::new` because
    /// e2e.rs's top-of-module `use` is `std::process::Command`) —
    /// six identically-shaped bodies past THEORY §VI.1's
    /// three-is-a-law threshold (PRIME DIRECTIVE: duplication budget
    /// is zero). Mirrors the sibling shield in
    /// `commands/e2e.rs::docker_bin_routing_tests`, same primitive on
    /// the receiving end.
    ///
    /// The delegation-count floor mirrors the sibling shield in
    /// `commands/e2e.rs`, and the needle-reconstruction discipline
    /// matches the same `format!`-based `probe_stdout_capture_sync(`
    /// needle so this shield's own source text does not self-match.
    #[test]
    fn test_prerelease_diagnostic_probes_route_through_probe_stdout_capture_sync() {
        const SOURCE: &str = include_str!("prerelease.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            SOURCE,
            "commands/prerelease.rs",
        );
        // The three diagnostic probes route through the shared
        // `crate::retry::probe_stdout_capture_sync` primitive: two
        // (docker ps / docker ps -a --since=15m --filter status=exited)
        // reach it INDIRECTLY through the
        // `crate::docker_ps_diag_section::print_docker_ps_diag_section`
        // fused header+probe primitive (which delegates to the two
        // specialized `crate::probe_dump::probe_and_dump_docker_ps_<mode>`
        // wrappers, which in turn delegate to
        // `probe_and_dump_or_none_sync` at the byte level, owning the
        // `--format` template as well as the `(none)`-or-dump ternary),
        // and one (docker images inside
        // `print_e2e_diagnostics_on_failure`) reaches it DIRECTLY
        // because that probe filters its output line-by-line rather
        // than dumping whole. All delegation shapes route through the
        // shared primitive at the byte level; the count floor is the
        // sum of the three, and the shield accepts any shape as a
        // valid delegation.
        let direct_needle = format!("probe_stdout_capture_{}(", "sync");
        let fusion_needle = format!("probe_and_dump_or_none_{}(", "sync");
        let docker_ps_running_needle = format!("probe_and_dump_docker_ps_{}(", "running");
        let docker_ps_exited_needle = format!("probe_and_dump_docker_ps_exited_since_{}(", "15m");
        let docker_ps_diag_section_needle = format!("print_docker_ps_diag_{}(", "section");
        let mut hits = crate::test_support::code_line_hits(body, &direct_needle);
        hits.extend(crate::test_support::code_line_hits(body, &fusion_needle));
        hits.extend(crate::test_support::code_line_hits(
            body,
            &docker_ps_running_needle,
        ));
        hits.extend(crate::test_support::code_line_hits(
            body,
            &docker_ps_exited_needle,
        ));
        hits.extend(crate::test_support::code_line_hits(
            body,
            &docker_ps_diag_section_needle,
        ));
        assert!(
            hits.len() >= 3,
            "commands/prerelease.rs must delegate its three \
             best-effort `docker` diagnostic probes (docker ps / \
             docker ps -a --since=15m --filter status=exited / docker \
             images inside `print_e2e_diagnostics`) through the \
             shared `crate::retry::probe_stdout_capture_sync` \
             primitive — either directly or through the sibling \
             `crate::probe_dump::probe_and_dump_or_none_sync` fusion \
             primitive that owns the `(none)`-or-dump ternary and calls \
             `probe_stdout_capture_sync` internally. Found {} \
             delegation(s) in the top-of-file body, expected at least 3. \
             A regression that reintroduces the pre-lift `if let \
             Ok(output) = std::process::Command::new(docker_bin())\
             .args(...).output() {{ let stdout = \
             String::from_utf8_lossy(&output.stdout); ... }}` stanza \
             re-establishes the six-copy duplication this commit \
             closes. Offending hits: {hits:?}",
            hits.len(),
        );
    }

    /// Whole-module shield: the `SKIP_INTEGRATION` and `SKIP_E2E`
    /// operator-facing gate-skip flags MUST route through
    /// [`crate::repo::truthy_flag_from_env`] — the crate-wide DEFAULT-
    /// FALSE / enable-with-`1`-or-`true` (case-insensitive) sigil that
    /// `commands/helm.rs::republish_enabled` also delegates through.
    ///
    /// Pre-lift each site spelled the inline shape
    /// `std::env::var("<NAME>").map(|v| v == "true" || v == "1")
    /// .unwrap_or(false)` (case-SENSITIVE on `"true"`, silently ignoring
    /// an operator's `SKIP_INTEGRATION=TRUE` / `SKIP_E2E=TRUE`
    /// uppercase export). The primitive is case-insensitive, so post-
    /// lift the uppercase form fires as intended — a load-bearing
    /// behavioral improvement, not a shuffle.
    ///
    /// The shield scans the whole file (production body + this
    /// `#[cfg(test)]` module + docstrings, filtered through
    /// [`crate::test_support::code_line_hits`] so `///` mentions of
    /// `env::var("SKIP_INTEGRATION")` — living inside this test's own
    /// docstring — stay out of scope). Both needles must be absent AND
    /// the two canonical delegations must be present.
    #[test]
    fn skip_gate_flags_route_through_truthy_flag_from_env_sigil() {
        const SOURCE: &str = include_str!("prerelease.rs");
        for env_var in ["SKIP_INTEGRATION", "SKIP_E2E"] {
            let raw_needle = format!("env::var(\"{env_var}\")");
            let raw_hits = crate::test_support::code_line_hits(SOURCE, &raw_needle);
            assert!(
                raw_hits.is_empty(),
                "commands/prerelease.rs must NOT spell the inline \
                 `env::var(\"{env_var}\").map(|v| v == \"true\" || v == \
                 \"1\").unwrap_or(false)` shape — that duplication was \
                 lifted onto [`crate::repo::truthy_flag_from_env`], \
                 which is case-INSENSITIVE and closes the pre-lift drift \
                 vs. `commands/helm.rs::republish_enabled`. A re-inline \
                 would silently reopen the class this shield exists to \
                 close AND revert an operator's `{env_var}=TRUE` \
                 (uppercase) from actually skipping the gate to silently \
                 running it. Offending hits: {raw_hits:?}",
            );
            let sigil_needle = format!("crate::repo::truthy_flag_from_env(\"{env_var}\")");
            let sigil_hits = crate::test_support::code_line_hits(SOURCE, &sigil_needle);
            assert!(
                !sigil_hits.is_empty(),
                "commands/prerelease.rs must delegate the `{env_var}` \
                 gate-skip flag through \
                 `crate::repo::truthy_flag_from_env(\"{env_var}\")` — \
                 the crate-wide DEFAULT-FALSE / enable-with-`1`-or-`true` \
                 (case-insensitive) sigil. Found no delegation call site.",
            );
        }
    }

    /// Whole-module shield: every captured-output `cargo` spawn on the fast-
    /// gate frontier (G1–G4) in this module MUST route through the
    /// [`cargo_output_at`] fusion primitive — the cargo-frontier sibling of
    /// [`frontend_validation::bun_output_at`] on the bun frontier and
    /// [`crate::infrastructure::kubectl::kubectl_output_spawn_anyhow`] on the
    /// kubectl frontier. The shield closes the composition discipline the
    /// sibling `cargo_bin`-routing shield above (CARGO routing at the sigil)
    /// leaves open: even after the sigil ensures every spawn resolves the
    /// substrate-pinned `cargo` derivation, a call site could still (a) forget
    /// the `.current_dir(backend_dir)` and spawn `cargo` in the caller's cwd,
    /// (b) forget the `.with_context(...)` and lose the operator's ability to
    /// tell WHICH cargo invocation spawn-failed, or (c) spell the context
    /// string inconsistently across sites and hide the site from a fleet-wide
    /// grep on the canonical `"Failed to spawn {op}: {io_error}"` envelope.
    ///
    /// # Two-arm pin
    ///
    /// Negative side pins that the pre-lift envelope string
    /// `"Failed to run cargo` NEVER appears in the module body — the
    /// distinguishing feature of the pre-lift shape (a per-site
    /// `.with_context(|| "Failed to run cargo <op>")?` chained onto a bare
    /// `Command::new(&cargo).args(...).current_dir(backend_dir).output().await`).
    /// Re-adding that envelope re-forks the canonical
    /// `"Failed to spawn {op}: {io_error}"` shape the fusion delivers.
    /// Positive side pins ≥5 `cargo_output_at(` delegation calls — a
    /// regression that dropped every delegation could not leave the negative
    /// scan trivially satisfied by absence. Both hits route through
    /// [`crate::test_support::code_line_hits`] so this shield's own docstring
    /// mentions of the needles (living in `///`-prefixed comment lines) never
    /// self-match.
    ///
    /// # Why not a bare `Command::new(&cargo)` count pin
    ///
    /// Unlike the sibling `bun_output_at` shield in
    /// `commands/frontend_validation.rs`, which pins `.output()` count == 1,
    /// this module intentionally keeps two `Command::new(&cargo)` +
    /// `.output()` sites past the fusion: `run_integration_gate` (G13) and
    /// `run_e2e_gate` (G14) each nest the cargo spawn inside
    /// `tokio::time::timeout(...)` for gate-level timeout enforcement and
    /// cannot ride this primitive without dropping the timeout. Pinning the
    /// envelope string instead targets exactly the pre-lift stanza this
    /// primitive replaces — the timeout-wrapped G13/G14 sites do NOT spell
    /// `.with_context(|| "Failed to run cargo …")` on the spawn future and so
    /// cannot false-trip this shield.
    ///
    /// # Fail-before-pass-after
    ///
    /// Pre-lift the five consumer sites (`run_cargo_check` G1,
    /// `run_cargo_clippy` G2, `run_cargo_fmt_check`'s auto-fix + verify arms
    /// G3, `run_cargo_test` G4) each spelled `Command::new(&cargo)…
    /// .with_context(|| "Failed to run cargo <op>")?` verbatim — the
    /// shield's `Failed to run cargo` count-eq-0 assertion fails-before at 5
    /// and passes-after at 0. Mirrors the sibling shield discipline
    /// `test_frontend_validation_bun_captured_spawns_route_through_bun_output_at`
    /// carries on the bun frontier.
    #[test]
    fn cargo_fast_gate_captured_spawns_route_through_cargo_output_at() {
        let body = crate::test_support::module_body_before_tests(
            include_str!("prerelease.rs"),
            "commands/prerelease.rs",
        );
        let raw_context_hits = crate::test_support::code_line_hits(body, "\"Failed to run cargo");
        assert!(
            raw_context_hits.is_empty(),
            "commands/prerelease.rs must NOT spell the per-site \
             `.with_context(|| \"Failed to run cargo <op>\")?` envelope — \
             the canonical envelope is `\"Failed to spawn {{op}}: \
             {{io_error}}\"` via `crate::retry::classify_spawn_anyhow`, \
             delivered by the `cargo_output_at` fusion. Re-adding a \
             `\"Failed to run cargo …\"` context string re-forks the \
             envelope this shield closes across the whole spawn frontier. \
             Offending hits: {raw_context_hits:?}",
        );
        let delegations = crate::test_support::code_line_hits(body, "cargo_output_at(").len();
        assert!(
            delegations >= 5,
            "commands/prerelease.rs must route captured-output `cargo` \
             spawns on the fast-gate frontier through the `cargo_output_at` \
             fusion — found only {delegations} delegation call(s); a dropped \
             call would leave the negative-side scan trivially satisfied by \
             absence. The five load-bearing sites are G1 `run_cargo_check`, \
             G2 `run_cargo_clippy`, G3 `run_cargo_fmt_check` (fix + check \
             arms), and G4 `run_cargo_test`.",
        );
    }

    /// Whole-module shield: every one-shot fast-gate opener (G1, G2, G4)
    /// in this module MUST route its announce + captured-spawn + elapse
    /// three-line preamble through the
    /// [`announce_gate_and_run_cargo_output_at`] fusion primitive — the
    /// sibling of [`cargo_output_at`] one layer up the composition stack,
    /// adding the announce-and-elapse pairing atop the bare captured-spawn
    /// primitive. Pre-lift the three sites spelled the same three-line
    /// stanza verbatim modulo argv, title and op label:
    ///
    /// ```text
    /// let start = crate::ui::print_step_heading_start("G<N>: <title>");
    /// let output = cargo_output_at(&[..], backend_dir, "cargo <op>").await?;
    /// let duration = start.elapsed();
    /// ```
    ///
    /// G3 `run_cargo_fmt_check` intentionally does NOT ride this primitive
    /// because it drives TWO cargo spawns (auto-fix `cargo fmt` +
    /// `cargo fmt -- --check` verify) off ONE start clock; a single-spawn
    /// primitive would either collapse the two-arm shape or double-sample
    /// the elapsed clock.
    ///
    /// # Two-arm pin
    ///
    /// Negative side pins that the per-site
    /// `crate::ui::print_step_heading_start("G<N>:` numbered opener for
    /// each of G1/G2/G4 never re-appears in the module body — a
    /// reconstruction of the announce alone would take it and the paired
    /// `let duration = start.elapsed()` off separate paths (the announce
    /// inline, the elapse still through the primitive) and drift the
    /// pairing one axis at a time. Positive side pins ≥3
    /// `announce_gate_and_run_cargo_output_at(` delegation call sites —
    /// one per migrated gate; a deletion drops the count and cannot leave
    /// the negative-side scan trivially satisfied by absence.
    ///
    /// # Fail-before-pass-after
    ///
    /// Pre-lift the three G1/G2/G4 sites each spelled the numbered
    /// `print_step_heading_start("G<N>:` opener verbatim — this shield's
    /// count-eq-0 assertion on each of the three numbered openers
    /// fails-before at 1 (per site) and passes-after at 0. The needles
    /// are literals in the assertion vec so this shield's own docstring
    /// mentions of the openers (living in `///`-prefixed comment lines)
    /// never self-match via [`crate::test_support::code_line_hits`]'s
    /// doc-comment filter.
    #[test]
    fn cargo_fast_gate_announce_preamble_routes_through_announce_gate_and_run_cargo_output_at() {
        let body = crate::test_support::module_body_before_tests(
            include_str!("prerelease.rs"),
            "commands/prerelease.rs",
        );
        for needle in [
            "print_step_heading_start(\"G1:",
            "print_step_heading_start(\"G2:",
            "print_step_heading_start(\"G4:",
        ] {
            let hits = crate::test_support::code_line_hits(body, needle);
            assert!(
                hits.is_empty(),
                "commands/prerelease.rs must NOT spell the per-site \
                 `crate::ui::print_step_heading_start(\"G<N>: ...\")` \
                 announce half of the pre-lift three-line preamble for \
                 the G1/G2/G4 one-shot cargo gates — the announce + \
                 captured-spawn + elapse preamble routes through \
                 `announce_gate_and_run_cargo_output_at`. Re-inlining the \
                 announce alone would take it and the paired \
                 `let duration = start.elapsed()` off separate paths. \
                 Offending needle `{needle}`, hits: {hits:?}",
            );
        }
        let delegations =
            crate::test_support::code_line_hits(body, "announce_gate_and_run_cargo_output_at(")
                .len();
        assert!(
            delegations >= 3,
            "commands/prerelease.rs must route the announce + \
             captured-spawn + elapse three-line preamble on the G1/G2/G4 \
             one-shot cargo gates through the \
             `announce_gate_and_run_cargo_output_at` fusion — found only \
             {delegations} delegation call(s); a dropped call would leave \
             the negative-side scan trivially satisfied by absence. The \
             three load-bearing sites are G1 `run_cargo_check`, G2 \
             `run_cargo_clippy`, and G4 `run_cargo_test`.",
        );
    }

    /// Whole-module shield: `run_e2e_gate` must not re-inline the pre-lift
    /// fused pair of `let _ = e2e::cleanup_testcontainers(); let _ =
    /// e2e::cleanup_e2e_images();` at any of its three post-test match
    /// arms — every arm routes through
    /// [`super::e2e::discard_post_run_e2e_cleanup`], the fusion primitive
    /// that pins containers-before-images ordering at one body.
    ///
    /// # Two-arm pin
    ///
    /// Negative side pins that neither `let _ = e2e::cleanup_testcontainers()`
    /// nor `let _ = e2e::cleanup_e2e_images()` (the two half-stanzas the
    /// pre-lift arms fused into a two-line block) appears in the module
    /// body — a regression that re-inlined one half of the pair while
    /// leaving the other routed through the primitive would drift the
    /// two-call sequence one arm at a time. Positive side pins ≥3
    /// `discard_post_run_e2e_cleanup(` delegation call sites — one per
    /// `run_e2e_gate`'s `Ok(Ok(_))` / `Ok(Err(_))` / `Err(_)` timeout-
    /// wrapper match arm; a deletion drops the count and fails the
    /// shield, so the negative-side scan cannot be trivially satisfied
    /// by absence.
    ///
    /// Mirrors the sibling shield discipline the whole-module CARGO /
    /// DOCKER routing shields carry above (envelope-string count-eq-0
    /// paired with a delegation-count-floor), which is the same
    /// composition every delegation-count-floor shield across
    /// `commands/e2e.rs` (`docker_bin_routing_tests`,
    /// `ps_filter_rm_f`-count pin) uses to prove that the primitive
    /// carries the load the shield forbids inlining.
    #[test]
    fn run_e2e_gate_post_cleanup_routes_through_discard_post_run_e2e_cleanup() {
        let body = crate::test_support::module_body_before_tests(
            include_str!("prerelease.rs"),
            "commands/prerelease.rs",
        );
        for needle in [
            "let _ = e2e::cleanup_testcontainers()",
            "let _ = e2e::cleanup_e2e_images()",
        ] {
            let hits = crate::test_support::code_line_hits(body, needle);
            assert!(
                hits.is_empty(),
                "commands/prerelease.rs must NOT spell the pre-lift \
                 discard-error half `{needle};` at any `run_e2e_gate` \
                 arm — the fused `cleanup_testcontainers` + \
                 `cleanup_e2e_images` pair lifted onto \
                 `e2e::discard_post_run_e2e_cleanup()`, and re-inlining \
                 one half would drift the two-call sequence one arm at \
                 a time from its siblings. Offending hits: {hits:?}",
            );
        }
        let delegations =
            crate::test_support::code_line_hits(body, "discard_post_run_e2e_cleanup(").len();
        assert!(
            delegations >= 3,
            "commands/prerelease.rs must route `run_e2e_gate`'s three \
             post-test match arms (`Ok(Ok(_))` success/failure fork, \
             `Ok(Err(_))` spawn error, `Err(_)` timeout) through \
             `e2e::discard_post_run_e2e_cleanup()` — found only \
             {delegations} delegation call(s); a dropped call would leave \
             the negative-side scan trivially satisfied by absence, and \
             a `run_e2e_gate` arm that skipped cleanup would leak \
             containers past the gate boundary.",
        );
    }
}
