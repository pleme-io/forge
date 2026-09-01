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

use anyhow::{bail, Context, Result};
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

    pub fn print_summary(&self) {
        println!();
        println!(
            "{}",
            "════════════════════════════════════════════════".bold()
        );
        println!("{}", "  Gate Summary".bold());
        println!(
            "{}",
            "════════════════════════════════════════════════".bold()
        );
        println!();

        if !self.passed.is_empty() {
            println!("{} Passed ({}):", "✅".green(), self.passed.len());
            for gate in &self.passed {
                println!("   {} {}", "✓".green(), gate);
            }
        }

        if !self.skipped.is_empty() {
            println!();
            println!("{} Skipped ({}):", "⏭️".yellow(), self.skipped.len());
            for gate in &self.skipped {
                println!("   {} {}", "○".yellow(), gate);
            }
        }

        if !self.failed.is_empty() {
            println!();
            println!("{} Failed ({}):", "❌".red(), self.failed.len());
            for gate in &self.failed {
                println!("   {} {}", "✗".red(), gate);
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
            println!(
                "{}",
                "✅ All gates passed! Ready for release.".green().bold()
            );
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
                eprintln!("📋 Loaded gate configuration from backend/deploy.yaml");
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
                eprintln!("📋 Loaded gate configuration from product/deploy.yaml");
                return config;
            }
        }
    }

    eprintln!("📋 Using default gate configuration");
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

    println!();
    println!(
        "{}",
        "════════════════════════════════════════════════".bold()
    );
    println!("{}", "  Pre-Release Gates".bold());
    println!(
        "{}",
        "════════════════════════════════════════════════".bold()
    );
    println!();
    println!("Working directory: {}", config.working_dir.display());
    println!("Backend: {}", config.backend_dir.display());
    println!("Frontend: {}", config.web_dir.display());
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
    println!("{}", "Phase 0a: Fast Gates (parallel)".bold().underline());
    println!();

    let (backend_results, migration_results, frontend_results) = tokio::join!(
        run_backend_gates(&config),
        run_migration_gates(&config),
        run_frontend_gates(&config),
    );

    // Merge backend results
    let backend_results = backend_results?;
    summary.passed.extend(backend_results.passed);
    summary.failed.extend(backend_results.failed);
    summary
        .failed_details
        .extend(backend_results.failed_details);
    summary.skipped.extend(backend_results.skipped);

    // Merge migration results
    let migration_results = migration_results?;
    summary.passed.extend(migration_results.passed);
    summary.failed.extend(migration_results.failed);
    summary
        .failed_details
        .extend(migration_results.failed_details);
    summary.skipped.extend(migration_results.skipped);

    // Merge frontend results
    let frontend_results = frontend_results?;
    summary.passed.extend(frontend_results.passed);
    summary.failed.extend(frontend_results.failed);
    summary
        .failed_details
        .extend(frontend_results.failed_details);
    summary.skipped.extend(frontend_results.skipped);

    // ========================================
    // Phase 0b: Integration tests (G13)
    // Requires Docker — testcontainers for Postgres, Redis, NATS
    // ========================================
    let skip_integration = crate::repo::truthy_flag_from_env("SKIP_INTEGRATION");

    if skip_integration || !config.gates.integration.enabled {
        let reason = if skip_integration {
            "SKIP_INTEGRATION=true"
        } else {
            "disabled"
        };
        summary
            .skipped
            .push(format!("G13: Integration tests ({})", reason));
    } else {
        println!();
        println!("{}", "Phase 0b: Integration Tests (G13)".bold().underline());
        println!();

        match run_integration_gate(&config).await {
            Ok(passed) => {
                if passed {
                    summary.passed.push("G13: Integration tests".to_string());
                } else {
                    summary.failed.push("G13: Integration tests".to_string());
                }
            }
            Err(e) => {
                println!("   {} Integration tests error: {}", "❌".red(), e);
                summary.failed.push("G13: Integration tests".to_string());
            }
        }
    }

    // ========================================
    // Phase 0c: E2E tests (G14)
    // Requires Docker + Nix images + Chrome (headless)
    // ========================================
    let skip_e2e = crate::repo::truthy_flag_from_env("SKIP_E2E");

    if skip_e2e || !config.gates.e2e.enabled {
        let reason = if skip_e2e {
            "SKIP_E2E=true"
        } else {
            "disabled"
        };
        summary.skipped.push(format!("G14: E2E tests ({})", reason));
    } else {
        println!();
        println!("{}", "Phase 0c: E2E Tests (G14)".bold().underline());
        println!();

        match run_e2e_gate(&config).await {
            Ok(passed) => {
                if passed {
                    summary.passed.push("G14: E2E tests".to_string());
                } else {
                    summary.failed.push("G14: E2E tests".to_string());
                }
            }
            Err(e) => {
                println!("   {} E2E tests error: {}", "❌".red(), e);
                summary.failed.push("G14: E2E tests".to_string());
            }
        }
    }

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

    println!("{}", "Backend Gates".bold().underline());
    println!();

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

    println!("{}", "Migration Gates".bold().underline());
    println!();

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

    println!("{}", "Frontend Gates".bold().underline());
    println!();

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
    println!("{}", "G13: Integration tests".bold());
    let start = Instant::now();

    // Ensure Docker is running (auto-start on macOS)
    if let Err(e) = e2e::ensure_docker_running() {
        println!("   {} Docker not available: {}", "❌".red(), e);
        return Ok(false);
    }

    let timeout_secs = config.gates.integration.timeout_secs;
    let cargo = cargo_bin();
    let output = tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        Command::new(&cargo)
            .args([
                "test",
                "--test",
                "integration_tests",
                "--features",
                "integration-tests",
            ])
            .current_dir(&config.backend_dir)
            .output(),
    )
    .await;

    let duration = start.elapsed();

    match output {
        Ok(Ok(output)) => {
            if output.status.success() {
                println!(
                    "   {} Integration tests passed ({:.1}s)",
                    "✅".green(),
                    duration.as_secs_f64()
                );
                Ok(true)
            } else {
                let (stdout, stderr) = crate::repo::utf8_lossy_streams(&output);
                println!(
                    "   {} Integration tests failed ({:.1}s)",
                    "❌".red(),
                    duration.as_secs_f64()
                );
                for line in stderr.lines().chain(stdout.lines()).take(15) {
                    if line.contains("FAILED") || line.contains("panicked") {
                        println!("   {}", line.red());
                    }
                }
                Ok(false)
            }
        }
        Ok(Err(e)) => {
            println!("   {} Failed to run integration tests: {}", "❌".red(), e);
            Ok(false)
        }
        Err(_) => {
            println!(
                "   {} Integration tests timed out after {}s",
                "❌".red(),
                timeout_secs
            );
            Ok(false)
        }
    }
}

/// Print diagnostic information when E2E tests fail
fn print_e2e_diagnostics(backend_dir: &Path) {
    println!();
    println!("{}", "── E2E Failure Diagnostics ──".bold().red());

    // Docker containers still running
    println!("\n   Docker containers (running):");
    if let Some(stdout) = crate::retry::probe_stdout_capture_sync(
        &docker_bin(),
        &["ps", "--format", "     {{.Names}}\t{{.Status}}\t{{.Ports}}"],
    ) {
        if stdout.trim().is_empty() {
            println!("     (none)");
        } else {
            print!("{}", stdout);
        }
    }

    // Recently exited containers
    println!("\n   Docker containers (recently exited):");
    if let Some(stdout) = crate::retry::probe_stdout_capture_sync(
        &docker_bin(),
        &[
            "ps",
            "-a",
            "--filter",
            "status=exited",
            "--since",
            "15m",
            "--format",
            "     {{.Names}}\t{{.Status}}\t{{.Image}}",
        ],
    ) {
        if stdout.trim().is_empty() {
            println!("     (none)");
        } else {
            print!("{}", stdout);
        }
    }

    // E2E images
    println!("\n   E2E Docker images:");
    if let Some(stdout) = crate::retry::probe_stdout_capture_sync(
        &docker_bin(),
        &[
            "images",
            "--format",
            "     {{.Repository}}:{{.Tag}}\t{{.Size}}\t{{.ID}}",
        ],
    ) {
        for line in stdout.lines() {
            if line.contains("-backend") || line.contains("-web") {
                println!("{}", line);
            }
        }
    }

    // Screenshots
    let screenshot_dir = backend_dir.join("target/screenshots");
    if let Ok(entries) = std::fs::read_dir(&screenshot_dir) {
        let screenshots: Vec<_> = entries
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "png")
                    .unwrap_or(false)
            })
            .collect();
        if !screenshots.is_empty() {
            println!("\n   Screenshots captured:");
            for entry in &screenshots {
                println!("     {}", entry.path().display());
            }
        }
    }

    println!();
    println!("   {}", "Troubleshooting:".bold());
    println!("     1. Rebuild images:  nix run .#e2e:prepare -- --force");
    println!("     2. Run headful:     nix run .#test:e2e -- --headless false");
    println!("     3. Run one test:    nix run .#test:e2e -- --filter test_name");
    println!("     4. Check logs:      docker logs <container_name>");
    println!("{}", "────────────────────────────".dimmed());
}

/// G14: Run E2E tests (chromiumoxide + testcontainers full stack)
async fn run_e2e_gate(config: &PreReleaseConfig) -> Result<bool> {
    println!("{}", "G14: E2E tests".bold());
    let start = Instant::now();

    // Ensure Docker is running (may already be started by G13)
    if let Err(e) = e2e::ensure_docker_running() {
        println!("   {} Docker not available: {}", "❌".red(), e);
        return Ok(false);
    }

    // Resolve repo root for image preparation
    let repo_root = config.working_dir.to_str().map(|s| s.to_string());

    // Pre-cleanup: ensure no orphaned containers from previous runs
    if let Err(e) = e2e::cleanup_testcontainers() {
        println!("   {} Pre-cleanup warning: {}", "⚠️".yellow(), e);
    }

    // Always force-rebuild E2E images to ensure tests run against the current code.
    // Without force=true, stale images from a previous build would be reused.
    if let Err(e) = e2e::prepare_e2e_images(repo_root.clone(), false, false, true) {
        println!("   {} Failed to prepare E2E images: {}", "❌".red(), e);
        return Ok(false);
    }

    let headless = config.gates.e2e.headless;
    let timeout_secs = config.gates.e2e.timeout_secs;

    let cargo = cargo_bin();
    let mut cmd = Command::new(&cargo);
    cmd.args([
        "test",
        "--test",
        "e2e_tests",
        "--features",
        "integration-tests",
        "--",
        "--include-ignored",
    ])
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
            let _ = e2e::cleanup_testcontainers();
            let _ = e2e::cleanup_e2e_images();

            if output.status.success() {
                println!(
                    "   {} E2E tests passed ({:.1}s)",
                    "✅".green(),
                    duration.as_secs_f64()
                );
                Ok(true)
            } else {
                let (stdout, stderr) = crate::repo::utf8_lossy_streams(&output);
                println!(
                    "   {} E2E tests failed ({:.1}s)",
                    "❌".red(),
                    duration.as_secs_f64()
                );

                // Show all test output for debugging
                println!();
                println!("{}", "── cargo test stdout ──".dimmed());
                for line in stdout.lines() {
                    println!("   {}", line);
                }
                println!("{}", "── cargo test stderr ──".dimmed());
                for line in stderr
                    .lines()
                    .rev()
                    .take(50)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                {
                    if line.contains("FAILED")
                        || line.contains("panicked")
                        || line.contains("error")
                    {
                        println!("   {}", line.red());
                    } else {
                        println!("   {}", line);
                    }
                }
                println!("{}", "───────────────────────".dimmed());

                print_e2e_diagnostics(&config.backend_dir);
                Ok(false)
            }
        }
        Ok(Err(e)) => {
            // Post-cleanup on spawn error
            let _ = e2e::cleanup_testcontainers();
            let _ = e2e::cleanup_e2e_images();

            println!("   {} Failed to run E2E tests: {}", "❌".red(), e);
            print_e2e_diagnostics(&config.backend_dir);
            Ok(false)
        }
        Err(_) => {
            // Post-cleanup on timeout (most critical — Ryuk won't clean up after force-kill)
            let _ = e2e::cleanup_testcontainers();
            let _ = e2e::cleanup_e2e_images();

            println!(
                "   {} E2E tests timed out after {}s ({:.1}s elapsed)",
                "❌".red(),
                timeout_secs,
                duration.as_secs_f64()
            );
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
    println!("{}", "G1: cargo check".bold());
    let start = Instant::now();

    // Check lib and bins only (not tests) - consistent with clippy
    // Test targets require test-helpers feature and are validated separately
    let cargo = cargo_bin();
    let output = Command::new(&cargo)
        .args(["check", "--lib", "--bins"])
        .current_dir(backend_dir)
        .output()
        .await
        .with_context(|| "Failed to run cargo check")?;

    let duration = start.elapsed();

    if output.status.success() {
        println!(
            "   {} Compilation check passed ({:.1}s)",
            "✅".green(),
            duration.as_secs_f64()
        );
        Ok(true)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!(
            "   {} Compilation check failed ({:.1}s)",
            "❌".red(),
            duration.as_secs_f64()
        );
        // Show first few errors
        for line in stderr.lines().take(10) {
            if line.contains("error") {
                println!("   {}", line.red());
            }
        }
        Ok(false)
    }
}

/// G2: Run cargo clippy with deny warnings
async fn run_cargo_clippy(backend_dir: &Path) -> Result<bool> {
    println!("{}", "G2: cargo clippy".bold());
    let start = Instant::now();

    // Check lib and bins only (not tests) - test dead code warnings are expected
    // since GraphQL types aren't constructed directly in test code
    let cargo = cargo_bin();
    let output = Command::new(&cargo)
        .args(["clippy", "--lib", "--bins", "--", "-D", "warnings"])
        .current_dir(backend_dir)
        .output()
        .await
        .with_context(|| "Failed to run cargo clippy")?;

    let duration = start.elapsed();

    if output.status.success() {
        println!(
            "   {} Clippy passed (0 warnings, {:.1}s)",
            "✅".green(),
            duration.as_secs_f64()
        );
        Ok(true)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let warning_count = stderr.matches("warning:").count();

        println!(
            "   {} Clippy failed ({} warnings, {:.1}s)",
            "❌".red(),
            warning_count,
            duration.as_secs_f64()
        );
        // Show first few warnings
        for line in stderr.lines().take(10) {
            if line.contains("warning:") || line.contains("error:") {
                println!("   {}", line);
            }
        }
        Ok(false)
    }
}

/// G3: Run cargo fmt (auto-fix) then verify
async fn run_cargo_fmt_check(backend_dir: &Path) -> Result<bool> {
    println!("{}", "G3: cargo fmt".bold());
    let start = Instant::now();

    // First, auto-fix formatting
    let cargo = cargo_bin();
    let fix_output = Command::new(&cargo)
        .args(["fmt"])
        .current_dir(backend_dir)
        .output()
        .await
        .with_context(|| "Failed to run cargo fmt")?;

    if !fix_output.status.success() {
        let stderr = String::from_utf8_lossy(&fix_output.stderr);
        println!(
            "   {} cargo fmt failed ({:.1}s)",
            "❌".red(),
            start.elapsed().as_secs_f64()
        );
        for line in stderr.lines().take(5) {
            println!("   {}", line);
        }
        return Ok(false);
    }

    // Then verify with --check (should always pass after auto-fix)
    let check_output = Command::new(&cargo)
        .args(["fmt", "--", "--check"])
        .current_dir(backend_dir)
        .output()
        .await
        .with_context(|| "Failed to run cargo fmt --check")?;

    let duration = start.elapsed();

    if check_output.status.success() {
        println!(
            "   {} Code formatting applied and verified ({:.1}s)",
            "✅".green(),
            duration.as_secs_f64()
        );
        Ok(true)
    } else {
        // This shouldn't happen after auto-fix, but handle it
        let stdout = String::from_utf8_lossy(&check_output.stdout);
        let unformatted_files: Vec<&str> = stdout
            .lines()
            .filter(|l| l.starts_with("Diff in"))
            .collect();

        println!(
            "   {} Code formatting check failed after auto-fix ({} files, {:.1}s)",
            "❌".red(),
            unformatted_files.len(),
            duration.as_secs_f64()
        );
        for file in unformatted_files.iter().take(5) {
            println!("   {}", file);
        }
        Ok(false)
    }
}

/// G4: Run cargo test
async fn run_cargo_test(backend_dir: &Path) -> Result<bool> {
    println!("{}", "G4: cargo test".bold());
    let start = Instant::now();

    let cargo = cargo_bin();
    let output = Command::new(&cargo)
        .args(["test", "--lib", "--bins"])
        .current_dir(backend_dir)
        .output()
        .await
        .with_context(|| "Failed to run cargo test")?;

    let duration = start.elapsed();
    let stdout = String::from_utf8_lossy(&output.stdout);

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
        println!(
            "   {} Tests passed ({} tests, {:.1}s)",
            "✅".green(),
            test_count.unwrap_or(0),
            duration.as_secs_f64()
        );
        Ok(true)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!(
            "   {} Tests failed ({:.1}s)",
            "❌".red(),
            duration.as_secs_f64()
        );
        println!();
        // Show full stdout (cargo test writes results there)
        if !stdout.trim().is_empty() {
            println!("{}", "── cargo test output ──".dimmed());
            for line in stdout.lines() {
                if line.contains("FAILED") || line.contains("panicked") || line.contains("error[") {
                    println!("   {}", line.red());
                } else {
                    println!("   {}", line);
                }
            }
        }
        // Show last 40 lines of stderr for compile errors / panic details
        let stderr_lines: Vec<&str> = stderr.lines().collect();
        if !stderr_lines.is_empty() {
            println!("{}", "── stderr (last 40 lines) ──".dimmed());
            let start = stderr_lines.len().saturating_sub(40);
            for line in &stderr_lines[start..] {
                if line.contains("error") || line.contains("FAILED") || line.contains("panicked") {
                    println!("   {}", line.red());
                } else {
                    println!("   {}", line);
                }
            }
        }
        println!("{}", "────────────────────────────".dimmed());
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
        merged.passed.extend(a.passed);
        merged.failed.extend(a.failed);
        merged.skipped.extend(a.skipped);
        merged.passed.extend(b.passed);
        merged.failed.extend(b.failed);
        merged.skipped.extend(b.skipped);

        assert_eq!(merged.passed.len(), 2);
        assert_eq!(merged.failed.len(), 1);
        assert_eq!(merged.skipped.len(), 1);
        assert!(!merged.all_passed());
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
        let needle = format!("probe_stdout_capture_{}(", "sync");
        let hits = crate::test_support::code_line_hits(body, &needle);
        assert!(
            hits.len() >= 3,
            "commands/prerelease.rs must delegate its three \
             best-effort `docker` diagnostic probes (docker ps / \
             docker ps -a --since=15m --filter status=exited / docker \
             images inside `print_e2e_diagnostics`) through the \
             shared `crate::retry::probe_stdout_capture_sync` \
             primitive — found {} delegation(s) in the top-of-file \
             body, expected at least 3. A regression that reintroduces \
             the pre-lift `if let Ok(output) = \
             std::process::Command::new(docker_bin()).args(...)\
             .output() {{ let stdout = String::from_utf8_lossy(\
             &output.stdout); ... }}` stanza re-establishes the \
             six-copy duplication this commit closes. Offending hits: \
             {hits:?}",
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
}
