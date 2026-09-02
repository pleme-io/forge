//! Test command for running unit and integration tests
//!
//! Supports both Rust services (cargo test) and Web services (vitest/playwright)
//!
//! Web services read test configuration from deploy.yaml:
//! - deployment.tests.unit: Unit tests (vitest)
//! - deployment.tests.api_integration: API integration tests (vitest)
//! - deployment.tests.e2e: E2E browser tests (playwright)
//!
//! Each test type has its own `enabled` flag for granular control.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use colored::Colorize;
use serde::Deserialize;
use tokio::process::Command;
use tokio::time::timeout;
use tracing::info;

use crate::retry::RetryPolicy;
use crate::ui::{styled_spinner, SpinnerStyle};

/// The typed exponential-backoff policy for [`run_test_suite`]'s
/// between-retry sleeps — `initial_backoff` 2s × `factor` 2 capped at
/// `max_backoff` 30s. Consumes the pre-existing typed primitive at
/// [`crate::retry::RetryPolicy`] so the per-attempt delay lands at
/// [`RetryPolicy::compute_delay`], whose docstring names its
/// raison d'être: "the pre-existing fixed `sleep(2s)` schedule ... is
/// the worst of both worlds ... Exponential backoff (Bazel-style:
/// 250ms × factor=2 capped at 30s) covers both regimes by
/// construction."
///
/// Pre-lift the three sibling `tokio::time::sleep(Duration::from_secs(2))
/// .await` sites in [`run_test_suite`]'s retry loop (one per failure
/// branch: test-non-zero-exit, command-error, timeout) each carried
/// three defects the typed-primitive body forecloses:
///
/// 1. **Fixed 2s schedule.** A flat `sleep(2s)` between attempts is
///    "too short when it's a 30-second upstream incident, 12 days too
///    long when it's a real integration-test flake that needs the
///    upstream to recover" — the exact failure mode the Bazel / Buck2
///    / BuildKit frontier hermetic-build systems close under an
///    exponential-with-cap schedule.
/// 2. **Three-way duplication of one schedule.** The (2s) magic number
///    lived at three sibling `tokio::time::sleep(Duration::from_secs(2))`
///    call sites in the same retry loop; a future edit to the schedule
///    (say, bumping to 5s to match `run_test_suite_with_retry` at
///    `commands/integration_tests.rs`) had to be applied at three
///    sites in lock-step, or one branch silently diverged. The lifted
///    `TEST_RETRY_BACKOFF` const is one load-bearing structural
///    surface all three branches read through.
/// 3. **No caller-visible schedule invariant.** The bare
///    `Duration::from_secs(2)` literal at three sites carried no name
///    a shield could pin — a future edit that changed the schedule at
///    one branch but not the others silently drifted. The lifted
///    `TEST_RETRY_BACKOFF` const names the (seed, factor, cap) triple
///    a shield can cite and enforce.
///
/// `max_attempts: 1` is a placeholder — the retry loop drives its own
/// attempt budget through the caller-supplied `config.max_retries`
/// parameter of the `for attempt in 1..=max_attempts` loop and
/// consumes only [`RetryPolicy::compute_delay`] from this policy, not
/// [`RetryPolicy::max_attempts`]. The `max_attempts` field is
/// unconsulted at this consumption site.
const TEST_RETRY_BACKOFF: RetryPolicy = RetryPolicy::caller_driven_backoff(Duration::from_secs(2));

/// Backoff between web-test-suite retries, given the 1-indexed local
/// `attempt` counter of the attempt that just failed (the
/// `for attempt in 1..=max_attempts` shape [`run_test_suite`] drives).
///
/// Maps the local 1-indexed counter to the 1-indexed
/// [`RetryPolicy::compute_delay`] attempt axis via `saturating_add(1)`:
/// local `attempt == 1` (the pre-retry sleep after the first failed
/// call) reads as `compute_delay(2) = initial_backoff * factor^0 =
/// initial_backoff`; local `attempt == 2` reads as
/// `compute_delay(3) = initial_backoff * factor^1`; and so on. The
/// `saturating_add` clamp forecloses the `u32` overflow class at the
/// bridge — an unlikely-but-possible `attempt == u32::MAX` from a
/// pathological `config.max_retries` reads as `compute_delay(u32::MAX)`,
/// which itself saturates to [`TEST_RETRY_BACKOFF::max_backoff`] via
/// the `checked_pow`-then-cap body inside [`RetryPolicy::compute_delay`]
/// without panic.
fn test_retry_delay(attempt: u32) -> Duration {
    TEST_RETRY_BACKOFF.compute_delay(attempt.saturating_add(1))
}

/// Test type to run
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TestType {
    Unit,
    Integration,
    All,
}

impl TestType {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "unit" => Ok(TestType::Unit),
            "integration" => Ok(TestType::Integration),
            "all" | "" => Ok(TestType::All),
            _ => bail!(
                "Invalid test type '{}'. Valid options: unit, integration, all",
                s
            ),
        }
    }
}

/// Service type
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ServiceType {
    Rust,
    Web,
}

impl ServiceType {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "rust" => Ok(ServiceType::Rust),
            "web" => Ok(ServiceType::Web),
            _ => bail!("Invalid service type '{}'. Valid options: rust, web", s),
        }
    }
}

// ============================================================================
// Web Test Configuration (from deploy.yaml)
// ============================================================================

/// Single test suite configuration
#[derive(Debug, Clone, Deserialize, Default)]
pub struct TestSuiteConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub command: String,
    #[serde(default)]
    pub working_dir: String,
    #[serde(default = "default_timeout")]
    pub timeout: String,
    #[serde(default)]
    pub retry_on_failure: bool,
    #[serde(default)]
    pub max_retries: u32,
}

fn default_timeout() -> String {
    "5m".to_string()
}

/// Web tests configuration (from deploy.yaml deployment.tests)
#[derive(Debug, Clone, Deserialize, Default)]
pub struct WebTestsConfig {
    #[serde(default)]
    pub unit: TestSuiteConfig,
    #[serde(default)]
    pub api_integration: TestSuiteConfig,
    #[serde(default)]
    pub e2e: TestSuiteConfig,
}

/// Raw deploy.yaml structure for parsing tests
#[derive(Debug, Clone, Deserialize)]
struct RawDeployYaml {
    #[serde(default)]
    deployment: Option<RawDeploymentSection>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct RawDeploymentSection {
    #[serde(default)]
    tests: Option<WebTestsConfig>,
}

/// Load web tests configuration from deploy.yaml
fn load_web_tests_config(service: &str, service_dir: &str) -> Result<WebTestsConfig> {
    let service_dir_path = PathBuf::from(service_dir);
    let deploy_yaml_path = if let Some(product_dir) =
        crate::repo::find_product_dir(&service_dir_path, crate::repo::ProductDirLayout::Monorepo)
    {
        crate::config::resolve_deploy_yaml_path(&product_dir, service, &service_dir_path)
    } else {
        service_dir_path.join("deploy.yaml")
    };

    if !deploy_yaml_path.exists() {
        info!("No deploy.yaml found, using default test configuration");
        return Ok(WebTestsConfig::default());
    }

    let raw_config: RawDeployYaml = crate::repo::read_yaml_sync(&deploy_yaml_path)?;

    Ok(raw_config
        .deployment
        .and_then(|d| d.tests)
        .unwrap_or_default())
}

/// Execute test command
pub async fn execute(
    service: &str,
    service_dir: &str,
    _repo_root: &str,
    service_type: &str,
    test_type: &str,
) -> Result<()> {
    let service_type = ServiceType::from_str(service_type)?;
    let test_type = TestType::from_str(test_type)?;

    println!();
    println!(
        "{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".bright_blue()
    );
    println!(
        "  {} Testing {} ({})",
        "🧪".bright_green(),
        service.bright_cyan(),
        match service_type {
            ServiceType::Rust => "Rust",
            ServiceType::Web => "Web",
        }
    );
    println!(
        "{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".bright_blue()
    );
    println!();

    match service_type {
        ServiceType::Rust => run_rust_tests(service, service_dir, test_type).await,
        ServiceType::Web => run_web_tests(service, service_dir, test_type).await,
    }
}

/// Run Rust tests
async fn run_rust_tests(service: &str, service_dir: &str, test_type: TestType) -> Result<()> {
    let run_unit = test_type == TestType::Unit || test_type == TestType::All;
    let run_integration = test_type == TestType::Integration || test_type == TestType::All;

    let cargo = crate::repo::get_tool_path("CARGO", "cargo");

    if run_unit {
        println!(
            "  {} Running Rust unit tests for {}...",
            "🧪".bright_yellow(),
            service.bright_cyan()
        );

        let mut cmd = Command::new(&cargo);
        cmd.args(["test", "--lib", "--bins"])
            .current_dir(service_dir);
        crate::retry::run_inherited_status(cmd, "cargo test --lib --bins")
            .await
            .context("Failed to run cargo test")?;

        println!("  {} Rust unit tests passed", "✅".bright_green());
    }

    if run_integration {
        println!(
            "  {} Running Rust integration tests for {}...",
            "🔗".bright_yellow(),
            service.bright_cyan()
        );

        let mut cmd = Command::new(&cargo);
        cmd.args(["test", "--test", "*"]).current_dir(service_dir);
        crate::retry::run_inherited_status(cmd, "cargo test --test *")
            .await
            .context("Failed to run cargo integration tests")?;

        println!("  {} Rust integration tests passed", "✅".bright_green());
    }

    print_success_summary();
    Ok(())
}

/// Run Web tests based on deploy.yaml configuration
async fn run_web_tests(service: &str, service_dir: &str, test_type: TestType) -> Result<()> {
    // Load configuration from deploy.yaml
    let config = load_web_tests_config(service, service_dir)?;

    let run_unit = test_type == TestType::Unit || test_type == TestType::All;
    let run_integration = test_type == TestType::Integration || test_type == TestType::All;

    let mut tests_run = 0;
    let mut tests_skipped = 0;

    // Print configuration status
    println!("  📋 Test Configuration (from deploy.yaml):");
    println!(
        "     • Unit tests: {}",
        if config.unit.enabled {
            "enabled".bright_green()
        } else {
            "disabled".bright_yellow()
        }
    );
    println!(
        "     • API integration: {}",
        if config.api_integration.enabled {
            "enabled".bright_green()
        } else {
            "disabled".bright_yellow()
        }
    );
    println!(
        "     • E2E (Playwright): {}",
        if config.e2e.enabled {
            "enabled".bright_green()
        } else {
            "disabled".bright_yellow()
        }
    );
    println!();

    // Unit tests
    if run_unit {
        if config.unit.enabled && !config.unit.command.is_empty() {
            run_test_suite(service, service_dir, "unit", &config.unit).await?;
            tests_run += 1;
        } else if !config.unit.enabled {
            println!(
                "  {} Unit tests: {} (disabled in deploy.yaml)",
                "⏭️ ".bright_yellow(),
                "skipped".dimmed()
            );
            tests_skipped += 1;
        }
    }

    // API Integration tests
    if run_integration {
        if config.api_integration.enabled && !config.api_integration.command.is_empty() {
            run_test_suite(
                service,
                service_dir,
                "api_integration",
                &config.api_integration,
            )
            .await?;
            tests_run += 1;
        } else if !config.api_integration.enabled {
            println!(
                "  {} API integration tests: {} (disabled in deploy.yaml)",
                "⏭️ ".bright_yellow(),
                "skipped".dimmed()
            );
            tests_skipped += 1;
        }

        // E2E tests
        if config.e2e.enabled && !config.e2e.command.is_empty() {
            run_test_suite(service, service_dir, "e2e", &config.e2e).await?;
            tests_run += 1;
        } else if !config.e2e.enabled {
            println!(
                "  {} E2E tests: {} (disabled in deploy.yaml)",
                "⏭️ ".bright_yellow(),
                "skipped".dimmed()
            );
            tests_skipped += 1;
        }
    }

    // Summary
    println!();
    println!(
        "{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".bright_blue()
    );

    if tests_run > 0 {
        println!(
            "  {} {} test suite(s) passed{}",
            "✅".bright_green(),
            tests_run,
            if tests_skipped > 0 {
                format!(", {} skipped", tests_skipped).dimmed().to_string()
            } else {
                String::new()
            }
        );
    } else {
        println!(
            "  {} No tests were run ({} skipped)",
            "⚠️ ".bright_yellow(),
            tests_skipped
        );
    }

    println!(
        "{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".bright_blue()
    );
    println!();

    Ok(())
}

/// Run a single test suite
async fn run_test_suite(
    service: &str,
    service_dir: &str,
    suite_name: &str,
    config: &TestSuiteConfig,
) -> Result<()> {
    println!();
    println!(
        "  {} Running {} tests for {}...",
        match suite_name {
            "unit" => "🧪",
            "api_integration" => "🔗",
            "e2e" => "🌐",
            _ => "📦",
        }
        .bright_yellow(),
        suite_name.bright_cyan(),
        service.bright_cyan()
    );

    if !config.description.is_empty() {
        println!("     {}", config.description.dimmed());
    }
    println!("     Command: {}", config.command.dimmed());
    println!();

    // Malformed `timeout: "5min"` etc. was previously silently swallowed
    // to a 300s default here — the load-bearing hole
    // `crate::duration::parse_timeout_field` closes. `WebTestsConfig` has
    // no `.validate()` on load so this is the sole fail-fast surface for
    // its timeout grammar.
    let test_timeout = crate::duration::parse_timeout_field(
        &config.timeout,
        &format!("test suite '{suite_name}' for service '{service}'"),
    )?;

    let max_attempts = if config.retry_on_failure {
        config.max_retries + 1
    } else {
        1
    };

    let working_dir = if config.working_dir.is_empty() || config.working_dir == "." {
        PathBuf::from(service_dir)
    } else {
        PathBuf::from(service_dir).join(&config.working_dir)
    };

    for attempt in 1..=max_attempts {
        if attempt > 1 {
            println!(
                "     {} Retry attempt {}/{}",
                "🔄".bright_yellow(),
                attempt,
                max_attempts
            );
        }

        let spinner = styled_spinner(
            SpinnerStyle::Cyan,
            format!("Running {} tests...", suite_name),
        );

        let result = timeout(test_timeout, async {
            let output = Command::new(crate::repo::get_tool_path("SH_BIN", "sh"))
                .arg("-c")
                .arg(&config.command)
                .current_dir(&working_dir)
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()
                .await?;

            Ok::<_, anyhow::Error>(output.success())
        })
        .await;

        spinner.finish_and_clear();

        match result {
            Ok(Ok(true)) => {
                println!("  {} {} tests passed", "✅".bright_green(), suite_name);
                return Ok(());
            }
            Ok(Ok(false)) => {
                if attempt == max_attempts {
                    bail!("{} tests failed", suite_name);
                }
                println!("     {} Test failed, will retry...", "⚠️ ".bright_yellow());
                tokio::time::sleep(test_retry_delay(attempt)).await;
            }
            Ok(Err(e)) => {
                if attempt == max_attempts {
                    bail!("{} tests failed: {}", suite_name, e);
                }
                println!(
                    "     {} Command error: {}, will retry...",
                    "⚠️ ".bright_yellow(),
                    e
                );
                tokio::time::sleep(test_retry_delay(attempt)).await;
            }
            Err(_) => {
                if attempt == max_attempts {
                    bail!("{} tests timed out after {:?}", suite_name, test_timeout);
                }
                println!("     {} Timed out, will retry...", "⚠️ ".bright_yellow());
                tokio::time::sleep(test_retry_delay(attempt)).await;
            }
        }
    }

    bail!(
        "{} tests failed after {} attempts",
        suite_name,
        max_attempts
    );
}

fn print_success_summary() {
    println!();
    println!(
        "{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".bright_blue()
    );
    println!("  {} All tests passed!", "✅".bright_green());
    println!(
        "{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".bright_blue()
    );
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_test_type_from_str_unit() {
        assert_eq!(TestType::from_str("unit").unwrap(), TestType::Unit);
        assert_eq!(TestType::from_str("Unit").unwrap(), TestType::Unit);
        assert_eq!(TestType::from_str("UNIT").unwrap(), TestType::Unit);
    }

    #[test]
    fn test_test_type_from_str_integration() {
        assert_eq!(
            TestType::from_str("integration").unwrap(),
            TestType::Integration
        );
    }

    #[test]
    fn test_test_type_from_str_all() {
        assert_eq!(TestType::from_str("all").unwrap(), TestType::All);
        assert_eq!(TestType::from_str("").unwrap(), TestType::All);
    }

    #[test]
    fn test_test_type_from_str_invalid() {
        assert!(TestType::from_str("smoke").is_err());
    }

    #[test]
    fn test_service_type_from_str_rust() {
        assert_eq!(ServiceType::from_str("rust").unwrap(), ServiceType::Rust);
        assert_eq!(ServiceType::from_str("Rust").unwrap(), ServiceType::Rust);
    }

    #[test]
    fn test_service_type_from_str_web() {
        assert_eq!(ServiceType::from_str("web").unwrap(), ServiceType::Web);
    }

    #[test]
    fn test_service_type_from_str_invalid() {
        assert!(ServiceType::from_str("python").is_err());
        assert!(ServiceType::from_str("").is_err());
    }

    /// Whole-module shield: no raw `Command::new("cargo")` may live in
    /// this module's non-test body. Every `cargo` spawn in
    /// `commands/test.rs` — the `run_rust_tests` unit-test spawn and
    /// integration-test spawn — must first resolve `CARGO` via
    /// [`crate::repo::get_tool_path`], the canonical env-var override
    /// every sibling cargo-consuming surface honors
    /// (`commands/test_ci.rs` four sites at e1677d3;
    /// `commands/developer_tools.rs` nine sites at 8687093;
    /// `commands/comprehensive_release.rs` two sites at f95d541;
    /// `commands/prerelease.rs` seven sites at cfdba0d;
    /// `commands/tool.rs` five sites at 79e03a5).
    ///
    /// Pre-lift both sites spelled `Command::new("cargo")` verbatim,
    /// ignoring `CARGO` at every one. `forge test <rust-service>` is
    /// invoked from CI wrappers that export
    /// `CARGO=/nix/store/...-cargo/bin/cargo`; pre-lift the two rust-
    /// test spawns silently fell through to whatever `cargo` the
    /// wrapper's PATH found first — the same silent-PATH-fallback bug
    /// class the `test_ci.rs` (e1677d3), `developer_tools.rs`
    /// (8687093), `comprehensive_release.rs` (f95d541), `prerelease.rs`
    /// (cfdba0d), and `tool.rs` (79e03a5) CARGO lifts closed on their
    /// respective spawn surfaces.
    ///
    /// Scan bounds on the whole-module boundary — from file start to
    /// the FIRST `\n#[cfg(test)]\nmod tests {` marker in source order
    /// — so this shield's own docstring mentions of the forbidden
    /// literal, living in the `#[cfg(test)]` block below that marker,
    /// stay out of scope AND every current or future cargo-spawning
    /// helper landing anywhere in the top-level module body cannot
    /// silently ride along without going through `CARGO`. Mirrors the
    /// whole-module-boundary scan discipline of the sibling
    /// `test_ci.rs` cargo shield (e1677d3) and every sibling module's
    /// CARGO shield.
    #[test]
    fn test_cargo_spawn_routes_through_cargo_env_not_raw_literal() {
        let body = crate::test_support::module_body_before_tests(
            include_str!("test.rs"),
            "commands/test.rs",
        );
        assert!(
            !body.contains("Command::new(\"cargo\")"),
            "commands/test.rs must not spawn `cargo` via the bare literal — \
             every `cargo` spawn must resolve `CARGO` via \
             `crate::repo::get_tool_path(\"CARGO\", \"cargo\")` first. \
             A raw `Command::new(\"cargo\")` bypasses the hermetic-runner \
             contract substrate's mkRuntimeToolsEnv exports."
        );
    }

    /// Whole-module shield: no raw `Command::new("sh")` may live in this
    /// module's non-test body. `run_web_test_suite`'s per-suite spawn
    /// (line 437, inside `timeout(test_timeout, async { … })`) drives
    /// user-supplied `deploy.yaml deployment.tests.<suite>.command`
    /// strings through `sh -c`; every such spawn must first resolve
    /// `SH_BIN` via [`crate::repo::get_tool_path`], the two-arg env-var
    /// override every sibling probe/spawn surface honors
    /// (`commands/nix_builder.rs` `{SSH,NC,DIG}_BIN` four sites at
    /// 5e6672d; `commands/comprehensive_release.rs` `SQLX_BIN` at
    /// ecace0a; `commands/sync.rs` `SEA_ORM_CLI_BIN` at b037895;
    /// `commands/search_sync.rs` `NOVASEARCHCTL_BIN` at 19463db).
    ///
    /// Pre-lift the site spelled `Command::new("sh")` verbatim, ignoring
    /// `SH_BIN` at the site. A Nix-hermetic runner whose derivation
    /// exports `SH_BIN=/nix/store/…-bash/bin/sh` but omits `sh` from
    /// PATH silently fell through to whatever ambient shell an outer
    /// wrapper had (or fail-to-exec, when none) — the same
    /// silent-PATH-fallback bug class the sibling `CARGO` shield
    /// (this module's `run_rust_tests` spawns) closes for the
    /// build-tool surface, here closed for the `sh -c` test-driver
    /// surface.
    ///
    /// Scan bounds on the whole-module boundary — from file start to
    /// the FIRST `\n#[cfg(test)]\nmod tests {` marker in source order
    /// — so this shield's own docstring mentions of the forbidden
    /// literal, living in the `#[cfg(test)]` block below that marker,
    /// stay out of scope AND every current or future `sh`-spawning
    /// helper landing anywhere in the top-level module body cannot
    /// silently ride along without going through `SH_BIN`. The
    /// forbidden shape is reconstructed via [`format!`] from the bare
    /// string `"sh"` so this shield's own source text does not
    /// false-match itself.
    #[test]
    fn test_sh_spawn_routes_through_sh_bin_env_not_raw_literal() {
        let body = crate::test_support::module_body_before_tests(
            include_str!("test.rs"),
            "commands/test.rs",
        );
        crate::test_support::assert_source_forbids_bare_spawn_shapes(
            body,
            "commands/test.rs",
            "sh",
            "resolve `SH_BIN` via `crate::repo::get_tool_path(\"SH_BIN\", \"sh\")`",
        );
        assert!(
            body.contains("get_tool_path(\"SH_BIN\", \"sh\")"),
            "commands/test.rs must resolve the `sh` binary via the \
             canonical `crate::repo::get_tool_path(\"SH_BIN\", \"sh\")` \
             two-arg constructor — the required form was not found \
             in the module body."
        );
    }

    // ====================================================================
    // web-test-suite retry backoff — TEST_RETRY_BACKOFF + helper
    // ====================================================================
    //
    // These pin the RetryPolicy-consuming replacement of the pre-lift
    // three sibling `tokio::time::sleep(Duration::from_secs(2)).await`
    // sites that `run_test_suite`'s retry loop (test-non-zero-exit,
    // command-error, timeout branches) polled through. Sibling of the
    // `FLUX_POLL_BACKOFF` shields at `commands/flux.rs::tests` (commit
    // 65de62f), the `SHINKA_MIGRATION_POLL_BACKOFF` shields at
    // `commands/migrations.rs::tests` (commit b962db5), and the
    // `HEALTH_ENDPOINT_BACKOFF` shields at
    // `commands/post_deploy_verification.rs::tests` (commit b5db3b6) —
    // same const- + delegation-helper shape, same four-test pattern
    // (policy-shape / in-cap-schedule / past-cap-cap /
    // saturating-no-panic), same whole-module boundary shield that
    // forbids re-fusing the pre-lift bare-literal `sleep(2s)` shape.

    /// The `TEST_RETRY_BACKOFF` const's `(initial_backoff, factor,
    /// max_backoff)` triple is the load-bearing invariant every
    /// consumption site (all three retry-loop failure branches, plus
    /// any future retry-loop consumer that reads the same schedule)
    /// shares. Pinned here so a future edit at the const's site is
    /// caught at a named test rather than silently across the three
    /// consumption sites and the delegation helper.
    #[test]
    fn test_test_retry_backoff_policy_shape() {
        assert_eq!(
            TEST_RETRY_BACKOFF.initial_backoff,
            Duration::from_secs(2),
            "TEST_RETRY_BACKOFF.initial_backoff must be 2s \
             — preserves the pre-lift `sleep(Duration::from_secs(2))` \
             seed verbatim at the first between-retry sleep.",
        );
        assert_eq!(
            TEST_RETRY_BACKOFF.factor, 2,
            "TEST_RETRY_BACKOFF.factor must be 2 \
             — Bazel-style doubling climb between retries.",
        );
        assert_eq!(
            TEST_RETRY_BACKOFF.max_backoff,
            Duration::from_secs(30),
            "TEST_RETRY_BACKOFF.max_backoff must be 30s \
             — the shared cap every sibling RetryPolicy-consumer \
             (FLUX_POLL_BACKOFF, SHINKA_MIGRATION_POLL_BACKOFF, \
             HEALTH_ENDPOINT_BACKOFF) also names.",
        );
    }

    /// Pre-lift the first between-retry sleep emitted
    /// `sleep(Duration::from_secs(2))` verbatim; the lift's 1-indexed
    /// `attempt` counter must reproduce that seed at `attempt == 1`
    /// via `test_retry_delay(1)`. The subsequent within-cap attempts
    /// (2/3/4) must emit the Bazel-style doubling climb (4s/8s/16s),
    /// strictly better than the pre-lift flat-2s schedule at every
    /// retry past the first.
    #[test]
    fn test_test_retry_delay_matches_pre_lift_seed_and_climbs_at_in_cap_attempts() {
        assert_eq!(
            test_retry_delay(1),
            Duration::from_secs(2),
            "attempt=1 must sleep 2s — matches pre-lift \
             `sleep(Duration::from_secs(2))` seed verbatim.",
        );
        assert_eq!(
            test_retry_delay(2),
            Duration::from_secs(4),
            "attempt=2 must sleep 4s — Bazel-style `2s * 2 = 4s`.",
        );
        assert_eq!(
            test_retry_delay(3),
            Duration::from_secs(8),
            "attempt=3 must sleep 8s — Bazel-style `4s * 2 = 8s`.",
        );
        assert_eq!(
            test_retry_delay(4),
            Duration::from_secs(16),
            "attempt=4 must sleep 16s — Bazel-style `8s * 2 = 16s`.",
        );
    }

    /// Attempts past the cap must all emit `max_backoff = 30s` —
    /// `(16s * 2).min(30s) = 30s` at attempt=5 and `(30s * 2).min(30s)
    /// = 30s` at every subsequent attempt. `config.max_retries` is a
    /// user-supplied `deploy.yaml` field with no upper bound in the
    /// schema, so beyond-cap attempts must stay at the ceiling rather
    /// than climb past it and stretch a single suite's total retry
    /// wall-clock into hours.
    #[test]
    fn test_test_retry_delay_caps_at_max_backoff_past_the_cap() {
        assert_eq!(
            test_retry_delay(5),
            Duration::from_secs(30),
            "attempt=5 must sleep 30s (cap) — `(16s * 2).min(30s) = 30s`.",
        );
        assert_eq!(
            test_retry_delay(6),
            Duration::from_secs(30),
            "attempt=6 must sleep 30s (cap).",
        );
        assert_eq!(
            test_retry_delay(50),
            Duration::from_secs(30),
            "attempt=50 must sleep 30s (cap) — a pathological \
             `config.max_retries` cannot stretch a single sleep past \
             the ceiling.",
        );
    }

    /// The retry loop's `attempt` counter is a `u32` bounded only by
    /// the caller-supplied `config.max_retries + 1`, so a pathological
    /// deploy.yaml with `max_retries: u32::MAX` could in principle
    /// drive `test_retry_delay(u32::MAX)`. Pre-lift the fixed
    /// `Duration::from_secs(2)` literal never panicked at any attempt;
    /// post-lift `saturating_add(1)` inside `test_retry_delay` bounds
    /// the argument to `RetryPolicy::compute_delay`, whose
    /// `checked_pow`-then-cap body itself saturates without panic.
    /// This test pins that composition: an `attempt == u32::MAX`
    /// argument returns a bounded delay rather than panicking.
    #[test]
    fn test_test_retry_delay_saturates_without_panic_at_arbitrarily_large_attempt() {
        assert_eq!(
            test_retry_delay(u32::MAX),
            Duration::from_secs(30),
            "attempt=u32::MAX must saturate to max_backoff without \
             panic — the `saturating_add(1)` bridge + \
             `RetryPolicy::compute_delay`'s `checked_pow` cap close \
             the u32 overflow class by construction.",
        );
        assert_eq!(
            test_retry_delay(u32::MAX - 1),
            Duration::from_secs(30),
            "attempt=u32::MAX - 1 must also saturate to max_backoff \
             — the bridge `saturating_add(1)` returns u32::MAX, still \
             far past the cap.",
        );
    }

    /// Whole-module boundary shield: the `run_test_suite` retry loop
    /// MUST consume the typed primitive at `test_retry_delay` rather
    /// than re-fusing the pre-lift bare-literal
    /// `tokio::time::sleep(Duration::from_secs(2))` shape (or any
    /// sibling `Duration::from_secs(N)`-in-a-`sleep`-call fixed
    /// schedule). A future refactor that reintroduces a flat
    /// schedule at any of the three failure branches — or grows a
    /// fourth branch and copies the pre-lift shape — fails here, not
    /// silently in production. Whole-module boundary discipline
    /// sibling of
    /// `test_flux_polling_loops_consume_typed_poll_delay_not_bespoke_backoff_struct`
    /// at `commands/flux.rs::tests` (commit 65de62f) and
    /// `test_wait_for_shinka_migration_consumes_typed_poll_delay_not_mut_backoff_secs`
    /// at `commands/migrations.rs::tests` (commit b962db5).
    ///
    /// Code-line filter (via [`crate::test_support::code_line_hits`])
    /// skips docstring / prose-comment lines, so the shield does not
    /// false-positive on `TEST_RETRY_BACKOFF`'s own docstring above
    /// (which cites the pre-lift `Duration::from_secs(2)` shape as
    /// context for the three defects it forecloses).
    #[test]
    fn test_run_test_suite_consumes_typed_retry_delay_not_bare_fixed_sleep() {
        let module_body = crate::test_support::module_body_before_tests(
            include_str!("test.rs"),
            "commands/test.rs",
        );

        let bare_sleep_hits =
            crate::test_support::code_line_hits(module_body, "sleep(Duration::from_secs(2))");
        assert!(
            bare_sleep_hits.is_empty(),
            "commands/test.rs must NOT drive the retry loop through \
             a bare `sleep(Duration::from_secs(2))` — the sleep site \
             must consume `test_retry_delay(attempt)`, grounding \
             through `RetryPolicy::compute_delay`. Found code-line \
             hits: {:#?}",
            bare_sleep_hits,
        );
        let delegation_hits =
            crate::test_support::code_line_hits(module_body, "test_retry_delay(attempt)");
        assert!(
            !delegation_hits.is_empty(),
            "commands/test.rs must consume the typed retry-delay \
             helper at every failure branch of `run_test_suite`'s \
             retry loop — the canonical delegation call was not \
             found at any code line.",
        );
    }
}
