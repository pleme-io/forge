use anyhow::{bail, Context, Result};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::time::{sleep, timeout};
use tracing::{debug, error, info, warn};

use crate::infrastructure::kubectl::kubectl_command_async;
use crate::retry::RetryPolicy;

/// The typed exponential-backoff policy for [`execute_suite`]'s
/// between-retry sleeps — `initial_backoff` 5s × `factor` 2 capped at
/// `max_backoff` 30s. Consumes the pre-existing typed primitive at
/// [`crate::retry::RetryPolicy`] so the per-attempt delay lands at
/// [`RetryPolicy::compute_delay`], whose docstring names its
/// raison d'être: "the pre-existing fixed `sleep(2s)` schedule ... is
/// the worst of both worlds ... Exponential backoff (Bazel-style:
/// 250ms × factor=2 capped at 30s) covers both regimes by
/// construction."
///
/// Pre-lift the three sibling `sleep(Duration::from_secs(5)).await`
/// sites in [`execute_suite`]'s post-deployment retry loop (one per
/// failure branch: test-non-zero-exit, command-error, timeout) each
/// carried three defects the typed-primitive body forecloses,
/// exactly the sibling-shape the `TEST_RETRY_BACKOFF` docstring at
/// `commands/test.rs::run_test_suite` (commit 9fd38d3) cites for
/// its own three-sibling `sleep(Duration::from_secs(2)).await`
/// retry-loop lift:
///
/// 1. **Fixed 5s schedule.** A flat `sleep(5s)` between attempts is
///    "too short when it's a 30-second upstream incident, 12 days too
///    long when it's a real integration-test flake that needs the
///    upstream to recover" — the exact failure mode the Bazel / Buck2
///    / BuildKit frontier hermetic-build systems close under an
///    exponential-with-cap schedule.
/// 2. **Three-way duplication of one schedule.** The (5s) magic number
///    lived at three sibling `sleep(Duration::from_secs(5))` call sites
///    in the same retry loop; a future edit to the schedule had to be
///    applied at three sites in lock-step, or one branch silently
///    diverged. The lifted `INTEGRATION_TEST_RETRY_BACKOFF` const is
///    one load-bearing structural surface all three branches read
///    through.
/// 3. **No caller-visible schedule invariant.** The bare
///    `Duration::from_secs(5)` literal at three sites carried no name
///    a shield could pin. The lifted `INTEGRATION_TEST_RETRY_BACKOFF`
///    const names the (seed, factor, cap) triple a shield can cite
///    and enforce.
///
/// `max_attempts: 1` is a placeholder — the retry loop drives its own
/// attempt budget through the caller-supplied `suite.max_retries`
/// deploy.yaml field and consumes only [`RetryPolicy::compute_delay`]
/// from this policy, not [`RetryPolicy::max_attempts`]. The
/// `max_attempts` field is unconsulted at this consumption site.
const INTEGRATION_TEST_RETRY_BACKOFF: RetryPolicy =
    RetryPolicy::caller_driven_backoff(Duration::from_secs(5));

/// Backoff between post-deployment integration-test-suite retries,
/// given the 1-indexed local `attempts` counter of the attempt that
/// just failed (the `loop { attempts += 1; ... }` shape
/// [`execute_suite`] drives).
///
/// Maps the local 1-indexed counter to the 1-indexed
/// [`RetryPolicy::compute_delay`] attempt axis via `saturating_add(1)`:
/// local `attempts == 1` (the pre-retry sleep after the first failed
/// call) reads as `compute_delay(2) = initial_backoff * factor^0 =
/// initial_backoff = 5s`; local `attempts == 2` reads as
/// `compute_delay(3) = 10s`; local `attempts == 3` reads as
/// `compute_delay(4) = 20s`; local `attempts == 4` reads as
/// `compute_delay(5) = min(40s, 30s) = 30s` (cap); local
/// `attempts >= 4` stays at 30s. The `saturating_add` clamp forecloses
/// the `u32` overflow class at the bridge — an unlikely-but-possible
/// `attempts == u32::MAX` from a pathological `suite.max_retries`
/// reads as `compute_delay(u32::MAX)`, which itself saturates to
/// [`INTEGRATION_TEST_RETRY_BACKOFF::max_backoff`] via the
/// `checked_pow`-then-cap body inside [`RetryPolicy::compute_delay`]
/// without panic.
fn integration_test_retry_delay(attempts: u32) -> Duration {
    INTEGRATION_TEST_RETRY_BACKOFF.compute_delay(attempts.saturating_add(1))
}

/// The typed exponential-backoff policy for [`execute`]'s post-deployment
/// readiness poll loop — `initial_backoff` 2s × `factor` 2 capped at
/// `max_backoff` 30s. Consumes the pre-existing typed primitive at
/// [`crate::retry::RetryPolicy`] so the per-attempt delay lands at
/// [`RetryPolicy::compute_delay`], which the retry module's docstring
/// names as its raison d'être: "the pre-existing fixed `sleep(2s)`
/// schedule ... is the worst of both worlds ... Exponential backoff
/// (Bazel-style: 250ms × factor=2 capped at 30s) covers both regimes
/// by construction."
///
/// Pre-lift the readiness poll loop drove a flat
/// `sleep(Duration::from_secs(2)).await` at every non-terminal iteration
/// of the wall-clock-bounded `while start.elapsed() < max_wait` loop
/// that waits for the freshly-deployed application's `/health` endpoint
/// to return 200 before the post-deployment integration-test suite runs.
/// That shape carried three structural defects the typed-primitive body
/// forecloses, exactly the sibling shape the `HEALTH_ENDPOINT_BACKOFF`
/// docstring at `commands/post_deploy_verification.rs::verify_health_endpoint`
/// (commit b5db3b6) cites for its own health-endpoint retry-loop lift:
///
/// 1. **Fixed 2s schedule.** A flat `sleep(2s)` between health probes is
///    "too short when the application is still starting (a stream of
///    HTTP GETs every 2s across the full `warmup_delay` window
///    hammering an application that hasn't yet bound its port), 2s too
///    long when `/health` flipped to 200 100ms ago" — the exact worst-
///    of-both failure mode the sibling `HEALTH_ENDPOINT_BACKOFF` /
///    `SERVICES_HEALTHY_POLL_BACKOFF` / `MIGRATION_JOB_POLL_BACKOFF` /
///    `SHINKA_MIGRATION_POLL_BACKOFF` / `GITHUB_RUNNER_ROLLOUT_POLL_BACKOFF`
///    / `FEDERATION_JOB_POLL_BACKOFF` docstrings cite. Post-lift the
///    first probe still waits 2s (preserving the seed verbatim), then
///    4s / 8s / 16s / 30s / 30s / … under the exponential-with-cap
///    climb rather than the pre-lift flat 2s at every probe.
/// 2. **No caller-visible schedule invariant.** The bare
///    `Duration::from_secs(2)` literal at the poll-loop sleep carried
///    no name a shield could pin — a future edit that changed the
///    schedule at this site did not surface at any named-primitive
///    audit path. The lifted `POST_DEPLOYMENT_READINESS_POLL_BACKOFF`
///    const names the (seed, factor, cap) triple a shield can cite
///    and enforce.
/// 3. **Schedule desync from the sibling health-poll surface.** The
///    post-deployment readiness poll observes the freshly-deployed
///    application's `/health` endpoint transitioning to 200 the same
///    way the sibling health-endpoint retry loop
///    (`commands/post_deploy_verification.rs::verify_health_endpoint`,
///    b5db3b6) observes it, and the same way the sibling docker-compose
///    services-healthy poll loop
///    (`commands/comprehensive_release.rs::execute`, ad2e31e) observes
///    docker `ps` status. Pre-lift each spelled its own local fixed-
///    sleep schedule, so a future edit to one silently diverged from
///    the others. Post-lift all three consume the same shared body via
///    the same `RetryPolicy::network()` `(factor=2, max_backoff=30s)`
///    reference schedule.
///
/// `max_attempts: 1` is a placeholder — the readiness poll loop drives
/// its own budget through the `while start.elapsed() < max_wait` wall-
/// clock bound (`max_wait` from the caller-supplied
/// `execution.warmup_delay` deploy.yaml field) and consumes only
/// [`RetryPolicy::compute_delay`] from this policy, not
/// [`RetryPolicy::max_attempts`]. The `max_attempts` field is
/// unconsulted at this consumption site.
const POST_DEPLOYMENT_READINESS_POLL_BACKOFF: RetryPolicy =
    RetryPolicy::caller_driven_backoff(Duration::from_secs(2));

/// Backoff between post-deployment readiness poll iterations, given the
/// 0-indexed local `backoff_attempt` counter of the iteration about to
/// sleep (the `while start.elapsed() < max_wait { ... backoff_attempt +=
/// 1 }` shape [`execute`]'s readiness poll loop drives).
///
/// Maps the local 0-indexed counter to the 1-indexed
/// [`RetryPolicy::compute_delay`] attempt axis via `saturating_add(2)`:
/// local `backoff_attempt == 0` (the first between-probe sleep after
/// the first failed `/health` GET) reads as `compute_delay(2) =
/// initial_backoff * factor^0 = initial_backoff = 2s`; local
/// `backoff_attempt == 1` reads as `compute_delay(3) = 4s`;
/// `backoff_attempt == 2` reads as `compute_delay(4) = 8s`;
/// `backoff_attempt == 3` reads as `compute_delay(5) = 16s`;
/// `backoff_attempt >= 4` reads as `compute_delay(>=6) = 30s` (cap) —
/// preserves the pre-lift `sleep(Duration::from_secs(2))` seed verbatim
/// at the first probe and strictly diverges upward at every later
/// probe. The `saturating_add` clamp forecloses the `u32` overflow
/// class at the bridge — an unlikely-but-possible `backoff_attempt ==
/// u32::MAX` from a pathological `warmup_delay` wall-clock window reads
/// as `compute_delay(u32::MAX)`, which itself saturates to
/// [`POST_DEPLOYMENT_READINESS_POLL_BACKOFF::max_backoff`] via the
/// `checked_pow`-then-cap body inside [`RetryPolicy::compute_delay`]
/// without panic.
fn post_deployment_readiness_poll_delay(backoff_attempt: u32) -> Duration {
    POST_DEPLOYMENT_READINESS_POLL_BACKOFF.compute_delay(backoff_attempt.saturating_add(2))
}

/// The typed exponential-backoff policy for
/// [`execute_pre_deployment_tests`]'s between-retry sleeps —
/// `initial_backoff` 2s × `factor` 2 capped at `max_backoff` 30s.
/// Consumes the pre-existing typed primitive at
/// [`crate::retry::RetryPolicy`] so the per-attempt delay lands at
/// [`RetryPolicy::compute_delay`], whose docstring names its raison
/// d'être: "the pre-existing fixed `sleep(2s)` schedule ... is the
/// worst of both worlds ... Exponential backoff (Bazel-style: 250ms ×
/// factor=2 capped at 30s) covers both regimes by construction."
///
/// Pre-lift the bare `sleep(Duration::from_secs(2)).await` at the
/// pre-deployment-test-suite retry loop's between-attempt sleep site
/// carried three defects the typed-primitive body forecloses, exactly
/// the sibling shape the `INTEGRATION_TEST_RETRY_BACKOFF` docstring
/// above (this same module) and the `TEST_RETRY_BACKOFF` docstring at
/// `commands/test.rs::run_test_suite` (commit 9fd38d3) each cite for
/// their own test-suite retry-loop lifts:
///
/// 1. **Fixed 2s schedule.** A flat `sleep(2s)` between attempts is
///    "too short when it's a 30-second upstream incident, 28 minutes
///    too long when the retry loop drives its full `max_retries`
///    budget against a real pre-deployment test flake that needs the
///    upstream to recover" — the exact failure mode the Bazel /
///    Buck2 / BuildKit frontier hermetic-build systems close under an
///    exponential-with-cap schedule.
/// 2. **No caller-visible schedule invariant.** The bare
///    `Duration::from_secs(2)` literal at the sleep site carried no
///    name a shield could pin — a future edit that changed the
///    schedule at this site did not surface at any named-primitive
///    audit path. The lifted `PRE_DEPLOYMENT_TEST_SUITE_RETRY_BACKOFF`
///    const names the (seed, factor, cap) triple a shield can cite
///    and enforce.
/// 3. **Schedule desync from the sibling test-suite retry surface.**
///    The pre-deployment-test-suite retry loop drives an identical
///    `loop { attempts += 1; ... if attempts < max_attempts { sleep;
///    } }` shape to `execute_suite`'s post-deployment retry loop
///    (this same module, `INTEGRATION_TEST_RETRY_BACKOFF`) and
///    `run_test_suite`'s web-test-suite retry loop
///    (`commands/test.rs`, `TEST_RETRY_BACKOFF`, commit 9fd38d3).
///    Pre-lift each spelled its own local fixed-sleep schedule (5s /
///    5s / 2s), so a future edit to one silently diverged from the
///    others. Post-lift all three consume the same shared body via
///    the same `RetryPolicy::network()` `(factor=2, max_backoff=30s)`
///    reference schedule; only the seeds diverge, preserved per site
///    at the named const.
///
/// `max_attempts: 1` is a placeholder — the retry loop drives its own
/// attempt budget through the caller-supplied `suite.max_retries`
/// pre-deployment-tests config field and consumes only
/// [`RetryPolicy::compute_delay`] from this policy, not
/// [`RetryPolicy::max_attempts`]. The `max_attempts` field is
/// unconsulted at this consumption site.
const PRE_DEPLOYMENT_TEST_SUITE_RETRY_BACKOFF: RetryPolicy =
    RetryPolicy::caller_driven_backoff(Duration::from_secs(2));

/// Backoff between pre-deployment test-suite retries, given the
/// 1-indexed local `attempts` counter of the attempt that just failed
/// (the `loop { attempts += 1; ... }` shape
/// [`execute_pre_deployment_tests`] drives).
///
/// Maps the local 1-indexed counter to the 1-indexed
/// [`RetryPolicy::compute_delay`] attempt axis via `saturating_add(1)`:
/// local `attempts == 1` (the pre-retry sleep after the first failed
/// call) reads as `compute_delay(2) = initial_backoff * factor^0 =
/// initial_backoff = 2s`; local `attempts == 2` reads as
/// `compute_delay(3) = 4s`; `attempts == 3` reads as
/// `compute_delay(4) = 8s`; `attempts == 4` reads as
/// `compute_delay(5) = 16s`; `attempts >= 5` reads as
/// `compute_delay(>=6) = 30s` (cap). The `saturating_add` clamp
/// forecloses the `u32` overflow class at the bridge — an
/// unlikely-but-possible `attempts == u32::MAX` from a pathological
/// `suite.max_retries` reads as `compute_delay(u32::MAX)`, which
/// itself saturates to
/// [`PRE_DEPLOYMENT_TEST_SUITE_RETRY_BACKOFF::max_backoff`] via the
/// `checked_pow`-then-cap body inside [`RetryPolicy::compute_delay`]
/// without panic.
fn pre_deployment_test_suite_retry_delay(attempts: u32) -> Duration {
    PRE_DEPLOYMENT_TEST_SUITE_RETRY_BACKOFF.compute_delay(attempts.saturating_add(1))
}

/// Integration test suite configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestSuite {
    pub name: String,
    pub description: String,
    pub command: String,
    pub working_dir: String,
    pub timeout: String,
    pub retry_on_failure: bool,
    pub max_retries: u32,
}

/// Test execution configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionConfig {
    pub parallel: bool,
    pub fail_fast: bool,
    pub warmup_delay: String,
}

/// Test environment configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentConfig {
    pub base_url: String,
    pub graphql_endpoint: String,
    pub test_user_email_secret: Option<String>,
    pub test_user_password_secret: Option<String>,
}

/// On-failure action configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnFailureConfig {
    pub action: String, // rollback | continue | fail
    pub notify: Vec<String>,
}

/// Complete integration test configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationTestConfig {
    pub enabled: bool,
    pub test_suites: Vec<TestSuite>,
    pub execution: ExecutionConfig,
    pub environment: EnvironmentConfig,
    pub on_failure: OnFailureConfig,
}

/// Parsed test counts from test runner output
#[derive(Debug, Clone, Default)]
pub struct TestCounts {
    pub passed: u32,
    pub failed: u32,
    pub skipped: u32,
}

impl TestCounts {
    pub fn total(&self) -> u32 {
        self.passed + self.failed + self.skipped
    }
}

/// Test result
#[derive(Debug, Clone)]
pub struct TestResult {
    pub suite_name: String,
    pub success: bool,
    pub duration: Duration,
    pub output: String,
    pub attempts: u32,
    pub test_counts: Option<TestCounts>,
}

/// Parse the `deployment.integration_tests.execution.warmup_delay`
/// `deploy.yaml` field through the canonical [`crate::duration`] grammar
/// oracle, echoing both the offending value and the field name on grammar
/// rejection.
///
/// Post-deployment peer of the four other `deploy.yaml` timeout-field
/// parse sites the [`crate::duration::parse_timeout_field`] helper serves
/// (`PreDeploymentTestsConfig::validate` at config-load, `run_test_suite`
/// in [`crate::commands::test`], [`execute_pre_deployment_tests`], and
/// [`parse_post_deployment_suite_timeout`] here). Before this rerouting,
/// a malformed `warmup_delay: "5min"` fired an error that named the
/// offending value but NOT the field name — a `deploy.yaml` author had to
/// hunt through the file to find which timeout forge rejected. Fails
/// LOUD now, naming both.
fn parse_post_deployment_warmup_delay(value: &str) -> Result<Duration> {
    crate::duration::parse_timeout_field(
        value,
        "post-deployment integration tests execution.warmup_delay",
    )
}

/// Parse a post-deployment `deployment.integration_tests.test_suites[]`
/// entry's `timeout` field through the canonical [`crate::duration`]
/// grammar oracle, naming the offending suite alongside the offending
/// value on grammar rejection.
///
/// The post-deployment peer of the pre-deployment inline
/// `parse_timeout_field(&s, &format!("pre-deployment test suite '{}'",
/// ...))` shape at [`execute_pre_deployment_tests`]: the label prefix
/// distinguishes pre-deployment from post-deployment so a `deploy.yaml`
/// author with a shared suite name ("e2e") in both stages sees which
/// stage's suite forge refused.
fn parse_post_deployment_suite_timeout(suite: &TestSuite) -> Result<Duration> {
    crate::duration::parse_timeout_field(
        &suite.timeout,
        &format!("post-deployment integration test suite '{}'", suite.name),
    )
}

/// Parse test counts from test runner output
/// Supports multiple formats: Vitest, Cargo test, Playwright, Jest
fn parse_test_counts(output: &str) -> Option<TestCounts> {
    // Vitest format: "Tests  3 passed | 1 failed (4)" or "Tests  3 passed (3)"
    // Also handles: "✓ 3 passed" / "× 1 failed"
    let vitest_summary = Regex::new(
        r"Tests\s+(\d+)\s+passed(?:\s*\|\s*(\d+)\s+failed)?(?:\s*\|\s*(\d+)\s+skipped)?",
    )
    .ok()?;

    if let Some(caps) = vitest_summary.captures(output) {
        let passed = caps
            .get(1)
            .and_then(|m| m.as_str().parse().ok())
            .unwrap_or(0);
        let failed = caps
            .get(2)
            .and_then(|m| m.as_str().parse().ok())
            .unwrap_or(0);
        let skipped = caps
            .get(3)
            .and_then(|m| m.as_str().parse().ok())
            .unwrap_or(0);
        return Some(TestCounts {
            passed,
            failed,
            skipped,
        });
    }

    // Cargo test format: "test result: ok. 5 passed; 0 failed; 1 ignored"
    let cargo_test =
        Regex::new(r"test result:.*?(\d+)\s+passed;\s*(\d+)\s+failed;\s*(\d+)\s+ignored").ok()?;

    if let Some(caps) = cargo_test.captures(output) {
        let passed = caps
            .get(1)
            .and_then(|m| m.as_str().parse().ok())
            .unwrap_or(0);
        let failed = caps
            .get(2)
            .and_then(|m| m.as_str().parse().ok())
            .unwrap_or(0);
        let skipped = caps
            .get(3)
            .and_then(|m| m.as_str().parse().ok())
            .unwrap_or(0);
        return Some(TestCounts {
            passed,
            failed,
            skipped,
        });
    }

    // Playwright format: "3 passed" or "2 failed" or "1 skipped"
    // Usually appears as separate lines near the end
    let playwright_passed = Regex::new(r"(\d+)\s+passed").ok()?;
    let playwright_failed = Regex::new(r"(\d+)\s+failed").ok()?;
    let playwright_skipped = Regex::new(r"(\d+)\s+skipped").ok()?;

    // Check if this looks like Playwright output (contains timing info like "3 passed (1.5s)")
    if output.contains("passed (") || output.contains("failed (") {
        let passed = playwright_passed
            .captures(output)
            .and_then(|c| c.get(1))
            .and_then(|m| m.as_str().parse().ok())
            .unwrap_or(0);
        let failed = playwright_failed
            .captures(output)
            .and_then(|c| c.get(1))
            .and_then(|m| m.as_str().parse().ok())
            .unwrap_or(0);
        let skipped = playwright_skipped
            .captures(output)
            .and_then(|c| c.get(1))
            .and_then(|m| m.as_str().parse().ok())
            .unwrap_or(0);

        if passed > 0 || failed > 0 {
            return Some(TestCounts {
                passed,
                failed,
                skipped,
            });
        }
    }

    // Jest format: "Tests:       3 passed, 1 failed, 4 total"
    let jest_test = Regex::new(
        r"Tests:\s+(?:(\d+)\s+passed)?(?:,\s*)?(?:(\d+)\s+failed)?(?:,\s*)?(?:(\d+)\s+skipped)?(?:,\s*)?(\d+)\s+total"
    ).ok()?;

    if let Some(caps) = jest_test.captures(output) {
        let passed = caps
            .get(1)
            .and_then(|m| m.as_str().parse().ok())
            .unwrap_or(0);
        let failed = caps
            .get(2)
            .and_then(|m| m.as_str().parse().ok())
            .unwrap_or(0);
        let skipped = caps
            .get(3)
            .and_then(|m| m.as_str().parse().ok())
            .unwrap_or(0);
        return Some(TestCounts {
            passed,
            failed,
            skipped,
        });
    }

    None
}

/// Execute integration tests after successful deployment
pub async fn execute(
    config: IntegrationTestConfig,
    working_dir: PathBuf,
) -> Result<Vec<TestResult>> {
    if !config.enabled {
        info!("📊 Integration tests disabled in config");
        return Ok(vec![]);
    }

    println!();
    println!(
        "{}",
        "╔═══════════════════════════════════════════════════════════════╗"
            .bright_cyan()
            .bold()
    );
    println!(
        "{}",
        "║  📊 Running Post-Deployment Integration Tests              ║"
            .bright_cyan()
            .bold()
    );
    println!(
        "{}",
        "╚═══════════════════════════════════════════════════════════════╝"
            .bright_cyan()
            .bold()
    );
    println!();

    // Wait for application to be ready by polling health endpoint
    info!("🔍 Waiting for application to be ready...");
    // Malformed `warmup_delay: "5min"` etc. previously errored without
    // naming which `deploy.yaml` field forge refused — `?` propagates the
    // grammar-oracle error verbatim, but the outer context was missing.
    // Routing through the field-naming helper closes the residual gap
    // the `parse_timeout_field` module was built to close: a
    // `deploy.yaml` timeout parse names BOTH the offending value AND
    // the offending field at every deploy-pipeline call site.
    let max_wait = parse_post_deployment_warmup_delay(&config.execution.warmup_delay)?;
    let health_url = format!("{}/health", config.environment.base_url);

    let start = std::time::Instant::now();
    let mut ready = false;
    let mut backoff_attempt: u32 = 0;

    while start.elapsed() < max_wait {
        match reqwest::get(&health_url).await {
            Ok(response) if response.status().is_success() => {
                // Parse health response to get version information
                if let Ok(health_json) = response.json::<serde_json::Value>().await {
                    info!(
                        "   ✅ Application is ready (took {:.1}s)",
                        start.elapsed().as_secs_f64()
                    );

                    // Log version information if available
                    if let Some(version) = health_json.get("version") {
                        info!("   📦 Deployment version:");
                        if let Some(git_sha) = version.get("gitSha") {
                            info!("      Git SHA: {}", git_sha);
                        }
                        if let Some(app_version) = version.get("version") {
                            info!("      App: {}", app_version);
                        }
                        if let Some(build_time) = version.get("buildTime") {
                            info!("      Built: {}", build_time);
                        }
                    }
                } else {
                    info!(
                        "   ✅ Application is ready (took {:.1}s)",
                        start.elapsed().as_secs_f64()
                    );
                }
                ready = true;
                break;
            }
            _ => {
                sleep(post_deployment_readiness_poll_delay(backoff_attempt)).await;
                backoff_attempt = backoff_attempt.saturating_add(1);
            }
        }
    }

    if !ready {
        warn!(
            "   ⚠️  Health endpoint not responding after {:.1}s, proceeding anyway",
            max_wait.as_secs_f64()
        );
    }
    println!();

    // Prepare environment variables
    let mut env_vars = prepare_environment(&config).await?;

    // Add working directory to env
    env_vars.insert("PWD".to_string(), working_dir.display().to_string());

    // Execute test suites
    let mut results = Vec::new();

    if config.execution.parallel {
        // Run tests in parallel
        info!(
            "🔄 Running {} test suites in parallel",
            config.test_suites.len()
        );
        results = execute_parallel(&config, &working_dir, &env_vars).await?;
    } else {
        // Run tests sequentially
        info!(
            "➡️  Running {} test suites sequentially",
            config.test_suites.len()
        );
        results = execute_sequential(&config, &working_dir, &env_vars).await?;
    }

    // Print summary
    print_summary(&results);

    // Handle failures
    let failed = results.iter().filter(|r| !r.success).count();
    if failed > 0 {
        error!("❌ {} of {} test suites failed", failed, results.len());
        println!();

        // Print detailed output for all failed tests
        for result in results.iter().filter(|r| !r.success) {
            println!();
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!(
                "❌ Failed Test Suite: {}",
                result.suite_name.bright_yellow()
            );
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            if !result.output.is_empty() {
                println!();
                for line in result.output.lines() {
                    println!("{}", line);
                }
            } else {
                println!("(No output captured)");
            }
            println!();
        }
        println!();

        match config.on_failure.action.as_str() {
            "rollback" => {
                warn!("🔄 Triggering rollback due to test failure");
                // TODO: Implement rollback logic
                anyhow::bail!("Integration tests failed - rollback required");
            }
            "fail" => {
                anyhow::bail!("Integration tests failed");
            }
            "continue" => {
                warn!("⚠️  Continuing despite test failures");
            }
            _ => {
                anyhow::bail!("Unknown on_failure action: {}", config.on_failure.action);
            }
        }
    } else {
        info!("✅ All integration tests passed!");
    }

    Ok(results)
}

/// Prepare environment variables for tests
async fn prepare_environment(config: &IntegrationTestConfig) -> Result<HashMap<String, String>> {
    let mut env = HashMap::new();

    // Base URL
    env.insert("BASE_URL".to_string(), config.environment.base_url.clone());

    // GraphQL endpoint
    env.insert(
        "GRAPHQL_ENDPOINT".to_string(),
        config.environment.graphql_endpoint.clone(),
    );

    // Test credentials (fetch from Kubernetes secrets if configured)
    if let Some(secret_name) = &config.environment.test_user_email_secret {
        if let Ok(email) = fetch_secret(secret_name, "email").await {
            env.insert("TEST_USER_EMAIL".to_string(), email);
        }
    }

    if let Some(secret_name) = &config.environment.test_user_password_secret {
        if let Ok(password) = fetch_secret(secret_name, "password").await {
            env.insert("TEST_USER_PASSWORD".to_string(), password);
        }
    }

    Ok(env)
}

/// Fetch secret from Kubernetes
async fn fetch_secret(secret_name: &str, key: &str) -> Result<String> {
    let output = kubectl_command_async()
        .args(&[
            "get",
            "secret",
            secret_name,
            "-o",
            &format!("jsonpath={{.data.{}}}", key),
        ])
        .output()
        .await
        .context("Failed to fetch secret from Kubernetes")?;

    if !output.status.success() {
        anyhow::bail!("Failed to fetch secret {}/{}", secret_name, key);
    }

    let base64_value = String::from_utf8(output.stdout)?;

    // Decode base64 using the standard engine
    use base64::{engine::general_purpose, Engine as _};
    let decoded = general_purpose::STANDARD
        .decode(base64_value.trim())
        .context("Failed to decode base64 secret")?;

    Ok(String::from_utf8(decoded)?)
}

/// Execute test suites sequentially
async fn execute_sequential(
    config: &IntegrationTestConfig,
    working_dir: &PathBuf,
    env_vars: &HashMap<String, String>,
) -> Result<Vec<TestResult>> {
    let mut results = Vec::new();

    for (idx, suite) in config.test_suites.iter().enumerate() {
        println!();
        println!(
            "📦 Test Suite {}/{}: {}",
            idx + 1,
            config.test_suites.len(),
            suite.name.bright_yellow()
        );
        info!("   {}", suite.description);
        println!();

        let result = execute_suite(suite, working_dir, env_vars).await?;

        results.push(result.clone());

        if !result.success && config.execution.fail_fast {
            warn!("⚠️  Fail-fast enabled, stopping test execution");
            break;
        }
    }

    Ok(results)
}

/// Execute test suites in parallel
async fn execute_parallel(
    config: &IntegrationTestConfig,
    working_dir: &PathBuf,
    env_vars: &HashMap<String, String>,
) -> Result<Vec<TestResult>> {
    let mut handles = vec![];

    for suite in &config.test_suites {
        let suite = suite.clone();
        let working_dir = working_dir.clone();
        let env_vars = env_vars.clone();

        let handle =
            tokio::spawn(async move { execute_suite(&suite, &working_dir, &env_vars).await });

        handles.push(handle);
    }

    // Wait for all tests to complete
    let mut results = Vec::new();
    for handle in handles {
        let result = handle.await??;
        results.push(result);
    }

    Ok(results)
}

/// Execute a single test suite
async fn execute_suite(
    suite: &TestSuite,
    working_dir: &PathBuf,
    env_vars: &HashMap<String, String>,
) -> Result<TestResult> {
    // Malformed `timeout: "5min"` etc. on a post-deployment suite
    // previously errored without naming which suite forge refused —
    // symmetric with the pre-deployment path this module already routes
    // through `parse_timeout_field` at line ~1071. Closes the final
    // `deploy.yaml` timeout-field parse site whose error lacked
    // field-name context.
    let suite_timeout = parse_post_deployment_suite_timeout(suite)?;
    let mut attempts = 0;
    let max_attempts = if suite.retry_on_failure {
        suite.max_retries + 1
    } else {
        1
    };

    loop {
        attempts += 1;

        info!("🧪 Attempt {}/{}", attempts, max_attempts);

        let start = std::time::Instant::now();

        // Create progress spinner
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.cyan} {msg}")
                .unwrap(),
        );
        pb.set_message(format!("Running {}", suite.name));
        pb.enable_steady_tick(Duration::from_millis(100));

        // Build command
        let suite_working_dir = working_dir.join(&suite.working_dir);

        let mut cmd = Command::new(crate::repo::get_tool_path("SH_BIN", "sh"));
        cmd.arg("-c")
            .arg(&suite.command)
            .current_dir(&suite_working_dir)
            .envs(env_vars)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        debug!("Executing: {} in {:?}", suite.command, suite_working_dir);

        // Execute with timeout
        let result = timeout(suite_timeout, async {
            let mut child = cmd.spawn()?;

            // Capture output
            let stdout = child.stdout.take().expect("Failed to capture stdout");
            let stderr = child.stderr.take().expect("Failed to capture stderr");

            let mut stdout_reader = BufReader::new(stdout).lines();
            let mut stderr_reader = BufReader::new(stderr).lines();

            let mut output = String::new();

            // Read output as it comes
            loop {
                tokio::select! {
                    line = stdout_reader.next_line() => {
                        if let Ok(Some(line)) = line {
                            debug!("[{}] {}", suite.name, line);
                            output.push_str(&line);
                            output.push('\n');
                        } else {
                            break;
                        }
                    }
                    line = stderr_reader.next_line() => {
                        if let Ok(Some(line)) = line {
                            debug!("[{}] {}", suite.name, line);
                            output.push_str(&line);
                            output.push('\n');
                        }
                    }
                }
            }

            let status = child.wait().await?;

            Ok::<(bool, String), anyhow::Error>((status.success(), output))
        })
        .await;

        pb.finish_and_clear();

        let duration = start.elapsed();

        match result {
            Ok(Ok((success, output))) => {
                if success {
                    println!(
                        "   {} Test suite completed in {:.2}s",
                        "✅".bright_green(),
                        duration.as_secs_f64()
                    );

                    // Parse test counts from output
                    let test_counts = parse_test_counts(&output);

                    return Ok(TestResult {
                        suite_name: suite.name.clone(),
                        success: true,
                        duration,
                        output,
                        attempts,
                        test_counts,
                    });
                } else {
                    println!(
                        "   {} Test suite failed after {:.2}s",
                        "❌".bright_red(),
                        duration.as_secs_f64()
                    );

                    // Print test output on failure for debugging
                    if !output.is_empty() {
                        println!();
                        println!("   📋 Test Output:");
                        println!("   ┌────────────────────────────────────────────────────────");
                        for line in output.lines() {
                            println!("   │ {}", line);
                        }
                        println!("   └────────────────────────────────────────────────────────");
                        println!();
                    }

                    if attempts >= max_attempts {
                        // Parse test counts even on failure (useful for partial results)
                        let test_counts = parse_test_counts(&output);

                        return Ok(TestResult {
                            suite_name: suite.name.clone(),
                            success: false,
                            duration,
                            output,
                            attempts,
                            test_counts,
                        });
                    }

                    warn!("   🔄 Retrying ({}/{})", attempts, max_attempts);
                    sleep(integration_test_retry_delay(attempts)).await;
                }
            }
            Ok(Err(e)) => {
                error!("   ❌ Command execution failed: {}", e);

                if attempts >= max_attempts {
                    return Ok(TestResult {
                        suite_name: suite.name.clone(),
                        success: false,
                        duration,
                        output: format!("Execution error: {}", e),
                        attempts,
                        test_counts: None,
                    });
                }

                warn!("   🔄 Retrying ({}/{})", attempts, max_attempts);
                sleep(integration_test_retry_delay(attempts)).await;
            }
            Err(_) => {
                error!("   ⏱️  Test suite timed out after {:?}", suite_timeout);

                if attempts >= max_attempts {
                    return Ok(TestResult {
                        suite_name: suite.name.clone(),
                        success: false,
                        duration,
                        output: format!("Timeout after {:?}", suite_timeout),
                        attempts,
                        test_counts: None,
                    });
                }

                warn!("   🔄 Retrying ({}/{})", attempts, max_attempts);
                sleep(integration_test_retry_delay(attempts)).await;
            }
        }
    }
}

/// Print test summary
fn print_summary(results: &[TestResult]) {
    println!();
    println!();
    println!(
        "{}",
        "╔════════════════════════════════════════════════════════════════╗"
            .bright_cyan()
            .bold()
    );
    println!(
        "{}",
        "║                    🏁 FINAL TEST RESULTS                       ║"
            .bright_cyan()
            .bold()
    );
    println!(
        "{}",
        "╚════════════════════════════════════════════════════════════════╝"
            .bright_cyan()
            .bold()
    );
    println!();

    // Suite-level counts
    let suites_passed = results.iter().filter(|r| r.success).count();
    let suites_failed = results.len() - suites_passed;
    let total_duration: Duration = results.iter().map(|r| r.duration).sum();

    // Print the big verdict first
    if suites_failed == 0 {
        println!("   {}", "✅ ALL TESTS PASSED".bright_green().bold());
    } else {
        println!(
            "   {}",
            format!("❌ {} TEST SUITE(S) FAILED", suites_failed)
                .bright_red()
                .bold()
        );
    }
    println!();

    // Aggregate individual test counts across all suites (from FINAL attempt only)
    let mut total_tests_passed: u32 = 0;
    let mut total_tests_failed: u32 = 0;
    let mut total_tests_skipped: u32 = 0;
    let mut has_test_counts = false;

    for result in results {
        if let Some(counts) = &result.test_counts {
            has_test_counts = true;
            total_tests_passed += counts.passed;
            total_tests_failed += counts.failed;
            total_tests_skipped += counts.skipped;
        }
    }

    // Print individual test counts if available
    if has_test_counts {
        let total_tests = total_tests_passed + total_tests_failed + total_tests_skipped;
        println!(
            "   {} {}",
            "📋 Individual Tests:".bright_cyan().bold(),
            format!("{} total", total_tests)
        );
        println!(
            "      ✅ Passed:  {}",
            total_tests_passed.to_string().bright_green()
        );
        println!(
            "      ❌ Failed:  {}",
            if total_tests_failed > 0 {
                total_tests_failed.to_string().bright_red()
            } else {
                "0".to_string().dimmed()
            }
        );
        if total_tests_skipped > 0 {
            println!(
                "      ⏭️  Skipped: {}",
                total_tests_skipped.to_string().bright_yellow()
            );
        }
        println!();
    }

    // Print suite-level summary
    println!(
        "   {} {}",
        "📦 Test Suites:".bright_cyan().bold(),
        format!("{} total", results.len())
    );
    println!(
        "      ✅ Passed:  {}",
        suites_passed.to_string().bright_green()
    );
    println!(
        "      ❌ Failed:  {}",
        if suites_failed > 0 {
            suites_failed.to_string().bright_red()
        } else {
            "0".to_string().dimmed()
        }
    );
    println!();
    println!(
        "   ⏱️  Total Duration: {:.2}s",
        total_duration.as_secs_f64()
    );
    println!();

    // Print per-suite details
    println!("   {}", "Suite Results (after all retries):".bright_cyan());
    for result in results {
        let icon = if result.success {
            "✅".bright_green()
        } else {
            "❌".bright_red()
        };

        // Build test count string if available
        let test_info = if let Some(counts) = &result.test_counts {
            if result.success {
                format!(" [{} passed]", counts.passed)
            } else {
                format!(" [{} passed, {} failed]", counts.passed, counts.failed)
            }
        } else {
            String::new()
        };

        // Show retry info only if there were multiple attempts
        let retry_info = if result.attempts > 1 {
            format!(" (after {} attempts)", result.attempts)
        } else {
            String::new()
        };

        println!(
            "      {} {} - {:.2}s{}{}",
            icon,
            result.suite_name,
            result.duration.as_secs_f64(),
            retry_info.dimmed(),
            test_info.bright_white()
        );
    }

    println!();
    println!(
        "{}",
        "════════════════════════════════════════════════════════════════".bright_cyan()
    );
    println!();
}

// ============================================================================
// PRE-DEPLOYMENT TESTS
// ============================================================================
// These tests run BEFORE push/deploy to provide fast feedback on code quality.
// Unit tests, linting, type checks should run here.
// Integration tests run AFTER deployment (above).
// ============================================================================

use crate::config::PreDeploymentTestsConfig;
use std::path::Path;

/// Walk up from a service directory to find the product directory (pkgs/products/{product}).
fn find_product_dir_from_service(service_dir: &Path) -> Option<PathBuf> {
    let mut current = service_dir.to_path_buf();
    loop {
        if let Some(parent) = current.parent() {
            if let Some(grandparent) = parent.parent() {
                if parent.file_name().and_then(|n| n.to_str()) == Some("products")
                    && grandparent.file_name().and_then(|n| n.to_str()) == Some("pkgs")
                {
                    return Some(current);
                }
            }
        }
        if let Some(parent) = current.parent() {
            current = parent.to_path_buf();
        } else {
            return None;
        }
    }
}

/// Raw deploy.yaml structure for parsing integration_tests directly
/// (Web services use a different structure than Rust services)
#[derive(Debug, Clone, Deserialize)]
struct RawDeployYaml {
    #[serde(default)]
    deployment: Option<RawDeploymentSection>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawDeploymentSection {
    #[serde(default)]
    integration_tests: Option<IntegrationTestConfig>,
}

/// Execute manual integration tests from CLI (nix run .#test:product:service)
/// This is called directly from the CLI, not during release workflow
pub async fn execute_manual(
    service: &str,
    service_dir: &str,
    repo_root: &str,
    suite_filter: Option<String>,
) -> Result<()> {
    // Set up environment for root flake pattern
    std::env::set_var("REPO_ROOT", repo_root);
    std::env::set_var("SERVICE_DIR", service_dir);
    std::env::set_current_dir(repo_root)?;

    // Load deploy.yaml - check deploy/{service_name}.yaml first (outside Nix source tree),
    // then fall back to service_dir/deploy.yaml for backward compatibility.
    let service_dir_path = PathBuf::from(service_dir);
    let deploy_yaml_path =
        if let Some(product_dir) = find_product_dir_from_service(&service_dir_path) {
            crate::config::resolve_deploy_yaml_path(&product_dir, service, &service_dir_path)
        } else {
            service_dir_path.join("deploy.yaml")
        };
    if !deploy_yaml_path.exists() {
        anyhow::bail!("No deploy.yaml found at: {}", deploy_yaml_path.display());
    }

    let yaml_content = std::fs::read_to_string(&deploy_yaml_path).context(format!(
        "Failed to read deploy.yaml at: {}",
        deploy_yaml_path.display()
    ))?;

    let raw_config: RawDeployYaml =
        serde_yaml::from_str(&yaml_content).context("Failed to parse deploy.yaml")?;

    // Get integration test config
    let integration_config = raw_config
        .deployment
        .and_then(|d| d.integration_tests)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No deployment.integration_tests section found in deploy.yaml for service '{}'",
                service
            )
        })?;

    println!();
    println!(
        "{}",
        "╔═══════════════════════════════════════════════════════════════╗"
            .bright_magenta()
            .bold()
    );
    println!(
        "{}",
        format!(
            "║  🧪 Manual Integration Tests: {}                           ║",
            service
        )
        .bright_magenta()
        .bold()
    );
    println!(
        "{}",
        "╚═══════════════════════════════════════════════════════════════╝"
            .bright_magenta()
            .bold()
    );
    println!();

    // Filter test suites if requested
    let test_suites: Vec<TestSuite> = if let Some(filter) = &suite_filter {
        integration_config
            .test_suites
            .iter()
            .filter(|s| s.name == *filter)
            .cloned()
            .collect()
    } else {
        integration_config.test_suites.clone()
    };

    if test_suites.is_empty() {
        if let Some(filter) = &suite_filter {
            anyhow::bail!(
                "No test suite named '{}' found. Available suites: {}",
                filter,
                integration_config
                    .test_suites
                    .iter()
                    .map(|s| s.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        } else {
            info!("No integration test suites configured");
            return Ok(());
        }
    }

    println!("📋 Test suites to run: {}", test_suites.len());
    for suite in &test_suites {
        println!(
            "   • {} - {}",
            suite.name.bright_yellow(),
            suite.description
        );
    }
    println!();

    // Create modified config with filtered suites
    let config = IntegrationTestConfig {
        enabled: true, // Force enabled for manual execution
        test_suites,
        execution: integration_config.execution.clone(),
        environment: integration_config.environment.clone(),
        on_failure: OnFailureConfig {
            action: "fail".to_string(), // Always fail on manual execution
            notify: vec![],
        },
    };

    // Get working directory from service_dir
    let working_dir = PathBuf::from(service_dir);

    // Execute tests
    let results = execute(config, working_dir).await?;

    // Return appropriate exit code
    let failed = results.iter().filter(|r| !r.success).count();
    if failed > 0 {
        std::process::exit(1);
    }

    Ok(())
}

/// Execute pre-deployment tests (runs BEFORE push/deploy)
/// Returns Ok(()) if all tests pass, Err if any fail (unless on_failure.action = "warn")
pub async fn execute_pre_deployment_tests(
    config: &PreDeploymentTestsConfig,
    working_dir: PathBuf,
    service_name: &str,
) -> Result<()> {
    if !config.enabled {
        info!("🧪 Pre-deployment tests disabled, skipping...");
        return Ok(());
    }

    if config.test_suites.is_empty() {
        info!("🧪 No pre-deployment test suites configured, skipping...");
        return Ok(());
    }

    println!();
    println!(
        "{}",
        "╔═══════════════════════════════════════════════════════════════╗"
            .bright_yellow()
            .bold()
    );
    println!(
        "{}",
        "║  🧪 Running Pre-Deployment Tests (before push/deploy)       ║"
            .bright_yellow()
            .bold()
    );
    println!(
        "{}",
        "╚═══════════════════════════════════════════════════════════════╝"
            .bright_yellow()
            .bold()
    );
    println!();

    println!("📋 Test suites to run: {}", config.test_suites.len());
    for suite in &config.test_suites {
        println!("   • {} - {}", suite.name, suite.description);
    }
    println!();

    let start_time = std::time::Instant::now();
    let mut all_results: Vec<TestResult> = vec![];
    let mut any_failed = false;

    for suite in &config.test_suites {
        println!("━━━ Running: {} ━━━", suite.name.bright_white().bold());
        println!("   Command: {}", suite.command.dimmed());

        let suite_working_dir = working_dir.join(&suite.working_dir);
        // Malformed `timeout: "5min"` etc. was previously silently
        // swallowed to a 300s default here — the load-bearing hole
        // `crate::duration::parse_timeout_field` closes. `PreDeploymentTestsConfig::validate`
        // catches it at config-load; this fails LOUD if a runtime path
        // ever bypasses that validator (e.g. a hand-constructed test
        // config, a future partial-load code path).
        let test_timeout = crate::duration::parse_timeout_field(
            &suite.timeout,
            &format!("pre-deployment test suite '{}'", suite.name),
        )?;

        let mut attempts = 0;
        let max_attempts = if suite.retry_on_failure {
            suite.max_retries + 1
        } else {
            1
        };

        let result = loop {
            attempts += 1;

            let attempt_start = std::time::Instant::now();

            // Parse command and args
            let parts: Vec<&str> = suite.command.split_whitespace().collect();
            if parts.is_empty() {
                break TestResult {
                    suite_name: suite.name.clone(),
                    success: false,
                    duration: attempt_start.elapsed(),
                    output: "Empty command".to_string(),
                    attempts,
                    test_counts: None,
                };
            }

            let cmd = parts[0];
            let args = &parts[1..];

            let spinner = ProgressBar::new_spinner();
            spinner.set_style(
                ProgressStyle::default_spinner()
                    .template("{spinner:.yellow} {msg}")
                    .unwrap(),
            );
            spinner.set_message(format!(
                "Running {} (attempt {}/{})",
                suite.name, attempts, max_attempts
            ));
            spinner.enable_steady_tick(Duration::from_millis(100));

            // Run the test command
            let child = Command::new(cmd)
                .args(args)
                .current_dir(&suite_working_dir)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn();

            let result = match child {
                Ok(child) => {
                    match timeout(test_timeout, async {
                        let output = child.wait_with_output().await?;
                        Ok::<_, anyhow::Error>((
                            output.status.success(),
                            String::from_utf8_lossy(&output.stdout).to_string()
                                + &String::from_utf8_lossy(&output.stderr).to_string(),
                        ))
                    })
                    .await
                    {
                        Ok(Ok((success, output))) => {
                            let test_counts = parse_test_counts(&output);
                            TestResult {
                                suite_name: suite.name.clone(),
                                success,
                                duration: attempt_start.elapsed(),
                                output,
                                attempts,
                                test_counts,
                            }
                        }
                        Ok(Err(e)) => TestResult {
                            suite_name: suite.name.clone(),
                            success: false,
                            duration: attempt_start.elapsed(),
                            output: format!("Command error: {}", e),
                            attempts,
                            test_counts: None,
                        },
                        Err(_) => TestResult {
                            suite_name: suite.name.clone(),
                            success: false,
                            duration: test_timeout,
                            output: format!("Timeout after {:?}", test_timeout),
                            attempts,
                            test_counts: None,
                        },
                    }
                }
                Err(e) => TestResult {
                    suite_name: suite.name.clone(),
                    success: false,
                    duration: attempt_start.elapsed(),
                    output: format!("Failed to spawn command: {}", e),
                    attempts,
                    test_counts: None,
                },
            };

            spinner.finish_and_clear();

            if result.success {
                break result;
            } else if attempts < max_attempts {
                warn!("   ⚠️  Attempt {} failed, retrying...", attempts);
                sleep(pre_deployment_test_suite_retry_delay(attempts)).await;
            } else {
                break result;
            }
        };

        // Print result
        if result.success {
            let test_info = result
                .test_counts
                .as_ref()
                .map(|c| format!(" [{} passed]", c.passed))
                .unwrap_or_default();
            println!(
                "   {} {} - {:.2}s{}",
                "✅".green(),
                suite.name,
                result.duration.as_secs_f64(),
                test_info.bright_white()
            );
        } else {
            let test_info = result
                .test_counts
                .as_ref()
                .map(|c| format!(" [{} passed, {} failed]", c.passed, c.failed))
                .unwrap_or_default();
            println!(
                "   {} {} - {:.2}s{}",
                "❌".red(),
                suite.name,
                result.duration.as_secs_f64(),
                test_info.bright_white()
            );
            // Print output for failed tests
            if !result.output.is_empty() {
                println!("   {}", "─".repeat(60).dimmed());
                for line in result.output.lines().take(50) {
                    println!("   {}", line.dimmed());
                }
                if result.output.lines().count() > 50 {
                    println!("   {} (output truncated)", "...".dimmed());
                }
                println!("   {}", "─".repeat(60).dimmed());
            }
            any_failed = true;
        }

        all_results.push(result);
        println!();

        // Fail fast if configured
        if any_failed && config.execution.fail_fast {
            break;
        }
    }

    let total_duration = start_time.elapsed();

    // Summary
    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("📊 Pre-Deployment Test Summary for '{}'", service_name);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    let passed = all_results.iter().filter(|r| r.success).count();
    let failed = all_results.iter().filter(|r| !r.success).count();

    println!(
        "   {} passed, {} failed - total time: {:.2}s",
        passed.to_string().green(),
        if failed > 0 {
            failed.to_string().red()
        } else {
            failed.to_string().dimmed()
        },
        total_duration.as_secs_f64()
    );
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    // Handle failure
    if any_failed {
        if config.on_failure.action == "warn" {
            warn!("⚠️  Pre-deployment tests failed but on_failure.action = 'warn', continuing...");
            Ok(())
        } else {
            error!("❌ Pre-deployment tests failed! Release aborted.");
            bail!(
                "Pre-deployment tests failed for '{}'. {} of {} suites failed.",
                service_name,
                failed,
                all_results.len()
            );
        }
    } else {
        println!("{}", "✅ All pre-deployment tests passed!".green());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_test_counts_total() {
        let counts = TestCounts {
            passed: 10,
            failed: 2,
            skipped: 3,
        };
        assert_eq!(counts.total(), 15);
    }

    #[test]
    fn test_test_counts_default() {
        let counts = TestCounts::default();
        assert_eq!(counts.passed, 0);
        assert_eq!(counts.failed, 0);
        assert_eq!(counts.skipped, 0);
        assert_eq!(counts.total(), 0);
    }

    /// The happy path is byte-for-byte the shared grammar oracle: a
    /// well-formed `warmup_delay: "30s"` parses to `Duration::from_secs(30)`.
    /// The field-naming context is present only on the error path.
    #[test]
    fn parse_post_deployment_warmup_delay_parses_well_formed_values() {
        assert_eq!(
            parse_post_deployment_warmup_delay("30s").unwrap(),
            Duration::from_secs(30)
        );
        assert_eq!(
            parse_post_deployment_warmup_delay("5m").unwrap(),
            Duration::from_secs(300)
        );
    }

    /// The load-bearing invariant: a malformed `warmup_delay` surfaces
    /// BOTH the offending value AND the field name at the runtime call
    /// site, so a `deploy.yaml` author no longer has to hunt through the
    /// file to find which timeout forge rejected.
    #[test]
    fn parse_post_deployment_warmup_delay_error_names_field_and_value() {
        let msg = parse_post_deployment_warmup_delay("5min")
            .unwrap_err()
            .to_string();
        assert!(
            msg.contains("execution.warmup_delay"),
            "error must echo the field label: {msg}"
        );
        assert!(
            msg.contains("5min"),
            "error must echo the offending value: {msg}"
        );
    }

    /// A post-deployment suite whose `timeout` string is a unit typo
    /// surfaces the offending suite name and value at the runtime call
    /// site, matching the pre-deployment path's fail-fast fidelity.
    #[test]
    fn parse_post_deployment_suite_timeout_error_names_suite_and_value() {
        let suite = TestSuite {
            name: "e2e".to_string(),
            description: String::new(),
            command: String::new(),
            working_dir: String::new(),
            timeout: "5min".to_string(),
            retry_on_failure: false,
            max_retries: 0,
        };
        let msg = parse_post_deployment_suite_timeout(&suite)
            .unwrap_err()
            .to_string();
        assert!(
            msg.contains("post-deployment integration test suite 'e2e'"),
            "error must echo the field label naming stage and suite: {msg}"
        );
        assert!(
            msg.contains("5min"),
            "error must echo the offending value: {msg}"
        );
    }

    /// Both pre-deployment (`execute_pre_deployment_tests`) and
    /// post-deployment (`execute_suite`) parse a `deploy.yaml` suite
    /// `timeout` field; the label prefix distinguishes the two so a
    /// shared suite name ("e2e") appearing in both stages doesn't leave
    /// a `deploy.yaml` author guessing which stage's suite forge refused.
    #[test]
    fn parse_post_deployment_suite_timeout_stage_prefix_distinguishes_pre_from_post() {
        let suite = TestSuite {
            name: "e2e".to_string(),
            description: String::new(),
            command: String::new(),
            working_dir: String::new(),
            timeout: "not-a-timeout".to_string(),
            retry_on_failure: false,
            max_retries: 0,
        };
        let msg = parse_post_deployment_suite_timeout(&suite)
            .unwrap_err()
            .to_string();
        assert!(
            msg.contains("post-deployment"),
            "post-deployment label must distinguish from pre-deployment: {msg}"
        );
        assert!(
            !msg.contains("pre-deployment"),
            "must not accidentally re-emit the pre-deployment label: {msg}"
        );
    }

    /// A post-deployment suite's happy-path parse is byte-for-byte the
    /// shared grammar oracle: a well-formed `timeout: "5m"` parses to
    /// `Duration::from_secs(300)`, mirroring the parity the pre-deployment
    /// path already has.
    #[test]
    fn parse_post_deployment_suite_timeout_parses_well_formed_values() {
        let suite = TestSuite {
            name: "e2e".to_string(),
            description: String::new(),
            command: String::new(),
            working_dir: String::new(),
            timeout: "5m".to_string(),
            retry_on_failure: false,
            max_retries: 0,
        };
        assert_eq!(
            parse_post_deployment_suite_timeout(&suite).unwrap(),
            Duration::from_secs(300)
        );
    }
}

#[cfg(test)]
mod integration_test_retry_backoff_tests {
    use super::*;

    // ====================================================================
    // integration-test-suite retry backoff — INTEGRATION_TEST_RETRY_BACKOFF
    // + helper
    // ====================================================================
    //
    // These pin the RetryPolicy-consuming replacement of the pre-lift
    // three sibling `sleep(Duration::from_secs(5)).await` sites that
    // `execute_suite`'s post-deployment retry loop (test-non-zero-exit,
    // command-error, timeout branches) polled through. Sibling of the
    // `TEST_RETRY_BACKOFF` shields at `commands/test.rs::tests` (commit
    // 9fd38d3), the `FLUX_POLL_BACKOFF` shields at `commands/flux.rs::
    // tests` (commit 65de62f), the `SHINKA_MIGRATION_POLL_BACKOFF`
    // shields at `commands/migrations.rs::tests` (commit b962db5), and
    // the `HEALTH_ENDPOINT_BACKOFF` shields at
    // `commands/post_deploy_verification.rs::tests` (commit b5db3b6) —
    // same const- + delegation-helper shape, same four-test pattern
    // (policy-shape / in-cap-schedule / past-cap-cap /
    // saturating-no-panic), same whole-module boundary shield that
    // forbids re-fusing the pre-lift bare-literal `sleep(5s)` shape.

    /// The `INTEGRATION_TEST_RETRY_BACKOFF` const's
    /// `(initial_backoff, factor, max_backoff)` triple is the
    /// load-bearing invariant every consumption site (all three
    /// retry-loop failure branches, plus any future retry-loop
    /// consumer that reads the same schedule) shares. Pinned here so
    /// a future edit at the const's site is caught at a named test
    /// rather than silently across the three consumption sites and
    /// the delegation helper.
    #[test]
    fn test_integration_test_retry_backoff_policy_shape() {
        assert_eq!(
            INTEGRATION_TEST_RETRY_BACKOFF.initial_backoff,
            Duration::from_secs(5),
            "INTEGRATION_TEST_RETRY_BACKOFF.initial_backoff must be 5s \
             — preserves the pre-lift `sleep(Duration::from_secs(5))` \
             seed verbatim at the first between-retry sleep.",
        );
        assert_eq!(
            INTEGRATION_TEST_RETRY_BACKOFF.factor, 2,
            "INTEGRATION_TEST_RETRY_BACKOFF.factor must be 2 \
             — Bazel-style doubling climb between retries.",
        );
        assert_eq!(
            INTEGRATION_TEST_RETRY_BACKOFF.max_backoff,
            Duration::from_secs(30),
            "INTEGRATION_TEST_RETRY_BACKOFF.max_backoff must be 30s \
             — the shared cap every sibling RetryPolicy-consumer \
             (TEST_RETRY_BACKOFF, FLUX_POLL_BACKOFF, \
             SHINKA_MIGRATION_POLL_BACKOFF, HEALTH_ENDPOINT_BACKOFF) \
             also names.",
        );
    }

    /// Pre-lift the first between-retry sleep emitted
    /// `sleep(Duration::from_secs(5))` verbatim; the lift's 1-indexed
    /// `attempts` counter must reproduce that seed at
    /// `attempts == 1` via `integration_test_retry_delay(1)`. The
    /// subsequent within-cap attempts (2/3) must emit the Bazel-style
    /// doubling climb (10s/20s), strictly better than the pre-lift
    /// flat-5s schedule at every retry past the first.
    #[test]
    fn test_integration_test_retry_delay_matches_pre_lift_seed_and_climbs_at_in_cap_attempts() {
        assert_eq!(
            integration_test_retry_delay(1),
            Duration::from_secs(5),
            "attempts=1 must sleep 5s — matches pre-lift \
             `sleep(Duration::from_secs(5))` seed verbatim.",
        );
        assert_eq!(
            integration_test_retry_delay(2),
            Duration::from_secs(10),
            "attempts=2 must sleep 10s — Bazel-style `5s * 2 = 10s`.",
        );
        assert_eq!(
            integration_test_retry_delay(3),
            Duration::from_secs(20),
            "attempts=3 must sleep 20s — Bazel-style `10s * 2 = 20s`.",
        );
    }

    /// Attempts past the cap must all emit `max_backoff = 30s` —
    /// `(20s * 2).min(30s) = 30s` at attempts=4 and `(30s * 2).min(30s)
    /// = 30s` at every subsequent attempt. `suite.max_retries` is a
    /// user-supplied `deploy.yaml` field with no upper bound in the
    /// schema, so beyond-cap attempts must stay at the ceiling rather
    /// than climb past it and stretch a single suite's total retry
    /// wall-clock into hours.
    #[test]
    fn test_integration_test_retry_delay_caps_at_max_backoff_past_the_cap() {
        assert_eq!(
            integration_test_retry_delay(4),
            Duration::from_secs(30),
            "attempts=4 must sleep 30s (cap) — `(20s * 2).min(30s) = 30s`.",
        );
        assert_eq!(
            integration_test_retry_delay(5),
            Duration::from_secs(30),
            "attempts=5 must sleep 30s (cap).",
        );
        assert_eq!(
            integration_test_retry_delay(50),
            Duration::from_secs(30),
            "attempts=50 must sleep 30s (cap) — a pathological \
             `suite.max_retries` cannot stretch a single sleep past \
             the ceiling.",
        );
    }

    /// The retry loop's `attempts` counter is a `u32` bounded only by
    /// the caller-supplied `suite.max_retries + 1`, so a pathological
    /// deploy.yaml with `max_retries: u32::MAX` could in principle
    /// drive `integration_test_retry_delay(u32::MAX)`. Pre-lift the
    /// fixed `Duration::from_secs(5)` literal never panicked at any
    /// attempt; post-lift `saturating_add(1)` inside
    /// `integration_test_retry_delay` bounds the argument to
    /// `RetryPolicy::compute_delay`, whose `checked_pow`-then-cap
    /// body itself saturates without panic. This test pins that
    /// composition: an `attempts == u32::MAX` argument returns a
    /// bounded delay rather than panicking.
    #[test]
    fn test_integration_test_retry_delay_saturates_without_panic_at_arbitrarily_large_attempt() {
        assert_eq!(
            integration_test_retry_delay(u32::MAX),
            Duration::from_secs(30),
            "attempts=u32::MAX must saturate to max_backoff without \
             panic — the `saturating_add(1)` bridge + \
             `RetryPolicy::compute_delay`'s `checked_pow` cap close \
             the u32 overflow class by construction.",
        );
        assert_eq!(
            integration_test_retry_delay(u32::MAX - 1),
            Duration::from_secs(30),
            "attempts=u32::MAX - 1 must also saturate to max_backoff \
             — the bridge `saturating_add(1)` returns u32::MAX, still \
             far past the cap.",
        );
    }

    /// Whole-module boundary shield: `execute_suite`'s post-deployment
    /// retry loop MUST consume the typed primitive at
    /// `integration_test_retry_delay` rather than re-fusing the
    /// pre-lift bare-literal `sleep(Duration::from_secs(5))` shape
    /// (or any sibling `Duration::from_secs(N)`-in-a-`sleep`-call
    /// fixed schedule) at any of the three failure branches. A future
    /// refactor that reintroduces a flat schedule — or grows a fourth
    /// branch and copies the pre-lift shape — fails here, not
    /// silently in production. Whole-module boundary discipline
    /// sibling of
    /// `test_run_test_suite_consumes_typed_retry_delay_not_bare_fixed_sleep`
    /// at `commands/test.rs::tests` (commit 9fd38d3),
    /// `test_flux_polling_loops_consume_typed_poll_delay_not_bespoke_backoff_struct`
    /// at `commands/flux.rs::tests` (commit 65de62f), and
    /// `test_wait_for_shinka_migration_consumes_typed_poll_delay_not_mut_backoff_secs`
    /// at `commands/migrations.rs::tests` (commit b962db5).
    ///
    /// Code-line filter (via [`crate::test_support::code_line_hits`])
    /// skips docstring / prose-comment lines, so the shield does not
    /// false-positive on `INTEGRATION_TEST_RETRY_BACKOFF`'s own
    /// docstring above (which cites the pre-lift
    /// `Duration::from_secs(5)` shape as context for the three
    /// defects it forecloses).
    #[test]
    fn test_execute_suite_consumes_typed_retry_delay_not_bare_fixed_sleep() {
        let source = include_str!("integration_tests.rs");
        let tests_marker = "\n#[cfg(test)]\nmod tests {";
        let body_end = source.find(tests_marker).expect(
            "the `#[cfg(test)]\\nmod tests {` marker must follow \
             the module body — the shield's slice boundary relies \
             on this module ordering",
        );
        let module_body = &source[..body_end];

        let bare_sleep_hits =
            crate::test_support::code_line_hits(module_body, "sleep(Duration::from_secs(5))");
        assert!(
            bare_sleep_hits.is_empty(),
            "commands/integration_tests.rs must NOT drive the \
             post-deployment retry loop through a bare \
             `sleep(Duration::from_secs(5))` — every sleep site in \
             `execute_suite`'s retry loop must consume \
             `integration_test_retry_delay(attempts)`, grounding \
             through `RetryPolicy::compute_delay`. Found code-line \
             hits: {:#?}",
            bare_sleep_hits,
        );
        let delegation_hits = crate::test_support::code_line_hits(
            module_body,
            "integration_test_retry_delay(attempts)",
        );
        assert!(
            !delegation_hits.is_empty(),
            "commands/integration_tests.rs must consume the typed \
             retry-delay helper at every failure branch of \
             `execute_suite`'s retry loop — the canonical delegation \
             call was not found at any code line.",
        );
    }
}

#[cfg(test)]
mod post_deployment_readiness_poll_backoff_tests {
    use super::*;

    // ====================================================================
    // post-deployment readiness poll backoff —
    // POST_DEPLOYMENT_READINESS_POLL_BACKOFF + helper
    // ====================================================================
    //
    // These pin the `RetryPolicy`-consuming replacement of the pre-lift
    // bare fixed `sleep(Duration::from_secs(2)).await` at the wall-clock-
    // bounded readiness poll loop in `execute` that waits for the
    // freshly-deployed application's `/health` endpoint to return 200
    // before the post-deployment integration-test suite runs. Sibling of
    // the `HEALTH_ENDPOINT_BACKOFF` shields at
    // `commands/post_deploy_verification.rs::tests` (commit b5db3b6), the
    // `SERVICES_HEALTHY_POLL_BACKOFF` shields at
    // `commands/comprehensive_release.rs::tests` (commit ad2e31e), the
    // `MIGRATION_JOB_POLL_BACKOFF` shields at
    // `services/migration_service.rs::tests` (commit ac61874), and the
    // `FEDERATION_JOB_POLL_BACKOFF` shields at
    // `commands/federation_tests.rs::tests` (commit 8319fa2) — same
    // const- + delegation-helper shape, same five-test pattern
    // (policy-shape / in-cap-schedule / past-cap-cap / saturating-no-
    // panic / delegation-boundary), and the same function-body-scoped
    // no-re-fusion shield closes the pre-lift bare-literal shape at the
    // `execute` readiness poll site.

    /// The `POST_DEPLOYMENT_READINESS_POLL_BACKOFF` const's
    /// `(initial_backoff, factor, max_backoff)` triple is the load-
    /// bearing invariant every consumption site (the `execute` readiness
    /// poll loop, plus any future readiness-poll consumer that reads
    /// the same schedule) shares. Pinned here so a future edit at the
    /// const's site is caught at a named test rather than silently
    /// across the consumption site and the delegation helper.
    #[test]
    fn test_post_deployment_readiness_poll_backoff_policy_shape() {
        assert_eq!(
            POST_DEPLOYMENT_READINESS_POLL_BACKOFF.initial_backoff,
            Duration::from_secs(2),
            "POST_DEPLOYMENT_READINESS_POLL_BACKOFF.initial_backoff must be 2s \
             — preserves the pre-lift bare `sleep(Duration::from_secs(2))` \
             seed verbatim at the readiness poll loop's first sleep.",
        );
        assert_eq!(
            POST_DEPLOYMENT_READINESS_POLL_BACKOFF.factor, 2,
            "POST_DEPLOYMENT_READINESS_POLL_BACKOFF.factor must be 2 \
             — Bazel-style doubling climb between probes.",
        );
        assert_eq!(
            POST_DEPLOYMENT_READINESS_POLL_BACKOFF.max_backoff,
            Duration::from_secs(30),
            "POST_DEPLOYMENT_READINESS_POLL_BACKOFF.max_backoff must be 30s \
             — the shared cap every sibling RetryPolicy-consumer \
             (HEALTH_ENDPOINT_BACKOFF, SERVICES_HEALTHY_POLL_BACKOFF, \
             MIGRATION_JOB_POLL_BACKOFF, FEDERATION_JOB_POLL_BACKOFF) \
             also names.",
        );
    }

    /// Pre-lift the readiness poll loop emitted a flat
    /// `sleep(Duration::from_secs(2))` at every non-terminal iteration.
    /// Post-lift the first iteration preserves that 2s seed verbatim
    /// (`backoff_attempt == 0` → `compute_delay(2) = initial_backoff =
    /// 2s`), then diverges upward at every later iteration
    /// (`backoff_attempt == 1` → `4s`, `== 2` → `8s`, `== 3` → `16s`) —
    /// strictly better than the pre-lift flat 2s schedule at every
    /// probe past the first.
    #[test]
    fn test_post_deployment_readiness_poll_delay_matches_pre_lift_seed_and_climbs_at_in_cap_attempts(
    ) {
        assert_eq!(
            post_deployment_readiness_poll_delay(0),
            Duration::from_secs(2),
            "backoff_attempt=0 must sleep 2s — matches pre-lift \
             `sleep(Duration::from_secs(2))` seed verbatim.",
        );
        assert_eq!(
            post_deployment_readiness_poll_delay(1),
            Duration::from_secs(4),
            "backoff_attempt=1 must sleep 4s — Bazel-style `2s * 2 = 4s`.",
        );
        assert_eq!(
            post_deployment_readiness_poll_delay(2),
            Duration::from_secs(8),
            "backoff_attempt=2 must sleep 8s — Bazel-style `4s * 2 = 8s`.",
        );
        assert_eq!(
            post_deployment_readiness_poll_delay(3),
            Duration::from_secs(16),
            "backoff_attempt=3 must sleep 16s — Bazel-style `8s * 2 = 16s`.",
        );
    }

    /// Iterations past the cap must all emit `max_backoff = 30s` —
    /// `(16s * 2).min(30s) = 30s` at `backoff_attempt == 4` and every
    /// subsequent iteration. `warmup_delay` is a user-supplied
    /// `deploy.yaml` field with no upper bound in the schema, so
    /// beyond-cap iterations must stay at the ceiling rather than
    /// climb past it and stretch a single readiness-poll iteration's
    /// sleep into minutes.
    #[test]
    fn test_post_deployment_readiness_poll_delay_caps_at_max_backoff_past_the_cap() {
        assert_eq!(
            post_deployment_readiness_poll_delay(4),
            Duration::from_secs(30),
            "backoff_attempt=4 must sleep 30s (cap) — `(16s * 2).min(30s) = 30s`.",
        );
        assert_eq!(
            post_deployment_readiness_poll_delay(5),
            Duration::from_secs(30),
            "backoff_attempt=5 must sleep 30s (cap).",
        );
        assert_eq!(
            post_deployment_readiness_poll_delay(50),
            Duration::from_secs(30),
            "backoff_attempt=50 must sleep 30s (cap) — a pathological \
             `warmup_delay` cannot stretch a single sleep past the ceiling.",
        );
    }

    /// The readiness poll loop's `backoff_attempt` counter is a `u32`
    /// bounded only by the caller-supplied `warmup_delay` wall-clock
    /// window, so a pathological `warmup_delay` of years could in
    /// principle drive `post_deployment_readiness_poll_delay(u32::MAX)`.
    /// Pre-lift the fixed `Duration::from_secs(2)` literal never panicked
    /// at any iteration; post-lift `saturating_add(2)` inside
    /// `post_deployment_readiness_poll_delay` bounds the argument to
    /// `RetryPolicy::compute_delay`, whose `checked_pow`-then-cap body
    /// itself saturates without panic. This test pins that composition:
    /// a `backoff_attempt == u32::MAX` argument returns a bounded delay
    /// rather than panicking.
    #[test]
    fn test_post_deployment_readiness_poll_delay_saturates_without_panic_at_arbitrarily_large_attempt(
    ) {
        assert_eq!(
            post_deployment_readiness_poll_delay(u32::MAX),
            Duration::from_secs(30),
            "backoff_attempt=u32::MAX must saturate to max_backoff without \
             panic — the `saturating_add(2)` bridge + \
             `RetryPolicy::compute_delay`'s `checked_pow` cap close \
             the u32 overflow class by construction.",
        );
        assert_eq!(
            post_deployment_readiness_poll_delay(u32::MAX - 2),
            Duration::from_secs(30),
            "backoff_attempt=u32::MAX - 2 must also saturate to max_backoff \
             — the bridge `saturating_add(2)` returns u32::MAX, still \
             far past the cap.",
        );
    }

    /// The readiness-poll policy shares `(factor, max_backoff)` with the
    /// canonical [`RetryPolicy::network()`] reference schedule; only
    /// `initial_backoff` diverges (2s vs 250ms) to preserve the pre-lift
    /// bare `sleep(Duration::from_secs(2))` seed verbatim. Pin the
    /// shared invariants so a future refinement to the retry module's
    /// reference schedule surfaces the intentional 2s-seed divergence
    /// as a named failure rather than a silent per-consumer drift.
    #[test]
    fn test_post_deployment_readiness_poll_backoff_shares_network_factor_and_cap() {
        let net = RetryPolicy::network();
        assert_eq!(
            POST_DEPLOYMENT_READINESS_POLL_BACKOFF.factor, net.factor,
            "POST_DEPLOYMENT_READINESS_POLL_BACKOFF.factor must match \
             RetryPolicy::network().factor — the Bazel-style doubling \
             climb is the shared invariant across every RetryPolicy \
             consumer.",
        );
        assert_eq!(
            POST_DEPLOYMENT_READINESS_POLL_BACKOFF.max_backoff, net.max_backoff,
            "POST_DEPLOYMENT_READINESS_POLL_BACKOFF.max_backoff must match \
             RetryPolicy::network().max_backoff — the 30s ceiling is the \
             shared invariant across every RetryPolicy consumer.",
        );
    }

    /// The `execute` readiness poll loop MUST consume the typed
    /// primitive at `post_deployment_readiness_poll_delay(backoff_attempt)`
    /// rather than re-fusing the pre-lift bare-literal
    /// `sleep(Duration::from_secs(2))` shape. A future refactor that
    /// reintroduces the fixed-literal shape (see
    /// `POST_DEPLOYMENT_READINESS_POLL_BACKOFF`'s docstring for the
    /// three structural defects the lift closed) fails here, not
    /// silently in production where a slow-booting application would
    /// resume flooding `/health` with ~30 probes per minute across the
    /// full `warmup_delay` wall-clock window. Whole-function-body
    /// boundary discipline sibling of
    /// `test_wait_for_job_consumes_typed_poll_delay_not_bare_fixed_sleep`
    /// at `services/migration_service.rs::tests` (commit ac61874) and
    /// `test_execute_consumes_typed_poll_delay_not_bare_fixed_sleep`
    /// at `commands/comprehensive_release.rs::tests` (commit ad2e31e).
    ///
    /// The scan is bounded strictly to the `pub async fn execute(` body
    /// (from its signature through the next top-level function's
    /// signature `async fn prepare_environment`) — the sibling
    /// pre-deployment-test-suite retry-loop sleep site in
    /// `execute_pre_deployment_tests` (2s seed, lifted onto its own
    /// `PRE_DEPLOYMENT_TEST_SUITE_RETRY_BACKOFF` +
    /// `pre_deployment_test_suite_retry_delay(attempts)` typed pair)
    /// lives outside this function-scoped slice and is pinned by its
    /// own dedicated shield module below. Uses the
    /// [`crate::test_support::code_line_hits`] helper
    /// so the shield does not false-positive on any comment or
    /// docstring text inside the function body. The forbidden literal
    /// is reconstructed at test time via [`format!`] and the diagnostic
    /// prose refers to it only via the reconstructed `bespoke_needle`
    /// (never the fused literal), so the assert message body itself
    /// stays unmatchable.
    #[test]
    fn test_execute_readiness_poll_consumes_typed_delay_not_bare_fixed_sleep() {
        let source = include_str!("integration_tests.rs");
        let fn_marker = "pub async fn execute(";
        let next_fn_marker = "\nasync fn prepare_environment";
        let fn_start = source.find(fn_marker).expect(
            "the `pub async fn execute(` signature must exist — the \
             shield's slice boundary relies on this signature.",
        );
        let fn_body_rel = source[fn_start..].find(next_fn_marker).expect(
            "the `async fn prepare_environment` signature must follow \
             `execute` — the shield's slice boundary relies on this \
             ordering.",
        );
        let execute_body = &source[fn_start..fn_start + fn_body_rel];

        let bespoke_needle = format!(
            "sleep(Duration::from_secs({}))",
            POST_DEPLOYMENT_READINESS_POLL_BACKOFF
                .initial_backoff
                .as_secs(),
        );
        let bespoke_hits = crate::test_support::code_line_hits(execute_body, &bespoke_needle);
        assert!(
            bespoke_hits.is_empty(),
            "commands/integration_tests.rs::execute must NOT re-fuse the \
             pre-lift bare fixed sleep at the readiness poll loop — the \
             schedule lives at `POST_DEPLOYMENT_READINESS_POLL_BACKOFF` \
             + `post_deployment_readiness_poll_delay`, both grounding \
             through `RetryPolicy::compute_delay`. Found code-line hits: \
             {:#?}",
            bespoke_hits,
        );
        let delegation_hits = crate::test_support::code_line_hits(
            execute_body,
            "post_deployment_readiness_poll_delay(backoff_attempt)",
        );
        assert!(
            !delegation_hits.is_empty(),
            "commands/integration_tests.rs::execute must consume the \
             typed readiness-poll-delay helper at the poll loop's sleep \
             site — the canonical delegation call was not found at any \
             code line inside `pub async fn execute`.",
        );
    }
}

#[cfg(test)]
mod pre_deployment_test_suite_retry_backoff_tests {
    use super::*;

    // ====================================================================
    // pre-deployment test-suite retry backoff —
    // PRE_DEPLOYMENT_TEST_SUITE_RETRY_BACKOFF + helper
    // ====================================================================
    //
    // These pin the `RetryPolicy`-consuming replacement of the pre-lift
    // bare fixed `sleep(Duration::from_secs(2)).await` at the
    // between-attempt sleep site of `execute_pre_deployment_tests`'s
    // test-suite retry loop that runs suite by suite before push/deploy.
    // Sibling of the `INTEGRATION_TEST_RETRY_BACKOFF` shields at
    // `commands/integration_tests.rs::integration_test_retry_backoff_tests`
    // (the twin 5s-seed post-deployment retry surface, this same module)
    // and the `TEST_RETRY_BACKOFF` shields at
    // `commands/test.rs::tests` (commit 9fd38d3) — same const- +
    // delegation-helper shape, same six-test pattern (policy-shape /
    // in-cap-schedule / past-cap-cap / saturating-no-panic /
    // shared-factor-and-cap / function-body-scoped no-re-fusion).

    /// The `PRE_DEPLOYMENT_TEST_SUITE_RETRY_BACKOFF` const's
    /// `(initial_backoff, factor, max_backoff)` triple is the
    /// load-bearing invariant every consumption site (the
    /// `execute_pre_deployment_tests` retry loop, plus any future
    /// retry-loop consumer that reads the same schedule) shares. Pinned
    /// here so a future edit at the const's site is caught at a named
    /// test rather than silently across the consumption site and the
    /// delegation helper.
    #[test]
    fn test_pre_deployment_test_suite_retry_backoff_policy_shape() {
        assert_eq!(
            PRE_DEPLOYMENT_TEST_SUITE_RETRY_BACKOFF.initial_backoff,
            Duration::from_secs(2),
            "PRE_DEPLOYMENT_TEST_SUITE_RETRY_BACKOFF.initial_backoff must be 2s \
             — preserves the pre-lift bare `sleep(Duration::from_secs(2))` \
             seed verbatim at the retry loop's first between-attempt sleep.",
        );
        assert_eq!(
            PRE_DEPLOYMENT_TEST_SUITE_RETRY_BACKOFF.factor, 2,
            "PRE_DEPLOYMENT_TEST_SUITE_RETRY_BACKOFF.factor must be 2 \
             — Bazel-style doubling climb between retries.",
        );
        assert_eq!(
            PRE_DEPLOYMENT_TEST_SUITE_RETRY_BACKOFF.max_backoff,
            Duration::from_secs(30),
            "PRE_DEPLOYMENT_TEST_SUITE_RETRY_BACKOFF.max_backoff must be 30s \
             — the shared cap every sibling RetryPolicy-consumer \
             (INTEGRATION_TEST_RETRY_BACKOFF, TEST_RETRY_BACKOFF, \
             POST_DEPLOYMENT_READINESS_POLL_BACKOFF, \
             HEALTH_ENDPOINT_BACKOFF) also names.",
        );
    }

    /// Pre-lift the first between-retry sleep emitted
    /// `sleep(Duration::from_secs(2))` verbatim; the lift's 1-indexed
    /// `attempts` counter must reproduce that seed at
    /// `attempts == 1` via `pre_deployment_test_suite_retry_delay(1)`.
    /// The subsequent within-cap attempts (2/3/4) must emit the
    /// Bazel-style doubling climb (4s / 8s / 16s), strictly better than
    /// the pre-lift flat-2s schedule at every retry past the first.
    #[test]
    fn test_pre_deployment_test_suite_retry_delay_matches_pre_lift_seed_and_climbs_at_in_cap_attempts(
    ) {
        assert_eq!(
            pre_deployment_test_suite_retry_delay(1),
            Duration::from_secs(2),
            "attempts=1 must sleep 2s — matches pre-lift \
             `sleep(Duration::from_secs(2))` seed verbatim.",
        );
        assert_eq!(
            pre_deployment_test_suite_retry_delay(2),
            Duration::from_secs(4),
            "attempts=2 must sleep 4s — Bazel-style `2s * 2 = 4s`.",
        );
        assert_eq!(
            pre_deployment_test_suite_retry_delay(3),
            Duration::from_secs(8),
            "attempts=3 must sleep 8s — Bazel-style `4s * 2 = 8s`.",
        );
        assert_eq!(
            pre_deployment_test_suite_retry_delay(4),
            Duration::from_secs(16),
            "attempts=4 must sleep 16s — Bazel-style `8s * 2 = 16s`.",
        );
    }

    /// Attempts past the cap must all emit `max_backoff = 30s` —
    /// `(16s * 2).min(30s) = 30s` at attempts=5 and every subsequent
    /// attempt. `suite.max_retries` is a user-supplied pre-deployment-
    /// tests config field with no upper bound in the schema, so
    /// beyond-cap attempts must stay at the ceiling rather than climb
    /// past it and stretch a single suite's total retry wall-clock
    /// into hours.
    #[test]
    fn test_pre_deployment_test_suite_retry_delay_caps_at_max_backoff_past_the_cap() {
        assert_eq!(
            pre_deployment_test_suite_retry_delay(5),
            Duration::from_secs(30),
            "attempts=5 must sleep 30s (cap) — `(16s * 2).min(30s) = 30s`.",
        );
        assert_eq!(
            pre_deployment_test_suite_retry_delay(6),
            Duration::from_secs(30),
            "attempts=6 must sleep 30s (cap).",
        );
        assert_eq!(
            pre_deployment_test_suite_retry_delay(50),
            Duration::from_secs(30),
            "attempts=50 must sleep 30s (cap) — a pathological \
             `suite.max_retries` cannot stretch a single sleep past \
             the ceiling.",
        );
    }

    /// The retry loop's `attempts` counter is a `u32` bounded only by
    /// the caller-supplied `suite.max_retries + 1`, so a pathological
    /// config with `max_retries: u32::MAX` could in principle drive
    /// `pre_deployment_test_suite_retry_delay(u32::MAX)`. Pre-lift the
    /// fixed `Duration::from_secs(2)` literal never panicked at any
    /// attempt; post-lift `saturating_add(1)` inside
    /// `pre_deployment_test_suite_retry_delay` bounds the argument to
    /// `RetryPolicy::compute_delay`, whose `checked_pow`-then-cap body
    /// itself saturates without panic. This test pins that
    /// composition: an `attempts == u32::MAX` argument returns a
    /// bounded delay rather than panicking.
    #[test]
    fn test_pre_deployment_test_suite_retry_delay_saturates_without_panic_at_arbitrarily_large_attempt(
    ) {
        assert_eq!(
            pre_deployment_test_suite_retry_delay(u32::MAX),
            Duration::from_secs(30),
            "attempts=u32::MAX must saturate to max_backoff without \
             panic — the `saturating_add(1)` bridge + \
             `RetryPolicy::compute_delay`'s `checked_pow` cap close \
             the u32 overflow class by construction.",
        );
        assert_eq!(
            pre_deployment_test_suite_retry_delay(u32::MAX - 1),
            Duration::from_secs(30),
            "attempts=u32::MAX - 1 must also saturate to max_backoff \
             — the bridge `saturating_add(1)` returns u32::MAX, still \
             far past the cap.",
        );
    }

    /// The pre-deployment-test-suite retry policy shares
    /// `(factor, max_backoff)` with the canonical
    /// [`RetryPolicy::network()`] reference schedule; only
    /// `initial_backoff` diverges (2s vs 250ms) to preserve the
    /// pre-lift bare `sleep(Duration::from_secs(2))` seed verbatim.
    /// Pin the shared invariants so a future refinement to the retry
    /// module's reference schedule surfaces the intentional 2s-seed
    /// divergence as a named failure rather than a silent per-consumer
    /// drift.
    #[test]
    fn test_pre_deployment_test_suite_retry_backoff_shares_network_factor_and_cap() {
        let net = RetryPolicy::network();
        assert_eq!(
            PRE_DEPLOYMENT_TEST_SUITE_RETRY_BACKOFF.factor, net.factor,
            "PRE_DEPLOYMENT_TEST_SUITE_RETRY_BACKOFF.factor must match \
             RetryPolicy::network().factor — the Bazel-style doubling \
             climb is the shared invariant across every RetryPolicy \
             consumer.",
        );
        assert_eq!(
            PRE_DEPLOYMENT_TEST_SUITE_RETRY_BACKOFF.max_backoff, net.max_backoff,
            "PRE_DEPLOYMENT_TEST_SUITE_RETRY_BACKOFF.max_backoff must match \
             RetryPolicy::network().max_backoff — the 30s ceiling is the \
             shared invariant across every RetryPolicy consumer.",
        );
    }

    /// The `execute_pre_deployment_tests` retry loop MUST consume the
    /// typed primitive at
    /// `pre_deployment_test_suite_retry_delay(attempts)` rather than
    /// re-fusing the pre-lift bare-literal
    /// `sleep(Duration::from_secs(2))` shape (see
    /// `PRE_DEPLOYMENT_TEST_SUITE_RETRY_BACKOFF`'s docstring for the
    /// three structural defects the lift closed). A future refactor
    /// that reintroduces a flat schedule at this site fails here, not
    /// silently in production. Whole-function-body boundary discipline
    /// sibling of
    /// `test_execute_readiness_poll_consumes_typed_delay_not_bare_fixed_sleep`
    /// at this same module and
    /// `test_execute_suite_consumes_typed_retry_delay_not_bare_fixed_sleep`
    /// at this same module.
    ///
    /// The scan is bounded strictly to the
    /// `pub async fn execute_pre_deployment_tests(` body (from its
    /// signature through EOF, since it is the last top-level function
    /// in the module before the test modules). Uses the
    /// [`crate::test_support::code_line_hits`] helper so the shield
    /// does not false-positive on any comment or docstring text inside
    /// the function body. The forbidden literal is reconstructed at
    /// test time via [`format!`] off the const's `initial_backoff`
    /// field, so the assert message body itself stays unmatchable.
    #[test]
    fn test_execute_pre_deployment_tests_retry_consumes_typed_delay_not_bare_fixed_sleep() {
        let source = include_str!("integration_tests.rs");
        let fn_marker = "pub async fn execute_pre_deployment_tests(";
        let fn_start = source.find(fn_marker).expect(
            "the `pub async fn execute_pre_deployment_tests(` \
             signature must exist — the shield's slice boundary \
             relies on this signature.",
        );
        // Bound the slice at the first `#[cfg(test)]` (start of the
        // test-module block that follows the last runtime function)
        // so the shield does not scan its own docstring text below.
        let tests_marker = "\n#[cfg(test)]\n";
        let fn_body_rel = source[fn_start..].find(tests_marker).expect(
            "the `#[cfg(test)]` test-module block must follow \
             `execute_pre_deployment_tests` — the shield's slice \
             boundary relies on this ordering.",
        );
        let fn_body = &source[fn_start..fn_start + fn_body_rel];

        let bespoke_needle = format!(
            "sleep(Duration::from_secs({}))",
            PRE_DEPLOYMENT_TEST_SUITE_RETRY_BACKOFF
                .initial_backoff
                .as_secs(),
        );
        let bespoke_hits = crate::test_support::code_line_hits(fn_body, &bespoke_needle);
        assert!(
            bespoke_hits.is_empty(),
            "commands/integration_tests.rs::execute_pre_deployment_tests \
             must NOT re-fuse the pre-lift bare fixed sleep at the \
             retry loop — the schedule lives at \
             `PRE_DEPLOYMENT_TEST_SUITE_RETRY_BACKOFF` + \
             `pre_deployment_test_suite_retry_delay`, both grounding \
             through `RetryPolicy::compute_delay`. Found code-line \
             hits: {:#?}",
            bespoke_hits,
        );
        let delegation_hits = crate::test_support::code_line_hits(
            fn_body,
            "pre_deployment_test_suite_retry_delay(attempts)",
        );
        assert!(
            !delegation_hits.is_empty(),
            "commands/integration_tests.rs::execute_pre_deployment_tests \
             must consume the typed retry-delay helper at the retry \
             loop's sleep site — the canonical delegation call was not \
             found at any code line inside \
             `pub async fn execute_pre_deployment_tests`.",
        );
    }
}

#[cfg(test)]
mod kubectl_bin_routing_tests {
    /// Whole-module shield: no raw `Command::new`-with-bare-`kubectl`-
    /// literal may live in `commands/integration_tests.rs`. Every
    /// `kubectl` spawn on this module — pre-lift the sole
    /// `fetch_secret` `kubectl get secret … -o jsonpath={.data.<key>}`
    /// call at line 442 (the Kubernetes-Secret-backed credential
    /// resolver `build_env_vars` uses to inject `TEST_USER_EMAIL` /
    /// `TEST_USER_PASSWORD` into every integration-test suite the
    /// `forge test` flow spawns) — must resolve through
    /// [`crate::infrastructure::kubectl::kubectl_command_async`] —
    /// the async constructor that reads the `KUBECTL_BIN` env
    /// override via [`crate::tools::get_tool_path`] on the canonical
    /// `tools::KUBECTL` name.
    ///
    /// Pre-lift the `kubectl` spawn site spelled the bare
    /// `"kubectl"` literal via `Command::new` (aliased through the
    /// module's `use tokio::process::Command`), ignoring
    /// `KUBECTL_BIN` at the site. A Nix-hermetic runner's substrate-
    /// derived `kubectl` path was lost to whatever `kubectl` sat
    /// first on PATH — the same silent-PATH-fallback bug class the
    /// sibling consumer sites in forge already avoid
    /// (`commands/rust_service.rs` at 40cfe44,
    /// `commands/search_sync.rs` at 2bf0490,
    /// `commands/rollout.rs::execute` at c5fcf83,
    /// `commands/migrations.rs` at 946e573,
    /// `commands/status.rs` at c2760df,
    /// `commands/flux.rs` at f8da719,
    /// `commands/federation_tests.rs` at 9a409e8,
    /// `commands/supergraph_verification.rs` at 65283fb,
    /// `services/migration_service.rs` at 5986a10,
    /// `commands/github_runner_ci.rs` at 5566415,
    /// `commands/product_release.rs::run_health_check` at 5bb7cff).
    ///
    /// This shield scans the module's own source via [`include_str!`]
    /// and forbids the fused literal shape. The forbidden shape is
    /// reconstructed via [`format!`] from the bare string `"kubectl"`
    /// so this shield's own source text does not false-match itself
    /// — the whole-module scan therefore covers both the top-of-file
    /// production body AND every sibling `#[cfg(test)]` block (the
    /// pre-existing `tests` module and this block), any of which
    /// could otherwise silently re-introduce a raw literal. The
    /// end-to-end `KUBECTL_BIN`-routing invariant of the underlying
    /// primitive is pinned separately by
    /// [`crate::infrastructure::kubectl::tests::test_kubectl_command_async_routes_through_kubectl_bin_env_var`];
    /// this shield only certifies that every `kubectl`-spawning site
    /// in this module resolves through the constructor first.
    #[test]
    fn test_kubectl_spawn_routes_through_kubectl_command_async_not_raw_literal() {
        const SOURCE: &str = include_str!("integration_tests.rs");

        crate::test_support::assert_source_forbids_bare_spawn_shapes(
            SOURCE,
            "commands/integration_tests.rs",
            "kubectl",
            "resolve the substrate-exported `KUBECTL_BIN` env override via \
             `kubectl_command_async`",
        );
        crate::test_support::assert_source_delegates_via_constructor_call_code_line(
            SOURCE,
            "commands/integration_tests.rs",
            "kubectl",
            "kubectl_command_async",
        );
    }
}

#[cfg(test)]
mod sh_bin_routing_tests {
    /// Whole-module shield: no raw `Command::new`-with-bare-`sh`-literal
    /// may live in `commands/integration_tests.rs`. The sole `sh` spawn
    /// on this module — the per-suite `sh -c <suite.command>` invocation
    /// at line 572 inside `run_test_suite` that drives every
    /// `deploy.yaml` integration `TestSuite.command` string through a
    /// shell — must resolve `SH_BIN` via
    /// [`crate::repo::get_tool_path`], the two-arg env-var override
    /// every sibling probe/spawn surface honors (`commands/nix_builder.rs`
    /// `{SSH,NC,DIG}_BIN` four sites at 5e6672d;
    /// `commands/comprehensive_release.rs` `SQLX_BIN` at ecace0a;
    /// `commands/sync.rs` `SEA_ORM_CLI_BIN` at b037895;
    /// `commands/search_sync.rs` `NOVASEARCHCTL_BIN` at 19463db).
    ///
    /// Pre-lift the spawn site spelled the bare `"sh"` literal via
    /// `Command::new` (aliased through the module's
    /// `use tokio::process::Command`), ignoring `SH_BIN` at the site.
    /// A Nix-hermetic runner whose derivation exports
    /// `SH_BIN=/nix/store/…-bash/bin/sh` but omits `sh` from PATH
    /// silently fell through to whatever ambient shell an outer
    /// wrapper had — the same silent-PATH-fallback bug class the
    /// sibling `KUBECTL_BIN` shield above closes for the `kubectl`
    /// surface, here closed for the `sh -c` integration-driver
    /// surface.
    ///
    /// This shield scans the module's own source via [`include_str!`]
    /// and forbids the fused literal shape. The forbidden shape is
    /// reconstructed via [`format!`] from the bare string `"sh"` so
    /// this shield's own source text does not false-match itself —
    /// the whole-module scan therefore covers both the top-of-file
    /// production body AND every sibling `#[cfg(test)]` block, any
    /// of which could otherwise silently re-introduce a raw literal.
    #[test]
    fn test_sh_spawn_routes_through_sh_bin_env_not_raw_literal() {
        const SOURCE: &str = include_str!("integration_tests.rs");

        crate::test_support::assert_source_forbids_bare_spawn_shapes(
            SOURCE,
            "commands/integration_tests.rs",
            "sh",
            "resolve `SH_BIN` via `crate::repo::get_tool_path(\"SH_BIN\", \"sh\")`",
        );
        crate::test_support::assert_source_has_get_tool_path_two_arg_call_code_line(
            SOURCE,
            "commands/integration_tests.rs",
            "SH_BIN",
            "sh",
        );
    }
}
