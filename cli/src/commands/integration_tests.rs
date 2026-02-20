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

/// Parse duration string like "30s", "5m", "1h"
pub fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    if s.ends_with('s') {
        let secs: u64 = s[..s.len() - 1].parse()?;
        Ok(Duration::from_secs(secs))
    } else if s.ends_with('m') {
        let mins: u64 = s[..s.len() - 1].parse()?;
        Ok(Duration::from_secs(mins * 60))
    } else if s.ends_with('h') {
        let hours: u64 = s[..s.len() - 1].parse()?;
        Ok(Duration::from_secs(hours * 3600))
    } else {
        // Assume seconds if no suffix
        let secs: u64 = s.parse()?;
        Ok(Duration::from_secs(secs))
    }
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
    let max_wait = parse_duration(&config.execution.warmup_delay)?;
    let health_url = format!("{}/health", config.environment.base_url);

    let start = std::time::Instant::now();
    let mut ready = false;

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
                // Wait 2 seconds before next poll
                sleep(Duration::from_secs(2)).await;
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
    let output = Command::new("kubectl")
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
    let suite_timeout = parse_duration(&suite.timeout)?;
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

        let mut cmd = Command::new("sh");
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
                    sleep(Duration::from_secs(5)).await;
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
                sleep(Duration::from_secs(5)).await;
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
                sleep(Duration::from_secs(5)).await;
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
    let deploy_yaml_path = if let Some(product_dir) = find_product_dir_from_service(&service_dir_path) {
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
        let test_timeout = parse_duration(&suite.timeout).unwrap_or(Duration::from_secs(300));

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
                sleep(Duration::from_secs(2)).await;
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
