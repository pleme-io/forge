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

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use serde::Deserialize;
use tokio::process::Command;
use tokio::time::timeout;
use tracing::info;

use crate::commands::integration_tests::parse_duration;

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

/// Walk up from a path to find the product directory (pkgs/products/{product}).
fn find_product_dir_from_path(start: &Path) -> Option<PathBuf> {
    let mut current = start.to_path_buf();
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

/// Load web tests configuration from deploy.yaml
fn load_web_tests_config(service: &str, service_dir: &str) -> Result<WebTestsConfig> {
    let service_dir_path = PathBuf::from(service_dir);
    let deploy_yaml_path = if let Some(product_dir) = find_product_dir_from_path(&service_dir_path) {
        crate::config::resolve_deploy_yaml_path(&product_dir, service, &service_dir_path)
    } else {
        service_dir_path.join("deploy.yaml")
    };

    if !deploy_yaml_path.exists() {
        info!("No deploy.yaml found, using default test configuration");
        return Ok(WebTestsConfig::default());
    }

    let yaml_content = std::fs::read_to_string(&deploy_yaml_path).context(format!(
        "Failed to read deploy.yaml at: {}",
        deploy_yaml_path.display()
    ))?;

    let raw_config: RawDeployYaml =
        serde_yaml::from_str(&yaml_content).context("Failed to parse deploy.yaml")?;

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

    if run_unit {
        println!(
            "  {} Running Rust unit tests for {}...",
            "🧪".bright_yellow(),
            service.bright_cyan()
        );

        let status = Command::new("cargo")
            .args(["test", "--lib", "--bins"])
            .current_dir(service_dir)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .await
            .context("Failed to run cargo test")?;

        if !status.success() {
            bail!("Rust unit tests failed");
        }

        println!("  {} Rust unit tests passed", "✅".bright_green());
    }

    if run_integration {
        println!(
            "  {} Running Rust integration tests for {}...",
            "🔗".bright_yellow(),
            service.bright_cyan()
        );

        let status = Command::new("cargo")
            .args(["test", "--test", "*"])
            .current_dir(service_dir)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .await
            .context("Failed to run cargo integration tests")?;

        if !status.success() {
            bail!("Rust integration tests failed");
        }

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

    let test_timeout = parse_duration(&config.timeout).unwrap_or(Duration::from_secs(300));

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

        let spinner = ProgressBar::new_spinner();
        spinner.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.cyan} {msg}")
                .unwrap(),
        );
        spinner.set_message(format!("Running {} tests...", suite_name));
        spinner.enable_steady_tick(Duration::from_millis(100));

        let result = timeout(test_timeout, async {
            let output = Command::new("sh")
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
                tokio::time::sleep(Duration::from_secs(2)).await;
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
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Err(_) => {
                if attempt == max_attempts {
                    bail!("{} tests timed out after {:?}", suite_name, test_timeout);
                }
                println!("     {} Timed out, will retry...", "⚠️ ".bright_yellow());
                tokio::time::sleep(Duration::from_secs(2)).await;
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
