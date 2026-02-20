//! Frontend Validation Gates
//!
//! This module provides pre-release validation for frontend code:
//! - TypeScript type checking (tsc --noEmit)
//! - Lint validation (biome or eslint, configurable)
//! - Unit tests (vitest)
//!
//! Part of the pre-release gate system.

use anyhow::{Context, Result};
use colored::Colorize;
use std::path::Path;
use std::time::Instant;
use tokio::process::Command;

use crate::repo::get_tool_path;

use crate::config::FrontendGatesConfig;

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
    let bun = get_tool_path("BUN_BIN", "bun");
    let output = Command::new(&bun)
        .args(["run", "type-check"])
        .current_dir(web_dir)
        .output()
        .await
        .with_context(|| format!("Failed to run type-check in {}", web_dir.display()))?;

    let duration = start.elapsed();

    if output.status.success() {
        println!(
            "   {} Type check passed ({:.1}s)",
            "✅".green(),
            duration.as_secs_f64()
        );
        Ok((true, Vec::new()))
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);

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
    let bun = get_tool_path("BUN_BIN", "bun");
    let output = Command::new(&bun)
        .args(["run", "lint"])
        .current_dir(web_dir)
        .output()
        .await
        .with_context(|| format!("Failed to run lint in {}", web_dir.display()))?;

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
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
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
    let bun = get_tool_path("BUN_BIN", "bun");
    let fix_output = Command::new(&bun)
        .args(["x", "biome", "check", "--write", "src"])
        .current_dir(web_dir)
        .output()
        .await
        .with_context(|| "Failed to run biome check --write")?;

    // Auto-fix may report issues it couldn't fix - that's OK
    // We'll catch those in the verification step

    if !fix_output.status.success() {
        let stderr = String::from_utf8_lossy(&fix_output.stderr);
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
            return Ok((false, stderr.lines().take(5).map(|l| l.to_string()).collect()));
        }
        // Otherwise, continue to check step - unfixable issues will be caught there
    }

    println!("   Auto-fix complete, verifying...");

    // Then verify with biome check (no --write)
    let check_output = Command::new(&bun)
        .args(["x", "biome", "check", "src"])
        .current_dir(web_dir)
        .output()
        .await
        .with_context(|| "Failed to run biome check")?;

    let duration = start.elapsed();

    if check_output.status.success() {
        println!(
            "   {} Biome lint applied and verified ({:.1}s)",
            "✅".green(),
            duration.as_secs_f64()
        );
        Ok((true, Vec::new()))
    } else {
        let stderr = String::from_utf8_lossy(&check_output.stderr);
        let stdout = String::from_utf8_lossy(&check_output.stdout);
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

    let bun = get_tool_path("BUN_BIN", "bun");
    let output = Command::new(&bun)
        .args(["run", "test", "--", "--run"]) // --run for non-watch mode
        .current_dir(web_dir)
        .output()
        .await
        .with_context(|| format!("Failed to run tests in {}", web_dir.display()))?;

    let duration = start.elapsed();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
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
            println!(
                "   {}",
                details.join("\n   ")
            );
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
    let bun = get_tool_path("BUN_BIN", "bun");
    let install = Command::new(&bun)
        .args(["install", "--frozen-lockfile"])
        .current_dir(web_dir)
        .output()
        .await
        .with_context(|| format!("Failed to run bun install in {}", web_dir.display()))?;

    if !install.status.success() {
        let stderr = String::from_utf8_lossy(&install.stderr);
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
