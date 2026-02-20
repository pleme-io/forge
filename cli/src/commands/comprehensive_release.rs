use anyhow::{Context, Result};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::time::{Duration, Instant};
use tokio::process::Command;
use tracing::{debug, info, warn};

use crate::{commands, git};

/// Comprehensive release workflow with full testing
///
/// Workflow:
/// 1. Input Validation
/// 2. Pre-Build Validation (unit tests)
/// 3. Build Docker Image
/// 4. Integration Testing (optional, with compose)
/// 5. Push to Registry
/// 6. Deploy to Kubernetes
#[allow(clippy::too_many_arguments)]
pub async fn execute(
    service_name: String,
    product_name: String,
    namespace: String,
    flake_attr: String,
    working_dir: String,
    compose_file: Option<String>,
    registry: String,
    manifest: String,
    migrations_path: String,
    cache_url: String,
    cache_name: String,
    db_port: u16,
    db_user: String,
    db_password: String,
    db_name: String,
    skip_unit_tests: bool,
    skip_integration_tests: bool,
    skip_build: bool,
    skip_push: bool,
    skip_deploy: bool,
    watch: bool,
) -> Result<()> {
    let workflow_start = Instant::now();
    println!();
    println!(
        "{}",
        "╔═══════════════════════════════════════════════════════════════╗"
            .bright_cyan()
            .bold()
    );
    println!(
        "{}",
        format!("║  🚀 {} Comprehensive Release Workflow", service_name)
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

    // ========================================================================
    // STEP 0: INPUT VALIDATION
    // ========================================================================
    info!("🔍 Validating inputs...");

    // Validate working directory exists
    let working_dir_path = std::path::Path::new(&working_dir);
    if !working_dir_path.exists() {
        anyhow::bail!("Working directory does not exist: {}", working_dir);
    }
    if !working_dir_path.is_dir() {
        anyhow::bail!("Working directory is not a directory: {}", working_dir);
    }

    // Validate compose file exists if provided
    if let Some(ref compose_path) = compose_file {
        let compose_file_path = working_dir_path.join(compose_path);
        if !compose_file_path.exists() {
            anyhow::bail!(
                "Compose file does not exist: {} (resolved to {})",
                compose_path,
                compose_file_path.display()
            );
        }
        debug!("Compose file validated: {}", compose_file_path.display());
    }

    // Validate migrations directory exists (warning only)
    let migrations_dir = working_dir_path.join(&migrations_path);
    if !migrations_dir.exists() {
        warn!(
            "⚠️  Migrations directory not found: {} - migrations will be skipped",
            migrations_path
        );
    } else {
        debug!("Migrations directory found: {}", migrations_dir.display());
    }

    info!("✅ Input validation complete");
    println!();

    // Get git SHA for tagging
    let git_sha = git::get_short_sha()?;
    info!("📦 Git SHA: {}", git_sha);
    info!("🎯 Registry: {}", registry);
    info!("🌍 Namespace: {} (staging)", namespace);
    println!();

    // Find repo root
    let repo_root = git::get_repo_root().context("Failed to find git repository")?;
    let repo_root_str = repo_root
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid repository path"))?;

    // ========================================================================
    // STEP 1: PRE-BUILD VALIDATION (Unit Tests)
    // ========================================================================
    if !skip_unit_tests {
        let step_start = Instant::now();
        info!("━━━ Step 1/5: Pre-Build Validation ━━━");
        println!();

        info!("🧪 Running unit tests...");
        println!();

        let spinner = ProgressBar::new_spinner();
        spinner.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} {msg}")
                .unwrap(),
        );
        spinner.set_message("Running cargo test --lib --bins...");
        spinner.enable_steady_tick(Duration::from_millis(100));

        let test_result = Command::new("cargo")
            .current_dir(&working_dir)
            .args(&["test", "--lib", "--bins", "--", "--show-output"])
            .env("RUST_LOG", "info")
            .env("RUST_BACKTRACE", "1")
            .env("SQLX_OFFLINE", "true")
            .status()
            .await
            .context("Failed to run cargo test")?;

        spinner.finish_and_clear();

        if !test_result.success() {
            println!();
            println!("{}", "✗ Unit tests failed".red().bold());
            println!();
            anyhow::bail!("Unit tests failed - aborting release");
        }

        let step_duration = step_start.elapsed();
        println!();
        info!(
            "{} (took {:.1}s)",
            "✅ Unit tests passed".green().bold(),
            step_duration.as_secs_f64()
        );
        println!();
    } else {
        info!("⏭️  Skipping unit tests");
        println!();
    }

    // ========================================================================
    // STEP 2: BUILD DOCKER IMAGE
    // ========================================================================
    let build_output = "result";

    if !skip_build {
        let step_start = Instant::now();
        info!("━━━ Step 2/5: Build Docker Image ━━━");
        println!();

        commands::build::execute(
            flake_attr.clone(),
            working_dir.clone(),
            "x86_64-linux".to_string(),
            cache_url.clone(),
            cache_name.clone(),
            true, // push_cache
            build_output.to_string(),
        )
        .await?;

        let step_duration = step_start.elapsed();
        info!(
            "{} (took {:.1}s)",
            "✅ Docker image built successfully".green().bold(),
            step_duration.as_secs_f64()
        );
        println!();
    } else {
        info!("⏭️  Skipping build step");
        println!();
    }

    // ========================================================================
    // STEP 3: INTEGRATION TESTING (Conditional)
    // ========================================================================
    if !skip_integration_tests {
        if let Some(compose_path) = &compose_file {
            let step_start = Instant::now();
            info!("━━━ Step 3/5: Integration Testing ━━━");
            println!();

            // Check if compose file exists
            let compose_file_path = std::path::Path::new(&working_dir).join(compose_path);
            if !compose_file_path.exists() {
                warn!(
                    "⚠️  Compose file not found: {}",
                    compose_file_path.display()
                );
                warn!("⚠️  Skipping integration tests");
                println!();
            } else {
                info!("📦 Loading Docker image into local daemon...");

                // Load Docker image
                let load_result = Command::new("docker")
                    .current_dir(&working_dir)
                    .args(&["load", "-i", build_output])
                    .output()
                    .await
                    .context("Failed to load Docker image")?;

                if !load_result.status.success() {
                    anyhow::bail!("Failed to load Docker image");
                }

                // Extract image name from docker load output
                let load_output = String::from_utf8_lossy(&load_result.stdout);
                let image_name = load_output
                    .lines()
                    .find(|line| line.contains("Loaded image"))
                    .and_then(|line| line.split(':').last())
                    .map(|s| s.trim())
                    .ok_or_else(|| anyhow::anyhow!("Could not determine loaded image name"))?;

                info!("   Loaded: {}", image_name);

                // Tag for compose
                let compose_tag = format!("{}:latest", registry);
                info!("🏷️  Tagging image: {}", compose_tag);

                let tag_result = Command::new("docker")
                    .args(&["tag", image_name, &compose_tag])
                    .status()
                    .await
                    .context("Failed to tag Docker image")?;

                if !tag_result.success() {
                    anyhow::bail!("Failed to tag Docker image");
                }

                println!();
                info!("🚀 Starting docker-compose environment...");

                // Start docker-compose
                let up_result = Command::new("docker-compose")
                    .current_dir(&working_dir)
                    .args(&["-f", compose_path, "up", "-d"])
                    .status()
                    .await
                    .context("Failed to start docker-compose")?;

                if !up_result.success() {
                    // Cleanup on failure
                    let _ = Command::new("docker-compose")
                        .current_dir(&working_dir)
                        .args(&["-f", compose_path, "down", "-v"])
                        .status()
                        .await;
                    anyhow::bail!("Failed to start docker-compose");
                }

                // Wait for services to be healthy
                info!("⏳ Waiting for services to be healthy...");
                let mut attempts = 0;
                let max_attempts = 60; // 2 minutes (60 * 2s)

                loop {
                    let ps_result = Command::new("docker-compose")
                        .current_dir(&working_dir)
                        .args(&["-f", compose_path, "ps"])
                        .output()
                        .await?;

                    let ps_output = String::from_utf8_lossy(&ps_result.stdout);
                    if ps_output.contains("healthy") || ps_output.contains("Up") {
                        break;
                    }

                    attempts += 1;
                    if attempts >= max_attempts {
                        // Show logs and cleanup
                        let _ = Command::new("docker-compose")
                            .current_dir(&working_dir)
                            .args(&["-f", compose_path, "logs"])
                            .status()
                            .await;

                        let _ = Command::new("docker-compose")
                            .current_dir(&working_dir)
                            .args(&["-f", compose_path, "down", "-v"])
                            .status()
                            .await;

                        anyhow::bail!("Timeout waiting for services to become healthy");
                    }

                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                }

                info!("{}", "✅ Services are healthy".green());
                println!();

                // Run migrations
                let migrations_dir = std::path::Path::new(&working_dir).join(&migrations_path);
                if migrations_dir.exists() {
                    info!("🗄️  Running database migrations...");

                    // Use configurable database connection parameters
                    let db_url = format!(
                        "postgresql://{}:{}@localhost:{}/{}",
                        db_user, db_password, db_port, db_name
                    );

                    debug!(
                        "Database URL: postgresql://{}:***@localhost:{}/{}",
                        db_user, db_port, db_name
                    );

                    let migrate_result = Command::new("sqlx")
                        .args(&[
                            "migrate",
                            "run",
                            "--database-url",
                            &db_url,
                            "--source",
                            migrations_dir.to_str().unwrap(),
                        ])
                        .status()
                        .await;

                    match migrate_result {
                        Ok(status) if status.success() => {
                            info!("   ✅ Migrations applied successfully");
                        }
                        Ok(status) => {
                            warn!(
                                "   ⚠️  Migration command failed with exit code: {:?}",
                                status.code()
                            );
                            warn!("   This might indicate a database connection issue or migration error");
                        }
                        Err(e) => {
                            warn!("   ⚠️  Failed to execute sqlx: {}", e);
                            warn!("   Ensure sqlx-cli is installed: cargo install sqlx-cli");
                        }
                    }
                    println!();
                } else {
                    debug!("Migrations directory not found: {:?}", migrations_dir);
                }

                // Run integration tests
                info!("🧪 Running integration tests...");
                println!();

                let integration_test_result = Command::new("cargo")
                    .current_dir(&working_dir)
                    .args(&["test", "--test", "*", "--", "--ignored", "--test-threads=1"])
                    .env("RUST_LOG", "info")
                    .env("RUST_BACKTRACE", "1")
                    .status()
                    .await;

                // Check integration test result BEFORE cleanup (so we can show logs)
                let tests_failed = match integration_test_result {
                    Ok(status) if status.success() => false,
                    _ => true,
                };

                // If tests failed, show service logs BEFORE cleanup
                if tests_failed {
                    println!();
                    println!("{}", "✗ Integration tests failed".red().bold());
                    println!();

                    info!("📋 Dumping service logs for debugging...");
                    println!();

                    let _ = Command::new("docker-compose")
                        .current_dir(&working_dir)
                        .args(&["-f", compose_path, "logs", "--tail=100"])
                        .status()
                        .await;

                    println!();
                }

                // Always cleanup compose environment
                info!("🧹 Cleaning up docker-compose environment...");
                let cleanup_result = Command::new("docker-compose")
                    .current_dir(&working_dir)
                    .args(&["-f", compose_path, "down", "-v"])
                    .status()
                    .await;

                if cleanup_result.is_err() {
                    warn!("⚠️  Failed to cleanup docker-compose (non-fatal)");
                }

                // Bail after cleanup if tests failed
                if tests_failed {
                    anyhow::bail!("Integration tests failed - aborting release");
                }

                let step_duration = step_start.elapsed();
                println!();
                info!(
                    "{} (took {:.1}s)",
                    "✅ Integration tests passed".green().bold(),
                    step_duration.as_secs_f64()
                );
                println!();
            }
        } else {
            info!("━━━ Step 3/5: Integration Testing ━━━");
            println!();
            warn!("⚠️  No compose file provided, skipping integration tests");
            println!();
        }
    } else {
        info!("⏭️  Skipping integration tests");
        println!();
    }

    // ========================================================================
    // STEP 4: PUSH TO REGISTRY
    // ========================================================================
    if !skip_push {
        let step_start = Instant::now();
        info!("━━━ Step 4/5: Push to Registry ━━━");
        println!();

        commands::push::execute(
            build_output.to_string(),
            registry.clone(),
            vec![git_sha.clone(), "latest".to_string()],
            false,               // auto_tags - already have explicit tags
            "amd64".to_string(), // arch
            10,                  // retries
            None,                // token from env
            true,                // push_attic
            cache_name.clone(),
            None,  // update_kustomization_path
            false, // commit_kustomization
        )
        .await?;

        let step_duration = step_start.elapsed();
        info!(
            "{} (took {:.1}s)",
            "✅ Image pushed successfully".green().bold(),
            step_duration.as_secs_f64()
        );
        println!();
    } else {
        info!("⏭️  Skipping push step");
        println!();
    }

    // ========================================================================
    // STEP 5: DEPLOY TO KUBERNETES
    // ========================================================================
    if !skip_deploy {
        let step_start = Instant::now();
        info!("━━━ Step 5/5: Deploy to Kubernetes ━━━");
        println!();

        // Create result symlink at repo root for deploy command
        let result_link = std::path::Path::new(repo_root_str).join("result");
        let work_dir_result = std::path::Path::new(&working_dir).join(build_output);

        // Remove existing symlink
        let _ = tokio::fs::remove_file(&result_link).await;

        // Create new symlink
        tokio::fs::symlink(&work_dir_result, &result_link)
            .await
            .context("Failed to create result symlink")?;

        commands::deploy::execute(
            manifest.clone(),
            registry.clone(),
            git_sha.clone(),
            namespace.clone(),
            service_name.clone(),
            watch,
            "10m".to_string(),
            true, // skip_build
            cache_url,
            cache_name,
        )
        .await?;

        let step_duration = step_start.elapsed();
        info!(
            "{} (took {:.1}s)",
            "✅ Deployment complete".green().bold(),
            step_duration.as_secs_f64()
        );
        println!();
    } else {
        info!("⏭️  Skipping deploy step");
        println!();
    }

    // ========================================================================
    // SUMMARY
    // ========================================================================
    let workflow_duration = workflow_start.elapsed();
    println!();
    println!(
        "{}",
        "╔═══════════════════════════════════════════════════════════════╗"
            .bright_green()
            .bold()
    );
    println!(
        "{}",
        "║  ✅ Comprehensive Release Complete!                           ║"
            .bright_green()
            .bold()
    );
    println!(
        "{}",
        "╚═══════════════════════════════════════════════════════════════╝"
            .bright_green()
            .bold()
    );
    println!();
    println!("Summary:");
    println!(
        "  • Unit tests: {}",
        if skip_unit_tests { "SKIPPED" } else { "PASSED" }
    );
    println!(
        "  • Integration tests: {}",
        if skip_integration_tests || compose_file.is_none() {
            "SKIPPED"
        } else {
            "PASSED"
        }
    );
    println!(
        "  • Docker build: {}",
        if skip_build { "SKIPPED" } else { "SUCCESS" }
    );

    let push_status = if skip_push {
        "SKIPPED".to_string()
    } else {
        format!("SUCCESS (tag: {})", git_sha)
    };
    println!("  • Registry push: {}", push_status);
    println!(
        "  • Kubernetes deploy: {}",
        if skip_deploy { "SKIPPED" } else { "SUCCESS" }
    );
    println!();
    println!("Service {} is now deployed to {}", service_name, namespace);
    println!();
    println!(
        "⏱️  Total workflow time: {:.1}s ({:.1}m)",
        workflow_duration.as_secs_f64(),
        workflow_duration.as_secs_f64() / 60.0
    );
    println!();

    Ok(())
}
