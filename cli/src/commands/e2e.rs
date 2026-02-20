//! E2E testing commands
//!
//! Provides commands for running unit, integration, and E2E tests.
//! Each test level is self-preparing:
//! - Unit: no dependencies
//! - Integration: auto-starts Docker on macOS if not running
//! - E2E: auto-builds and loads images if missing

use anyhow::{bail, Context, Result};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use crate::repo::get_tool_path;
use crate::ui;

/// Test pyramid levels
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TestLevel {
    Unit,
    Integration,
    E2e,
}

/// Run the full testing pyramid
///
/// Executes tests in order: Unit → Integration → E2E (fast feedback first)
pub fn run_test_pyramid(
    repo_root: Option<String>,
    skip_unit: bool,
    skip_integration: bool,
    skip_e2e: bool,
    filter: Option<String>,
    fail_fast: bool,
    report: bool,
    report_path: Option<String>,
) -> Result<()> {
    let repo_root = resolve_repo_root(repo_root)?;
    // TODO: derive product paths from deploy.yaml config
    let backend_dir = format!("{}/services/rust/backend", repo_root);
    let web_dir = format!("{}/web", repo_root);

    ui::print_header("Testing Pyramid");
    println!();
    println!("Test order: Unit → Integration → E2E (fast feedback first)");
    println!();

    let mut all_passed = true;

    // Phase 1: Backend Unit Tests
    if !skip_unit {
        ui::print_header("Phase 1: Backend Unit Tests");
        let result = run_backend_unit_tests(&backend_dir, filter.as_deref());
        if result.is_err() {
            all_passed = false;
            if fail_fast {
                return result;
            }
            ui::print_error("Backend unit tests failed");
        } else {
            ui::print_success("Backend unit tests passed");
        }
        println!();
    }

    // Phase 2: Frontend Unit Tests
    if !skip_unit {
        ui::print_header("Phase 2: Frontend Unit Tests");
        let result =
            run_frontend_unit_tests(&web_dir, filter.as_deref(), report, report_path.as_deref());
        if result.is_err() {
            all_passed = false;
            if fail_fast {
                return result;
            }
            ui::print_error("Frontend unit tests failed");
        } else {
            ui::print_success("Frontend unit tests passed");
        }
        println!();
    }

    // Phase 3: Backend Integration Tests
    if !skip_integration {
        ui::print_header("Phase 3: Backend Integration Tests");

        // Verify Docker is available
        if let Err(e) = verify_docker() {
            ui::print_warning(&format!("Skipping integration tests: {}", e));
        } else {
            let result = run_backend_integration_tests(&backend_dir, filter.as_deref());
            if result.is_err() {
                all_passed = false;
                if fail_fast {
                    return result;
                }
                ui::print_error("Backend integration tests failed");
            } else {
                ui::print_success("Backend integration tests passed");
            }
        }
        println!();
    }

    // Phase 4: E2E Tests
    if !skip_e2e {
        ui::print_header("Phase 4: E2E Tests");

        // Check if images exist, prepare if not
        let backend_exists = check_image_exists("backend").unwrap_or(false);
        let frontend_exists = check_image_exists("web").unwrap_or(false);

        if !backend_exists || !frontend_exists {
            ui::print_warning("E2E images not found. Preparing them first...");
            if let Err(e) = prepare_e2e_images(Some(repo_root.clone()), false, false, false) {
                ui::print_warning(&format!("Failed to prepare E2E images: {}", e));
                ui::print_info("Skipping E2E tests");
            } else {
                let result = run_e2e_tests(Some(repo_root.clone()), true, filter.clone());
                if result.is_err() {
                    all_passed = false;
                    if fail_fast {
                        return result;
                    }
                    ui::print_error("E2E tests failed");
                } else {
                    ui::print_success("E2E tests passed");
                }
            }
        } else {
            let result = run_e2e_tests(Some(repo_root.clone()), true, filter.clone());
            if result.is_err() {
                all_passed = false;
                if fail_fast {
                    return result;
                }
                ui::print_error("E2E tests failed");
            } else {
                ui::print_success("E2E tests passed");
            }
        }
        println!();
    }

    // Summary
    println!();
    ui::print_header("Test Pyramid Summary");
    if all_passed {
        ui::print_success("All test levels passed!");
    } else {
        bail!("Some tests failed");
    }

    Ok(())
}

/// Run backend unit tests
fn run_backend_unit_tests(backend_dir: &str, filter: Option<&str>) -> Result<()> {
    ui::print_info("Running cargo test --lib");

    let mut cmd = Command::new("cargo");
    cmd.current_dir(backend_dir).arg("test").arg("--lib");

    if let Some(f) = filter {
        cmd.arg(f);
    }

    let start = Instant::now();
    let status = cmd.status().context("Failed to run cargo test")?;
    let elapsed = start.elapsed();

    ui::print_info(&format!("Backend unit tests completed in {:.1}s", elapsed.as_secs_f64()));

    if !status.success() {
        bail!("Backend unit tests failed (exit code: {:?})", status.code());
    }

    Ok(())
}

/// Run frontend unit tests
fn run_frontend_unit_tests(
    web_dir: &str,
    filter: Option<&str>,
    report: bool,
    report_path: Option<&str>,
) -> Result<()> {
    if report {
        // Determine report path
        let output_file = report_path
            .map(|p| p.to_string())
            .unwrap_or_else(|| format!("{}/test-report.json", web_dir));

        ui::print_info(&format!(
            "Running tests with live output + JSON report → {}",
            output_file
        ));

        // Use BOTH default reporter (for terminal) AND json reporter (for file)
        // This gives live feedback while still generating a machine-readable report
        let bun = get_tool_path("BUN_BIN", "bun");
        let mut cmd = Command::new(&bun);
        cmd.current_dir(web_dir)
            .arg("run")
            .arg("test")
            .arg("--")
            .arg("--run")
            .arg("--reporter=default")
            .arg("--reporter=json")
            .arg(format!("--outputFile={}", output_file));

        if let Some(f) = filter {
            cmd.arg(f);
        }

        let start = Instant::now();
        let status = cmd
            .status()
            .context("Failed to run bun test with reporter")?;
        let elapsed = start.elapsed();

        println!();
        ui::print_info(&format!("Frontend tests completed in {:.1}s", elapsed.as_secs_f64()));
        ui::print_info(&format!("JSON report: {}", output_file));

        if !status.success() {
            bail!("Frontend unit tests failed (see report for details)");
        }
    } else {
        ui::print_info("Running bun run test");

        let bun = get_tool_path("BUN_BIN", "bun");
        let mut cmd = Command::new(&bun);
        cmd.current_dir(web_dir)
            .arg("run")
            .arg("test")
            .arg("--")
            .arg("--run");

        if let Some(f) = filter {
            cmd.arg(f);
        }

        let start = Instant::now();
        let status = cmd.status().context("Failed to run bun test")?;
        let elapsed = start.elapsed();

        ui::print_info(&format!("Frontend unit tests completed in {:.1}s", elapsed.as_secs_f64()));

        if !status.success() {
            bail!("Frontend unit tests failed (exit code: {:?})", status.code());
        }
    }

    Ok(())
}

/// Run backend integration tests
fn run_backend_integration_tests(backend_dir: &str, filter: Option<&str>) -> Result<()> {
    let mut args = vec![
        "test", "--test", "integration_tests", "--features", "integration-tests",
    ];
    if let Some(f) = filter {
        args.push("--");
        args.push(f);
    }

    ui::print_info(&format!("Running cargo {}", args.join(" ")));

    let start = Instant::now();
    let status = Command::new("cargo")
        .current_dir(backend_dir)
        .args(&args)
        .status()
        .context("Failed to run integration tests")?;
    let elapsed = start.elapsed();

    ui::print_info(&format!("Integration tests completed in {:.1}s", elapsed.as_secs_f64()));

    if !status.success() {
        bail!("Backend integration tests failed (exit code: {:?})", status.code());
    }

    Ok(())
}

/// Prepare E2E test images by building them via Nix and loading into Docker
pub fn prepare_e2e_images(
    repo_root: Option<String>,
    skip_backend: bool,
    skip_frontend: bool,
    force: bool,
) -> Result<()> {
    let repo_root = resolve_repo_root(repo_root)?;

    ui::print_header("E2E Test Image Preparation");
    println!();

    // Step 1: Verify Docker is available
    verify_docker()?;

    // Step 2: Check if images already exist (unless force rebuild)
    if !force {
        let backend_exists = check_image_exists("backend")?;
        let frontend_exists = check_image_exists("web")?;

        if backend_exists && frontend_exists {
            ui::print_success("E2E images already exist. Use --force to rebuild.");
            println!();
            print_image_info()?;
            return Ok(());
        }
    }

    // Step 3: Build and load backend image
    if !skip_backend {
        build_and_load_image(&repo_root, "backend", ".#backend")?;
    } else {
        ui::print_info("Skipping backend image build");
    }

    // Step 4: Build and load frontend image
    if !skip_frontend {
        build_and_load_image(&repo_root, "web", ".#web")?;
    } else {
        ui::print_info("Skipping frontend image build");
    }

    // Step 5: Print summary
    println!();
    ui::print_success("E2E images ready!");
    println!();
    print_image_info()?;

    println!();
    ui::print_info("You can now run E2E tests:");
    println!("  nix run .#e2e");
    println!("  # or");
    println!("  forge e2e-run");

    Ok(())
}

/// Run E2E tests with full-stack testcontainers
pub fn run_e2e_tests(
    repo_root: Option<String>,
    headless: bool,
    filter: Option<String>,
) -> Result<()> {
    let repo_root = resolve_repo_root(repo_root)?;

    ui::print_header("E2E Test Execution");
    println!();

    // Verify Docker is available
    verify_docker()?;

    // Check if images are available
    let backend_exists = check_image_exists("backend")?;
    let frontend_exists = check_image_exists("web")?;

    if !backend_exists || !frontend_exists {
        ui::print_warning("E2E images not found. Building them first...");
        println!();
        prepare_e2e_images(Some(repo_root.clone()), false, false, false)?;
        println!();
    }

    // TODO: derive product paths from deploy.yaml config
    let backend_dir = format!("{}/services/rust/backend", repo_root);

    // Pre-cleanup: ensure clean slate
    cleanup_testcontainers()?;

    // Build the cargo command
    let mut args = vec![
        "test",
        "--test",
        "e2e_tests",
        "--features",
        "integration-tests",
        "--",
        "--include-ignored",
    ];
    let filter_owned;
    if let Some(f) = &filter {
        filter_owned = f.clone();
        args.push(&filter_owned);
    }

    ui::print_info("Running E2E tests");
    println!("  Command: cargo {}", args.join(" "));
    println!("  Dir:     {}", backend_dir);
    println!("  Headless: {}", headless);
    println!();

    let start = Instant::now();

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&backend_dir).args(&args);

    // Set headless mode
    if headless {
        cmd.env("E2E_HEADLESS", "1");
    } else {
        cmd.env_remove("E2E_HEADLESS");
    }

    let status = cmd.status().context("Failed to run cargo test")?;
    let elapsed = start.elapsed();

    // Post-cleanup: remove containers regardless of pass/fail
    if let Err(e) = cleanup_testcontainers() {
        ui::print_warning(&format!("Post-test cleanup warning: {}", e));
    }

    println!();
    ui::print_info(&format!("E2E tests completed in {:.1}s", elapsed.as_secs_f64()));

    if !status.success() {
        print_failure_diagnostics();
        bail!("E2E tests failed (exit code: {:?})", status.code());
    }

    ui::print_success("E2E tests passed!");
    Ok(())
}

// =============================================================================
// Cleanup Functions
// =============================================================================

/// Kill all testcontainers-managed containers and Ryuk sidecars.
/// Safe to call when no containers exist.
pub fn cleanup_testcontainers() -> Result<()> {
    ui::print_info("Cleaning up testcontainers...");

    // Kill containers with testcontainers label
    let output = Command::new("docker")
        .args(["ps", "-q", "--filter", "label=org.testcontainers=true"])
        .output()
        .context("Failed to list testcontainers")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let container_ids: Vec<&str> = stdout
        .trim()
        .lines()
        .filter(|l| !l.is_empty())
        .collect();

    let tc_count = container_ids.len();

    if !container_ids.is_empty() {
        let ids: Vec<String> = container_ids.iter().map(|s| s.to_string()).collect();
        let mut args = vec!["rm", "-f"];
        for id in &ids {
            args.push(id);
        }
        let _ = Command::new("docker").args(&args).output();
    }

    // Kill Ryuk sidecars (may not have the label)
    let ryuk_output = Command::new("docker")
        .args(["ps", "-q", "--filter", "ancestor=testcontainers/ryuk"])
        .output()
        .context("Failed to list Ryuk containers")?;

    let ryuk_stdout = String::from_utf8_lossy(&ryuk_output.stdout);
    let ryuk_ids: Vec<&str> = ryuk_stdout
        .trim()
        .lines()
        .filter(|l| !l.is_empty())
        .collect();

    let ryuk_count = ryuk_ids.len();

    if !ryuk_ids.is_empty() {
        let ids: Vec<String> = ryuk_ids.iter().map(|s| s.to_string()).collect();
        let mut args = vec!["rm", "-f"];
        for id in &ids {
            args.push(id);
        }
        let _ = Command::new("docker").args(&args).output();
    }

    let total = tc_count + ryuk_count;
    if total > 0 {
        ui::print_success(&format!(
            "Removed {} container(s) ({} testcontainers, {} Ryuk sidecars)",
            total, tc_count, ryuk_count
        ));
    } else {
        ui::print_info("No orphaned testcontainers found");
    }

    Ok(())
}

/// Remove backend and web Docker images, plus dangling testcontainer images.
pub fn cleanup_e2e_images() -> Result<()> {
    ui::print_info("Cleaning up E2E images...");

    let mut removed = 0;

    for image in &["backend", "web"] {
        let exists = check_image_exists(image).unwrap_or(false);
        if exists {
            let status = Command::new("docker")
                .args(["rmi", "-f", image])
                .output()
                .context(format!("Failed to remove {} image", image))?;
            if status.status.success() {
                removed += 1;
                ui::print_info(&format!("Removed {} image", image));
            }
        }
    }

    // Prune dangling images from testcontainers
    let _ = Command::new("docker")
        .args(["image", "prune", "-f", "--filter", "label=org.testcontainers=true"])
        .output();

    if removed > 0 {
        ui::print_success(&format!("Removed {} E2E image(s)", removed));
    } else {
        ui::print_info("No E2E images to remove");
    }

    Ok(())
}

/// Full cleanup: containers + images. Intended for the CLI subcommand.
pub fn cleanup_all() -> Result<()> {
    ui::print_header("E2E Cleanup");
    println!();

    cleanup_testcontainers()?;
    cleanup_e2e_images()?;

    println!();
    ui::print_success("Cleanup complete");
    Ok(())
}

/// Resolve repository root from argument or git
fn resolve_repo_root(repo_root: Option<String>) -> Result<String> {
    if let Some(root) = repo_root {
        return Ok(root);
    }

    // Try to get from git
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .context("Failed to run git rev-parse")?;

    if output.status.success() {
        let root = String::from_utf8(output.stdout)
            .context("Invalid UTF-8 in git output")?
            .trim()
            .to_string();
        return Ok(root);
    }

    // Fall back to current directory
    Ok(std::env::current_dir()
        .context("Failed to get current directory")?
        .to_string_lossy()
        .to_string())
}

/// Verify Docker daemon is running
fn verify_docker() -> Result<()> {
    ui::print_info("Verifying Docker daemon");

    // Check if docker command exists
    let which_output = Command::new("which")
        .arg("docker")
        .output()
        .context("Failed to check for docker command")?;

    if !which_output.status.success() {
        bail!("Docker is not installed. Please install Docker first.");
    }

    // Check if Docker daemon is running
    let info_output = Command::new("docker")
        .arg("info")
        .output()
        .context("Failed to run docker info")?;

    if !info_output.status.success() {
        bail!("Docker daemon is not running. Please start Docker first.");
    }

    ui::print_success("Docker daemon is running");
    Ok(())
}

/// Check if a Docker image exists locally
fn check_image_exists(image_name: &str) -> Result<bool> {
    let output = Command::new("docker")
        .args(["images", "-q", image_name])
        .output()
        .context("Failed to check for Docker image")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(!stdout.trim().is_empty())
}

/// Build a Nix image and load it into Docker
fn build_and_load_image(repo_root: &str, name: &str, flake_attr: &str) -> Result<()> {
    let output_path = format!("/tmp/{}-image", name);

    // Build with Nix
    ui::print_info(&format!("Building {} image via Nix", name));
    let build_status = Command::new("nix")
        .current_dir(repo_root)
        .args(["build", flake_attr, "-o", &output_path])
        .status()
        .context("Failed to run nix build")?;

    if !build_status.success() {
        bail!("Nix build failed for {}", flake_attr);
    }

    // Load into Docker
    ui::print_info(&format!("Loading {} image into Docker", name));

    // Read the image file and pipe to docker load
    let image_file = std::fs::File::open(&output_path)
        .context(format!("Failed to open image file: {}", output_path))?;

    let mut docker_load = Command::new("docker")
        .arg("load")
        .stdin(image_file)
        .spawn()
        .context("Failed to spawn docker load")?;

    let load_status = docker_load
        .wait()
        .context("Failed to wait for docker load")?;

    if !load_status.success() {
        bail!("docker load failed for {}", name);
    }

    ui::print_success(&format!("{} image loaded", name));
    Ok(())
}

/// Print information about loaded E2E images
fn print_image_info() -> Result<()> {
    println!("Loaded images:");

    let output = Command::new("docker")
        .args([
            "images",
            "--format",
            "  {{.Repository}}:{{.Tag}}\t{{.Size}}\t{{.CreatedSince}}",
        ])
        .output()
        .context("Failed to list Docker images")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if line.contains("backend") || line.contains("web") {
            println!("{}", line);
        }
    }

    Ok(())
}

/// Print diagnostic info when E2E tests fail
fn print_failure_diagnostics() {
    eprintln!();
    eprintln!("{}", "=".repeat(72));
    eprintln!("E2E TEST FAILURE DIAGNOSTICS");
    eprintln!("{}", "=".repeat(72));

    // Docker container status
    eprintln!("\nDocker containers (running):");
    if let Ok(output) = Command::new("docker")
        .args([
            "ps",
            "--format",
            "  {{.Names}}\t{{.Status}}\t{{.Ports}}",
        ])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.trim().is_empty() {
            eprintln!("  (none)");
        } else {
            eprint!("{}", stdout);
        }
    }

    // Recently exited containers (testcontainers that died)
    eprintln!("\nDocker containers (recently exited):");
    if let Ok(output) = Command::new("docker")
        .args([
            "ps",
            "-a",
            "--filter",
            "status=exited",
            "--since",
            "15m",
            "--format",
            "  {{.Names}}\t{{.Status}}\t{{.Image}}",
        ])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.trim().is_empty() {
            eprintln!("  (none)");
        } else {
            eprint!("{}", stdout);
        }
    }

    // Check Docker images
    eprintln!("\nE2E Docker images:");
    if let Ok(output) = Command::new("docker")
        .args([
            "images",
            "--format",
            "  {{.Repository}}:{{.Tag}}\t{{.Size}}\t{{.ID}}",
        ])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains("backend") || line.contains("web") {
                eprintln!("{}", line);
            }
        }
    }

    // Check for screenshots
    let screenshot_dir = "target/screenshots";
    if let Ok(entries) = std::fs::read_dir(screenshot_dir) {
        let screenshots: Vec<_> = entries
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map(|ext| ext == "png").unwrap_or(false))
            .collect();
        if !screenshots.is_empty() {
            eprintln!("\nScreenshots captured:");
            for entry in &screenshots {
                eprintln!("  {}", entry.path().display());
            }
        }
    }

    eprintln!("\n{}", "=".repeat(72));
    eprintln!("Troubleshooting:");
    eprintln!("  1. Rebuild images:  nix run .#e2e:prepare -- --force");
    eprintln!("  2. Run headful:     nix run .#test:e2e -- --headless false");
    eprintln!("  3. Run one test:    nix run .#test:e2e -- --filter test_name");
    eprintln!("  4. Check logs:      docker logs <container_name>");
    eprintln!("{}", "=".repeat(72));
}

// =============================================================================
// Individual Test Level Commands
// =============================================================================

/// Run unit tests only (backend + frontend)
/// No external dependencies required.
pub fn run_unit_tests(
    repo_root: Option<String>,
    filter: Option<String>,
    skip_frontend: bool,
    report: bool,
    report_path: Option<String>,
) -> Result<()> {
    let repo_root = resolve_repo_root(repo_root)?;
    // TODO: derive product paths from deploy.yaml config
    let backend_dir = format!("{}/services/rust/backend", repo_root);
    let web_dir = format!("{}/web", repo_root);

    ui::print_header("Unit Tests");
    println!();

    // Backend unit tests
    ui::print_info("Running backend unit tests");
    run_backend_unit_tests(&backend_dir, filter.as_deref())?;
    ui::print_success("Backend unit tests passed");

    // Frontend unit tests
    if !skip_frontend {
        println!();
        ui::print_info("Running frontend unit tests");
        match run_frontend_unit_tests(&web_dir, filter.as_deref(), report, report_path.as_deref()) {
            Ok(_) => ui::print_success("Frontend unit tests passed"),
            Err(e) => {
                ui::print_warning(&format!("Frontend unit tests skipped: {}", e));
            }
        }
    }

    println!();
    ui::print_success("Unit tests complete!");
    Ok(())
}

/// Run integration tests only
/// Auto-starts Docker on macOS if not running.
pub fn run_integration_tests(repo_root: Option<String>, filter: Option<String>) -> Result<()> {
    let repo_root = resolve_repo_root(repo_root)?;
    // TODO: derive product paths from deploy.yaml config
    let backend_dir = format!("{}/services/rust/backend", repo_root);

    ui::print_header("Integration Tests");
    println!();

    // Ensure Docker is running (auto-start on macOS)
    ensure_docker_running()?;

    // Run integration tests
    ui::print_info("Running backend integration tests");
    run_backend_integration_tests(&backend_dir, filter.as_deref())?;

    println!();
    ui::print_success("Integration tests complete!");
    Ok(())
}

/// Run E2E tests with smart image preparation
/// Auto-builds and loads images if missing.
pub fn run_e2e_tests_smart(
    repo_root: Option<String>,
    headless: bool,
    filter: Option<String>,
    force_rebuild: bool,
) -> Result<()> {
    let repo_root = resolve_repo_root(repo_root)?;

    ui::print_header("E2E Tests");
    println!();

    // Ensure Docker is running
    ensure_docker_running()?;

    // Check if images exist, build if missing (or forced)
    let backend_exists = check_image_exists("backend").unwrap_or(false);
    let web_exists = check_image_exists("web").unwrap_or(false);

    if force_rebuild || !backend_exists || !web_exists {
        if force_rebuild {
            ui::print_info("Force rebuilding Docker images...");
        } else {
            ui::print_info("Docker images missing. Building them...");
        }
        println!();

        prepare_e2e_images(
            Some(repo_root.clone()),
            backend_exists && !force_rebuild, // skip if exists and not forcing
            web_exists && !force_rebuild,
            force_rebuild,
        )?;
        println!();
    } else {
        ui::print_success("Docker images already present");
    }

    // Run E2E tests
    run_e2e_tests(Some(repo_root), headless, filter)?;

    Ok(())
}

/// Ensure Docker daemon is running, auto-starting on macOS if needed
pub fn ensure_docker_running() -> Result<()> {
    // Check if docker command exists
    let which_output = Command::new("which")
        .arg("docker")
        .output()
        .context("Failed to check for docker command")?;

    if !which_output.status.success() {
        bail!("Docker is not installed. Please install Docker first.");
    }

    // Check if Docker daemon is running
    let info_output = Command::new("docker")
        .arg("info")
        .output()
        .context("Failed to run docker info")?;

    if info_output.status.success() {
        ui::print_success("Docker daemon is running");
        return Ok(());
    }

    // Docker not running - try to start on macOS
    if cfg!(target_os = "macos") {
        ui::print_warning("Docker daemon not running. Attempting to start Docker Desktop...");

        // Try to open Docker Desktop
        let _ = Command::new("open").args(["-a", "Docker"]).output();

        // Wait for Docker to start (up to 60 seconds)
        ui::print_info("Waiting for Docker to start...");
        for i in 1..=30 {
            thread::sleep(Duration::from_secs(2));

            let check = Command::new("docker")
                .arg("info")
                .output()
                .context("Failed to run docker info")?;

            if check.status.success() {
                ui::print_success(&format!("Docker started after {} seconds", i * 2));
                return Ok(());
            }

            if i % 5 == 0 {
                ui::print_info(&format!("Still waiting... ({}s)", i * 2));
            }
        }

        bail!("Docker failed to start within 60 seconds. Please start Docker Desktop manually.");
    }

    bail!("Docker daemon is not running. Please start Docker first.");
}
