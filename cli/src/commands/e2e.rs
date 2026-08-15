//! E2E testing commands
//!
//! Provides commands for running unit, integration, and E2E tests.
//! Each test level is self-preparing:
//! - Unit: no dependencies
//! - Integration: auto-starts Docker on macOS if not running
//! - E2E: auto-builds and loads images if missing

use anyhow::{Context, Result, bail};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use crate::repo::get_tool_path;
use crate::retry::RetryPolicy;
use crate::ui;

/// Resolve the `docker` binary path via `DOCKER_BIN`, falling back to
/// `docker` on `PATH`. Wired through [`crate::repo::get_tool_path`] — the
/// canonical env-var-or-PATH lookup the sibling `commands/local.rs`
/// `docker_bin` sigil (1a984dd) resolves through. The pre-lift shape in
/// this module spelled `"docker"` bare at fourteen spawn sites
/// (`cleanup_testcontainers` ps + rm + ryuk-ps + ryuk-rm;
/// `cleanup_e2e_images` rmi + image-prune; `verify_docker` info;
/// `build_and_load_image` load; `print_image_info` images;
/// `print_failure_diagnostics` ps + ps-exited + images;
/// `ensure_docker_running` info + retry-info). Each bypassed the
/// `DOCKER_BIN` env override the substrate-`mkRuntimeToolsEnv` derivation
/// exports, so a Nix-hermetic runner's docker nixpkgs pin lost to
/// whatever `docker` was first on PATH at the E2E-image build /
/// docker-load / cleanup / diagnostics surface every `forge test`,
/// `forge e2e-run`, `forge e2e-cleanup`, and `forge e2e-prepare` step
/// trusts. Mirrors the sibling `docker_bin` sigil on
/// `commands/local.rs` (1a984dd).
fn docker_bin() -> String {
    get_tool_path("DOCKER_BIN", "docker")
}

/// Resolve the macOS `open` binary path via `OPEN_BIN`, falling back to
/// `open` on `PATH`. Wired through [`crate::repo::get_tool_path`] — the
/// canonical env-var-or-PATH lookup the sibling `docker_bin` sigil above
/// (23241a6) rides on, and the same two-arg
/// `get_tool_path("<TOOL>_BIN", "<tool>")` convention every other
/// substrate-declared tool-spawn site in forge honors (sibling `SH_BIN`
/// b382b78; `{SSH,NC,DIG}_BIN` 5e6672d; `SQLX_BIN` ecace0a;
/// `SEA_ORM_CLI_BIN` b037895; `NOVASEARCHCTL_BIN` 19463db).
///
/// The single spawn site lives in [`ensure_docker_running`], where the
/// macOS-only `cfg!(target_os = "macos")` branch invokes `open -a Docker`
/// to auto-start Docker Desktop after `docker info` fails on a macOS
/// host. Pre-lift that site spawned `open` via the bare tool-name
/// literal, bypassing `OPEN_BIN` at exactly the moment hermetic-runner
/// consistency matters most — the surface `forge test`, `forge e2e-run`,
/// `forge e2e-prepare`, and `forge integration-tests` invoke to bootstrap
/// the Docker daemon the E2E and integration tiers trust. A macOS-hosted
/// Nix-hermetic runner whose derivation exports
/// `OPEN_BIN=/nix/store/…-open/bin/open` but omits `open` from PATH
/// silently fell through to whatever `open` was first on `PATH` — or, if
/// none, the spawn's `.output()` failed and its return was discarded by
/// the `let _ = …` binding, degrading auto-start into a 60-second timeout
/// wait for a daemon that would never come up. Post-lift both branches
/// observe the same substrate-declared path every other spawn site in
/// this module observes, without an ambient-PATH intermediary.
fn open_bin() -> String {
    get_tool_path("OPEN_BIN", "open")
}

/// The typed exponential-backoff policy for [`ensure_docker_running`]'s
/// macOS Docker Desktop startup-poll cadence — `initial_backoff` 2s ×
/// `factor` 2 capped at `max_backoff` 30s. Consumes the pre-existing
/// typed primitive at [`crate::retry::RetryPolicy`] so the per-attempt
/// delay lands at [`RetryPolicy::compute_delay`], the same shared body
/// the sibling post-deployment readiness-poll surface
/// `commands/integration_tests.rs::POST_DEPLOYMENT_READINESS_POLL_BACKOFF`
/// (commit ef57ce5), the docker-compose services-healthy poll surface
/// `commands/comprehensive_release.rs::SERVICES_HEALTHY_POLL_BACKOFF`
/// (commit ad2e31e), the k8s-Job status-poll surface
/// `services/migration_service.rs::MIGRATION_JOB_POLL_BACKOFF` (commit
/// ac61874), and the health-endpoint retry surface
/// `commands/post_deploy_verification.rs::HEALTH_ENDPOINT_BACKOFF`
/// (commit b5db3b6) read through.
///
/// Pre-lift the schedule was spelled inline as a bare fixed
/// `thread::sleep(Duration::from_secs(2))` at every iteration of the
/// macOS `open -a Docker` auto-start's `docker info` poll loop. That
/// shape carried three structural defects the typed-primitive body
/// forecloses:
/// 1. **Fixed 2s schedule.** A flat `sleep(2s)` between `docker info`
///    probes is "too short when Docker Desktop is still initializing
///    (30 rapid-fire probes against a daemon that has not yet bound
///    its Unix socket — noise against an already-loaded macOS host),
///    2s too long when the daemon bound its socket 100ms ago" — the
///    exact worst-of-both failure mode the sibling
///    `POST_DEPLOYMENT_READINESS_POLL_BACKOFF` /
///    `SERVICES_HEALTHY_POLL_BACKOFF` / `MIGRATION_JOB_POLL_BACKOFF` /
///    `HEALTH_ENDPOINT_BACKOFF` docstrings cite. Post-lift, the first
///    probe still waits 2s (preserving the seed verbatim), then 4s /
///    8s / 16s / 30s / 30s / … under the exponential-with-cap climb
///    rather than the pre-lift flat 2s at every probe.
/// 2. **No caller-visible schedule invariant.** The bare
///    `Duration::from_secs(2)` literal at the poll-loop sleep carried
///    no name a shield could pin — a future edit that changed the
///    schedule at this site did not surface at any named-primitive
///    audit path. The lifted `DOCKER_STARTUP_POLL_BACKOFF` const names
///    the (seed, factor, cap) triple a shield can cite and enforce.
/// 3. **Schedule desync from the sibling readiness-poll surfaces.**
///    The macOS Docker Desktop startup-poll loop observes a workload's
///    terminal transition to "daemon accepting `docker info`" the
///    same way the sibling docker-compose services-healthy poll
///    observes container transitions to `Up (healthy)` and the sibling
///    post-deployment readiness poll observes `/health` transitions to
///    200. Pre-lift each spelled its own local fixed-sleep schedule,
///    so a future edit to one silently diverged from the others.
///    Post-lift all consume the same shared body via the same
///    `RetryPolicy::network()` `(factor=2, max_backoff=30s)` reference
///    schedule.
///
/// `max_attempts: u32::MAX` is a placeholder — the poll loop is bounded
/// by wall-clock via [`DOCKER_STARTUP_MAX_WAIT`], not by attempt count
/// — and consumes only [`RetryPolicy::compute_delay`] from this policy,
/// not [`RetryPolicy::max_attempts`]. The `max_attempts` field is
/// unconsulted at this consumption site.
const DOCKER_STARTUP_POLL_BACKOFF: RetryPolicy = RetryPolicy {
    max_attempts: u32::MAX,
    initial_backoff: Duration::from_secs(2),
    factor: 2,
    max_backoff: Duration::from_secs(30),
};

/// Wall-clock deadline for [`ensure_docker_running`]'s Docker Desktop
/// startup poll — preserves the pre-lift 60-second bound the fixed-
/// iteration `for i in 1..=30 { thread::sleep(Duration::from_secs(2)); }`
/// shape provided (30 iterations × 2s = 60s). Post-lift the loop is
/// wall-clock-bounded via `start.elapsed() >= DOCKER_STARTUP_MAX_WAIT`
/// rather than iteration-count-bounded, so the exponential-with-cap
/// climb at [`DOCKER_STARTUP_POLL_BACKOFF`] can pace the probes
/// (2s → 4s → 8s → 16s → 30s → 30s → …) without exceeding the same
/// 60-second budget the pre-lift shape declared in its error message.
const DOCKER_STARTUP_MAX_WAIT: Duration = Duration::from_secs(60);

/// Backoff between `docker info` probes in [`ensure_docker_running`]'s
/// macOS auto-start loop, given a 0-indexed local `backoff_attempt`
/// counter (the `loop { thread::sleep(...); backoff_attempt += 1; ... }`
/// shape drives one increment per iteration).
///
/// Maps the local 0-indexed counter to the 1-indexed
/// [`RetryPolicy::compute_delay`] attempt axis via `saturating_add(2)`:
/// local `backoff_attempt == 0` (the first between-probe sleep after
/// the `open -a Docker` spawn) reads as `compute_delay(2) =
/// initial_backoff * factor^0 = initial_backoff = 2s`; local
/// `backoff_attempt == 1` reads as `compute_delay(3) = 4s`;
/// `backoff_attempt == 2` reads as `compute_delay(4) = 8s`;
/// `backoff_attempt == 3` reads as `compute_delay(5) = 16s`;
/// `backoff_attempt >= 4` reads as `compute_delay(>=6) = 30s` (cap) —
/// preserves the pre-lift `thread::sleep(Duration::from_secs(2))` seed
/// verbatim at the first probe and strictly diverges upward at every
/// later probe.
///
/// The `saturating_add` clamp forecloses the `u32` overflow class at
/// the bridge — a pathologically-fast poll-arm (a stub `docker` that
/// returns instantly against a daemon that never comes up) that
/// exhausts `u32` iterations reads as `compute_delay(u32::MAX)`, which
/// itself saturates to [`DOCKER_STARTUP_POLL_BACKOFF::max_backoff`]
/// via the `checked_pow`-then-cap body inside
/// [`RetryPolicy::compute_delay`] without panic.
fn docker_startup_poll_delay(backoff_attempt: u32) -> Duration {
    DOCKER_STARTUP_POLL_BACKOFF.compute_delay(backoff_attempt.saturating_add(2))
}

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

    let cargo = get_tool_path("CARGO", "cargo");
    let mut cmd = Command::new(&cargo);
    cmd.current_dir(backend_dir).arg("test").arg("--lib");

    if let Some(f) = filter {
        cmd.arg(f);
    }

    let start = Instant::now();
    let status = cmd.status().context("Failed to run cargo test")?;
    let elapsed = start.elapsed();

    ui::print_info(&format!(
        "Backend unit tests completed in {:.1}s",
        elapsed.as_secs_f64()
    ));

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
        ui::print_info(&format!(
            "Frontend tests completed in {:.1}s",
            elapsed.as_secs_f64()
        ));
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

        ui::print_info(&format!(
            "Frontend unit tests completed in {:.1}s",
            elapsed.as_secs_f64()
        ));

        if !status.success() {
            bail!(
                "Frontend unit tests failed (exit code: {:?})",
                status.code()
            );
        }
    }

    Ok(())
}

/// Run backend integration tests
fn run_backend_integration_tests(backend_dir: &str, filter: Option<&str>) -> Result<()> {
    let mut args = vec![
        "test",
        "--test",
        "integration_tests",
        "--features",
        "integration-tests",
    ];
    if let Some(f) = filter {
        args.push("--");
        args.push(f);
    }

    ui::print_info(&format!("Running cargo {}", args.join(" ")));

    let start = Instant::now();
    let cargo = get_tool_path("CARGO", "cargo");
    let status = Command::new(&cargo)
        .current_dir(backend_dir)
        .args(&args)
        .status()
        .context("Failed to run integration tests")?;
    let elapsed = start.elapsed();

    ui::print_info(&format!(
        "Integration tests completed in {:.1}s",
        elapsed.as_secs_f64()
    ));

    if !status.success() {
        bail!(
            "Backend integration tests failed (exit code: {:?})",
            status.code()
        );
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

    let cargo = get_tool_path("CARGO", "cargo");
    let mut cmd = Command::new(&cargo);
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
    ui::print_info(&format!(
        "E2E tests completed in {:.1}s",
        elapsed.as_secs_f64()
    ));

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
    let output = Command::new(docker_bin())
        .args(["ps", "-q", "--filter", "label=org.testcontainers=true"])
        .output()
        .context("Failed to list testcontainers")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let container_ids: Vec<&str> = stdout.trim().lines().filter(|l| !l.is_empty()).collect();

    let tc_count = container_ids.len();

    if !container_ids.is_empty() {
        let ids: Vec<String> = container_ids.iter().map(|s| s.to_string()).collect();
        let mut args = vec!["rm", "-f"];
        for id in &ids {
            args.push(id);
        }
        let _ = Command::new(docker_bin()).args(&args).output();
    }

    // Kill Ryuk sidecars (may not have the label)
    let ryuk_output = Command::new(docker_bin())
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
        let _ = Command::new(docker_bin()).args(&args).output();
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
            let status = Command::new(docker_bin())
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
    let _ = Command::new(docker_bin())
        .args([
            "image",
            "prune",
            "-f",
            "--filter",
            "label=org.testcontainers=true",
        ])
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

    // Binary resolution rides `crate::git::git_command_sync()` so a
    // Nix-hermetic runner's `GIT_BIN` override wins over ambient
    // `PATH` at repo-root discovery time — same discipline the
    // sibling `commands/helm.rs::deploy` (0d922f6) and
    // `config::resolve_k8s_repo_root` (0a36ba0) sync sites honor and
    // the async `commands/push.rs` / `commands/rollback.rs` /
    // `commands/codegen_validation.rs` / `commands/federation.rs`
    // sites drive through `git_command_async`. Retains the
    // pre-migration `.output()`-then-`current_dir` fallback shape:
    // this discovery path is advisory and callers fall back to the
    // current directory on any non-success exit.
    let output = crate::git::git_command_sync()
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

    // Check if docker command exists via the in-process `which` crate rather
    // than a `which`-binary subprocess spawn. Mirrors the sibling
    // `check_novasearchctl_available` / `check_sea_orm_cli_available` lifts
    // (a46d580) — no ambient dependency on a `which` binary existing on PATH.
    if which::which("docker").is_err() {
        bail!("Docker is not installed. Please install Docker first.");
    }

    // Check if Docker daemon is running
    let info_output = Command::new(docker_bin())
        .arg("info")
        .output()
        .context("Failed to run docker info")?;

    if !info_output.status.success() {
        bail!("Docker daemon is not running. Please start Docker first.");
    }

    ui::print_success("Docker daemon is running");
    Ok(())
}

/// Check if a Docker image exists locally.
///
/// Delegates to the canonical
/// [`crate::infrastructure::docker::find_first_image_id_by_name`]
/// primitive — sibling of `product_release.rs::check_local_image_exists`
/// (async) and `product_release.rs::push_prebuilt_image`'s inline
/// image-id fetch. All three pre-lift sites spelled the same
/// `docker images -q <name>` + trim + `is_empty` body verbatim
/// (THEORY §VI.1 three-is-a-law); the typed primitive consolidates
/// them onto one shape. Spawn failure now collapses to `Ok(false)`
/// (matches every caller's `.unwrap_or(false)` immediate-recovery
/// pattern).
fn check_image_exists(image_name: &str) -> Result<bool> {
    Ok(crate::infrastructure::docker::find_first_image_id_by_name(image_name).is_some())
}

/// Build a Nix image and load it into Docker
fn build_and_load_image(repo_root: &str, name: &str, flake_attr: &str) -> Result<()> {
    let output_path = format!("/tmp/{}-image", name);

    // Build with Nix
    ui::print_info(&format!("Building {} image via Nix", name));
    let build_status = Command::new(get_tool_path("NIX_BIN", "nix"))
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

    let mut docker_load = Command::new(docker_bin())
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

    let output = Command::new(docker_bin())
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
    if let Ok(output) = Command::new(docker_bin())
        .args(["ps", "--format", "  {{.Names}}\t{{.Status}}\t{{.Ports}}"])
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
    if let Ok(output) = Command::new(docker_bin())
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
    if let Ok(output) = Command::new(docker_bin())
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
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "png")
                    .unwrap_or(false)
            })
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
    // Check if docker command exists via the in-process `which` crate rather
    // than a `which`-binary subprocess spawn. Mirrors the sibling
    // `check_novasearchctl_available` / `check_sea_orm_cli_available` lifts
    // (a46d580) — no ambient dependency on a `which` binary existing on PATH.
    if which::which("docker").is_err() {
        bail!("Docker is not installed. Please install Docker first.");
    }

    // Check if Docker daemon is running
    let info_output = Command::new(docker_bin())
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
        let _ = Command::new(open_bin()).args(["-a", "Docker"]).output();

        // Wait for Docker to start (up to DOCKER_STARTUP_MAX_WAIT)
        ui::print_info("Waiting for Docker to start...");
        let start = Instant::now();
        let mut backoff_attempt: u32 = 0;
        let mut last_report = start;
        loop {
            thread::sleep(docker_startup_poll_delay(backoff_attempt));
            backoff_attempt = backoff_attempt.saturating_add(1);

            let check = Command::new(docker_bin())
                .arg("info")
                .output()
                .context("Failed to run docker info")?;

            let elapsed = start.elapsed();
            if check.status.success() {
                ui::print_success(&format!("Docker started after {}s", elapsed.as_secs()));
                return Ok(());
            }

            if elapsed >= DOCKER_STARTUP_MAX_WAIT {
                break;
            }

            if last_report.elapsed() >= Duration::from_secs(10) {
                ui::print_info(&format!("Still waiting... ({}s)", elapsed.as_secs()));
                last_report = Instant::now();
            }
        }

        bail!(
            "Docker failed to start within {}s. Please start Docker Desktop manually.",
            DOCKER_STARTUP_MAX_WAIT.as_secs()
        );
    }

    bail!("Docker daemon is not running. Please start Docker first.");
}

#[cfg(test)]
mod resolve_repo_root_git_bin_routing_tests {
    /// Regression-shield: the git-discovery spawn in
    /// [`super::resolve_repo_root`] MUST resolve `git` through
    /// [`crate::git::git_command_sync`] rather than the pre-lift
    /// `std::process::Command::new("git")` literal. Pre-migration the
    /// single site bypassed the `GIT_BIN` env override the
    /// `tools::get_tool_path(tools::GIT)` idiom
    /// (cli/src/tools.rs:102-105) resolves — the same class of bug
    /// the sibling `flux` / `cargo` / `doca` / free-function-`git` /
    /// `GitClient` / `commands/federation.rs` / `commands/push.rs` /
    /// `commands/codegen_validation.rs` / `commands/rollback.rs` /
    /// `commands/helm.rs::deploy` / `config::resolve_k8s_repo_root`
    /// migrations redeemed at 621f827 / f0dfa12 / d3dd199 / 685642f /
    /// d6f6bc7 / dd5a212 / 673e4be / b02d4eb / 54a9985 / 139b37a /
    /// 818ed9a / badcdf4 / 8653403 / f6be190 / 81d7486 / 8a1958e /
    /// 0d922f6 / 0a36ba0. Lifts the sync half of the routing
    /// discipline onto the third sync consumer of
    /// `git_command_sync` — first was `helm::deploy` at 0d922f6,
    /// second was `config::resolve_k8s_repo_root` at 0a36ba0.
    ///
    /// This test reads this module's own source via [`include_str!`]
    /// and asserts the raw `Command::new("git")` string does not
    /// reappear in `resolve_repo_root` while the delegation to
    /// `git_command_sync` does. A future regression that re-fuses
    /// the raw-spawn body fails here, not silently in production
    /// where a Nix-hermetic runner's `GIT_BIN`-provided `git` would
    /// lose to whatever `git` is first on `PATH` at repo-root
    /// discovery time.
    ///
    /// The check is deliberately structural (substring on the source
    /// text) rather than behavioral — the end-to-end `GIT_BIN`-
    /// routing invariant is already pinned by
    /// [`crate::git::tests::test_git_command_sync_routes_through_git_bin_env_var`]
    /// on the primitive itself; this shield only certifies that the
    /// `resolve_repo_root` git spawn reads through that primitive.
    /// Mirrors the sibling shield on `config::resolve_k8s_repo_root`
    /// and `commands/helm.rs::deploy` for the sync half of the
    /// surface.
    #[test]
    fn test_resolve_repo_root_routes_git_through_git_command_sync_not_raw_command() {
        const SOURCE: &str = include_str!("e2e.rs");

        // Bound the scan to `resolve_repo_root` — the single git
        // spawn site lives inside it. Docstrings and sibling
        // functions in this module legitimately reference the
        // pre-migration literal, so scoping the check to the target
        // function's body avoids false positives.
        let fn_marker = "fn resolve_repo_root(";
        let start = SOURCE
            .find(fn_marker)
            .expect("commands/e2e.rs must contain `fn resolve_repo_root(` — module invariant");
        let after_fn = &SOURCE[start..];
        // Bound at the next top-level `fn verify_docker(` in source
        // order, which follows `resolve_repo_root`.
        let end_relative = after_fn
            .find("\nfn verify_docker(")
            .expect("commands/e2e.rs must contain `fn verify_docker(` after `resolve_repo_root`");
        let fn_body = &after_fn[..end_relative];

        assert!(
            !fn_body.contains("Command::new(\"git\")"),
            "resolve_repo_root() must NOT spawn `git` directly — \
             route through `crate::git::git_command_sync()` so \
             `GIT_BIN` overrides land at the shared primitive. Found \
             the pre-migration spawn body in resolve_repo_root()."
        );
        assert!(
            fn_body.contains("crate::git::git_command_sync()"),
            "resolve_repo_root() must delegate the git spawn to \
             `crate::git::git_command_sync()` — the delegation string \
             was not found in resolve_repo_root()."
        );
    }
}

#[cfg(test)]
mod nix_bin_routing_tests {
    /// Whole-module shield: no raw `Command::new("nix")` may live in
    /// `commands/e2e.rs`'s non-test body. Every `nix` spawn in this
    /// module must first resolve `NIX_BIN` via
    /// [`crate::repo::get_tool_path`] — the canonical env-var override
    /// every other nix-invocation site in forge honors
    /// (`commands/build.rs::execute` d8ef0d5,
    /// `commands/tool.rs::build_lock_target`,
    /// `commands/developer_tools.rs::rust_update_cargo_nix` and
    /// siblings 4dfb2b3, `commands/rust_service.rs`'s three nix spawn
    /// sites 7c34e57,
    /// `commands/product_release.rs::run_nix_release_app` d0cd622,
    /// `commands/nix_builder.rs::test`'s remote-build probe d930a5d,
    /// `nix.rs::build_flake_attr_in` / `build_docker_image_from_dir`
    /// / `path_info_recursive`, and
    /// `nix_hooks.rs::NixHooks::build_and_get_path`).
    ///
    /// Pre-lift this module carried one real `nix` spawn site:
    /// `build_and_load_image`'s `nix build <flake_attr> -o <path>` at
    /// line 660 — the E2E-image build step that `forge e2e run` (and
    /// the auto-build fallback inside `run_test_pyramid`'s E2E phase)
    /// invokes to materialize the backend/web container images that
    /// docker-load into the test daemon. The spawn spelled
    /// `Command::new("nix")` verbatim, bypassing `NIX_BIN` at exactly
    /// the moment hermetic-runner consistency matters most — the
    /// step that produces the very images the E2E tier will exercise.
    /// A Nix-hermetic runner with a store-path `nix` binary silently
    /// fell through to whatever `nix` was first on `PATH` at this
    /// site, diverging from every other nix-invocation surface in
    /// forge and from the sibling KUBECTL_BIN / GIT_BIN / CARGO /
    /// DOCKER_BIN / HELM_BIN frontier's uniform discipline.
    ///
    /// The scan bounds on the whole-module boundary (from the file
    /// start to the FIRST `\n#[cfg(test)]\n` marker in source order,
    /// which lands at the sibling `resolve_repo_root_git_bin_routing_tests`
    /// block above) so this shield's own docstring mentions of
    /// `Command::new("nix")` — living in a `#[cfg(test)]` block below
    /// that first marker — stay out of scope AND every current or
    /// future nix-spawning helper landing anywhere in the top-level
    /// module body cannot silently ride along without going through
    /// `NIX_BIN`. Mirrors the sibling whole-module shields on
    /// `commands/build.rs::test_execute_routes_nix_through_nix_bin_not_raw_command`
    /// (d8ef0d5),
    /// `commands/developer_tools.rs::test_developer_tools_routes_nix_through_nix_bin_not_raw_command`
    /// (4dfb2b3),
    /// `commands/rust_service.rs::test_rust_service_routes_nix_through_nix_bin_not_raw_command`
    /// (7c34e57), and
    /// `commands/nix_builder.rs::test_nix_builder_routes_nix_through_nix_bin_not_raw_command`
    /// (d930a5d) — the whole-module-boundary scan discipline
    /// pioneered on `commands/supergraph_verification.rs` (65283fb).
    #[test]
    fn test_e2e_routes_nix_through_nix_bin_not_raw_command() {
        const SOURCE: &str = include_str!("e2e.rs");
        let cutoff = SOURCE.find("\n#[cfg(test)]\n").expect(
            "e2e.rs must have a `#[cfg(test)]` marker — \
             the shield's scan boundary depends on it",
        );
        let body = &SOURCE[..cutoff];
        assert!(
            !body.contains("Command::new(\"nix\")"),
            "commands/e2e.rs must not spawn `nix` via the bare \
             literal — every `nix` spawn must resolve `NIX_BIN` via \
             `crate::repo::get_tool_path(\"NIX_BIN\", \"nix\")` first. \
             A raw `Command::new(\"nix\")` bypasses the hermetic-runner \
             contract substrate's mkRuntimeToolsEnv exports."
        );
        assert!(
            body.contains("get_tool_path(\"NIX_BIN\", \"nix\")"),
            "commands/e2e.rs must resolve the nix binary via \
             `get_tool_path(\"NIX_BIN\", \"nix\")` — the canonical \
             lookup was not found in the module body."
        );
    }
}

#[cfg(test)]
mod docker_bin_routing_tests {
    /// Whole-module shield: no raw `Command::new("docker")` may live in
    /// `commands/e2e.rs`'s non-test body. Every `docker` spawn in this
    /// module must first resolve `DOCKER_BIN` via [`super::docker_bin`],
    /// which delegates to [`crate::repo::get_tool_path`] — the canonical
    /// env-var override every other docker-invocation site in forge
    /// honors (`commands/local.rs` five spawns 1a984dd,
    /// `infrastructure/docker.rs::find_first_image_id_by_name` /
    /// `..._async`).
    ///
    /// Pre-lift this module carried fourteen real `docker` spawn sites:
    /// `cleanup_testcontainers` `docker ps` + `docker rm -f` (testcontainer
    /// class); `cleanup_testcontainers` ryuk-sidecar `docker ps` +
    /// `docker rm -f`; `cleanup_e2e_images` `docker rmi -f <image>` +
    /// `docker image prune -f`; `verify_docker` `docker info`;
    /// `build_and_load_image` piped `docker load`; `print_image_info`
    /// `docker images --format`; `print_failure_diagnostics` `docker ps`
    /// (running) + `docker ps -a --status=exited --since=15m` +
    /// `docker images` (E2E-image slice); `ensure_docker_running`
    /// `docker info` and its retry-poll `docker info`. Every one of
    /// those spawns spelled `Command::new("docker")` verbatim,
    /// bypassing `DOCKER_BIN` at exactly the moment hermetic-runner
    /// consistency matters most — the surface `forge test`, `forge
    /// e2e-run`, `forge e2e-prepare`, and `forge e2e-cleanup` invoke to
    /// build, load, run, tear down, and diagnose the very containers
    /// the E2E tier trusts. A Nix-hermetic runner with a store-path
    /// `docker` binary silently fell through to whatever `docker` was
    /// first on `PATH` at each site, diverging from every other
    /// docker-invocation surface in forge and from the sibling
    /// KUBECTL_BIN / GIT_BIN / CARGO / NIX_BIN / HELM_BIN frontier's
    /// uniform discipline.
    ///
    /// The scan bounds on the whole-module boundary (from the file
    /// start to the FIRST `\n#[cfg(test)]\n` marker in source order,
    /// which lands at the sibling `resolve_repo_root_git_bin_routing_tests`
    /// block near the end of the module body) so this shield's own
    /// docstring mentions of `Command::new("docker")` — living in a
    /// `#[cfg(test)]` block below that first marker — stay out of scope
    /// AND every current or future docker-spawning helper landing
    /// anywhere in the top-level module body cannot silently ride
    /// along without going through `docker_bin()`. Mirrors the sibling
    /// whole-module shields on `commands/local.rs` (1a984dd),
    /// `commands/migrations.rs` (946e573), `commands/crossplane.rs`
    /// (ee50c0e), `commands/status.rs` (c2760df), `commands/flux.rs`
    /// (f8da719), and this same module's `nix_bin_routing_tests`
    /// sibling above — the whole-module-boundary scan discipline
    /// pioneered on `commands/supergraph_verification.rs` (65283fb).
    #[test]
    fn test_e2e_routes_docker_through_docker_bin_not_raw_command() {
        const SOURCE: &str = include_str!("e2e.rs");
        let cutoff = SOURCE.find("\n#[cfg(test)]\n").expect(
            "e2e.rs must have a `#[cfg(test)]` marker — \
             the shield's scan boundary depends on it",
        );
        let body = &SOURCE[..cutoff];
        assert!(
            !body.contains("Command::new(\"docker\")"),
            "commands/e2e.rs must not spawn `docker` via the bare \
             literal — every `docker` spawn must resolve `DOCKER_BIN` \
             via `docker_bin()` first. A raw `Command::new(\"docker\")` \
             bypasses the hermetic-runner contract substrate's \
             mkRuntimeToolsEnv exports."
        );
        assert!(
            body.contains("Command::new(docker_bin())"),
            "commands/e2e.rs must resolve the docker binary via \
             `Command::new(docker_bin())` — the canonical delegation \
             was not found in the module body."
        );
        assert!(
            body.contains("fn docker_bin()"),
            "commands/e2e.rs must define the `docker_bin` sigil — the \
             one bridge between this module's docker spawns and the \
             substrate-exported `DOCKER_BIN` env override."
        );
    }
}

#[cfg(test)]
mod which_probe_routing_tests {
    /// Whole-module shield: no bare `which`-binary spawn (a raw
    /// `Command::new` on the bare tool-name literal) may live in
    /// `commands/e2e.rs`. The two sync PATH-probe sites — `verify_docker`
    /// and `ensure_docker_running`, both checking for the `docker`
    /// binary before invoking the daemon — must resolve through the
    /// in-process `which::which(...)` crate idiom, the same shape the
    /// sibling probes in `commands/test_ci.rs` (`cargo-nextest`,
    /// `cargo-tarpaulin`), `commands/rust_service.rs`
    /// (`qemu-aarch64-static`), `commands/tool.rs` (`crate2nix`),
    /// `commands/search_sync.rs` (`novasearchctl`, a46d580), and
    /// `commands/sync.rs` (`sea-orm-cli`, a46d580) already ride on.
    ///
    /// Pre-lift both sites spawned a `which` subprocess via the bare
    /// tool-name literal — a fork+exec that added an ambient dependency
    /// on a `which` binary existing on PATH itself. On a minimal Nix
    /// container whose derivation only exports the specific tool paths
    /// declared, the `which` binary is absent and the spawn
    /// fails-to-exec entirely, so the probe silently reports "not
    /// installed" for that reason alone — the exact same silent-false
    /// failure mode the sibling `DOCKER_BIN` fast-path at `docker_bin()`
    /// (23241a6) was written to close for its spawn surface, only one
    /// layer of ambient dependency deeper. Post-lift the probes resolve
    /// PATH in-process via the `which` crate; no fork+exec, no ambient
    /// binary, no silent-false. Closes the last two `Command::new`-on-
    /// `which` sites in forge — the sync half of the a46d580 lift.
    ///
    /// The forbidden shape is reconstructed at test time via [`format!`]
    /// so this shield's own source text does not false-match itself,
    /// and the docstring above uses `which`-binary paraphrase rather
    /// than the literal shape for the same reason; the whole-module
    /// scan therefore covers both the top-of-file production body AND
    /// every sibling `#[cfg(test)]` block. Also asserts the canonical
    /// `which::which("docker")` crate idiom is present in the module,
    /// so the sigil-body itself cannot silently drift back to a
    /// subprocess spawn.
    #[test]
    fn test_which_probes_route_through_which_crate_not_command_spawn() {
        const SOURCE: &str = include_str!("e2e.rs");

        crate::test_support::assert_source_forbids_bare_spawn_shapes(
            SOURCE,
            "commands/e2e.rs",
            "which",
            "resolve through the in-process `which::which(...)` crate idiom",
        );
        crate::test_support::assert_source_probes_via_which_which_code_line(
            SOURCE,
            "commands/e2e.rs",
            "docker",
        );
    }
}

#[cfg(test)]
mod cargo_env_routing_tests {
    /// Whole-module shield: no raw `Command::new("cargo")` may live in
    /// `commands/e2e.rs`'s non-test body. Every `cargo` spawn in this
    /// module must first resolve `CARGO` via
    /// [`crate::repo::get_tool_path`] — the canonical env-var override
    /// every other cargo-invocation site in forge honors
    /// (`commands/test.rs`'s two `run_rust_tests` spawns 4ea5076,
    /// `commands/test_ci.rs`'s four spawns e1677d3,
    /// `commands/tool.rs`'s five `cargo`/`crate2nix` spawns 79e03a5,
    /// `commands/comprehensive_release.rs`'s two spawns f95d541,
    /// `commands/prerelease.rs`'s seven spawns cfdba0d).
    ///
    /// Pre-lift this module carried three real `cargo` spawn sites in
    /// the test-pyramid orchestration surface: `run_backend_unit_tests`'
    /// `cargo test --lib` at line 182; `run_backend_integration_tests`'
    /// `cargo test --test integration_tests --features integration-tests`
    /// at line 308; and `run_e2e_tests`' `cargo test --test e2e_tests
    /// --features integration-tests -- --include-ignored` at line 442.
    /// Each spawn spelled `Command::new("cargo")` verbatim, bypassing
    /// `CARGO` at exactly the moment hermetic-runner consistency matters
    /// most — the surface `forge test-pyramid`, `forge e2e-run`, and the
    /// pyramid's Unit / Integration / E2E phases invoke to build and run
    /// the very test binaries the pyramid trusts. A Nix-hermetic runner
    /// with a store-path `cargo` binary silently fell through to whatever
    /// `cargo` was first on `PATH` at each site, diverging from every
    /// other cargo-invocation surface in forge and from the sibling
    /// KUBECTL_BIN / GIT_BIN / NIX_BIN / DOCKER_BIN / HELM_BIN frontier's
    /// uniform discipline.
    ///
    /// The scan bounds on the whole-module boundary (from the file start
    /// to the FIRST `\n#[cfg(test)]\n` marker in source order, which
    /// lands at the sibling `resolve_repo_root_git_bin_routing_tests`
    /// block near the end of the module body) so this shield's own
    /// docstring mentions of `Command::new("cargo")` — living in a
    /// `#[cfg(test)]` block below that first marker — stay out of scope
    /// AND every current or future cargo-spawning helper landing anywhere
    /// in the top-level module body cannot silently ride along without
    /// going through `get_tool_path("CARGO", "cargo")`. Mirrors the
    /// sibling whole-module shields on `commands/test.rs` (4ea5076),
    /// `commands/test_ci.rs` (e1677d3), and `commands/tool.rs` (79e03a5)
    /// — the whole-module-boundary scan discipline pioneered on
    /// `commands/supergraph_verification.rs` (65283fb).
    #[test]
    fn test_e2e_routes_cargo_through_cargo_env_not_raw_command() {
        const SOURCE: &str = include_str!("e2e.rs");
        let cutoff = SOURCE.find("\n#[cfg(test)]\n").expect(
            "e2e.rs must have a `#[cfg(test)]` marker — \
             the shield's scan boundary depends on it",
        );
        let body = &SOURCE[..cutoff];
        assert!(
            !body.contains("Command::new(\"cargo\")"),
            "commands/e2e.rs must not spawn `cargo` via the bare \
             literal — every `cargo` spawn must resolve `CARGO` via \
             `crate::repo::get_tool_path(\"CARGO\", \"cargo\")` first. \
             A raw `Command::new(\"cargo\")` bypasses the hermetic-runner \
             contract substrate's mkRuntimeToolsEnv exports."
        );
        assert!(
            body.contains("get_tool_path(\"CARGO\", \"cargo\")"),
            "commands/e2e.rs must resolve the cargo binary via \
             `get_tool_path(\"CARGO\", \"cargo\")` — the canonical \
             lookup was not found in the module body."
        );
    }
}

#[cfg(test)]
mod open_bin_routing_tests {
    /// Whole-module shield: no raw `Command::new("open")` may live in
    /// `commands/e2e.rs`'s non-test body. The single macOS `open`-binary
    /// spawn site — [`super::ensure_docker_running`]'s Docker Desktop
    /// auto-start call under `cfg!(target_os = "macos")` — must resolve
    /// through [`super::open_bin`], which delegates to
    /// [`crate::repo::get_tool_path`] — the two-arg env-var override
    /// every sibling probe/spawn surface in forge honors (this module's
    /// own `docker_bin` sigil 23241a6; `SH_BIN` two-arg lift b382b78;
    /// `{SSH,NC,DIG}_BIN` 5e6672d; `SQLX_BIN` ecace0a;
    /// `SEA_ORM_CLI_BIN` b037895; `NOVASEARCHCTL_BIN` 19463db).
    ///
    /// Pre-lift the site spelled `Command::new("open")` verbatim,
    /// bypassing `OPEN_BIN` at exactly the surface `forge test`,
    /// `forge e2e-run`, `forge e2e-prepare`, and `forge
    /// integration-tests` all invoke on macOS hosts to bootstrap the
    /// Docker daemon the E2E and integration tiers trust. A macOS-hosted
    /// Nix-hermetic runner whose derivation exports
    /// `OPEN_BIN=/nix/store/…-open/bin/open` but omits `open` from PATH
    /// silently fell through to whatever `open` was first on PATH — or,
    /// if none, the spawn's `.output()` failed and its return was
    /// discarded by the `let _ = …` binding, degrading auto-start into a
    /// 60-second wait for a daemon that would never come up. The same
    /// silent-PATH-fallback bug class the sibling `docker_bin` shield
    /// closes for the docker-invocation surface, here closed for the
    /// macOS auto-start surface.
    ///
    /// Scan bounds on the whole-module boundary — from the file start to
    /// the FIRST `\n#[cfg(test)]\n` marker in source order (which lands
    /// at the sibling `resolve_repo_root_git_bin_routing_tests` block
    /// near the end of the module body) — so this shield's own docstring
    /// mentions of the forbidden literal, living in a `#[cfg(test)]`
    /// block below that first marker, stay out of scope AND every
    /// current or future `open`-spawning helper landing anywhere in the
    /// top-level module body cannot silently ride along without going
    /// through `open_bin()`. The forbidden shape is reconstructed at
    /// test time via [`format!`] from the bare string `"open"` so this
    /// shield's own source text does not false-match itself. Also
    /// asserts the canonical `Command::new(open_bin())` delegation and
    /// the `fn open_bin()` sigil are present, so a regression that
    /// removed the sigil would surface with a diagnostic pointing at
    /// the missing constructor rather than at a compile error at the
    /// call site.
    #[test]
    fn test_e2e_routes_open_through_open_bin_not_raw_command() {
        const SOURCE: &str = include_str!("e2e.rs");
        let cutoff = SOURCE.find("\n#[cfg(test)]\n").expect(
            "e2e.rs must have a `#[cfg(test)]` marker — \
             the shield's scan boundary depends on it",
        );
        let body = &SOURCE[..cutoff];
        crate::test_support::assert_source_forbids_bare_spawn_shapes(
            body,
            "commands/e2e.rs",
            "open",
            "resolve `OPEN_BIN` via `open_bin()`",
        );
        assert!(
            body.contains("Command::new(open_bin())"),
            "commands/e2e.rs must resolve the open binary via \
             `Command::new(open_bin())` — the canonical delegation was \
             not found in the module body."
        );
        assert!(
            body.contains("fn open_bin()"),
            "commands/e2e.rs must define the `open_bin` sigil — the one \
             bridge between this module's `open` spawn and the \
             substrate-exported `OPEN_BIN` env override."
        );
    }
}

#[cfg(test)]
mod docker_startup_poll_backoff_tests {
    use super::*;

    /// The `(initial_backoff, factor, max_backoff)` shape of the Docker
    /// Desktop startup-poll backoff policy is a load-bearing invariant
    /// shared with the sibling readiness-poll surfaces at
    /// `commands/integration_tests.rs::POST_DEPLOYMENT_READINESS_POLL_BACKOFF`
    /// (ef57ce5), `commands/comprehensive_release.rs::
    /// SERVICES_HEALTHY_POLL_BACKOFF` (ad2e31e), and
    /// `services/migration_service.rs::MIGRATION_JOB_POLL_BACKOFF`
    /// (ac61874) — all four policies consume the same
    /// `RetryPolicy::network()` `(factor=2, max_backoff=30s)` reference
    /// schedule and the same 2s seed. Pinned here so a future silent-
    /// desync at the const site (a factor bump, a cap change, a seed
    /// drift) is caught at a named test rather than silently across the
    /// two consumption sites (`docker_startup_poll_delay` + the loop
    /// body).
    #[test]
    fn test_docker_startup_poll_backoff_policy_shape() {
        assert_eq!(
            DOCKER_STARTUP_POLL_BACKOFF.initial_backoff,
            Duration::from_secs(2),
            "DOCKER_STARTUP_POLL_BACKOFF.initial_backoff must be 2s \
             — preserves the pre-lift bare `thread::sleep(Duration::\
             from_secs(2))` seed verbatim at the poll loop's first \
             sleep.",
        );
        assert_eq!(
            DOCKER_STARTUP_POLL_BACKOFF.factor, 2,
            "DOCKER_STARTUP_POLL_BACKOFF.factor must be 2 \
             — the Bazel/Buck2/SLSA-frontier reference doubling climb \
             the sibling `RetryPolicy::network()` factory also emits.",
        );
        assert_eq!(
            DOCKER_STARTUP_POLL_BACKOFF.max_backoff,
            Duration::from_secs(30),
            "DOCKER_STARTUP_POLL_BACKOFF.max_backoff must be 30s \
             — the Bazel/Buck2/SLSA-frontier 30s cap the sibling \
             `RetryPolicy::network()` factory also emits.",
        );
    }

    /// The wall-clock deadline preserves the pre-lift 60-second bound
    /// the fixed-iteration `for i in 1..=30 { thread::sleep(2s); }`
    /// shape provided (30 iterations × 2s = 60s), pinned as a named
    /// const so a future edit that changes the budget at
    /// `ensure_docker_running` surfaces here rather than silently at
    /// the loop body.
    #[test]
    fn test_docker_startup_max_wait_preserves_pre_lift_bound() {
        assert_eq!(
            DOCKER_STARTUP_MAX_WAIT,
            Duration::from_secs(60),
            "DOCKER_STARTUP_MAX_WAIT must be 60s — preserves the \
             pre-lift `for i in 1..=30 {{ thread::sleep(Duration::\
             from_secs(2)); }}` shape's 30 iterations × 2s = 60s \
             wall-clock budget the bail! diagnostic named.",
        );
    }

    /// The first probe preserves the pre-lift seed verbatim
    /// (`backoff_attempt == 0` → `compute_delay(2) = initial_backoff =
    /// 2s`); every later probe strictly diverges upward under the
    /// exponential-with-cap climb (`4s → 8s → 16s → 30s → …`) rather
    /// than re-emitting the pre-lift `2s` flat.
    #[test]
    fn test_docker_startup_poll_delay_matches_pre_lift_seed_and_climbs_at_in_cap_attempts() {
        assert_eq!(
            docker_startup_poll_delay(0),
            Duration::from_secs(2),
            "backoff_attempt=0 must sleep 2s — matches pre-lift \
             `thread::sleep(Duration::from_secs(2))` seed verbatim.",
        );
        assert_eq!(
            docker_startup_poll_delay(1),
            Duration::from_secs(4),
            "backoff_attempt=1 must sleep 4s — pre-lift stayed flat \
             at 2s; post-lift climbs `initial_backoff * factor = 4s`.",
        );
        assert_eq!(
            docker_startup_poll_delay(2),
            Duration::from_secs(8),
            "backoff_attempt=2 must sleep 8s — pre-lift stayed flat \
             at 2s; post-lift climbs `initial_backoff * factor^2 = 8s`.",
        );
        assert_eq!(
            docker_startup_poll_delay(3),
            Duration::from_secs(16),
            "backoff_attempt=3 must sleep 16s — pre-lift stayed flat \
             at 2s; post-lift climbs `initial_backoff * factor^3 = 16s`.",
        );
    }

    /// Iterations past the cap must all emit `max_backoff = 30s` —
    /// under a wall-clock-bounded loop the exponential climb saturates
    /// to the cap after `attempt >= 4` (`compute_delay(6) = 32s`
    /// clamped to 30s).
    #[test]
    fn test_docker_startup_poll_delay_caps_at_max_backoff_past_the_cap() {
        assert_eq!(
            docker_startup_poll_delay(4),
            Duration::from_secs(30),
            "backoff_attempt=4 must sleep 30s (cap) — \
             `initial_backoff * factor^4 = 32s`, clamped to \
             `max_backoff = 30s`.",
        );
        assert_eq!(
            docker_startup_poll_delay(5),
            Duration::from_secs(30),
            "backoff_attempt=5 must sleep 30s (cap).",
        );
        assert_eq!(
            docker_startup_poll_delay(50),
            Duration::from_secs(30),
            "backoff_attempt=50 must sleep 30s (cap) — beyond-cap \
             iterations must stay at the ceiling rather than drifting \
             upward.",
        );
    }

    /// The poll loop is bounded by wall-clock via
    /// [`DOCKER_STARTUP_MAX_WAIT`], not by attempt count, so
    /// `backoff_attempt` can in principle reach any `u32` value on a
    /// pathologically-fast poll-arm (a stub `docker` that returns
    /// instantly against a daemon that never comes up). This test pins
    /// that composition: an `attempt == u32::MAX` argument returns a
    /// bounded delay rather than panicking. The `saturating_add(2)`
    /// bridge inside `docker_startup_poll_delay` clamps to `u32::MAX`,
    /// and [`RetryPolicy::compute_delay`]'s `checked_pow`-then-cap body
    /// itself saturates to `max_backoff` without panic.
    #[test]
    fn test_docker_startup_poll_delay_saturates_without_panic_at_arbitrarily_large_attempt() {
        assert_eq!(
            docker_startup_poll_delay(u32::MAX),
            Duration::from_secs(30),
            "backoff_attempt=u32::MAX must saturate to max_backoff \
             without panic — the `saturating_add(2)` bridge + \
             `RetryPolicy::compute_delay`'s `checked_pow` cap close \
             the u32 overflow class by construction.",
        );
        assert_eq!(
            docker_startup_poll_delay(u32::MAX - 1),
            Duration::from_secs(30),
            "backoff_attempt=u32::MAX - 1 must also saturate to \
             max_backoff — the bridge `saturating_add(2)` returns \
             u32::MAX, still far past the cap.",
        );
    }

    /// The `(factor, max_backoff)` pair of `DOCKER_STARTUP_POLL_BACKOFF`
    /// matches the Bazel/Buck2/SLSA-frontier reference schedule the
    /// retry module cites at [`RetryPolicy::network`]'s docstring. The
    /// Docker startup-poll policy diverges only at `initial_backoff`
    /// (2s vs 250ms) to preserve the pre-lift
    /// `thread::sleep(Duration::from_secs(2))` seed verbatim. Pin the
    /// shared invariants so a future refinement to the retry module's
    /// reference schedule surfaces the intentional Docker-startup-side
    /// divergence as a named test failure rather than silently
    /// propagating.
    #[test]
    fn test_docker_startup_poll_backoff_shares_network_factor_and_cap() {
        let network = RetryPolicy::network();
        assert_eq!(
            DOCKER_STARTUP_POLL_BACKOFF.factor, network.factor,
            "DOCKER_STARTUP_POLL_BACKOFF.factor must match \
             RetryPolicy::network().factor — both consume the \
             Bazel/Buck2/SLSA-frontier factor=2 reference.",
        );
        assert_eq!(
            DOCKER_STARTUP_POLL_BACKOFF.max_backoff, network.max_backoff,
            "DOCKER_STARTUP_POLL_BACKOFF.max_backoff must match \
             RetryPolicy::network().max_backoff — both consume the \
             Bazel/Buck2/SLSA-frontier 30s cap reference.",
        );
    }

    /// The macOS Docker Desktop startup-poll loop body inside
    /// [`super::ensure_docker_running`] MUST consume the typed primitive
    /// at `docker_startup_poll_delay(backoff_attempt)` rather than the
    /// pre-lift bare `thread::sleep(Duration::from_secs(2))` literal. A
    /// future refactor that reintroduces the fixed-literal shape (see
    /// `DOCKER_STARTUP_POLL_BACKOFF`'s docstring for the three
    /// structural defects the lift closed) fails here, not silently in
    /// production where a slow-starting Docker Desktop would resume
    /// hammering the daemon with ~30 rapid probes over its 60-second
    /// window.
    ///
    /// Uses the [`crate::test_support::code_line_hits`] helper so the
    /// shield does not false-positive on `DOCKER_STARTUP_POLL_BACKOFF`'s
    /// own docstring above (which cites the pre-lift shape as context
    /// for the three defects it forecloses). The forbidden literal is
    /// reconstructed at test time via [`format!`] and the diagnostic
    /// prose refers to it only via the reconstructed `bespoke_needle`
    /// (never the fused literal), so the assert message body itself
    /// stays unmatchable — same code-line-filter-plus-format-
    /// reconstruction discipline sibling shields 4163c7e / ffa5271 /
    /// fa2c702 / a7d5375 / ab06395 use.
    ///
    /// The scan is bounded strictly to `pub fn ensure_docker_running(`'s
    /// body — from its signature through the next `\n#[cfg(test)]\n`
    /// marker in source order — so unrelated `sleep` sites elsewhere in
    /// this module do not false-trigger the shield, and this shield's
    /// own docstring mention of the pre-lift shape (living in a
    /// `#[cfg(test)]` block below that marker) stays out of scope.
    #[test]
    fn test_ensure_docker_running_consumes_typed_poll_delay_not_bare_fixed_sleep() {
        const SOURCE: &str = include_str!("e2e.rs");

        let fn_marker = "pub fn ensure_docker_running(";
        let start = SOURCE.find(fn_marker).expect(
            "commands/e2e.rs must contain `pub fn ensure_docker_running(` \
             — the shield's slice boundary relies on this function name",
        );
        let after_fn = &SOURCE[start..];
        let end_relative = after_fn.find("\n#[cfg(test)]\n").expect(
            "commands/e2e.rs must have a `#[cfg(test)]` marker after \
             `ensure_docker_running` — the shield's slice boundary \
             depends on the module ordering",
        );
        let fn_body = &after_fn[..end_relative];

        let bespoke_needle = format!(
            "thread::sleep(Duration::from_secs({}))",
            DOCKER_STARTUP_POLL_BACKOFF.initial_backoff.as_secs(),
        );
        let bespoke_hits = crate::test_support::code_line_hits(fn_body, &bespoke_needle);
        assert!(
            bespoke_hits.is_empty(),
            "ensure_docker_running() must NOT re-fuse the pre-lift \
             bare fixed sleep at the poll loop — the schedule lives \
             at `DOCKER_STARTUP_POLL_BACKOFF` + \
             `docker_startup_poll_delay`, both grounding through \
             `RetryPolicy::compute_delay`. Found code-line hits: {:#?}",
            bespoke_hits,
        );
        let delegation_hits = crate::test_support::code_line_hits(
            fn_body,
            "docker_startup_poll_delay(backoff_attempt)",
        );
        assert!(
            !delegation_hits.is_empty(),
            "ensure_docker_running() must consume the typed \
             poll-delay helper at the poll loop's sleep site — the \
             canonical delegation call was not found at any code line.",
        );
    }
}
