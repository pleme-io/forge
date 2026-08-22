//! E2E testing commands
//!
//! Provides commands for running unit, integration, and E2E tests.
//! Each test level is self-preparing:
//! - Unit: no dependencies
//! - Integration: auto-starts Docker on macOS if not running
//! - E2E: auto-builds and loads images if missing

use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use crate::repo::get_tool_path;
use crate::retry::{run_inherited_status_sync, RetryPolicy};
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

/// Resolve the `cargo` binary via the `CARGO` env override, falling back
/// to `cargo` on `PATH`. Wired through [`crate::repo::get_tool_path`] —
/// the canonical env-var-or-PATH lookup every cargo-invocation site in
/// forge honors. Fourth landing of the `cargo_bin()` sigil after
/// `commands/test_ci.rs:28` (916f1a4), `commands/prerelease.rs:109`
/// (79e03a5), and `commands/developer_tools.rs:36` (534ef48) — the
/// pattern is proven; `commands/e2e.rs` was the outlier still respelling
/// the two-argument resolve at every consumer. Solve-once at the sigil
/// (THEORY §I.5 — duplication budget zero; every recurring shape becomes
/// a helper before it becomes duplicated code) means a future added
/// `cargo` spawn in this module cannot silently re-copy the two-argument
/// resolve and drift away from the `CARGO` override at exactly the tier
/// the hermetic-runner contract binds. The `cargo_env_routing_tests`
/// shield below asserts three invariants: no bare cargo-literal spawn in
/// the module body (already landed pre-lift), `fn cargo_bin()` is
/// defined, and the two-argument resolve appears in EXACTLY one place —
/// only the sigil body — so a future added spawn cannot silently
/// re-copy the resolve inline. Pre-lift the three consumer sites
/// (`run_backend_unit_tests`, `run_backend_integration_tests`,
/// `run_e2e_tests`) each spelled the two-argument resolve verbatim.
fn cargo_bin() -> String {
    get_tool_path("CARGO", "cargo")
}

/// Resolve the `bun` binary via the `BUN_BIN` env override, falling back
/// to `bun` on `PATH`. Wired through [`crate::repo::get_tool_path`] —
/// the canonical env-var-or-PATH lookup every bun-invocation site in
/// forge honors. Second landing of the `bun_bin()` sigil after the
/// initial `commands/frontend_validation.rs::bun_bin` lift (9986f11) —
/// the pattern is proven; `commands/e2e.rs` was the remaining
/// bun-spawning outlier still respelling the two-argument resolve at
/// every consumer. Solve-once at the sigil (THEORY §I.5 — duplication
/// budget zero; every recurring shape becomes a helper before it
/// becomes duplicated code) means a future added `bun` spawn in this
/// module cannot silently re-copy the two-argument resolve and drift
/// away from the `BUN_BIN` override at exactly the tier the
/// hermetic-runner contract binds. The `bun_env_routing_tests` shield
/// below asserts three invariants: no bare bun-literal spawn in the
/// module body (already landed pre-lift), `fn bun_bin()` is defined,
/// and the two-argument resolve appears in EXACTLY one place — only
/// the sigil body — so a future added spawn cannot silently re-copy
/// the resolve inline. Pre-lift the two consumer sites
/// (`run_frontend_unit_tests`'s live-output + JSON-report branch and
/// its console-reporter fallback) each spelled the two-argument
/// resolve verbatim, so a Nix-hermetic runner whose derivation exports
/// `BUN_BIN=/nix/store/…-bun/bin/bun` but omits `bun` from PATH
/// silently fell through to whatever `bun` was first on PATH at each
/// site — the E2E frontend-unit-test verdict was attributed to
/// whichever `bun` PATH resolved first, not to the substrate-pinned
/// bun derivation the flake declared. Same silent-PATH-fallback bug
/// class the sibling `docker_bin` (23241a6), `open_bin` (8f4c717),
/// and `cargo_bin` (170ecac) sigils on this same module already
/// close for their respective spawn surfaces.
fn bun_bin() -> String {
    get_tool_path("BUN_BIN", "bun")
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
const DOCKER_STARTUP_POLL_BACKOFF: RetryPolicy =
    RetryPolicy::wall_clock_poll(Duration::from_secs(2));

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

    let cargo = cargo_bin();
    let mut cmd = Command::new(&cargo);
    cmd.current_dir(backend_dir).arg("test").arg("--lib");

    if let Some(f) = filter {
        cmd.arg(f);
    }

    let start = Instant::now();
    let outcome = run_inherited_status_sync(cmd, "Backend unit tests");
    let elapsed = start.elapsed();

    ui::print_info(&format!(
        "Backend unit tests completed in {:.1}s",
        elapsed.as_secs_f64()
    ));

    outcome
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
        let bun = bun_bin();
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
        let outcome = run_inherited_status_sync(cmd, "Frontend unit tests");
        let elapsed = start.elapsed();

        println!();
        ui::print_info(&format!(
            "Frontend tests completed in {:.1}s",
            elapsed.as_secs_f64()
        ));
        ui::print_info(&format!("JSON report: {}", output_file));

        outcome?;
    } else {
        ui::print_info("Running bun run test");

        let bun = bun_bin();
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
        let outcome = run_inherited_status_sync(cmd, "Frontend unit tests");
        let elapsed = start.elapsed();

        ui::print_info(&format!(
            "Frontend unit tests completed in {:.1}s",
            elapsed.as_secs_f64()
        ));

        outcome?;
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
    let cargo = cargo_bin();
    let mut cmd = Command::new(&cargo);
    cmd.current_dir(backend_dir).args(&args);
    let outcome = run_inherited_status_sync(cmd, "Backend integration tests");
    let elapsed = start.elapsed();

    ui::print_info(&format!(
        "Integration tests completed in {:.1}s",
        elapsed.as_secs_f64()
    ));

    outcome
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

    let cargo = cargo_bin();
    let mut cmd = Command::new(&cargo);
    cmd.current_dir(&backend_dir).args(&args);

    // Set headless mode
    if headless {
        cmd.env("E2E_HEADLESS", "1");
    } else {
        cmd.env_remove("E2E_HEADLESS");
    }

    let outcome = run_inherited_status_sync(cmd, "E2E tests");
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

    if outcome.is_err() {
        print_failure_diagnostics();
    }
    outcome?;

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
        crate::retry::run_discard_sync(&docker_bin(), &args);
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
        crate::retry::run_discard_sync(&docker_bin(), &args);
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
    crate::retry::run_discard_sync(
        &docker_bin(),
        &[
            "image",
            "prune",
            "-f",
            "--filter",
            "label=org.testcontainers=true",
        ],
    );

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

    // Delegate the repo-root discovery to the canonical
    // [`crate::git::try_repo_root_via_rev_parse`] primitive, which
    // owns the `git rev-parse --show-toplevel` argv literal + the
    // trimmed-stdout decode + the `GIT_BIN`-routed spawn at ONE body
    // (cli/src/git.rs). Retains the pre-migration advisory-fallback
    // shape: any git failure (spawn miss, non-zero exit, UTF-8
    // decode) collapses to `None` and this site falls back to the
    // current working directory rather than surfacing an error.
    if let Some(root) = crate::git::try_repo_root_via_rev_parse() {
        return Ok(root.to_string_lossy().to_string());
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

/// Reserve a hermetic on-disk destination for a `nix build -o <path>`
/// output symlink that a subsequent `docker load` reads. Returns a
/// `(TempDir, PathBuf)` pair whose `TempDir` half is a RAII guard —
/// its `Drop` unlinks the created directory AND the symlink inside it,
/// panic-safe by construction. The path half is `<dir>/<name>-image`,
/// the destination `nix build <flake_attr> -o <path>` will create as a
/// GC-root symlink into the Nix store. It does NOT yet exist, so a
/// `nix build -o` that refuses to overwrite still succeeds. The
/// returned `TempDir` MUST be bound to a local `_dir` (or longer-lived)
/// variable for the duration of the caller: an unbound
/// `let (_, out) = e2e_image_output_symlink(name)?;` drops the guard
/// immediately, unlinks the scratch dir, and the follow-up
/// `nix build -o <out>` (or `File::open(<out>)`) reproducibly fails
/// with a parent-dir `ENOENT` — a fast, loud signal instead of a
/// flake. Sibling shape discipline to
/// `commands/crossplane.rs::xpkg_output_file` (220b207),
/// `commands/federation_tests.rs::federation_test_job_manifest_file`
/// (76b256e), and `commands/migrations.rs::migration_job_manifest_file`
/// (950a0e7), all `(TempDir, PathBuf)` returners on the same
/// "the returned owner is what keeps the on-disk state alive" contract.
///
/// # Why the RAII-scratch shape is load-bearing
///
/// Three defects lived at the pre-lift `format!("/tmp/{}-image", name)`
/// shape that `build_and_load_image` carried at the `nix build -o <path>`
/// destination the sibling `docker load` reads:
///
/// 1. **Unbounded on-disk symlink leak — the store path stays GC-rooted forever.**
///    The pre-lift shape carried NO cleanup — not on the happy path,
///    not on `?` propagation from the `nix build` / `docker load` bail
///    sites, not on `await`-boundary panic, not on operator Ctrl-C.
///    Every `forge e2e-prepare` (or `forge test`-with-E2E-fallback)
///    invocation left a `/tmp/backend-image` + `/tmp/web-image`
///    symlink on the runner, AND those symlinks are Nix GC roots —
///    the store paths they point at are pinned against
///    `nix-collect-garbage` for as long as the symlinks exist. A
///    long-running self-hosted runner accumulates one pair per
///    `forge e2e-prepare` invocation, indefinitely, and each pair
///    pins a full container image tarball (backend + web, hundreds of
///    MB each) against GC — so the runner's Nix store grows without
///    bound. `TempDir::Drop` unlinks the symlink on every exit path,
///    at which point the store path becomes GC-eligible on the next
///    `nix-collect-garbage` pass — the correct lifecycle, since after
///    `docker load` the Docker daemon carries the image and the
///    Nix-store copy is redundant.
/// 2. **Hard-coded `/tmp` bypasses `TMPDIR` and breaks in the Nix hermetic sandbox.**
///    A Nix build under a `sandbox = true` daemon (the default on the
///    fleet's build runners) has no writable `/tmp`; the daemon
///    exposes only `$TMPDIR`, which the pre-lift `format!("/tmp/…")`
///    ignored — so a hermetic-runner `forge e2e-prepare` step would
///    fail at the `nix build -o` step before even reaching `docker
///    load`. `tempfile::Builder::tempdir()` honors `TMPDIR` via
///    `std::env::temp_dir()` so the daemon-provided scratch root is
///    respected by construction rather than by every-caller-
///    remembers-to-check prose.
/// 3. **Concurrent-invocation race on a fixed slot.**
///    Two `forge e2e-prepare` invocations on the same runner (a
///    re-run after a transient nix-daemon error) both wrote to
///    `/tmp/backend-image` and raced the `nix build -o` → `File::open`
///    → `docker load` handoff. The second builder's `nix build -o`
///    replaced the first's symlink between the first's build and its
///    `File::open`, so the second builder's bytes rode into the
///    first's `docker load` under the first's image name. The
///    `mkdtemp(3)`-appended unique suffix in
///    `tempfile::Builder::tempdir()` closes it at the syscall.
fn e2e_image_output_symlink(name: &str) -> Result<(tempfile::TempDir, PathBuf)> {
    let dir = tempfile::Builder::new()
        .prefix("forge-e2e-image-")
        .tempdir()
        .context("create e2e image output scratch tempdir")?;
    let path = dir.path().join(format!("{}-image", name));
    Ok((dir, path))
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
    // Typed RAII scratch surface — `_output_dir` is the guard whose
    // `Drop` unlinks the whole tempdir + the `nix build -o` symlink
    // inside it, panic-safe across the build → docker-load handoff and
    // closing the pre-lift `format!("/tmp/{}-image", name)` shape's
    // triple defect (unbounded GC-rooted store-path leak on every exit
    // path, hard-coded `/tmp` bypassing `TMPDIR` on Nix-sandbox
    // runners, and the fixed-slot race between two concurrent
    // `forge e2e-prepare` invocations). Sibling shape discipline to
    // `commands/crossplane.rs`'s `xpkg_output_file` (220b207),
    // `commands/federation_tests.rs`'s
    // `federation_test_job_manifest_file` (76b256e), and
    // `commands/migrations.rs`'s `migration_job_manifest_file`
    // (950a0e7). `docker load` handoff below opens the symlink by
    // path — `File::open` follows it into the Nix store, and the
    // subsequent `.stdin(image_file)` pipe survives past this fn's
    // `Ok(())` because the `File` handle is dropped only after
    // `run_inherited_status_sync` returns, at which point Drop of
    // `_output_dir` unlinks the symlink (marking the store path
    // GC-eligible on the next `nix-collect-garbage` pass, which is
    // the correct lifecycle: Docker daemon now carries the image and
    // the Nix-store tarball is redundant).
    let (_output_dir, output_path) = e2e_image_output_symlink(name)?;
    let output_path_str = output_path.to_string_lossy().into_owned();

    // Build with Nix
    ui::print_info(&format!("Building {} image via Nix", name));
    let mut build_cmd = Command::new(get_tool_path("NIX_BIN", "nix"));
    build_cmd
        .current_dir(repo_root)
        .args(["build", flake_attr, "-o", &output_path_str]);
    run_inherited_status_sync(build_cmd, &format!("nix build {}", flake_attr))?;

    // Load into Docker
    ui::print_info(&format!("Loading {} image into Docker", name));

    // Route the second-half `docker load` — fed via `stdin(image_file)`
    // from the Nix-built store path — through the canonical sync
    // primitive so both halves of `build_and_load_image` (the `nix
    // build <flake_attr> -o <path>` above and this `docker load`)
    // ride the same one delegation shape. Pre-lift this site spelled
    // an eight-line `.spawn().context("Failed to spawn docker load")?`
    // + `.wait().context("Failed to wait for docker load")?` + `if
    // !load_status.success() { bail!("docker load failed for {name}") }`
    // stanza whose `bail!` dropped the exit code (`load_status.code()`
    // was in scope but discarded) — precisely the regression the sync
    // primitive was written to close (retry.rs:14243 →
    // classify_inherited_status at retry.rs:14190) — and whose two
    // context messages named only the phase (`docker load`) without
    // the image name, so an operator seeing `"Failed to spawn docker
    // load"` in a multi-image E2E build (`backend` + `web`, called at
    // 525 / 532) had no way to tell which `build_and_load_image` had
    // failed. Post-lift the canonical `"docker load for {name} failed
    // (exit {code})"` envelope emerges by construction and the image
    // name lands in both the spawn-failure context and the non-zero
    // envelope at the one primitive body — the shape every
    // sync-frontier sibling (`commands/{crossplane, pangea_infra,
    // gem, infra, tool, test_ci, local, e2e, rust_service,
    // image_release, helm}.rs`, 6cb9442 through 5772ab2) already
    // emits.
    //
    // `std::process::Command::status()` (called inside the primitive)
    // inherits the caller-configured `.stdin(image_file)` File →
    // Stdio conversion — `run_inherited_status_sync` overrides only
    // stdout/stderr — so the file-into-docker-load pipe survives the
    // lift, and the pre-lift `.spawn()`+`.wait()` two-call shape (a
    // stdin-piping-specific workaround from before `.status()` was
    // established as sufficient for pre-configured stdin) collapses
    // to the same one delegation the sibling non-piped spawns use.
    let image_file = std::fs::File::open(&output_path)
        .context(format!("Failed to open image file: {}", output_path_str))?;

    let mut docker_load_cmd = Command::new(docker_bin());
    docker_load_cmd.arg("load").stdin(image_file);
    run_inherited_status_sync(docker_load_cmd, &format!("docker load for {}", name))?;

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
    if let Some(stdout) = crate::retry::probe_stdout_capture_sync(
        &docker_bin(),
        &["ps", "--format", "  {{.Names}}\t{{.Status}}\t{{.Ports}}"],
    ) {
        if stdout.trim().is_empty() {
            eprintln!("  (none)");
        } else {
            eprint!("{}", stdout);
        }
    }

    // Recently exited containers (testcontainers that died)
    eprintln!("\nDocker containers (recently exited):");
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
            "  {{.Names}}\t{{.Status}}\t{{.Image}}",
        ],
    ) {
        if stdout.trim().is_empty() {
            eprintln!("  (none)");
        } else {
            eprint!("{}", stdout);
        }
    }

    // Check Docker images
    eprintln!("\nE2E Docker images:");
    if let Some(stdout) = crate::retry::probe_stdout_capture_sync(
        &docker_bin(),
        &[
            "images",
            "--format",
            "  {{.Repository}}:{{.Tag}}\t{{.Size}}\t{{.ID}}",
        ],
    ) {
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
    /// `std::process::Command::new("git")` literal. Pre-lift the
    /// single site bypassed the `GIT_BIN` env override the
    /// `tools::get_tool_path(tools::GIT)` idiom
    /// (cli/src/tools.rs:102-105) resolves; the first migration
    /// (447cad1) routed the spawn through `git_command_sync` and
    /// this shield certified that. The second migration lifted the
    /// `git rev-parse --show-toplevel` argv literal + the
    /// trimmed-stdout decode onto the canonical
    /// [`crate::git::try_repo_root_via_rev_parse`] primitive so a
    /// downstream consumer that ever forgot the `git_command_sync`
    /// spawn constructor still inherits the `GIT_BIN` override by
    /// construction (the primitive itself owns the routing at ONE
    /// body). This shield now asserts the delegation to that
    /// primitive rather than the inline `git_command_sync()` call
    /// the pre-lift shape carried.
    ///
    /// This test reads this module's own source via [`include_str!`]
    /// and asserts the raw `Command::new("git")` string does not
    /// reappear in `resolve_repo_root` while the delegation to
    /// `crate::git::try_repo_root_via_rev_parse()` does. A future
    /// regression that re-fuses the raw-spawn body fails here, not
    /// silently in production where a Nix-hermetic runner's
    /// `GIT_BIN`-provided `git` would lose to whatever `git` is
    /// first on `PATH` at repo-root discovery time.
    ///
    /// The check is deliberately structural (substring on the source
    /// text) rather than behavioral — the end-to-end `GIT_BIN`-
    /// routing invariant is already pinned by
    /// [`crate::git::tests::test_git_command_sync_routes_through_git_bin_env_var`]
    /// on the primitive itself and by the sibling primitive's own
    /// hermetic test; this shield only certifies that the
    /// `resolve_repo_root` git discovery reads through the canonical
    /// primitive. Mirrors the sibling shields on
    /// `config::resolve_k8s_repo_root` and `commands/helm.rs::deploy`
    /// for the sync half of the surface.
    #[test]
    fn test_resolve_repo_root_routes_git_through_git_command_sync_not_raw_command() {
        const SOURCE: &str = include_str!("e2e.rs");

        // Bound the scan to `resolve_repo_root` — the single git
        // discovery site lives inside it. Docstrings and sibling
        // functions in this module legitimately reference the
        // pre-migration literal, so scoping the check to the target
        // function's body avoids false positives.
        // Bound the fn body between `resolve_repo_root`'s header and
        // the next top-level `fn verify_docker(` in source order,
        // which follows `resolve_repo_root`.
        let fn_body = crate::test_support::fn_body_slice_between_markers(
            SOURCE,
            "commands/e2e.rs",
            "fn resolve_repo_root(",
            "\nfn verify_docker(",
        );

        assert!(
            !fn_body.contains("Command::new(\"git\")"),
            "resolve_repo_root() must NOT spawn `git` directly — \
             route through `crate::git::try_repo_root_via_rev_parse()` \
             so `GIT_BIN` overrides land at the shared primitive. \
             Found the pre-migration spawn body in resolve_repo_root()."
        );
        assert!(
            fn_body.contains("crate::git::try_repo_root_via_rev_parse()"),
            "resolve_repo_root() must delegate the git discovery to \
             `crate::git::try_repo_root_via_rev_parse()` — the \
             delegation string was not found in resolve_repo_root()."
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
        let body =
            crate::test_support::module_body_before_first_cfg_test(SOURCE, "commands/e2e.rs");
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
        let body =
            crate::test_support::module_body_before_first_cfg_test(SOURCE, "commands/e2e.rs");
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

    /// Whole-module shield: the three best-effort-captured `docker`
    /// diagnostic probes inside [`super::print_failure_diagnostics`]
    /// (docker ps / docker ps -a --since=15m --filter status=exited /
    /// docker images, the three sites the E2E-failure post-mortem
    /// surface renders in order) MUST delegate through
    /// [`crate::retry::probe_stdout_capture_sync`], never through a
    /// hand-rolled `if let Ok(output) = Command::new(docker_bin())
    /// .args(...).output() { let stdout =
    /// String::from_utf8_lossy(&output.stdout); ... }` best-effort
    /// captured-output stanza that silently reintroduces the six-copy
    /// pre-lift duplication this commit closes.
    ///
    /// Pre-lift the three sites each carried the verbatim three-line
    /// stanza above, and the sibling `commands/prerelease.rs::
    /// print_e2e_diagnostics` block carried three MORE copies past
    /// its own docker-literal shield — six identically-shaped bodies
    /// past THEORY §VI.1's three-is-a-law threshold (PRIME DIRECTIVE:
    /// duplication budget is zero). The lift onto
    /// [`crate::retry::probe_stdout_capture_sync`] preserves the exact
    /// pre-lift semantics — spawn `Err` skips the block, spawn `Ok`
    /// returns the UTF-8-lossy stdout regardless of `output.status`
    /// — so the migration is behavior-identical at the diagnostic
    /// surface, and the primitive's docstring pins the "deliberately
    /// infallible at the caller" contract that future callers must
    /// honor.
    ///
    /// # Why a delegation-count floor (not just a negative scan)
    ///
    /// A negative-only shield that forbids the pre-lift stanza is
    /// trivially satisfied by absence — a regression that
    /// accidentally deleted one of the three diagnostic probes
    /// (say, dropped the `docker images` block during a diagnostic
    /// prose rewrite) would still pass the negative scan. Pinning
    /// the delegation count to `>= 3` means every one of the three
    /// diagnostic surfaces MUST still route through the primitive;
    /// a deletion drops the count and fails the shield. Same
    /// discipline the sibling status-only-spawn shields
    /// (a21bd67 `test_ci` four spawns, 5faeecb `e2e` six spawns,
    /// c2922fd `local` four spawns, and the eight sync-frontier
    /// consolidations at 08fdb86 / a31ef65) honor via the two-arm
    /// `assert_source_routes_status_only_spawns_through_run_inherited_status_sync`
    /// composition.
    ///
    /// # Reconstruction discipline
    ///
    /// The delegation needle `probe_stdout_capture_sync(` is
    /// reconstructed via [`format!`] at test time so this shield's
    /// own source text does not self-match the substring count — the
    /// per-line filter would otherwise inflate the count by one for
    /// the needle-literal line. The three delegation sites each
    /// spell `crate::retry::probe_stdout_capture_sync(` verbatim; the
    /// shorter `probe_stdout_capture_sync(` needle matches all three
    /// (a suffix of the fully-qualified form) without also matching
    /// the shield's own body (which only spells the two halves as
    /// separate literals joined at `format!` time).
    #[test]
    fn test_e2e_diagnostic_probes_route_through_probe_stdout_capture_sync() {
        const SOURCE: &str = include_str!("e2e.rs");
        let body =
            crate::test_support::module_body_before_first_cfg_test(SOURCE, "commands/e2e.rs");
        let needle = format!("probe_stdout_capture_{}(", "sync");
        let hits = crate::test_support::code_line_hits(body, &needle);
        assert!(
            hits.len() >= 3,
            "commands/e2e.rs must delegate its three best-effort \
             `docker` diagnostic probes (docker ps / docker ps -a \
             --since=15m --filter status=exited / docker images inside \
             `print_failure_diagnostics`) through the shared \
             `crate::retry::probe_stdout_capture_sync` primitive — \
             found {} delegation(s) in the top-of-file body, expected \
             at least 3. A regression that reintroduces the pre-lift \
             `if let Ok(output) = Command::new(docker_bin()).args(...)\
             .output() {{ let stdout = String::from_utf8_lossy(\
             &output.stdout); ... }}` stanza re-establishes the \
             six-copy duplication this commit closes. Offending hits: \
             {hits:?}",
            hits.len(),
        );
    }

    /// Whole-module shield: the three best-effort silent
    /// spawn-and-discard `docker` cleanup sites inside
    /// [`super::cleanup_testcontainers`] (two `docker rm -f <ids>`
    /// sweeps — the testcontainer class and the Ryuk-sidecar class,
    /// both after a preceding `docker ps` listing surfaced the
    /// container IDs to remove) and [`super::cleanup_e2e_images`]
    /// (one `docker image prune -f --filter
    /// label=org.testcontainers=true` sweep) MUST delegate through
    /// [`crate::retry::run_discard_sync`], never through a hand-rolled
    /// `let _ = Command::new(docker_bin()).args([...]).output();`
    /// discard-both-streams stanza that silently reintroduces the
    /// five-copy pre-lift duplication this commit closes.
    ///
    /// Pre-lift the three sites each carried the verbatim one-line
    /// stanza above, and the sibling `commands/local.rs::up` block
    /// carried two MORE copies past its own docker-literal shield —
    /// five identically-shaped bodies past THEORY §VI.1's
    /// three-is-a-law threshold (PRIME DIRECTIVE: duplication budget
    /// is zero). The lift onto [`crate::retry::run_discard_sync`]
    /// preserves the exact pre-lift semantics — spawn `Err` is
    /// swallowed, spawn `Ok` discards the entire
    /// [`std::process::Output`] regardless of `output.status` — so
    /// the migration is behavior-identical at the cleanup surface,
    /// and the primitive's docstring pins the "deliberately
    /// infallible at the caller" contract that future callers must
    /// honor.
    ///
    /// # Why a delegation-count floor (not just a negative scan)
    ///
    /// A negative-only shield that forbids the pre-lift stanza is
    /// trivially satisfied by absence — a regression that
    /// accidentally deleted one of the three cleanup sweeps (say,
    /// dropped the `docker image prune` block during a cleanup-tier
    /// prose rewrite) would still pass the negative scan. Pinning
    /// the delegation count to `>= 3` means every one of the three
    /// cleanup surfaces MUST still route through the primitive; a
    /// deletion drops the count and fails the shield. Same
    /// discipline the sibling
    /// `test_e2e_diagnostic_probes_route_through_probe_stdout_capture_sync`
    /// (1ffda81) shield above and the fleet-wide status-only-spawn
    /// shields (a21bd67 `test_ci` four spawns, 5faeecb `e2e` six
    /// spawns, c2922fd `local` four spawns, and the eight
    /// sync-frontier consolidations at 08fdb86 / a31ef65) honor via
    /// the two-arm
    /// `assert_source_routes_status_only_spawns_through_run_inherited_status_sync`
    /// composition.
    ///
    /// # Reconstruction discipline
    ///
    /// The delegation needle `run_discard_sync(` is reconstructed
    /// via [`format!`] at test time so this shield's own source
    /// text does not self-match the substring count — the per-line
    /// filter would otherwise inflate the count by one for the
    /// needle-literal line. The three delegation sites each spell
    /// `crate::retry::run_discard_sync(` verbatim; the shorter
    /// `run_discard_sync(` needle matches all three (a suffix of
    /// the fully-qualified form) without also matching the shield's
    /// own body (which only spells the two halves as separate
    /// literals joined at `format!` time).
    #[test]
    fn test_e2e_cleanup_sweeps_route_through_run_discard_sync() {
        const SOURCE: &str = include_str!("e2e.rs");
        let body =
            crate::test_support::module_body_before_first_cfg_test(SOURCE, "commands/e2e.rs");
        let needle = format!("run_discard_{}(", "sync");
        let hits = crate::test_support::code_line_hits(body, &needle);
        assert!(
            hits.len() >= 3,
            "commands/e2e.rs must delegate its three best-effort \
             `docker` cleanup sweeps (two `docker rm -f <ids>` \
             sweeps inside `cleanup_testcontainers` and one \
             `docker image prune -f --filter \
             label=org.testcontainers=true` inside \
             `cleanup_e2e_images`) through the shared \
             `crate::retry::run_discard_sync` primitive — found {} \
             delegation(s) in the top-of-file body, expected at \
             least 3. A regression that reintroduces the pre-lift \
             `let _ = Command::new(docker_bin()).args([...]).output();` \
             stanza re-establishes the five-copy duplication this \
             commit closes. Offending hits: {hits:?}",
            hits.len(),
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
        let body =
            crate::test_support::module_body_before_first_cfg_test(SOURCE, "commands/e2e.rs");
        assert!(
            !body.contains("Command::new(\"cargo\")"),
            "commands/e2e.rs must not spawn `cargo` via the bare \
             literal — every `cargo` spawn must resolve `CARGO` via \
             `crate::repo::get_tool_path(\"CARGO\", \"cargo\")` first. \
             A raw `Command::new(\"cargo\")` bypasses the hermetic-runner \
             contract substrate's mkRuntimeToolsEnv exports."
        );
        // Sigil sibling: after the cargo_bin() lift, every consumer routes
        // through the sigil, so `fn cargo_bin()` must be defined AND the
        // two-argument resolve string must appear in EXACTLY one place —
        // only the sigil body — so a future added spawn cannot silently
        // re-copy the resolve inline and drift away from the sigil's
        // single point of truth. Mirrors the sibling `cargo_bin()` shield
        // pair on `commands/developer_tools.rs::test_developer_tools_routes_cargo_through_cargo_env_not_raw_command`
        // (534ef48). THEORY §I.5: duplication budget zero.
        assert!(
            body.contains("fn cargo_bin()"),
            "commands/e2e.rs must define `cargo_bin()` — the sigil \
             function that resolves the tools-registry `CARGO` override \
             for every cargo spawn. Mirrors the `cargo_bin()` sigil at \
             `commands/test_ci.rs:28`, `commands/prerelease.rs:109`, and \
             `commands/developer_tools.rs:36`."
        );
        let two_arg_needle =
            crate::test_support::get_tool_path_two_arg_call_needle("CARGO", "cargo");
        let resolve_count = body.matches(two_arg_needle.as_str()).count();
        assert_eq!(
            resolve_count, 1,
            "the two-argument resolve `{two_arg_needle}` must appear \
             exactly ONCE in the module body (only in the `cargo_bin()` \
             sigil), not {resolve_count} times — every consumer must route \
             through `cargo_bin()`, not re-copy the resolve inline"
        );
    }
}

#[cfg(test)]
mod bun_env_routing_tests {
    /// Whole-module shield: no raw `Command::new("bun")` may live in
    /// `commands/e2e.rs`'s non-test body, `fn bun_bin()` must be
    /// defined, and the two-argument resolve
    /// `get_tool_path("BUN_BIN", "bun")` must appear exactly ONCE
    /// (only in the sigil body).
    ///
    /// Pre-lift the two consumer sites — `run_frontend_unit_tests`'
    /// live-output + JSON-report branch at line 464 and its
    /// console-reporter fallback at line 498 — each spelled
    /// `let bun = get_tool_path("BUN_BIN", "bun");` verbatim. Post-lift
    /// each consumer routes through `bun_bin()` and the two-argument
    /// resolve appears in exactly ONE place (the sigil body). The
    /// `resolve_count == 1` assertion fails-before at 2, passes-after
    /// at 1 — the canonical fail-before-pass-after arc matching the
    /// sibling `<tool>_bin()` shield discipline landed on this same
    /// module for `docker_bin` (23241a6), `open_bin` (8f4c717), and
    /// `cargo_bin` (170ecac), and on the sibling
    /// `commands/frontend_validation.rs::bun_bin` first landing
    /// (9986f11).
    ///
    /// The scan bounds on the whole-module boundary (from the file
    /// start to the FIRST `\n#[cfg(test)]\n` marker in source order,
    /// which lands at the sibling
    /// `resolve_repo_root_git_bin_routing_tests` block near the end of
    /// the module body) so this shield's own docstring mentions of the
    /// forbidden literal — living in a `#[cfg(test)]` block below that
    /// first marker — stay out of scope AND every current or future
    /// bun-spawning helper landing anywhere in the top-level module
    /// body cannot silently ride along without going through
    /// `bun_bin()`. Mirrors the sibling whole-module shields on the
    /// same module (`cargo_env_routing_tests`, `docker_bin_routing_tests`,
    /// `open_bin_routing_tests`).
    ///
    /// The two-argument-resolve needle is reconstructed via `format!`
    /// inside [`crate::test_support::get_tool_path_two_arg_call_needle`],
    /// so this shield's own source never contains the literal
    /// `get_tool_path("BUN_BIN", "bun")` string and cannot false-match
    /// itself on the count-eq-1 assertion.
    ///
    /// A Nix-hermetic runner whose derivation exports
    /// `BUN_BIN=/nix/store/…-bun/bin/bun` but omits `bun` from PATH
    /// silently fell through to whatever `bun` was first on PATH at
    /// each pre-lift site — the E2E frontend-unit-test verdict was
    /// attributed to whichever `bun` PATH resolved first, not to the
    /// substrate-pinned bun derivation the flake declared. Same
    /// silent-PATH-fallback bug class the sibling
    /// `commands/frontend_validation.rs::bun_bin` shield closes for the
    /// pre-release frontend-validation surface, here closed for the
    /// E2E frontend-unit-test surface.
    #[test]
    fn test_e2e_routes_bun_through_bun_bin_sigil_not_raw_command() {
        const SOURCE: &str = include_str!("e2e.rs");
        let body =
            crate::test_support::module_body_before_first_cfg_test(SOURCE, "commands/e2e.rs");
        assert!(
            !body.contains("Command::new(\"bun\")"),
            "commands/e2e.rs must not spawn `bun` via the bare \
             literal — every `bun` spawn must resolve `BUN_BIN` via \
             `bun_bin()` first. A raw `Command::new(\"bun\")` bypasses \
             the hermetic-runner contract substrate's mkRuntimeToolsEnv \
             exports."
        );
        assert!(
            body.contains("fn bun_bin()"),
            "commands/e2e.rs must define `bun_bin()` — the sigil \
             function that resolves the tools-registry `BUN_BIN` \
             override for every bun spawn. Mirrors the `bun_bin()` \
             sigil at `commands/frontend_validation.rs:50` (9986f11) \
             and the sibling `cargo_bin()` / `docker_bin()` / \
             `open_bin()` sigils on this same module."
        );
        let two_arg_needle =
            crate::test_support::get_tool_path_two_arg_call_needle("BUN_BIN", "bun");
        let resolve_count = body.matches(two_arg_needle.as_str()).count();
        assert_eq!(
            resolve_count, 1,
            "the two-argument resolve `{two_arg_needle}` must appear \
             exactly ONCE in the module body (only in the `bun_bin()` \
             sigil), not {resolve_count} times — every consumer must \
             route through `bun_bin()`, not re-copy the resolve inline"
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
        let body =
            crate::test_support::module_body_before_first_cfg_test(SOURCE, "commands/e2e.rs");
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

        let fn_body = crate::test_support::fn_body_slice_between_markers(
            SOURCE,
            "commands/e2e.rs",
            "pub fn ensure_docker_running(",
            "\n#[cfg(test)]\n",
        );

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

#[cfg(test)]
mod e2e_status_spawn_routing_tests {
    /// Whole-module shield: every status-only spawn in
    /// `commands/e2e.rs` routes through
    /// [`crate::retry::run_inherited_status_sync`], never a hand-rolled
    /// inline builder-terminator + `if !status.success()` stanza that
    /// drops the exit code from the operator log line.
    ///
    /// Pre-lift, seven status-only sites each spelled a hand-rolled
    /// inline shape verbatim:
    ///
    /// 1. `run_backend_unit_tests` — `cargo test --lib`;
    /// 2. `run_frontend_unit_tests` (reporter branch) — `bun run test
    ///    --reporter=json`; pre-lift its diagnostic bailed with
    ///    `"Frontend unit tests failed (see report for details)"`
    ///    and **dropped the exit code entirely**;
    /// 3. `run_frontend_unit_tests` (console branch) — `bun run test`;
    /// 4. `run_backend_integration_tests` — `cargo test --test
    ///    integration_tests`;
    /// 5. `run_e2e_tests` — `cargo test --test e2e_tests`;
    /// 6. `build_and_load_image` — `nix build <flake-attr>`;
    /// 7. `build_and_load_image` — `docker load` (fed via
    ///    `stdin(image_file)` from the Nix store path).
    ///
    /// Sites 1, 3, 4, 5 routed through a local
    /// `ensure_test_suite_success` helper whose bail body spelled
    /// `"<suite> failed (exit code: {:?})"` — the pre-canonical
    /// `Debug`-format envelope (`Some(1)` / `None`) rather than the
    /// canonical `retry::classify_inherited_status` envelope
    /// (`"exit 1"` / `"killed by signal"`). Site 2 dropped the exit
    /// code altogether; site 6 kept only the flake-attr and dropped
    /// the exit code. Site 7 uniquely spelled the pre-lift shape as
    /// `.spawn().context(SPAWN_CTX)?` + `.wait().context(WAIT_CTX)?`
    /// + `if !load_status.success() { bail!(FAIL_MSG) }` (the
    /// stdin-piping-specific spawn+wait shape used before `.status()`
    /// was established as sufficient for pre-configured stdin), and
    /// its `bail!` dropped the exit code AND its two context
    /// messages dropped the image name — an operator seeing
    /// `"Failed to spawn docker load"` in a multi-image E2E build
    /// (`backend` + `web`, called at 525 / 532) had no way to tell
    /// WHICH `build_and_load_image` had failed. Post-lift both
    /// name-carrying context (`"Failed to run docker load for
    /// {name}"`) and exit-carrying envelope (`"docker load for
    /// {name} failed (exit {code})"`) emerge by construction at the
    /// one primitive body.
    ///
    /// Post-lift each spawn is a one-line delegation and the
    /// canonical `"{op} failed (exit {code})"` envelope emerges by
    /// construction at the `run_inherited_status_sync` body — so
    /// every failed E2E-tier spawn's operator log line now reads
    /// e.g. `"Backend unit tests failed (exit 1)"` (Display, one
    /// shape across every status-only site in forge) rather than the
    /// per-site dialect the pre-lift shape carried.
    ///
    /// Sibling of the `commands/crossplane.rs` shield
    /// `test_crossplane_status_spawns_route_through_run_inherited_status_sync`
    /// (6cb9442), `commands/pangea_infra.rs`'s
    /// `test_pangea_infra_status_spawns_route_through_run_inherited_status_sync`
    /// (a6e9b96), `commands/gem.rs`'s
    /// `test_gem_status_spawns_route_through_run_inherited_status_sync`
    /// (9072905), `commands/infra.rs`'s
    /// `test_infra_status_spawns_route_through_run_inherited_status_sync`
    /// (27896e4), and `commands/tool.rs`'s
    /// `test_tool_status_spawns_route_through_run_inherited_status_sync`
    /// (a3d51eb). Same three-primitive discipline: negative side
    /// forbids the inline `.status()` builder-terminator at any code
    /// line in the module body; positive side pins that
    /// `run_inherited_status_sync(` appears at ≥7 code lines (one
    /// per pre-lift spawn — the six original status-only sites plus
    /// the `docker load` site whose stdin-piping-specific `.spawn()`
    /// + `.wait()` shape now collapses onto the same primitive), so
    /// a regression that dropped every delegation cannot leave the
    /// negative scan trivially satisfied by absence. Both hits
    /// route through [`crate::test_support::code_line_hits`] for
    /// anti-docstring-self-match discipline. Scan bounds from file
    /// start to the FIRST `\n#[cfg(test)]\n` marker (the sibling
    /// `resolve_repo_root_git_bin_routing_tests` opener), so this
    /// shield's own body — the string literal `".status()"` passed
    /// to `code_line_hits`, and the assertion message that names the
    /// forbidden terminator — stays out of scope.
    #[test]
    fn test_e2e_status_spawns_route_through_run_inherited_status_sync() {
        crate::test_support::assert_source_routes_status_only_spawns_through_run_inherited_status_sync(
            include_str!("e2e.rs"),
            "commands/e2e.rs",
            7,
            "all seven status-only spawns (`cargo test --lib`, `bun \
             run test` reporter + console branches, `cargo test \
             --test integration_tests`, `cargo test --test \
             e2e_tests`, `nix build <flake-attr>`, and the piped \
             `docker load` in `build_and_load_image`)",
        );
    }
}

#[cfg(test)]
mod e2e_image_output_symlink_tests {
    /// Primitive pin: the returned path's basename is exactly
    /// `<name>-image` — the same shape the pre-lift
    /// `format!("/tmp/{}-image", name)` reservation produced, so an
    /// operator dumping the scratch tempdir root after a failing
    /// `forge e2e-prepare` (or auto-fallback E2E-image build inside
    /// `run_test_pyramid`'s E2E phase) can still trace the symlink
    /// back to the image name it was built for. A drift onto a bare
    /// `image` basename would still let `nix build -o` succeed and
    /// `docker load` follow the symlink, but two concurrent
    /// `build_and_load_image` calls with different `name`s
    /// (`backend` vs `web`) would produce two `image` symlinks in
    /// two different tempdirs — an operator debugging a scratch-dir
    /// leak in a hermetic-runner post-mortem would have no way to
    /// tell which tempdir was which.
    #[test]
    fn test_e2e_image_output_symlink_returns_expected_basename() {
        let (_dir, path) =
            super::e2e_image_output_symlink("backend").expect("e2e_image_output_symlink backend");
        assert_eq!(
            path.file_name().and_then(|s| s.to_str()),
            Some("backend-image"),
            "e2e_image_output_symlink(\"backend\") must return a path \
             whose basename is exactly `backend-image` — same shape the \
             pre-lift `format!(\"/tmp/{{}}-image\", name)` reservation \
             produced; got {path:?}",
        );
        let (_dir_web, path_web) =
            super::e2e_image_output_symlink("web").expect("e2e_image_output_symlink web");
        assert_eq!(
            path_web.file_name().and_then(|s| s.to_str()),
            Some("web-image"),
            "e2e_image_output_symlink(\"web\") must return a path whose \
             basename is exactly `web-image`; got {path_web:?}",
        );
    }

    /// Primitive pin — the concurrent-race half: two calls in the
    /// same process with the same `name` return strictly-distinct
    /// paths, so two `forge e2e-prepare` invocations on the same
    /// runner cannot alias on the same on-disk symlink slot even
    /// when the image name collides (both call
    /// `build_and_load_image(&repo_root, "backend", …)`, say — a
    /// re-run after a transient nix-daemon error). `mkdtemp(3)`-
    /// backed unique-suffix discipline; a drift onto a fixed-dir
    /// shape would fail HERE, not as a mysterious wrong-bytes-to-
    /// wrong-image-name `docker load` downstream.
    #[test]
    fn test_e2e_image_output_symlink_returns_distinct_paths_on_each_call() {
        let (_a_dir, a) = super::e2e_image_output_symlink("backend").expect("a");
        let (_b_dir, b) = super::e2e_image_output_symlink("backend").expect("b");
        assert_ne!(
            a, b,
            "two calls to e2e_image_output_symlink(same name) must return \
             strictly-distinct paths — a fixed-dir shape would race two \
             concurrent forge e2e-prepare invocations against the same \
             `<name>-image` symlink slot",
        );
    }

    /// Primitive pin — the leak half: the returned path starts fresh
    /// (the caller creates the symlink via `nix build -o <path>`),
    /// the guard keeps the scratch dir alive across a mid-body
    /// write, and `Drop` unlinks both dir AND the symlink inside it.
    /// A drift onto a `NamedTempFile`-only shape that pre-created
    /// the file would change the `nix build -o` semantics (from
    /// create-fresh-symlink to `nix build -o` refuses-to-overwrite);
    /// a drift onto a bare `tempdir()` without the RAII guard held
    /// would flake because `Drop` ran between the `nix build -o` and
    /// the `File::open` follow-through. Both surface here.
    #[test]
    fn test_e2e_image_output_symlink_fresh_and_dir_drop_unlinks_written_bytes() {
        let path = {
            let (dir, out) =
                super::e2e_image_output_symlink("backend").expect("e2e_image_output_symlink");
            assert!(
                !out.exists(),
                "returned path must be fresh — the caller creates the \
                 symlink via `nix build -o <path>`; a pre-created file \
                 would change `nix build -o` semantics from create-fresh \
                 to refuses-to-overwrite"
            );
            // Stub the symlink-payload with a plain file — the leak
            // discipline is on the on-disk entry, not on the symlink-vs-
            // regular-file distinction the real caller carries.
            std::fs::write(&out, b"stub image tarball\n").expect("write stub image bytes");
            assert!(
                out.exists() && dir.path().is_dir(),
                "file exists AND dir is alive while the RAII guard is held"
            );
            out
        };
        assert!(
            !path.exists(),
            "`TempDir::Drop` must unlink the scratch dir + its contents \
             — a mid-body panic between `nix build -o` and `docker load` \
             would otherwise leak `/tmp/forge-e2e-image-*/backend-image` \
             AND pin the GC-rooted store path forever"
        );
    }

    /// Whole-fn shield: `build_and_load_image` MUST reserve its
    /// `nix build -o <path>` destination through the
    /// `e2e_image_output_symlink()` sigil, never a hand-rolled
    /// `format!("/tmp/{}-image", name)` stanza that leaks the
    /// GC-rooted store path AND ignores `TMPDIR`.
    ///
    /// Pre-lift `build_and_load_image` spelled the fixed-path shape
    /// verbatim (`let output_path = format!("/tmp/{}-image", name);`
    /// at the build-destination reservation site with NO cleanup at
    /// any exit path — not on the happy path, not on `?` propagation
    /// from `nix build` / `docker load` bails, not on operator
    /// Ctrl-C), so every non-happy exit left the `/tmp/<name>-image`
    /// symlink on the runner forever AND pinned the container-
    /// tarball store path against `nix-collect-garbage`. And a
    /// hermetic Nix-sandbox build with no writable `/tmp` failed
    /// to even create the symlink, because `format!("/tmp/…")`
    /// bypassed the daemon-provided `TMPDIR`. `TempDir::Drop` +
    /// `tempfile::Builder::tempdir()`'s `std::env::temp_dir()`
    /// honor close both defects by construction. Sibling shape
    /// discipline to the `test_run_federation_tests_manifest_path_
    /// routes_through_federation_test_job_manifest_file` shield
    /// (76b256e) and the `test_run_migration_job_manifest_path_
    /// routes_through_migration_job_manifest_file` shield
    /// (950a0e7) on the sibling command modules.
    ///
    /// Positive side: the delegation call
    /// `e2e_image_output_symlink(` must appear at exactly ONE code
    /// line in `build_and_load_image`'s fn body (the single
    /// consumer site), so a regression that deleted the delegation
    /// call cannot leave the negative scan trivially satisfied by
    /// absence. The sigil definition itself (line reading `fn
    /// e2e_image_output_symlink(`) is out of scope because this
    /// shield's fn-body slice starts at the `fn
    /// build_and_load_image(` marker.
    ///
    /// Negative side: the pre-lift `format!("/tmp/{}-image", name)`
    /// shape must not appear at any code line in the fn body. The
    /// forbidden needle is reconstructed at test time via
    /// `format!("format!(\"/{}/", "tmp")` so this shield's own
    /// panic-message and docstring prose does not false-match
    /// itself (same discipline the sibling
    /// `federation_test_job_manifest_file` shield's negative-scan
    /// needle carries). Scope is `build_and_load_image`'s fn body
    /// (via [`crate::test_support::fn_body_slice_between_markers`])
    /// with end marker `\nfn print_image_info(` — the next fn in
    /// source order after `build_and_load_image`.
    #[test]
    fn test_build_and_load_image_output_path_routes_through_e2e_image_output_symlink() {
        const SOURCE: &str = include_str!("e2e.rs");
        let body = crate::test_support::fn_body_slice_between_markers(
            SOURCE,
            "commands/e2e.rs",
            "fn build_and_load_image(",
            "\nfn print_image_info(",
        );
        // Positive: build_and_load_image delegates to the sigil.
        let delegation_hits =
            crate::test_support::code_line_hits(body, "e2e_image_output_symlink(");
        assert_eq!(
            delegation_hits.len(),
            1,
            "build_and_load_image must delegate to `e2e_image_output_symlink(` \
             at exactly one code line (the single scratch-symlink consumer \
             site); got {} — hits: {delegation_hits:#?}",
            delegation_hits.len(),
        );
        // Negative: no code-line hit of the pre-lift fixed `/tmp/…` shape.
        let forbidden = format!("format!(\"/{}/", "tmp");
        let stale = crate::test_support::code_line_hits(body, &forbidden);
        assert!(
            stale.is_empty(),
            "build_and_load_image must not spell the pre-lift fixed-`/tmp/…` \
             scratch-symlink shape at any code line — every scratch-symlink \
             path must route through `e2e_image_output_symlink()` so \
             `TempDir::Drop` closes the leak AND `tempfile::Builder`'s \
             `std::env::temp_dir()` honor closes the hermetic-`TMPDIR` \
             bypass. Offending: {stale:#?}",
        );
    }
}
