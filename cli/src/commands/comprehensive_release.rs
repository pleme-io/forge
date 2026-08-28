use anyhow::{Context, Result};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::time::{Duration, Instant};
use tokio::process::Command;
use tracing::{debug, info, warn};

use crate::repo::get_tool_path;
use crate::retry::RetryPolicy;
use crate::{commands, git};

/// The typed exponential-backoff policy for the docker-compose services-
/// healthy status-poll cadence in [`execute`]'s integration-test step —
/// `initial_backoff` 2s × `factor` 2 capped at `max_backoff` 30s. Consumes
/// the pre-existing typed primitive at [`crate::retry::RetryPolicy`] so
/// the per-attempt delay lands at [`RetryPolicy::compute_delay`], the same
/// shared body the sibling k8s-Job status-poll surface
/// `services/migration_service.rs::MIGRATION_JOB_POLL_BACKOFF`
/// (commit ac61874), the reconcile-poll surface `commands/migrations.rs::
/// SHINKA_MIGRATION_POLL_BACKOFF` (commit b962db5), the flux polling-loops
/// surface `commands/flux.rs::FLUX_POLL_BACKOFF` (commit 65de62f), the
/// health-endpoint retry surface `commands/post_deploy_verification.rs::
/// HEALTH_ENDPOINT_BACKOFF` (commit b5db3b6), and the federation-test
/// / rollout-watch / test-suite retry surfaces (commits 8319fa2 /
/// 7fe79de / 9fd38d3 / e22b0a2) read through.
///
/// Pre-lift the schedule was spelled inline as a bare fixed
/// `tokio::time::sleep(tokio::time::Duration::from_secs(2)).await` at the
/// tail of every non-terminal iteration of the docker-compose `ps` health
/// probe loop, bounded by a count-based `attempts >= 60` cap (the flat 2s
/// × 60 iteration budget the pre-lift `// 2 minutes (60 * 2s)` comment
/// cited as the intended wall-clock timeout). That shape carried three
/// structural defects the typed-primitive body forecloses:
/// 1. **Fixed 2s schedule.** A flat `sleep(2s)` between poll iterations
///    is "too short when the services are still starting (60 `docker-
///    compose ps` probes across a 2-minute window — a stream of daemon
///    round-trips for containers that haven't yet emitted their
///    healthcheck), 2s too long when the last container flipped to
///    `healthy` 100ms ago" — the exact worst-of-both failure mode the
///    sibling `MIGRATION_JOB_POLL_BACKOFF` / `SHINKA_MIGRATION_POLL_
///    BACKOFF` / `GITHUB_RUNNER_ROLLOUT_POLL_BACKOFF` / `FEDERATION_JOB_
///    POLL_BACKOFF` docstrings cite. Post-lift, the first poll still
///    waits 2s (preserving the seed verbatim), then 4s / 8s / 16s /
///    30s / 30s / … — ~7 iterations reach the 2-minute window under the
///    exponential-with-cap climb rather than 60 iterations under the
///    pre-lift flat 2s.
/// 2. **No caller-visible schedule invariant.** The bare
///    `tokio::time::Duration::from_secs(2)` literal at the poll-loop
///    sleep carried no name a shield could pin — a future edit that
///    changed the schedule at this site did not surface at any named-
///    primitive audit path. The lifted `SERVICES_HEALTHY_POLL_BACKOFF`
///    const names the (seed, factor, cap) triple a shield can cite and
///    enforce.
/// 3. **Count-bounded timeout coupled to the pre-lift schedule.** The
///    `attempts >= 60` cap encoded the 2-minute wall-clock budget as
///    `60 * 2s`, so any schedule change (this lift itself, a future seed
///    bump) silently invalidated the intended wall-clock semantics.
///    Post-lift the loop rebounds on wall-clock (`start.elapsed() >
///    SERVICES_HEALTHY_TIMEOUT`) — the schedule and the timeout are
///    named at two independent typed sites, mirroring the sibling
///    `services/migration_service.rs::MigrationService::wait_for_job`
///    wall-clock-bound loop.
///
/// `max_attempts: u32::MAX` is a placeholder — the poll loop is bounded
/// by wall-clock via [`SERVICES_HEALTHY_TIMEOUT`], not by attempt count —
/// and consumes only [`RetryPolicy::compute_delay`] from this policy,
/// not [`RetryPolicy::max_attempts`]. The `max_attempts` field is
/// unconsulted at this consumption site.
const SERVICES_HEALTHY_POLL_BACKOFF: RetryPolicy =
    RetryPolicy::wall_clock_poll(Duration::from_secs(2));

/// Wall-clock timeout on the docker-compose services-healthy poll loop —
/// preserves the pre-lift `60 * 2s = 2 minutes` intended budget the
/// `// 2 minutes (60 * 2s)` inline comment cited. Named as an independent
/// typed const so a future refinement of either the schedule
/// ([`SERVICES_HEALTHY_POLL_BACKOFF`]) or the wall-clock budget lands at
/// two named typed sites rather than fused into a single count-bounded
/// cap that couples the two invariants.
const SERVICES_HEALTHY_TIMEOUT: Duration = Duration::from_secs(120);

/// Backoff between docker-compose services-healthy poll iterations, given
/// a 0-indexed local `attempt` counter (the `loop { ... }` shape in
/// [`execute`]'s integration-test step drives increments once per
/// non-terminal iteration).
///
/// Maps the local 0-indexed counter to the 1-indexed
/// [`RetryPolicy::compute_delay`] attempt axis via `saturating_add(2)`:
/// local `attempt == 0` (the sleep after the first non-terminal poll)
/// reads as `compute_delay(2) = initial_backoff * factor^0 =
/// initial_backoff = 2s`; local `attempt == 1` reads as `compute_delay(3)
/// = 4s`; local `attempt == 2` reads as `compute_delay(4) = 8s`; local
/// `attempt == 3` reads as `compute_delay(5) = 16s`; local `attempt >= 4`
/// reads as `compute_delay(>=6) = 30s` (cap) — preserves the pre-lift
/// `tokio::time::sleep(tokio::time::Duration::from_secs(2))` seed
/// verbatim at the first poll and strictly diverges upward at every
/// later poll.
///
/// The `saturating_add` clamp forecloses the `u32` overflow class at the
/// bridge — a pathologically-long-running poll loop that reaches
/// `attempt == u32::MAX` reads as `compute_delay(u32::MAX)`, which itself
/// saturates to [`SERVICES_HEALTHY_POLL_BACKOFF::max_backoff`] via the
/// `checked_pow`-then-cap body inside [`RetryPolicy::compute_delay`]
/// without panic.
fn services_healthy_poll_delay(attempt: u32) -> Duration {
    SERVICES_HEALTHY_POLL_BACKOFF.poll_iteration_delay(attempt)
}

/// Resolve the `cargo` binary via the `CARGO` env override, falling
/// back to `cargo` on PATH. Every `cargo` spawn in this module reads
/// through this sigil so the resolve happens in exactly one place —
/// mirrors the `cargo_bin()` sigil at `commands/test_ci.rs:28`
/// (916f1a4), `commands/prerelease.rs:109` (79e03a5),
/// `commands/developer_tools.rs:36` (534ef48),
/// `commands/tool.rs:36` (9f6046b), and `commands/e2e.rs:88`
/// (170ecac), and the sibling `bun_bin()` / `crate2nix_bin()` /
/// `nix_bin()` sigil discipline every substrate-`<TOOL>` /
/// `<TOOL>_BIN`-routed spawn surface in forge with more than one
/// consumer site honors. Solve-once at the sigil (THEORY §I.5 —
/// duplication budget zero; every recurring shape becomes a helper
/// before it becomes duplicated code) means a future added `cargo`
/// spawn cannot silently re-copy the two-argument resolve and drift
/// away from the `CARGO` override at exactly the tier the
/// hermetic-runner contract binds.
///
/// Pre-lift the two consumer sites in [`execute`] — the Step 1/5
/// unit-test spawn (`cargo test --lib --bins`) and the Step 3/5
/// integration-test spawn (`cargo test --test * -- --ignored
/// --test-threads=1`) — each spelled the two-argument resolve
/// verbatim. Post-lift each site collapses to `let cargo =
/// cargo_bin();` and the resolve appears in exactly ONE place (the
/// sigil body). A Nix-hermetic runner exporting `CARGO=/nix/store/
/// …/bin/cargo` while omitting `cargo` from PATH would previously
/// make each consumer re-derive the same two-argument resolve
/// independently, so a future edit to the override contract would
/// have to touch each site rather than one.
fn cargo_bin() -> String {
    get_tool_path("CARGO", "cargo")
}

/// Resolve the `docker` binary via the `DOCKER_BIN` env override,
/// falling back to `docker` on PATH. Every `docker` spawn in this
/// module reads through this sigil so the two-argument resolve
/// appears in exactly ONE place (this sigil body) — mirrors the
/// sibling `docker_bin()` sigils at `commands/local.rs:31`,
/// `commands/infra.rs:33`, `commands/e2e.rs:36`, and
/// `commands/prerelease.rs:77`. Solve-once at the sigil (THEORY
/// §I.5 — duplication budget zero) means a future added `docker`
/// spawn cannot silently re-copy the resolve inline and drift from
/// the `DOCKER_BIN` override at exactly the tier the hermetic-runner
/// contract binds. The two-argument resolve string is spelled only
/// in the sigil body below, never in this docstring, so the
/// count-eq-1 shield in the test module cannot self-match against
/// this comment.
fn docker_bin() -> String {
    get_tool_path("DOCKER_BIN", "docker")
}

/// Resolve the `docker-compose` binary via the `DOCKER_COMPOSE_BIN`
/// env override, falling back to `docker-compose` on PATH. Every
/// `docker-compose` spawn in this module reads through this sigil
/// so the two-argument resolve appears in exactly ONE place (this
/// sigil body) — mirrors the sibling `docker_compose_bin()` sigil
/// at `commands/developer_tools.rs:86`. The pre-lift inline resolve
/// at the top of the integration-test step bound one var and passed
/// it through three consumer sites (`up -d`, `ps` poll, final
/// `down -v`); post-lift the resolve moves to the sigil body so a
/// future added docker-compose spawn cannot silently re-copy the
/// two-argument resolve inline. The two-argument resolve string is
/// spelled only in the sigil body below, never in this docstring,
/// so the count-eq-1 shield in the test module cannot self-match
/// against this comment.
fn docker_compose_bin() -> String {
    get_tool_path("DOCKER_COMPOSE_BIN", "docker-compose")
}

/// Resolve the `sqlx` binary via the `SQLX_BIN` env override,
/// falling back to `sqlx` on PATH. Every `sqlx` spawn in this
/// module reads through this sigil so the two-argument resolve
/// appears in exactly ONE place (this sigil body). Solve-once at
/// the sigil closes the silent-PATH-fallback bug class on the
/// `sqlx` surface the sibling `docker_bin` / `docker_compose_bin` /
/// `cargo_bin` sigils close elsewhere in this same module. The
/// two-argument resolve string is spelled only in the sigil body
/// below, never in this docstring, so the count-eq-1 shield in the
/// test module cannot self-match against this comment.
fn sqlx_bin() -> String {
    get_tool_path("SQLX_BIN", "sqlx")
}

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

        // Resolve the `cargo` binary path via the `cargo_bin()` sigil,
        // which routes through `CARGO` (falling back to `cargo` on
        // PATH) at a single point of truth. Matches the sibling
        // `cargo_bin()` sigil discipline in `commands/test_ci.rs`
        // (916f1a4) and `commands/developer_tools.rs` (534ef48) — a
        // Nix-hermetic runner's substrate-derived `CARGO` lands at the
        // unit-test gate that decides whether the comprehensive
        // release proceeds past Step 1/5.
        let cargo = cargo_bin();

        // Route the status-only unit-test spawn through the canonical
        // `crate::retry::run_inherited_status` primitive so the pre-lift
        // `.status().await.context("Failed to run cargo`
        // ` test")?` + `if !test_result.success() { anyhow::bail!("Unit`
        // ` tests failed - aborting release") }` stanza — which dropped
        // the exit code
        // from the operator log line (`test_result.code()` was in scope
        // and unread) — collapses onto the primitive and the canonical
        // `"unit tests failed (exit {code})"` envelope emerges by
        // construction at `retry::classify_inherited_status`'s ONE
        // body. Binding the outcome before the spinner-clear preserves
        // the pre-existing UX (spinner clears BEFORE the red ✗ line
        // and BEFORE the propagated bail) AND closes a latent leak on
        // the spawn-error path: pre-lift the `?` on `.context("Failed
        // to run cargo test")` ran BEFORE `spinner.finish_and_clear()`,
        // so a missing-cargo bubble left the terminal with a live
        // spinner animating beneath the printed error; post-lift the
        // spinner clears on every path (success, non-zero exit, AND
        // spawn error). Sibling of `commands/build.rs::execute` (72a7adf)
        // and `commands/github_runner_ci.rs::execute` (4510026) —
        // three `spinner + status-only cargo/nix spawn` sites past
        // THEORY §VI.1's three-times-is-a-law threshold.
        let mut test_cmd = Command::new(&cargo);
        test_cmd
            .current_dir(&working_dir)
            .args(&["test", "--lib", "--bins", "--", "--show-output"])
            .env("RUST_LOG", "info")
            .env("RUST_BACKTRACE", "1")
            .env("SQLX_OFFLINE", "true");
        let outcome = crate::retry::run_inherited_status(test_cmd, "unit tests").await;

        spinner.finish_and_clear();

        if let Err(err) = outcome {
            println!();
            println!("{}", "✗ Unit tests failed".red().bold());
            println!();
            return Err(err.context("aborting release"));
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

                // Resolve the `docker` binary path via `DOCKER_BIN`, falling
                // back to `docker` on `PATH`. Hoisted once and shared across
                // both the load + tag spawn sites below so a Nix-hermetic
                // runner's substrate-derived `DOCKER_BIN` lands at every
                // docker-invocation in the integration-test path — matching
                // the sibling docker-family sigils
                // (`commands/local.rs::docker_bin`,
                // `commands/infra.rs::docker_bin`,
                // `commands/e2e.rs::docker_bin`,
                // `commands/product_release.rs::push_prebuilt_image`) and
                // the file's own established `docker_compose_bin()`
                // sigil for the docker-compose spawn sites below.
                let docker = docker_bin();

                // Load Docker image
                let load_result = Command::new(&docker)
                    .current_dir(&working_dir)
                    .args(&["load", "-i", build_output])
                    .output()
                    .await
                    .context("Failed to load Docker image")?;

                if !load_result.status.success() {
                    anyhow::bail!("Failed to load Docker image");
                }

                // Extract image name from docker load output. The typed
                // primitive `crate::oci_manifest::docker_load_image_reference`
                // strips the `Loaded image[ ID]:` prefix in one step,
                // preserving the tag colon inside the reference and the
                // `sha256:` algorithm prefix inside an image-ID identity;
                // the prior `line.split(':').last()` scan lost both
                // (dropping the image name from `nginx:latest` → `latest`
                // and the algorithm prefix from `sha256:hex` → bare hex),
                // silently breaking the downstream `docker tag` step for
                // every real docker-load output.
                let load_output = String::from_utf8_lossy(&load_result.stdout);
                let image_name = load_output
                    .lines()
                    .find_map(crate::oci_manifest::docker_load_image_reference)
                    .ok_or_else(|| anyhow::anyhow!("Could not determine loaded image name"))?;

                info!("   Loaded: {}", image_name);

                // Tag for compose. Routed through
                // `crate::retry::run_inherited_status` so the pre-lift
                // `.status().await` + `.context("Failed to tag Docker
                // image")?` + `if !tag_result.success() { anyhow::bail!(
                // "Failed to tag Docker image") }` stanza — whose ad-hoc
                // bail named the phase but dropped the exit code
                // (`tag_result.code()` was in scope and unread) —
                // collapses onto the primitive and the canonical
                // `"docker tag <img> -> <compose_tag> failed (exit
                // {code})"` envelope emerges by construction at
                // `retry::classify_inherited_status`'s ONE body. Folds
                // the source-image and target-tag pair into the `op`
                // label so the operator log line names WHICH tag the
                // spawn was staging when it failed, with the exit code
                // the pre-lift stanza dropped now preserved at the
                // operator surface by construction. Sibling of the
                // async-frontier lifts already on this primitive
                // (`commands/{build, github_runner_ci, image_release,
                // pangea, product_release, rust_service, search_sync,
                // typescript}.rs`, 72a7adf / 4510026 / b5d9573 /
                // c5ff1c4 / bf6d836 / 5b5c765 / b864fd8 / a3c3a49).
                let compose_tag = format!("{}:latest", registry);
                info!("🏷️  Tagging image: {}", compose_tag);

                let mut tag_cmd = Command::new(&docker);
                tag_cmd.args(["tag", image_name, &compose_tag]);
                let tag_op = format!("docker tag {} -> {}", image_name, compose_tag);
                crate::retry::run_inherited_status(tag_cmd, &tag_op).await?;

                println!();
                info!("🚀 Starting docker-compose environment...");

                let docker_compose = docker_compose_bin();

                // Start docker-compose
                let up_result = Command::new(&docker_compose)
                    .current_dir(&working_dir)
                    .args(&["-f", compose_path, "up", "-d"])
                    .status()
                    .await
                    .context("Failed to start docker-compose")?;

                if !up_result.success() {
                    // Cleanup on failure — best-effort async
                    // `docker-compose down -v` whose exit envelope is
                    // deliberately discarded (a cleanup failure must
                    // not mask the "failed to start docker-compose"
                    // bail below) and whose stdio inherits both
                    // streams so the operator sees which containers
                    // compose actually tore down.
                    crate::retry::run_status_discard_in_async(
                        &docker_compose,
                        &working_dir,
                        &["-f", compose_path, "down", "-v"],
                    )
                    .await;
                    anyhow::bail!("Failed to start docker-compose");
                }

                // Wait for services to be healthy
                info!("⏳ Waiting for services to be healthy...");
                let health_start = Instant::now();
                let mut backoff_attempt: u32 = 0;

                loop {
                    let ps_result = Command::new(&docker_compose)
                        .current_dir(&working_dir)
                        .args(&["-f", compose_path, "ps"])
                        .output()
                        .await?;

                    let ps_output = String::from_utf8_lossy(&ps_result.stdout);
                    if ps_output.contains("healthy") || ps_output.contains("Up") {
                        break;
                    }

                    if health_start.elapsed() >= SERVICES_HEALTHY_TIMEOUT {
                        // Show logs and cleanup — both best-effort
                        // async spawns whose exit envelope is
                        // discarded (the enclosing bail! is the
                        // authoritative failure) and whose stdio
                        // inherits both streams so the operator sees
                        // the compose logs that name why services
                        // never went healthy AND which containers
                        // compose actually tore down.
                        crate::retry::run_status_discard_in_async(
                            &docker_compose,
                            &working_dir,
                            &["-f", compose_path, "logs"],
                        )
                        .await;

                        crate::retry::run_status_discard_in_async(
                            &docker_compose,
                            &working_dir,
                            &["-f", compose_path, "down", "-v"],
                        )
                        .await;

                        anyhow::bail!("Timeout waiting for services to become healthy");
                    }

                    tokio::time::sleep(services_healthy_poll_delay(backoff_attempt)).await;
                    backoff_attempt = backoff_attempt.saturating_add(1);
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

                    // Resolve the `sqlx` binary path via `SQLX_BIN` for the
                    // migrate spawn — shares the sibling sigil discipline of
                    // the docker / docker-compose / cargo lifts elsewhere in
                    // this module so the migrate step names the same
                    // substrate-derived sqlx-cli derivation on a
                    // Nix-hermetic runner. A bare literal spawn would
                    // silently fall through to whatever `sqlx` binary is
                    // first on PATH — the same silent-PATH-fallback bug
                    // class the sibling shields below close for docker /
                    // docker-compose / cargo in this same file. The shield
                    // asserts the forbidden literal shape is absent from
                    // the module body, so this comment names the bug class
                    // without spelling the exact string the shield scans
                    // for.
                    let sqlx_bin = sqlx_bin();
                    let migrate_result = Command::new(&sqlx_bin)
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
                            warn!(
                                "   This might indicate a database connection issue or migration error"
                            );
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

                // Resolve the `cargo` binary path via the `cargo_bin()`
                // sigil for the integration-test spawn — shares the
                // sibling sigil discipline of `commands/test_ci.rs`
                // (916f1a4) and `commands/developer_tools.rs`
                // (534ef48) so the integration-test invocation and the
                // unit-test invocation above both name the same
                // substrate-derived cargo derivation on a Nix-hermetic
                // runner via the module's single point of truth.
                let cargo = cargo_bin();

                let integration_test_result = Command::new(&cargo)
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

                    // Best-effort async `docker-compose logs
                    // --tail=100` diagnostic — exit envelope discarded
                    // (the caller renders logs FOR debugging, so a
                    // logs-spawn failure must not mask the underlying
                    // integration-test failure) and stdio inherits
                    // both streams so the last-100-lines-per-service
                    // dump reaches the operator's terminal directly.
                    crate::retry::run_status_discard_in_async(
                        &docker_compose,
                        &working_dir,
                        &["-f", compose_path, "logs", "--tail=100"],
                    )
                    .await;

                    println!();
                }

                // Always cleanup compose environment
                info!("🧹 Cleaning up docker-compose environment...");
                let cleanup_result = Command::new(&docker_compose)
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

#[cfg(test)]
mod tests {
    use super::{
        services_healthy_poll_delay, SERVICES_HEALTHY_POLL_BACKOFF, SERVICES_HEALTHY_TIMEOUT,
    };
    use crate::retry::RetryPolicy;
    use std::time::Duration;

    // ====================================================================
    // SERVICES_HEALTHY_POLL_BACKOFF / services_healthy_poll_delay shields
    // ====================================================================
    //
    // These pin the `RetryPolicy`-consuming replacement of the pre-lift
    // bare fixed `tokio::time::sleep(tokio::time::Duration::from_secs(2))
    // .await` at the docker-compose services-healthy poll loop in
    // `execute`'s integration-test step. Sibling of the
    // `MIGRATION_JOB_POLL_BACKOFF` shields at
    // `services/migration_service.rs::tests` (commit ac61874), the
    // `SHINKA_MIGRATION_POLL_BACKOFF` shields at
    // `commands/migrations.rs::tests` (commit b962db5), and the
    // `FEDERATION_JOB_POLL_BACKOFF` / `GITHUB_RUNNER_ROLLOUT_POLL_BACKOFF`
    // shields at `commands/federation_tests.rs::tests` /
    // `commands/github_runner_ci.rs::tests` (commits 8319fa2 / 7fe79de).

    /// The `(initial_backoff, factor, max_backoff)` shape of the
    /// docker-compose services-healthy poll-backoff policy is a load-
    /// bearing invariant shared with every sibling `_POLL_BACKOFF`
    /// const across the fleet — all consume the same
    /// `RetryPolicy::network()` `(factor=2, max_backoff=30s)` reference
    /// schedule and diverge only at `initial_backoff` to preserve their
    /// respective pre-lift seeds verbatim. Pinned here so a future
    /// silent-desync at the const site (a factor bump, a cap change, a
    /// seed drift) is caught at a named test rather than silently
    /// propagating across the two consumption sites
    /// (`services_healthy_poll_delay` + the loop body).
    #[test]
    fn test_services_healthy_poll_backoff_policy_shape() {
        assert_eq!(
            SERVICES_HEALTHY_POLL_BACKOFF.initial_backoff,
            Duration::from_secs(2),
            "SERVICES_HEALTHY_POLL_BACKOFF.initial_backoff must be 2s \
             — preserves the pre-lift bare `tokio::time::sleep(\
             tokio::time::Duration::from_secs(2))` seed verbatim at the \
             poll loop's first sleep.",
        );
        assert_eq!(
            SERVICES_HEALTHY_POLL_BACKOFF.factor, 2,
            "SERVICES_HEALTHY_POLL_BACKOFF.factor must be 2 \
             — the Bazel/Buck2/SLSA-frontier reference doubling climb \
             the sibling `RetryPolicy::network()` factory also emits.",
        );
        assert_eq!(
            SERVICES_HEALTHY_POLL_BACKOFF.max_backoff,
            Duration::from_secs(30),
            "SERVICES_HEALTHY_POLL_BACKOFF.max_backoff must be 30s \
             — the Bazel/Buck2/SLSA-frontier 30s cap the sibling \
             `RetryPolicy::network()` factory also emits.",
        );
    }

    /// Pre-lift the poll loop emitted a flat `tokio::time::sleep(\
    /// tokio::time::Duration::from_secs(2))` at every non-terminal
    /// iteration. Post-lift the first iteration preserves that 2s seed
    /// verbatim (`services_healthy_poll_delay(0) == 2s`); every later
    /// iteration strictly diverges upward under the exponential-with-cap
    /// climb (`4s → 8s → 16s → 30s → …`) rather than re-emitting the
    /// pre-lift `2s` flat.
    #[test]
    fn test_services_healthy_poll_delay_matches_pre_lift_seed_and_climbs() {
        assert_eq!(
            services_healthy_poll_delay(0),
            Duration::from_secs(2),
            "iter 0 must sleep 2s — matches pre-lift `tokio::time::\
             sleep(tokio::time::Duration::from_secs(2))` seed verbatim.",
        );
        assert_eq!(
            services_healthy_poll_delay(1),
            Duration::from_secs(4),
            "iter 1 must sleep 4s — pre-lift stayed flat at 2s; \
             post-lift climbs `initial_backoff * factor = 4s`.",
        );
        assert_eq!(
            services_healthy_poll_delay(2),
            Duration::from_secs(8),
            "iter 2 must sleep 8s — pre-lift stayed flat at 2s; \
             post-lift climbs `initial_backoff * factor^2 = 8s`.",
        );
        assert_eq!(
            services_healthy_poll_delay(3),
            Duration::from_secs(16),
            "iter 3 must sleep 16s — pre-lift stayed flat at 2s; \
             post-lift climbs `initial_backoff * factor^3 = 16s`.",
        );
    }

    /// Iterations past the cap must all emit `max_backoff = 30s` —
    /// pre-lift stayed flat at 2s at every iteration, so a slow-boot
    /// docker-compose stack (say, a Postgres pull-then-init the pre-lift
    /// 60-attempt cap sized against) would emit ~60 `docker-compose ps`
    /// probes over the 2-minute window; post-lift the climb caps at 30s
    /// and the same 2-minute window emits ~7 probes.
    #[test]
    fn test_services_healthy_poll_delay_caps_at_max_backoff_past_the_cap() {
        assert_eq!(
            services_healthy_poll_delay(4),
            Duration::from_secs(30),
            "iter 4 must sleep 30s (cap) — `initial_backoff * factor^4 \
             = 32s`, clamped to `max_backoff = 30s`.",
        );
        assert_eq!(
            services_healthy_poll_delay(5),
            Duration::from_secs(30),
            "iter 5 must sleep 30s (cap).",
        );
        assert_eq!(
            services_healthy_poll_delay(50),
            Duration::from_secs(30),
            "iter 50 must sleep 30s (cap) — long-boot compose stacks \
             can poll for minutes past the cap, so beyond-cap iterations \
             must stay at the ceiling rather than drifting upward.",
        );
    }

    /// The poll loop is bounded by wall-clock via
    /// [`SERVICES_HEALTHY_TIMEOUT`], not by attempt count, so
    /// `backoff_attempt` can in principle reach any `u32` value on a
    /// pathologically-fast poll-arm (a stub docker-compose that returns
    /// instantly against a lengthened `SERVICES_HEALTHY_TIMEOUT`). This
    /// test pins that composition: an `attempt == u32::MAX` argument
    /// returns a bounded delay rather than panicking. The
    /// `saturating_add(2)` bridge inside `services_healthy_poll_delay`
    /// clamps to `u32::MAX`, and [`RetryPolicy::compute_delay`]'s
    /// `checked_pow`-then-cap body itself saturates to `max_backoff`
    /// without panic.
    #[test]
    fn test_services_healthy_poll_delay_saturates_without_panic_at_arbitrarily_large_attempt() {
        assert_eq!(
            services_healthy_poll_delay(u32::MAX),
            Duration::from_secs(30),
            "attempt=u32::MAX must saturate to max_backoff without \
             panic — the `saturating_add(2)` bridge + `RetryPolicy::\
             compute_delay`'s `checked_pow` cap close the u32 overflow \
             class by construction.",
        );
        assert_eq!(
            services_healthy_poll_delay(u32::MAX - 1),
            Duration::from_secs(30),
            "attempt=u32::MAX - 1 must also saturate to max_backoff — \
             the bridge `saturating_add(2)` returns u32::MAX, still far \
             past the cap.",
        );
    }

    /// The `(factor, max_backoff)` pair of `SERVICES_HEALTHY_POLL_BACKOFF`
    /// matches the Bazel/Buck2/SLSA-frontier reference schedule the retry
    /// module cites at [`RetryPolicy::network`]'s docstring. The docker-
    /// compose services-healthy poll policy diverges only at
    /// `initial_backoff` (2s vs 250ms) to preserve the pre-lift bare
    /// `tokio::time::sleep(tokio::time::Duration::from_secs(2))` seed
    /// verbatim. Pin the shared invariants so a future refinement to
    /// the retry module's reference schedule surfaces the intentional
    /// services-healthy-side divergence as a named test failure rather
    /// than silently propagating. Sibling of
    /// `test_migration_job_poll_backoff_shares_network_factor_and_cap`
    /// at `services/migration_service.rs::tests` (commit ac61874).
    #[test]
    fn test_services_healthy_poll_backoff_shares_network_factor_and_cap() {
        let network = RetryPolicy::network();
        assert_eq!(
            SERVICES_HEALTHY_POLL_BACKOFF.factor, network.factor,
            "SERVICES_HEALTHY_POLL_BACKOFF.factor must match \
             RetryPolicy::network().factor — both consume the \
             Bazel/Buck2/SLSA-frontier factor=2 reference.",
        );
        assert_eq!(
            SERVICES_HEALTHY_POLL_BACKOFF.max_backoff, network.max_backoff,
            "SERVICES_HEALTHY_POLL_BACKOFF.max_backoff must match \
             RetryPolicy::network().max_backoff — both consume the \
             Bazel/Buck2/SLSA-frontier 30s cap reference.",
        );
    }

    /// The wall-clock timeout on the services-healthy poll loop must
    /// remain the pre-lift intended `60 * 2s = 120s` budget the removed
    /// inline `// 2 minutes (60 * 2s)` comment cited. Pin the const so a
    /// future silent bump does not decouple the observed wall-clock
    /// behavior from the load-bearing 2-minute intent.
    #[test]
    fn test_services_healthy_timeout_preserves_pre_lift_two_minute_budget() {
        assert_eq!(
            SERVICES_HEALTHY_TIMEOUT,
            Duration::from_secs(120),
            "SERVICES_HEALTHY_TIMEOUT must be 120s — preserves the \
             pre-lift `60 * 2s = 2 minutes` intended wall-clock budget \
             at the docker-compose services-healthy poll loop.",
        );
    }

    /// The docker-compose services-healthy poll loop body MUST consume
    /// the typed primitive at `services_healthy_poll_delay(\
    /// backoff_attempt)` rather than the pre-lift bare `tokio::time::\
    /// sleep(tokio::time::Duration::from_secs(2))` literal. A future
    /// refactor that reintroduces the fixed-literal shape (see
    /// `SERVICES_HEALTHY_POLL_BACKOFF`'s docstring for the three
    /// structural defects the lift closed) fails here, not silently in
    /// production where a slow-booting compose stack would resume
    /// flooding the docker daemon with ~60 probes over its 2-minute
    /// window. Whole-module boundary discipline sibling of
    /// `test_wait_for_job_consumes_typed_poll_delay_not_bare_fixed_sleep`
    /// at `services/migration_service.rs::tests` (commit ac61874) and
    /// `test_wait_for_shinka_migration_consumes_typed_poll_delay_not_mut_backoff_secs`
    /// at `commands/migrations.rs::tests` (commit b962db5).
    ///
    /// Uses the [`crate::test_support::code_line_hits`] helper so the
    /// shield does not false-positive on `SERVICES_HEALTHY_POLL_BACKOFF`'s
    /// own docstring above (which cites the pre-lift shape as context
    /// for the three defects it forecloses). The forbidden literal is
    /// reconstructed at test time via [`format!`] and the diagnostic
    /// prose refers to it only via the reconstructed `bespoke_needle`
    /// (never the fused literal), so the assert message body itself
    /// stays unmatchable — same code-line-filter-plus-format-
    /// reconstruction discipline sibling shields 4163c7e / ffa5271 /
    /// fa2c702 / a7d5375 / ab06395 use.
    ///
    /// The scan is bounded strictly to the pre-tests module body — from
    /// the module start through the `#[cfg(test)]\nmod tests {` marker
    /// — so this shield's own docstring mention of `tokio::time::sleep(\
    /// tokio::time::Duration::from_secs(2))` (which lives inside this
    /// `#[cfg(test)] mod tests` block below that marker) stays out of
    /// scope AND every current or future sleep-emitting helper landing
    /// anywhere in the top-level module body cannot silently ride along
    /// without going through the primitive.
    #[test]
    fn test_execute_consumes_typed_poll_delay_not_bare_fixed_sleep() {
        let module_body = crate::test_support::module_body_before_tests(
            include_str!("comprehensive_release.rs"),
            "commands/comprehensive_release.rs",
        );

        let bespoke_needle = format!(
            "tokio::time::sleep(tokio::time::Duration::from_secs({}))",
            SERVICES_HEALTHY_POLL_BACKOFF.initial_backoff.as_secs(),
        );
        let bespoke_hits = crate::test_support::code_line_hits(module_body, &bespoke_needle);
        assert!(
            bespoke_hits.is_empty(),
            "commands/comprehensive_release.rs must NOT re-fuse the pre-lift \
             bare fixed sleep at the poll loop — the schedule lives at \
             `SERVICES_HEALTHY_POLL_BACKOFF` + `services_healthy_poll_delay`, \
             both grounding through `RetryPolicy::compute_delay`. Found \
             code-line hits: {:#?}",
            bespoke_hits,
        );
        let delegation_hits = crate::test_support::code_line_hits(
            module_body,
            "services_healthy_poll_delay(backoff_attempt)",
        );
        assert!(
            !delegation_hits.is_empty(),
            "commands/comprehensive_release.rs must consume the typed \
             poll-delay helper at the poll loop's sleep site — the \
             canonical delegation call was not found at any code line.",
        );
    }

    /// Whole-module shield: no raw `Command::new("docker-compose")` may live in
    /// this module's non-test body. Every `docker-compose` spawn in
    /// `commands/comprehensive_release.rs` must first resolve `DOCKER_COMPOSE_BIN`
    /// via [`crate::repo::get_tool_path`] — the canonical env-var override
    /// idiom every sibling docker-family surface honors
    /// (`commands/local.rs::docker_bin`, `commands/e2e.rs::docker_bin` via
    /// `DOCKER_BIN` at 1a984dd / 23241a6; `commands/developer_tools.rs`'s
    /// two docker-compose sites via `DOCKER_COMPOSE_BIN` at bdb7fb0).
    ///
    /// Pre-lift the seven consumer sites in `execute` (the integration-test
    /// step's docker-compose up / cleanup-on-failure / ps-poll loop / logs-
    /// on-timeout / down-on-timeout / logs-on-test-failure / final cleanup)
    /// each spelled `Command::new("docker-compose")` verbatim, ignoring
    /// `DOCKER_COMPOSE_BIN` at all seven. A Nix-hermetic runner with a
    /// store-path `docker-compose` binary silently fell through to whatever
    /// `docker-compose` was first on PATH — the same silent-PATH-fallback
    /// bug class the sibling `commands/developer_tools.rs` shield closed at
    /// bdb7fb0 for its two docker-compose sites, and the `DOCKER_BIN` lifts
    /// (1a984dd / 23241a6) closed for the sibling `docker` surface across
    /// `commands/local.rs` and `commands/e2e.rs`.
    ///
    /// The scan bounds on the whole-module boundary (from the file start
    /// to the FIRST `\n#[cfg(test)]\nmod tests {` marker in source order,
    /// which lands at this shield's `#[cfg(test)] mod tests` opener) so
    /// this shield's own docstring mentions of `Command::new("docker-compose")`
    /// — living in a `#[cfg(test)]` block below that first marker — stay
    /// out of scope AND every current or future docker-compose-spawning
    /// helper landing anywhere in the top-level module body cannot silently
    /// ride along without going through `DOCKER_COMPOSE_BIN`. Mirrors the
    /// whole-module-boundary scan discipline of the sibling
    /// `commands/developer_tools.rs::tests::test_developer_tools_routes_docker_compose_through_docker_compose_bin_not_raw_command`
    /// (bdb7fb0) and the lineage traced there.
    #[test]
    fn test_comprehensive_release_routes_docker_compose_through_docker_compose_bin_not_raw_command()
    {
        crate::test_support::assert_source_routes_bare_spawn_through_sigil_bin_fn_at_exactly_one_resolve(
            include_str!("comprehensive_release.rs"),
            "commands/comprehensive_release.rs",
            "docker-compose",
            "DOCKER_COMPOSE_BIN",
        );
    }

    /// Whole-module shield: no raw `Command::new("docker")` may live in
    /// this module's non-test body. Every `docker` spawn in
    /// `commands/comprehensive_release.rs` must first resolve `DOCKER_BIN`
    /// via [`crate::repo::get_tool_path`] — the canonical env-var override
    /// idiom every sibling docker-family surface honors
    /// (`commands/local.rs::docker_bin`, `commands/infra.rs::docker_bin`,
    /// `commands/e2e.rs::docker_bin` via `DOCKER_BIN` at 1a984dd / 7f49465
    /// / 23241a6; `commands/product_release.rs::push_prebuilt_image` via
    /// `DOCKER_BIN` at b7d432f; `commands/prerelease.rs`'s three docker
    /// diag spawns via `DOCKER_BIN` at 7c096f8).
    ///
    /// Pre-lift the two consumer sites in `execute` — the integration-test
    /// step's `docker load -i <archive>` and downstream `docker tag
    /// <image_name> <compose_tag>` — each spelled `Command::new("docker")`
    /// verbatim, ignoring `DOCKER_BIN` at both sites. A Nix-hermetic
    /// runner with a store-path `docker` binary silently fell through to
    /// whatever `docker` was first on PATH — the same silent-PATH-fallback
    /// bug class the sibling docker-compose shield above closed for the
    /// seven docker-compose sites, and the sibling `DOCKER_BIN` lifts
    /// (1a984dd / 7f49465 / 23241a6 / b7d432f / 7c096f8) closed across the
    /// docker surface elsewhere in the fleet.
    ///
    /// The scan bounds on the whole-module boundary (from the file start
    /// to the FIRST `\n#[cfg(test)]\nmod tests {` marker in source order,
    /// which lands at the sibling shield's `#[cfg(test)] mod tests`
    /// opener above) so this shield's own docstring mentions of
    /// `Command::new("docker")` — living in a `#[cfg(test)]` block below
    /// that first marker — stay out of scope AND every current or future
    /// docker-spawning helper landing anywhere in the top-level module
    /// body cannot silently ride along without going through `DOCKER_BIN`.
    /// Mirrors the whole-module-boundary scan discipline of the sibling
    /// docker-compose shield above.
    #[test]
    fn test_comprehensive_release_routes_docker_through_docker_bin_not_raw_command() {
        crate::test_support::assert_source_routes_bare_spawn_through_sigil_bin_fn_at_exactly_one_resolve(
            include_str!("comprehensive_release.rs"),
            "commands/comprehensive_release.rs",
            "docker",
            "DOCKER_BIN",
        );
    }

    /// Whole-module shield: no raw `Command::new("cargo")` may live
    /// in this module's non-test body, `fn cargo_bin()` must be
    /// defined, and the two-argument `CARGO` resolve must appear
    /// exactly ONCE in the module body (only in the sigil body).
    ///
    /// Pre-lift the two consumer sites in `execute` — the Step 1/5
    /// unit-test spawn (`cargo test --lib --bins`) and the Step 3/5
    /// integration-test spawn (`cargo test --test * -- --ignored
    /// --test-threads=1`) — each spelled the two-argument resolve
    /// verbatim at each consumer. Post-lift each site collapses to
    /// `let cargo = cargo_bin();` and the resolve appears in exactly
    /// ONE place (the sigil body). The `resolve_count == 1`
    /// assertion fails-before at 2, passes-after at 1 — the canonical
    /// fail-before-pass-after arc matching the sibling `<tool>_bin()`
    /// shield discipline landed on `commands/test_ci.rs::cargo_bin`
    /// (916f1a4), `commands/developer_tools.rs::cargo_bin` (534ef48),
    /// `commands/tool.rs::cargo_bin` (9f6046b),
    /// `commands/e2e.rs::cargo_bin` (170ecac),
    /// `commands/frontend_validation.rs::bun_bin` (9986f11), and the
    /// broader NIX_BIN / CRATE2NIX / BUN_BIN sigil family. A
    /// Nix-hermetic runner with a store-path `cargo` binary that
    /// pre-lift silently fell through to whatever `cargo` was first
    /// on PATH — the same silent-PATH-fallback bug class the sibling
    /// `commands/test_ci.rs` shield closed at 916f1a4 and
    /// `commands/developer_tools.rs` shield closed at 534ef48, and
    /// the sibling `DOCKER_BIN` / `DOCKER_COMPOSE_BIN` shields above
    /// closed for the docker surface in this same file — is now
    /// closed by construction on the cargo surface too.
    ///
    /// The scan bounds on the whole-module boundary (from the file
    /// start to the FIRST `\n#[cfg(test)]\nmod tests {` marker in
    /// source order, which lands at the sibling docker-compose
    /// shield's `#[cfg(test)] mod tests` opener at the top of this
    /// block) so this shield's own docstring mentions of
    /// `Command::new("cargo")` — living in a `#[cfg(test)]` block
    /// below that first marker — stay out of scope AND every current
    /// or future cargo-spawning helper landing anywhere in the
    /// top-level module body cannot silently ride along without going
    /// through `cargo_bin()`. Mirrors the whole-module-boundary scan
    /// discipline of the sibling docker / docker-compose shields
    /// above and the lineage traced there.
    ///
    /// The two-argument-resolve needle is reconstructed via `format!`
    /// inside [`crate::test_support::get_tool_path_two_arg_call_needle`],
    /// so this shield's own source never contains the literal
    /// two-argument CARGO resolve string and cannot false-match
    /// itself on the count-eq-1 assertion.
    #[test]
    fn test_comprehensive_release_routes_cargo_through_cargo_bin_sigil_not_raw_command() {
        crate::test_support::assert_source_routes_bare_spawn_through_sigil_bin_fn_at_exactly_one_resolve(
            include_str!("comprehensive_release.rs"),
            "commands/comprehensive_release.rs",
            "cargo",
            "CARGO",
        );
    }

    /// Whole-module shield: no raw `Command::new("sqlx")` may live in
    /// this module's non-test body. Every `sqlx` spawn in
    /// `commands/comprehensive_release.rs` must first resolve `SQLX_BIN`
    /// via [`crate::repo::get_tool_path`] — the canonical env-var
    /// override idiom every sibling sqlx-consuming surface honors
    /// (`commands/developer_tools.rs::rust_dev`'s `sqlx_cmd` fallback
    /// path, whose CLI-arg-first resolution now falls through to
    /// `SQLX_BIN` before bare PATH — the last consumer of the raw
    /// `"sqlx"` fallback string anywhere in forge).
    ///
    /// Pre-lift the one consumer site in `execute` — the integration-
    /// test step's `sqlx migrate run --database-url <db_url> --source
    /// <migrations_dir>` migration invocation — spelled
    /// `Command::new("sqlx")` verbatim, ignoring `SQLX_BIN`. A
    /// Nix-hermetic runner with a store-path `sqlx-cli` binary silently
    /// fell through to whatever `sqlx` was first on PATH — the same
    /// silent-PATH-fallback bug class the sibling `docker` /
    /// `docker-compose` / `cargo` shields above closed for those three
    /// tool surfaces in this same file, and every sibling
    /// `{TOOL}_BIN`-lifted shield across the fleet closed for the
    /// respective tool.
    ///
    /// The scan bounds on the whole-module boundary (from the file
    /// start to the FIRST `\n#[cfg(test)]\nmod tests {` marker in
    /// source order, which lands at the sibling docker-compose
    /// shield's `#[cfg(test)] mod tests` opener above) so this
    /// shield's own docstring mentions of `Command::new("sqlx")` —
    /// living in a `#[cfg(test)]` block below that first marker —
    /// stay out of scope AND every current or future sqlx-spawning
    /// helper landing anywhere in the top-level module body cannot
    /// silently ride along without going through `SQLX_BIN`. Mirrors
    /// the whole-module-boundary scan discipline of the sibling
    /// docker / docker-compose / cargo shields above and the lineage
    /// traced there.
    ///
    /// The forbidden `Command::new("sqlx")` shape is reconstructed at
    /// test time via `format!` so the shield's own source text does
    /// not false-match itself — mirrors the anti-self-match discipline
    /// the sibling `SEA_ORM_CLI_BIN` shield (b037895) established.
    #[test]
    fn test_comprehensive_release_routes_sqlx_through_sqlx_bin_not_raw_command() {
        crate::test_support::assert_source_routes_bare_spawn_through_sigil_bin_fn_at_exactly_one_resolve(
            include_str!("comprehensive_release.rs"),
            "commands/comprehensive_release.rs",
            "sqlx",
            "SQLX_BIN",
        );
    }

    /// Marker-scoped shield: the `docker tag` block inside
    /// [`super::execute`] (the integration-test step's "Tag for compose"
    /// spawn that stages the loaded OCI image under `<registry>:latest`
    /// for the sibling `docker-compose up`) MUST route through
    /// [`crate::retry::run_inherited_status`], never through a
    /// hand-rolled inline builder terminated by a `.status().await`
    /// then `.context(…)?` then `if !status.success() { anyhow::bail!(
    /// FAIL_MSG) }` stanza that drops the exit code from the operator
    /// log line.
    ///
    /// Pre-lift the site spelled the seven-line stanza with a pair of
    /// ad-hoc failure messages (a `.context("Failed to tag Docker
    /// image")?` builder-terminator suffix followed by a `bail!(
    /// "Failed to tag Docker image")` inline bail) that named the
    /// phase but dropped the exit code `tag_result.code()` returned —
    /// the same class the async primitive was written to close
    /// (retry.rs `classify_inherited_status`). Post-lift the
    /// delegation call routes through the primitive and the canonical
    /// `"docker tag <img> -> <compose_tag> failed (exit {code})"`
    /// envelope emerges by construction at the primitive's ONE body,
    /// the shape every sibling on the async spawn frontier
    /// (`commands/{build, github_runner_ci, image_release, pangea,
    /// product_release, rust_service, search_sync, typescript}.rs`,
    /// 72a7adf / 4510026 / b5d9573 / c5ff1c4 / bf6d836 / 5b5c765 /
    /// b864fd8 / a3c3a49) already emits.
    ///
    /// # Why marker-scoped, not whole-module
    ///
    /// `super::execute` intentionally carries many other `.status().await`
    /// terminators — the docker-compose up spawn (has a compose-down
    /// cleanup branch on failure that must run BEFORE the bail), the
    /// docker-compose ps / logs / down fire-and-forget cleanups (`let _
    /// = …status().await;`), the sqlx migrate warn-on-failure spawn
    /// (match-based dispatch, no bail), and the integration-test spawn
    /// (deferred bail so cleanup runs first). The cargo unit-test
    /// spawn in Step 1/5 — previously listed here as a legitimate
    /// remaining site because "spinner-clear must run between the
    /// status and the bail" — now routes through the same primitive
    /// via the `let outcome = run_inherited_status(...).await;
    /// spinner.finish_and_clear(); if let Err(err) = outcome { ...;
    /// return Err(err.context(...)) }` shape that `commands/build.rs`
    /// (72a7adf) and `commands/github_runner_ci.rs` (4510026) already
    /// use for the same spinner-wrapped Nix build spawn; its shield
    /// is `test_unit_test_spawn_routes_through_run_inherited_status`
    /// below. None of the remaining legitimate sites lift cleanly onto
    /// `run_inherited_status`, so a
    /// whole-module shield would false-fire on legitimate remaining
    /// sites. This shield bounds the negative scan to ONLY the docker-
    /// tag block via [`crate::test_support::fn_body_slice_between_markers`]
    /// (open marker `// Tag for compose. Routed through`, end marker
    /// `// Start docker-compose`) so the discipline is tight against
    /// the block-under-migration and leaves the surrounding legitimate
    /// stanzas alone. Sibling of `commands/search_sync.rs::tests::
    /// test_run_sync_via_kubectl_cp_spawn_routes_through_run_inherited_status`
    /// (b864fd8), which uses the same primitive to bound its shield
    /// tightly around one function's `kubectl cp` block while excluding
    /// a sibling `let _ = …status().await;` best-effort cleanup at the
    /// tail of the same function.
    ///
    /// # Anti-self-match discipline
    ///
    /// The pre-lift `.context(…)?` and `bail!(…)` needles are
    /// reconstructed at test time via `format!` so this shield's own
    /// docstring — which names the pre-lift shape only in prose above
    /// — does not false-match itself against the module-body scan.
    /// Positive side pins that `crate::retry::run_inherited_status(`
    /// appears in the sliced block at ≥1 line, so a regression that
    /// dropped the delegation cannot leave the negative scan trivially
    /// satisfied by absence.
    #[test]
    fn test_docker_tag_spawn_routes_through_run_inherited_status() {
        const SOURCE: &str = include_str!("comprehensive_release.rs");

        let block = crate::test_support::fn_body_slice_between_markers(
            SOURCE,
            "commands/comprehensive_release.rs",
            "// Tag for compose. Routed through",
            "// Start docker-compose",
        );

        let pre_lift_context = format!(".context({}Failed to tag Docker image{})", '"', '"');
        assert!(
            !block.contains(&pre_lift_context),
            "commands/comprehensive_release.rs must not re-inline the \
             pre-lift `.context(…)?` stanza on the `docker tag` spawn \
             — every status-only spawn in this block must route \
             through `crate::retry::run_inherited_status`, which carries \
             the exit code into the failure envelope."
        );

        let pre_lift_bail = format!("bail!({}Failed to tag Docker image{})", '"', '"');
        assert!(
            !block.contains(&pre_lift_bail),
            "commands/comprehensive_release.rs must not re-inline the \
             pre-lift `bail!(…)` on the `docker tag` spawn — the \
             ad-hoc message dropped the exit code `tag_result.code()` \
             returned. `run_inherited_status`'s canonical \
             `\"{{op}} failed (exit {{code}})\"` envelope preserves it."
        );

        assert!(
            block.contains("crate::retry::run_inherited_status("),
            "commands/comprehensive_release.rs must dispatch its \
             `docker tag` spawn through \
             `crate::retry::run_inherited_status` — the delegation \
             string was not found in the docker-tag block."
        );
    }

    /// Whole-module delegation-count shield: the four best-effort
    /// async `docker-compose` cleanup / diagnostic spawns in
    /// `execute` — services-up-failure `down -v` cleanup, services-
    /// healthy-timeout `logs`, services-healthy-timeout `down -v`
    /// cleanup, and integration-test-failure `logs --tail=100`
    /// diagnostic — must each dispatch through the shared
    /// `crate::retry::run_status_discard_in_async` primitive rather
    /// than re-inline the pre-lift six-line stanza
    ///
    /// ```text
    /// let _ = Command::new(&docker_compose)
    ///     .current_dir(&working_dir)
    ///     .args(&[…])
    ///     .status()
    ///     .await;
    /// ```
    ///
    /// Pre-lift the four sites carried this stanza verbatim modulo
    /// the per-site argv slice — four identically-shaped bodies past
    /// THEORY §VI.1's three-is-a-law threshold (PRIME DIRECTIVE:
    /// duplication budget is zero). The lift onto
    /// [`crate::retry::run_status_discard_in_async`] preserves the
    /// exact pre-lift semantics — spawn `Err` is swallowed, spawn
    /// `Ok` discards the entire `io::Result<ExitStatus>` regardless
    /// of `output.status`, and the child's stdout and stderr remain
    /// inherited-into-parent by construction (via `.status()`, not
    /// `.output()`) so the compose-log output an operator watching
    /// `forge comprehensive-release` needs to triage a failure
    /// stays visible on the terminal.
    ///
    /// # Why a delegation-count floor (not just a negative scan)
    ///
    /// A negative-only shield that forbids the pre-lift stanza is
    /// trivially satisfied by absence — a regression that
    /// accidentally deleted one of the four cleanup / diagnostic
    /// sweeps (say, dropped the timeout `logs` block during a
    /// cleanup-tier prose rewrite) would still pass the negative
    /// scan. Pinning the delegation count to `>= 4` means every
    /// one of the four cleanup / diagnostic surfaces MUST still
    /// route through the primitive; a deletion drops the count and
    /// fails the shield. Same discipline the sibling
    /// `test_e2e_cleanup_sweeps_route_through_run_discard_sync`
    /// (72a49d4) shield and the fleet-wide status-only-spawn
    /// shields (a21bd67 / 5faeecb / c2922fd / 08fdb86 / a31ef65 /
    /// c7cb181 / 1ffda81) honor.
    ///
    /// # Reconstruction discipline
    ///
    /// The delegation needle `run_status_discard_in_async(` is
    /// reconstructed via [`format!`] at test time so this shield's
    /// own source text does not self-match the substring count —
    /// the per-line filter would otherwise inflate the count by one
    /// for the needle-literal line. The four delegation sites each
    /// spell `crate::retry::run_status_discard_in_async(` verbatim;
    /// the shorter `run_status_discard_in_async(` needle matches
    /// all four (a suffix of the fully-qualified form) without also
    /// matching the shield's own body (which only spells the two
    /// halves as separate literals joined at `format!` time).
    #[test]
    fn test_comprehensive_release_docker_compose_cleanup_routes_through_run_status_discard_in_async(
    ) {
        const SOURCE: &str = include_str!("comprehensive_release.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            SOURCE,
            "commands/comprehensive_release.rs",
        );
        let needle = format!("run_status_discard_{}(", "in_async");
        let hits = crate::test_support::code_line_hits(body, &needle);
        assert!(
            hits.len() >= 4,
            "commands/comprehensive_release.rs must delegate its \
             four best-effort async `docker-compose` cleanup / \
             diagnostic spawns (services-up-failure `down -v` \
             cleanup, services-healthy-timeout `logs`, services-\
             healthy-timeout `down -v` cleanup, integration-test-\
             failure `logs --tail=100` diagnostic) through the \
             shared `crate::retry::run_status_discard_in_async` \
             primitive — found {} delegation(s) in the top-of-file \
             body, expected at least 4. A regression that \
             reintroduces the pre-lift `let _ = Command::new( \
             &docker_compose).current_dir(&working_dir).args([...]) \
             .status().await;` stanza re-establishes the four-copy \
             duplication this commit closes. Offending hits: \
             {hits:?}",
            hits.len(),
        );
    }

    /// Marker-scoped shield: the cargo unit-test spawn inside
    /// [`super::execute`]'s Step 1/5 pre-build-validation block MUST
    /// route through [`crate::retry::run_inherited_status`], never
    /// through a hand-rolled inline builder terminated by a
    /// `.status().await` then `.context("Failed to run cargo test")?`
    /// then `if !test_result.success() { anyhow::bail!("Unit tests
    /// failed - aborting release") }` stanza that drops the exit code
    /// from the operator log line.
    ///
    /// Pre-lift the site spelled the fifteen-line stanza with a pair
    /// of ad-hoc failure messages (a `.context("Failed to run cargo
    /// test")?` builder-terminator suffix followed by a
    /// `bail!("Unit tests failed - aborting release")` inline bail)
    /// that named the phase but dropped the exit code
    /// `test_result.code()` returned — the same class the async
    /// primitive was written to close
    /// (retry.rs `classify_inherited_status`). Post-lift the
    /// delegation routes through the primitive and the canonical
    /// `"unit tests failed (exit {code})"` envelope emerges by
    /// construction at the primitive's ONE body — the shape every
    /// sibling on the async spawn frontier (`commands/{build,
    /// github_runner_ci, image_release, pangea, product_release,
    /// rust_service, search_sync, typescript}.rs`) already emits.
    /// Post-lift binding the outcome before the spinner-clear also
    /// closes a latent leak on the spawn-error path: pre-lift the `?`
    /// on `.context("Failed to run cargo test")` ran BEFORE
    /// `spinner.finish_and_clear()`, so a missing-cargo bubble left
    /// the terminal with a live spinner animating beneath the printed
    /// error; post-lift the spinner clears on every path (success,
    /// non-zero exit, AND spawn error) — the same latent-leak fix
    /// `commands/build.rs::execute` (72a7adf) and
    /// `commands/github_runner_ci.rs::execute` (4510026) landed for
    /// the sibling spinner-wrapped Nix build spawn.
    ///
    /// # Why marker-scoped, not whole-module
    ///
    /// The sibling docstring on
    /// `test_docker_tag_spawn_routes_through_run_inherited_status`
    /// above enumerates the remaining legitimate `.status().await`
    /// terminators in `super::execute` (docker-compose up with its
    /// deferred cleanup branch, docker-compose ps / logs / down
    /// fire-and-forget cleanups, sqlx migrate warn-on-failure,
    /// integration-test with its deferred bail); a whole-module
    /// shield would false-fire on those. This shield bounds the
    /// negative scan to ONLY the Step 1/5 block via
    /// [`crate::test_support::fn_body_slice_between_markers`]
    /// (open marker `// STEP 1: PRE-BUILD VALIDATION (Unit Tests)`,
    /// end marker `// STEP 2: BUILD DOCKER IMAGE`) so the discipline
    /// is tight against the block-under-migration and leaves the
    /// surrounding legitimate stanzas alone.
    ///
    /// # Anti-self-match discipline
    ///
    /// The pre-lift `.context(…)?` and `bail!(…)` needles are
    /// reconstructed at test time via `format!` so this shield's own
    /// docstring — which names the pre-lift shape only in prose above
    /// — does not false-match itself against the module-body scan.
    /// Positive side pins that `crate::retry::run_inherited_status(`
    /// appears in the sliced block at ≥1 line, so a regression that
    /// dropped the delegation cannot leave the negative scan trivially
    /// satisfied by absence.
    #[test]
    fn test_unit_test_spawn_routes_through_run_inherited_status() {
        const SOURCE: &str = include_str!("comprehensive_release.rs");

        let block = crate::test_support::fn_body_slice_between_markers(
            SOURCE,
            "commands/comprehensive_release.rs",
            "// STEP 1: PRE-BUILD VALIDATION (Unit Tests)",
            "// STEP 2: BUILD DOCKER IMAGE",
        );

        let pre_lift_context = format!(".context({}Failed to run cargo test{})", '"', '"');
        assert!(
            !block.contains(&pre_lift_context),
            "commands/comprehensive_release.rs must not re-inline the \
             pre-lift `.context(…)?` stanza on the unit-test spawn — \
             `crate::retry::run_inherited_status` owns the spawn-error \
             envelope, and the pre-lift `?` on `.context(...)` also ran \
             BEFORE `spinner.finish_and_clear()`, leaving a live spinner \
             under the printed error on a missing-cargo bubble."
        );

        let pre_lift_bail = format!("bail!({}Unit tests failed - aborting release{})", '"', '"');
        assert!(
            !block.contains(&pre_lift_bail),
            "commands/comprehensive_release.rs must not re-inline the \
             pre-lift `bail!(…)` on the unit-test spawn — the ad-hoc \
             message dropped the exit code `test_result.code()` \
             returned. `run_inherited_status`'s canonical \
             `\"{{op}} failed (exit {{code}})\"` envelope preserves it."
        );

        assert!(
            block.contains("crate::retry::run_inherited_status("),
            "commands/comprehensive_release.rs must dispatch its \
             unit-test spawn through \
             `crate::retry::run_inherited_status` — the delegation \
             string was not found in the STEP 1 block."
        );
    }
}
