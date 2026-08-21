use anyhow::{Context, Result};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;
use tokio::process::Command;
use tracing::{debug, info, warn};

use crate::flux_reconcile;
use crate::git;
use crate::infrastructure::kubectl::kubectl_command_async;
use crate::repo::get_tool_path;
use crate::retry::{debug_log_capture_streams, retry_command_logged, RetryPolicy};

/// The typed exponential-backoff policy for the StatefulSet rollout-watch
/// pod-status-poll cadence in [`execute`]'s `--watch` branch — `initial_backoff`
/// 5s × `factor` 2 capped at `max_backoff` 30s. Consumes the pre-existing typed
/// primitive at [`crate::retry::RetryPolicy`] so the per-attempt delay lands at
/// [`RetryPolicy::compute_delay`], the same shared body the sibling k8s-Job
/// status-poll surface `services/migration_service.rs::MIGRATION_JOB_POLL_BACKOFF`
/// (commit ac61874), the Shinka reconcile-poll surface `commands/migrations.rs::
/// SHINKA_MIGRATION_POLL_BACKOFF` (commit b962db5), the flux polling-loops
/// surface `commands/flux.rs::FLUX_POLL_BACKOFF` (commit 65de62f), the
/// health-endpoint retry surface `commands/post_deploy_verification.rs::
/// HEALTH_ENDPOINT_BACKOFF` (commit b5db3b6), the web / integration test-suite
/// retry surfaces (commits 9fd38d3 / e22b0a2), and the helm-dependency-update
/// retry surface `commands/helm.rs::HELM_DEP_UPDATE_RETRY_BACKOFF`
/// (commit 0a087de) read through.
///
/// Pre-lift the schedule was spelled inline as a bare fixed
/// `tokio::time::sleep(tokio::time::Duration::from_secs(5)).await` at the tail
/// of every non-terminal iteration of the rollout-watch pod-status-poll loop.
/// That shape carried three structural defects the typed-primitive body
/// forecloses:
/// 1. **Fixed 5s schedule.** A flat `sleep(5s)` between pod-status polls is
///    "too short when the rollout is actually progressing (up to 60 kubectl
///    probes across the 5-minute `rollout_timeout` window — noise against the
///    k8s API), 5s too long when a `Running`/`Ready` transition landed 200ms
///    ago" — the exact worst-of-both failure mode the sibling
///    `MIGRATION_JOB_POLL_BACKOFF` / `SHINKA_MIGRATION_POLL_BACKOFF` /
///    `FLUX_POLL_BACKOFF` docstrings cite for their own pre-lift fixed /
///    bespoke schedules. Post-lift, the first poll still waits 5s (preserving
///    the seed verbatim), then 10s / 20s / 30s / 30s / … — ~12 iterations
///    reach the 5-minute `rollout_timeout` under the exponential-with-cap
///    climb rather than 60 iterations under the pre-lift flat 5s.
/// 2. **No caller-visible schedule invariant.** The bare
///    `Duration::from_secs(5)` literal at the poll-loop sleep carried no name
///    a shield could pin — a future edit that changed the schedule at this
///    site did not surface at any named-primitive audit path. The lifted
///    `GITHUB_RUNNER_ROLLOUT_POLL_BACKOFF` const names the (seed, factor, cap)
///    triple a shield can cite and enforce.
/// 3. **Schedule desync from the sibling k8s-workload-poll surfaces.**
///    The rollout-watch poll loop observes a k8s `StatefulSet`'s per-pod
///    status conditions; the sibling `wait_for_job` loop
///    (`services/migration_service.rs`, ac61874) observes a k8s `Job`'s
///    status conditions; the sibling `wait_for_shinka_migration` loop
///    (`commands/migrations.rs`, b962db5) observes a Shinka reconciler's
///    phase transitions. All three poll the k8s API for a workload
///    resource's terminal transition and pre-lift each spelled its own
///    local fixed-sleep schedule, so a future edit to one silently diverged
///    from the others. Post-lift all three consume the same shared body via
///    the same `RetryPolicy::network()` `(factor=2, max_backoff=30s)`
///    reference schedule, differing only at their respective pre-lift seeds
///    (5s here, 2s at the sibling two) each preserves verbatim.
///
/// `max_attempts: u32::MAX` is a placeholder — the rollout-watch loop is
/// bounded by wall-clock via the local `rollout_timeout` (5 minutes,
/// `Instant::now().duration_since(start_time) > rollout_timeout` at loop
/// head), not by attempt count — and consumes only [`RetryPolicy::compute_delay`]
/// from this policy, not [`RetryPolicy::max_attempts`]. The `max_attempts`
/// field is unconsulted at this consumption site.
const GITHUB_RUNNER_ROLLOUT_POLL_BACKOFF: RetryPolicy =
    RetryPolicy::wall_clock_poll(Duration::from_secs(5));

/// Backoff between StatefulSet rollout-watch pod-status-poll iterations, given
/// a 0-indexed local `attempt` counter (the `loop { ... }` shape in
/// [`execute`]'s `--watch` branch drives increments once per non-terminal
/// iteration).
///
/// Maps the local 0-indexed counter to the 1-indexed
/// [`RetryPolicy::compute_delay`] attempt axis via `saturating_add(2)`:
/// local `attempt == 0` (the sleep after the first non-terminal poll)
/// reads as `compute_delay(2) = initial_backoff * factor^0 =
/// initial_backoff = 5s`; local `attempt == 1` reads as `compute_delay(3)
/// = 10s`; local `attempt == 2` reads as `compute_delay(4) = 20s`; local
/// `attempt >= 3` reads as `compute_delay(>=5) = 30s` (cap) — preserves
/// the pre-lift `sleep(Duration::from_secs(5))` seed verbatim at the first
/// poll and strictly diverges upward at every later poll.
///
/// The `saturating_add` clamp forecloses the `u32` overflow class at the
/// bridge — a rollout-watch loop that reaches `attempt == u32::MAX` reads
/// as `compute_delay(u32::MAX)`, which itself saturates to
/// [`GITHUB_RUNNER_ROLLOUT_POLL_BACKOFF::max_backoff`] via the
/// `checked_pow`-then-cap body inside [`RetryPolicy::compute_delay`]
/// without panic.
fn github_runner_rollout_poll_delay(attempt: u32) -> Duration {
    GITHUB_RUNNER_ROLLOUT_POLL_BACKOFF.compute_delay(attempt.saturating_add(2))
}

/// Check if SAFE mode is enabled (retry on errors)
/// Default: true (retries enabled by default)
/// Disable with: SAFE=false or SAFE=0
fn is_safe_mode() -> bool {
    std::env::var("SAFE")
        .map(|v| {
            let val = v.to_lowercase();
            val != "false" && val != "0"
        })
        .unwrap_or(true) // Default to true
}

pub async fn execute(
    working_dir: String,
    cache_url: String,
    cache_name: String,
    registry: String,
    manifest: String,
    namespace: String,
    name: String,
    skip_build: bool,
    skip_push: bool,
    watch: bool,
) -> Result<()> {
    println!();
    println!(
        "{}",
        "╔════════════════════════════════════════════════════════════╗"
            .bright_cyan()
            .bold()
    );
    println!(
        "{}",
        "║  GitHub Runner CI Workflow                                ║"
            .bright_cyan()
            .bold()
    );
    println!(
        "{}",
        "╚════════════════════════════════════════════════════════════╝"
            .bright_cyan()
            .bold()
    );
    println!();

    // Get git SHA for tagging
    let git_sha = git::get_short_sha()?;
    info!("📦 Git SHA: {}", git_sha);
    info!("🎯 Target: {}:{}", registry, git_sha);
    println!();

    // Find repo root
    let repo_root = git::get_repo_root().context("Failed to find git repository")?;
    let repo_root_str = repo_root
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid repository path"))?;

    // Build output symlink
    let build_output = format!("{}/result-runner", working_dir);

    // Step 1: Build with Nix (unless skipped)
    if !skip_build {
        info!("━━━ Step 1/3: Build ━━━");
        println!();

        // Get ATTIC_TOKEN from environment or kubernetes secret
        // Fallback namespace can be configured via ATTIC_FALLBACK_NAMESPACE env var
        let attic_token = std::env::var("ATTIC_TOKEN")
            .ok()
            .or_else(|| {
                debug!("ATTIC_TOKEN not in env, trying kubectl...");
                let primary = crate::infrastructure::kubectl::fetch_secret_value(
                    "attic-secrets",
                    "github-actions",
                    "server-token",
                );
                if primary.is_some() {
                    debug!("Found attic-secrets in github-actions namespace");
                    return primary;
                }
                debug!("attic-secrets not found in github-actions namespace");
                let fallback_ns = std::env::var("ATTIC_FALLBACK_NAMESPACE").ok()?;
                debug!("Trying {} namespace...", fallback_ns);
                let fallback = crate::infrastructure::kubectl::fetch_secret_value(
                    "attic-secrets",
                    &fallback_ns,
                    "server-token",
                );
                if fallback.is_some() {
                    debug!("Found attic-secrets in {} namespace", fallback_ns);
                } else {
                    debug!("attic-secrets not found in {} namespace", fallback_ns);
                }
                fallback
            })
            .ok_or_else(|| anyhow::anyhow!("ATTIC_TOKEN not found in env or kubernetes (tried github-actions namespace; set ATTIC_FALLBACK_NAMESPACE for additional namespace)"))?;

        // Attic server alias — configurable via ATTIC_SERVER_NAME (default: "default")
        let attic_server =
            std::env::var("ATTIC_SERVER_NAME").unwrap_or_else(|_| "default".to_string());

        info!("🔧 Configuring Attic cache...");

        let safe_mode = is_safe_mode();
        if safe_mode {
            info!("🛡️  SAFE mode: automatic retries enabled (disable with SAFE=false)");
        } else {
            info!("⚠️  SAFE mode disabled: no automatic retries");
        }

        debug!("Attic cache URL: {}", cache_url);
        debug!("Attic cache name: {}", cache_name);

        // Login to Attic. Routes through
        // [`crate::infrastructure::attic::AtticClient::login_with_retries`]
        // so THREE load-bearing properties this site previously bypassed
        // via the domain-agnostic stringly `attic_command_with_retry`
        // helper land at ONE call:
        //   1. `ATTIC_BIN` env override — the pre-migration helper
        //      resolved `attic` via `get_tool_path("ATTIC_BIN", "attic")`
        //      at the top of the free-standing helper; the
        //      `login_with_retries` primitive resolves it via
        //      `resolve_attic_bin` in the same shape every other
        //      `AtticClient` method uses — pinning ONE env-override
        //      discovery site across the typed client.
        //   2. Typed-error dispatch — pre-migration the helper produced
        //      only untyped `anyhow::Error`; post-migration the failure
        //      lands as `AtticError::LoginFailed { cache, server_url,
        //      exit_code, stderr }` (or `AtticError::ExecFailed` on
        //      spawn, or `AtticError::TokenRequired` if the caller
        //      forgot the token) — the structural-record tuple Phase 1
        //      attestation records (THEORY §V.4) consume. A "bad token"
        //      now surfaces at the type level with the captured stderr
        //      attached, instead of as a fused string on the anyhow
        //      boundary.
        //   3. Retiring the domain-agnostic helper — this was the LAST
        //      remaining call site of `attic_command_with_retry`
        //      (siblings 09f05fb `push` and 8569c0a `use` migrated in
        //      prior runs). Deleting the helper removes ~40 lines of
        //      stringly `args: &[&str]` glue and pins the "no
        //      domain-agnostic attic invocation wrapper survives"
        //      floor across every forge command that talks to attic.
        // The `safe_mode` partition maps directly to the retry-budget
        // parameter `login_with_retries` accepts: safe_mode=true → 5
        // attempts (matching `RetryPolicy::network`'s canonical budget
        // on the migrated `push_with_retries` sibling); safe_mode=false
        // → 1 attempt (no retry). `login_with_retries` clamps
        // `retries=0` to 1 at `RetryPolicy::new`, so the partition
        // cannot silently collapse into a no-op. The regression-shield
        // `tests::test_execute_routes_attic_login_through_attic_client_not_helper`
        // pins the delegation structurally against a future re-fusion.
        let attic_login_retries = if safe_mode { 5 } else { 1 };
        crate::infrastructure::attic::AtticClient::new(attic_server.clone())
            .with_token(attic_token.clone())
            .login_with_retries(&cache_url, attic_login_retries)
            .await?;

        // Select the server-scoped cache as active. Routes through
        // [`crate::infrastructure::attic::AtticClient::use_cache`] so two
        // load-bearing properties this site previously bypassed land at
        // ONE call:
        //   1. `ATTIC_BIN` env override — the pre-migration
        //      `attic_command_with_retry` helper resolved `attic` via
        //      `get_tool_path("ATTIC_BIN", "attic")` at the top of the
        //      free-standing helper, but the `use_cache` primitive
        //      resolves it via `resolve_attic_bin` in the same shape
        //      every other `AtticClient` method uses — pinning ONE
        //      env-override discovery site across the typed client.
        //   2. Typed-error dispatch — pre-migration the helper produced
        //      untyped `anyhow::Error`; post-migration the failure lands
        //      as `AtticError::UseFailed { cache, server, exit_code,
        //      stderr }` (or `AtticError::ExecFailed` on spawn) — the
        //      structural-record tuple Phase 1 attestation records
        //      (THEORY §V.4) consume. A "wrong server alias" now
        //      surfaces at the type level with the captured stderr
        //      attached, instead of as a mysterious substituter-fetch
        //      failure from the subsequent `nix build` with no
        //      structural link back to the mis-`use`d cache.
        // The retry loop the pre-migration helper wrapped around this
        // call is dropped: `attic use` is a local operation that writes
        // to `~/.config/attic/config.toml` and does not touch the
        // network, so retrying on transient network stderr markers was
        // wasted budget by construction — the sibling `build.rs`
        // migration (99aab8b) established the same drop against a
        // pre-existing raw `Command::new("attic")` invocation with a
        // `use`-subcommand args slice that also did not retry. The
        // hard-fail contract this
        // site had (a `use` failure aborts CI because subsequent
        // substituter fetches would target the wrong cache) is
        // preserved by the `?` propagation onto the `AtticError`
        // variant. Sibling of the `attic push` migration at line ~220
        // above (09f05fb) and of the `build.rs::use_cache` migration
        // (99aab8b). The regression-shield
        // `tests::test_execute_routes_attic_use_through_attic_client_not_helper`
        // pins the delegation structurally against a future re-fusion.
        crate::infrastructure::attic::AtticClient::new(cache_name.clone())
            .use_cache(&attic_server)
            .await?;

        info!("✅ Attic configured");
        println!();

        info!("🔨 Building runner image with Nix...");
        info!("   Working directory: {}", working_dir);
        info!("   Architecture: x86_64-linux");
        println!();

        let spinner = ProgressBar::new_spinner();
        spinner.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} {msg}")
                .unwrap(),
        );
        spinner.set_message("Building with Nix...");
        spinner.enable_steady_tick(std::time::Duration::from_millis(100));

        let build_result = Command::new(get_tool_path("NIX_BIN", "nix"))
            .current_dir(&working_dir)
            .args(&["build", ".#dockerImage", "--print-build-logs"])
            .status()
            .await
            .context("Failed to run nix build")?;

        spinner.finish_and_clear();

        if !build_result.success() {
            anyhow::bail!("Nix build failed");
        }

        // Create result-runner symlink - use just "result" as relative path
        tokio::fs::remove_file(&build_output).await.ok(); // Ignore if doesn't exist

        // Read the nix store path from result symlink
        let result_path = format!("{}/result", working_dir);
        let target = tokio::fs::read_link(&result_path)
            .await
            .context("Failed to read result symlink")?;

        // Create result-runner symlink pointing to the same nix store path
        tokio::fs::symlink(&target, &build_output)
            .await
            .context("Failed to create result-runner symlink")?;

        info!("✅ Build complete: result-runner");
        println!();

        // Push to Attic
        info!("📤 Pushing to Attic cache...");
        debug!("Pushing {} to cache {}", build_output, cache_name);

        // Delegated to the typed
        // `crate::infrastructure::attic::AtticClient::push_with_retries`
        // primitive so a non-zero exit surfaces as
        // `AtticError::PushFailed` carrying the (cache, store_path,
        // attempts, exit_code, stderr) structural-record tuple Phase 1
        // attestation records (THEORY §V.4) consume; a spawn failure
        // (attic not on PATH under the CI runner's toolchain) surfaces
        // as `AtticError::ExecFailed` carrying the cache and the
        // spawn-error message. Pre-migration the stringly
        // `attic_command_with_retry` helper at this site produced
        // only untyped `anyhow::Error` — the non-fatal-warn branch
        // below now debug-logs a structured `AtticError` record via
        // `{:?}` instead of a fused string.
        //
        // The retry budget mirrors the safe_mode partition the
        // domain-agnostic helper encoded: safe_mode=true → 5 attempts
        // (matching `RetryPolicy::network`'s canonical budget on the
        // migrated `build.rs` / `push.rs` sibling surfaces);
        // safe_mode=false → 1 attempt (no retry). `push_with_retries`
        // clamps `retries=0` to 1 at `RetryPolicy::new`, so the
        // partition cannot silently collapse into a no-op.
        //
        // No `.with_token(...)` on the client: the token was seeded
        // into attic's on-disk config by the earlier `login` step, and
        // the pre-migration call at this site did NOT inject
        // `ATTIC_TOKEN` into the spawned process's env either.
        // Preserving the absent-env property means a ps-visible
        // observation surface on shared CI hosts is unchanged.
        let attic_push_retries = if safe_mode { 5 } else { 1 };
        let push_result = crate::infrastructure::attic::AtticClient::new(cache_name.clone())
            .push_with_retries(&build_output, attic_push_retries)
            .await;

        match push_result {
            Ok(_) => info!("✅ Cached in Attic"),
            Err(e) => {
                warn!("⚠️  Failed to push to Attic cache (non-fatal): {}", e);
                debug!("Attic push error details: {:?}", e);
            }
        }
        println!();
    } else {
        info!("⏭️  Skipping build step");
        println!();
    }

    // Step 2: Push to GHCR (unless skipped)
    if !skip_push {
        info!("━━━ Step 2/3: Push to GHCR ━━━");
        println!();

        // Get GHCR token via canonical discovery chain
        let ghcr_token = crate::infrastructure::registry::RegistryCredentials::discover_token(None)
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        info!("📤 Pushing to GHCR with doca...");

        let pb = ProgressBar::new(2);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} {msg}")
                .unwrap()
                .progress_chars("#>-"),
        );

        // Push latest tag
        pb.set_message(format!("Pushing {}:latest", registry));
        push_with_retry(&build_output, &registry, "latest", &ghcr_token, 10).await?;
        pb.inc(1);

        // Push git SHA tag
        pb.set_message(format!("Pushing {}:{}", registry, git_sha));
        push_with_retry(&build_output, &registry, &git_sha, &ghcr_token, 10).await?;
        pb.inc(1);

        pb.finish_with_message("Push complete");

        println!();
        info!("✅ Images pushed to GHCR");
        println!("   • {}:latest", registry);
        println!("   • {}:{}", registry, git_sha);
        println!();
    } else {
        info!("⏭️  Skipping push step");
        println!();
    }

    // Step 3: Update manifest and commit
    info!("━━━ Step 3/3: GitOps Deployment ━━━");
    println!();

    let manifest_path = std::path::Path::new(repo_root_str).join(&manifest);

    // Read current tag from manifest
    let manifest_content = tokio::fs::read_to_string(&manifest_path)
        .await
        .context("Failed to read manifest")?;

    // Parse YAML to get current tag from images[].newTag field
    let yaml: serde_yaml::Value =
        serde_yaml::from_str(&manifest_content).context("Failed to parse manifest as YAML")?;

    let old_tag = yaml
        .get("images")
        .and_then(|images| images.as_sequence())
        .and_then(|seq| seq.first())
        .and_then(|img| img.get("newTag"))
        .and_then(|tag| tag.as_str())
        .ok_or_else(|| anyhow::anyhow!("Could not find images[0].newTag in manifest"))?
        .to_string();

    info!("📝 Updating manifest...");
    info!("   Old: github-runner:{}", old_tag);
    info!("   New: github-runner:{}", git_sha);
    println!();

    // Update manifest
    git::update_manifest(&manifest_path, &old_tag, &git_sha).await?;

    // Update ConfigMap with GIT_SHA
    info!("📝 Updating ConfigMap with GIT_SHA...");
    git::update_configmap_git_sha(&manifest_path, &git_sha).await?;

    // Commit and push
    info!("📤 Committing to Git...");

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );
    pb.set_message("Pushing to main...");
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    git::commit_and_push(&manifest_path, &old_tag, &git_sha)?;

    pb.finish_with_message("✅ Pushed to main");
    println!();

    // Trigger FluxCD reconciliation and wait for deployment
    info!("🔄 Triggering FluxCD reconciliation...");

    // Reconcile the flux-system to pull latest git changes and apply them
    match flux_reconcile::reconcile_kustomization("flux-system", "flux-system", true).await {
        Ok(()) => {
            info!("✅ FluxCD reconciliation complete");
        }
        Err(e) => {
            warn!("⚠️  FluxCD reconcile failed (non-fatal): {}", e);
        }
    }

    // Give Kubernetes a moment to start the rollout
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    // Wait for StatefulSet rollout if watch flag is enabled
    if watch {
        println!();
        info!("👀 Watching StatefulSet rollout...");
        info!("   Namespace: {}", namespace);
        info!("   StatefulSet: {}", name);
        println!();

        // Monitor rollout with pod failure detection
        let rollout_timeout = tokio::time::Duration::from_secs(300); // 5 minutes
        let start_time = tokio::time::Instant::now();
        let mut last_check = None;
        let mut backoff_attempt: u32 = 0;

        loop {
            // Check for timeout
            if tokio::time::Instant::now().duration_since(start_time) > rollout_timeout {
                warn!("⚠️  Rollout timeout after 5 minutes");
                break;
            }

            // Get pod status
            let pod_status_result = kubectl_command_async()
                .args(&[
                    "get",
                    "pods",
                    "-n",
                    &namespace,
                    "-l",
                    &format!("app={}", name),
                    "-o",
                    "json",
                ])
                .output()
                .await;

            match pod_status_result {
                Ok(output) if output.status.success() => {
                    let pod_json = String::from_utf8_lossy(&output.stdout);

                    // Parse JSON to check pod states
                    if let Ok(pods_value) = serde_json::from_str::<serde_json::Value>(&pod_json) {
                        if let Some(items) = pods_value.get("items").and_then(|i| i.as_array()) {
                            let mut failed_pods = Vec::new();
                            let mut pending_count = 0;
                            let mut running_count = 0;

                            for item in items {
                                let pod_name = item
                                    .get("metadata")
                                    .and_then(|m| m.get("name"))
                                    .and_then(|n| n.as_str())
                                    .unwrap_or("unknown");

                                let phase = item
                                    .get("status")
                                    .and_then(|s| s.get("phase"))
                                    .and_then(|p| p.as_str())
                                    .unwrap_or("Unknown");

                                let container_statuses = item
                                    .get("status")
                                    .and_then(|s| s.get("containerStatuses"))
                                    .and_then(|cs| cs.as_array());

                                // Check for container failures
                                if let Some(statuses) = container_statuses {
                                    for status in statuses {
                                        let container_name = status
                                            .get("name")
                                            .and_then(|n| n.as_str())
                                            .unwrap_or("unknown");

                                        // Check for CrashLoopBackOff or other failure states
                                        let waiting =
                                            status.get("state").and_then(|s| s.get("waiting"));

                                        if let Some(waiting_state) = waiting {
                                            let reason = waiting_state
                                                .get("reason")
                                                .and_then(|r| r.as_str())
                                                .unwrap_or("");

                                            if reason.contains("CrashLoopBackOff")
                                                || reason.contains("Error")
                                                || reason.contains("ImagePullBackOff")
                                            {
                                                failed_pods.push((
                                                    pod_name.to_string(),
                                                    container_name.to_string(),
                                                    reason.to_string(),
                                                ));
                                            }
                                        }

                                        // Check for terminated with error
                                        let terminated =
                                            status.get("state").and_then(|s| s.get("terminated"));

                                        if let Some(terminated_state) = terminated {
                                            let exit_code = terminated_state
                                                .get("exitCode")
                                                .and_then(|c| c.as_i64())
                                                .unwrap_or(0);

                                            if exit_code != 0 {
                                                let reason = terminated_state
                                                    .get("reason")
                                                    .and_then(|r| r.as_str())
                                                    .unwrap_or("Error");
                                                failed_pods.push((
                                                    pod_name.to_string(),
                                                    container_name.to_string(),
                                                    format!("{} (exit {})", reason, exit_code),
                                                ));
                                            }
                                        }
                                    }
                                }

                                // Count pod phases
                                match phase {
                                    "Pending" => pending_count += 1,
                                    "Running" => running_count += 1,
                                    _ => {}
                                }
                            }

                            // If we have failing pods, report them and exit
                            if !failed_pods.is_empty() {
                                println!();
                                warn!("❌ Pod failures detected during rollout!");
                                println!();

                                for (pod_name, container_name, reason) in &failed_pods {
                                    warn!("   Pod: {} / Container: {}", pod_name, container_name);
                                    warn!("   Reason: {}", reason);
                                    println!();

                                    // Fetch logs from the failed container
                                    info!("📋 Fetching logs from {}...", pod_name);
                                    let log_result = kubectl_command_async()
                                        .args(&[
                                            "logs",
                                            pod_name,
                                            "-c",
                                            container_name,
                                            "-n",
                                            &namespace,
                                            "--tail=30",
                                        ])
                                        .output()
                                        .await;

                                    match log_result {
                                        Ok(log_output) if log_output.status.success() => {
                                            let logs = String::from_utf8_lossy(&log_output.stdout);
                                            println!("━━━ Logs from {} ━━━", pod_name);
                                            println!("{}", logs);
                                            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                                        }
                                        _ => {
                                            warn!("   Could not fetch logs");
                                        }
                                    }
                                    println!();
                                }

                                anyhow::bail!(
                                    "Rollout failed: {} pod(s) in crash state. See logs above for details.",
                                    failed_pods.len()
                                );
                            }

                            // Check if rollout is complete
                            let total_pods = items.len();
                            if running_count == total_pods && pending_count == 0 {
                                info!(
                                    "✅ StatefulSet rollout complete: {}/{} pods running",
                                    running_count, total_pods
                                );
                                break;
                            }

                            // Print status update if changed
                            let current_status = format!(
                                "{}/{} running, {} pending",
                                running_count, total_pods, pending_count
                            );
                            if last_check != Some(current_status.clone()) {
                                debug!("Rollout status: {}", current_status);
                                last_check = Some(current_status);
                            }
                        }
                    }
                }
                _ => {
                    debug!("Could not check pod status, retrying...");
                }
            }

            // Wait before next check — schedule owned by
            // `GITHUB_RUNNER_ROLLOUT_POLL_BACKOFF` +
            // `github_runner_rollout_poll_delay` (both grounding through
            // `RetryPolicy::compute_delay`).
            tokio::time::sleep(github_runner_rollout_poll_delay(backoff_attempt)).await;
            backoff_attempt = backoff_attempt.saturating_add(1);
        }

        // Verify the new image is deployed
        println!();
        info!("🔍 Verifying deployment...");
        let verify_result = kubectl_command_async()
            .args(&[
                "get",
                &format!("statefulset/{}", name),
                "-n",
                &namespace,
                "-o",
                &format!("jsonpath={{.spec.template.spec.containers[?(@.name=='runner')].image}}"),
            ])
            .output()
            .await;

        match verify_result {
            Ok(output) if output.status.success() => {
                let deployed_image = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if deployed_image.contains(&git_sha) {
                    info!("✅ Verified: {}", deployed_image);
                } else {
                    warn!("⚠️  Image mismatch!");
                    warn!("   Expected: {}:{}", registry, git_sha);
                    warn!("   Deployed: {}", deployed_image);
                }
            }
            _ => {
                warn!("⚠️  Could not verify deployed image");
            }
        }
    } else {
        info!("⏭️  Skipping rollout watch (use --watch to enable)");
    }

    println!();
    println!(
        "{}",
        "╔════════════════════════════════════════════════════════════╗"
            .bright_green()
            .bold()
    );
    println!(
        "{}",
        "║  ✅ GitHub Runner CI Complete!                             ║"
            .bright_green()
            .bold()
    );
    println!(
        "{}",
        "╚════════════════════════════════════════════════════════════╝"
            .bright_green()
            .bold()
    );
    println!();
    println!("📦 Deployed: {}:{}", registry, git_sha);
    println!("🎯 Namespace: {}", namespace);
    println!("🚀 StatefulSet: {}", name);
    println!();

    Ok(())
}

async fn push_with_retry(
    image_path: &str,
    registry: &str,
    tag: &str,
    token: &str,
    retries: u32,
) -> Result<()> {
    let safe_mode = is_safe_mode();

    // Pre-loop: image file must exist. Structural precondition; not a
    // retry-recoverable failure.
    debug!("Verifying image file: {}", image_path);
    match tokio::fs::metadata(image_path).await {
        Ok(meta) => debug!("Image file found, size: {} bytes", meta.len()),
        Err(e) => anyhow::bail!("Image file not found at {}: {}", image_path, e),
    }

    let doca = get_tool_path("DOCA_BIN", "oci-push");

    // Pre-loop: doca must be available. Same structural precondition.
    debug!("Checking if doca is available at: {}", doca);
    let doca_check = Command::new(&doca).arg("--version").output().await;
    match doca_check {
        Ok(output) if output.status.success() => {
            debug!(
                "Found doca: {}",
                String::from_utf8_lossy(&output.stdout).trim()
            );
        }
        _ => {
            // NAMES THE BINARY THAT IS ACTUALLY MISSING. This message used to
            // say "install skopeo" and list brew/apt/yum recipes for it — which,
            // after the doca conversion, sent the operator to install a tool
            // this code path no longer invokes while the real missing binary
            // went unnamed. A diagnostic that points at the wrong thing costs
            // more than no diagnostic.
            anyhow::bail!(
                "doca (oci-push) not found — checked the DOCA_BIN env var and PATH.\n\
                 doca is the pleme-io container tool that replaced skopeo here; it is\n\
                 built from substrate and normally baked into the runner image:\n\
                 - Nix:  nix run github:pleme-io/substrate#oci-push -- --version\n\
                 - or set DOCA_BIN to an existing oci-push binary"
            );
        }
    }

    // Extract organization from registry URL for credentials. Falls
    // back to "user" when the registry is malformed (single-segment),
    // matching pre-existing behaviour.
    let parsed_registry = crate::infrastructure::registry::RegistryRef::parse(registry).ok();
    let organization = parsed_registry
        .as_ref()
        .map_or("user", |r| r.organization())
        .to_string();

    // Outer retry: shared `retry_command` (composes the canonical
    // classifier with `CommandAttemptFailure::from_capture`). The
    // `retries` parameter is preserved as skopeo's internal
    // `--retry-times` (a per-blob retry inside skopeo); the OUTER loop
    // is bounded by the typed policy. Pre-existing code conflated the
    // two: when `safe_mode` was on, the outer loop never terminated
    // (the `attempts < retries || safe_mode` guard was always true).
    // The migration fixes that bug by construction.
    let policy = RetryPolicy::network_or_immediate(safe_mode);
    let op = format!("push {}:{}", registry, tag);

    // doca takes --registry/--image separately; a base with no '/' is refused
    // rather than guessed, since a wrong split pushes to the wrong repository.
    let (host, image) = registry.split_once('/').ok_or_else(|| {
        anyhow::anyhow!("registry {registry:?} has no '/', cannot split host from image")
    })?;
    let host = host.to_string();
    let image = image.to_string();

    let result = retry_command_logged(&policy, &op, |attempt| {
        let doca = doca.clone();
        let organization = organization.clone();
        let host = host.clone();
        let image = image.clone();
        async move {
            debug!("Pushing {}:{} (attempt {})", registry, tag, attempt);
            // CREDENTIALS BY ENV, NEVER ARGV: `--dest-creds=<org>:<token>` put
            // the token in /proc/<pid>/cmdline, world-readable on a shared
            // runner. `--retry-times` dropped as a redundant inner retry loop —
            // doca's push_with_retry backs off and distinguishes transient from
            // permanent failures.
            let outcome = Command::new(&doca)
                .args([
                    "push",
                    "--tarball",
                    image_path,
                    "--registry",
                    &host,
                    "--image",
                    &image,
                    "--tag",
                    tag,
                ])
                .env("INPUT_DEST_USER", &organization)
                .env("INPUT_DEST_PASS", token)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .output()
                .await;

            // Domain-specific debug observability. The non-success
            // streams-tee dispatch flows through the canonical
            // [`debug_log_capture_streams`] primitive — same shape as
            // `attic_command_with_retry`'s migrated dispatch above, so
            // the `<tool> stdout/stderr: <trimmed>` message format is
            // pinned by one test in `cli/src/retry.rs` across both
            // retry-driven CI surfaces. The success arm is
            // domain-specific (per-call-site context). Interleaves
            // BEFORE the primitive's per-attempt warn dispatch —
            // `retry_command_logged` wraps the closure's OUTPUT with
            // [`log_retry_attempt`], not its BODY, so a per-site
            // debug tee inside the closure fires before the retry-
            // loop's warn arm.
            if let Ok(out) = outcome.as_ref() {
                if out.status.success() {
                    debug!("Push successful for {}:{}", registry, tag);
                } else {
                    debug_log_capture_streams(out, "doca");
                }
            }
            outcome
        }
    })
    .await;

    result.map(|_| ()).map_err(|e| anyhow::anyhow!("{}", e))
}

#[cfg(test)]
mod tests {
    /// Regression shield: the `attic push` step inside `execute()`
    /// must route through
    /// [`crate::infrastructure::attic::AtticClient::push_with_retries`]
    /// rather than the retired domain-agnostic
    /// `attic_command_with_retry` helper (deleted in the migration
    /// that landed the sibling login shield below). Pre-migration
    /// this call site spawned `attic push` via a stringly
    /// `args: &[&str]` wrapper that produced only untyped
    /// `anyhow::Error`; post-migration the typed
    /// [`crate::error::AtticError::PushFailed`] and
    /// [`crate::error::AtticError::ExecFailed`] variants reach the
    /// call site so the non-fatal-warn branch's
    /// `debug!("Attic push error details: {:?}", e)` line surfaces a
    /// structural record — (cache, store_path, attempts, exit_code,
    /// stderr) — rather than a fused string.
    ///
    /// Sibling of the regression shields the prior four migration
    /// commits (36fd3b1 push.rs::push_optional; 0365a59 build.rs::
    /// login_optional; 99aab8b build.rs::use_cache; 8569c0a
    /// github_runner_ci.rs::use_cache — this file's sibling shield
    /// below) pinned on their respective `execute()` bodies. The
    /// FIVE shields together close the "no raw `attic <sub>` spawn
    /// survives in an execute() body" floor across every forge
    /// command that talks to attic through a client-owned surface,
    /// and — with the retirement of the `attic_command_with_retry`
    /// helper — the "no domain-agnostic stringly attic wrapper
    /// survives" floor too.
    ///
    /// Structural, not behavioral — reads this module's own source
    /// via `include_str!` and inspects the `execute()` body slice
    /// (bounded above by the fn header, below by the `#[cfg(test)]`
    /// marker for this tests module). A future regression that
    /// re-fuses the push step back onto a raw `attic push` spawn or
    /// a resurrected stringly helper — even without changing
    /// observable behavior — fails this test rather than silently
    /// un-migrating the typed-error surface.
    #[test]
    fn test_execute_routes_attic_push_through_attic_client_not_helper() {
        // Bound the fn body between `execute()`'s header and the next
        // `\n#[cfg(test)]` marker so this test's own docstring — which
        // legitimately spells the pre-migration `&["push", ...]` args
        // slice for context — is excluded from the scan.
        let execute_body = crate::test_support::fn_body_slice_between_markers(
            include_str!("github_runner_ci.rs"),
            "commands/github_runner_ci.rs",
            "pub async fn execute(",
            "\n#[cfg(test)]",
        );

        // Post-migration invariant #1: no `attic_command_with_retry`
        // call spawning `attic push` remains in `execute()`. The
        // literal `&["push",` sub-slice is the load-bearing marker
        // that pre-migration the call was routed through the stringly
        // helper; if a future regression rewires the push step back
        // onto that helper, the marker reappears and this shield
        // fires.
        assert!(
            !execute_body.contains("&[\"push\","),
            "execute() must not spawn `attic push` via the domain-agnostic \
             `attic_command_with_retry` helper — the `&[\"push\", ...]` args \
             slice was found in execute(). Route the push step through \
             `crate::infrastructure::attic::AtticClient::new(cache_name.clone()\
              ).push_with_retries(&build_output, ...)` instead."
        );

        // Post-migration invariant #2: the delegation to
        // `AtticClient::push_with_retries` is present. Pins the
        // positive form of the migration so a future regression that
        // silently drops the call (e.g., stripping the push step
        // entirely) fails this test rather than silently skipping the
        // cache-write.
        assert!(
            execute_body.contains("push_with_retries"),
            "execute() must delegate the push step to \
             `AtticClient::push_with_retries` — the `push_with_retries` \
             method call was not found in execute()."
        );
        assert!(
            execute_body.contains("AtticClient::new"),
            "execute() must construct an `AtticClient` for the push step \
             — the `AtticClient::new` string was not found in execute()."
        );
    }

    /// Regression shield: the `attic use` step inside `execute()`
    /// must route through
    /// [`crate::infrastructure::attic::AtticClient::use_cache`] rather
    /// than the retired domain-agnostic `attic_command_with_retry`
    /// helper (deleted in the migration that landed the sibling
    /// login shield below). Pre-migration this call site spawned
    /// `attic use` via a stringly
    /// `&["use", &format!("{}:{}", attic_server, cache_name)]` slice
    /// wrapper that produced only untyped `anyhow::Error`;
    /// post-migration the typed
    /// [`crate::error::AtticError::UseFailed`] and
    /// [`crate::error::AtticError::ExecFailed`] variants reach the
    /// call site so a "wrong server alias" surfaces as a structural
    /// record — (cache, server, exit_code, stderr) — instead of a
    /// mysterious substituter-fetch failure from the subsequent
    /// `nix build` with no structural link back to the mis-`use`d
    /// cache.
    ///
    /// Sibling of the five regression shields the prior migration
    /// commits pinned (and the sibling login shield this run adds):
    /// - 36fd3b1 `push.rs::execute` → `push_optional`
    /// - 0365a59 `build.rs::execute` → `login_optional`
    /// - 99aab8b `build.rs::execute` → `use_cache`
    /// - 09f05fb `github_runner_ci.rs::execute` → `push_with_retries`
    ///   (the shield above this one)
    /// - this-run `github_runner_ci.rs::execute` →
    ///   `login_with_retries` (the shield below this one)
    ///
    /// The six shields together close the "no `attic <sub>`
    /// invocation via the domain-agnostic stringly
    /// `attic_command_with_retry` / raw
    /// `Command::new("attic").args(&[<sub>, ...])` helper survives
    /// in an `execute()` body" floor across every forge command that
    /// talks to attic through a client-owned surface — AND the
    /// helper itself is now retired (the last remaining call site
    /// migrated in this run).
    ///
    /// Structural, not behavioral — reads this module's own source
    /// via `include_str!` and inspects the `execute()` body slice
    /// (bounded above by the fn header, below by the `#[cfg(test)]`
    /// marker for this tests module). A future regression that
    /// re-fuses the `use` step back onto a raw `attic use` spawn or
    /// a resurrected stringly helper — even without changing
    /// observable behavior — fails this test rather than silently
    /// un-migrating the typed-error surface.
    #[test]
    fn test_execute_routes_attic_use_through_attic_client_not_helper() {
        // Bound the fn body between `execute()`'s header and the next
        // `\n#[cfg(test)]` marker so this test's own docstring — which
        // legitimately spells the pre-migration `&["use", ...]` args
        // slice for context — is excluded from the scan.
        let execute_body = crate::test_support::fn_body_slice_between_markers(
            include_str!("github_runner_ci.rs"),
            "commands/github_runner_ci.rs",
            "pub async fn execute(",
            "\n#[cfg(test)]",
        );

        // Post-migration invariant #1: no `attic_command_with_retry`
        // call spawning `attic use` remains in `execute()`. The
        // literal `&["use",` sub-slice is the load-bearing marker
        // that pre-migration the call was routed through the stringly
        // helper; if a future regression rewires the `use` step back
        // onto that helper, the marker reappears and this shield
        // fires.
        assert!(
            !execute_body.contains("&[\"use\","),
            "execute() must not spawn `attic use` via the domain-agnostic \
             `attic_command_with_retry` helper — the `&[\"use\", ...]` args \
             slice was found in execute(). Route the use step through \
             `crate::infrastructure::attic::AtticClient::new(cache_name.clone()\
              ).use_cache(&attic_server)` instead."
        );

        // Post-migration invariant #2: the delegation to
        // `AtticClient::use_cache` is present. Pins the positive form
        // of the migration so a future regression that silently drops
        // the call (e.g., stripping the cache-selection step
        // entirely) fails this test rather than silently skipping the
        // `attic use` — which would leave subsequent nix substituter
        // fetches routed at whatever cache was previously selected in
        // `~/.config/attic/config.toml`.
        assert!(
            execute_body.contains("use_cache"),
            "execute() must delegate the use step to \
             `AtticClient::use_cache` — the `use_cache` \
             method call was not found in execute()."
        );
    }

    /// Regression shield: the `attic login` step at the top of
    /// `execute()` must route through
    /// [`crate::infrastructure::attic::AtticClient::login_with_retries`]
    /// rather than the retired domain-agnostic
    /// `attic_command_with_retry` helper. Pre-migration this call
    /// site spawned `attic login` via a stringly
    /// `&["login", &attic_server, &cache_url, &attic_token]` slice
    /// wrapper that produced only untyped `anyhow::Error`;
    /// post-migration the typed
    /// [`crate::error::AtticError::LoginFailed`],
    /// [`crate::error::AtticError::ExecFailed`], and
    /// [`crate::error::AtticError::TokenRequired`] variants reach
    /// the call site so a "bad token" surfaces as a structural
    /// record — (cache, server_url, exit_code, stderr) — instead of
    /// a fused string on the anyhow boundary.
    ///
    /// This migration retired the `attic_command_with_retry` helper
    /// entirely (deletion in the same commit as this shield): the
    /// login step was the LAST remaining call site. Sibling of the
    /// prior five migration shields; the six together close BOTH
    /// the "no raw `attic <sub>` spawn in an `execute()` body" AND
    /// the "no domain-agnostic stringly `attic_command_with_retry`
    /// helper survives anywhere in the workspace" floors, so the
    /// only sanctioned path for a forge command to talk to attic is
    /// through an `AtticClient` method.
    ///
    /// Structural, not behavioral — reads this module's own source
    /// via `include_str!` and asserts the raw `&["login",` slice
    /// does not reappear inside `execute()` while the delegation to
    /// `AtticClient::new(attic_server.clone()).with_token(...)
    /// .login_with_retries(&cache_url, retries)` does. A future
    /// regression that re-fuses the login step back onto a raw
    /// stringly-args wrapper fails here rather than silently
    /// un-migrating the typed-error surface.
    #[test]
    fn test_execute_routes_attic_login_through_attic_client_not_helper() {
        // Bound the fn body between `execute()`'s header and the next
        // `\n#[cfg(test)]` marker so this test's own docstring — which
        // legitimately spells the pre-migration `&["login", ...]` args
        // slice for context — is excluded from the scan. The
        // whole-module `source` binding is retained below for the
        // sibling retired-helper predicate that scans past the
        // tests-module boundary.
        let source = include_str!("github_runner_ci.rs");
        let execute_body = crate::test_support::fn_body_slice_between_markers(
            source,
            "commands/github_runner_ci.rs",
            "pub async fn execute(",
            "\n#[cfg(test)]",
        );

        // Post-migration invariant #1: no `attic_command_with_retry`
        // call spawning `attic login` remains in `execute()`. The
        // literal `&["login",` sub-slice is the load-bearing marker
        // that pre-migration the call was routed through the
        // (now-retired) stringly helper; if a future regression
        // rewires the login step back onto a resurrected helper or
        // a raw spawn with the same args shape, the marker reappears
        // and this shield fires.
        assert!(
            !execute_body.contains("&[\"login\","),
            "execute() must not spawn `attic login` via a stringly \
             `args: &[&str]` wrapper — the `&[\"login\", ...]` args slice \
             was found in execute(). Route the login step through \
             `crate::infrastructure::attic::AtticClient::new(attic_server\
              .clone()).with_token(attic_token.clone()).login_with_retries\
              (&cache_url, retries)` instead."
        );

        // Post-migration invariant #2: the domain-agnostic helper
        // itself must NOT resurface anywhere in this module.
        // Pre-migration the helper lived at ~line 675 as a
        // free-standing (module-level, unindented) async fn; the
        // migration deleted it. Guards against a future regression
        // that re-introduces the helper (even if the login step
        // above doesn't wire onto it) — the retirement is
        // load-bearing across every attic subcommand in forge, not
        // just the login one.
        //
        // The marker below is a real-newline + unindented
        // `async fn` definition prefix: since sibling shields'
        // documentation references the retired name only inside
        // 8-space-indented `//` comments (never at column 0), this
        // predicate fires solely on an actual module-level
        // definition — not on documentation drift.
        let retired_helper_marker = concat!("\n", "async fn ", "attic_command_with_retry");
        assert!(
            !source.contains(retired_helper_marker),
            "the domain-agnostic `attic_command_with_retry` helper was \
             retired in the login-migration commit — it must not be \
             resurrected. Route new retry-driven attic subcommands \
             through `AtticClient` methods (e.g., `login_with_retries`, \
             `push_with_retries`) instead of re-lifting a stringly \
             `args: &[&str]` wrapper."
        );

        // Post-migration invariant #3: the delegation to
        // `AtticClient::login_with_retries` is present. Pins the
        // positive form of the migration so a future regression that
        // silently drops the call (e.g., stripping the login step
        // entirely) fails this test rather than silently skipping
        // the login — which would leave subsequent `attic push` /
        // `nix build --substituters` calls without a seeded auth
        // token in `~/.config/attic/config.toml`.
        assert!(
            execute_body.contains("login_with_retries"),
            "execute() must delegate the login step to \
             `AtticClient::login_with_retries` — the \
             `login_with_retries` method call was not found in execute()."
        );
    }

    /// Regression shield: every `kubectl`-spawning site in
    /// `commands/github_runner_ci.rs::execute` MUST resolve the
    /// binary through
    /// [`crate::infrastructure::kubectl::kubectl_command_async`]
    /// rather than the pre-lift `Command::new("kubectl")` literal.
    /// Pre-migration three sites (rollout pod-status probe, per-pod
    /// crash-log fetch, deployed-image verification) each spelled
    /// the bare `Command::new("kubectl")` shape verbatim and thereby
    /// bypassed the `KUBECTL_BIN` env override the tools-registry
    /// idiom (`crate::tools::get_tool_path(tools::KUBECTL)`,
    /// cli/src/tools.rs:102-105) resolves — the same class of bug
    /// the sibling `flux` / `cargo` / `doca` / free-function-`git` /
    /// `GitClient` / `commands/federation.rs` /
    /// `commands/push.rs` / `commands/rollback.rs` /
    /// `commands/helm.rs` / `commands/product_release.rs::run_health_check`
    /// migrations redeemed at 621f827 / f0dfa12 / d3dd199 / 685642f /
    /// d6f6bc7 / dd5a212 / 673e4be / b02d4eb / 54a9985 / 139b37a /
    /// 818ed9a / badcdf4 / 8653403 / f6be190 / 8a1958e / 81d7486 /
    /// 0d922f6 / 82376e1 / 34661e3 / 5bb7cff.
    ///
    /// This test reads this module's own source via [`include_str!`]
    /// and asserts the raw `Command::new("kubectl")` string does not
    /// reappear in `execute()` while the delegation to
    /// `kubectl_command_async()` does. A future regression that
    /// re-fuses the raw-spawn body fails here, not silently in
    /// production where a Nix-hermetic runner's
    /// `KUBECTL_BIN`-provided `kubectl` would lose to whatever
    /// `kubectl` is first on `PATH` at
    /// `forge github-runner-ci --watch` invocation time.
    ///
    /// The check is deliberately structural (substring on the source
    /// text) rather than behavioral — the end-to-end
    /// `KUBECTL_BIN`-routing invariant is already pinned by
    /// [`crate::infrastructure::kubectl::tests::test_kubectl_command_async_routes_through_kubectl_bin_env_var`]
    /// on the primitive itself; this shield only certifies that
    /// every `execute()` kubectl spawn reads through that primitive.
    ///
    /// The scan is bounded strictly to `execute()`'s body — from
    /// `pub async fn execute(` to the next top-level marker
    /// `\nasync fn push_with_retry(` — so this shield's own
    /// docstring mention of `Command::new("kubectl")` stays out of
    /// scope. Mirrors the sibling shield on
    /// `commands/product_release.rs::run_health_check` for the
    /// second consumer of the `kubectl_command_async` primitive.
    #[test]
    fn test_execute_routes_kubectl_through_kubectl_command_async_not_raw_command() {
        // Bound at the next top-level function marker in source order.
        // `push_with_retry` follows `execute`; the tests-module
        // `#[cfg(test)]` marker follows `push_with_retry`. Using the
        // fn-boundary keeps the shield scoped strictly to `execute()`
        // so a future kubectl-spawning helper landing between the two
        // functions cannot silently ride along without its own shield.
        let execute_body = crate::test_support::fn_body_slice_between_markers(
            include_str!("github_runner_ci.rs"),
            "commands/github_runner_ci.rs",
            "pub async fn execute(",
            "\nasync fn push_with_retry(",
        );

        assert!(
            !execute_body.contains("Command::new(\"kubectl\")"),
            "execute() must NOT spawn `kubectl` directly — route \
             through `crate::infrastructure::kubectl::kubectl_command_async()` \
             so `KUBECTL_BIN` overrides land at the shared primitive. \
             Found the pre-migration spawn body in execute()."
        );
        assert!(
            execute_body.contains("kubectl_command_async()"),
            "execute() must delegate every kubectl spawn to \
             `kubectl_command_async()` — the delegation string was not \
             found in execute()."
        );
    }

    use super::{github_runner_rollout_poll_delay, GITHUB_RUNNER_ROLLOUT_POLL_BACKOFF};
    use crate::retry::RetryPolicy;
    use crate::test_support::code_line_hits;
    use std::time::Duration;

    /// The `(initial_backoff, factor, max_backoff)` shape of the
    /// StatefulSet rollout-watch poll backoff policy is a load-bearing
    /// invariant shared with the sibling k8s-workload-poll surfaces at
    /// `services/migration_service.rs::MIGRATION_JOB_POLL_BACKOFF` (ac61874,
    /// differing only in the 2s-vs-5s initial-backoff kept to preserve each
    /// pre-lift schedule verbatim) and
    /// `commands/migrations.rs::SHINKA_MIGRATION_POLL_BACKOFF` (b962db5,
    /// differing only in the 2s-vs-5s initial-backoff for the same reason)
    /// and pinned here so a future silent-desync at the const site (a factor
    /// bump, a cap change) is caught at a named test rather than silently
    /// across the two consumption sites (`github_runner_rollout_poll_delay`
    /// + the loop body). Sibling of
    ///   `test_migration_job_poll_backoff_policy_shape` at
    ///   `services/migration_service.rs::tests` (ac61874),
    ///   `test_shinka_migration_poll_backoff_policy_shape` at
    ///   `commands/migrations.rs::tests` (b962db5), and
    ///   `test_health_endpoint_backoff_policy_shape` at
    ///   `commands/post_deploy_verification.rs::tests` (b5db3b6).
    #[test]
    fn test_github_runner_rollout_poll_backoff_policy_shape() {
        assert_eq!(
            GITHUB_RUNNER_ROLLOUT_POLL_BACKOFF.initial_backoff,
            Duration::from_secs(5),
            "GITHUB_RUNNER_ROLLOUT_POLL_BACKOFF.initial_backoff must be 5s \
             — preserves the pre-lift bare `sleep(Duration::from_secs(5))` \
             seed verbatim at the rollout-watch loop's first sleep.",
        );
        assert_eq!(
            GITHUB_RUNNER_ROLLOUT_POLL_BACKOFF.factor, 2,
            "GITHUB_RUNNER_ROLLOUT_POLL_BACKOFF.factor must be 2 \
             — matches the Bazel/Buck2/SLSA-frontier factor=2 reference \
             the sibling `RetryPolicy::network()` cites.",
        );
        assert_eq!(
            GITHUB_RUNNER_ROLLOUT_POLL_BACKOFF.max_backoff,
            Duration::from_secs(30),
            "GITHUB_RUNNER_ROLLOUT_POLL_BACKOFF.max_backoff must be 30s \
             — matches the Bazel/Buck2/SLSA-frontier 30s cap reference \
             the sibling `RetryPolicy::network()` cites.",
        );
    }

    /// Pre-lift the rollout-watch loop's every iteration emitted
    /// `sleep(5s)` via the bare `Duration::from_secs(5)` literal. The
    /// lift's 0-indexed `attempt` counter must preserve that 5s seed
    /// verbatim at the first sleep and strictly diverge upward at every
    /// later sleep under the exponential-with-cap climb.
    #[test]
    fn test_github_runner_rollout_poll_delay_matches_pre_lift_seed_and_climbs() {
        assert_eq!(
            github_runner_rollout_poll_delay(0),
            Duration::from_secs(5),
            "iter 0 must sleep 5s — matches pre-lift \
             `sleep(Duration::from_secs(5))` seed at the first poll.",
        );
        assert_eq!(
            github_runner_rollout_poll_delay(1),
            Duration::from_secs(10),
            "iter 1 must sleep 10s — `5s * 2^1 = 10s` under the \
             exponential climb, strictly better than pre-lift's flat 5s.",
        );
        assert_eq!(
            github_runner_rollout_poll_delay(2),
            Duration::from_secs(20),
            "iter 2 must sleep 20s — `5s * 2^2 = 20s`.",
        );
    }

    /// Iterations past the cap must all emit `max_backoff = 30s` —
    /// under `factor=2` and `initial_backoff=5s` the cap fires at iter 3
    /// (`5s * 2^3 = 40s → capped to 30s`) and every subsequent iter
    /// stays at the ceiling.
    #[test]
    fn test_github_runner_rollout_poll_delay_caps_at_max_backoff_past_the_cap() {
        assert_eq!(
            github_runner_rollout_poll_delay(3),
            Duration::from_secs(30),
            "iter 3 must sleep 30s (cap) — `5s * 2^3 = 40s` exceeds \
             the 30s cap.",
        );
        assert_eq!(
            github_runner_rollout_poll_delay(4),
            Duration::from_secs(30),
            "iter 4 must sleep 30s (cap).",
        );
        assert_eq!(
            github_runner_rollout_poll_delay(50),
            Duration::from_secs(30),
            "iter 50 must sleep 30s (cap) — rollout-watch loops can \
             ride the full 5-minute `rollout_timeout` window on slow \
             pod pull/start cycles, so beyond-cap iterations must stay \
             at the ceiling rather than growing unboundedly.",
        );
    }

    /// The rollout-watch loop is bounded by the local `rollout_timeout`
    /// wall-clock (5 minutes) rather than by attempt count, so
    /// `backoff_attempt` can in principle reach any `u32` value in a
    /// pathological future where the timeout is lifted or extended.
    /// The `saturating_add(2)` bridge inside
    /// `github_runner_rollout_poll_delay` bounds the argument to
    /// `RetryPolicy::compute_delay`, whose `checked_pow`-then-cap body
    /// itself saturates without panic. This test pins that composition:
    /// an `attempt == u32::MAX` argument returns a bounded delay rather
    /// than panicking.
    #[test]
    fn test_github_runner_rollout_poll_delay_saturates_without_panic_at_arbitrarily_large_attempt()
    {
        assert_eq!(
            github_runner_rollout_poll_delay(u32::MAX),
            Duration::from_secs(30),
            "attempt=u32::MAX must saturate to max_backoff without \
             panic — the `saturating_add(2)` bridge + \
             `RetryPolicy::compute_delay`'s `checked_pow` cap close \
             the u32 overflow class by construction.",
        );
        assert_eq!(
            github_runner_rollout_poll_delay(u32::MAX - 1),
            Duration::from_secs(30),
            "attempt=u32::MAX - 1 must also saturate to max_backoff \
             — the bridge `saturating_add(2)` returns u32::MAX, still \
             far past the cap.",
        );
    }

    /// [`RetryPolicy::network`]'s `factor == 2` and
    /// `max_backoff == 30s` are the Bazel/Buck2/SLSA-frontier reference
    /// schedule the retry module cites in its constructor docstrings.
    /// The rollout-watch poll policy consumes the same
    /// `(factor, max_backoff)` pair, diverging only at `initial_backoff`
    /// (5s vs 250ms) to preserve the pre-lift rollout-watch loop
    /// schedule verbatim. Pin the shared invariants so a future
    /// refinement to the retry module's reference schedule surfaces the
    /// intentional 5s-seed divergence as a named test failure rather
    /// than silently propagating. Sibling of
    /// `test_migration_job_poll_backoff_shares_network_factor_and_cap`
    /// at `services/migration_service.rs::tests` (ac61874) and
    /// `test_shinka_migration_poll_backoff_shares_network_factor_and_cap`
    /// at `commands/migrations.rs::tests` (b962db5).
    #[test]
    fn test_github_runner_rollout_poll_backoff_shares_network_factor_and_cap() {
        let network = RetryPolicy::network();
        assert_eq!(
            GITHUB_RUNNER_ROLLOUT_POLL_BACKOFF.factor, network.factor,
            "GITHUB_RUNNER_ROLLOUT_POLL_BACKOFF.factor must match \
             RetryPolicy::network().factor — both consume the \
             Bazel/Buck2/SLSA-frontier factor=2 reference.",
        );
        assert_eq!(
            GITHUB_RUNNER_ROLLOUT_POLL_BACKOFF.max_backoff, network.max_backoff,
            "GITHUB_RUNNER_ROLLOUT_POLL_BACKOFF.max_backoff must match \
             RetryPolicy::network().max_backoff — both consume the \
             Bazel/Buck2/SLSA-frontier 30s cap reference.",
        );
    }

    /// The rollout-watch loop-body shape MUST consume the typed
    /// primitive at `github_runner_rollout_poll_delay(backoff_attempt)`
    /// rather than the pre-lift bare-literal
    /// `sleep(Duration::from_secs(5))` shape. A future refactor that
    /// re-fuses the bare literal at the poll-loop sleep site (see
    /// `GITHUB_RUNNER_ROLLOUT_POLL_BACKOFF`'s docstring for the three
    /// structural defects the lift closed) fails here, not silently in
    /// production. Uses the `code_line_hits` helper
    /// (`test_support.rs`) so the shield does not false-positive on
    /// `GITHUB_RUNNER_ROLLOUT_POLL_BACKOFF`'s own docstring, which cites
    /// the pre-lift shape as context for the three defects it
    /// forecloses. The forbidden literal is reconstructed at test time
    /// via `format!` and the diagnostic prose refers to it only via
    /// the reconstructed `bespoke_needle` (never the fused literal),
    /// so the assert message body itself stays unmatchable. Whole-module
    /// boundary discipline sibling of
    /// `test_wait_for_job_consumes_typed_poll_delay_not_bare_fixed_sleep`
    /// at `services/migration_service.rs::tests` (ac61874),
    /// `test_wait_for_shinka_migration_consumes_typed_poll_delay_not_mut_backoff_secs`
    /// at `commands/migrations.rs::tests` (b962db5),
    /// `test_flux_polling_loops_consume_typed_poll_delay_not_bespoke_backoff_struct`
    /// at `commands/flux.rs::tests` (65de62f), and
    /// `test_helm_dependency_update_consumes_typed_retry_delay_not_bespoke_linear_sleep`
    /// at `commands/helm.rs::tests` (0a087de).
    #[test]
    fn test_execute_consumes_typed_rollout_poll_delay_not_bare_fixed_sleep() {
        let source = include_str!("github_runner_ci.rs");
        let tests_marker = "\n#[cfg(test)]\n";
        let body_end = source.find(tests_marker).expect(
            "the `#[cfg(test)]\\n` marker must follow the module body — \
             the shield's slice boundary relies on this module ordering",
        );
        let module_body = &source[..body_end];

        // Reconstruct the forbidden bare-literal at test time so this
        // shield's own body does not carry the fused literal — mirrors
        // the anti-self-match discipline the sibling lifts established.
        let bespoke_needle = format!(
            "tokio::time::sleep(tokio::time::Duration::from_secs({}))",
            5
        );

        // Code-line filter (via `code_line_hits`) skips docstring /
        // prose-comment lines, so the shield does not false-positive on
        // `GITHUB_RUNNER_ROLLOUT_POLL_BACKOFF`'s own docstring above
        // (which cites the pre-lift bare-literal shape as context for
        // the three defects it forecloses).
        let bespoke_hits = code_line_hits(module_body, &bespoke_needle);
        assert!(
            bespoke_hits.is_empty(),
            "github_runner_ci.rs must NOT re-fuse the pre-lift bare \
             `{}` literal at the rollout-watch poll-loop sleep site — \
             the schedule lives at `GITHUB_RUNNER_ROLLOUT_POLL_BACKOFF` \
             + `github_runner_rollout_poll_delay`, both grounding \
             through `RetryPolicy::compute_delay`. Found code-line \
             hits: {:#?}",
            bespoke_needle,
            bespoke_hits,
        );
        let delegation_hits = code_line_hits(
            module_body,
            "github_runner_rollout_poll_delay(backoff_attempt)",
        );
        assert!(
            !delegation_hits.is_empty(),
            "github_runner_ci.rs must consume the typed poll-delay \
             helper at the rollout-watch loop's sleep site — the \
             canonical delegation call was not found at any code line.",
        );
    }
}

#[cfg(test)]
mod nix_bin_routing_tests {
    /// Whole-module shield: no raw `Command::new("nix")` may live in
    /// `commands/github_runner_ci.rs`'s non-test body. Every `nix`
    /// spawn in this module must first resolve `NIX_BIN` via
    /// [`crate::repo::get_tool_path`] — the canonical env-var
    /// override every other nix-invocation site in forge honors
    /// (`commands/build.rs::execute` d8ef0d5,
    /// `commands/tool.rs::build_lock_target`,
    /// `commands/developer_tools.rs::rust_update_cargo_nix` and
    /// siblings 4dfb2b3, `commands/rust_service.rs`'s three nix
    /// spawn sites 7c34e57,
    /// `commands/product_release.rs::run_nix_release_app` d0cd622,
    /// `commands/nix_builder.rs::test`'s remote-build probe d930a5d,
    /// `commands/e2e.rs::build_and_load_image` 5cd137f,
    /// `nix.rs::build_flake_attr_in` / `build_docker_image_from_dir`
    /// / `path_info_recursive`, and
    /// `nix_hooks.rs::NixHooks::build_and_get_path`).
    ///
    /// Pre-lift this module carried one real `nix` spawn site: the
    /// `nix build .#dockerImage --print-build-logs` invocation in
    /// `execute()` at line 229 — Step 1/3 of the
    /// `forge github-runner-ci` workflow that materializes the
    /// self-hosted runner's OCI image (the image that subsequently
    /// gets pushed to GHCR via doca and pinned into the FluxCD-
    /// managed StatefulSet manifest). The spawn spelled
    /// `Command::new("nix")` verbatim, bypassing `NIX_BIN` at exactly
    /// the moment hermetic-runner consistency matters most — the
    /// step that produces the very image feeding the CI runner
    /// fleet. A Nix-hermetic runner with a store-path `nix` binary
    /// silently fell through to whatever `nix` was first on `PATH`
    /// at this site, diverging from every other nix-invocation
    /// surface in forge and from the sibling KUBECTL_BIN / GIT_BIN /
    /// CARGO / DOCKER_BIN / HELM_BIN frontier's uniform discipline.
    ///
    /// The scan bounds on the whole-module boundary (from the file
    /// start to the FIRST `\n#[cfg(test)]\n` marker in source order,
    /// which lands at the sibling `mod tests` block above) so this
    /// shield's own docstring mentions of `Command::new("nix")` —
    /// living in a `#[cfg(test)]` block below that first marker —
    /// stay out of scope AND every current or future nix-spawning
    /// helper landing anywhere in the top-level module body cannot
    /// silently ride along without going through `NIX_BIN`. Mirrors
    /// the sibling whole-module shields on `commands/build.rs`
    /// (d8ef0d5), `commands/developer_tools.rs` (4dfb2b3),
    /// `commands/rust_service.rs` (7c34e57),
    /// `commands/nix_builder.rs` (d930a5d), and `commands/e2e.rs`
    /// (5cd137f) — the whole-module-boundary scan discipline
    /// pioneered on `commands/supergraph_verification.rs` (65283fb).
    ///
    /// This shield closes the last raw `Command::new("nix")` site
    /// the prior five commit bodies enumerated as remaining on the
    /// command surface: with this migration, EVERY nix-invocation
    /// site across forge's `commands/` tree resolves the binary
    /// through the `NIX_BIN` env override — the "no raw nix spawn
    /// in a command module" floor is now a compile-checked
    /// whole-module-boundary invariant across the full command
    /// surface.
    #[test]
    fn test_github_runner_ci_routes_nix_through_nix_bin_not_raw_command() {
        const SOURCE: &str = include_str!("github_runner_ci.rs");
        let cutoff = SOURCE.find("\n#[cfg(test)]\n").expect(
            "github_runner_ci.rs must have a `#[cfg(test)]` marker — \
             the shield's scan boundary depends on it",
        );
        let body = &SOURCE[..cutoff];
        assert!(
            !body.contains("Command::new(\"nix\")"),
            "commands/github_runner_ci.rs must not spawn `nix` via \
             the bare literal — every `nix` spawn must resolve \
             `NIX_BIN` via `crate::repo::get_tool_path(\"NIX_BIN\", \
             \"nix\")` first. A raw `Command::new(\"nix\")` bypasses \
             the hermetic-runner contract substrate's \
             mkRuntimeToolsEnv exports."
        );
        assert!(
            body.contains("get_tool_path(\"NIX_BIN\", \"nix\")"),
            "commands/github_runner_ci.rs must resolve the nix \
             binary via `get_tool_path(\"NIX_BIN\", \"nix\")` — the \
             canonical lookup was not found in the module body."
        );
    }
}
