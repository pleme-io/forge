use anyhow::{Context, Result};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use tokio::process::Command;
use tracing::{debug, info, warn};

use crate::flux_reconcile;
use crate::git;
use crate::infrastructure::kubectl::kubectl_command_async;
use crate::repo::get_tool_path;
use crate::retry::{debug_log_capture_streams, log_retry_attempt, retry_command, RetryPolicy};

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

        let build_result = Command::new("nix")
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

            // Wait before next check
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
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
    let (host, image) = registry
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("registry {registry:?} has no '/', cannot split host from image"))?;
    let host = host.to_string();
    let image = image.to_string();

    let result = retry_command(&policy, &op, |attempt| {
        let doca = doca.clone();
        let organization = organization.clone();
        let op = op.clone();
        let policy = policy.clone();
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
            // domain-specific (per-call-site context).
            if let Ok(out) = outcome.as_ref() {
                if out.status.success() {
                    debug!("Push successful for {}:{}", registry, tag);
                } else {
                    debug_log_capture_streams(out, "doca");
                }
            }
            log_retry_attempt(outcome, &op, attempt, &policy)
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
        let source = include_str!("github_runner_ci.rs");
        let execute_start = source
            .find("pub async fn execute(")
            .expect("execute() must be present in this module's source");
        // Bound the search at the tests module marker so this test's
        // own docstring — which legitimately spells the pre-migration
        // `&["push", ...]` args slice for context — is excluded from
        // the scan. The pre-migration `\nasync fn attic_command_with_retry`
        // boundary marker was retired when the helper itself was
        // deleted; the tests-module boundary is the load-bearing
        // marker every real `execute()` code site sits strictly above.
        let helper_marker = "\n#[cfg(test)]";
        let execute_end = source[execute_start..]
            .find(helper_marker)
            .map(|i| execute_start + i)
            .expect(
                "the `#[cfg(test)]` tests-module marker must follow `execute()` — \
                 the shield's slice boundary relies on this module ordering",
            );
        let execute_body = &source[execute_start..execute_end];

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
        let source = include_str!("github_runner_ci.rs");
        let execute_start = source
            .find("pub async fn execute(")
            .expect("execute() must be present in this module's source");
        // Bound the search at the tests module marker so this test's
        // own docstring — which legitimately spells the pre-migration
        // `&["use", ...]` args slice for context — is excluded from
        // the scan. The pre-migration `\nasync fn attic_command_with_retry`
        // boundary marker was retired when the helper itself was
        // deleted.
        let helper_marker = "\n#[cfg(test)]";
        let execute_end = source[execute_start..]
            .find(helper_marker)
            .map(|i| execute_start + i)
            .expect(
                "the `#[cfg(test)]` tests-module marker must follow `execute()` — \
                 the shield's slice boundary relies on this module ordering",
            );
        let execute_body = &source[execute_start..execute_end];

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
        let source = include_str!("github_runner_ci.rs");
        let execute_start = source
            .find("pub async fn execute(")
            .expect("execute() must be present in this module's source");
        // Bound the search at the tests module marker so this test's
        // own docstring — which legitimately spells the pre-migration
        // `&["login", ...]` args slice for context — is excluded from
        // the scan.
        let helper_marker = "\n#[cfg(test)]";
        let execute_end = source[execute_start..]
            .find(helper_marker)
            .map(|i| execute_start + i)
            .expect(
                "the `#[cfg(test)]` tests-module marker must follow `execute()` — \
                 the shield's slice boundary relies on this module ordering",
            );
        let execute_body = &source[execute_start..execute_end];

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
        let retired_helper_marker =
            concat!("\n", "async fn ", "attic_command_with_retry");
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
        let source = include_str!("github_runner_ci.rs");
        let execute_start = source
            .find("pub async fn execute(")
            .expect("execute() must be present in this module's source");
        // Bound at the next top-level function marker in source order.
        // `push_with_retry` follows `execute`; the tests-module
        // `#[cfg(test)]` marker follows `push_with_retry`. Using the
        // fn-boundary keeps the shield scoped strictly to `execute()`
        // so a future kubectl-spawning helper landing between the two
        // functions cannot silently ride along without its own shield.
        let helper_marker = "\nasync fn push_with_retry(";
        let execute_end = source[execute_start..]
            .find(helper_marker)
            .map(|i| execute_start + i)
            .expect(
                "the `async fn push_with_retry(` marker must follow \
                 `execute()` — the shield's slice boundary relies on \
                 this module ordering",
            );
        let execute_body = &source[execute_start..execute_end];

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
}
