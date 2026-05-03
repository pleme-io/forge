use anyhow::{Context, Result};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use tokio::process::Command;
use tracing::{debug, info, warn};

use crate::git;
use crate::repo::get_tool_path;
use crate::retry::{retry_command, RetryPolicy};

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
        let attic_token = std::env::var("ATTIC_TOKEN").or_else(|_| {
            debug!("ATTIC_TOKEN not in env, trying kubectl...");

            // Try github-actions namespace first
            let token = std::process::Command::new("kubectl")
                .args(&[
                    "get",
                    "secret",
                    "attic-secrets",
                    "-n",
                    "github-actions",
                    "-o",
                    "jsonpath={.data.server-token}",
                ])
                .output()
                .ok()
                .and_then(|o| {
                    if o.status.success() {
                        debug!("Found attic-secrets in github-actions namespace");
                        String::from_utf8(o.stdout)
                            .ok()
                            .and_then(|s| base64::decode(s.trim()).ok())
                            .and_then(|b| String::from_utf8(b).ok())
                    } else {
                        debug!("attic-secrets not found in github-actions namespace");
                        None
                    }
                });

            // Fall back to configured namespace (via ATTIC_FALLBACK_NAMESPACE env var)
            token.or_else(|| {
                let fallback_ns = std::env::var("ATTIC_FALLBACK_NAMESPACE").ok()?;
                debug!("Trying {} namespace...", fallback_ns);
                std::process::Command::new("kubectl")
                    .args(&[
                        "get",
                        "secret",
                        "attic-secrets",
                        "-n",
                        &fallback_ns,
                        "-o",
                        "jsonpath={.data.server-token}",
                    ])
                    .output()
                    .ok()
                    .and_then(|o| {
                        if o.status.success() {
                            debug!("Found attic-secrets in {} namespace", fallback_ns);
                            String::from_utf8(o.stdout)
                                .ok()
                                .and_then(|s| base64::decode(s.trim()).ok())
                                .and_then(|b| String::from_utf8(b).ok())
                        } else {
                            debug!("attic-secrets not found in {} namespace", fallback_ns);
                            None
                        }
                    })
            })
            .ok_or_else(|| anyhow::anyhow!("ATTIC_TOKEN not found in env or kubernetes (tried github-actions namespace; set ATTIC_FALLBACK_NAMESPACE for additional namespace)"))
        })?;

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

        // Login to Attic with retry logic
        attic_command_with_retry(
            &["login", &attic_server, &cache_url, &attic_token],
            "login to Attic",
            safe_mode,
        )
        .await?;

        // Use cache with retry logic
        attic_command_with_retry(
            &["use", &format!("{}:{}", attic_server, cache_name)],
            "configure Attic cache",
            safe_mode,
        )
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

        let push_result = attic_command_with_retry(
            &["push", &cache_name, &build_output],
            "push to Attic cache",
            safe_mode,
        )
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

        info!("📤 Pushing to GHCR with skopeo...");

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
    let flux_system_result = Command::new("flux")
        .args(&[
            "reconcile",
            "kustomization",
            "flux-system",
            "-n",
            "flux-system",
            "--with-source",
        ])
        .output()
        .await;

    match flux_system_result {
        Ok(output) if output.status.success() => {
            info!("✅ FluxCD reconciliation complete");
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("⚠️  FluxCD reconcile failed (non-fatal): {}", stderr);
        }
        Err(e) => {
            warn!("⚠️  Could not execute flux command (non-fatal): {}", e);
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
            let pod_status_result = Command::new("kubectl")
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
                                    let log_result = Command::new("kubectl")
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
        let verify_result = Command::new("kubectl")
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

/// Execute an `attic` subcommand with retry-on-transient.
///
/// Drives [`crate::retry::retry_command`] with a network-shaped policy
/// (5 attempts × 250ms × factor=2 capped at 30s) when `safe_mode` is on,
/// or [`RetryPolicy::immediate`] (no retry) when off. The lifted helper
/// composes the canonical `is_transient_network_stderr` classifier with
/// the canonical `CommandAttemptFailure::from_capture` mapping in one
/// primitive — the duplication budget on the hand-rolled retry loops in
/// `commands/push.rs::push_with_retry` and `commands/github_runner_ci.rs`
/// is redeemed by construction (THEORY §VI.1). The LAST
/// `CommandAttemptFailure` from the loop is mapped to `anyhow::Error` at
/// the public boundary so existing call sites remain unchanged.
async fn attic_command_with_retry(args: &[&str], operation: &str, safe_mode: bool) -> Result<()> {
    let policy = if safe_mode {
        RetryPolicy::network()
    } else {
        RetryPolicy::immediate()
    };
    let max_attempts = policy.max_attempts;
    let attic = get_tool_path("ATTIC_BIN", "attic");
    let op = operation.to_string();
    let op_for_warn = op.clone();

    let result = retry_command(&policy, &op, |attempt| {
        let attic = attic.clone();
        let op_for_warn = op_for_warn.clone();
        async move {
            debug!("Running: attic {}", args.join(" "));
            let outcome = Command::new(&attic)
                .args(args)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .output()
                .await;

            match outcome.as_ref() {
                Ok(out) if out.status.success() => {
                    debug!("attic command succeeded on attempt {}", attempt);
                }
                Ok(out) => {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    if !stdout.trim().is_empty() {
                        debug!("attic stdout: {}", stdout.trim());
                    }
                    if !stderr.trim().is_empty() {
                        debug!("attic stderr: {}", stderr.trim());
                    }
                    if attempt < max_attempts {
                        warn!(
                            "⚠️  {} failed (attempt {}/{}): retrying...",
                            op_for_warn, attempt, max_attempts
                        );
                    }
                }
                Err(_) => {
                    if attempt < max_attempts {
                        warn!(
                            "⚠️  {} failed (attempt {}/{}): retrying...",
                            op_for_warn, attempt, max_attempts
                        );
                    }
                }
            }
            outcome
        }
    })
    .await;

    result.map(|_| ()).map_err(|e| anyhow::anyhow!("{}", e))
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

    let skopeo = get_tool_path("SKOPEO_BIN", "skopeo");

    // Pre-loop: skopeo must be available. Same structural precondition.
    debug!("Checking if skopeo is available at: {}", skopeo);
    let skopeo_check = Command::new(&skopeo).arg("--version").output().await;
    match skopeo_check {
        Ok(output) if output.status.success() => {
            debug!(
                "Found skopeo: {}",
                String::from_utf8_lossy(&output.stdout).trim()
            );
        }
        _ => {
            anyhow::bail!(
                "skopeo command not found (checked SKOPEO_BIN env var and PATH). Please install skopeo:\n\
                 - macOS: brew install skopeo\n\
                 - Linux: apt-get install skopeo or yum install skopeo\n\
                 - Nix: nix-shell -p skopeo"
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
    let policy = if safe_mode {
        RetryPolicy::network()
    } else {
        RetryPolicy::immediate()
    };
    let max_attempts = policy.max_attempts;
    let op = format!("push {}:{}", registry, tag);

    let result = retry_command(&policy, &op, |attempt| {
        let skopeo = skopeo.clone();
        let organization = organization.clone();
        async move {
            debug!("Pushing {}:{} (attempt {})", registry, tag, attempt);
            let outcome = Command::new(&skopeo)
                .args([
                    "copy",
                    "--insecure-policy",
                    &format!("--retry-times={}", retries),
                    &format!("--dest-creds={}:{}", organization, token),
                    &format!("docker-archive:{}", image_path),
                    &format!("docker://{}:{}", registry, tag),
                ])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .output()
                .await;

            match outcome.as_ref() {
                Ok(out) if out.status.success() => {
                    debug!("Push successful for {}:{}", registry, tag);
                }
                Ok(out) => {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    if !stdout.trim().is_empty() {
                        debug!("skopeo stdout: {}", stdout.trim());
                    }
                    if !stderr.trim().is_empty() {
                        debug!("skopeo stderr: {}", stderr.trim());
                    }
                    if attempt < max_attempts {
                        warn!("Push attempt {} failed, retrying...", attempt);
                    }
                }
                Err(_) => {
                    if attempt < max_attempts {
                        warn!("Push attempt {} failed, retrying...", attempt);
                    }
                }
            }
            outcome
        }
    })
    .await;

    result.map(|_| ()).map_err(|e| anyhow::anyhow!("{}", e))
}
