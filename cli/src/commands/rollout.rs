use anyhow::Result;
use colored::Colorize;
use std::collections::HashMap;
use tracing::{debug, error, info, warn};

use crate::infrastructure::kubectl::kubectl_command_async;
use crate::k8s;

#[derive(Clone, Debug)]
struct PodStateHistory {
    last_state: String,
    last_reason: Option<String>,
    iterations_in_state: u32,
    last_restart_count: i32,
}

pub async fn execute(
    namespace: String,
    name: String,
    interval: u64,
    timeout: Option<String>,
    rollback: bool,
    safe_mode: bool,
) -> Result<()> {
    // If rollback requested, perform rollback and exit
    if rollback {
        info!("🔄 Performing rollback...");
        info!("   Namespace: {}", namespace);
        info!("   Deployment: {}", name);
        println!();

        let rollback_result = kubectl_command_async()
            .args(&[
                "rollout",
                "undo",
                &format!("deployment/{}", name),
                "-n",
                &namespace,
            ])
            .status()
            .await;

        match rollback_result {
            Ok(status) if status.success() => {
                info!("✅ Rollback initiated successfully");
                println!();

                // Monitor the rollback
                info!("🔄 Monitoring rollback progress...");
                println!();
            }
            Ok(status) => {
                anyhow::bail!("Rollback failed with exit code: {:?}", status.code());
            }
            Err(e) => {
                anyhow::bail!("Failed to execute rollback: {}", e);
            }
        }
    }

    info!("🔄 Rolling out new image to all pods...");
    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    let client = k8s::create_client().await?;

    // Get total replicas and expected image tag
    let replicas = k8s::get_replicas(&client, &namespace, &name).await?;
    let expected_tag = k8s::get_expected_image_tag(&client, &namespace, &name).await?;
    info!("   Total replicas: {}", replicas);
    info!("   Expected image tag: {}", expected_tag);

    // Parse timeout if provided
    let max_iterations = if let Some(timeout_str) = timeout {
        parse_timeout(&timeout_str)?
    } else {
        200 // Default: 200 * 3s = 10 minutes
    };

    if max_iterations < 200 {
        info!(
            "   Timeout: {} iterations (~{}s)",
            max_iterations,
            max_iterations * interval
        );
    }
    println!();

    info!(
        "Tracking pod updates (refreshing every {} seconds):",
        interval
    );
    println!();

    let mut iteration = 0;

    let mut pod_status_history: HashMap<String, String> = HashMap::new();
    let mut pod_state_tracking: HashMap<String, PodStateHistory> = HashMap::new();

    // Build label selector for the deployment
    let label_selector = format!("app={}", name);

    // Thresholds for stuck detection
    const STUCK_THRESHOLD_ITERATIONS: u32 = 10; // 30 seconds with 3s interval
    const RESTART_THRESHOLD: i32 = 3;

    loop {
        iteration += 1;

        if iteration > max_iterations {
            warn!("⏱️  Timeout reached after {} iterations", max_iterations);
            anyhow::bail!("Rollout timeout exceeded");
        }

        // Get pod statuses
        let pods = k8s::get_pod_statuses(&client, &namespace, &label_selector).await?;

        // Clear screen for refresh (move cursor up if not first iteration)
        if iteration > 1 {
            for _ in 0..=pods.len() + 2 {
                print!("\x1B[1A\x1B[2K"); // Move up and clear line
            }
        }

        // Print timestamp
        let now = chrono::Local::now();
        println!(
            "{} - Rollout Progress (pods: {}):",
            now.format("%H:%M:%S"),
            pods.len()
        );
        println!();

        let mut all_ready = true;
        let mut updated_count = 0;
        let mut problems_detected = Vec::new();

        for pod in &pods {
            // Check for bad states
            let is_bad = k8s::is_bad_state(pod);

            // Track state history
            let current_state = pod
                .container_state
                .as_ref()
                .map(|s| s.state.clone())
                .unwrap_or_else(|| pod.phase.clone());

            let current_reason = pod.container_state.as_ref().and_then(|s| s.reason.clone());

            let current_restarts = pod
                .container_state
                .as_ref()
                .map(|s| s.restart_count)
                .unwrap_or(0);

            let state_key = format!(
                "{}:{}",
                current_state,
                current_reason.as_deref().unwrap_or("")
            );

            let history = pod_state_tracking
                .entry(pod.name.clone())
                .or_insert_with(|| PodStateHistory {
                    last_state: state_key.clone(),
                    last_reason: current_reason.clone(),
                    iterations_in_state: 0,
                    last_restart_count: current_restarts,
                });

            // Check if state changed
            if history.last_state == state_key {
                history.iterations_in_state += 1;
            } else {
                debug!(
                    "Pod {} state changed: {} -> {}",
                    pod.name, history.last_state, state_key
                );
                history.last_state = state_key.clone();
                history.last_reason = current_reason.clone();
                history.iterations_in_state = 1;
            }

            // Update restart count
            history.last_restart_count = current_restarts;

            // Detect stuck pods
            let is_stuck = history.iterations_in_state >= STUCK_THRESHOLD_ITERATIONS
                && !pod.ready
                && pod.phase != "Succeeded";

            // Detect excessive restarts
            let excessive_restarts = current_restarts >= RESTART_THRESHOLD;

            // Choose icon based on state
            let status_icon = if is_bad {
                "❌".bright_red()
            } else if excessive_restarts {
                "🔄".bright_red()
            } else if is_stuck {
                "⚠️ ".bright_yellow()
            } else if pod.ready && pod.phase == "Running" {
                "✅".bright_green()
            } else if pod.phase == "Running" {
                "🔄".bright_yellow()
            } else {
                "⏳".bright_blue()
            };

            // Build status message with detailed state info
            let mut status_parts = vec![format!("Image: {}", pod.image_tag)];

            if let Some(state) = &pod.container_state {
                status_parts.push(format!("State: {}", state.state));

                if let Some(reason) = &state.reason {
                    status_parts.push(format!("Reason: {}", reason));
                }

                if state.restart_count > 0 {
                    status_parts.push(format!("Restarts: {}", state.restart_count));
                }
            } else {
                status_parts.push(format!("Phase: {}", pod.phase));
            }

            if is_stuck {
                status_parts.push(format!(
                    "⚠️  STUCK ({}s)",
                    history.iterations_in_state * interval as u32
                ));
            }

            let status_msg = if is_bad || excessive_restarts {
                status_parts.join(" | ").bright_red()
            } else if is_stuck {
                status_parts.join(" | ").bright_yellow()
            } else if pod.ready && pod.phase == "Running" {
                status_parts.join(" | ").bright_green()
            } else {
                status_parts.join(" | ").bright_blue()
            };

            // Check if pod has the expected image
            let has_correct_image = pod.image_tag == expected_tag;
            let needs_update = !has_correct_image;

            // Show indicator if pod needs update
            let update_indicator = if needs_update {
                " 🔄 UPDATE PENDING".bright_yellow()
            } else {
                "".normal()
            };

            println!(
                "  {} {} | {}{}",
                status_icon, pod.name, status_msg, update_indicator
            );

            // Track problems for SAFE mode
            if is_bad || excessive_restarts || is_stuck {
                problems_detected.push((pod.clone(), is_bad, excessive_restarts, is_stuck));
                all_ready = false;
            } else if pod.ready && pod.phase == "Running" && has_correct_image {
                // Only count as updated if pod is ready AND has the correct image
                updated_count += 1;
            } else {
                all_ready = false;
            }

            // Update image tag history
            pod_status_history.insert(pod.name.clone(), pod.image_tag.clone());
        }

        // Check if we should scrape diagnostics (SAFE mode)
        if safe_mode && !problems_detected.is_empty() {
            error!("🔬 Problems detected! Scraping diagnostics...");
            println!();

            for (pod, is_bad, excessive_restarts, _is_stuck) in &problems_detected {
                error!("━━━ Diagnostics for {} ━━━", pod.name);

                let problem_type = if *is_bad {
                    "BAD STATE"
                } else if *excessive_restarts {
                    "EXCESSIVE RESTARTS"
                } else {
                    "STUCK"
                };

                error!("Problem: {}", problem_type);

                // Show container state details
                if let Some(state) = &pod.container_state {
                    error!("Container State: {}", state.state);
                    if let Some(reason) = &state.reason {
                        error!("Reason: {}", reason);
                    }
                    if let Some(message) = &state.message {
                        error!("Message: {}", message);
                    }
                    error!("Restart Count: {}", state.restart_count);
                }

                // Get events
                match k8s::get_pod_events(&client, &namespace, &pod.name).await {
                    Ok(events) => {
                        if !events.is_empty() {
                            error!("Recent Events:");
                            for event in events.iter().rev().take(10) {
                                error!("  {}", event);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to get events: {}", e);
                    }
                }

                // Get logs
                match k8s::get_pod_logs(&client, &namespace, &pod.name, 30).await {
                    Ok(logs) => {
                        if !logs.is_empty() {
                            error!("Recent Logs (last 30 lines):");
                            for line in logs.lines().take(30) {
                                error!("  {}", line);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to get logs: {}", e);
                    }
                }

                println!();
            }

            anyhow::bail!(
                "Rollout failed with {} problem(s) detected in SAFE mode",
                problems_detected.len()
            );
        }

        // Check if rollout complete
        if all_ready && updated_count == replicas as usize {
            println!();
            break;
        }

        // Sleep before next iteration
        tokio::time::sleep(tokio::time::Duration::from_secs(interval)).await;
    }

    println!();
    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    info!("{}", "✅ All pods updated and ready!".bright_green().bold());
    println!();

    Ok(())
}

/// Parse the `rollout --timeout` CLI flag into a number of poll
/// iterations at the 3-second poll interval. The string grammar is the
/// canonical [`crate::duration::parse_duration`] oracle (lifted out of
/// this module's prior hand-rolled suffix match); an empty string keeps
/// this CLI's historical default of 200 iterations (≈10 minutes).
///
/// Routes through [`crate::duration::parse_timeout_field`] so a malformed
/// `--timeout 5min` surfaces both the offending value AND the field name
/// (`rollout --timeout`) — byte-for-byte the same
/// `"invalid timeout '{value}' for {field}"` shape the five `deploy.yaml`
/// timeout-parse sites (`PreDeploymentTestsConfig::validate`,
/// `run_test_suite`, `execute_pre_deployment_tests`, `execute::warmup_delay`,
/// `execute_suite`) already emit. Was the last inline
/// `parse_duration(&s)?` call outside the tests module that named the
/// offending value without naming the field.
fn parse_timeout(timeout_str: &str) -> Result<u64> {
    let timeout_str = timeout_str.trim();

    if timeout_str.is_empty() {
        return Ok(200); // Default
    }

    let total_seconds =
        crate::duration::parse_timeout_field(timeout_str, "rollout --timeout")?.as_secs();

    // Convert to iterations (assuming 3 second interval); at least 1.
    Ok((total_seconds / 3).max(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An empty timeout string keeps the historical default of 200
    /// iterations (≈10 minutes at the 3-second poll interval), so the
    /// caller pattern `parse_timeout(&timeout_str)?` at line ~75 keeps
    /// the same default the old inline `200 // Default` fallback gave
    /// when no `--timeout` was provided.
    #[test]
    fn empty_returns_default_iterations() {
        assert_eq!(parse_timeout("").unwrap(), 200);
        assert_eq!(parse_timeout("   ").unwrap(), 200);
    }

    /// Well-formed timeouts convert to iteration counts at the 3-second
    /// poll interval. `"5m"` = 300s ÷ 3 = 100 iterations; `"2h"` =
    /// 7200s ÷ 3 = 2400 iterations; a bare `"30"` = 30s ÷ 3 = 10.
    #[test]
    fn well_formed_timeouts_convert_to_iteration_count() {
        assert_eq!(parse_timeout("5m").unwrap(), 100);
        assert_eq!(parse_timeout("2h").unwrap(), 2400);
        assert_eq!(parse_timeout("30").unwrap(), 10);
        assert_eq!(parse_timeout("30s").unwrap(), 10);
    }

    /// Sub-poll-interval timeouts saturate to a single iteration rather
    /// than 0, so the poll loop still runs once and either succeeds or
    /// reports timeout — the same `.max(1)` guard the prior inline
    /// arithmetic used.
    #[test]
    fn sub_interval_timeout_saturates_to_one_iteration() {
        assert_eq!(parse_timeout("1s").unwrap(), 1);
        assert_eq!(parse_timeout("2s").unwrap(), 1);
        assert_eq!(parse_timeout("3s").unwrap(), 1);
    }

    /// The load-bearing shape-uniformity assertion: a malformed
    /// `rollout --timeout` value now emits the canonical
    /// `"invalid timeout '{value}' for {field}"` shape — byte-for-byte
    /// the same shape the five `deploy.yaml` timeout-parse sites emit
    /// through [`crate::duration::parse_timeout_field`]. Before this
    /// commit the CLI site called `parse_duration` bare and propagated a
    /// naked `"invalid timeout '5min': magnitude '5mi' is not a base-10
    /// integer …"` — the offending value was echoed but the field
    /// (`--timeout`) was not, breaking the ONE-shape discipline the five
    /// `deploy.yaml` sites established.
    #[test]
    fn malformed_error_names_offending_value_and_field() {
        let err = parse_timeout("5min").unwrap_err().to_string();
        assert!(
            err.contains("5min"),
            "error must echo the offending value: {err}"
        );
        assert!(
            err.contains("rollout --timeout"),
            "error must name the field (rollout --timeout) so a user sees \
             which CLI flag forge rejected: {err}"
        );
        assert!(
            err.contains("invalid timeout"),
            "error must use the canonical `invalid timeout '{{v}}' for {{f}}` \
             shape parse_timeout_field emits at the five deploy.yaml sites, \
             so a `grep 'invalid timeout'` alert scoops up CLI grammar \
             rejections uniformly with config-load + runtime rejections: {err}"
        );
    }

    /// The other malformed shapes — English-phrase units, non-numeric
    /// magnitudes, negative magnitudes — all route through the same
    /// oracle so a user cannot land on a `deploy.yaml` timeout error
    /// grammar that differs from the `--timeout` CLI grammar for the
    /// same input.
    #[test]
    fn other_malformed_shapes_error_through_same_oracle() {
        for bad in ["10 minutes", "abc", "-5s"] {
            let err = parse_timeout(bad).unwrap_err().to_string();
            assert!(
                err.contains("rollout --timeout"),
                "malformed input {bad:?} must route through parse_timeout_field \
                 and name the field: {err}"
            );
            assert!(
                err.contains(bad),
                "malformed input {bad:?} must be echoed in the error: {err}"
            );
        }
    }

    /// Whole-module shield: no raw `Command::new`-with-bare-`kubectl`-
    /// literal may live in `commands/rollout.rs`. Every `kubectl`
    /// spawn on this module's `execute` rollback path must resolve
    /// through
    /// [`crate::infrastructure::kubectl::kubectl_command_async`] —
    /// the async constructor that reads the `KUBECTL_BIN` env
    /// override via [`crate::tools::get_tool_path`] on the canonical
    /// `tools::KUBECTL` name.
    ///
    /// Pre-lift the sole `kubectl` spawn — `execute`'s
    /// `kubectl rollout undo deployment/<name> -n <ns>` step on the
    /// `--rollback` branch — spelled the bare `"kubectl"` literal
    /// verbatim, ignoring `KUBECTL_BIN` at the site. A Nix-hermetic
    /// runner's substrate-derived `kubectl` path was lost to
    /// whatever `kubectl` sat first on PATH — the same silent-PATH-
    /// fallback bug class the sibling ten async-consumer sites in
    /// forge already avoid (`product_release::run_health_check`,
    /// `github_runner_ci::execute`, `services/migration_service`,
    /// `supergraph_verification`, `commands/status`, `commands/flux`,
    /// `commands/migrations`, `commands/federation_tests`,
    /// `commands/e2e`, and the tools-registry-idiom sibling
    /// consumers the recent claude-routine commits converged on).
    ///
    /// This shield scans the module's own source via [`include_str!`]
    /// and forbids the fused literal shape. The forbidden shape is
    /// reconstructed via [`format!`] so this shield's own source text
    /// does not false-match itself — the whole-module scan therefore
    /// covers both the top-of-file production body AND every sibling
    /// `#[cfg(test)]` block (any of which could otherwise silently
    /// re-introduce a raw literal). The end-to-end
    /// `KUBECTL_BIN`-routing invariant of the underlying primitive
    /// is pinned separately by
    /// [`crate::infrastructure::kubectl::tests::test_kubectl_command_async_routes_through_kubectl_bin_env_var`];
    /// this shield only certifies that every `kubectl`-spawning site
    /// in this module resolves through the constructor first.
    #[test]
    fn test_kubectl_spawn_routes_through_kubectl_command_async_not_raw_literal() {
        const SOURCE: &str = include_str!("rollout.rs");

        crate::test_support::assert_source_forbids_bare_spawn_shapes(
            SOURCE,
            "commands/rollout.rs",
            "kubectl",
            "resolve the substrate-exported `KUBECTL_BIN` env override via \
             `kubectl_command_async`",
        );
        crate::test_support::assert_source_delegates_via_constructor_call_code_line(
            SOURCE,
            "commands/rollout.rs",
            "kubectl",
            "kubectl_command_async",
        );
    }
}
