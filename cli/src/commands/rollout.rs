use anyhow::Result;
use colored::Colorize;
use std::collections::HashMap;
use tokio::process::Command;
use tracing::{debug, error, info, warn};

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

        let rollback_result = Command::new("kubectl")
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

/// Parse timeout string (e.g., "5m", "30s", "2h") into number of iterations
fn parse_timeout(timeout_str: &str) -> Result<u64> {
    let timeout_str = timeout_str.trim();

    if timeout_str.is_empty() {
        return Ok(200); // Default
    }

    // Extract number and unit
    let (num_str, unit) = if timeout_str.ends_with('s') {
        (timeout_str.trim_end_matches('s'), "s")
    } else if timeout_str.ends_with('m') {
        (timeout_str.trim_end_matches('m'), "m")
    } else if timeout_str.ends_with('h') {
        (timeout_str.trim_end_matches('h'), "h")
    } else {
        // Assume seconds if no unit
        (timeout_str, "s")
    };

    let num: u64 = num_str
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid timeout format: {}", timeout_str))?;

    // Convert to seconds
    let total_seconds = match unit {
        "s" => num,
        "m" => num * 60,
        "h" => num * 3600,
        _ => return Err(anyhow::anyhow!("Unknown timeout unit: {}", unit)),
    };

    // Convert to iterations (assuming 3 second interval)
    let iterations = total_seconds / 3;

    Ok(iterations.max(1)) // At least 1 iteration
}
