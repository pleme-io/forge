//! FluxCD operations for GitOps deployments.

use anyhow::{bail, Context, Result};
use colored::Colorize;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::sleep;

use crate::config::DeployConfig;
use crate::flux_get::{
    get_kustomization_scoped, list_kustomizations_all_namespaces, list_kustomizations_in_namespace,
    FluxGetKustomizationsError, KustomizationRow,
};

/// FluxCD health check before and after deployments.
///
/// This verifies the GitOps system is healthy before and after deployments.
/// Returns an error if any kustomization is not Ready.
pub async fn health_check(context: &str) -> Result<()> {
    println!(
        "🩺 {}",
        format!("FluxCD health check ({})...", context).bold()
    );

    // Route through the canonical `flux_get::list_kustomizations_all_namespaces`
    // primitive so this site honors `FLUX_BIN` (via `get_tool_path("flux")`)
    // and — on failure — surfaces the typed `(exit_code, stderr)` record. The
    // outer `.context("Failed to run flux get kustomizations")?` wraps the
    // typed error, so a telemetry consumer can still recover the typed
    // variant across the anyhow boundary via
    // `err.downcast_ref::<FluxGetKustomizationsError>()`.
    let rows = list_kustomizations_all_namespaces()
        .await
        .context("Failed to run flux get kustomizations")?;

    let (ready_count, failures) = partition_ready(&rows);
    let total = rows.len();

    println!("   Kustomizations: {}/{} ready", ready_count, total);

    if !failures.is_empty() {
        println!();
        println!("{}", "❌ FluxCD is NOT healthy:".red().bold());
        for failure in &failures {
            println!("{}", failure.red());
        }
        println!();
        println!(
            "{}",
            "FluxCD must be healthy before releases can proceed.".yellow()
        );
        println!("{}", "Please fix the issues above and try again.".yellow());
        println!();
        println!("Debug commands:");
        println!("  flux get all                  # Show all FluxCD resources");
        println!("  flux logs --all-namespaces    # Check FluxCD controller logs");

        bail!(
            "FluxCD health check failed: {} kustomization(s) not ready",
            failures.len()
        );
    }

    println!("   {}", "✅ All kustomizations are healthy".green());
    Ok(())
}

/// FluxCD health check with retry logic for post-release verification
///
/// After pushing changes to git and triggering Flux reconciliation, kustomizations
/// temporarily enter "not ready" states. This function waits for Flux to finish
/// reconciling before declaring success or failure.
///
/// # Parameters
/// * `context` - Description of when this check is running (e.g., "post-release")
/// * `timeout_secs` - Maximum time to wait for Flux to become healthy (seconds)
/// * `interval_secs` - Time between retry attempts (seconds)
///
/// # Returns
/// * `Ok(())` if Flux becomes healthy within timeout
/// * `Err` if Flux is still unhealthy after timeout
pub async fn health_check_with_retry(
    context: &str,
    timeout_secs: u64,
    interval_secs: u64,
) -> Result<()> {
    println!(
        "🩺 {}",
        format!("FluxCD health check ({})...", context).bold()
    );
    println!(
        "   ⏳ Waiting up to {} seconds for Flux to reconcile...",
        timeout_secs
    );

    let start = std::time::Instant::now();
    let mut attempt = 0;

    loop {
        attempt += 1;
        let elapsed = start.elapsed().as_secs();

        // Try the health check
        match check_health_status().await {
            Ok((ready, total)) => {
                println!(
                    "   ✅ All kustomizations healthy ({}/{} ready)",
                    ready, total
                );
                return Ok(());
            }
            Err((ready, total, failures)) => {
                // Check if we've exceeded timeout
                if elapsed >= timeout_secs {
                    println!();
                    println!(
                        "{}",
                        "❌ FluxCD health check FAILED after timeout".red().bold()
                    );
                    println!("   Waited: {} seconds", elapsed);
                    println!("   Status: {}/{} kustomizations ready", ready, total);
                    println!();
                    println!("{}", "Unhealthy kustomizations:".red().bold());
                    for failure in &failures {
                        println!("{}", failure.red());
                    }
                    println!();
                    println!("Debug commands:");
                    println!("  flux get all                  # Show all FluxCD resources");
                    println!("  flux logs --all-namespaces    # Check FluxCD controller logs");

                    bail!(
                        "FluxCD health check failed after {} seconds: {} kustomization(s) not ready",
                        elapsed,
                        failures.len()
                    );
                }

                // Not healthy yet, but haven't timed out
                println!(
                    "   ⏳ Attempt {}: {}/{} kustomizations ready ({} reconciling, {} seconds remaining...)",
                    attempt,
                    ready,
                    total,
                    failures.len(),
                    timeout_secs - elapsed
                );

                // Show which kustomizations are not ready (condensed format)
                if failures.len() <= 5 {
                    for failure in &failures {
                        println!("      {}", failure.dimmed());
                    }
                } else {
                    // Too many failures, just show count
                    println!(
                        "      {} kustomizations still reconciling...",
                        failures.len()
                    );
                }

                // Wait before next attempt
                sleep(Duration::from_secs(interval_secs)).await;
            }
        }
    }
}

/// Partition parsed kustomization rows into `(ready_count, failure_lines)`.
///
/// The `ready` counter and the `failure_lines` vector are the two outputs
/// both `health_check` and `check_health_status` re-derived from the raw
/// parsed rows verbatim before this lift. Naming the partition here means
/// the two sites share the exact counting-and-rendering discipline: a
/// future prose refresh on the failure line (owned by
/// [`KustomizationRow::render_failure_line`]) or a future refinement of
/// the ready predicate (owned by [`KustomizationRow::is_ready`]) lands
/// at one method and reaches both sites without drift.
fn partition_ready(rows: &[KustomizationRow]) -> (usize, Vec<String>) {
    let mut ready = 0usize;
    let mut failures = Vec::new();
    for row in rows {
        if row.is_ready() {
            ready += 1;
        } else {
            failures.push(row.render_failure_line());
        }
    }
    (ready, failures)
}

/// Check Flux health status without failing immediately
///
/// Returns Ok((ready_count, total_count)) if all healthy,
/// Err((ready_count, total_count, failures)) if any unhealthy
async fn check_health_status() -> Result<(usize, usize), (usize, usize, Vec<String>)> {
    // Route through the canonical `flux_get::list_kustomizations_all_namespaces`
    // primitive so this site honors `FLUX_BIN` (via `get_tool_path("flux")`)
    // and — on failure — collapses the typed `(exit_code, stderr)` record
    // into the pre-lift `(0, 0, vec![message])` tuple by rendering the
    // typed error via `Display`. That preserves the pre-lift caller
    // contract bit-for-bit while gaining the operator-visible exit code
    // and stderr in the collapsed failure line: pre-lift both spawn-
    // failure and op-failure surfaced as bare "Failed to run flux command"
    // / "Failed to get FluxCD status" strings that dropped the stderr and
    // the exit code.
    let rows = list_kustomizations_all_namespaces()
        .await
        .map_err(|e: FluxGetKustomizationsError| (0usize, 0usize, vec![e.to_string()]))?;

    let (ready, failures) = partition_ready(&rows);
    let total = rows.len();

    if failures.is_empty() {
        Ok((ready, total))
    } else {
        Err((ready, total, failures))
    }
}

/// Force Flux to reconcile the git source, root kustomization, and product chain
///
/// CRITICAL: We must reconcile the git source BEFORE the kustomization.
/// Without this, the kustomization applies from a stale git revision,
/// meaning the deployment never gets the new image tag.
///
/// After reconciling the root kustomization, we cascade through the product
/// kustomization chain (init → secrets → databases → bootstrap → governance →
/// migrations → app) to avoid waiting for the default reconcile interval.
///
/// Flow: reconcile_source() → reconcile_kustomization() → reconcile_product_chain()
pub async fn reconcile(namespace: String) -> Result<()> {
    println!("🔄 {}", "Forcing Flux reconcile...".bold());

    // Step 1: Reconcile the git source so Flux fetches the latest commit
    reconcile_source().await?;

    // Step 2: Reconcile the root kustomization which cascades to all children
    reconcile_kustomization().await?;

    // Step 3: Cascade through the product kustomization chain
    // Without this, each step waits for its default reconcile interval (up to 10min)
    reconcile_product_chain(&namespace).await?;

    println!(
        "✅ {}",
        "Flux reconcile triggered - GitOps will handle deployment".green()
    );
    Ok(())
}

/// Reconcile the FluxCD git source to fetch the latest commit
///
/// Without this step, `flux reconcile kustomization` applies from
/// whatever git revision is already cached, which may be stale.
async fn reconcile_source() -> Result<()> {
    println!("   🔄 Reconciling git source...");

    // Route through the canonical `flux_reconcile::reconcile_source_git`
    // primitive so this site honors `FLUX_BIN` (via
    // `get_tool_path("flux")`) and — on failure — surfaces the typed
    // `(source_name, namespace, exit_code, stderr)` record. Pre-lift
    // `run_inherited_status` streamed flux's live progress to the
    // operator; post-lift the primitive captures stderr and embeds it
    // in the failure message, which is what the outer anyhow context
    // ultimately needs.
    crate::flux_reconcile::reconcile_source_git("flux-system", "flux-system")
        .await
        .context("Failed to reconcile FluxCD git source")?;

    println!("   ✅ Git source reconciled");
    Ok(())
}

/// Reconcile the product kustomization dependency chain
///
/// Products use a multi-phase deployment chain:
///   init → secrets → databases → bootstrap → governance → migrations → app
///
/// Each phase is a separate FluxCD Kustomization with dependsOn pointing to the
/// previous phase. Without explicit reconciliation, each waits for its default
/// interval (5-10 min), causing the full chain to take 30-60 minutes.
///
/// This function reconciles each phase in order, skipping phases that don't exist.
async fn reconcile_product_chain(namespace: &str) -> Result<()> {
    // The phases in dependency order. The final phase uses the bare namespace name.
    let phases = [
        "init",
        "secrets",
        "databases",
        "bootstrap",
        "governance",
        "migrations",
        "", // final phase = bare kustomization name (e.g., "{product}-{environment}")
    ];

    println!(
        "   🔄 Reconciling product chain for {}...",
        namespace.cyan()
    );

    for phase in &phases {
        let ks_name = if phase.is_empty() {
            namespace.to_string()
        } else {
            format!("{}-{}", namespace, phase)
        };

        // Route through the canonical `flux_get::get_kustomization_scoped`
        // primitive so this site honors `FLUX_BIN` (via
        // `get_tool_path("flux")`), reads the ready-boundary through
        // `KustomizationRow::is_ready` (one-oracle for the `== "True"`
        // comparison this site pre-lift duplicated against the
        // `--all-namespaces` sibling), and carries the typed
        // `FluxGetKustomizationError` at the API boundary. Pre-lift the
        // site fused spawn-failure and non-zero-exit into a single
        // `_ => continue` arm; the primitive splits them structurally
        // — `Ok(None)` for "kustomization doesn't exist" (silently
        // skip, matching pre-lift), `Err(_)` for spawn-failure — and
        // we preserve the pre-lift silent-skip on both by collapsing
        // them at the `let-else` here so this commit's blast radius
        // stays a pure refactor.
        let Ok(Some(row)) = get_kustomization_scoped(&ks_name, "flux-system").await else {
            continue;
        };

        if row.is_ready() {
            let phase_label = if phase.is_empty() { "app" } else { phase };
            println!("      ✓ {} (already ready)", phase_label.dimmed());
            continue;
        }

        let phase_label = if phase.is_empty() { "app" } else { phase };
        println!("      ⏳ Reconciling {}...", phase_label);

        // Route through the canonical `flux_reconcile` primitive so this
        // site honors `FLUX_BIN` (via `get_tool_path("flux")`) and yields
        // the typed `(kustomization, namespace, with_source, exit_code,
        // stderr)` failure record on non-zero exit — best-effort warn
        // preserved by matching on the typed variant.
        match crate::flux_reconcile::reconcile_kustomization(&ks_name, "flux-system", false).await {
            Ok(()) => println!("      ✓ {}", phase_label.green()),
            Err(e @ crate::flux_reconcile::FluxReconcileError::SpawnFailed { .. }) => {
                return Err(anyhow::Error::new(e)
                    .context(format!("Failed to reconcile kustomization {}", ks_name)));
            }
            Err(crate::flux_reconcile::FluxReconcileError::Failed {
                exit_code, stderr, ..
            }) => {
                // Non-fatal: the kustomization might have a dependency not yet
                // ready. The verify_deployment_image step will catch this
                // downstream. Surface exit code + trimmed stderr so the operator
                // has a real hint instead of a bare "returned non-zero".
                println!(
                    "      ⚠ {} (reconcile returned non-zero, may need dependency; \
                     exit={:?}): {}",
                    phase_label.yellow(),
                    exit_code,
                    stderr.trim()
                );
            }
        }
    }

    println!("   ✅ Product chain reconciled");
    Ok(())
}

/// Reconcile the root kustomization (cascades to all children)
async fn reconcile_kustomization() -> Result<()> {
    println!("   🔄 Reconciling kustomization...");

    // Route through the canonical `flux_reconcile` primitive so this site honors
    // `FLUX_BIN` (via `get_tool_path("flux")`) and — on failure — surfaces the
    // typed `(kustomization, namespace, with_source, exit_code, stderr)` record.
    // Pre-lift `run_inherited_status` streamed flux's live progress to the
    // operator; post-lift the primitive captures stderr and embeds it in the
    // failure message, which is what the outer anyhow context ultimately needs.
    crate::flux_reconcile::reconcile_kustomization("flux-system", "flux-system", false)
        .await
        .context("Failed to reconcile root FluxCD kustomization")?;

    println!("   ✅ Kustomization reconciled");
    Ok(())
}

/// Verify that a deployment has the expected image tag
///
/// After flux reconcile, polls the deployment to confirm the new image tag
/// has been applied. This catches edge cases where the git source reconciled
/// but the kustomization hasn't cascaded yet.
///
/// # Arguments
/// * `namespace` - Kubernetes namespace
/// * `deployment_name` - Name of the deployment
/// * `expected_tag_suffix` - The git SHA suffix expected in the image tag
/// * `timeout_secs` - Maximum time to wait (default: 60s)
pub async fn verify_deployment_image(
    namespace: &str,
    deployment_name: &str,
    expected_tag_suffix: &str,
    _timeout_secs: u64, // kept for API compat, not used as hard timeout
) -> Result<()> {
    println!(
        "🔍 {}",
        format!(
            "Verifying deployment {} has image with SHA {}...",
            deployment_name, expected_tag_suffix
        )
        .bold()
    );

    let start = std::time::Instant::now();
    let mut backoff = Backoff::new();
    let mut last_diag_at = 0u64;

    loop {
        let elapsed = start.elapsed().as_secs();

        match get_pod_status_full(namespace, deployment_name).await {
            Ok(pod) => {
                if pod.image.contains(expected_tag_suffix) {
                    let tag = crate::oci_manifest::image_tag_display(&pod.image);
                    println!("   ✅ Deployment has correct image tag: {}", tag);
                    return Ok(());
                }

                // Check for terminal failures on the NEW pod
                if let Some(ref reason) = pod.waiting_reason {
                    if is_terminal_failure(reason) {
                        let diagnostics =
                            gather_deployment_diagnostics(namespace, deployment_name).await;
                        bail!(
                            "Deployment {} failed: {} ({})\n{}",
                            deployment_name,
                            reason,
                            pod.waiting_message.as_deref().unwrap_or(""),
                            diagnostics,
                        );
                    }
                }

                let tag = crate::oci_manifest::image_tag_display(&pod.image);
                println!(
                    "   ⏳ Current tag: {}, waiting for SHA {} ({}s elapsed)",
                    tag, expected_tag_suffix, elapsed
                );
            }
            Err(e) => {
                println!("   ⏳ Waiting for deployment ({}, {}s elapsed)", e, elapsed);
            }
        }

        // Print diagnostics every 120s for visibility
        if elapsed - last_diag_at >= 120 && elapsed > 0 {
            last_diag_at = elapsed;
            let diag = gather_deployment_diagnostics(namespace, deployment_name).await;
            println!("{}", diag);
        }

        backoff.wait().await;
    }
}

/// Wait for deployment rollout to complete with the NEW image tag.
///
/// Polls with exponential backoff until the pod has the expected image and is ready.
/// Detects terminal failures (ImagePullBackOff, CrashLoopBackOff, etc.) and bails immediately.
/// Never times out — the process either succeeds or fails definitively.
pub async fn wait_for_deployment(
    service: String,
    namespace: String,
    _timeout_secs: u64, // kept for API compat, not used as hard timeout
    expected_tag_suffix: String,
    deploy_config: &DeployConfig,
) -> Result<()> {
    let deployment_name = deploy_config
        .service
        .kubernetes
        .as_ref()
        .and_then(|k| k.deployment_name.clone())
        .unwrap_or_else(|| service.clone());

    println!(
        "⏳ {}",
        format!(
            "Waiting for {} deployment with correct image tag...",
            deployment_name
        )
        .bold()
    );

    let expected_sha = expected_tag_suffix;
    println!("   Expected git SHA in image tag: {}", expected_sha);

    let start = std::time::Instant::now();
    let mut backoff = Backoff::new();
    let mut last_diag_at = 0u64;

    loop {
        let elapsed = start.elapsed().as_secs();

        match get_pod_status_full(&namespace, &deployment_name).await {
            Ok(pod) => {
                let has_correct_image = pod.image.contains(&expected_sha);

                if has_correct_image && pod.ready {
                    let current_tag = crate::oci_manifest::image_tag_display(&pod.image);
                    println!("   ✅ Pod has correct image ({}) and is ready", current_tag);
                    println!(
                        "✅ {}",
                        format!("{} deployment is ready with new image", deployment_name).green()
                    );
                    return Ok(());
                }

                // Check for terminal failures
                if let Some(ref reason) = pod.waiting_reason {
                    if is_terminal_failure(reason) {
                        let diagnostics =
                            gather_deployment_diagnostics(&namespace, &deployment_name).await;
                        bail!(
                            "Deployment {} failed: {} ({})\n{}",
                            deployment_name,
                            reason,
                            pod.waiting_message.as_deref().unwrap_or(""),
                            diagnostics,
                        );
                    }
                }

                let current_tag = crate::oci_manifest::image_tag_display(&pod.image);
                if has_correct_image {
                    println!(
                        "   ⏳ Pod has correct image but not ready yet (status: {}, {}s elapsed)",
                        pod.phase, elapsed
                    );
                } else {
                    println!(
                        "   ⏳ Waiting for new image (current: {}, expected SHA: {}, {}s elapsed)",
                        current_tag, expected_sha, elapsed
                    );
                }
            }
            Err(e) => {
                println!("   ⏳ Waiting for pod ({}, {}s elapsed)", e, elapsed);
            }
        }

        // Print diagnostics every 120s for visibility
        if elapsed - last_diag_at >= 120 && elapsed > 0 {
            last_diag_at = elapsed;
            let diag = gather_deployment_diagnostics(&namespace, &deployment_name).await;
            println!("{}", diag);
        }

        backoff.wait().await;
    }
}

/// Exponential backoff for polling loops.
/// Starts at 2s, doubles each iteration, caps at 30s.
struct Backoff {
    current: u64,
}

impl Backoff {
    fn new() -> Self {
        Self { current: 2 }
    }

    async fn wait(&mut self) {
        sleep(Duration::from_secs(self.current)).await;
        self.current = (self.current * 2).min(30);
    }
}

/// Terminal container failure reasons that won't resolve on their own.
fn is_terminal_failure(waiting_reason: &str) -> bool {
    matches!(
        waiting_reason,
        "ImagePullBackOff"
            | "ErrImagePull"
            | "InvalidImageName"
            | "ErrImageNeverPull"
            | "CreateContainerConfigError"
            | "CrashLoopBackOff"
    )
}

/// Full pod status including container waiting reasons for failure detection.
struct PodStatus {
    image: String,
    phase: String,
    ready: bool,
    waiting_reason: Option<String>,
    waiting_message: Option<String>,
}

/// Get comprehensive pod status for a deployment (image, phase, readiness, waiting reasons).
async fn get_pod_status_full(namespace: &str, deployment_name: &str) -> Result<PodStatus> {
    // Single kubectl call using JSON for all fields
    let output = Command::new("kubectl")
        .args([
            "get",
            "pods",
            "-n",
            namespace,
            "-l",
            &format!("app={}", deployment_name),
            "-o",
            "json",
        ])
        .output()
        .await
        .context("Failed to get pods")?;

    if !output.status.success() {
        bail!("kubectl get pods failed");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).context("Failed to parse pod JSON")?;

    let items = json["items"].as_array().context("No items in pod list")?;

    if items.is_empty() {
        bail!("No pods found");
    }

    // Use the first pod (newest during rollout will be checked by image)
    let pod = &items[0];

    let image = pod["spec"]["containers"][0]["image"]
        .as_str()
        .unwrap_or("")
        .to_string();
    if image.is_empty() {
        bail!("No image found on pod");
    }

    let phase = pod["status"]["phase"]
        .as_str()
        .unwrap_or("Unknown")
        .to_string();

    let ready = pod["status"]["conditions"]
        .as_array()
        .and_then(|conditions| conditions.iter().find(|c| c["type"] == "Ready"))
        .and_then(|c| c["status"].as_str())
        .unwrap_or("False")
        == "True";

    // Extract waiting reason from container statuses
    let container_statuses = pod["status"]["containerStatuses"].as_array();

    let (waiting_reason, waiting_message) = container_statuses
        .and_then(|statuses| {
            statuses.iter().find_map(|cs| {
                let waiting = &cs["state"]["waiting"];
                if waiting.is_object() {
                    Some((
                        waiting["reason"].as_str().map(|s| s.to_string()),
                        waiting["message"].as_str().map(|s| s.to_string()),
                    ))
                } else {
                    None
                }
            })
        })
        .unwrap_or((None, None));

    Ok(PodStatus {
        image,
        phase,
        ready,
        waiting_reason,
        waiting_message,
    })
}

/// Gather comprehensive deployment diagnostics for debugging failures.
///
/// Collects pod statuses, container states, events, deployment conditions,
/// and flux kustomization status. Returns a formatted diagnostic string.
pub async fn gather_deployment_diagnostics(namespace: &str, deployment_name: &str) -> String {
    let mut diag = String::new();
    diag.push_str(&format!("\n{}\n", "━".repeat(72)));
    diag.push_str(&format!(
        "  DEPLOYMENT DIAGNOSTICS: {} in {}\n",
        deployment_name, namespace
    ));
    diag.push_str(&format!("{}\n", "━".repeat(72)));

    // 1. Deployment status (replicas, conditions)
    if let Ok(output) = Command::new("kubectl")
        .args([
            "get",
            "deployment",
            deployment_name,
            "-n",
            namespace,
            "-o",
            "jsonpath={.status.replicas}/{.status.updatedReplicas}/{.status.readyReplicas}/{.status.availableReplicas}/{.status.unavailableReplicas}",
        ])
        .output()
        .await
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let parts: Vec<&str> = stdout.trim().split('/').collect();
        diag.push_str("\n  Deployment Replicas:\n");
        diag.push_str(&format!(
            "    total={} updated={} ready={} available={} unavailable={}\n",
            parts.first().unwrap_or(&"?"),
            parts.get(1).unwrap_or(&"?"),
            parts.get(2).unwrap_or(&"?"),
            parts.get(3).unwrap_or(&"?"),
            parts.get(4).unwrap_or(&"?"),
        ));
    }

    // 2. Deployment conditions
    if let Ok(output) = Command::new("kubectl")
        .args([
            "get",
            "deployment",
            deployment_name,
            "-n",
            namespace,
            "-o",
            "jsonpath={range .status.conditions[*]}{.type}={.status} ({.reason}: {.message}){\"\\n\"}{end}",
        ])
        .output()
        .await
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.trim().is_empty() {
            diag.push_str("\n  Deployment Conditions:\n");
            for line in stdout.trim().lines() {
                diag.push_str(&format!("    {}\n", line));
            }
        }
    }

    // 3. All pods for this deployment (not just first)
    if let Ok(output) = Command::new("kubectl")
        .args([
            "get",
            "pods",
            "-n",
            namespace,
            "-l",
            &format!("app={}", deployment_name),
            "-o",
            "wide",
        ])
        .output()
        .await
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.trim().is_empty() {
            diag.push_str("\n  All Pods:\n");
            for line in stdout.trim().lines() {
                diag.push_str(&format!("    {}\n", line));
            }
        }
    }

    // 4. Container status details (waiting reasons like ImagePullBackOff, CrashLoopBackOff)
    if let Ok(output) = Command::new("kubectl")
        .args([
            "get",
            "pods",
            "-n",
            namespace,
            "-l",
            &format!("app={}", deployment_name),
            "-o",
            "jsonpath={range .items[*]}{.metadata.name}: {range .status.containerStatuses[*]}[{.name} state={.state} ready={.ready} restarts={.restartCount}] {end}{\"\\n\"}{end}",
        ])
        .output()
        .await
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.trim().is_empty() {
            diag.push_str("\n  Container States:\n");
            for line in stdout.trim().lines() {
                diag.push_str(&format!("    {}\n", line));
            }
        }
    }

    // 5. Waiting/terminated reasons (the most useful for debugging)
    if let Ok(output) = Command::new("kubectl")
        .args([
            "get",
            "pods",
            "-n",
            namespace,
            "-l",
            &format!("app={}", deployment_name),
            "-o",
            "jsonpath={range .items[*]}{.metadata.name}: {range .status.containerStatuses[*]}waiting={.state.waiting.reason}:{.state.waiting.message} terminated={.state.terminated.reason}:{.state.terminated.exitCode} {end}{\"\\n\"}{end}",
        ])
        .output()
        .await
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let has_reasons = stdout.lines().any(|l| {
            l.contains("waiting=") && !l.contains("waiting=:")
                || l.contains("terminated=") && !l.contains("terminated=:")
        });
        if has_reasons {
            diag.push_str("\n  Container Wait/Termination Reasons:\n");
            for line in stdout.trim().lines() {
                diag.push_str(&format!("    {}\n", line));
            }
        }
    }

    // 6. Recent events for this namespace (last 20, sorted by time)
    if let Ok(output) = Command::new("kubectl")
        .args([
            "get",
            "events",
            "-n",
            namespace,
            "--sort-by=.lastTimestamp",
            "--field-selector",
            &format!("involvedObject.name={}", deployment_name),
            "-o",
            "custom-columns=TIME:.lastTimestamp,TYPE:.type,REASON:.reason,MESSAGE:.message",
            "--no-headers",
        ])
        .output()
        .await
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.trim().is_empty() {
            diag.push_str("\n  Deployment Events:\n");
            for line in stdout.trim().lines().rev().take(10) {
                diag.push_str(&format!("    {}\n", line));
            }
        }
    }

    // 7. Pod events (scheduling, image pull, etc.)
    if let Ok(output) = Command::new("kubectl")
        .args([
            "get",
            "events",
            "-n",
            namespace,
            "--sort-by=.lastTimestamp",
            "-o",
            "custom-columns=TIME:.lastTimestamp,TYPE:.type,REASON:.reason,OBJECT:.involvedObject.name,MESSAGE:.message",
            "--no-headers",
        ])
        .output()
        .await
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Filter to pod events matching our deployment
        let pod_events: Vec<&str> = stdout
            .trim()
            .lines()
            .filter(|l| l.contains(deployment_name))
            .collect();
        if !pod_events.is_empty() {
            diag.push_str("\n  Related Pod Events (last 15):\n");
            for line in pod_events.iter().rev().take(15) {
                diag.push_str(&format!("    {}\n", line));
            }
        }
    }

    // 8. Flux kustomization status for namespace — route through the
    //    canonical `flux_get::list_kustomizations_in_namespace` primitive
    //    (the last raw `Command::new("flux")` stanza in forge, redeemed
    //    here) so this site honors `FLUX_BIN` (via `get_tool_path("flux")`),
    //    reads `is_ready` through the one-oracle boundary
    //    `KustomizationRow` owns, and yields typed
    //    `FluxGetKustomizationsError` on failure. Best-effort diagnostic:
    //    if the primitive errors, we silently omit this subsection —
    //    matching the pre-lift `if let Ok(output) = ...` arm.
    if let Ok(rows) = list_kustomizations_in_namespace("flux-system").await {
        // Preserve the pre-lift substring semantic: the raw filter was
        // `l.contains(namespace)` on the whole tabular line, which matched
        // rows whose NAME encoded the namespace by convention (e.g.
        // `alpha-init`, `alpha-app`) AND rows whose MESSAGE mentioned the
        // namespace (e.g. `dependency 'flux-system/alpha' is not ready`).
        // Post-lift, we filter typed rows by the same two fields to keep
        // the operator-visible diagnostic scope unchanged.
        let relevant: Vec<&KustomizationRow> = rows
            .iter()
            .filter(|r| r.name.contains(namespace) || r.message.contains(namespace))
            .collect();
        if !relevant.is_empty() {
            diag.push_str("\n  Flux Kustomizations:\n");
            diag.push_str("    NAME  REVISION  SUSPENDED  READY  MESSAGE\n");
            for row in &relevant {
                diag.push_str(&format!(
                    "    {}  {}  {}  {}  {}\n",
                    row.name, row.revision, row.suspended, row.ready, row.message
                ));
            }
        }
    }

    diag.push_str(&format!("\n  Debug commands:\n"));
    diag.push_str(&format!(
        "    kubectl describe deployment {} -n {}\n",
        deployment_name, namespace
    ));
    diag.push_str(&format!(
        "    kubectl describe pods -n {} -l app={}\n",
        namespace, deployment_name
    ));
    diag.push_str(&format!(
        "    kubectl logs -n {} -l app={} --tail=50\n",
        namespace, deployment_name
    ));
    diag.push_str(&format!("{}\n", "━".repeat(72)));

    diag
}
