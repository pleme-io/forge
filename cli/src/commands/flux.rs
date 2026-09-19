//! FluxCD operations for GitOps deployments.

use anyhow::{bail, Context, Result};
use colored::Colorize;
use std::io;
use std::time::Duration;
use tokio::time::sleep;

use crate::config::DeployConfig;
use crate::flux_get::{
    get_kustomization_scoped, list_kustomizations_all_namespaces, list_kustomizations_in_namespace,
    FluxGetKustomizationsError, KustomizationRow,
};
use crate::infrastructure::kubectl::{
    kubectl_capture_anyhow, kubectl_probe_push_nonempty_section_4sp, kubectl_probe_stdout_capture,
};
use crate::retry::RetryPolicy;

/// The typed exponential-backoff policy for the two deployment-pod-
/// polling loops in this module ([`verify_deployment_image`] and
/// [`wait_for_deployment`]) — `initial_backoff` 2s × `factor` 2 capped at
/// `max_backoff` 30s. Consumes the pre-existing typed primitive at
/// [`crate::retry::RetryPolicy`] so the per-attempt delay lands at
/// [`RetryPolicy::compute_delay`], the same shared body the sibling
/// reconcile-poll surface `commands/migrations.rs::
/// SHINKA_MIGRATION_POLL_BACKOFF` (commit b962db5) and the health-endpoint
/// retry surface `commands/post_deploy_verification.rs::
/// HEALTH_ENDPOINT_BACKOFF` (commit b5db3b6) read through.
///
/// Pre-lift the hand-rolled schedule was spelled inline as the two-field
/// struct `struct Backoff { current: u64 }` seeded via
/// `Self { current: 2 }` and driven by `sleep(Duration::from_secs(
/// self.current)).await; self.current = (self.current * 2).min(30);`.
/// That shape carried three structural defects the typed-primitive body
/// forecloses:
/// 1. **Instance-state escape.** The `Backoff` struct owned its state in
///    a `current: u64` field held by an instance passed to a helper
///    method — the state lived outside the loop body and outside the
///    caller's local scope. A future refactor that hoisted a single
///    `Backoff` instance across two polling loops (e.g., an outer retry
///    wrapping an inner poll) silently continued from the prior loop's
///    cap (30s) instead of resetting to the 2s seed, converting a fresh
///    2s first sleep into a 30s wait with no visible source-level
///    change. This is a strictly worse variant of the same
///    `mut backoff_secs` local-state escape that
///    `SHINKA_MIGRATION_POLL_BACKOFF`'s docstring cites at
///    `commands/migrations.rs`, because instance state survives loop
///    exit whereas a local dies at the enclosing block. Lifting to
///    `compute_delay(attempt)` names the schedule as a pure function of
///    a monotonic counter that is re-seeded to `0` at every consumer's
///    loop entry, so no code path can silently desync the delay from
///    the iteration index across loop boundaries.
/// 2. **`u64 * 2` unbounded until the cap.** The multiply was unbounded
///    until the `.min(30)` clamp — safe in practice because the cap
///    fired at iteration 4 (16 → 32.min(30) = 30), but the shape did
///    not compose with a future refactor that lifted the cap or the
///    factor. [`RetryPolicy::compute_delay`]'s `checked_pow` saturating
///    body is safe by construction under arbitrarily-large `factor` and
///    `attempt`.
/// 3. **No caller-visible schedule invariant.** The `Backoff` struct
///    was a bespoke private newtype whose `(seed=2, factor=2, cap=30)`
///    schedule was three magic numbers spread across `Self { current: 2
///    }` and `(self.current * 2).min(30)`. A future edit that bumped
///    the cap to 60 or the seed to 5 landed silently at the struct's
///    private state without a named-primitive audit surface. The lifted
///    const `FLUX_POLL_BACKOFF` is a single load-bearing structural
///    surface that a caller can point at, cite, and test-shield in one
///    place.
///
/// `max_attempts: u32::MAX` is a placeholder — both polling loops are
/// unbounded by design (`wait_for_deployment`'s `_timeout_secs`
/// parameter carries a `kept for API compat, not used as hard timeout`
/// comment; `verify_deployment_image` mirrors the same shape) and
/// consume only [`RetryPolicy::compute_delay`] from this policy, not
/// [`RetryPolicy::max_attempts`]. The `max_attempts` field is
/// unconsulted at these consumption sites.
const FLUX_POLL_BACKOFF: RetryPolicy = RetryPolicy::wall_clock_poll(Duration::from_secs(2));

/// Backoff between deployment-pod-polling iterations, given a 0-indexed
/// local `attempt` counter (the `loop { ... }` shape both
/// [`verify_deployment_image`] and [`wait_for_deployment`] drive
/// increments once per non-terminal iteration).
///
/// Maps the local 0-indexed counter to the 1-indexed
/// [`RetryPolicy::compute_delay`] attempt axis via `saturating_add(2)`:
/// local `attempt == 0` (the sleep after the first non-terminal poll)
/// reads as `compute_delay(2) = initial_backoff * factor^0 =
/// initial_backoff = 2s`; local `attempt == 1` reads as `compute_delay(3)
/// = 4s`; local `attempt == 2` reads as `compute_delay(4) = 8s`; local
/// `attempt == 3` reads as `compute_delay(5) = 16s`; local `attempt >= 4`
/// reads as `compute_delay(>=6) = 30s` (cap) — matching the pre-lift
/// `Backoff` struct's `2 → 4 → 8 → 16 → 30 → 30 → …` schedule verbatim.
///
/// The `saturating_add` clamp forecloses the `u32` overflow class at
/// the bridge — an unbounded polling loop that reaches
/// `attempt == u32::MAX` reads as `compute_delay(u32::MAX)`, which
/// itself saturates to [`FLUX_POLL_BACKOFF::max_backoff`] via the
/// `checked_pow`-then-cap body inside [`RetryPolicy::compute_delay`]
/// without panic.
fn flux_poll_delay(attempt: u32) -> Duration {
    FLUX_POLL_BACKOFF.poll_iteration_delay(attempt)
}

/// The invariant `🩺` glyph both [`health_check`] and
/// [`health_check_with_retry`] spelled as the leading emoji of their
/// running-branch announce line. Named as a `const` so a future
/// re-branding (a swap for `⚕️`, a promotion to a themed glyph via
/// [`crate::ui`], or a drop of the glyph entirely) reaches ONE site
/// rather than two lockstep string literals.
const FLUX_HEALTH_CHECK_RUNNING_ANNOUNCE_GLYPH: &str = "🩺";

/// Emit the canonical `🩺 FluxCD health check (<context>)....bold()\n`
/// running-branch announce line to stdout. Called from
/// [`health_check`] and [`health_check_with_retry`] as their opening
/// line.
///
/// Delegates to [`write_flux_health_check_running_announce_line`]
/// against [`std::io::stdout`]; the writer split exists so the
/// fail-before-pass byte-oracle tests pin the exact rendered bytes
/// without capturing stdout.
fn print_flux_health_check_running_announce_line(context: &str) {
    let _ = write_flux_health_check_running_announce_line(&mut io::stdout().lock(), context);
}

/// Writer-taking sibling to
/// [`print_flux_health_check_running_announce_line`]. Emits the single
/// `🩺 FluxCD health check (<context>)....bold()\n` line via
/// [`writeln!`] against the supplied writer.
///
/// Tests can pin the exact byte shape — the
/// [`FLUX_HEALTH_CHECK_RUNNING_ANNOUNCE_GLYPH`] prefix, the single
/// space after it, the plain ASCII `FluxCD health check (` prefix, the
/// caller's `<context>` verbatim, the trailing `)...`, and the
/// `.bold()` ANSI envelope — without capturing stdout.
fn write_flux_health_check_running_announce_line<W: io::Write>(
    w: &mut W,
    context: &str,
) -> io::Result<()> {
    writeln!(
        w,
        "{} {}",
        FLUX_HEALTH_CHECK_RUNNING_ANNOUNCE_GLYPH,
        format!("FluxCD health check ({})...", context).bold()
    )
}

/// FluxCD health check before and after deployments.
///
/// This verifies the GitOps system is healthy before and after deployments.
/// Returns an error if any kustomization is not Ready.
pub async fn health_check(context: &str) -> Result<()> {
    print_flux_health_check_running_announce_line(context);

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
        crate::commands::flux_debug_commands_hint::print_flux_debug_commands_hint();

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
    print_flux_health_check_running_announce_line(context);
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
                crate::ui::print_step_pass(&format!(
                    "All kustomizations healthy ({}/{} ready)",
                    ready, total
                ));
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
                    crate::commands::flux_debug_commands_hint::print_flux_debug_commands_hint();

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
    crate::ui::print_bold_titled_phase_open("🔄", "Forcing Flux reconcile...");

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

    crate::ui::print_step_pass("Git source reconciled");
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
    // The 7-phase dependency-order chain
    // (`init → secrets → databases → bootstrap → governance →
    // migrations → app`) lives in
    // `commands/flux_product_chain_phase::FluxProductChainPhase::ORDER`
    // as a `[Self; 7]` slice. Pre-lift this site seeded the phases as
    // a `[&'static str; 7]` inline literal whose final element was the
    // empty string `""` sentinel, and the loop body then carried three
    // sibling `if phase.is_empty() { <app arm> } else { <named arm> }`
    // decisions (kustomization-name resolution, ready-branch label,
    // reconcile-branch label). Post-lift the closed enum owns all
    // three projections; adding a new phase means adding a variant +
    // an `ORDER` entry + a match arm, and the exhaustiveness check
    // forecloses the pre-lift "slice extended without updating the
    // sibling label projection" drift.
    use crate::commands::flux_product_chain_phase::{
        print_phase_already_ready_ack, print_phase_reconcile_nonzero_warn,
        print_phase_reconciled_ack, print_reconciling_phase_announce, FluxProductChainPhase,
    };

    println!(
        "   🔄 Reconciling product chain for {}...",
        namespace.cyan()
    );

    for phase in FluxProductChainPhase::ORDER {
        let ks_name = phase.kustomization_name(namespace);

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
            print_phase_already_ready_ack(phase);
            continue;
        }

        print_reconciling_phase_announce(phase);

        // Route through the canonical `flux_reconcile` primitive so this
        // site honors `FLUX_BIN` (via `get_tool_path("flux")`) and yields
        // the typed `(kustomization, namespace, with_source, exit_code,
        // stderr)` failure record on non-zero exit — best-effort warn
        // preserved by matching on the typed variant.
        match crate::flux_reconcile::reconcile_kustomization(&ks_name, "flux-system", false).await {
            Ok(()) => print_phase_reconciled_ack(phase),
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
                print_phase_reconcile_nonzero_warn(phase, exit_code, &stderr);
            }
        }
    }

    crate::ui::print_step_pass("Product chain reconciled");
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

    crate::ui::print_step_pass("Kustomization reconciled");
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

    let mut poll_clock = crate::deployment_poll_clock::DeploymentPollClock::new();

    loop {
        let elapsed = poll_clock.elapsed_secs();

        match get_pod_status_full(namespace, deployment_name).await {
            Ok(pod) => {
                if pod.image.contains(expected_tag_suffix) {
                    let tag = crate::oci_manifest::image_tag_display(&pod.image);
                    crate::ui::print_step_pass(&format!(
                        "Deployment has correct image tag: {}",
                        tag
                    ));
                    return Ok(());
                }

                // Check for terminal failures on the NEW pod
                bail_on_terminal_pod_failure(&pod, namespace, deployment_name).await?;

                let tag = crate::oci_manifest::image_tag_display(&pod.image);
                println!(
                    "   ⏳ Current tag: {}, waiting for SHA {} ({}s elapsed)",
                    tag, expected_tag_suffix, elapsed
                );
            }
            Err(e) => {
                crate::pod_probe_pending_wait_line::print_pod_probe_pending_wait_line(
                    crate::pod_probe_pending_wait_line::PodPollTargetLabel::Deployment,
                    &e,
                    elapsed,
                );
            }
        }

        emit_periodic_deployment_diagnostics_burst(
            namespace,
            deployment_name,
            elapsed,
            &mut poll_clock.last_diag_at,
        )
        .await;

        crate::poll_backoff_advance::advance_poll_backoff_tokio(
            &mut poll_clock.backoff_attempt,
            flux_poll_delay,
        )
        .await;
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
    crate::ui::print_field("Expected git SHA in image tag", &expected_sha);

    let mut poll_clock = crate::deployment_poll_clock::DeploymentPollClock::new();

    loop {
        let elapsed = poll_clock.elapsed_secs();

        match get_pod_status_full(&namespace, &deployment_name).await {
            Ok(pod) => {
                let has_correct_image = pod.image.contains(&expected_sha);

                if has_correct_image && pod.ready {
                    let current_tag = crate::oci_manifest::image_tag_display(&pod.image);
                    crate::ui::print_step_pass(&format!(
                        "Pod has correct image ({}) and is ready",
                        current_tag
                    ));
                    println!(
                        "✅ {}",
                        format!("{} deployment is ready with new image", deployment_name).green()
                    );
                    return Ok(());
                }

                // Check for terminal failures
                bail_on_terminal_pod_failure(&pod, &namespace, &deployment_name).await?;

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
                crate::pod_probe_pending_wait_line::print_pod_probe_pending_wait_line(
                    crate::pod_probe_pending_wait_line::PodPollTargetLabel::Pod,
                    &e,
                    elapsed,
                );
            }
        }

        emit_periodic_deployment_diagnostics_burst(
            &namespace,
            &deployment_name,
            elapsed,
            &mut poll_clock.last_diag_at,
        )
        .await;

        crate::poll_backoff_advance::advance_poll_backoff_tokio(
            &mut poll_clock.backoff_attempt,
            flux_poll_delay,
        )
        .await;
    }
}

/// Load-bearing 120-second cadence for the periodic diagnostic burst
/// emitted from the two deployment-poll loops
/// ([`verify_deployment_image`] and [`wait_for_deployment`]).
///
/// Pinned at ONE code point so a future re-tuning of the burst
/// frequency lands at one edit rather than silently drifting across the
/// two callers. Pre-lift both consumer sites spelled `120` inline as a
/// magic literal (`if elapsed - last_diag_at >= 120 && elapsed > 0
/// { … }`) — a bump at one site alone would have silently desynced the
/// two operator-visible diagnostic cadences on the same deployment
/// verification surface.
const DEPLOYMENT_DIAG_BURST_INTERVAL_SECS: u64 = 120;

/// Emit a diagnostic burst to stdout when at least
/// [`DEPLOYMENT_DIAG_BURST_INTERVAL_SECS`] seconds have elapsed since
/// the last burst (`last_diag_at` cursor), gated by `elapsed > 0` so
/// the very first poll iteration (before any wall time has passed)
/// never fires.
///
/// Both consumer sites — [`verify_deployment_image`] and
/// [`wait_for_deployment`] — pre-lift spelled the 4-line stanza
/// (`if elapsed - last_diag_at >= 120 && elapsed > 0 { last_diag_at =
/// elapsed; let diag = gather_deployment_diagnostics(<ns>,
/// <deploy>).await; println!("{}", diag); }`) verbatim, differing only
/// in whether `namespace` / `deployment_name` were already `&str` refs
/// or `String` bindings taken by `&`. Post-lift the burst frequency,
/// the `elapsed > 0` first-tick suppression, the cursor-update ordering
/// (advance BEFORE the diagnostics call so a slow `kubectl` probe
/// cannot silently double-fire the burst on the same interval boundary),
/// and the `println!("{}", diag)` render surface all live at ONE code
/// point.
///
/// # Underflow-safe cursor arithmetic
///
/// `saturating_sub` replaces the pre-lift bare subtraction as a
/// defense in depth. Under the poll-loop invariant `elapsed >=
/// *last_diag_at` (both consumers seed `last_diag_at = 0u64` and only
/// overwrite it with a past `elapsed` value under the guard), the two
/// shapes are bit-identical; but a future edit that re-seeded the
/// cursor with a non-zero placeholder — or a caller that read the
/// elapsed value from a monotonic clock racing against a wall-clock
/// snapshot — cannot silently underflow the `u64` and turn the guard
/// into a "burst every tick" storm.
async fn emit_periodic_deployment_diagnostics_burst(
    namespace: &str,
    deployment_name: &str,
    elapsed: u64,
    last_diag_at: &mut u64,
) {
    if elapsed.saturating_sub(*last_diag_at) >= DEPLOYMENT_DIAG_BURST_INTERVAL_SECS && elapsed > 0 {
        *last_diag_at = elapsed;
        let diag = gather_deployment_diagnostics(namespace, deployment_name).await;
        println!("{}", diag);
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

/// Bail with the canonical `"Deployment {name} failed: {reason}
/// ({message})\n{diagnostics}"` envelope when `pod.waiting_reason`
/// carries a value that [`is_terminal_failure`] classifies as
/// unrecoverable; otherwise return `Ok(())` and let the poll loop keep
/// walking.
///
/// Both deployment-pod-polling loops
/// ([`verify_deployment_image`] and [`wait_for_deployment`]) pre-lift
/// spelled the 10-line stanza
///
/// ```ignore
/// if let Some(ref reason) = pod.waiting_reason {
///     if is_terminal_failure(reason) {
///         let diagnostics =
///             gather_deployment_diagnostics(<ns>, <deploy>).await;
///         bail!(
///             "Deployment {} failed: {} ({})\n{}",
///             deployment_name,
///             reason,
///             pod.waiting_message.as_deref().unwrap_or(""),
///             diagnostics,
///         );
///     }
/// }
/// ```
///
/// verbatim, differing only in whether `namespace` / `deployment_name`
/// were already `&str` refs or `String` bindings taken by `&`. Post-lift
/// the terminal-failure discriminator, the diagnostics-gather
/// call-order (probe first, then bail so the operator log line carries
/// the failing pod's live kubectl state), the `bail!` envelope shape,
/// and the `waiting_message.as_deref().unwrap_or("")` fallback all live
/// at ONE code point. A future re-tuning of the failure envelope —
/// wrapping the diagnostics in a fenced block, promoting `reason` to a
/// typed enum, or carrying the pod name alongside the deployment name —
/// lands at one edit rather than silently drifting across the two
/// callers on the same deployment-verification surface.
async fn bail_on_terminal_pod_failure(
    pod: &PodStatus,
    namespace: &str,
    deployment_name: &str,
) -> Result<()> {
    if let Some(ref reason) = pod.waiting_reason {
        if is_terminal_failure(reason) {
            let diagnostics = gather_deployment_diagnostics(namespace, deployment_name).await;
            bail!(
                "Deployment {} failed: {} ({})\n{}",
                deployment_name,
                reason,
                pod.waiting_message.as_deref().unwrap_or(""),
                diagnostics,
            );
        }
    }
    Ok(())
}

/// Get comprehensive pod status for a deployment (image, phase, readiness, waiting reasons).
async fn get_pod_status_full(namespace: &str, deployment_name: &str) -> Result<PodStatus> {
    // Single kubectl call using JSON for all fields.
    // Owns the async captured-output spawn + classify ritual at the
    // canonical `crate::infrastructure::kubectl::kubectl_capture_anyhow`
    // fusion primitive — the same `(op, exit_code, stderr)` envelope
    // `retry::classify_capture_anyhow` produces, now available at the
    // `(args, op)`-front on the `infrastructure::kubectl` surface this
    // module already imports. Pre-lift the three-line `let mut cmd =
    // <constructor>; cmd.args([...]); let output =
    // run_capture_anyhow(cmd, "<op>").await?;` stanza was one of the
    // two occurrences the fusion primitive consolidates (sibling:
    // `crate::commands::integration_tests::fetch_secret`).
    let output = kubectl_capture_anyhow(
        &crate::kubectl_get_pods_by_selector_argv::kubectl_get_pods_by_selector_argv(
            namespace,
            &crate::k8s_label_selector::format_app_label_selector(&deployment_name),
            crate::kubectl_get_pods_by_selector_argv::PodListingOutput::Json,
        ),
        "kubectl get pods",
    )
    .await?;

    let stdout = crate::repo::utf8_lossy_borrow(&output.stdout);
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
    if let Some(stdout) = kubectl_probe_stdout_capture(&[
        "get",
        "deployment",
        deployment_name,
        "-n",
        namespace,
        "-o",
        "jsonpath={.status.replicas}/{.status.updatedReplicas}/{.status.readyReplicas}/{.status.availableReplicas}/{.status.unavailableReplicas}",
    ])
    .await
    {
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
    kubectl_probe_push_nonempty_section_4sp(
        &mut diag,
        "Deployment Conditions",
        &[
            "get",
            "deployment",
            deployment_name,
            "-n",
            namespace,
            "-o",
            "jsonpath={range .status.conditions[*]}{.type}={.status} ({.reason}: {.message}){\"\\n\"}{end}",
        ],
    )
    .await;

    // 3. All pods for this deployment (not just first)
    kubectl_probe_push_nonempty_section_4sp(
        &mut diag,
        "All Pods",
        &crate::kubectl_get_pods_by_selector_argv::kubectl_get_pods_by_selector_argv(
            namespace,
            &crate::k8s_label_selector::format_app_label_selector(&deployment_name),
            crate::kubectl_get_pods_by_selector_argv::PodListingOutput::Wide,
        ),
    )
    .await;

    // 4. Container status details (waiting reasons like ImagePullBackOff, CrashLoopBackOff)
    kubectl_probe_push_nonempty_section_4sp(
        &mut diag,
        "Container States",
        &[
            "get",
            "pods",
            "-n",
            namespace,
            "-l",
            &crate::k8s_label_selector::format_app_label_selector(&deployment_name),
            "-o",
            "jsonpath={range .items[*]}{.metadata.name}: {range .status.containerStatuses[*]}[{.name} state={.state} ready={.ready} restarts={.restartCount}] {end}{\"\\n\"}{end}",
        ],
    )
    .await;

    // 5. Waiting/terminated reasons (the most useful for debugging)
    if let Some(stdout) = kubectl_probe_stdout_capture(&[
        "get",
        "pods",
        "-n",
        namespace,
        "-l",
        &crate::k8s_label_selector::format_app_label_selector(&deployment_name),
        "-o",
        "jsonpath={range .items[*]}{.metadata.name}: {range .status.containerStatuses[*]}waiting={.state.waiting.reason}:{.state.waiting.message} terminated={.state.terminated.reason}:{.state.terminated.exitCode} {end}{\"\\n\"}{end}",
    ])
    .await
    {
        let has_reasons = stdout.lines().any(|l| {
            l.contains("waiting=") && !l.contains("waiting=:")
                || l.contains("terminated=") && !l.contains("terminated=:")
        });
        if has_reasons {
            crate::repo::push_section_indented_lines_4sp(
                &mut diag,
                "Container Wait/Termination Reasons",
                stdout.trim().lines(),
            );
        }
    }

    // 6. Recent events for this namespace (last 20, sorted by time)
    if let Some(stdout) = kubectl_probe_stdout_capture(&[
        "get",
        "events",
        "-n",
        namespace,
        "--sort-by=.lastTimestamp",
        "--field-selector",
        &crate::k8s_field_selector::format_involved_object_name_field_selector(&deployment_name),
        "-o",
        "custom-columns=TIME:.lastTimestamp,TYPE:.type,REASON:.reason,MESSAGE:.message",
        "--no-headers",
    ])
    .await
    {
        if !stdout.trim().is_empty() {
            crate::repo::push_section_indented_lines_4sp(
                &mut diag,
                "Deployment Events",
                stdout.trim().lines().rev().take(10),
            );
        }
    }

    // 7. Pod events (scheduling, image pull, etc.)
    if let Some(stdout) = kubectl_probe_stdout_capture(&[
        "get",
        "events",
        "-n",
        namespace,
        "--sort-by=.lastTimestamp",
        "-o",
        "custom-columns=TIME:.lastTimestamp,TYPE:.type,REASON:.reason,OBJECT:.involvedObject.name,MESSAGE:.message",
        "--no-headers",
    ])
    .await
    {
        // Filter to pod events matching our deployment
        let pod_events: Vec<&str> = stdout
            .trim()
            .lines()
            .filter(|l| l.contains(deployment_name))
            .collect();
        if !pod_events.is_empty() {
            crate::repo::push_section_indented_lines_4sp(
                &mut diag,
                "Related Pod Events (last 15)",
                pod_events.iter().rev().take(15),
            );
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

#[cfg(test)]
mod tests {
    use super::{
        bail_on_terminal_pod_failure, flux_poll_delay,
        write_flux_health_check_running_announce_line, PodStatus,
        FLUX_HEALTH_CHECK_RUNNING_ANNOUNCE_GLYPH, FLUX_POLL_BACKOFF,
    };
    use crate::test_support::code_line_hits;
    use std::time::Duration;

    // ====================================================================
    // deployment-pod-polling backoff — FLUX_POLL_BACKOFF + helper
    // ====================================================================
    //
    // These pin the RetryPolicy-consuming replacement of the pre-lift
    // bespoke `Backoff` struct (`Self { current: 2 }` seed, driven by
    // `sleep(Duration::from_secs(self.current)); self.current =
    // (self.current * 2).min(30)`) that both `verify_deployment_image`
    // and `wait_for_deployment` polled through. Sibling of the
    // `SHINKA_MIGRATION_POLL_BACKOFF` shields at
    // `commands/migrations.rs::tests` (commit b962db5) — same const-
    // + delegation-helper shape, same three-test pattern
    // (policy-shape / in-cap-schedule / past-cap-cap /
    // saturating-no-panic), same whole-module boundary shield that
    // forbids re-fusing the pre-lift `Backoff` struct.

    /// The `FLUX_POLL_BACKOFF` const's `(initial_backoff, factor,
    /// max_backoff)` triple is the load-bearing invariant every
    /// consumption site (both polling loops here, plus any future
    /// polling-loop consumer that reads the same schedule) shares.
    /// Pinned here so a future edit at the const's site is caught
    /// at a named test rather than silently across the two
    /// consumption sites and the delegation helper.
    #[test]
    fn test_flux_poll_backoff_policy_shape() {
        assert_eq!(
            FLUX_POLL_BACKOFF.initial_backoff,
            Duration::from_secs(2),
            "FLUX_POLL_BACKOFF.initial_backoff must be 2s \
             — preserves the pre-lift bespoke `Backoff {{ current: 2 }}` \
             seed verbatim at both polling loops' first sleep.",
        );
        assert_eq!(
            FLUX_POLL_BACKOFF.factor, 2,
            "FLUX_POLL_BACKOFF.factor must be 2 \
             — preserves the pre-lift `self.current * 2` climb verbatim.",
        );
        assert_eq!(
            FLUX_POLL_BACKOFF.max_backoff,
            Duration::from_secs(30),
            "FLUX_POLL_BACKOFF.max_backoff must be 30s \
             — preserves the pre-lift `.min(30)` cap verbatim.",
        );
    }

    /// Pre-lift the deployment-pod-polling loop's first four iterations
    /// emitted `sleep(2) → sleep(4) → sleep(8) → sleep(16)` via the
    /// mutating `Backoff::wait` body (seeded at 2, doubled after each
    /// non-terminal iteration, capped at 30). The lift's 0-indexed
    /// `attempt` counter must reproduce that schedule verbatim under
    /// `flux_poll_delay` at every within-cap attempt.
    #[test]
    fn test_flux_poll_delay_matches_pre_lift_schedule_at_in_cap_attempts() {
        assert_eq!(
            flux_poll_delay(0),
            Duration::from_secs(2),
            "iter 0 must sleep 2s — matches pre-lift `Backoff {{ current: 2 }}` seed.",
        );
        assert_eq!(
            flux_poll_delay(1),
            Duration::from_secs(4),
            "iter 1 must sleep 4s — matches pre-lift `2 * 2 = 4`.",
        );
        assert_eq!(
            flux_poll_delay(2),
            Duration::from_secs(8),
            "iter 2 must sleep 8s — matches pre-lift `4 * 2 = 8`.",
        );
        assert_eq!(
            flux_poll_delay(3),
            Duration::from_secs(16),
            "iter 3 must sleep 16s — matches pre-lift `8 * 2 = 16`.",
        );
    }

    /// Iterations past the cap must all emit `max_backoff = 30s` —
    /// pre-lift `(16 * 2).min(30) = 30` at iter 4 and `(30 * 2).min(30)
    /// = 30` at every subsequent iter. Both `verify_deployment_image`
    /// and `wait_for_deployment` are unbounded polling loops that can
    /// run minutes on slow deployments, so beyond-cap iterations must
    /// stay at the ceiling.
    #[test]
    fn test_flux_poll_delay_caps_at_max_backoff_past_the_cap() {
        assert_eq!(
            flux_poll_delay(4),
            Duration::from_secs(30),
            "iter 4 must sleep 30s (cap) — pre-lift `(16 * 2).min(30) = 30`.",
        );
        assert_eq!(
            flux_poll_delay(5),
            Duration::from_secs(30),
            "iter 5 must sleep 30s (cap).",
        );
        assert_eq!(
            flux_poll_delay(50),
            Duration::from_secs(30),
            "iter 50 must sleep 30s (cap) — polling loops can run \
             minutes on slow deployments, so beyond-cap iterations \
             must stay at the ceiling.",
        );
    }

    /// Both polling loops are unbounded by design (`_timeout_secs`
    /// carries a `kept for API compat, not used as hard timeout`
    /// comment), so `backoff_attempt` can in principle reach any
    /// `u32` value. Pre-lift the `self.current * 2` climb was safe
    /// only because `.min(30)` fired at iter 4; post-lift
    /// `saturating_add(2)` inside `flux_poll_delay` bounds the
    /// argument to `RetryPolicy::compute_delay`, whose
    /// `checked_pow`-then-cap body itself saturates without panic.
    /// This test pins that composition: an `attempt == u32::MAX`
    /// argument (a pathologically-long-running poll) returns a bounded
    /// delay rather than panicking.
    #[test]
    fn test_flux_poll_delay_saturates_without_panic_at_arbitrarily_large_attempt() {
        assert_eq!(
            flux_poll_delay(u32::MAX),
            Duration::from_secs(30),
            "attempt=u32::MAX must saturate to max_backoff without \
             panic — the `saturating_add(2)` bridge + \
             `RetryPolicy::compute_delay`'s `checked_pow` cap close \
             the u32 overflow class by construction.",
        );
        assert_eq!(
            flux_poll_delay(u32::MAX - 1),
            Duration::from_secs(30),
            "attempt=u32::MAX - 1 must also saturate to max_backoff \
             — the bridge `saturating_add(2)` returns u32::MAX, still \
             far past the cap.",
        );
    }

    /// Whole-module boundary shield: both polling-loop bodies MUST
    /// consume the typed primitive at `flux_poll_delay` rather than
    /// re-fusing the pre-lift bespoke `Backoff` struct or its
    /// mutating `Self { current: u64 }` state escape. A future
    /// refactor that reintroduces the instance-state escape (see
    /// `FLUX_POLL_BACKOFF`'s docstring for the three structural
    /// defects the lift closed) fails here, not silently in
    /// production. Whole-module boundary discipline sibling of
    /// `test_wait_for_shinka_migration_consumes_typed_poll_delay_not_mut_backoff_secs`
    /// at `commands/migrations.rs::tests` (commit b962db5).
    #[test]
    fn test_flux_polling_loops_consume_typed_poll_delay_not_bespoke_backoff_struct() {
        let module_body = crate::test_support::module_body_before_tests(
            include_str!("flux.rs"),
            "commands/flux.rs",
        );

        // Code-line filter (via `code_line_hits`) skips docstring /
        // prose-comment lines, so the shield does not false-positive
        // on `FLUX_POLL_BACKOFF`'s own docstring above (which cites
        // the pre-lift `struct Backoff { current: u64 }` shape as
        // context for the three defects it forecloses).
        let bespoke_struct_hits = code_line_hits(module_body, "struct Backoff");
        assert!(
            bespoke_struct_hits.is_empty(),
            "flux.rs must NOT hand-roll a bespoke `struct Backoff` \
             for the polling loops — the schedule lives at \
             `FLUX_POLL_BACKOFF` + `flux_poll_delay`, both grounding \
             through `RetryPolicy::compute_delay`. Found code-line \
             hits: {:#?}",
            bespoke_struct_hits,
        );
        let wait_call_hits = code_line_hits(module_body, "backoff.wait().await");
        assert!(
            wait_call_hits.is_empty(),
            "flux.rs must NOT drive the polling loops through a \
             bespoke `backoff.wait().await` method — the sleep site \
             must consume `crate::poll_backoff_advance::\
             advance_poll_backoff_tokio(&mut backoff_attempt, \
             flux_poll_delay)`. Found code-line hits: {:#?}",
            wait_call_hits,
        );
        let delegation_hits = code_line_hits(module_body, "flux_poll_delay");
        assert!(
            delegation_hits.len() >= 3,
            "flux.rs must consume the typed poll-delay helper at both \
             polling loops' sleep sites — post-lift the `flux_poll_delay` \
             function pointer is passed to \
             `crate::poll_backoff_advance::advance_poll_backoff_tokio` \
             at 2 call sites, plus the fn-definition line contributes \
             one hit, so the floor is `>= 3` code-line hits. Found:\n{}",
            delegation_hits.join("\n"),
        );
    }

    /// Regression shield: every `kubectl`-spawning site in
    /// `commands/flux.rs`'s two async diagnostic helpers
    /// (`get_pod_status_full`, `gather_deployment_diagnostics`) MUST
    /// resolve the binary through the higher-level primitives on
    /// [`crate::infrastructure::kubectl`] — post-lift the module has
    /// no direct call to
    /// [`crate::infrastructure::kubectl::kubectl_command_async`]
    /// anymore. The control-flow-carrying capture at
    /// `get_pod_status_full` rides on
    /// [`crate::infrastructure::kubectl::kubectl_capture_anyhow`] (the
    /// `kubectl_command_async()` + `.args()` + `run_capture_anyhow`
    /// fusion primitive), and the seven best-effort diagnostic probes
    /// at `gather_deployment_diagnostics` ride on
    /// [`crate::infrastructure::kubectl::kubectl_probe_stdout_capture`]
    /// (the sibling `(args)`-front async best-effort primitive). Both
    /// primitives internally spawn through
    /// [`crate::infrastructure::kubectl::kubectl_command_async`], so
    /// the `KUBECTL_BIN` env override discipline is inherited by
    /// construction. Pre-migration eight sites each spelled the bare
    /// `Command::new("kubectl")` shape verbatim and thereby bypassed
    /// the `KUBECTL_BIN` env override the tools-registry idiom
    /// (`crate::tools::get_tool_path(tools::KUBECTL)`,
    /// cli/src/tools.rs:102-105) resolves — the same class of bug
    /// the sibling `commands/status.rs` /
    /// `commands/supergraph_verification.rs` /
    /// `commands/product_release.rs::run_health_check` /
    /// `commands/github_runner_ci.rs::execute` /
    /// `services/migration_service.rs::MigrationService`
    /// migrations redeemed at c2760df / 65283fb / 5bb7cff / 5566415
    /// / 5986a10.
    ///
    /// This test reads this module's own source via [`include_str!`]
    /// and asserts the raw `Command::new("kubectl")` string does not
    /// reappear anywhere in the module's non-test body while the
    /// delegation to at least one of the two higher-level primitives
    /// does. A future regression that re-fuses the raw-spawn body
    /// fails here, not silently in production where a Nix-hermetic
    /// runner's `KUBECTL_BIN`-provided `kubectl` would lose to
    /// whatever `kubectl` is first on `PATH` at `forge deploy`
    /// diagnostic invocation time (the diagnostics helper is the
    /// operator-facing failure-triage surface for every deployment
    /// that goes red).
    ///
    /// The scan is bounded strictly to the module's non-test body
    /// — from the file start to the `#[cfg(test)]` marker — so
    /// this shield's own docstring mention of
    /// `Command::new("kubectl")` (which lives inside this
    /// `#[cfg(test)] mod tests` block) stays out of scope AND every
    /// current or future kubectl-spawning helper landing anywhere
    /// in the top-level module body cannot silently ride along
    /// without going through the primitive. Mirrors the
    /// whole-module boundary discipline `commands/status.rs`
    /// (c2760df) and `commands/supergraph_verification.rs`
    /// (65283fb) hold on the multi-function consumer surface.
    #[test]
    fn test_flux_routes_kubectl_through_infrastructure_primitives_not_raw_command() {
        let module_body = crate::test_support::module_body_before_tests(
            include_str!("flux.rs"),
            "commands/flux.rs",
        );

        assert!(
            !module_body.contains("Command::new(\"kubectl\")"),
            "flux.rs must NOT spawn `kubectl` directly — route \
             through one of the `crate::infrastructure::kubectl` \
             higher-level primitives (`kubectl_capture_anyhow` for \
             control-flow-carrying captures, `kubectl_probe_stdout_capture` \
             for best-effort diagnostics) so `KUBECTL_BIN` overrides \
             land at the shared constructor. Found the pre-migration \
             spawn body in the module."
        );
        let capture_hits =
            crate::test_support::code_line_hits(module_body, "kubectl_capture_anyhow(").len();
        let probe_hits =
            crate::test_support::code_line_hits(module_body, "kubectl_probe_stdout_capture(").len();
        assert!(
            capture_hits + probe_hits >= 1,
            "flux.rs must delegate every kubectl spawn to one of the \
             higher-level `crate::infrastructure::kubectl` primitives \
             (`kubectl_capture_anyhow` for control-flow-carrying \
             captures, `kubectl_probe_stdout_capture` for best-effort \
             diagnostics) — neither delegation was found at any *code* \
             line in the module body (capture_hits={capture_hits}, \
             probe_hits={probe_hits})."
        );
    }

    /// Captured-output routing shield scoped to the whole
    /// `commands/flux.rs` module body: the sole
    /// `if !output.status.success() { bail!("kubectl get pods failed") }`
    /// stanza in `get_pod_status_full` — the module's ONE captured-
    /// output bail-on-non-zero-exit site — MUST route through
    /// [`crate::retry::run_capture_anyhow`]. Pre-lift the operator
    /// log line read `"kubectl get pods failed"` and dropped BOTH
    /// the exit code AND the stderr: an operator triaging a Flux-
    /// managed deployment that never went ready had `kubectl get pods`
    /// failing with no signal whether kubectl exited 1 (a real
    /// kubeconfig / RBAC error against the target namespace), 127
    /// (`KUBECTL_BIN` route broken), or was killed by a signal
    /// (runner OOM). Post-lift the canonical
    /// `"kubectl get pods failed (exit {code}): {stderr}"` envelope
    /// is emitted by construction at `retry.rs::classify_capture_anyhow`'s
    /// ONE body, and the exit-code carry makes the three failure
    /// modes discriminable at the first log line.
    ///
    /// Sibling of the `commands/dashboards.rs` shield
    /// `test_generate_dashboards_from_jsonnet_bail_routes_through_classify_capture_anyhow`
    /// (b82200d), the `commands/sync.rs::generate_entities` shield
    /// (b82200d), the `commands/codegen.rs::execute` shield
    /// `test_execute_bun_install_routes_through_run_capture_anyhow_not_inline_bail`
    /// (06cd778), and the `commands/nix_builder.rs::test` shields
    /// (06cd778). Same discipline: negative side forbids the inline
    /// `if !output.status.success` bail terminator at any code line
    /// in the module body; positive side pins that
    /// `run_capture_anyhow(` appears at ≥1 code line — a regression
    /// that dropped the delegation cannot leave the negative scan
    /// trivially satisfied by absence. Scan bounds from file start
    /// to the FIRST `\n#[cfg(test)]\n` marker (the primary `mod tests`
    /// opener above), so this shield's own docstring mention of
    /// `if !output.status.success` stays out of scope.
    #[test]
    fn test_get_pod_status_full_bail_routes_through_run_capture_anyhow() {
        const SOURCE: &str = include_str!("flux.rs");
        let body = crate::test_support::module_body_before_tests(SOURCE, "commands/flux.rs");
        crate::test_support::assert_source_routes_captured_bails_through_classify_capture_anyhow(
            body,
            "commands/flux.rs::get_pod_status_full",
            1,
        );
    }

    /// Whole-module lift shield for the two pre-lift sibling 4-line
    /// `if elapsed - last_diag_at >= 120 && elapsed > 0 { last_diag_at
    /// = elapsed; let diag = gather_deployment_diagnostics(<ns>,
    /// <deploy>).await; println!("{}", diag); }` "every-120s poll-loop
    /// diagnostic burst" stanzas — one in
    /// [`super::verify_deployment_image`] and one in
    /// [`super::wait_for_deployment`], which formerly differed only in
    /// whether `namespace` / `deployment_name` were already `&str` refs
    /// or `String` bindings taken by `&`.
    ///
    /// Post-lift both consumer sites delegate through
    /// [`super::emit_periodic_deployment_diagnostics_burst`] and the
    /// 120-second cadence lives at ONE code point on
    /// [`super::DEPLOYMENT_DIAG_BURST_INTERVAL_SECS`]. This shield pins
    /// three invariants:
    ///
    /// 1. The pre-lift `elapsed - last_diag_at >= 120` guard does NOT
    ///    reappear anywhere in the module's non-test body — a
    ///    regression that re-fuses either 4-line stanza fails here
    ///    rather than silently desyncing the two operator-visible
    ///    diagnostic cadences.
    /// 2. `emit_periodic_deployment_diagnostics_burst(` appears at
    ///    exactly 2 call sites in the module body (both consumer
    ///    loops), plus one hit for the primitive's own `fn` definition
    ///    line, so the floor is `>= 3` code-line hits — a future edit
    ///    that dropped the delegation at either consumer cannot leave
    ///    the negative scan trivially satisfied by absence.
    /// 3. The `120` literal appears at exactly ONE code line: the
    ///    primitive's own const definition. A future edit that
    ///    re-inlined the burst frequency at either consumer fails
    ///    here.
    ///
    /// Scan bounded strictly to the module's non-test body (file start
    /// to the FIRST `\n#[cfg(test)]\nmod tests {` marker) so this
    /// shield's own docstring mentions of the pre-lift shape stay out
    /// of scope. Sibling of the `flux_poll_delay` whole-module
    /// boundary shield at
    /// [`test_flux_polling_loops_consume_typed_poll_delay_not_bespoke_backoff_struct`]
    /// above — same "one const + one delegation-helper + whole-module
    /// negative + positive-floor" quadruple discipline both polling
    /// loops share.
    #[test]
    fn test_flux_polling_loops_route_periodic_diag_burst_through_typed_primitive() {
        let module_body = crate::test_support::module_body_before_tests(
            include_str!("flux.rs"),
            "commands/flux.rs",
        );

        // (1) Pre-lift guard shape must not reappear at any code line.
        let pre_lift_hits = code_line_hits(module_body, "elapsed - last_diag_at >= 120");
        assert!(
            pre_lift_hits.is_empty(),
            "commands/flux.rs must NOT re-fuse the pre-lift 4-line \
             `if elapsed - last_diag_at >= 120 && elapsed > 0 {{ … }}` \
             periodic-diagnostic-burst stanza at either polling loop — \
             route through \
             `emit_periodic_deployment_diagnostics_burst(namespace, \
             deployment_name, elapsed, &mut last_diag_at).await` \
             instead. Found code-line hits: {:#?}",
            pre_lift_hits,
        );

        // (2) Post-lift delegation must appear at ≥3 code lines
        // (two callers + the primitive's own `fn` definition line).
        let delegation_hits =
            code_line_hits(module_body, "emit_periodic_deployment_diagnostics_burst(");
        assert!(
            delegation_hits.len() >= 3,
            "commands/flux.rs must consume the typed \
             `emit_periodic_deployment_diagnostics_burst` primitive at \
             both polling loops — post-lift the primitive is invoked \
             at 2 call sites (`verify_deployment_image`, \
             `wait_for_deployment`) plus the `fn`-definition line \
             contributes one hit, so the floor is `>= 3` code-line \
             hits. Found:\n{}",
            delegation_hits.join("\n"),
        );

        // (3) The 120-second cadence literal must live at ONE code
        // point — the primitive's own const definition. Anchor the
        // needle to the const's `= 120;` suffix so a future
        // `RetryPolicy::max_attempts = 120` or an unrelated 120
        // elsewhere in the module cannot false-positive.
        let cadence_const_hits = code_line_hits(
            module_body,
            "const DEPLOYMENT_DIAG_BURST_INTERVAL_SECS: u64 = 120;",
        );
        assert_eq!(
            cadence_const_hits.len(),
            1,
            "commands/flux.rs must pin the 120-second periodic-diagnostic \
             burst cadence at exactly ONE code point — the \
             `DEPLOYMENT_DIAG_BURST_INTERVAL_SECS` const's own \
             definition line. Found code-line hits: {:#?}",
            cadence_const_hits,
        );
    }

    /// Whole-module lift shield for the two pre-lift sibling 3-line
    /// preamble stanzas
    ///
    /// ```ignore
    /// let start = std::time::Instant::now();
    /// let mut backoff_attempt: u32 = 0;
    /// let mut last_diag_at = 0u64;
    /// ```
    ///
    /// that opened the two deployment-pod-polling loops in
    /// [`super::verify_deployment_image`] and
    /// [`super::wait_for_deployment`]. Post-lift both consumer sites
    /// bind a single `let mut poll_clock =
    /// crate::deployment_poll_clock::DeploymentPollClock::new();`
    /// carrying the same three fields as pub fields for disjoint
    /// mutable borrows through the existing
    /// [`super::emit_periodic_deployment_diagnostics_burst`] and
    /// [`crate::poll_backoff_advance::advance_poll_backoff_tokio`]
    /// consumers.
    ///
    /// Two invariants pinned here:
    ///
    /// 1. **Negative:** The `let mut last_diag_at = 0u64;` line — a
    ///    tell for the pre-lift 3-line preamble whose ident +
    ///    literal-type pair (`0u64`, not the bare `0`) is unique to
    ///    the two lifted sites in this crate — must not reappear in
    ///    the module body. A regression that re-inlined either
    ///    preamble fails here. (`let mut backoff_attempt: u32 = 0;`
    ///    appears in eight other polling loops fleet-wide, so it
    ///    would false-positive on cross-module drift; `last_diag_at`
    ///    is exclusive to this module by grep, making it the reliable
    ///    tell.)
    /// 2. **Positive delegation floor ≥ 2:** `DeploymentPollClock::new(`
    ///    appears at ≥ 2 code lines in the module body — both
    ///    consumer loops. A future third deployment-pod-polling loop
    ///    added to this module joins the same delegation chain, and
    ///    the floor grows with it.
    ///
    /// Scan bounded strictly to the module's non-test body (file
    /// start to the FIRST `\n#[cfg(test)]\nmod tests {` marker) so
    /// this shield's own docstring mention of the pre-lift shape
    /// stays out of scope. Sibling of the
    /// `test_flux_polling_loops_route_periodic_diag_burst_through_typed_primitive`
    /// whole-module boundary shield above — same "one const + one
    /// delegation-helper + whole-module negative + positive-floor"
    /// quadruple discipline every three-field poll-loop preamble
    /// this module carries.
    #[test]
    fn test_flux_polling_loops_route_deployment_poll_clock_new() {
        let module_body = crate::test_support::module_body_before_tests(
            include_str!("flux.rs"),
            "commands/flux.rs",
        );

        // (1) Pre-lift preamble tell — `let mut last_diag_at = 0u64;`
        // — must not reappear at any code line.
        let pre_lift_hits = code_line_hits(module_body, "let mut last_diag_at = 0u64;");
        assert!(
            pre_lift_hits.is_empty(),
            "commands/flux.rs must NOT re-inline the pre-lift 3-line \
             `let start = std::time::Instant::now(); \
             let mut backoff_attempt: u32 = 0; \
             let mut last_diag_at = 0u64;` deployment-pod-polling \
             preamble at either consumer loop — route through \
             `crate::deployment_poll_clock::DeploymentPollClock::new()` \
             instead. Found code-line hits: {:#?}",
            pre_lift_hits,
        );

        // (2) Post-lift delegation must appear at ≥ 2 code lines
        // (one per consumer loop).
        let delegation_hits = code_line_hits(module_body, "DeploymentPollClock::new()");
        assert!(
            delegation_hits.len() >= 2,
            "commands/flux.rs must consume \
             `crate::deployment_poll_clock::DeploymentPollClock::new()` \
             at both polling loops' preambles — post-lift the \
             constructor is invoked at 2 call sites \
             (`verify_deployment_image`, `wait_for_deployment`). \
             Found:\n{}",
            delegation_hits.join("\n"),
        );
    }

    /// Delegation-count shield for the seven best-effort captured-
    /// stdout diagnostic probes in
    /// [`super::gather_deployment_diagnostics`]. Every one MUST route
    /// through one of the two typed primitives on the
    /// `crate::infrastructure::kubectl` surface — the raw
    /// [`crate::infrastructure::kubectl::kubectl_probe_stdout_capture`]
    /// (async twin of [`crate::retry::probe_stdout_capture_sync`] at
    /// the `kubectl_command_async()` frontier) OR the fused
    /// [`crate::infrastructure::kubectl::kubectl_probe_push_nonempty_section_4sp`]
    /// (probe + `push_section_indented_lines_4sp` at three of the
    /// seven sites) — so a regression that reintroduced the pre-lift
    /// four-line stanza
    /// (`if let Ok(output) = kubectl_command_async().args([...]).output().await
    /// { let stdout = String::from_utf8_lossy(&output.stdout); ... }`)
    /// at even one of the seven sites fails here rather than silently
    /// drifting the diagnostic-print surface's discipline.
    ///
    /// The delegation-count floor mirrors the sibling
    /// `commands/e2e.rs::docker_bin_routing_tests` and
    /// `commands/prerelease.rs::tests` shields at 1ffda81 — a
    /// negative-only scan (forbidding the pre-lift stanza) would be
    /// trivially satisfied by absence, so the `>= 7` positive floor
    /// forces every current-and-future diagnostic probe in this
    /// module to land on one of the two primitives by construction.
    /// The floor sums direct `kubectl_probe_stdout_capture(` calls
    /// and fused `kubectl_probe_push_nonempty_section_4sp(` calls
    /// (each fusion call composes one `kubectl_probe_stdout_capture`
    /// internally), so a future edit that migrates a raw-probe site
    /// onto the fusion primitive — or a new probe that lands on either
    /// primitive — keeps the sum ≥ 7. Scan bounded strictly to the
    /// module's non-test body (file start to the FIRST
    /// `#[cfg(test)]\nmod tests {` marker) so this shield's own
    /// docstring mention of both primitives stays out of scope.
    #[test]
    fn test_gather_deployment_diagnostics_routes_through_kubectl_probe_stdout_capture() {
        const SOURCE: &str = include_str!("flux.rs");
        let body = crate::test_support::module_body_before_tests(SOURCE, "commands/flux.rs");
        let raw_hits = crate::test_support::code_line_hits(body, "kubectl_probe_stdout_capture(");
        let fused_hits =
            crate::test_support::code_line_hits(body, "kubectl_probe_push_nonempty_section_4sp(");
        let total = raw_hits.len() + fused_hits.len();
        assert!(
            total >= 7,
            "commands/flux.rs::gather_deployment_diagnostics must \
             route every one of its seven best-effort captured-stdout \
             diagnostic probes through either \
             `crate::infrastructure::kubectl::kubectl_probe_stdout_capture` \
             or its fused sibling \
             `crate::infrastructure::kubectl::kubectl_probe_push_nonempty_section_4sp` — \
             expected raw_hits + fused_hits >= 7, found raw_hits={} + \
             fused_hits={} = {}. Raw hits: {:#?}. Fused hits: {:#?}",
            raw_hits.len(),
            fused_hits.len(),
            total,
            raw_hits,
            fused_hits,
        );
    }

    // ====================================================================
    // FluxCD-health-check running-branch announce line —
    // `print_flux_health_check_running_announce_line` fuser
    // ====================================================================
    //
    // These shields pin the lift of the two sibling `println!("🩺 {}",
    // format!("FluxCD health check ({})...", context).bold())` running-
    // branch announce stanzas that opened `pub async fn health_check`
    // and `pub async fn health_check_with_retry` verbatim before the
    // lift onto `print_flux_health_check_running_announce_line`. Same
    // byte-oracle + delegation-shield pattern the sibling
    // `pre_release_flux_health_check_step` and
    // `post_release_flux_health_check_step` modules carry — but
    // module-local here because both consumers live in `flux.rs`.

    /// Byte-oracle for `write_flux_health_check_running_announce_line`
    /// on the `"pre-release"` context — the exact spelling
    /// [`health_check`]'s callers (both `commands/
    /// pre_release_flux_health_check_step::run_pre_release_flux_health_check_step`
    /// and the direct-invocation sites) hand in. A silent drift a
    /// future rewrite might introduce — dropping the `🩺` glyph,
    /// renaming the title, dropping the `.bold()` chain, dropping the
    /// trailing `\n` — flips this assertion rather than compiling and
    /// silently diverging the two consumer sites' visual grammar.
    #[test]
    fn write_running_announce_line_emits_pre_release_context_verbatim() {
        let mut buf: Vec<u8> = Vec::new();
        write_flux_health_check_running_announce_line(&mut buf, "pre-release")
            .expect("write against a Vec<u8> sink must succeed");
        let out = String::from_utf8(buf).expect(
            "running-branch announce line must emit valid UTF-8 (the pre-lift println! did)",
        );
        // `colored` is detect-terminal-aware, so at test time (no tty)
        // the ANSI envelope collapses to the bare bytes — assert on the
        // un-ANSI'd shape so this test survives both tty-and-piped runs.
        assert!(
            out.contains("🩺 "),
            "announce line must open with the `🩺 ` glyph + space \
             prefix (pre-lift literal at both consumer sites). Got {out:?}"
        );
        assert!(
            out.contains("FluxCD health check (pre-release)..."),
            "announce line must carry the plain-ASCII title body \
             verbatim under the `pre-release` context. Got {out:?}"
        );
        assert!(
            out.ends_with('\n'),
            "announce line must terminate with a single `\\n` \
             (pre-lift `println!` did). Got {out:?}"
        );
    }

    /// Byte-oracle sibling for the `"post-release"` context — the exact
    /// spelling [`health_check_with_retry`]'s callers (both
    /// `commands/post_release_flux_health_check_step::
    /// run_post_release_flux_health_check_step` and the direct-
    /// invocation sites) hand in. Pins the second consumer's context
    /// projection so a variant-dispatch regression that hard-coded the
    /// primitive on `"pre-release"` — silently mislabeling the
    /// `health_check_with_retry` announce line — surfaces here rather
    /// than in production.
    #[test]
    fn write_running_announce_line_emits_post_release_context_verbatim() {
        let mut buf: Vec<u8> = Vec::new();
        write_flux_health_check_running_announce_line(&mut buf, "post-release").unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("🩺 "),
            "announce line must open with the `🩺 ` glyph + space \
             prefix under the `post-release` context. Got {out:?}"
        );
        assert!(
            out.contains("FluxCD health check (post-release)..."),
            "announce line must carry the plain-ASCII title body \
             verbatim under the `post-release` context. Got {out:?}"
        );
    }

    /// The primitive MUST NOT emit anything beyond the exact context
    /// handed in — no trimming, case-folding, punctuation injection. A
    /// future normalisation at the primitive boundary would silently
    /// diverge from what the pre-lift inline `format!("FluxCD health
    /// check ({})...", context)` did with the literal context. Pin the
    /// verbatim-forwarding contract with a gnarly input.
    #[test]
    fn write_running_announce_line_forwards_context_verbatim_no_normalisation() {
        let mut buf: Vec<u8> = Vec::new();
        write_flux_health_check_running_announce_line(&mut buf, "STAGE-7/9").unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("FluxCD health check (STAGE-7/9)..."),
            "announce line must forward the context verbatim — no \
             trim, no case-fold, no punctuation injection. Got {out:?}"
        );
    }

    /// Pin the `🩺` glyph constant — pre-lift both sites spelled the
    /// literal `"🩺 "` as the leading `println!` prefix. A drift (a
    /// swap to `⚕️`, a drop of the glyph, a promotion to
    /// `crate::ui::print_running_step_heading`) reaches ONE site
    /// through the const.
    #[test]
    fn announce_line_glyph_constant_is_pre_lift_literal() {
        assert_eq!(
            FLUX_HEALTH_CHECK_RUNNING_ANNOUNCE_GLYPH, "🩺",
            "FLUX_HEALTH_CHECK_RUNNING_ANNOUNCE_GLYPH must project the \
             pre-lift `🩺` glyph both `health_check` and \
             `health_check_with_retry` spelled as their announce-line \
             prefix. Got {:?}",
            FLUX_HEALTH_CHECK_RUNNING_ANNOUNCE_GLYPH,
        );
    }

    /// Whole-module negative caller shield: no raw `"FluxCD health
    /// check ({})..."` template literal may live in the pre-tests body
    /// of `commands/flux.rs` outside of
    /// `write_flux_health_check_running_announce_line`. Post-lift the
    /// two pre-lift consumer sites each forward through
    /// `print_flux_health_check_running_announce_line`; a future
    /// re-inline (a "just call `println!` directly, it's shorter"
    /// cleanup) silently reopens the two-site duplication class this
    /// lift closed. The shield asserts the template survives at
    /// EXACTLY one code line — the writer body — so a re-inline at
    /// either consumer bumps the count above 1 and trips the test.
    #[test]
    fn no_raw_running_announce_template_survives_outside_writer_body() {
        const SOURCE: &str = include_str!("flux.rs");
        let body = crate::test_support::module_body_before_tests(SOURCE, "commands/flux.rs");
        const NEEDLE: &str = "\"FluxCD health check ({})...\"";
        let hits = code_line_hits(body, NEEDLE);
        assert_eq!(
            hits.len(),
            1,
            "commands/flux.rs pre-tests body must spell the raw \
             `\"FluxCD health check ({{}})...\"` template at EXACTLY \
             one code line — the writer body of \
             `write_flux_health_check_running_announce_line`. A hit \
             count above 1 means a re-inline at one of the two \
             pre-lift consumer sites silently reopened the two-site \
             duplication class this lift closed. Got {} hits: {:#?}",
            hits.len(),
            hits,
        );
    }

    /// Positive delegation shield — `commands/flux.rs` must forward
    /// through `print_flux_health_check_running_announce_line` at
    /// exactly 2 call sites (one per pre-lift consumer:
    /// [`health_check`] and [`health_check_with_retry`]). A fusion
    /// that folded the two sites into one call or dropped one of the
    /// consumers silently fails here — the negative half above would
    /// still pass, but the positive count would fall below the
    /// pre-lift census.
    ///
    /// The primitive's own `fn` definition line matches the needle
    /// too, so the shield filters out lines whose trimmed prefix
    /// starts with `fn ` to count only invocation sites.
    #[test]
    fn flux_module_forwards_through_running_announce_line_primitive_twice() {
        const SOURCE: &str = include_str!("flux.rs");
        let body = crate::test_support::module_body_before_tests(SOURCE, "commands/flux.rs");
        const FORWARD_NEEDLE: &str = "print_flux_health_check_running_announce_line(";
        let call_site_hits: Vec<String> = code_line_hits(body, FORWARD_NEEDLE)
            .into_iter()
            .filter(|line| !line.contains(": fn "))
            .collect();
        assert_eq!(
            call_site_hits.len(),
            2,
            "commands/flux.rs pre-tests body must forward to \
             `print_flux_health_check_running_announce_line(...)` at \
             exactly 2 call sites — one per pre-lift consumer (`health_check` \
             and `health_check_with_retry`). Found {} call-site hits: {:#?}",
            call_site_hits.len(),
            call_site_hits,
        );
    }

    // ====================================================================
    // bail_on_terminal_pod_failure — terminal-container-failure discriminator
    // ====================================================================
    //
    // Pre-lift both deployment-pod-polling loops
    // (`verify_deployment_image` at ~line 548, `wait_for_deployment` at
    // ~line 635) each carried the same 10-line stanza:
    //
    //     if let Some(ref reason) = pod.waiting_reason {
    //         if is_terminal_failure(reason) {
    //             let diagnostics =
    //                 gather_deployment_diagnostics(<ns>, <deploy>).await;
    //             bail!(
    //                 "Deployment {} failed: {} ({})\n{}",
    //                 deployment_name,
    //                 reason,
    //                 pod.waiting_message.as_deref().unwrap_or(""),
    //                 diagnostics,
    //             );
    //         }
    //     }
    //
    // differing only in whether `namespace` / `deployment_name` were
    // `&str` refs (`verify_deployment_image`) or `String` bindings
    // taken by `&` (`wait_for_deployment`). Post-lift both consumers
    // delegate through `bail_on_terminal_pod_failure(&pod, ns,
    // deploy).await?` and the terminal-failure discriminator, the
    // diagnostics-gather call, and the `bail!` envelope all live at
    // ONE code point. Sibling of the periodic-diagnostic-burst lift
    // shield above — same "whole-module negative + positive-floor +
    // typed unit test" triple discipline.

    /// Non-terminal path — `pod.waiting_reason = None` (the fresh
    /// pod's steady state before a container starts) must fold to
    /// `Ok(())` so the poll loop's next iteration walks. This exercise
    /// only touches the primitive's early-return path and never hits
    /// `gather_deployment_diagnostics`, so no kubectl process is
    /// spawned and the test runs hermetically.
    #[tokio::test]
    async fn bail_on_terminal_pod_failure_returns_ok_when_waiting_reason_absent() {
        let pod = PodStatus {
            image: "ghcr.io/x/svc:sha".to_string(),
            phase: "Running".to_string(),
            ready: true,
            waiting_reason: None,
            waiting_message: None,
        };
        let outcome = bail_on_terminal_pod_failure(&pod, "ns", "svc").await;
        assert!(
            outcome.is_ok(),
            "bail_on_terminal_pod_failure must fold `waiting_reason = \
             None` (the fresh-pod steady state) to `Ok(())` so the \
             deployment-pod-polling loop's next iteration walks. Got: \
             {:?}",
            outcome,
        );
    }

    /// Non-terminal path — a non-fatal `waiting_reason`
    /// (e.g. `"ContainerCreating"`) must also fold to `Ok(())`. The
    /// canonical `is_terminal_failure` closed set is
    /// `{ImagePullBackOff, ErrImagePull, InvalidImageName,
    /// ErrImageNeverPull, CreateContainerConfigError,
    /// CrashLoopBackOff}` — anything outside that set is a transient
    /// state the poll loop must keep walking through, never bail on.
    #[tokio::test]
    async fn bail_on_terminal_pod_failure_returns_ok_when_waiting_reason_non_terminal() {
        let pod = PodStatus {
            image: "ghcr.io/x/svc:sha".to_string(),
            phase: "Pending".to_string(),
            ready: false,
            waiting_reason: Some("ContainerCreating".to_string()),
            waiting_message: Some("pulling image".to_string()),
        };
        let outcome = bail_on_terminal_pod_failure(&pod, "ns", "svc").await;
        assert!(
            outcome.is_ok(),
            "bail_on_terminal_pod_failure must fold a non-terminal \
             `waiting_reason` (e.g. `ContainerCreating`) to `Ok(())` \
             so the poll loop keeps walking. Got: {:?}",
            outcome,
        );
    }

    /// Whole-module lift shield for the two pre-lift sibling 10-line
    /// terminal-pod-failure bail stanzas. Post-lift the discriminator
    /// lives at ONE code point on `bail_on_terminal_pod_failure` and
    /// both consumer sites delegate through it.
    ///
    /// Two invariants pinned here:
    ///
    /// 1. **Negative:** The pre-lift envelope literal
    ///    `"Deployment {} failed: {} ({})\n{}"` must appear at exactly
    ///    ONE code line — the primitive's own `bail!(…)` body. Pre-
    ///    lift the same literal appeared at two consumer sites; a
    ///    regression that re-fused either 10-line stanza fails here
    ///    rather than silently drifting the two operator-visible
    ///    deployment-failure envelopes apart.
    /// 2. **Positive delegation floor ≥ 2:**
    ///    `bail_on_terminal_pod_failure(` appears at ≥ 2 code lines in
    ///    the module body (both consumer loops; the `async fn`
    ///    definition line contributes a third hit and the assertion
    ///    tolerates it). A future third deployment-pod-polling loop
    ///    added to this module joins the same delegation chain, and
    ///    the floor grows with it.
    ///
    /// Scan bounded strictly to the module's non-test body (file start
    /// to the FIRST `\n#[cfg(test)]\nmod tests {` marker) so this
    /// shield's own docstring mention of the pre-lift envelope stays
    /// out of scope. Sibling of the
    /// `test_flux_polling_loops_route_periodic_diag_burst_through_typed_primitive`
    /// whole-module boundary shield above — same "one primitive +
    /// whole-module negative + positive floor" triple discipline both
    /// polling loops share.
    #[test]
    fn test_flux_polling_loops_route_terminal_pod_failure_through_typed_primitive() {
        let module_body = crate::test_support::module_body_before_tests(
            include_str!("flux.rs"),
            "commands/flux.rs",
        );

        // (1) Pre-lift envelope must live at exactly ONE code line
        // (the primitive's own `bail!(…)` body).
        let envelope_hits = code_line_hits(module_body, "\"Deployment {} failed: {} ({})\\n{}\",");
        assert_eq!(
            envelope_hits.len(),
            1,
            "commands/flux.rs must pin the canonical \
             `\"Deployment {{}} failed: {{}} ({{}})\\n{{}}\"` bail \
             envelope at exactly ONE code point — the \
             `bail_on_terminal_pod_failure` primitive's own `bail!(…)` \
             body. A hit count other than 1 means either a consumer \
             loop re-inlined the pre-lift 10-line stanza or the \
             primitive body drifted. Found code-line hits: {:#?}",
            envelope_hits,
        );

        // (2) Post-lift delegation must appear at ≥ 2 code lines
        // (one per consumer loop).
        let delegation_hits = code_line_hits(module_body, "bail_on_terminal_pod_failure(");
        assert!(
            delegation_hits.len() >= 2,
            "commands/flux.rs must consume the typed \
             `bail_on_terminal_pod_failure` primitive at both polling \
             loops — post-lift the primitive is invoked at ≥ 2 call \
             sites (`verify_deployment_image`, `wait_for_deployment`; \
             the `async fn` definition line contributes a further \
             hit). Found:\n{}",
            delegation_hits.join("\n"),
        );
    }
}
