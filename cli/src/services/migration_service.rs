//! Migration service - runs database migrations
//!
//! Handles running migrations as Kubernetes Jobs with proper monitoring.

use anyhow::{Context, Result};
use std::time::{Duration, Instant};
use tracing::{info, warn};

use crate::domain::migration::{DatabaseType, MigrationConfig, MigrationResult};
use crate::retry::RetryPolicy;

/// The typed exponential-backoff policy for [`MigrationService::wait_for_job`]
/// k8s-Job status-poll cadence — `initial_backoff` 2s × `factor` 2 capped at
/// `max_backoff` 30s. Consumes the pre-existing typed primitive at
/// [`crate::retry::RetryPolicy`] so the per-attempt delay lands at
/// [`RetryPolicy::compute_delay`], the same shared body the sibling
/// reconcile-poll surface `commands/migrations.rs::
/// SHINKA_MIGRATION_POLL_BACKOFF` (commit b962db5), the flux polling-loops
/// surface `commands/flux.rs::FLUX_POLL_BACKOFF` (commit 65de62f), the
/// health-endpoint retry surface `commands/post_deploy_verification.rs::
/// HEALTH_ENDPOINT_BACKOFF` (commit b5db3b6), and the web / integration
/// test-suite retry surfaces (commits 9fd38d3 / e22b0a2) read through.
///
/// Pre-lift the schedule was spelled inline as a bare fixed
/// `tokio::time::sleep(Duration::from_secs(2)).await` at every non-terminal
/// arm of the k8s-Job status-poll loop. That shape carried three structural
/// defects the typed-primitive body forecloses:
/// 1. **Fixed 2s schedule.** A flat `sleep(2s)` between poll iterations is
///    "too short when the migration is actually running (150 kubectl probes
///    over a 5-minute job — noise against the k8s API), 2s too long when
///    the Complete condition landed 100ms ago" — the exact worst-of-both
///    failure mode the sibling `TEST_RETRY_BACKOFF` / `INTEGRATION_TEST_
///    RETRY_BACKOFF` / `FLUX_POLL_BACKOFF` docstrings cite for their own
///    pre-lift fixed / bespoke schedules. Post-lift, the first poll still
///    waits 2s (preserving the seed verbatim), then 4s / 8s / 16s / 30s /
///    30s / … — 13 iterations reach the 5-minute default timeout under the
///    exponential-with-cap climb rather than 150 iterations under the
///    pre-lift flat 2s.
/// 2. **No caller-visible schedule invariant.** The bare
///    `Duration::from_secs(2)` literal at the poll-loop sleep carried no
///    name a shield could pin — a future edit that changed the schedule at
///    this site did not surface at any named-primitive audit path. The
///    lifted `MIGRATION_JOB_POLL_BACKOFF` const names the (seed, factor,
///    cap) triple a shield can cite and enforce.
/// 3. **Schedule desync from the sibling reconcile-poll surface.**
///    The Shinka reconcile-poll loop and the k8s-Job status-poll loop
///    poll the same class of resource (a k8s migration surface) with the
///    same 2s seed — pre-lift each spelled its own local, so a future edit
///    to one silently diverged from the other. Post-lift both consume the
///    same shared body via the same `RetryPolicy::network()`
///    `(factor=2, max_backoff=30s)` reference schedule, differing only at
///    the shared 2s seed both preserve verbatim from their pre-lift shapes.
///
/// `max_attempts: u32::MAX` is a placeholder — the poll loop is bounded by
/// wall-clock via [`MigrationService::timeout`] (`start.elapsed() > self.
/// timeout` at loop head), not by attempt count — and consumes only
/// [`RetryPolicy::compute_delay`] from this policy, not
/// [`RetryPolicy::max_attempts`]. The `max_attempts` field is unconsulted
/// at this consumption site.
const MIGRATION_JOB_POLL_BACKOFF: RetryPolicy =
    RetryPolicy::wall_clock_poll(Duration::from_secs(2));

/// Backoff between k8s-Job status-poll iterations, given a 0-indexed local
/// `attempt` counter (the `loop { ... }` shape
/// [`MigrationService::wait_for_job`] drives increments once per
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
/// `sleep(Duration::from_secs(2))` seed verbatim at the first poll and
/// strictly diverges upward at every later poll.
///
/// The `saturating_add` clamp forecloses the `u32` overflow class at the
/// bridge — a pathologically-long-running poll loop that reaches
/// `attempt == u32::MAX` reads as `compute_delay(u32::MAX)`, which itself
/// saturates to [`MIGRATION_JOB_POLL_BACKOFF::max_backoff`] via the
/// `checked_pow`-then-cap body inside [`RetryPolicy::compute_delay`]
/// without panic.
fn migration_job_poll_delay(attempt: u32) -> Duration {
    MIGRATION_JOB_POLL_BACKOFF.compute_delay(attempt.saturating_add(2))
}

/// Service for running database migrations
pub struct MigrationService {
    /// Timeout for waiting on jobs
    timeout: Duration,
}

impl MigrationService {
    /// Create a new migration service
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(300),
        }
    }

    /// Create with custom timeout
    pub fn with_timeout(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// Run migrations for a service
    pub async fn run(&self, config: &MigrationConfig) -> Result<MigrationResult> {
        // Check if migrations should be skipped
        if config.should_skip() {
            info!("No migrations configured for {}", config.service);
            return Ok(MigrationResult {
                success: true,
                duration: Duration::ZERO,
                logs: None,
            });
        }

        let run_mode = config
            .database_type
            .run_mode()
            .expect("run_mode should exist if not skipped");

        info!(
            "Running {} migrations for {}",
            config.database_type.name(),
            config.service
        );
        info!("RUN_MODE={}", run_mode);

        let start = Instant::now();

        // Create and run the migration job
        let result = self.run_migration_job(config).await;
        let duration = start.elapsed();

        match result {
            Ok(logs) => {
                info!(
                    "Migrations completed successfully in {:.1}s",
                    duration.as_secs_f64()
                );
                Ok(MigrationResult {
                    success: true,
                    duration,
                    logs: Some(logs),
                })
            }
            Err(e) => {
                warn!("Migrations failed: {}", e);
                Ok(MigrationResult {
                    success: false,
                    duration,
                    logs: Some(e.to_string()),
                })
            }
        }
    }

    /// Create and run the Kubernetes Job for migrations
    async fn run_migration_job(&self, config: &MigrationConfig) -> Result<String> {
        let job_name = config.job_name();

        info!("Creating migration job: {}", job_name);

        // Delete existing job if present
        self.delete_existing_job(&job_name, &config.namespace)
            .await?;

        // Create new job
        self.create_job(config).await?;

        // Wait for job completion
        self.wait_for_job(&job_name, &config.namespace).await?;

        // Get logs
        let logs = self.get_job_logs(&job_name, &config.namespace).await?;

        // Cleanup
        self.delete_existing_job(&job_name, &config.namespace)
            .await?;

        Ok(logs)
    }

    async fn delete_existing_job(&self, name: &str, namespace: &str) -> Result<()> {
        let output = crate::infrastructure::kubectl::kubectl_command_async()
            .args(["delete", "job", name, "-n", namespace, "--ignore-not-found"])
            .output()
            .await
            .context("Failed to delete existing job")?;

        if !output.status.success() {
            warn!(
                "Failed to delete job (may not exist): {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(())
    }

    async fn create_job(&self, config: &MigrationConfig) -> Result<()> {
        let run_mode = config
            .database_type
            .run_mode()
            .expect("run_mode should exist");

        let job_manifest = format!(
            r#"
apiVersion: batch/v1
kind: Job
metadata:
  name: {}
  namespace: {}
spec:
  ttlSecondsAfterFinished: 300
  backoffLimit: 0
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: migrate
          image: {}
          env:
            - name: RUN_MODE
              value: "{}"
          envFrom:
            - secretRef:
                name: {}-secrets
                optional: true
          resources:
            requests:
              memory: "{}"
              cpu: "{}"
            limits:
              memory: "{}"
              cpu: "{}"
"#,
            config.job_name(),
            config.namespace,
            config.image_ref(),
            run_mode,
            config.service,
            config.resources.memory_request,
            config.resources.cpu_request,
            config.resources.memory_limit,
            config.resources.cpu_limit,
        );

        let mut child = crate::infrastructure::kubectl::kubectl_command_async()
            .args(["apply", "-f", "-"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .context("Failed to spawn kubectl")?;

        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            stdin
                .write_all(job_manifest.as_bytes())
                .await
                .context("Failed to write job manifest")?;
        }

        let status = child.wait().await.context("Failed to wait for kubectl")?;

        if !status.success() {
            anyhow::bail!("Failed to create migration job");
        }

        Ok(())
    }

    async fn wait_for_job(&self, name: &str, namespace: &str) -> Result<()> {
        let start = Instant::now();
        let mut backoff_attempt: u32 = 0;

        loop {
            if start.elapsed() > self.timeout {
                anyhow::bail!("Timeout waiting for migration job");
            }

            let output = crate::infrastructure::kubectl::kubectl_command_async()
                .args([
                    "get",
                    "job",
                    name,
                    "-n",
                    namespace,
                    "-o",
                    "jsonpath={.status.conditions[?(@.type==\"Complete\")].status}",
                ])
                .output()
                .await
                .context("Failed to check job status")?;

            let status = String::from_utf8_lossy(&output.stdout);

            if status.trim() == "True" {
                return Ok(());
            }

            // Check for failure
            let output = crate::infrastructure::kubectl::kubectl_command_async()
                .args([
                    "get",
                    "job",
                    name,
                    "-n",
                    namespace,
                    "-o",
                    "jsonpath={.status.conditions[?(@.type==\"Failed\")].status}",
                ])
                .output()
                .await?;

            let failed = String::from_utf8_lossy(&output.stdout);
            if failed.trim() == "True" {
                anyhow::bail!("Migration job failed");
            }

            tokio::time::sleep(migration_job_poll_delay(backoff_attempt)).await;
            backoff_attempt = backoff_attempt.saturating_add(1);
        }
    }

    async fn get_job_logs(&self, name: &str, namespace: &str) -> Result<String> {
        let output = crate::infrastructure::kubectl::kubectl_command_async()
            .args(["logs", &format!("job/{}", name), "-n", namespace])
            .output()
            .await
            .context("Failed to get job logs")?;

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

impl Default for MigrationService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_migration_service_creation() {
        let service = MigrationService::new();
        assert_eq!(service.timeout, Duration::from_secs(300));
    }

    #[test]
    fn test_migration_service_with_timeout() {
        let service = MigrationService::with_timeout(Duration::from_secs(600));
        assert_eq!(service.timeout, Duration::from_secs(600));
    }

    /// The `(initial_backoff, factor, max_backoff)` shape of the k8s-Job
    /// status-poll backoff policy is a load-bearing invariant shared with
    /// the sibling reconcile-poll surface at `commands/migrations.rs::
    /// SHINKA_MIGRATION_POLL_BACKOFF` — both policies consume the same
    /// `RetryPolicy::network()` `(factor=2, max_backoff=30s)` reference
    /// schedule and the same 2s seed. Pinned here so a future silent-
    /// desync at the const site (a factor bump, a cap change, a seed
    /// drift) is caught at a named test rather than silently across the
    /// two consumption sites (`migration_job_poll_delay` + the loop
    /// body). Sibling of `test_shinka_migration_poll_backoff_policy_shape`
    /// at `commands/migrations.rs::tests` (commit b962db5).
    #[test]
    fn test_migration_job_poll_backoff_policy_shape() {
        assert_eq!(
            MIGRATION_JOB_POLL_BACKOFF.initial_backoff,
            Duration::from_secs(2),
            "MIGRATION_JOB_POLL_BACKOFF.initial_backoff must be 2s \
             — preserves the pre-lift bare `sleep(Duration::from_secs(2))` \
             seed verbatim at the poll loop's first sleep.",
        );
        assert_eq!(
            MIGRATION_JOB_POLL_BACKOFF.factor, 2,
            "MIGRATION_JOB_POLL_BACKOFF.factor must be 2 \
             — the Bazel/Buck2/SLSA-frontier reference doubling climb \
             the sibling `RetryPolicy::network()` factory also emits.",
        );
        assert_eq!(
            MIGRATION_JOB_POLL_BACKOFF.max_backoff,
            Duration::from_secs(30),
            "MIGRATION_JOB_POLL_BACKOFF.max_backoff must be 30s \
             — the Bazel/Buck2/SLSA-frontier 30s cap the sibling \
             `RetryPolicy::network()` factory also emits.",
        );
    }

    /// Pre-lift the poll loop emitted a flat `sleep(Duration::from_secs(2))`
    /// at every non-terminal iteration. Post-lift the first iteration
    /// preserves that 2s seed verbatim (`migration_job_poll_delay(0) ==
    /// 2s`); every later iteration strictly diverges upward under the
    /// exponential-with-cap climb (`4s → 8s → 16s → 30s → …`) rather than
    /// re-emitting the pre-lift `2s` flat.
    #[test]
    fn test_migration_job_poll_delay_matches_pre_lift_seed_and_climbs() {
        assert_eq!(
            migration_job_poll_delay(0),
            Duration::from_secs(2),
            "iter 0 must sleep 2s — matches pre-lift `sleep(Duration::\
             from_secs(2))` seed verbatim.",
        );
        assert_eq!(
            migration_job_poll_delay(1),
            Duration::from_secs(4),
            "iter 1 must sleep 4s — pre-lift stayed flat at 2s; \
             post-lift climbs `initial_backoff * factor = 4s`.",
        );
        assert_eq!(
            migration_job_poll_delay(2),
            Duration::from_secs(8),
            "iter 2 must sleep 8s — pre-lift stayed flat at 2s; \
             post-lift climbs `initial_backoff * factor^2 = 8s`.",
        );
        assert_eq!(
            migration_job_poll_delay(3),
            Duration::from_secs(16),
            "iter 3 must sleep 16s — pre-lift stayed flat at 2s; \
             post-lift climbs `initial_backoff * factor^3 = 16s`.",
        );
    }

    /// Iterations past the cap must all emit `max_backoff = 30s` — pre-lift
    /// stayed flat at 2s at every iteration, so a long-running migration
    /// (say, a 5-minute Databend backfill against the default
    /// [`MigrationService::new`] `timeout: 300s`) would emit ~150 kubectl
    /// probes; post-lift the climb caps at 30s and the same 5-minute window
    /// emits ~13 probes.
    #[test]
    fn test_migration_job_poll_delay_caps_at_max_backoff_past_the_cap() {
        assert_eq!(
            migration_job_poll_delay(4),
            Duration::from_secs(30),
            "iter 4 must sleep 30s (cap) — `initial_backoff * factor^4 \
             = 32s`, clamped to `max_backoff = 30s`.",
        );
        assert_eq!(
            migration_job_poll_delay(5),
            Duration::from_secs(30),
            "iter 5 must sleep 30s (cap).",
        );
        assert_eq!(
            migration_job_poll_delay(50),
            Duration::from_secs(30),
            "iter 50 must sleep 30s (cap) — long-running migrations can \
             poll for minutes past the cap, so beyond-cap iterations must \
             stay at the ceiling rather than drifting upward.",
        );
    }

    /// The poll loop is bounded by wall-clock via
    /// [`MigrationService::timeout`], not by attempt count, so
    /// `backoff_attempt` can in principle reach any `u32` value on a
    /// pathologically-fast poll-arm (a stub kubectl that returns instantly
    /// against a `with_timeout(Duration::MAX)` service). This test pins
    /// that composition: an `attempt == u32::MAX` argument returns a
    /// bounded delay rather than panicking. The `saturating_add(2)` bridge
    /// inside `migration_job_poll_delay` clamps to `u32::MAX`, and
    /// [`RetryPolicy::compute_delay`]'s `checked_pow`-then-cap body itself
    /// saturates to `max_backoff` without panic.
    #[test]
    fn test_migration_job_poll_delay_saturates_without_panic_at_arbitrarily_large_attempt() {
        assert_eq!(
            migration_job_poll_delay(u32::MAX),
            Duration::from_secs(30),
            "attempt=u32::MAX must saturate to max_backoff without panic \
             — the `saturating_add(2)` bridge + `RetryPolicy::compute_\
             delay`'s `checked_pow` cap close the u32 overflow class by \
             construction.",
        );
        assert_eq!(
            migration_job_poll_delay(u32::MAX - 1),
            Duration::from_secs(30),
            "attempt=u32::MAX - 1 must also saturate to max_backoff — \
             the bridge `saturating_add(2)` returns u32::MAX, still far \
             past the cap.",
        );
    }

    /// The `(factor, max_backoff)` pair of `MIGRATION_JOB_POLL_BACKOFF`
    /// matches the Bazel/Buck2/SLSA-frontier reference schedule the retry
    /// module cites at [`RetryPolicy::network`]'s docstring. The k8s-Job
    /// poll policy diverges only at `initial_backoff` (2s vs 250ms) to
    /// preserve the pre-lift `sleep(Duration::from_secs(2))` seed
    /// verbatim. Pin the shared invariants so a future refinement to the
    /// retry module's reference schedule surfaces the intentional
    /// k8s-Job-side divergence as a named test failure rather than
    /// silently propagating. Sibling of
    /// `test_shinka_migration_poll_backoff_shares_network_factor_and_cap`
    /// at `commands/migrations.rs::tests` (commit b962db5).
    #[test]
    fn test_migration_job_poll_backoff_shares_network_factor_and_cap() {
        let network = RetryPolicy::network();
        assert_eq!(
            MIGRATION_JOB_POLL_BACKOFF.factor, network.factor,
            "MIGRATION_JOB_POLL_BACKOFF.factor must match \
             RetryPolicy::network().factor — both consume the \
             Bazel/Buck2/SLSA-frontier factor=2 reference.",
        );
        assert_eq!(
            MIGRATION_JOB_POLL_BACKOFF.max_backoff, network.max_backoff,
            "MIGRATION_JOB_POLL_BACKOFF.max_backoff must match \
             RetryPolicy::network().max_backoff — both consume the \
             Bazel/Buck2/SLSA-frontier 30s cap reference.",
        );
    }

    /// The k8s-Job status-poll loop body MUST consume the typed primitive
    /// at `migration_job_poll_delay(backoff_attempt)` rather than the
    /// pre-lift bare `sleep(Duration::from_secs(2))` literal. A future
    /// refactor that reintroduces the fixed-literal shape (see
    /// `MIGRATION_JOB_POLL_BACKOFF`'s docstring for the three structural
    /// defects the lift closed) fails here, not silently in production
    /// where a long-running migration would resume flooding the k8s API
    /// with ~150 probes over its 5-minute window. Whole-module boundary
    /// discipline sibling of
    /// `test_wait_for_shinka_migration_consumes_typed_poll_delay_not_mut_backoff_secs`
    /// at `commands/migrations.rs::tests` (commit b962db5).
    ///
    /// Uses the [`crate::test_support::code_line_hits`] helper so the
    /// shield does not false-positive on `MIGRATION_JOB_POLL_BACKOFF`'s
    /// own docstring above (which cites the pre-lift shape as context
    /// for the three defects it forecloses). The forbidden literal is
    /// reconstructed at test time via [`format!`] and the diagnostic
    /// prose refers to it only via the reconstructed `bespoke_needle`
    /// (never the fused literal), so the assert message body itself stays
    /// unmatchable — same code-line-filter-plus-format-reconstruction
    /// discipline sibling shields 4163c7e / ffa5271 / fa2c702 / a7d5375 /
    /// ab06395 use.
    ///
    /// The scan is bounded strictly to the pre-tests module body — from
    /// the module start through the `#[cfg(test)]\nmod tests {` marker —
    /// so this shield's own docstring mention of `sleep(Duration::from_\
    /// secs(2))` (which lives inside this `#[cfg(test)] mod tests` block
    /// below that marker) stays out of scope AND every current or future
    /// sleep-emitting helper landing anywhere in the top-level module
    /// body cannot silently ride along without going through the
    /// primitive.
    #[test]
    fn test_wait_for_job_consumes_typed_poll_delay_not_bare_fixed_sleep() {
        let source = include_str!("migration_service.rs");
        let tests_marker = "\n#[cfg(test)]\nmod tests {";
        let body_end = source.find(tests_marker).expect(
            "the `#[cfg(test)]\\nmod tests {` marker must follow \
             the module body — the shield's slice boundary relies \
             on this module ordering",
        );
        let module_body = &source[..body_end];

        let bespoke_needle = format!(
            "sleep(Duration::from_secs({}))",
            MIGRATION_JOB_POLL_BACKOFF.initial_backoff.as_secs(),
        );
        let bespoke_hits = crate::test_support::code_line_hits(module_body, &bespoke_needle);
        assert!(
            bespoke_hits.is_empty(),
            "migration_service.rs must NOT re-fuse the pre-lift bare \
             fixed sleep at the poll loop — the schedule lives at \
             `MIGRATION_JOB_POLL_BACKOFF` + `migration_job_poll_delay`, \
             both grounding through `RetryPolicy::compute_delay`. Found \
             code-line hits: {:#?}",
            bespoke_hits,
        );
        let delegation_hits = crate::test_support::code_line_hits(
            module_body,
            "migration_job_poll_delay(backoff_attempt)",
        );
        assert!(
            !delegation_hits.is_empty(),
            "migration_service.rs must consume the typed poll-delay \
             helper at the poll loop's sleep site — the canonical \
             delegation call was not found at any code line.",
        );
    }

    /// Shield: every `kubectl` spawn inside `impl MigrationService`
    /// routes through `kubectl_command_async()` rather than the
    /// pre-lift `Command::new("kubectl")` literal. Pre-migration five
    /// sites (delete-existing-job, apply-job manifest, wait-for-job
    /// Complete probe, wait-for-job Failed probe, get-job-logs) each
    /// spelled the bare `Command::new("kubectl")` shape verbatim and
    /// thereby bypassed the `KUBECTL_BIN` env override the tools-
    /// registry idiom (`crate::tools::get_tool_path(tools::KUBECTL)`,
    /// cli/src/tools.rs:102-105) resolves — the same class of bug the
    /// sibling `flux` / `cargo` / `doca` / free-function-`git` /
    /// `GitClient` / `commands/federation.rs` / `commands/push.rs` /
    /// `commands/rollback.rs` / `commands/helm.rs` /
    /// `commands/product_release.rs::run_health_check` /
    /// `commands/github_runner_ci.rs::execute` migrations redeemed at
    /// 621f827 / f0dfa12 / d3dd199 / 685642f / d6f6bc7 / dd5a212 /
    /// 673e4be / b02d4eb / 54a9985 / 139b37a / 818ed9a / badcdf4 /
    /// 8653403 / f6be190 / 8a1958e / 81d7486 / 0d922f6 / 82376e1 /
    /// 34661e3 / 5bb7cff / 5566415.
    ///
    /// This test reads the module's own source via [`include_str!`]
    /// and asserts the raw `Command::new("kubectl")` string does not
    /// reappear inside the `impl MigrationService` block while the
    /// delegation to `kubectl_command_async()` does. A future
    /// regression that re-fuses the raw-spawn body fails here, not
    /// silently in production where a Nix-hermetic runner's
    /// `KUBECTL_BIN`-provided `kubectl` would lose to whatever
    /// `kubectl` is first on `PATH` at migration-job invocation time.
    ///
    /// The check is deliberately structural (substring on the source
    /// text) rather than behavioral — the end-to-end
    /// `KUBECTL_BIN`-routing invariant is already pinned by
    /// [`crate::infrastructure::kubectl::tests::test_kubectl_command_async_routes_through_kubectl_bin_env_var`]
    /// on the primitive itself; this shield only certifies that
    /// every `MigrationService` method reads through that primitive.
    ///
    /// The scan is bounded strictly to the `impl MigrationService`
    /// block — from `impl MigrationService {` through its closing
    /// `\n}\n` — so this shield's own docstring mention of
    /// `Command::new("kubectl")` (which lives inside the sibling
    /// `#[cfg(test)] mod tests` block) stays out of scope. Mirrors
    /// the sibling shields on
    /// `commands/product_release.rs::run_health_check` (5bb7cff) and
    /// `commands/github_runner_ci.rs::execute` (5566415).
    #[test]
    fn test_migration_service_routes_kubectl_through_kubectl_command_async_not_raw_command() {
        let source = include_str!("migration_service.rs");
        let impl_marker = "impl MigrationService {";
        let impl_start = source
            .find(impl_marker)
            .expect("`impl MigrationService {` must be present in this module's source");
        // Bound at the closing brace of the impl block. Using the
        // `\n}\n\nimpl Default for MigrationService` marker keeps the
        // slice strictly to the primary impl block, so a future
        // kubectl-spawning helper landing in the `impl Default` block
        // or the `#[cfg(test)] mod tests` block cannot silently ride
        // along without its own shield.
        let end_marker = "\n}\n\nimpl Default for MigrationService";
        let impl_end = source[impl_start..]
            .find(end_marker)
            .map(|i| impl_start + i)
            .expect(
                "the `\\n}\\n\\nimpl Default for MigrationService` marker \
                 must follow the primary impl block — the shield's slice \
                 boundary relies on this module ordering",
            );
        let impl_body = &source[impl_start..impl_end];

        assert!(
            !impl_body.contains("Command::new(\"kubectl\")"),
            "MigrationService methods must NOT spawn `kubectl` directly \
             — route through \
             `crate::infrastructure::kubectl::kubectl_command_async()` \
             so `KUBECTL_BIN` overrides land at the shared primitive. \
             Found the pre-migration spawn body inside impl MigrationService."
        );
        assert!(
            impl_body.contains("kubectl_command_async()"),
            "MigrationService methods must delegate every kubectl spawn \
             to `kubectl_command_async()` — the delegation string was \
             not found in impl MigrationService."
        );
    }
}
