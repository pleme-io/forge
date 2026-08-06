//! Migration service - runs database migrations
//!
//! Handles running migrations as Kubernetes Jobs with proper monitoring.

use anyhow::{Context, Result};
use std::time::{Duration, Instant};
use tracing::{info, warn};

use crate::domain::migration::{DatabaseType, MigrationConfig, MigrationResult};

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

            tokio::time::sleep(Duration::from_secs(2)).await;
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
