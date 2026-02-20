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
        let output = tokio::process::Command::new("kubectl")
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

        let mut child = tokio::process::Command::new("kubectl")
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

            let output = tokio::process::Command::new("kubectl")
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
            let output = tokio::process::Command::new("kubectl")
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
        let output = tokio::process::Command::new("kubectl")
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
}
