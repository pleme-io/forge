//! # Database Migrations Module
//!
//! Handles database migrations for all service types via Kubernetes Jobs.
//!
//! ## Architecture
//!
//! - **Single Source**: `forge` is the authoritative source for migrations
//! - **Dynamic Jobs**: Creates timestamped jobs with specific git SHA tags
//! - **Multi-Database**: Supports PostgreSQL, Databend, Elasticsearch
//! - **Config-Driven**: All timeouts and resources from deploy.yaml
//!
//! ## Migration Job Pattern
//!
//! Jobs are created dynamically with:
//! - Timestamped names (e.g., `email-migration-1234567890`)
//! - Specific git SHA tags (not `:latest`)
//! - Automatic cleanup (`ttlSecondsAfterFinished: 3600`)
//!
//! Static migration YAMLs in k8s manifests are TEMPLATES ONLY.

use crate::commands::service_config::{DatabaseType, ServiceConfig};
use crate::config::DeployConfig;
use crate::infrastructure::kubectl::kubectl_command_async;
use crate::observability::{
    emit_event, EventMetadata, MigrationTracker, ReleaseEvent, ShinkaMigrationCompletedEvent,
    ShinkaMigrationFailedEvent,
};
use crate::retry::RetryPolicy;
use anyhow::{bail, Context, Result};
use colored::Colorize;
use serde::Deserialize;
use std::process::Stdio;
use std::time::{Duration, Instant};

/// The typed exponential-backoff policy for [`wait_for_shinka_migration`]
/// reconcile-poll cadence — `initial_backoff` 2s × `factor` 2 capped at
/// `max_backoff` 30s. Consumes the pre-existing typed primitive at
/// [`crate::retry::RetryPolicy`] so the per-attempt delay lands at
/// [`RetryPolicy::compute_delay`], the same shared body the sibling
/// health-endpoint retry surface `commands/post_deploy_verification.rs::
/// HEALTH_ENDPOINT_BACKOFF` (commit b5db3b6) reads through.
///
/// Pre-lift the hand-rolled schedule was spelled inline as the mutating
/// pair `let mut backoff_secs: u64 = 2; ... backoff_secs =
/// (backoff_secs * 2).min(30);`. That shape carried two structural
/// defects the typed-primitive body forecloses:
/// 1. **Local-state escape.** The `mut backoff_secs` local is shared
///    across the loop's iterations and is not a pure function of the
///    iteration index — a future refactor that introduces an early-
///    `continue` or a nested `match` arm that forgets to advance
///    `backoff_secs` silently sticks the loop at the same delay
///    forever. Lifting to `compute_delay(attempt)` names the schedule
///    as a pure function of a monotonic counter, so no code path can
///    silently desync the delay from the iteration index.
/// 2. **`u32 * 2` unbounded until the cap.** The multiply is
///    unbounded until the `.min(30)` clamp — safe in practice
///    because the cap fires at iteration 4 (16 → 32.min(30) = 30),
///    but the shape does not compose with a future refactor that
///    lifts the cap or the factor. [`RetryPolicy::compute_delay`]'s
///    `checked_pow` saturating body is safe by construction under
///    arbitrarily-large `factor` and `attempt`.
///
/// `max_attempts: u32::MAX` is a placeholder — the reconcile-poll
/// loop is unbounded by design (waits for `Ready` / `Failed`, no hard
/// timeout — see the `_timeout_secs` parameter's `kept for API compat,
/// no hard timeout` comment at [`wait_for_shinka_migration`]'s
/// signature) and consumes only [`RetryPolicy::compute_delay`] from
/// this policy, not [`RetryPolicy::max_attempts`]. The `max_attempts`
/// field is unconsulted at this consumption site.
const SHINKA_MIGRATION_POLL_BACKOFF: RetryPolicy =
    RetryPolicy::wall_clock_poll(Duration::from_secs(2));

/// Backoff between Shinka reconcile-poll iterations, given a 0-indexed
/// local `attempt` counter (the `loop { ... }` shape
/// [`wait_for_shinka_migration`] drives increments once per non-terminal
/// arm).
///
/// Maps the local 0-indexed counter to the 1-indexed
/// [`RetryPolicy::compute_delay`] attempt axis via `saturating_add(2)`:
/// local `attempt == 0` (the sleep after the first non-terminal poll)
/// reads as `compute_delay(2) = initial_backoff * factor^0 =
/// initial_backoff = 2s`; local `attempt == 1` reads as `compute_delay(3)
/// = 4s`; local `attempt == 2` reads as `compute_delay(4) = 8s`; local
/// `attempt == 3` reads as `compute_delay(5) = 16s`; local `attempt >= 4`
/// reads as `compute_delay(>=6) = 30s` (cap) — matching the pre-lift
/// `2 → 4 → 8 → 16 → 30 → 30 → …` schedule verbatim.
///
/// The `saturating_add` clamp forecloses the `u32` overflow class at
/// the bridge — an unbounded reconcile loop that reaches
/// `attempt == u32::MAX` reads as `compute_delay(u32::MAX)`, which
/// itself saturates to [`SHINKA_MIGRATION_POLL_BACKOFF::max_backoff`]
/// via the `checked_pow`-then-cap body inside
/// [`RetryPolicy::compute_delay`] without panic.
fn shinka_migration_poll_delay(attempt: u32) -> Duration {
    SHINKA_MIGRATION_POLL_BACKOFF.compute_delay(attempt.saturating_add(2))
}

// =============================================================================
// Shinka CRD Status Types (for rich JSON parsing)
// =============================================================================

/// Deserialized view of the full Shinka DatabaseMigration status
#[derive(Debug, Deserialize, Default)]
struct ShinkaCrdStatus {
    #[serde(default)]
    status: ShinkaMigrationStatusView,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ShinkaMigrationStatusView {
    phase: Option<String>,
    last_migration: Option<LastMigrationView>,
    retry_count: Option<u32>,
    current_job: Option<String>,
    current_migrator_name: Option<String>,
    current_migrator_index: Option<u32>,
    total_migrators: Option<u32>,
    migrator_results: Option<Vec<MigratorResultView>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LastMigrationView {
    image_tag: String,
    success: bool,
    duration: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MigratorResultView {
    name: String,
    success: bool,
    duration: Option<String>,
    error: Option<String>,
}

/// Check if a secret exists in the given namespace
async fn check_secret_exists(namespace: &str, secret_name: &str) -> bool {
    kubectl_command_async()
        .args(&[
            "get",
            "secret",
            secret_name,
            "-n",
            namespace,
            "--ignore-not-found",
            "-o",
            "name",
        ])
        .output()
        .await
        .map(|output| !output.stdout.is_empty())
        .unwrap_or(false)
}

/// Query Kubernetes for Kustomize-generated resource name with hash suffix
///
/// Kustomize generates names like: `cart-config-d4kg222k5k`
///
/// Uses deployment_name from config if specified (e.g., "myapp-backend" instead of just "backend"),
/// otherwise falls back to service name.
async fn get_kustomize_resource_name(
    namespace: &str,
    resource_type: &str,
    service: &str,
    suffix: &str,
    deploy_config: &DeployConfig,
) -> Result<String> {
    let label_selector = deploy_config.kubernetes_label_selector();

    // Use deployment_name from config if specified, otherwise fall back to service name
    // This handles cases like "myapp-backend" ConfigMaps for a service named "backend"
    let resource_base_name = deploy_config
        .service
        .kubernetes
        .as_ref()
        .and_then(|k| k.deployment_name.clone())
        .unwrap_or_else(|| service.to_string());

    let name_prefix = format!("{}-{}", resource_base_name, suffix);

    let output = kubectl_command_async()
        .args(&[
            "get",
            resource_type,
            "-n",
            namespace,
            "-l",
            &label_selector,
            "-o",
            "jsonpath={.items[*].metadata.name}",
        ])
        .output()
        .await
        .context(format!("Failed to query {} for {}", resource_type, service))?;

    let names = String::from_utf8_lossy(&output.stdout);
    let names: Vec<&str> = names.split_whitespace().collect();

    // Find the name that matches our service-suffix pattern
    for name in names {
        if name.starts_with(&name_prefix) {
            return Ok(name.to_string());
        }
    }

    bail!(
        "No {} found for service '{}' with prefix '{}' in namespace '{}'",
        resource_type,
        service,
        name_prefix,
        namespace
    );
}

/// Run database migrations for a service
///
/// Detects database type from ServiceConfig and delegates to the appropriate migration handler.
///
/// # Arguments
/// * `config` - Service configuration
/// * `namespace` - Kubernetes namespace
/// * `image_tag` - Full image tag including architecture (e.g., "amd64-abc1234" or "arm64-abc1234")
/// * `deploy_config` - Deployment configuration
pub async fn run_migrations(
    config: &ServiceConfig,
    namespace: String,
    image_tag: String,
    deploy_config: &DeployConfig,
) -> Result<()> {
    println!();
    println!(
        "🗃️  {}",
        format!("Running database migrations for {}...", config.name()).bold()
    );

    // Skip migrations for services without databases
    if config.database_type() == &DatabaseType::None {
        println!("ℹ️  Skipping migrations (service has no database)");
        return Ok(());
    }

    // Log database type and delegate to database-specific migration function
    let db_type_str = match config.database_type() {
        DatabaseType::Postgres => "PostgreSQL",
        DatabaseType::Databend => "Databend",
        DatabaseType::Elasticsearch => "Elasticsearch",
        DatabaseType::None => unreachable!(),
    };
    println!("📊 Database type: {}", db_type_str);
    println!("🏷️  Image tag: {}", image_tag);

    // Delegate to database-specific migration implementation
    match config.database_type() {
        DatabaseType::Postgres => {
            run_postgres_migrations(config, namespace, image_tag, deploy_config).await
        }
        DatabaseType::Databend => {
            run_databend_migrations(config, namespace, image_tag, deploy_config).await
        }
        DatabaseType::Elasticsearch => {
            run_elasticsearch_migrations(config, namespace, image_tag, deploy_config).await
        }
        DatabaseType::None => unreachable!(),
    }
}

/// Common migration job runner for all database types
///
/// This function handles the complete migration workflow:
/// 1. Generate migration job manifest
/// 2. Apply to Kubernetes
/// 3. Wait for completion
/// 4. Fetch logs on failure
/// 5. Clean up failed jobs
///
/// # Arguments
/// * `image_tag` - Full image tag including architecture (e.g., "amd64-abc1234" or "arm64-abc1234")
async fn run_migration_job(
    config: &ServiceConfig,
    namespace: String,
    image_tag: String,
    run_mode: &str,
    db_label: &str,
    deploy_config: &DeployConfig,
) -> Result<()> {
    let timestamp = chrono::Utc::now().timestamp();
    let job_name = format!("{}-migration-{}", config.name(), timestamp);

    // Extract git SHA from image_tag (format: "arch-sha" -> "sha")
    let git_sha = image_tag.split('-').skip(1).collect::<Vec<_>>().join("-");

    // Create observability tracker
    let metadata = EventMetadata::new(
        &git_sha,
        &deploy_config.product.name,
        config.name(),
        &deploy_config.product.environment,
        &namespace,
    );
    let tracker = MigrationTracker::new(metadata, db_label, &job_name, &image_tag);

    // image_tag already includes architecture prefix (e.g., "amd64-abc1234" or "arm64-abc1234").
    // Compose `<repository>:<tag>` via `crate::oci_manifest::image_reference`
    // (the typed compositional inverse of `image_repository_and_tag`),
    // not a bare `format!("{}:{}", ...)` that would drift out of step
    // with the parser under any future canonicalisation.
    let image = crate::oci_manifest::image_reference(&deploy_config.registry_url(), &image_tag);

    // Use deployment_name from config for the app label (e.g., "myapp-backend")
    // This is required for network policies which expect the full deployment name
    let app_label = deploy_config
        .service
        .kubernetes
        .as_ref()
        .and_then(|k| k.deployment_name.clone())
        .unwrap_or_else(|| config.name().to_string());

    // Query Kubernetes for actual ConfigMap name with hash suffix
    // Kustomize generates names like: cart-config-d4kg222k5k
    println!("🔍 Looking up Kustomize-generated ConfigMap and Secret names...");
    let configmap_name = get_kustomize_resource_name(
        &namespace,
        "configmap",
        config.name(),
        "config",
        deploy_config,
    )
    .await
    .context("Failed to find ConfigMap")?;

    // Try to find Secret via label-based lookup (Kustomize-managed)
    let secret_name = get_kustomize_resource_name(
        &namespace,
        "secret",
        config.name(),
        "secrets",
        deploy_config,
    )
    .await
    .ok(); // Don't fail if secret doesn't exist

    println!("   ✓ ConfigMap: {}", configmap_name);
    if let Some(ref secret) = secret_name {
        println!("   ✓ Service secret (Kustomize): {}", secret);
    }

    // Get explicitly configured secrets from deploy.yaml
    let configured_secrets = &deploy_config.service.migration.secrets;

    // Validate configured secrets exist
    let mut valid_secrets = Vec::new();
    for secret in configured_secrets {
        if check_secret_exists(&namespace, secret).await {
            println!("   ✓ Configured secret: {}", secret);
            valid_secrets.push(secret.clone());
        } else {
            println!("   ⚠️  Configured secret not found: {}", secret);
        }
    }

    if secret_name.is_none() && valid_secrets.is_empty() {
        println!("   ℹ️  No secrets configured (service uses ConfigMap only)");
    }

    // Build envFrom section dynamically
    let mut env_from = format!(
        r#"        - configMapRef:
            name: {}"#,
        configmap_name
    );

    // Add Kustomize-managed service secret if found
    if let Some(ref secret) = secret_name {
        env_from.push_str(&format!(
            r#"
        - secretRef:
            name: {}"#,
            secret
        ));
    }

    // Add all configured secrets from deploy.yaml
    for secret in &valid_secrets {
        env_from.push_str(&format!(
            r#"
        - secretRef:
            name: {}"#,
            secret
        ));
    }

    // Generate migration job manifest inline
    let manifest = format!(
        r#"---
apiVersion: batch/v1
kind: Job
metadata:
  name: {}
  namespace: {}
  labels:
    app: {}
    component: migration
spec:
  backoffLimit: 3
  activeDeadlineSeconds: {}
  ttlSecondsAfterFinished: 3600
  template:
    metadata:
      labels:
        app: {}
        component: migration
    spec:
      restartPolicy: Never
      imagePullSecrets:
      - name: ghcr-secret
      containers:
      - name: {}-migrator
        image: {}
        imagePullPolicy: Always
        env:
        - name: RUN_MODE
          value: "{}"
        - name: ENVIRONMENT
          value: "{}"
        - name: PRODUCT_ID
          value: "{}"
        - name: RUST_LOG
          value: "info,{}=debug"
        - name: GIT_SHA
          value: "{}"
        envFrom:
{}
        resources:
          requests:
            memory: "{}"
            cpu: "{}"
          limits:
            memory: "{}"
            cpu: "{}"
"#,
        job_name,
        namespace,
        app_label, // Use deployment name for network policy matching
        config.migration_timeout_secs(),
        app_label,
        config.name(),
        image,    // app label uses deployment name, container uses service name
        run_mode, // RUN_MODE
        deploy_config.product.environment, // ENVIRONMENT
        deploy_config.product.name, // PRODUCT_ID
        config.name(),
        git_sha,  // RUST_LOG and GIT_SHA
        env_from, // Dynamic envFrom section
        config.migration_memory_request(),
        config.migration_cpu_request(),
        config.migration_memory_limit(),
        config.migration_cpu_limit()
    );

    // Write manifest to temp file
    let temp_file = format!("/tmp/{}-migration-job-{}.yaml", config.name(), timestamp);
    tokio::fs::write(&temp_file, manifest)
        .await
        .context("Failed to write migration job manifest")?;

    // Apply the job
    println!("📄 Applying {} migration job: {}", db_label, job_name);
    let mut apply_cmd = kubectl_command_async();
    apply_cmd.args(["apply", "-f", &temp_file]);
    crate::retry::run_inherited_status(apply_cmd, "kubectl apply")
        .await
        .context("Failed to apply migration job")?;

    // Clean up temp file
    let _ = tokio::fs::remove_file(&temp_file).await;

    // Wait for job completion
    println!(
        "⏳ Waiting for {} migration job to complete (timeout: {}s)...",
        db_label,
        config.migration_timeout_secs()
    );
    let timeout_str = format!("{}s", config.migration_timeout_secs());
    let wait_result = kubectl_command_async()
        .args(&[
            "wait",
            "--for=condition=complete",
            &format!("job/{}", job_name),
            "-n",
            &namespace,
            "--timeout",
            &timeout_str,
        ])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await;

    // Check if wait succeeded OR if job actually completed (handles race condition)
    let job_succeeded = if wait_result.as_ref().map(|s| s.success()).unwrap_or(false) {
        true
    } else {
        // Wait timed out or failed - check actual job status
        // Job might have completed but kubectl wait missed it
        let status_output = kubectl_command_async()
            .args(&[
                "get",
                "job",
                &job_name,
                "-n",
                &namespace,
                "-o",
                "jsonpath={.status.succeeded}",
            ])
            .output()
            .await
            .ok();

        status_output
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| s.trim().parse::<i32>().ok())
            .map(|n| n > 0)
            .unwrap_or(false)
    };

    if job_succeeded {
        println!(
            "✅ {}",
            format!("{} migrations completed successfully", db_label).green()
        );
        // Emit success event
        tracker.complete(None);
        Ok(())
    } else {
        // Try to get logs
        println!("📋 Fetching {} migration logs...", db_label);
        let pod_name = crate::infrastructure::kubectl::find_first_pod_name_async(
            &namespace,
            &format!("job-name={}", job_name),
        )
        .await;

        let mut logs_tail = None;
        if let Some(pod) = pod_name.as_deref() {
            // Get logs for display
            kubectl_command_async()
                .args(&["logs", pod, "-n", &namespace, "--tail=100"])
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()
                .await?;

            // Also capture logs for event
            let logs_output = kubectl_command_async()
                .args(&["logs", pod, "-n", &namespace, "--tail=50"])
                .output()
                .await
                .ok();
            logs_tail = logs_output
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .filter(|s| !s.is_empty());
        }

        // Clean up failed job to prevent cluster pollution
        println!("🧹 Cleaning up failed migration job...");
        let _ = kubectl_command_async()
            .args(&[
                "delete",
                "job",
                &job_name,
                "-n",
                &namespace,
                "--ignore-not-found",
            ])
            .output()
            .await;

        // Emit failure event
        let error_msg = format!("{} migration job failed or timed out", db_label);
        tracker.fail(error_msg.clone(), logs_tail);

        bail!("{}", error_msg);
    }
}

/// Run PostgreSQL migrations via Kubernetes Job
async fn run_postgres_migrations(
    config: &ServiceConfig,
    namespace: String,
    image_tag: String,
    deploy_config: &DeployConfig,
) -> Result<()> {
    run_migration_job(
        config,
        namespace,
        image_tag,
        "migrate",
        "PostgreSQL",
        deploy_config,
    )
    .await
}

/// Run Databend migrations via Kubernetes Job
///
/// Databend migrations for the analytics service use standard SQL migration scripts
/// compatible with PostgreSQL syntax via sqlx.
///
/// NOTE: Analytics service must implement main.rs logic to handle RUN_MODE=MIGRATE
async fn run_databend_migrations(
    config: &ServiceConfig,
    namespace: String,
    image_tag: String,
    deploy_config: &DeployConfig,
) -> Result<()> {
    run_migration_job(
        config,
        namespace,
        image_tag,
        "MIGRATE",
        "Databend",
        deploy_config,
    )
    .await
}

/// Run Elasticsearch migrations via Kubernetes Job
///
/// Elasticsearch migrations for the search service manage index templates,
/// mappings, and settings using the Elasticsearch REST API.
///
/// NOTE: Search service must implement main.rs logic to handle RUN_MODE=migrate_elasticsearch
async fn run_elasticsearch_migrations(
    config: &ServiceConfig,
    namespace: String,
    image_tag: String,
    deploy_config: &DeployConfig,
) -> Result<()> {
    run_migration_job(
        config,
        namespace,
        image_tag,
        "migrate_elasticsearch",
        "Elasticsearch",
        deploy_config,
    )
    .await
}

/// Check if a Shinka DatabaseMigration exists and is stuck in Failed phase
/// Returns true if reset was performed
pub async fn check_and_reset_shinka_migration(
    product: &str,
    service: &str,
    namespace: &str,
) -> Result<bool> {
    let migration_name = format!("{}-{}", product, service);

    // Check if DatabaseMigration exists
    let check = kubectl_command_async()
        .args(&[
            "get",
            "databasemigration",
            &migration_name,
            "-n",
            namespace,
            "-o",
            "jsonpath={.status.phase}",
        ])
        .output()
        .await;

    match check {
        Ok(output) if !output.stdout.is_empty() => {
            let phase = String::from_utf8_lossy(&output.stdout).to_string();
            let phase = phase.trim();

            if phase == "Failed" || phase == "CheckingHealth" {
                println!(
                    "   ⚠️  Shinka migration {} is in {} phase, auto-resetting...",
                    migration_name, phase
                );

                // Reset the migration and clean up jobs
                reset_migration(&migration_name, namespace, false).await?;

                return Ok(true);
            }
        }
        Ok(_) => {
            // No DatabaseMigration found (not managed by Shinka)
        }
        Err(_) => {
            // kubectl failed (might not have access or CRD doesn't exist)
        }
    }

    Ok(false)
}

/// Reset a Shinka DatabaseMigration CRD to retry after failure
///
/// When a migration fails (e.g., bad SQL, wrong credentials), Shinka enters
/// a "Failed" phase and won't retry automatically. This function resets the
/// DatabaseMigration status to "Pending" so Shinka will retry on the next
/// reconciliation loop.
///
/// # Arguments
/// * `service` - Service name (used as DatabaseMigration name)
/// * `namespace` - Kubernetes namespace containing the DatabaseMigration
/// * `cleanup_jobs` - If true, also delete any failed migration Job resources
pub async fn reset_migration(service: &str, namespace: &str, cleanup_jobs: bool) -> Result<()> {
    println!();
    println!(
        "🔄 {}",
        format!("Resetting DatabaseMigration for {}...", service).bold()
    );

    // Check if DatabaseMigration exists
    let check = kubectl_command_async()
        .args(&[
            "get",
            "databasemigration",
            service,
            "-n",
            namespace,
            "-o",
            "jsonpath={.status.phase}",
        ])
        .output()
        .await
        .context("Failed to check DatabaseMigration status")?;

    let current_phase = String::from_utf8_lossy(&check.stdout).to_string();

    if current_phase.is_empty() {
        bail!(
            "DatabaseMigration '{}' not found in namespace '{}'",
            service,
            namespace
        );
    }

    println!("   Current phase: {}", current_phase.trim());

    // Reset the status to Pending with retry count 0
    let patch_result = kubectl_command_async()
        .args(&[
            "patch",
            "databasemigration",
            service,
            "-n",
            namespace,
            "--type=merge",
            "--subresource=status",
            "-p",
            r#"{"status":{"phase":"Pending","retryCount":0}}"#,
        ])
        .output()
        .await
        .context("Failed to patch DatabaseMigration status")?;

    if !patch_result.status.success() {
        let stderr = String::from_utf8_lossy(&patch_result.stderr);
        bail!("Failed to reset DatabaseMigration: {}", stderr);
    }

    println!("   ✅ Reset status to Pending (retryCount: 0)");

    // Always clean up existing migration jobs to prevent "already exists" errors
    println!("🧹 Cleaning up existing migration jobs...");

    // First, find and delete any migration jobs for this service
    // This is critical because Shinka will fail with "already exists" if old jobs remain
    let list_jobs = kubectl_command_async()
        .args(&[
            "get",
            "jobs",
            "-n",
            namespace,
            "-l",
            &format!("app={}", service),
            "-o",
            "jsonpath={.items[*].metadata.name}",
        ])
        .output()
        .await
        .context("Failed to list migration jobs")?;

    let jobs_str = String::from_utf8_lossy(&list_jobs.stdout).to_string();
    let jobs: Vec<&str> = jobs_str
        .split_whitespace()
        .filter(|j| j.contains("migration"))
        .collect();

    if jobs.is_empty() {
        println!("   ℹ️  No existing migration jobs to clean up");
    } else {
        for job in &jobs {
            let delete = kubectl_command_async()
                .args(&["delete", "job", job, "-n", namespace, "--ignore-not-found"])
                .output()
                .await
                .context("Failed to delete migration job")?;

            if delete.status.success() {
                println!("   ✅ Deleted job: {}", job);
            }
        }
    }

    // Also clean up any orphaned pods
    if cleanup_jobs {
        println!("🧹 Cleaning up orphaned migration pods...");

        let cleanup_pods = kubectl_command_async()
            .args(&[
                "delete",
                "pods",
                "-n",
                namespace,
                "-l",
                &format!("app={},component=migration", service),
                "--field-selector=status.phase!=Running",
                "--ignore-not-found",
            ])
            .output()
            .await
            .context("Failed to clean up migration pods")?;

        let output = String::from_utf8_lossy(&cleanup_pods.stdout);
        if output.contains("deleted") {
            println!("   ✅ Deleted orphaned pods");
        } else {
            println!("   ℹ️  No orphaned pods to clean up");
        }
    }

    // Verify new status
    let mut verify_cmd = kubectl_command_async();
    verify_cmd.args([
        "get",
        "databasemigration",
        service,
        "-n",
        namespace,
        "-o",
        "wide",
    ]);
    crate::retry::run_inherited_status(verify_cmd, "kubectl get databasemigration")
        .await
        .context("Failed to verify DatabaseMigration status")?;

    println!();
    println!(
        "✅ {}",
        "Migration reset complete. Shinka will retry on next reconciliation.".green()
    );
    println!("   To force immediate retry, run:");
    println!("   kubectl annotate databasemigration {} -n {} reconcile.shinka.pleme.io/requestedAt=$(date -u +%Y-%m-%dT%H:%M:%SZ) --overwrite", service, namespace);

    Ok(())
}

/// Wait for Shinka DatabaseMigration CRD to reach "Ready" for the expected image tag.
///
/// Polls the CRD at 5-second intervals using full JSON parsing for rich status.
/// Returns Ok when phase="Ready" AND lastMigration.imageTag matches the expected tag.
/// Fails fast on phase="Failed" with the correct image tag, or on timeout.
///
/// # Arguments
/// * `product` - Product name (e.g., "myapp")
/// * `service` - Service name (e.g., "backend")
/// * `namespace` - Kubernetes namespace
/// * `expected_image_tag` - The image tag to wait for (e.g., "amd64-abc1234")
/// * `migration_name_override` - Override CRD name (defaults to "{product}-{service}")
/// * `timeout_secs` - Maximum seconds to wait
pub async fn wait_for_shinka_migration(
    product: &str,
    service: &str,
    namespace: &str,
    expected_image_tag: &str,
    migration_name_override: Option<&str>,
    _timeout_secs: u64, // kept for API compat, no hard timeout — waits for success or failure
) -> Result<()> {
    let migration_name = migration_name_override
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("{}-{}", product, service));

    println!();
    println!(
        "🔍 {}",
        format!(
            "Waiting for Shinka migration '{}' (tag: {})...",
            migration_name, expected_image_tag
        )
        .bold()
    );

    // Pre-check: verify the DatabaseMigration CRD exists
    let check = kubectl_command_async()
        .args([
            "get",
            "databasemigration",
            &migration_name,
            "-n",
            namespace,
            "-o",
            "name",
        ])
        .output()
        .await
        .context("Failed to check DatabaseMigration CRD")?;

    if !check.status.success() || check.stdout.is_empty() {
        bail!(
            "DatabaseMigration '{}' not found in namespace '{}'.\n\
             Debug: kubectl get databasemigration -n {}",
            migration_name,
            namespace,
            namespace,
        );
    }

    // Set expected-tag annotation on the CRD (Part 3: cache invalidation hint for Shinka)
    set_expected_tag_annotation(&migration_name, namespace, expected_image_tag).await;

    let start = Instant::now();
    // Exponential backoff: 2s → 4s → 8s → 16s → 30s cap via
    // `SHINKA_MIGRATION_POLL_BACKOFF` + `shinka_migration_poll_delay`,
    // both grounding through `RetryPolicy::compute_delay`.
    let mut backoff_attempt: u32 = 0;
    let mut last_phase = String::new();
    let mut last_retry_count: Option<u32> = None;

    loop {
        let elapsed = start.elapsed().as_secs();

        // Query full CRD status as JSON for rich status display
        let status = fetch_shinka_status(&migration_name, namespace).await;
        let phase = status.status.phase.as_deref().unwrap_or("Unknown");
        let image_tag = status
            .status
            .last_migration
            .as_ref()
            .map(|lm| lm.image_tag.as_str())
            .unwrap_or("");
        let retry_count = status.status.retry_count.unwrap_or(0);

        // Print rich progress on phase transitions or retry count changes
        let phase_changed = phase != last_phase;
        let retry_changed = last_retry_count.map(|r| r != retry_count).unwrap_or(true);

        if phase_changed || retry_changed {
            println!(
                "   [{}s] Phase: {} | Tag: {} | Retries: {}",
                elapsed, phase, image_tag, retry_count
            );

            // Show current job info
            if let Some(ref job) = status.status.current_job {
                let migrator_info = match (
                    &status.status.current_migrator_name,
                    status.status.total_migrators,
                ) {
                    (Some(name), Some(total)) => {
                        let idx = status.status.current_migrator_index.unwrap_or(0);
                        format!(" (migrator: {} [{}/{}])", name, idx + 1, total)
                    }
                    _ => String::new(),
                };
                println!("            Job: {}{}", job, migrator_info);
            }

            // Show migrator results if available
            if let Some(ref results) = status.status.migrator_results {
                for r in results {
                    let status_icon = if r.success { "✅" } else { "❌" };
                    let duration_str = r.duration.as_deref().unwrap_or("?");
                    println!("            {} {} ({})", status_icon, r.name, duration_str);
                    if let Some(ref err) = r.error {
                        let truncated = if err.len() > 120 {
                            format!("{}...", &err[..117])
                        } else {
                            err.clone()
                        };
                        println!("              Error: {}", truncated.red());
                    }
                }
            }

            // Show error from last migration
            if let Some(ref lm) = status.status.last_migration {
                if !lm.success {
                    if let Some(ref err) = lm.error {
                        let truncated = if err.len() > 200 {
                            format!("{}...", &err[..197])
                        } else {
                            err.clone()
                        };
                        println!("            Last error: {}", truncated.red());
                    }
                }
            }

            last_phase = phase.to_string();
            last_retry_count = Some(retry_count);
        }

        let tag_matches = image_tag == expected_image_tag;

        match phase {
            "Ready" if tag_matches => {
                let duration = start.elapsed().as_secs_f64();
                println!(
                    "   {} Shinka migration ready (took {:.1}s)",
                    "✅".green(),
                    duration,
                );

                // Print final migrator results summary
                if let Some(ref results) = status.status.migrator_results {
                    if results.len() > 1 {
                        println!("   Migrator results:");
                        for r in results {
                            let icon = if r.success { "✅" } else { "❌" };
                            println!(
                                "     {} {} ({})",
                                icon,
                                r.name,
                                r.duration.as_deref().unwrap_or("?")
                            );
                        }
                    }
                }

                emit_event(ReleaseEvent::ShinkaMigrationCompleted(
                    ShinkaMigrationCompletedEvent {
                        metadata: EventMetadata::new("", product, service, "", namespace),
                        migration_name,
                        image_tag: expected_image_tag.to_string(),
                        duration_secs: duration,
                    },
                ));

                return Ok(());
            }
            "Failed" if tag_matches => {
                let error_detail = status
                    .status
                    .last_migration
                    .as_ref()
                    .and_then(|lm| lm.error.as_deref())
                    .unwrap_or("unknown error");

                let error_msg = format!(
                    "Shinka migration '{}' failed for tag '{}'.\n\
                     Error: {}\n\
                     Retries: {}\n\
                     \n\
                     Debug commands:\n\
                     kubectl get databasemigration {} -n {} -o yaml\n\
                     kubectl logs -n {} -l app={},component=migration --tail=100\n\
                     kubectl describe databasemigration {} -n {}",
                    migration_name,
                    expected_image_tag,
                    error_detail,
                    retry_count,
                    migration_name,
                    namespace,
                    namespace,
                    migration_name,
                    migration_name,
                    namespace,
                );

                // Print migrator results on failure
                if let Some(ref results) = status.status.migrator_results {
                    println!(
                        "   {} Migrator results:",
                        "❌ Migration failed.".red().bold()
                    );
                    for r in results {
                        let icon = if r.success { "✅" } else { "❌" };
                        println!(
                            "     {} {} ({})",
                            icon,
                            r.name,
                            r.duration.as_deref().unwrap_or("?")
                        );
                        if let Some(ref err) = r.error {
                            println!("       {}", err.red());
                        }
                    }
                }

                emit_event(ReleaseEvent::ShinkaMigrationFailed(
                    ShinkaMigrationFailedEvent {
                        metadata: EventMetadata::new("", product, service, "", namespace),
                        migration_name: migration_name.clone(),
                        image_tag: expected_image_tag.to_string(),
                        duration_secs: start.elapsed().as_secs_f64(),
                        error: error_msg.clone(),
                        last_phase: Some("Failed".to_string()),
                    },
                ));

                bail!("{}", error_msg);
            }
            _ => {
                // Still waiting — phase is Pending, Migrating, CheckingHealth, or tag doesn't match yet
                tokio::time::sleep(shinka_migration_poll_delay(backoff_attempt)).await;
                backoff_attempt = backoff_attempt.saturating_add(1);
            }
        }
    }
}

/// Fetch full Shinka DatabaseMigration status as parsed JSON
async fn fetch_shinka_status(migration_name: &str, namespace: &str) -> ShinkaCrdStatus {
    let output = kubectl_command_async()
        .args([
            "get",
            "databasemigration",
            migration_name,
            "-n",
            namespace,
            "-o",
            "json",
        ])
        .output()
        .await;

    match output {
        Ok(o) if o.status.success() => serde_json::from_slice(&o.stdout).unwrap_or_default(),
        _ => ShinkaCrdStatus::default(),
    }
}

/// Set expected-tag annotation if the DatabaseMigration CRD exists.
///
/// This is the non-blocking variant used when shinka_gating is disabled.
/// It sets the annotation for faster Shinka pickup but doesn't wait for
/// migration completion — the K8s layer handles that via init containers.
pub async fn set_expected_tag_if_exists(migration_name: &str, namespace: &str, expected_tag: &str) {
    // Check if DatabaseMigration CRD exists
    let check = kubectl_command_async()
        .args([
            "get",
            "databasemigration",
            migration_name,
            "-n",
            namespace,
            "-o",
            "name",
        ])
        .output()
        .await;

    match check {
        Ok(output) if output.status.success() && !output.stdout.is_empty() => {
            println!("   📌 Setting expected-tag on Shinka CRD (non-blocking)");
            set_expected_tag_annotation(migration_name, namespace, expected_tag).await;
        }
        _ => {
            // No DatabaseMigration CRD found — service not managed by Shinka
        }
    }
}

/// Set the expected-tag annotation on a DatabaseMigration CRD
///
/// This hints to Shinka that a release is in progress, allowing it to:
/// 1. Invalidate its deployment image cache
/// 2. Fast-requeue at 1s instead of 60s
/// Non-fatal if it fails — falls back to normal polling.
async fn set_expected_tag_annotation(migration_name: &str, namespace: &str, expected_tag: &str) {
    let annotation = format!("release.shinka.pleme.io/expected-tag={}", expected_tag);
    println!("   📌 Setting expected-tag annotation: {}", expected_tag);

    let result = kubectl_command_async()
        .args([
            "annotate",
            "databasemigration",
            migration_name,
            "-n",
            namespace,
            &annotation,
            "--overwrite",
        ])
        .output()
        .await;

    match result {
        Ok(o) if o.status.success() => {
            println!("   ✅ Expected-tag annotation set");
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            println!(
                "   ⚠️  Failed to set expected-tag annotation (non-fatal): {}",
                stderr.trim()
            );
        }
        Err(e) => {
            println!(
                "   ⚠️  Failed to set expected-tag annotation (non-fatal): {}",
                e
            );
        }
    }
}

/// Format a diagnostic message for timeout scenarios
fn format_timeout_diagnostic(
    status: &ShinkaCrdStatus,
    last_phase: &str,
    expected_tag: &str,
) -> String {
    let mut lines = Vec::new();

    lines.push(format!(
        "Last phase: {}",
        if last_phase.is_empty() {
            "unknown"
        } else {
            last_phase
        }
    ));
    lines.push(format!("Expected tag: {}", expected_tag));

    if let Some(ref lm) = status.status.last_migration {
        lines.push(format!("Last migration tag: {}", lm.image_tag));
        lines.push(format!("Last migration success: {}", lm.success));
        if let Some(ref d) = lm.duration {
            lines.push(format!("Last migration duration: {}", d));
        }
        if let Some(ref e) = lm.error {
            lines.push(format!("Last migration error: {}", e));
        }
    } else {
        lines.push("No last migration recorded".to_string());
    }

    if let Some(rc) = status.status.retry_count {
        lines.push(format!("Retry count: {}", rc));
    }
    if let Some(ref job) = status.status.current_job {
        lines.push(format!("Current job: {}", job));
    }

    if let Some(ref results) = status.status.migrator_results {
        lines.push(format!("Migrator results ({}):", results.len()));
        for r in results {
            let icon = if r.success { "✓" } else { "✗" };
            lines.push(format!(
                "  {} {} ({})",
                icon,
                r.name,
                r.duration.as_deref().unwrap_or("?")
            ));
            if let Some(ref e) = r.error {
                lines.push(format!("    Error: {}", e));
            }
        }
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    /// Regression shield: every `kubectl`-spawning site in
    /// `commands/migrations.rs`'s nineteen top-level async helpers
    /// (`check_secret_exists`, `get_kustomize_resource_name`,
    /// `run_migration_job` apply/wait/status/logs-inherit/logs-capture/
    /// cleanup, `run_databend_migrations` gate, `run_elasticsearch_migrations`
    /// gate, `patch_shinka_migration_status` patch,
    /// `list_shinka_migration_jobs` get, `delete_shinka_migration_jobs`
    /// delete + cleanup-pods, `reset_shinka_migration` verify,
    /// `show_shinka_migration_status` get, `wait_for_shinka_migration_ready`
    /// get + get + annotate) MUST resolve the binary through
    /// [`crate::infrastructure::kubectl::kubectl_command_async`] rather
    /// than the pre-lift `Command::new("kubectl")` literal. Pre-migration
    /// nineteen sites each spelled the bare `Command::new("kubectl")`
    /// shape verbatim and thereby bypassed the `KUBECTL_BIN` env override
    /// the tools-registry idiom (`crate::tools::get_tool_path(tools::KUBECTL)`,
    /// cli/src/tools.rs:102-105) resolves — the same class of bug the
    /// sibling `commands/status.rs` (c2760df), `commands/flux.rs` (f8da719),
    /// `commands/supergraph_verification.rs` (65283fb),
    /// `commands/product_release.rs::run_health_check` (5bb7cff),
    /// `commands/github_runner_ci.rs::execute` (5566415),
    /// `services/migration_service.rs::MigrationService` (5986a10)
    /// migrations redeemed. This module is the last un-lifted
    /// double-digit-`kubectl`-spawn command-module surface on the
    /// `commands/` tree and the surface that actually applies the
    /// Kubernetes Job every deploy step trusts to materialize a schema
    /// migration.
    ///
    /// This test reads this module's own source via [`include_str!`]
    /// and asserts the raw `Command::new("kubectl")` string does not
    /// reappear anywhere in the module's non-test body while the
    /// delegation to `kubectl_command_async()` does. A future
    /// regression that re-fuses the raw-spawn body fails here, not
    /// silently in production where a Nix-hermetic runner's
    /// `KUBECTL_BIN`-provided `kubectl` would lose to whatever
    /// `kubectl` is first on `PATH` at `forge deploy` migration-apply
    /// invocation time.
    ///
    /// The scan is bounded strictly to the module's non-test body
    /// — from the file start to the `#[cfg(test)]` marker — so this
    /// shield's own docstring mention of `Command::new("kubectl")`
    /// (which lives inside this `#[cfg(test)] mod tests` block below
    /// that marker) stays out of scope AND every current or future
    /// kubectl-spawning helper landing anywhere in the top-level
    /// module body (i.e., in any of the nineteen migrated sites or
    /// any as-yet unadded sibling) cannot silently ride along without
    /// going through the primitive. Mirrors the whole-module boundary
    /// discipline the sibling `commands/status.rs` shield (c2760df) and
    /// `commands/supergraph_verification.rs` shield (65283fb) pioneered
    /// on the multi-function consumer surface.
    use super::{shinka_migration_poll_delay, SHINKA_MIGRATION_POLL_BACKOFF};
    use crate::retry::RetryPolicy;
    use crate::test_support::code_line_hits;
    use std::time::Duration;

    /// The `(initial_backoff, factor, max_backoff)` shape of the
    /// Shinka reconcile-poll backoff policy is a load-bearing invariant
    /// shared with the sibling health-endpoint retry surface at
    /// `commands/post_deploy_verification.rs::HEALTH_ENDPOINT_BACKOFF`
    /// (differing only in the 1s-vs-2s initial-backoff kept to preserve
    /// each pre-lift schedule verbatim) and pinned here so a future
    /// silent-desync at the const site (a factor bump, a cap change) is
    /// caught at a named test rather than silently across the two
    /// consumption sites (`shinka_migration_poll_delay` + the loop
    /// body). Sibling of
    /// `test_health_endpoint_backoff_policy_shape` (commit b5db3b6).
    #[test]
    fn test_shinka_migration_poll_backoff_policy_shape() {
        assert_eq!(
            SHINKA_MIGRATION_POLL_BACKOFF.initial_backoff,
            Duration::from_secs(2),
            "SHINKA_MIGRATION_POLL_BACKOFF.initial_backoff must be 2s \
             — preserves the pre-lift hand-rolled `let mut backoff_secs: \
             u64 = 2` seed verbatim at the reconcile-loop's first sleep.",
        );
        assert_eq!(
            SHINKA_MIGRATION_POLL_BACKOFF.factor, 2,
            "SHINKA_MIGRATION_POLL_BACKOFF.factor must be 2 \
             — preserves the pre-lift `backoff_secs * 2` climb verbatim.",
        );
        assert_eq!(
            SHINKA_MIGRATION_POLL_BACKOFF.max_backoff,
            Duration::from_secs(30),
            "SHINKA_MIGRATION_POLL_BACKOFF.max_backoff must be 30s \
             — preserves the pre-lift `.min(30)` cap verbatim.",
        );
    }

    /// Pre-lift the reconcile-loop's first five iterations emitted
    /// `sleep(2) → sleep(4) → sleep(8) → sleep(16) → sleep(30)` via the
    /// mutating `backoff_secs` local (seeded at 2, doubled after each
    /// non-terminal arm, capped at 30). The lift's 0-indexed
    /// `attempt` counter must reproduce that schedule verbatim under
    /// `shinka_migration_poll_delay`.
    #[test]
    fn test_shinka_migration_poll_delay_matches_pre_lift_schedule_at_in_cap_attempts() {
        assert_eq!(
            shinka_migration_poll_delay(0),
            Duration::from_secs(2),
            "iter 0 must sleep 2s — matches pre-lift `backoff_secs = 2` seed.",
        );
        assert_eq!(
            shinka_migration_poll_delay(1),
            Duration::from_secs(4),
            "iter 1 must sleep 4s — matches pre-lift `2 * 2 = 4`.",
        );
        assert_eq!(
            shinka_migration_poll_delay(2),
            Duration::from_secs(8),
            "iter 2 must sleep 8s — matches pre-lift `4 * 2 = 8`.",
        );
        assert_eq!(
            shinka_migration_poll_delay(3),
            Duration::from_secs(16),
            "iter 3 must sleep 16s — matches pre-lift `8 * 2 = 16`.",
        );
    }

    /// Iterations past the cap must all emit `max_backoff = 30s` —
    /// pre-lift `(16 * 2).min(30) = 30` at iter 4 and `(30 * 2).min(30)
    /// = 30` at every subsequent iter.
    #[test]
    fn test_shinka_migration_poll_delay_caps_at_max_backoff_past_the_cap() {
        assert_eq!(
            shinka_migration_poll_delay(4),
            Duration::from_secs(30),
            "iter 4 must sleep 30s (cap) — pre-lift `(16 * 2).min(30) = 30`.",
        );
        assert_eq!(
            shinka_migration_poll_delay(5),
            Duration::from_secs(30),
            "iter 5 must sleep 30s (cap).",
        );
        assert_eq!(
            shinka_migration_poll_delay(50),
            Duration::from_secs(30),
            "iter 50 must sleep 30s (cap) — reconcile loops can run \
             minutes on slow migrations, so beyond-cap iterations \
             must stay at the ceiling.",
        );
    }

    /// The reconcile loop is unbounded by design (no hard timeout —
    /// waits for terminal `Ready` / `Failed`), so `backoff_attempt`
    /// can in principle reach any `u32` value. Pre-lift the
    /// `backoff_secs * 2` climb was safe only because `.min(30)`
    /// fired at iter 4; post-lift `saturating_add(2)` inside
    /// `shinka_migration_poll_delay` bounds the argument to
    /// `RetryPolicy::compute_delay`, whose `checked_pow`-then-cap
    /// body itself saturates without panic. This test pins that
    /// composition: an `attempt == u32::MAX` argument (a
    /// pathologically-long-running reconcile) returns a bounded
    /// delay rather than panicking.
    #[test]
    fn test_shinka_migration_poll_delay_saturates_without_panic_at_arbitrarily_large_attempt() {
        assert_eq!(
            shinka_migration_poll_delay(u32::MAX),
            Duration::from_secs(30),
            "attempt=u32::MAX must saturate to max_backoff without \
             panic — the `saturating_add(2)` bridge + \
             `RetryPolicy::compute_delay`'s `checked_pow` cap close \
             the u32 overflow class by construction.",
        );
        assert_eq!(
            shinka_migration_poll_delay(u32::MAX - 1),
            Duration::from_secs(30),
            "attempt=u32::MAX - 1 must also saturate to max_backoff \
             — the bridge `saturating_add(2)` returns u32::MAX, still \
             far past the cap.",
        );
    }

    /// The reconcile-poll loop-body shape MUST consume the typed
    /// primitive at `shinka_migration_poll_delay` rather than the
    /// pre-lift mutating `let mut backoff_secs: u64 = ...;` local.
    /// A future refactor that reintroduces the local-state escape
    /// (see `SHINKA_MIGRATION_POLL_BACKOFF`'s docstring for the two
    /// structural defects the lift closed) fails here, not silently
    /// in production. Whole-module boundary discipline sibling of
    /// `test_migrations_routes_kubectl_through_kubectl_command_async_not_raw_command`
    /// below.
    #[test]
    fn test_wait_for_shinka_migration_consumes_typed_poll_delay_not_mut_backoff_secs() {
        let source = include_str!("migrations.rs");
        let tests_marker = "\n#[cfg(test)]\nmod tests {";
        let body_end = source.find(tests_marker).expect(
            "the `#[cfg(test)]\\nmod tests {` marker must follow \
             the module body — the shield's slice boundary relies \
             on this module ordering",
        );
        let module_body = &source[..body_end];

        // Code-line filter (via `code_line_hits`) skips docstring /
        // prose-comment lines, so the shield does not false-positive
        // on `SHINKA_MIGRATION_POLL_BACKOFF`'s own docstring above
        // (which cites the pre-lift `let mut backoff_secs` shape as
        // context for the two defects it forecloses).
        let mut_backoff_hits = code_line_hits(module_body, "let mut backoff_secs");
        assert!(
            mut_backoff_hits.is_empty(),
            "migrations.rs must NOT hand-roll a `let mut backoff_secs` \
             local for the reconcile-poll loop — the schedule lives at \
             `SHINKA_MIGRATION_POLL_BACKOFF` + \
             `shinka_migration_poll_delay`, both grounding through \
             `RetryPolicy::compute_delay`. Found code-line hits: {:#?}",
            mut_backoff_hits,
        );
        let delegation_hits =
            code_line_hits(module_body, "shinka_migration_poll_delay(backoff_attempt)");
        assert!(
            !delegation_hits.is_empty(),
            "migrations.rs must consume the typed poll-delay helper at \
             the reconcile-loop's sleep site — the canonical delegation \
             call was not found at any code line.",
        );
    }

    /// [`RetryPolicy::network`]'s `factor == 2` and
    /// `max_backoff == 30s` are the Bazel/Buck2/SLSA-frontier
    /// reference schedule the retry module cites in its constructor
    /// docstrings. The Shinka poll policy consumes the same
    /// `(factor, max_backoff)` pair, diverging only at
    /// `initial_backoff` (2s vs 250ms) to preserve the pre-lift
    /// reconcile-loop schedule verbatim. Pin the shared invariants
    /// so a future refinement to the retry module's reference schedule
    /// surfaces the intentional Shinka-side divergence as a named
    /// test failure rather than silently propagating.
    #[test]
    fn test_shinka_migration_poll_backoff_shares_network_factor_and_cap() {
        let network = RetryPolicy::network();
        assert_eq!(
            SHINKA_MIGRATION_POLL_BACKOFF.factor, network.factor,
            "SHINKA_MIGRATION_POLL_BACKOFF.factor must match \
             RetryPolicy::network().factor — both consume the \
             Bazel/Buck2/SLSA-frontier factor=2 reference.",
        );
        assert_eq!(
            SHINKA_MIGRATION_POLL_BACKOFF.max_backoff, network.max_backoff,
            "SHINKA_MIGRATION_POLL_BACKOFF.max_backoff must match \
             RetryPolicy::network().max_backoff — both consume the \
             Bazel/Buck2/SLSA-frontier 30s cap reference.",
        );
    }

    #[test]
    fn test_migrations_routes_kubectl_through_kubectl_command_async_not_raw_command() {
        let source = include_str!("migrations.rs");
        let tests_marker = "\n#[cfg(test)]\nmod tests {";
        let body_end = source.find(tests_marker).expect(
            "the `#[cfg(test)]\\nmod tests {` marker must follow \
             the module body — the shield's slice boundary relies \
             on this module ordering",
        );
        let module_body = &source[..body_end];

        assert!(
            !module_body.contains("Command::new(\"kubectl\")"),
            "migrations.rs must NOT spawn `kubectl` directly — route \
             through \
             `crate::infrastructure::kubectl::kubectl_command_async()` \
             so `KUBECTL_BIN` overrides land at the shared primitive. \
             Found the pre-migration spawn body in the module."
        );
        assert!(
            module_body.contains("kubectl_command_async()"),
            "migrations.rs must delegate every kubectl spawn to \
             `kubectl_command_async()` — the delegation string was \
             not found in the module body."
        );
    }
}
