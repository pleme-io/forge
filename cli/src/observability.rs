//! # Release Observability Module
//!
//! Provides structured logging and metrics for release and migration operations.
//!
//! ## Event Flow
//!
//! ```text
//! forge → JSON stdout → Vector → Loki → Grafana
//!       ↘ Pushgateway → Prometheus → Grafana
//! ```
//!
//! ## Components
//!
//! 1. **Structured Events**: JSON logs prefixed with `FORGE_EVENT:` for Vector collection
//! 2. **Prometheus Metrics**: Pushed to Pushgateway for release/migration tracking
//!
//! ## Pushgateway
//!
//! Set `PUSHGATEWAY_URL` environment variable to enable metrics pushing:
//! ```bash
//! export PUSHGATEWAY_URL=http://pushgateway.monitoring.svc.cluster.local:9091
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Instant;

/// Event prefix for Vector to identify structured events
const EVENT_PREFIX: &str = "FORGE_EVENT:";

/// Release event types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event_type")]
pub enum ReleaseEvent {
    /// Release workflow started
    ReleaseStarted(ReleaseStartedEvent),
    /// Release workflow completed
    ReleaseCompleted(ReleaseCompletedEvent),
    /// Release workflow failed
    ReleaseFailed(ReleaseFailedEvent),
    /// Build step completed
    BuildCompleted(BuildCompletedEvent),
    /// Push step completed
    PushCompleted(PushCompletedEvent),
    /// Migration started
    MigrationStarted(MigrationStartedEvent),
    /// Migration completed
    MigrationCompleted(MigrationCompletedEvent),
    /// Migration failed
    MigrationFailed(MigrationFailedEvent),
    /// Deployment step completed
    DeploymentCompleted(DeploymentCompletedEvent),
    /// FluxCD reconciliation triggered
    FluxReconciled(FluxReconciledEvent),
    /// Rollout monitoring event
    RolloutStatus(RolloutStatusEvent),
    /// Shinka migration gating completed
    ShinkaMigrationCompleted(ShinkaMigrationCompletedEvent),
    /// Shinka migration gating failed
    ShinkaMigrationFailed(ShinkaMigrationFailedEvent),
}

/// Common fields for all events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventMetadata {
    /// Timestamp in RFC3339 format
    pub timestamp: String,
    /// Git SHA being deployed
    pub git_sha: String,
    /// Product name
    pub product: String,
    /// Service name
    pub service: String,
    /// Environment (staging, production)
    pub environment: String,
    /// Kubernetes namespace
    pub namespace: String,
    /// Hostname of the machine running the release
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// CI job ID if running in CI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ci_job_id: Option<String>,
}

impl EventMetadata {
    pub fn new(
        git_sha: impl Into<String>,
        product: impl Into<String>,
        service: impl Into<String>,
        environment: impl Into<String>,
        namespace: impl Into<String>,
    ) -> Self {
        Self {
            timestamp: Utc::now().to_rfc3339(),
            git_sha: git_sha.into(),
            product: product.into(),
            service: service.into(),
            environment: environment.into(),
            namespace: namespace.into(),
            hostname: std::env::var("HOSTNAME").ok(),
            ci_job_id: std::env::var("GITHUB_RUN_ID")
                .ok()
                .or_else(|| std::env::var("CI_JOB_ID").ok()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseStartedEvent {
    #[serde(flatten)]
    pub metadata: EventMetadata,
    /// Steps to be executed
    pub steps: Vec<String>,
    /// Whether this is a dry run
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseCompletedEvent {
    #[serde(flatten)]
    pub metadata: EventMetadata,
    /// Total duration in seconds
    pub duration_secs: f64,
    /// Individual step durations
    pub step_durations: Vec<StepDuration>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepDuration {
    pub step: String,
    pub duration_secs: f64,
    pub status: StepStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StepStatus {
    Success,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseFailedEvent {
    #[serde(flatten)]
    pub metadata: EventMetadata,
    /// Duration until failure
    pub duration_secs: f64,
    /// Step that failed
    pub failed_step: String,
    /// Error message
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildCompletedEvent {
    #[serde(flatten)]
    pub metadata: EventMetadata,
    /// Build duration in seconds
    pub duration_secs: f64,
    /// Architecture built (amd64, arm64)
    pub arch: String,
    /// Image size in bytes (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_size_bytes: Option<u64>,
    /// Whether build was cached
    pub cache_hit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushCompletedEvent {
    #[serde(flatten)]
    pub metadata: EventMetadata,
    /// Push duration in seconds
    pub duration_secs: f64,
    /// Registry URL
    pub registry: String,
    /// Tags pushed
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationStartedEvent {
    #[serde(flatten)]
    pub metadata: EventMetadata,
    /// Database type (postgres, databend, elasticsearch)
    pub database_type: String,
    /// Image tag for migration job
    pub image_tag: String,
    /// Kubernetes job name
    pub job_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationCompletedEvent {
    #[serde(flatten)]
    pub metadata: EventMetadata,
    /// Database type
    pub database_type: String,
    /// Migration duration in seconds
    pub duration_secs: f64,
    /// Kubernetes job name
    pub job_name: String,
    /// Number of migrations applied (if known)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub migrations_applied: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationFailedEvent {
    #[serde(flatten)]
    pub metadata: EventMetadata,
    /// Database type
    pub database_type: String,
    /// Duration until failure
    pub duration_secs: f64,
    /// Kubernetes job name
    pub job_name: String,
    /// Error message
    pub error: String,
    /// Last N lines of logs (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logs_tail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentCompletedEvent {
    #[serde(flatten)]
    pub metadata: EventMetadata,
    /// Deployment duration in seconds
    pub duration_secs: f64,
    /// Deployment strategy (RollingUpdate, Recreate)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strategy: Option<String>,
    /// Number of replicas
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replicas: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FluxReconciledEvent {
    #[serde(flatten)]
    pub metadata: EventMetadata,
    /// Kustomization name
    pub kustomization: String,
    /// Whether reconciliation succeeded
    pub success: bool,
    /// Duration in seconds
    pub duration_secs: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolloutStatusEvent {
    #[serde(flatten)]
    pub metadata: EventMetadata,
    /// Current replicas ready
    pub ready_replicas: u32,
    /// Desired replicas
    pub desired_replicas: u32,
    /// Rollout status
    pub status: RolloutState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RolloutState {
    InProgress,
    Completed,
    Failed,
    RolledBack,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShinkaMigrationCompletedEvent {
    #[serde(flatten)]
    pub metadata: EventMetadata,
    /// DatabaseMigration CRD name
    pub migration_name: String,
    /// Expected image tag that was waited for
    pub image_tag: String,
    /// Duration waiting for Shinka in seconds
    pub duration_secs: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShinkaMigrationFailedEvent {
    #[serde(flatten)]
    pub metadata: EventMetadata,
    /// DatabaseMigration CRD name
    pub migration_name: String,
    /// Expected image tag that was waited for
    pub image_tag: String,
    /// Duration until failure in seconds
    pub duration_secs: f64,
    /// Error message
    pub error: String,
    /// Last observed phase of the CRD
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_phase: Option<String>,
}

/// Emits a structured event as JSON to stdout
///
/// Events are prefixed with `FORGE_EVENT:` for Vector to parse.
pub fn emit_event(event: ReleaseEvent) {
    match serde_json::to_string(&event) {
        Ok(json) => {
            println!("{}{}", EVENT_PREFIX, json);
        }
        Err(e) => {
            tracing::error!("Failed to serialize event: {}", e);
        }
    }
}

/// Helper to track step timing
pub struct StepTimer {
    name: String,
    start: Instant,
}

impl StepTimer {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            start: Instant::now(),
        }
    }

    pub fn elapsed_secs(&self) -> f64 {
        self.start.elapsed().as_secs_f64()
    }

    pub fn finish(self) -> StepDuration {
        let duration = self.start.elapsed().as_secs_f64();
        StepDuration {
            step: self.name,
            duration_secs: duration,
            status: StepStatus::Success,
        }
    }

    pub fn finish_failed(self) -> StepDuration {
        let duration = self.start.elapsed().as_secs_f64();
        StepDuration {
            step: self.name,
            duration_secs: duration,
            status: StepStatus::Failed,
        }
    }

    pub fn finish_skipped(self) -> StepDuration {
        StepDuration {
            step: self.name,
            duration_secs: 0.0,
            status: StepStatus::Skipped,
        }
    }
}

/// Release workflow tracker
pub struct ReleaseTracker {
    metadata: EventMetadata,
    start: Instant,
    steps: Vec<StepDuration>,
    current_step: Option<StepTimer>,
}

impl ReleaseTracker {
    pub fn new(metadata: EventMetadata) -> Self {
        Self {
            metadata,
            start: Instant::now(),
            steps: Vec::new(),
            current_step: None,
        }
    }

    /// Start a new step
    pub fn start_step(&mut self, name: impl Into<String>) {
        // Finish any existing step first
        if let Some(timer) = self.current_step.take() {
            self.steps.push(timer.finish());
        }
        self.current_step = Some(StepTimer::new(name));
    }

    /// Mark current step as completed
    pub fn complete_step(&mut self) {
        if let Some(timer) = self.current_step.take() {
            self.steps.push(timer.finish());
        }
    }

    /// Mark current step as failed
    pub fn fail_step(&mut self) {
        if let Some(timer) = self.current_step.take() {
            self.steps.push(timer.finish_failed());
        }
    }

    /// Skip a step (record it without timing)
    pub fn skip_step(&mut self, name: impl Into<String>) {
        self.steps.push(StepDuration {
            step: name.into(),
            duration_secs: 0.0,
            status: StepStatus::Skipped,
        });
    }

    /// Emit release started event
    pub fn emit_started(&self, step_names: Vec<String>, dry_run: bool) {
        emit_event(ReleaseEvent::ReleaseStarted(ReleaseStartedEvent {
            metadata: self.metadata.clone(),
            steps: step_names,
            dry_run,
        }));
    }

    /// Emit release completed event
    pub fn emit_completed(mut self) {
        // Complete any pending step
        if let Some(timer) = self.current_step.take() {
            self.steps.push(timer.finish());
        }

        emit_event(ReleaseEvent::ReleaseCompleted(ReleaseCompletedEvent {
            metadata: self.metadata,
            duration_secs: self.start.elapsed().as_secs_f64(),
            step_durations: self.steps,
        }));
    }

    /// Emit release failed event
    pub fn emit_failed(mut self, failed_step: String, error: String) {
        // Fail any pending step
        if let Some(timer) = self.current_step.take() {
            self.steps.push(timer.finish_failed());
        }

        emit_event(ReleaseEvent::ReleaseFailed(ReleaseFailedEvent {
            metadata: self.metadata,
            duration_secs: self.start.elapsed().as_secs_f64(),
            failed_step,
            error,
        }));
    }

    /// Get reference to metadata for creating sub-events
    pub fn metadata(&self) -> &EventMetadata {
        &self.metadata
    }

    /// Get elapsed time
    pub fn elapsed_secs(&self) -> f64 {
        self.start.elapsed().as_secs_f64()
    }
}

/// Helper to emit migration events
pub struct MigrationTracker {
    metadata: EventMetadata,
    database_type: String,
    job_name: String,
    start: Instant,
}

impl MigrationTracker {
    pub fn new(
        metadata: EventMetadata,
        database_type: impl Into<String>,
        job_name: impl Into<String>,
        image_tag: impl Into<String>,
    ) -> Self {
        let tracker = Self {
            metadata: metadata.clone(),
            database_type: database_type.into(),
            job_name: job_name.into(),
            start: Instant::now(),
        };

        // Emit started event
        emit_event(ReleaseEvent::MigrationStarted(MigrationStartedEvent {
            metadata,
            database_type: tracker.database_type.clone(),
            image_tag: image_tag.into(),
            job_name: tracker.job_name.clone(),
        }));

        tracker
    }

    /// Mark migration as completed
    ///
    /// Emits completion event and pushes metrics to Pushgateway (if configured).
    pub fn complete(self, migrations_applied: Option<u32>) {
        let duration_secs = self.start.elapsed().as_secs_f64();

        emit_event(ReleaseEvent::MigrationCompleted(MigrationCompletedEvent {
            metadata: self.metadata.clone(),
            database_type: self.database_type.clone(),
            duration_secs,
            job_name: self.job_name,
            migrations_applied,
        }));

        // Push metrics asynchronously (fire and forget)
        let metadata = self.metadata;
        let db_type = self.database_type;
        tokio::spawn(async move {
            metrics::push_migration_metrics(&metadata, &db_type, duration_secs, true).await;
        });
    }

    /// Mark migration as failed
    ///
    /// Emits failure event and pushes metrics to Pushgateway (if configured).
    pub fn fail(self, error: String, logs_tail: Option<String>) {
        let duration_secs = self.start.elapsed().as_secs_f64();

        emit_event(ReleaseEvent::MigrationFailed(MigrationFailedEvent {
            metadata: self.metadata.clone(),
            database_type: self.database_type.clone(),
            duration_secs,
            job_name: self.job_name,
            error,
            logs_tail,
        }));

        // Push metrics asynchronously (fire and forget)
        let metadata = self.metadata;
        let db_type = self.database_type;
        tokio::spawn(async move {
            metrics::push_migration_metrics(&metadata, &db_type, duration_secs, false).await;
        });
    }

    /// Get elapsed time
    pub fn elapsed_secs(&self) -> f64 {
        self.start.elapsed().as_secs_f64()
    }
}

// =============================================================================
// PROMETHEUS METRICS - Pushgateway Integration
// =============================================================================

/// Prometheus metrics for releases and migrations
///
/// Metrics are pushed to Pushgateway if PUSHGATEWAY_URL is set.
pub mod metrics {
    use super::*;

    /// Get Pushgateway URL from environment
    pub fn pushgateway_url() -> Option<String> {
        std::env::var("PUSHGATEWAY_URL").ok()
    }

    /// Build Prometheus text format metrics for a release
    pub fn build_release_metrics(
        metadata: &EventMetadata,
        duration_secs: f64,
        success: bool,
        step_durations: &[StepDuration],
    ) -> String {
        let mut output = String::new();

        // Release duration histogram (we push the observation as a gauge for simplicity)
        output.push_str("# HELP forge_release_duration_seconds Duration of release operations\n");
        output.push_str("# TYPE forge_release_duration_seconds gauge\n");
        output.push_str(&format!(
            "forge_release_duration_seconds{{product=\"{}\",service=\"{}\",environment=\"{}\",git_sha=\"{}\"}} {:.3}\n",
            metadata.product, metadata.service, metadata.environment, metadata.git_sha, duration_secs
        ));

        // Release success/failure counter
        let status = if success { "success" } else { "failure" };
        output.push_str("# HELP forge_release_total Total release operations\n");
        output.push_str("# TYPE forge_release_total counter\n");
        output.push_str(&format!(
            "forge_release_total{{product=\"{}\",service=\"{}\",environment=\"{}\",status=\"{}\"}} 1\n",
            metadata.product, metadata.service, metadata.environment, status
        ));

        // Per-step durations
        output
            .push_str("# HELP forge_release_step_duration_seconds Duration of each release step\n");
        output.push_str("# TYPE forge_release_step_duration_seconds gauge\n");
        for step in step_durations {
            let step_status = match step.status {
                StepStatus::Success => "success",
                StepStatus::Failed => "failed",
                StepStatus::Skipped => "skipped",
            };
            output.push_str(&format!(
                "forge_release_step_duration_seconds{{product=\"{}\",service=\"{}\",step=\"{}\",status=\"{}\"}} {:.3}\n",
                metadata.product, metadata.service, step.step, step_status, step.duration_secs
            ));
        }

        output
    }

    /// Build Prometheus text format metrics for a migration
    pub fn build_migration_metrics(
        metadata: &EventMetadata,
        database_type: &str,
        duration_secs: f64,
        success: bool,
    ) -> String {
        let mut output = String::new();

        // Migration duration
        output
            .push_str("# HELP forge_migration_duration_seconds Duration of database migrations\n");
        output.push_str("# TYPE forge_migration_duration_seconds gauge\n");
        output.push_str(&format!(
            "forge_migration_duration_seconds{{product=\"{}\",service=\"{}\",environment=\"{}\",database=\"{}\"}} {:.3}\n",
            metadata.product, metadata.service, metadata.environment, database_type, duration_secs
        ));

        // Migration success/failure
        let status = if success { "success" } else { "failure" };
        output.push_str("# HELP forge_migration_total Total migration operations\n");
        output.push_str("# TYPE forge_migration_total counter\n");
        output.push_str(&format!(
            "forge_migration_total{{product=\"{}\",service=\"{}\",environment=\"{}\",database=\"{}\",status=\"{}\"}} 1\n",
            metadata.product, metadata.service, metadata.environment, database_type, status
        ));

        output
    }

    /// Push metrics to Pushgateway
    ///
    /// Uses the job/instance grouping for proper metric isolation:
    /// - job: "forge"
    /// - instance: "{product}/{service}"
    pub async fn push_metrics(metrics: &str, product: &str, service: &str) -> Result<(), String> {
        let base_url = match pushgateway_url() {
            Some(url) => url,
            None => {
                tracing::debug!("PUSHGATEWAY_URL not set, skipping metrics push");
                return Ok(());
            }
        };

        // URL encode the grouping keys
        let job = "forge";
        let instance = format!("{}/{}", product, service);

        // Pushgateway expects: /metrics/job/<job>/instance/<instance>
        let url = format!(
            "{}/metrics/job/{}/instance/{}",
            base_url.trim_end_matches('/'),
            urlencoding::encode(job),
            urlencoding::encode(&instance)
        );

        tracing::info!(url = %url, "Pushing metrics to Pushgateway");

        let client = reqwest::Client::new();
        let response = client
            .post(&url)
            .header("Content-Type", "text/plain")
            .body(metrics.to_string())
            .send()
            .await
            .map_err(|e| format!("Failed to push metrics: {}", e))?;

        if response.status().is_success() {
            tracing::info!("Metrics pushed successfully");
            Ok(())
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(format!("Pushgateway returned {}: {}", status, body))
        }
    }

    /// Push release metrics to Pushgateway
    pub async fn push_release_metrics(
        metadata: &EventMetadata,
        duration_secs: f64,
        success: bool,
        step_durations: &[StepDuration],
    ) {
        let metrics = build_release_metrics(metadata, duration_secs, success, step_durations);
        if let Err(e) = push_metrics(&metrics, &metadata.product, &metadata.service).await {
            tracing::warn!("Failed to push release metrics: {}", e);
        }
    }

    /// Push migration metrics to Pushgateway
    pub async fn push_migration_metrics(
        metadata: &EventMetadata,
        database_type: &str,
        duration_secs: f64,
        success: bool,
    ) {
        let metrics = build_migration_metrics(metadata, database_type, duration_secs, success);
        if let Err(e) = push_metrics(&metrics, &metadata.product, &metadata.service).await {
            tracing::warn!("Failed to push migration metrics: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_serialization() {
        let metadata =
            EventMetadata::new("abc123", "testapp", "backend", "staging", "testapp-staging");

        let event = ReleaseEvent::ReleaseStarted(ReleaseStartedEvent {
            metadata,
            steps: vec!["build".into(), "push".into(), "deploy".into()],
            dry_run: false,
        });

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("ReleaseStarted"));
        assert!(json.contains("testapp"));
        assert!(json.contains("backend"));
    }

    #[test]
    fn test_step_timer() {
        let timer = StepTimer::new("test_step");
        std::thread::sleep(std::time::Duration::from_millis(10));
        let duration = timer.finish();
        assert!(duration.duration_secs >= 0.01);
        assert_eq!(duration.step, "test_step");
    }

    #[test]
    fn test_release_metrics_format() {
        let metadata =
            EventMetadata::new("abc123", "testapp", "backend", "staging", "testapp-staging");

        let steps = vec![
            StepDuration {
                step: "build".into(),
                duration_secs: 10.5,
                status: StepStatus::Success,
            },
            StepDuration {
                step: "push".into(),
                duration_secs: 5.2,
                status: StepStatus::Success,
            },
        ];

        let output = metrics::build_release_metrics(&metadata, 15.7, true, &steps);

        // Verify metric format
        assert!(output.contains("forge_release_duration_seconds"));
        assert!(output.contains("product=\"testapp\""));
        assert!(output.contains("service=\"backend\""));
        assert!(output.contains("environment=\"staging\""));
        assert!(output.contains("git_sha=\"abc123\""));
        assert!(output.contains("15.700"));

        // Verify counter
        assert!(output.contains("forge_release_total"));
        assert!(output.contains("status=\"success\""));

        // Verify step metrics
        assert!(output.contains("forge_release_step_duration_seconds"));
        assert!(output.contains("step=\"build\""));
        assert!(output.contains("step=\"push\""));
    }

    #[test]
    fn test_migration_metrics_format() {
        let metadata = EventMetadata::new(
            "def456",
            "testapp",
            "auth",
            "production",
            "testapp-production",
        );

        let output = metrics::build_migration_metrics(&metadata, "postgres", 8.3, false);

        // Verify metric format
        assert!(output.contains("forge_migration_duration_seconds"));
        assert!(output.contains("product=\"testapp\""));
        assert!(output.contains("service=\"auth\""));
        assert!(output.contains("database=\"postgres\""));
        assert!(output.contains("8.300"));

        // Verify failure status
        assert!(output.contains("forge_migration_total"));
        assert!(output.contains("status=\"failure\""));
    }
}
