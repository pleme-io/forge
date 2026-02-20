//! Release domain types
//!
//! Defines the release workflow as a state machine with explicit phases.

use std::time::Duration;

/// Individual steps in a release workflow
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseStep {
    /// Build Docker image with Nix
    Build,
    /// Push image to container registry
    Push,
    /// Update Kubernetes manifests (GitOps)
    Deploy,
    /// Wait for Flux reconciliation
    FluxReconcile,
    /// Run database migrations
    Migrate,
    /// Extract GraphQL schema
    ExtractSchema,
    /// Update Apollo Federation supergraph
    UpdateFederation,
    /// Run integration tests
    IntegrationTests,
    /// Monitor rollout
    Rollout,
}

impl ReleaseStep {
    /// Get human-readable name for the step
    pub fn name(&self) -> &'static str {
        match self {
            Self::Build => "Build",
            Self::Push => "Push",
            Self::Deploy => "Deploy",
            Self::FluxReconcile => "Flux Reconcile",
            Self::Migrate => "Migrate",
            Self::ExtractSchema => "Extract Schema",
            Self::UpdateFederation => "Update Federation",
            Self::IntegrationTests => "Integration Tests",
            Self::Rollout => "Rollout",
        }
    }

    /// Get emoji for the step
    pub fn emoji(&self) -> &'static str {
        match self {
            Self::Build => "🔨",
            Self::Push => "📤",
            Self::Deploy => "🚀",
            Self::FluxReconcile => "🔄",
            Self::Migrate => "🗃️",
            Self::ExtractSchema => "📝",
            Self::UpdateFederation => "🌐",
            Self::IntegrationTests => "🧪",
            Self::Rollout => "👀",
        }
    }
}

/// Current phase of a release
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleasePhase {
    /// Not started
    Pending,
    /// Currently executing
    InProgress(ReleaseStep),
    /// Completed successfully
    Completed,
    /// Failed at a specific step
    Failed(ReleaseStep),
    /// Skipped (e.g., no migrations needed)
    Skipped,
}

/// Configuration for a release workflow
#[derive(Debug, Clone)]
pub struct ReleaseConfig {
    /// Service name
    pub service: String,
    /// Product name
    pub product: String,
    /// Kubernetes namespace
    pub namespace: String,
    /// Container registry URL
    pub registry: String,
    /// Path to Kubernetes manifest
    pub manifest_path: String,
    /// Path to built image
    pub image_path: String,
    /// Git SHA for tagging
    pub git_sha: String,
    /// Steps to execute
    pub steps: Vec<ReleaseStep>,
    /// Timeout for each step
    pub step_timeout: Duration,
    /// Whether to watch rollout
    pub watch_rollout: bool,
}

impl ReleaseConfig {
    /// Create a new release config with defaults
    pub fn new(
        service: impl Into<String>,
        product: impl Into<String>,
        namespace: impl Into<String>,
    ) -> Self {
        Self {
            service: service.into(),
            product: product.into(),
            namespace: namespace.into(),
            registry: String::new(),
            manifest_path: String::new(),
            image_path: String::new(),
            git_sha: String::new(),
            steps: Self::default_steps(),
            step_timeout: Duration::from_secs(600),
            watch_rollout: true,
        }
    }

    /// Default release steps for a Rust service
    pub fn default_steps() -> Vec<ReleaseStep> {
        vec![
            ReleaseStep::Push,
            ReleaseStep::Deploy,
            ReleaseStep::FluxReconcile,
            ReleaseStep::Migrate,
            ReleaseStep::ExtractSchema,
            ReleaseStep::UpdateFederation,
            ReleaseStep::Rollout,
        ]
    }

    /// Minimal release steps (push + deploy only)
    pub fn minimal_steps() -> Vec<ReleaseStep> {
        vec![
            ReleaseStep::Push,
            ReleaseStep::Deploy,
            ReleaseStep::FluxReconcile,
        ]
    }

    /// Builder: set registry
    pub fn with_registry(mut self, registry: impl Into<String>) -> Self {
        self.registry = registry.into();
        self
    }

    /// Builder: set manifest path
    pub fn with_manifest(mut self, path: impl Into<String>) -> Self {
        self.manifest_path = path.into();
        self
    }

    /// Builder: set image path
    pub fn with_image(mut self, path: impl Into<String>) -> Self {
        self.image_path = path.into();
        self
    }

    /// Builder: set git SHA
    pub fn with_sha(mut self, sha: impl Into<String>) -> Self {
        self.git_sha = sha.into();
        self
    }

    /// Builder: set steps
    pub fn with_steps(mut self, steps: Vec<ReleaseStep>) -> Self {
        self.steps = steps;
        self
    }

    /// Builder: disable rollout watching
    pub fn without_watch(mut self) -> Self {
        self.watch_rollout = false;
        self
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.service.is_empty() {
            errors.push("Service name is required".to_string());
        }
        if self.namespace.is_empty() {
            errors.push("Namespace is required".to_string());
        }
        if self.registry.is_empty() && self.steps.contains(&ReleaseStep::Push) {
            errors.push("Registry is required for push step".to_string());
        }
        if self.manifest_path.is_empty() && self.steps.contains(&ReleaseStep::Deploy) {
            errors.push("Manifest path is required for deploy step".to_string());
        }
        if self.image_path.is_empty() && self.steps.contains(&ReleaseStep::Push) {
            errors.push("Image path is required for push step".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// Result of a release step execution
#[derive(Debug)]
pub struct StepResult {
    pub step: ReleaseStep,
    pub success: bool,
    pub duration: Duration,
    pub message: Option<String>,
}

impl StepResult {
    pub fn success(step: ReleaseStep, duration: Duration) -> Self {
        Self {
            step,
            success: true,
            duration,
            message: None,
        }
    }

    pub fn failure(step: ReleaseStep, duration: Duration, message: impl Into<String>) -> Self {
        Self {
            step,
            success: false,
            duration,
            message: Some(message.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_release_config_builder() {
        let config = ReleaseConfig::new("api", "myproduct", "myproduct-staging")
            .with_registry("ghcr.io/org/project/myproduct-api")
            .with_manifest("nix/k8s/api/kustomization.yaml")
            .with_image("result-amd64")
            .with_sha("abc1234");

        assert_eq!(config.service, "api");
        assert_eq!(config.product, "myproduct");
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_release_config_validation() {
        let config = ReleaseConfig::new("", "myproduct", "");
        let result = config.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("Service")));
        assert!(errors.iter().any(|e| e.contains("Namespace")));
    }

    #[test]
    fn test_release_steps() {
        let steps = ReleaseConfig::default_steps();
        assert!(steps.contains(&ReleaseStep::Push));
        assert!(steps.contains(&ReleaseStep::Deploy));
        assert!(steps.contains(&ReleaseStep::Migrate));
    }
}
