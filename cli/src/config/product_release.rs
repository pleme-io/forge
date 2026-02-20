//! Product-level release orchestration configuration.
//!
//! Defines the service list, ordering, health checks, and hooks
//! for coordinating a full product release (all services, all phases).

use serde::{Deserialize, Serialize};

/// Product-level release orchestration config.
/// Lives in `pkgs/products/{product}/deploy.yaml` under `release:`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProductReleaseConfig {
    /// Services in release order (build all, then deploy in this order).
    #[serde(default)]
    pub services: Vec<ProductServiceConfig>,

    /// Run pre-release gates (convention: `{product}-prerelease` command).
    /// Default: true.
    #[serde(default = "default_true")]
    pub prerelease: bool,

    /// Run dashboard sync (convention: `{product}-dashboards` command).
    /// Default: false (controlled by `observability.dashboards.enabled`).
    #[serde(default)]
    pub dashboards: bool,

    /// Run post-deploy verification.
    /// Default: true.
    #[serde(default = "default_true")]
    pub post_deploy: bool,
}

/// Configuration for a single service within the product release.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductServiceConfig {
    /// Service name (e.g., "backend", "web").
    pub name: String,

    /// Service type: "rust" or "web".
    #[serde(rename = "type")]
    pub service_type: String,

    /// Path relative to product directory (e.g., "services/rust/backend", "web").
    pub path: String,

    /// Health check to run after deploying this service.
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,
}

/// Health check configuration for a service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    /// Kubernetes deployment name to check.
    pub deployment: String,

    /// Timeout in seconds (default: 60).
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_true() -> bool {
    true
}

fn default_timeout() -> u64 {
    60
}
