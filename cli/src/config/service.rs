//! Service-specific configuration.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::deployment::DeploymentConfig;
use super::federation::{
    FederationConfig, FederationTestsServiceConfig, ServiceFederationConfig,
    ServiceFederationTestsConfig,
};
use super::kubernetes::{KubernetesConfig, ManifestPathsConfig};
use super::migration::{NovaSearchConfig, ServiceMigrationConfig};
use super::prerelease::PreReleaseGatesConfig;
use super::release::{EnvironmentConfig, ReleaseConfig};

/// Local development configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LocalConfig {
    /// Docker compose services to start (e.g., ["postgres", "minio"])
    #[serde(default)]
    pub services: Vec<String>,

    /// Environment variables for local development
    #[serde(default)]
    pub env: HashMap<String, String>,

    /// Binary name to run (optional, auto-detected from Cargo.toml if not specified)
    #[serde(default)]
    pub binary: Option<String>,

    /// Additional cargo run arguments
    #[serde(default)]
    pub cargo_args: Vec<String>,
}

/// Service-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    /// Service name (e.g., "cart", "auth", "analytics")
    pub name: String,

    /// Migration configuration
    #[serde(default)]
    pub migration: ServiceMigrationConfig,

    /// Service-level Apollo Federation configuration
    #[serde(default)]
    pub graphql: ServiceFederationConfig,

    /// Federation integration tests configuration
    #[serde(default)]
    pub federation_tests: ServiceFederationTestsConfig,

    /// Federation tests service configuration (for the global test runner only)
    #[serde(default)]
    pub federation_tests_service: FederationTestsServiceConfig,

    /// Service-level deployment configuration overrides
    #[serde(default)]
    pub deployment: Option<DeploymentConfig>,

    /// Global federation routing overrides (optional, rarely used)
    /// Use graphql.* fields for service-specific GraphQL config
    pub federation: Option<FederationConfig>,

    /// Service-level Kubernetes configuration overrides
    /// Allows specifying deployment_name and other K8s settings per service
    #[serde(default)]
    pub kubernetes: Option<KubernetesConfig>,

    /// Kubernetes manifest paths (read from deploy.yaml)
    /// Falls back to computed paths if not specified
    #[serde(default)]
    pub manifests: ManifestPathsConfig,

    /// Search service GitOps configuration (special case for search service)
    /// Runs search sync after K8s deployment rollout
    #[serde(default)]
    pub novasearch: NovaSearchConfig,

    /// Local development configuration
    #[serde(default)]
    pub local: LocalConfig,

    /// Release workflow configuration (build-once-promote pattern)
    #[serde(default)]
    pub release: ReleaseConfig,

    /// Environment configurations (staging, production-a, production-b, etc.)
    #[serde(default)]
    pub environments: HashMap<String, EnvironmentConfig>,

    /// Environment aliases for backwards compatibility (e.g., "production" → "production-a")
    #[serde(default)]
    pub environment_aliases: HashMap<String, String>,

    /// Pre-release gate configuration
    /// Controls which validation gates run and how failures are handled
    #[serde(default)]
    pub prerelease: PreReleaseGatesConfig,
}
