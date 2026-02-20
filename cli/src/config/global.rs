//! Global deployment configuration.

use serde::{Deserialize, Serialize};

use super::deployment::{CloudflareConfig, DeploymentConfig};
use super::federation::{FederationConfig, FederationTestsConfig};
use super::kubernetes::{KubernetesConfig, PathsConfig};
use super::registry::{CacheConfig, RegistryConfig};

/// Global deployment configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GlobalConfig {
    /// Registry configuration
    #[serde(default)]
    pub registry: RegistryConfig,

    /// Cache configuration
    #[serde(default)]
    pub cache: CacheConfig,

    /// Kubernetes configuration
    #[serde(default)]
    pub kubernetes: KubernetesConfig,

    /// Path configuration
    #[serde(default)]
    pub paths: PathsConfig,

    /// Federation configuration
    #[serde(default)]
    pub federation: FederationConfig,

    /// Federation integration tests configuration
    #[serde(default)]
    pub federation_tests: FederationTestsConfig,

    /// Deployment operation configuration
    #[serde(default)]
    pub deployment: DeploymentConfig,

    /// Cloudflare cache purging configuration
    #[serde(default)]
    pub cloudflare: CloudflareConfig,
}
