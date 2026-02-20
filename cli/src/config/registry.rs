//! Registry and cache configuration for container images and binary caches.

use serde::{Deserialize, Serialize};

/// Registry configuration for container images
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryConfig {
    /// Registry host (e.g., "ghcr.io", "docker.io")
    #[serde(default = "default_registry_host")]
    pub host: String,

    /// Organization name (e.g., "myorg", "mycompany")
    #[serde(default = "default_organization")]
    pub organization: String,

    /// Project/monorepo name (e.g., "myproject")
    #[serde(default = "default_project")]
    pub project: String,

    /// Image name pattern (supports: {host}, {organization}, {project}, {product}, {service})
    #[serde(default = "default_image_pattern")]
    pub image_pattern: String,
}

fn default_registry_host() -> String {
    "ghcr.io".to_string()
}

fn default_organization() -> String {
    "org".to_string()
}

fn default_project() -> String {
    "project".to_string()
}

fn default_image_pattern() -> String {
    "{host}/{organization}/{project}/{product}-{service}".to_string()
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            host: default_registry_host(),
            organization: default_organization(),
            project: default_project(),
            image_pattern: default_image_pattern(),
        }
    }
}

/// Cache configuration for Attic binary cache
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Cache server name (e.g., "mycompany-cache", "company-cache")
    #[serde(default = "default_cache_server")]
    pub server: String,
}

fn default_cache_server() -> String {
    "cache".to_string()
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            server: default_cache_server(),
        }
    }
}
