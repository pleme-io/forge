//! Kubernetes configuration for namespaces, labels, and manifest paths.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Kubernetes configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesConfig {
    /// Product label key (default: "product")
    #[serde(default = "default_product_label_key")]
    pub product_label_key: String,

    /// Service/app label key (default: "app")
    /// Value will be formatted as {product}-{service} e.g., "myapp-backend"
    #[serde(default = "default_service_label_key")]
    pub service_label_key: String,

    /// Namespace pattern (supports: {product}, {environment})
    #[serde(default = "default_namespace_pattern")]
    pub namespace_pattern: String,

    /// Deployment name (if different from service name)
    /// For example, web frontend might be named "{product}-web" instead of just "web"
    #[serde(default)]
    pub deployment_name: Option<String>,

    /// Additional labels to apply to all resources
    #[serde(default)]
    pub additional_labels: HashMap<String, String>,
}

fn default_product_label_key() -> String {
    "product".to_string()
}

fn default_service_label_key() -> String {
    "app".to_string()
}

fn default_namespace_pattern() -> String {
    "{product}-{environment}".to_string()
}

impl Default for KubernetesConfig {
    fn default() -> Self {
        Self {
            product_label_key: default_product_label_key(),
            service_label_key: default_service_label_key(),
            namespace_pattern: default_namespace_pattern(),
            deployment_name: None,
            additional_labels: HashMap::new(),
        }
    }
}

/// Path configuration for repository structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathsConfig {
    /// Root directory for products (e.g., "pkgs/products")
    #[serde(default = "default_products_root")]
    pub products_root: String,

    /// Federation directory relative to product (e.g., "infrastructure/hive-router")
    #[serde(default = "default_federation_path")]
    pub federation_path: String,

    /// Services directory relative to product (e.g., "services/rust")
    #[serde(default = "default_services_path")]
    pub services_path: String,

    /// Kubernetes manifests root directory (e.g., "nix/k8s/clusters")
    #[serde(default = "default_k8s_root")]
    pub k8s_root: String,

    /// Kubernetes manifests path pattern (supports: {cluster}, {product}, {environment}, {service})
    #[serde(default = "default_k8s_manifest_pattern")]
    pub k8s_manifest_pattern: String,

    /// Subgraphs directory name within federation path (e.g., "subgraphs")
    #[serde(default = "default_subgraph_dir")]
    pub subgraph_dir: String,

    /// Federation root directory name (e.g., "infrastructure")
    #[serde(default = "default_federation_root")]
    pub federation_root: String,

    /// Router name/directory (e.g., "hive-router")
    #[serde(default = "default_router_name")]
    pub router_name: String,

    /// Supergraph config filename (e.g., "supergraph-config.yaml")
    #[serde(default = "default_supergraph_config_filename")]
    pub supergraph_config_filename: String,
}

fn default_products_root() -> String {
    "pkgs/products".to_string()
}

fn default_federation_path() -> String {
    "infrastructure/hive-router".to_string()
}

fn default_services_path() -> String {
    "services/rust".to_string()
}

fn default_k8s_root() -> String {
    "nix/k8s/clusters".to_string()
}

fn default_k8s_manifest_pattern() -> String {
    "nix/k8s/clusters/{cluster}/products/{product}-{environment}/services/{service}/kustomization.yaml".to_string()
}

fn default_subgraph_dir() -> String {
    "subgraphs".to_string()
}

fn default_federation_root() -> String {
    "infrastructure".to_string()
}

fn default_router_name() -> String {
    "hive-router".to_string()
}

fn default_supergraph_config_filename() -> String {
    "supergraph-config.yaml".to_string()
}

impl Default for PathsConfig {
    fn default() -> Self {
        Self {
            products_root: default_products_root(),
            federation_path: default_federation_path(),
            services_path: default_services_path(),
            k8s_root: default_k8s_root(),
            k8s_manifest_pattern: default_k8s_manifest_pattern(),
            subgraph_dir: default_subgraph_dir(),
            federation_root: default_federation_root(),
            router_name: default_router_name(),
            supergraph_config_filename: default_supergraph_config_filename(),
        }
    }
}

/// Single environment manifest paths
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ManifestPaths {
    /// Path to kustomization.yaml (relative to repo root)
    /// Example: "clusters/{cluster}/products/{product}/staging/kustomization.yaml"
    pub kustomization: Option<String>,

    /// Path to deployment.yaml (relative to repo root)
    pub deployment: Option<String>,

    /// Path to configmap.yaml (relative to repo root)
    pub configmap: Option<String>,
}

/// Kubernetes manifest paths configuration
/// Supports both flat structure (legacy) and environment-keyed structure (new)
///
/// Legacy (flat):
/// ```yaml
/// manifests:
///   kustomization: "path/to/kustomization.yaml"
/// ```
///
/// Environment-keyed (new — any environment key works):
/// ```yaml
/// manifests:
///   staging:
///     kustomization: "path/to/staging/kustomization.yaml"
///   production-a:
///     kustomization: "path/to/production/kustomization.yaml"
///   production-b:
///     kustomization: "path/to/cluster-b/kustomization.yaml"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ManifestPathsConfig {
    /// Legacy: flat kustomization path (deprecated, use environment keys)
    pub kustomization: Option<String>,

    /// Legacy: flat deployment path
    pub deployment: Option<String>,

    /// Legacy: flat configmap path
    pub configmap: Option<String>,

    /// Dynamic environment-keyed paths (staging, production-a, production-b, etc.)
    #[serde(flatten)]
    pub environments: HashMap<String, ManifestPaths>,
}

impl ManifestPathsConfig {
    /// Get kustomization path for a specific environment
    /// First checks environment-specific paths, then falls back to flat structure
    pub fn kustomization_for_env(&self, environment: &str) -> Option<&String> {
        self.environments
            .get(environment)
            .and_then(|p| p.kustomization.as_ref())
            .or(self.kustomization.as_ref())
    }
}
