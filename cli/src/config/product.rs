//! Product-specific configuration.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use super::product_release::ProductReleaseConfig;

/// Observability configuration for dashboards, metrics, and ReBAC keys.
///
/// All fields default to the product name so no configuration is required
/// for products that follow the standard naming conventions.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ObservabilityConfig {
    /// Prometheus metric name prefix (defaults to product name).
    /// e.g., "myapp" → metrics named "myapp_<entity>_operations_total"
    pub metric_prefix: Option<String>,

    /// Grafana dashboard folder name (defaults to capitalized product name).
    /// e.g., None → "MyApp"
    pub dashboard_folder: Option<String>,

    /// Redis key namespace prefix for ReBAC/permission keys (defaults to product name).
    /// e.g., "myapp" → keys like "myapp:rel:*", "myapp:perm:*"
    pub redis_key_prefix: Option<String>,
}

/// Seed / test-data configuration.
///
/// All fields default to values derived from the product name so no
/// configuration is required for standard setups.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SeedConfig {
    /// Email domain used for generated test profiles (defaults to "@{product}.test").
    /// e.g., "@myapp.test"
    pub email_domain: Option<String>,

    /// CNPG PostgreSQL cluster label for pod discovery (defaults to "{product}-postgres").
    /// e.g., "myapp-postgres"
    pub postgres_cluster: Option<String>,

    /// Database name passed to psql (defaults to product name).
    pub db_name: Option<String>,
}

/// Directory layout configuration.
///
/// All paths are relative to the product root (or absolute).
/// No defaults — must be explicitly configured to avoid wrong-directory assumptions.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DirsConfig {
    /// Backend Rust service directory (e.g., "services/rust/backend")
    pub backend: Option<String>,

    /// Web app directory (e.g., "web")
    pub web: Option<String>,

    /// Architecture docs directory (e.g., "docs/arch")
    pub docs_arch: Option<String>,

    /// Observability scripts/templates directory (e.g., "scripts/observability")
    pub observability_scripts: Option<String>,

    /// Dashboard CRD output directory — must be explicitly configured.
    pub dashboards_output: Option<String>,
}

/// Endpoint registry — maps (environment, endpoint_type) to a URL.
///
/// Structured as: `endpoints.{env}.{type} = "https://..."`.
/// Endpoint types are product-defined (e.g., "health", "graphql", "admin", "ws").
///
/// ```yaml
/// endpoints:
///   staging:
///     health: "https://api.staging.myapp.io/health"
///     graphql: "https://api.staging.myapp.io/graphql"
///   production:
///     health: "https://api.myapp.io/health"
///     graphql: "https://api.myapp.io/graphql"
/// ```
pub type EndpointsConfig = std::collections::HashMap<String, std::collections::HashMap<String, String>>;

/// Configuration for a separate K8s manifests repository.
///
/// When present in deploy.yaml, forge resolves manifest paths relative to the
/// k8s repo clone instead of the product repo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sRepoConfig {
    /// Git remote URL (for commit messages / validation)
    pub repo: Option<String>,

    /// Local path to k8s repo clone (relative to product repo root, or absolute)
    pub local: String,

    /// Branch to commit/push to (default: "main")
    #[serde(default = "default_k8s_branch")]
    pub branch: String,
}

fn default_k8s_branch() -> String {
    "main".to_string()
}

/// Product-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductConfig {
    /// Product name (e.g., "acme", "myapp")
    pub name: String,

    /// Environment (e.g., "staging", "production", "dev")
    #[serde(default = "default_environment")]
    pub environment: String,

    /// Kubernetes cluster name (e.g., "primary", "secondary")
    #[serde(default = "default_cluster")]
    pub cluster: String,

    /// Product-level release orchestration config (optional).
    /// Parsed from the `release:` section when present.
    #[serde(default)]
    pub release: Option<ProductReleaseConfig>,

    /// Separate K8s manifests repository configuration (optional).
    /// When present, manifest paths are resolved relative to the k8s repo clone.
    #[serde(default)]
    pub k8s: Option<K8sRepoConfig>,

    /// Product domain for URL derivation (e.g., "myapp.io").
    /// Used by post-deploy verification when --health-url is not provided.
    #[serde(default)]
    pub domain: Option<String>,

    /// Observability (metrics, dashboards, Redis keys) configuration.
    /// All fields default to values derived from the product name.
    #[serde(default)]
    pub observability: ObservabilityConfig,

    /// Seed / test-data configuration.
    /// All fields default to values derived from the product name.
    #[serde(default)]
    pub seed: SeedConfig,

    /// Directory layout — paths relative to product root.
    /// No defaults: configure explicitly to avoid wrong-path assumptions.
    #[serde(default)]
    pub dirs: DirsConfig,

    /// Endpoint registry — maps (environment, type) to a URL.
    /// e.g., endpoints.staging.health = "https://api.staging.myapp.io/health"
    #[serde(default)]
    pub endpoints: EndpointsConfig,
}

pub fn default_environment() -> String {
    "staging".to_string()
}

pub fn default_cluster() -> String {
    std::env::var("FORGE_CLUSTER").unwrap_or_else(|_| "default".to_string())
}

impl ProductConfig {
    // =========================================================================
    // Config-derived value helpers
    //
    // These provide product-specific values that flow from deploy.yaml.
    // Each falls back to a value derived from `self.name` so that products
    // following standard naming conventions require zero explicit configuration.
    // =========================================================================

    /// Prometheus metric name prefix (falls back to product name).
    pub fn metric_prefix(&self) -> &str {
        self.observability
            .metric_prefix
            .as_deref()
            .unwrap_or(&self.name)
    }

    /// Grafana dashboard folder name (falls back to capitalized product name).
    pub fn dashboard_folder(&self) -> String {
        if let Some(folder) = &self.observability.dashboard_folder {
            return folder.clone();
        }
        let mut folder = self.name.clone();
        if let Some(first) = folder.get_mut(0..1) {
            first.make_ascii_uppercase();
        }
        folder
    }

    /// Redis key namespace prefix for ReBAC/permission keys (falls back to product name).
    pub fn redis_key_prefix(&self) -> &str {
        self.observability
            .redis_key_prefix
            .as_deref()
            .unwrap_or(&self.name)
    }

    /// Email domain for generated seed profiles (falls back to "@{name}.test").
    pub fn seed_email_domain(&self) -> String {
        self.seed
            .email_domain
            .clone()
            .unwrap_or_else(|| format!("@{}.test", self.name))
    }

    /// CNPG PostgreSQL cluster label for pod discovery (falls back to "{name}-postgres").
    pub fn postgres_cluster(&self) -> String {
        self.seed
            .postgres_cluster
            .clone()
            .unwrap_or_else(|| format!("{}-postgres", self.name))
    }

    /// Database name for psql (falls back to product name).
    pub fn db_name(&self) -> &str {
        self.seed.db_name.as_deref().unwrap_or(&self.name)
    }

    /// Derive the Kubernetes namespace for an environment.
    ///
    /// Pattern: `{name}-{env_simplified}` where multi-cluster env names
    /// (production-a, production-b) collapse to "production".
    ///
    /// e.g., product "acme", env "staging" → "acme-staging"
    /// e.g., product "acme", env "production-a" → "acme-production"
    pub fn namespace_for_env(&self, env: &str) -> String {
        let simplified = match env {
            s if s.starts_with("production") => "production",
            other => other,
        };
        format!("{}-{}", self.name, simplified)
    }

    // =========================================================================
    // Directory helpers
    // =========================================================================

    /// Resolve a configured directory path relative to a root.
    /// Returns None if the path is not configured.
    pub fn resolve_dir(&self, root: &std::path::Path, path: Option<&str>) -> Option<std::path::PathBuf> {
        path.map(|p| {
            let p = std::path::Path::new(p);
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                root.join(p)
            }
        })
    }

    pub fn backend_dir(&self, root: &std::path::Path) -> Option<std::path::PathBuf> {
        self.resolve_dir(root, self.dirs.backend.as_deref())
    }

    pub fn web_dir(&self, root: &std::path::Path) -> Option<std::path::PathBuf> {
        self.resolve_dir(root, self.dirs.web.as_deref())
    }

    pub fn docs_arch_dir(&self, root: &std::path::Path) -> Option<std::path::PathBuf> {
        self.resolve_dir(root, self.dirs.docs_arch.as_deref())
    }

    pub fn observability_scripts_dir(&self, root: &std::path::Path) -> Option<std::path::PathBuf> {
        self.resolve_dir(root, self.dirs.observability_scripts.as_deref())
    }

    pub fn dashboards_output_dir(&self, root: &std::path::Path) -> Option<std::path::PathBuf> {
        self.resolve_dir(root, self.dirs.dashboards_output.as_deref())
    }

    // =========================================================================
    // Endpoint helpers
    // =========================================================================

    /// Look up a configured endpoint URL by environment and type.
    ///
    /// Returns None if not configured — callers must provide a fallback
    /// (e.g., `--health-url` flag) or error with a helpful message.
    pub fn endpoint_url(&self, env: &str, endpoint_type: &str) -> Option<&str> {
        self.endpoints
            .get(env)
            .and_then(|env_map| env_map.get(endpoint_type))
            .map(|s| s.as_str())
    }

    // =========================================================================

    /// Validate product configuration
    pub fn validate(&self) -> Result<()> {
        // Validate product name
        if self.name.trim().is_empty() {
            bail!("Product name cannot be empty");
        }

        // Validate product name format (lowercase, alphanumeric + hyphens)
        if !self
            .name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            bail!(
                "Product name '{}' must be lowercase alphanumeric with hyphens only",
                self.name
            );
        }

        // Validate environment
        if self.environment.trim().is_empty() {
            bail!("Environment cannot be empty");
        }

        // Validate environment is one of the known values (or warn)
        let known_environments = ["dev", "development", "staging", "production", "prod"];
        if !known_environments.contains(&self.environment.as_str()) {
            eprintln!(
                "⚠️  Warning: Environment '{}' is not a standard value. Known environments: {}",
                self.environment,
                known_environments.join(", ")
            );
        }

        // Validate cluster name
        if self.cluster.trim().is_empty() {
            bail!("Cluster name cannot be empty");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_product(name: &str) -> ProductConfig {
        ProductConfig {
            name: name.to_string(),
            environment: "staging".to_string(),
            cluster: "primary".to_string(),
            release: None,
            k8s: None,
            domain: None,
            observability: ObservabilityConfig::default(),
            seed: SeedConfig::default(),
            dirs: DirsConfig::default(),
            endpoints: Default::default(),
        }
    }

    #[test]
    fn test_metric_prefix_default() {
        let p = make_product("myapp");
        assert_eq!(p.metric_prefix(), "myapp");
    }

    #[test]
    fn test_metric_prefix_override() {
        let mut p = make_product("myapp");
        p.observability.metric_prefix = Some("custom_prefix".to_string());
        assert_eq!(p.metric_prefix(), "custom_prefix");
    }

    #[test]
    fn test_dashboard_folder_default() {
        let p = make_product("myapp");
        assert_eq!(p.dashboard_folder(), "Myapp");
    }

    #[test]
    fn test_dashboard_folder_override() {
        let mut p = make_product("myapp");
        p.observability.dashboard_folder = Some("Custom Folder".to_string());
        assert_eq!(p.dashboard_folder(), "Custom Folder");
    }

    #[test]
    fn test_redis_key_prefix_default() {
        let p = make_product("myapp");
        assert_eq!(p.redis_key_prefix(), "myapp");
    }

    #[test]
    fn test_redis_key_prefix_override() {
        let mut p = make_product("myapp");
        p.observability.redis_key_prefix = Some("custom".to_string());
        assert_eq!(p.redis_key_prefix(), "custom");
    }

    #[test]
    fn test_seed_email_domain_default() {
        let p = make_product("myapp");
        assert_eq!(p.seed_email_domain(), "@myapp.test");
    }

    #[test]
    fn test_seed_email_domain_override() {
        let mut p = make_product("myapp");
        p.seed.email_domain = Some("@custom.test".to_string());
        assert_eq!(p.seed_email_domain(), "@custom.test");
    }

    #[test]
    fn test_postgres_cluster_default() {
        let p = make_product("myapp");
        assert_eq!(p.postgres_cluster(), "myapp-postgres");
    }

    #[test]
    fn test_db_name_default() {
        let p = make_product("myapp");
        assert_eq!(p.db_name(), "myapp");
    }

    #[test]
    fn test_db_name_override() {
        let mut p = make_product("myapp");
        p.seed.db_name = Some("custom_db".to_string());
        assert_eq!(p.db_name(), "custom_db");
    }

    #[test]
    fn test_namespace_for_env_staging() {
        let p = make_product("myapp");
        assert_eq!(p.namespace_for_env("staging"), "myapp-staging");
    }

    #[test]
    fn test_namespace_for_env_production_simplified() {
        let p = make_product("myapp");
        assert_eq!(p.namespace_for_env("production-a"), "myapp-production");
        assert_eq!(p.namespace_for_env("production-b"), "myapp-production");
        assert_eq!(p.namespace_for_env("production"), "myapp-production");
    }

    #[test]
    fn test_namespace_for_env_custom() {
        let p = make_product("myapp");
        assert_eq!(p.namespace_for_env("dev"), "myapp-dev");
    }

    #[test]
    fn test_resolve_dir_none() {
        let p = make_product("myapp");
        let root = std::path::Path::new("/repo");
        assert!(p.resolve_dir(root, None).is_none());
    }

    #[test]
    fn test_resolve_dir_relative() {
        let p = make_product("myapp");
        let root = std::path::Path::new("/repo");
        let result = p.resolve_dir(root, Some("services/rust/backend"));
        assert_eq!(result.unwrap(), std::path::PathBuf::from("/repo/services/rust/backend"));
    }

    #[test]
    fn test_resolve_dir_absolute() {
        let p = make_product("myapp");
        let root = std::path::Path::new("/repo");
        let result = p.resolve_dir(root, Some("/absolute/path"));
        assert_eq!(result.unwrap(), std::path::PathBuf::from("/absolute/path"));
    }

    #[test]
    fn test_endpoint_url_found() {
        let mut p = make_product("myapp");
        let mut staging = std::collections::HashMap::new();
        staging.insert("health".to_string(), "https://api.staging.myapp.io/health".to_string());
        p.endpoints.insert("staging".to_string(), staging);
        assert_eq!(p.endpoint_url("staging", "health"), Some("https://api.staging.myapp.io/health"));
    }

    #[test]
    fn test_endpoint_url_not_found() {
        let p = make_product("myapp");
        assert!(p.endpoint_url("staging", "health").is_none());
    }

    #[test]
    fn test_validate_valid_product() {
        let p = make_product("myapp");
        assert!(p.validate().is_ok());
    }

    #[test]
    fn test_validate_empty_name() {
        let p = make_product("");
        assert!(p.validate().is_err());
    }

    #[test]
    fn test_validate_uppercase_name() {
        let p = make_product("MyApp");
        assert!(p.validate().is_err());
    }

    #[test]
    fn test_validate_name_with_underscore() {
        let p = make_product("my_app");
        assert!(p.validate().is_err());
    }

    #[test]
    fn test_validate_name_with_hyphen_ok() {
        let p = make_product("my-app");
        assert!(p.validate().is_ok());
    }

    #[test]
    fn test_validate_empty_environment() {
        let mut p = make_product("myapp");
        p.environment = "".to_string();
        assert!(p.validate().is_err());
    }

    #[test]
    fn test_validate_empty_cluster() {
        let mut p = make_product("myapp");
        p.cluster = "".to_string();
        assert!(p.validate().is_err());
    }
}
