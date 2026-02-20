//! # Deployment Configuration System
//!
//! Hierarchical configuration loading: Global → Product → Service
//!
//! ## Configuration Files
//!
//! 1. **Global** (`cli/deploy.yaml`)
//!    - Default values for all products and services
//!    - Registry settings, cache configuration, path patterns
//!
//! 2. **Product** (`pkgs/products/{product}/deploy.yaml`)
//!    - Product-specific overrides
//!    - Product name, environment, namespace settings
//!
//! 3. **Service** (`pkgs/products/{product}/services/rust/{service}/deploy.yaml`)
//!    - Service-specific overrides
//!    - Migration settings, federation routing, resource limits
//!
//! ## Example Usage
//!
//! ```rust,ignore
//! let config = DeployConfig::load_for_service("cart")?;
//! println!("Registry: {}", config.registry_url("cart"));
//! println!("Namespace: {}", config.kubernetes_namespace());
//! ```

mod deployment;
mod federation;
mod global;
mod kubernetes;
mod migration;
mod prerelease;
mod product;
pub mod product_release;
mod registry;
mod release;
mod service;

// Re-export all public types
pub use deployment::{
    AbSliceConfig, CloudflareConfig, DeploymentConfig, PreDeploymentTestExecution,
    PreDeploymentTestOnFailure, PreDeploymentTestSuite, PreDeploymentTestsConfig,
    ProductionStrategy,
};
pub use federation::{
    FederationConfig, FederationTestsConfig, FederationTestsServiceConfig, ServiceFederationConfig,
    ServiceFederationTestsConfig,
};
pub use global::GlobalConfig;
pub use kubernetes::{KubernetesConfig, ManifestPaths, ManifestPathsConfig, PathsConfig};
pub use migration::{NovaSearchConfig, ServiceMigrationConfig};
pub use prerelease::{
    BackendGatesConfig, E2eGatesConfig, FrontendGatesConfig, IntegrationGatesConfig,
    MigrationGatesConfig, PostDeployGatesConfig, PreReleaseGatesConfig,
};
pub use product::{
    default_cluster, default_environment, DirsConfig, EndpointsConfig, K8sRepoConfig,
    ObservabilityConfig, ProductConfig, SeedConfig,
};
pub use product_release::{HealthCheckConfig, ProductReleaseConfig, ProductServiceConfig};
pub use registry::{CacheConfig, RegistryConfig};
pub use release::{ArtifactInfo, EnvironmentConfig, EnvironmentsConfig, ReleaseConfig};
pub use service::{LocalConfig, ServiceConfig};

use anyhow::{anyhow, bail, Context, Result};
use std::path::{Path, PathBuf};

/// Resolve the product directory.
///
/// Standalone repo: deploy.yaml at repo root with matching `name:` field → repo root IS the product dir.
/// Monorepo: falls back to `{repo_root}/pkgs/products/{product}`.
pub fn resolve_product_dir(repo_root: &Path, product: &str) -> PathBuf {
    let root_deploy = repo_root.join("deploy.yaml");
    if root_deploy.exists() {
        if let Ok(content) = std::fs::read_to_string(&root_deploy) {
            if let Ok(yaml) = serde_yaml::from_str::<serde_yaml::Value>(&content) {
                if yaml.get("name").and_then(|n| n.as_str()) == Some(product) {
                    return repo_root.to_path_buf();
                }
            }
        }
    }
    repo_root.join("pkgs/products").join(product)
}

/// Load product config directly from a product directory.
///
/// Reads `{product_dir}/deploy.yaml` and deserializes it as [`ProductConfig`].
/// Used by commands that take `--working-dir` (prerelease, codegen, sync, seed, etc.)
/// so they can access product-level configuration without knowing the product name
/// in advance.
pub fn load_product_config_from_dir(product_dir: &Path) -> Result<ProductConfig> {
    let config_path = product_dir.join("deploy.yaml");
    let content = std::fs::read_to_string(&config_path)
        .with_context(|| format!("Failed to read {}", config_path.display()))?;
    serde_yaml::from_str(&content)
        .with_context(|| format!("Failed to parse {}", config_path.display()))
}

/// Auto-discover the product name from `deploy.yaml` at the repo root.
///
/// Reads `{repo_root}/deploy.yaml` and returns the `name:` field.
/// Used by `ProductRelease` and `Rollback` when `--product` is not provided.
pub fn auto_discover_product(repo_root: &str) -> Result<String> {
    let deploy_path = Path::new(repo_root).join("deploy.yaml");
    let content = std::fs::read_to_string(&deploy_path)
        .with_context(|| format!("--product not specified and no deploy.yaml found at {}", deploy_path.display()))?;
    let yaml: serde_yaml::Value = serde_yaml::from_str(&content)
        .with_context(|| format!("Failed to parse {}", deploy_path.display()))?;
    yaml.get("name")
        .and_then(|n| n.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("deploy.yaml at {} has no 'name:' field — use --product to specify the product name", deploy_path.display()))
}

/// Resolve the root directory for k8s manifests.
///
/// If product deploy.yaml has `k8s.local`, resolve relative to product repo root.
/// Otherwise, manifests are in the same repo (product_repo_root).
pub fn resolve_k8s_repo_root(product_config: &ProductConfig, product_repo_root: &Path) -> PathBuf {
    if let Some(k8s) = &product_config.k8s {
        let k8s_path = Path::new(&k8s.local);
        if k8s_path.is_absolute() {
            k8s_path.to_path_buf()
        } else {
            product_repo_root
                .join(k8s_path)
                .canonicalize()
                .unwrap_or_else(|_| product_repo_root.join(k8s_path))
        }
    } else {
        product_repo_root.to_path_buf()
    }
}

/// Resolve the path to a service's deploy.yaml.
///
/// Checks `{product_dir}/deploy/{service_name}.yaml` first (new convention that
/// keeps deploy configs outside Nix source trees), then falls back to
/// `{service_dir}/deploy.yaml` for backward compatibility with other products.
pub fn resolve_deploy_yaml_path(product_dir: &Path, service_name: &str, service_dir: &Path) -> PathBuf {
    let new_path = product_dir.join("deploy").join(format!("{}.yaml", service_name));
    if new_path.exists() {
        new_path
    } else {
        service_dir.join("deploy.yaml")
    }
}

/// Resolve the path to a service's artifact.json.
///
/// Machine-managed file storing artifact metadata (tag, previous_tag, built_at).
/// Located at `{product_dir}/deploy/{service_name}.artifact.json`.
pub fn resolve_artifact_json_path(product_dir: &Path, service_name: &str) -> PathBuf {
    product_dir.join("deploy").join(format!("{}.artifact.json", service_name))
}

/// Load artifact info from the JSON file, falling back to deploy.yaml for migration.
pub fn load_artifact_info(product_dir: &Path, service_name: &str, service_dir: &Path) -> Option<ArtifactInfo> {
    let json_path = resolve_artifact_json_path(product_dir, service_name);
    if json_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&json_path) {
            if let Ok(artifact) = serde_json::from_str::<ArtifactInfo>(&content) {
                return Some(artifact);
            }
        }
    }

    // Fallback: read from deploy.yaml for backward compatibility
    let yaml_path = resolve_deploy_yaml_path(product_dir, service_name, service_dir);
    if yaml_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&yaml_path) {
            if let Ok(yaml) = serde_yaml::from_str::<serde_yaml::Value>(&content) {
                if let Some(release) = yaml.get("release") {
                    if let Some(artifact) = release.get("artifact") {
                        return serde_yaml::from_value(artifact.clone()).ok();
                    }
                }
            }
        }
    }

    None
}

/// Complete deployment configuration (merged from all levels)
#[derive(Debug, Clone)]
pub struct DeployConfig {
    /// Global configuration
    pub global: GlobalConfig,

    /// Product configuration
    pub product: ProductConfig,

    /// Service configuration
    pub service: ServiceConfig,
}

impl DeployConfig {
    /// Load configuration for a specific service
    ///
    /// Root flake pattern (ONLY supported pattern):
    /// - Requires SERVICE_DIR environment variable (set by CLI --service-dir parameter)
    /// - Requires REPO_ROOT environment variable (set by CLI --repo-root parameter)
    ///
    /// Searches for configuration files in this order:
    /// 1. Service directory (for service-level deploy.yaml)
    /// 2. Product directory (for product-level deploy.yaml)
    /// 3. Repository root (for global deploy.yaml)
    ///
    /// # Errors
    /// Returns error if SERVICE_DIR not set or product directory cannot be found
    pub fn load_for_service(service_name: &str) -> Result<Self> {
        // Root flake pattern: SERVICE_DIR environment variable is REQUIRED
        let service_dir = std::env::var("SERVICE_DIR")
            .context(
                "SERVICE_DIR environment variable not set.\n  \
                 This tool requires the root flake pattern with --service-dir and --repo-root parameters.\n  \
                 Service-level flakes are no longer supported.",
            )
            .map(PathBuf::from)?;

        // Find product directory early so we can resolve deploy.yaml from
        // the deploy/ directory (outside the Nix source tree).
        let product_dir_for_resolve = Self::find_product_directory(&service_dir).ok();

        // Load service-level config (optional)
        let service_config_path = if let Some(ref pd) = product_dir_for_resolve {
            resolve_deploy_yaml_path(pd, service_name, &service_dir)
        } else {
            service_dir.join("deploy.yaml")
        };
        let service_config: Option<ServiceConfig> = if service_config_path.exists() {
            let content = std::fs::read_to_string(&service_config_path).with_context(|| {
                format!(
                    "Failed to read service config file: {}\n  Ensure the file is readable and not corrupted.",
                    service_config_path.display()
                )
            })?;

            Some(serde_yaml::from_str(&content).with_context(|| {
                format!(
                    "Failed to parse service config: {}\n  Check YAML syntax. Common issues:\n  \
                     - Incorrect indentation\n  \
                     - Missing quotes around strings with special characters\n  \
                     - Invalid field names (see CONFIGURATION.md for reference)",
                    service_config_path.display()
                )
            })?)
        } else {
            None
        };

        // Find product directory by walking up from service directory
        let product_dir = Self::find_product_directory(&service_dir).context(
            "Failed to find product directory.\n  \
                 Expected directory structure: pkgs/products/{product}/services/rust/{service}\n  \
                 Are you running from inside a service directory?",
        )?;

        let product_name = product_dir
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| {
                anyhow!(
                    "Failed to determine product name from directory: {}\n  \
                 Product directory path contains invalid UTF-8 characters",
                    product_dir.display()
                )
            })?
            .to_string();

        // Load product-level config (optional)
        let product_config_path = product_dir.join("deploy.yaml");
        let product_config_partial: Option<ProductConfig> = if product_config_path.exists() {
            let content = std::fs::read_to_string(&product_config_path).with_context(|| {
                format!(
                    "Failed to read product config file: {}\n  Ensure the file is readable.",
                    product_config_path.display()
                )
            })?;

            Some(serde_yaml::from_str(&content).with_context(|| {
                format!(
                    "Failed to parse product config: {}\n  Check YAML syntax (see CONFIGURATION.md)",
                    product_config_path.display()
                )
            })?)
        } else {
            None
        };

        // Load global config (optional)
        // Try to get repo root from environment variable first (set by --repo-root parameter)
        // Otherwise use find_repo_root to walk up directory tree
        let repo_root = Self::get_repo_root().context(
            "Failed to find repository root.\n  \
                 Are you inside a git repository?\n  \
                 Ensure git is available and you're in a git working directory.",
        )?;

        let global_config_path = repo_root.join("cli/deploy.yaml");
        let global_config: GlobalConfig = if global_config_path.exists() {
            let content = std::fs::read_to_string(&global_config_path).with_context(|| {
                format!(
                    "Failed to read global config file: {}\n  Ensure the file is readable.",
                    global_config_path.display()
                )
            })?;

            serde_yaml::from_str(&content).with_context(|| {
                format!(
                    "Failed to parse global config: {}\n  Check YAML syntax (see CONFIGURATION.md)",
                    global_config_path.display()
                )
            })?
        } else {
            GlobalConfig::default()
        };

        // Merge configurations (service overrides product overrides global)
        let product = product_config_partial.unwrap_or_else(|| ProductConfig {
            name: product_name.clone(),
            environment: default_environment(),
            cluster: default_cluster(),
            release: None,
            k8s: None,
            domain: None,
            observability: Default::default(),
            seed: Default::default(),
            dirs: Default::default(),
            endpoints: Default::default(),
        });

        let service = service_config.unwrap_or_else(|| ServiceConfig {
            name: service_name.to_string(),
            migration: ServiceMigrationConfig::default(),
            graphql: ServiceFederationConfig::default(),
            federation_tests: ServiceFederationTestsConfig::default(),
            federation_tests_service: FederationTestsServiceConfig::default(),
            deployment: None,
            federation: None,
            kubernetes: None,
            manifests: ManifestPathsConfig::default(),
            novasearch: NovaSearchConfig::default(),
            local: LocalConfig::default(),
            release: ReleaseConfig::default(),
            environments: std::collections::HashMap::new(),
            environment_aliases: std::collections::HashMap::new(),
            prerelease: PreReleaseGatesConfig::default(),
        });

        // Validate product configuration
        product.validate().with_context(|| {
            format!(
                "Invalid product configuration for '{}'\n  \
                 Check product name, environment, and cluster in deploy.yaml",
                product.name
            )
        })?;

        // Validate migration configuration
        service.migration.validate().with_context(|| {
            format!(
                "Invalid migration configuration for service '{}'\n  \
                 Check resource specifications in deploy.yaml (see CONFIGURATION.md)",
                service.name
            )
        })?;

        // Validate GraphQL/federation configuration
        service.graphql.validate(&service.name).with_context(|| {
            format!(
                "Invalid GraphQL/federation configuration for service '{}'\n  \
                 Check federation settings in deploy.yaml (see CONFIGURATION.md)",
                service.name
            )
        })?;

        // Validate federation tests configuration
        service
            .federation_tests
            .validate(&service.name)
            .with_context(|| {
                format!(
                    "Invalid federation tests configuration for service '{}'\n  \
                 Check federation_tests settings in deploy.yaml (see CONFIGURATION.md)",
                    service.name
                )
            })?;

        // Validate deployment configuration
        // Check service-level override first, then global
        if let Some(ref deployment) = service.deployment {
            deployment.validate().with_context(|| {
                format!(
                    "Invalid deployment configuration for service '{}'\n  \
                     Check deployment settings in service deploy.yaml",
                    service.name
                )
            })?;
        } else {
            global_config.deployment.validate().with_context(|| {
                "Invalid global deployment configuration\n  \
                     Check deployment settings in cli/deploy.yaml"
            })?;
        }

        // Validate Cloudflare configuration
        global_config.cloudflare.validate().with_context(|| {
            "Invalid Cloudflare configuration\n  \
                 Check cloudflare settings in deploy.yaml"
        })?;

        // Validate release configuration
        service.release.validate().with_context(|| {
            format!(
                "Invalid release configuration for service '{}'\n  \
                 Check release settings in deploy.yaml",
                service.name
            )
        })?;

        // Log configuration sources for debugging
        eprintln!("📋 Configuration loaded from:");
        eprintln!(
            "   Product: {} (from {})",
            product_name,
            if product_config_path.exists() {
                "deploy.yaml"
            } else {
                "defaults"
            }
        );
        eprintln!(
            "   Service: {} (from {})",
            service_name,
            if service_config_path.exists() {
                "deploy.yaml"
            } else {
                "defaults"
            }
        );
        eprintln!(
            "   Global: {}",
            if global_config_path.exists() {
                "cli/deploy.yaml"
            } else {
                "built-in defaults"
            }
        );

        Ok(Self {
            global: global_config,
            product,
            service,
        })
    }

    /// Load product-level deploy.yaml for the product-release orchestrator.
    ///
    /// Returns the product config with the optional `release` section parsed.
    /// This does NOT load service-level configs.
    pub fn load_product_config(product: &str, repo_root: &str) -> Result<ProductConfig> {
        let product_dir = resolve_product_dir(Path::new(repo_root), product);
        let config_path = product_dir.join("deploy.yaml");

        if !config_path.exists() {
            bail!(
                "Product deploy.yaml not found at {}\n  \
                 Expected: deploy.yaml (or pkgs/products/{}/deploy.yaml in monorepo)",
                config_path.display(),
                product
            );
        }

        let content = std::fs::read_to_string(&config_path)
            .with_context(|| format!("Failed to read product config: {}", config_path.display()))?;

        let config: ProductConfig = serde_yaml::from_str(&content).with_context(|| {
            format!("Failed to parse product config: {}", config_path.display())
        })?;

        Ok(config)
    }

    /// Load the product-level release orchestration config.
    ///
    /// Parses the `release:` section of the product deploy.yaml as a
    /// `ProductReleaseConfig`. Returns default if the section is missing.
    pub fn load_product_release_config(
        product: &str,
        repo_root: &str,
    ) -> Result<ProductReleaseConfig> {
        let product_dir = resolve_product_dir(Path::new(repo_root), product);
        let config_path = product_dir.join("deploy.yaml");

        if !config_path.exists() {
            return Ok(ProductReleaseConfig::default());
        }

        let content = std::fs::read_to_string(&config_path)
            .with_context(|| format!("Failed to read product config: {}", config_path.display()))?;

        let yaml: serde_yaml::Value = serde_yaml::from_str(&content).with_context(|| {
            format!("Failed to parse product config: {}", config_path.display())
        })?;

        match yaml.get("release") {
            Some(release_val) => {
                let release_config: ProductReleaseConfig =
                    serde_yaml::from_value(release_val.clone()).with_context(|| {
                        "Failed to parse release section in product deploy.yaml"
                    })?;
                Ok(release_config)
            }
            None => Ok(ProductReleaseConfig::default()),
        }
    }

    /// Load a service-level ReleaseConfig from its deploy.yaml.
    ///
    /// Used by `product-release` to check `build_environments` and `artifact` fields.
    /// Artifact metadata is loaded from `{service}.artifact.json` (machine-managed),
    /// with fallback to the `release.artifact` YAML section for backward compatibility.
    pub fn load_service_release_config(
        product: &str,
        service_path: &str,
        repo_root: &str,
    ) -> Result<ReleaseConfig> {
        let product_dir = resolve_product_dir(Path::new(repo_root), product);
        let service_dir = product_dir.join(service_path);
        let service_name = Path::new(service_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(service_path);
        let config_path = resolve_deploy_yaml_path(&product_dir, service_name, &service_dir);

        if !config_path.exists() {
            return Ok(ReleaseConfig::default());
        }

        let content = std::fs::read_to_string(&config_path)
            .with_context(|| format!("Failed to read service config: {}", config_path.display()))?;

        let yaml: serde_yaml::Value = serde_yaml::from_str(&content).with_context(|| {
            format!("Failed to parse service config: {}", config_path.display())
        })?;

        match yaml.get("release") {
            Some(release_val) => {
                let mut release_config: ReleaseConfig =
                    serde_yaml::from_value(release_val.clone()).with_context(|| {
                        format!(
                            "Failed to parse release section in {}",
                            config_path.display()
                        )
                    })?;

                // Override artifact from JSON file (machine-managed, takes priority)
                if let Some(artifact) =
                    load_artifact_info(&product_dir, service_name, &service_dir)
                {
                    release_config.artifact = Some(artifact);
                }

                Ok(release_config)
            }
            None => Ok(ReleaseConfig::default()),
        }
    }

    /// Load the registry URL from a service's deploy.yaml.
    ///
    /// Used by `product-release` for deploy-only environments.
    pub fn load_service_registry_url(
        product: &str,
        service_path: &str,
        repo_root: &str,
    ) -> Result<String> {
        let product_dir = resolve_product_dir(Path::new(repo_root), product);
        let service_dir = product_dir.join(service_path);
        let service_name = Path::new(service_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(service_path);
        let config_path = resolve_deploy_yaml_path(&product_dir, service_name, &service_dir);

        let content = std::fs::read_to_string(&config_path)
            .with_context(|| format!("Failed to read service config: {}", config_path.display()))?;

        let yaml: serde_yaml::Value = serde_yaml::from_str(&content).with_context(|| {
            format!("Failed to parse service config: {}", config_path.display())
        })?;

        yaml.get("registry")
            .and_then(|r| r.get("url"))
            .and_then(|u| u.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("registry.url not found in {}/deploy.yaml", service_path))
    }

    /// Load the Kubernetes namespace for a given environment from a service's deploy.yaml.
    ///
    /// Resolves environment aliases before looking up the namespace.
    /// Used by `product-release` for health checks after deployment.
    pub fn load_service_namespace(
        product: &str,
        service_path: &str,
        repo_root: &str,
        env_name: &str,
    ) -> Result<String> {
        let product_dir = resolve_product_dir(Path::new(repo_root), product);
        let service_dir = product_dir.join(service_path);
        let service_name = Path::new(service_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(service_path);
        let config_path = resolve_deploy_yaml_path(&product_dir, service_name, &service_dir);

        let content = std::fs::read_to_string(&config_path)
            .with_context(|| format!("Failed to read service config: {}", config_path.display()))?;

        let yaml: serde_yaml::Value = serde_yaml::from_str(&content).with_context(|| {
            format!("Failed to parse service config: {}", config_path.display())
        })?;

        // Resolve environment aliases (e.g. "production" → "production-a")
        let resolved_env = yaml
            .get("environment_aliases")
            .and_then(|a| a.get(env_name))
            .and_then(|e| e.as_str())
            .unwrap_or(env_name);

        yaml.get("environments")
            .and_then(|e| e.get(resolved_env))
            .and_then(|e| e.get("namespace"))
            .and_then(|n| n.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                anyhow!(
                    "namespace not found for environment '{}' in {}/deploy.yaml\n  \
                     Expected: environments.{}.namespace",
                    env_name,
                    service_path,
                    resolved_env
                )
            })
    }

    /// Find the product directory by walking up from current directory
    ///
    /// Looks for a directory matching: pkgs/products/{product_name}
    /// Also checks if the git repo root has a deploy.yaml with a `name:` field (standalone repo).
    fn find_product_directory(start: &Path) -> Result<PathBuf> {
        let mut current = start.to_path_buf();

        loop {
            // Check if we're inside pkgs/products/{something}
            if let Some(parent) = current.parent() {
                if let Some(grandparent) = parent.parent() {
                    if parent.file_name().and_then(|n| n.to_str()) == Some("products")
                        && grandparent.file_name().and_then(|n| n.to_str()) == Some("pkgs")
                    {
                        return Ok(current);
                    }
                }
            }

            // Check if current directory is a git root with deploy.yaml (standalone repo)
            if current.join(".git").exists() && current.join("deploy.yaml").exists() {
                if let Ok(content) = std::fs::read_to_string(current.join("deploy.yaml")) {
                    if let Ok(yaml) = serde_yaml::from_str::<serde_yaml::Value>(&content) {
                        if yaml.get("name").and_then(|n| n.as_str()).is_some() {
                            return Ok(current);
                        }
                    }
                }
            }

            // Move up one level
            if let Some(parent) = current.parent() {
                current = parent.to_path_buf();
            } else {
                bail!("Could not find product directory (expected pkgs/products/{{product}} or standalone repo with deploy.yaml)");
            }
        }
    }

    /// Find repository root by looking for .git directory
    pub fn find_repo_root(start: &Path) -> Result<PathBuf> {
        let mut current = start.to_path_buf();

        loop {
            if current.join(".git").exists() {
                return Ok(current);
            }

            if let Some(parent) = current.parent() {
                current = parent.to_path_buf();
            } else {
                bail!("Could not find repository root (.git directory)");
            }
        }
    }

    /// Get repository root, checking REPO_ROOT environment variable first
    /// Delegates to git::get_repo_root() which centralizes the logic
    fn get_repo_root() -> Result<PathBuf> {
        crate::git::get_repo_root()
    }

    /// Build full registry URL for a service
    ///
    /// Example: `ghcr.io/org/project/myproduct-api`
    pub fn registry_url(&self) -> String {
        self.global
            .registry
            .image_pattern
            .replace("{host}", &self.global.registry.host)
            .replace("{organization}", &self.global.registry.organization)
            .replace("{project}", &self.global.registry.project)
            .replace("{product}", &self.product.name)
            .replace("{service}", &self.service.name)
    }

    /// Build Kubernetes namespace
    ///
    /// Example: `myproduct-staging`
    pub fn kubernetes_namespace(&self) -> String {
        self.global
            .kubernetes
            .namespace_pattern
            .replace("{product}", &self.product.name)
            .replace("{environment}", &self.product.environment)
    }

    /// Build Kubernetes label selector
    ///
    /// Uses standard Kubernetes labeling: `app={product}-{service},product={product}`
    /// Example: `app=myapp-backend,product=myapp`
    pub fn kubernetes_label_selector(&self) -> String {
        // Build the app label value as {product}-{service} to match K8s resource labels
        // e.g., myproduct-backend, myproduct-api
        let app_value = format!("{}-{}", self.product.name, self.service.name);
        format!(
            "{}={},{}={}",
            self.global.kubernetes.service_label_key,
            app_value,
            self.global.kubernetes.product_label_key,
            self.product.name
        )
    }

    /// Build federation routing URL for a service
    ///
    /// Example: `http://{service}.{product}-{environment}:8080/graphql`
    pub fn federation_routing_url(&self) -> String {
        // Use service-level override if present, otherwise global
        let federation = self
            .service
            .federation
            .as_ref()
            .unwrap_or(&self.global.federation);

        federation
            .routing_url_pattern
            .replace("{protocol}", &federation.protocol)
            .replace("{service}", &self.service.name)
            .replace("{product}", &self.product.name)
            .replace("{environment}", &self.product.environment)
            .replace("{port}", &federation.port.to_string())
    }

    /// Build path to Hive Router federation directory
    ///
    /// Example: `../../../../../../pkgs/products/{product}/infrastructure/hive-router`
    ///
    /// # Errors
    /// Returns error if current directory is inaccessible or not in a git repository
    pub fn federation_directory(&self) -> Result<PathBuf> {
        let repo_root = Self::get_repo_root()?;
        Ok(repo_root
            .join(&self.global.paths.products_root)
            .join(&self.product.name)
            .join(&self.global.paths.federation_path))
    }

    /// Build path to Kubernetes manifest
    ///
    /// Example: `nix/k8s/clusters/{cluster}/products/{product}-{environment}/services/{service}/kustomization.yaml`
    ///
    /// # Errors
    /// Returns error if current directory is inaccessible or not in a git repository
    pub fn k8s_manifest_path(&self) -> Result<PathBuf> {
        let repo_root = Self::get_repo_root()?;
        let product_dir = resolve_product_dir(&repo_root, &self.product.name);
        let manifest_root = resolve_k8s_repo_root(&self.product, &product_dir);

        // Use explicit manifest path from deploy.yaml if specified
        // First check environment-specific paths, then fall back to flat structure
        if let Some(kustomization_path) = self
            .service
            .manifests
            .kustomization_for_env(&self.product.environment)
        {
            return Ok(manifest_root.join(kustomization_path));
        }

        // Fall back to computed path pattern
        let pattern = &self.global.paths.k8s_manifest_pattern;
        let path_str = pattern
            .replace("{cluster}", &self.product.cluster)
            .replace("{product}", &self.product.name)
            .replace("{environment}", &self.product.environment)
            .replace("{service}", &self.service.name);

        Ok(manifest_root.join(path_str))
    }

    /// Build path to subgraph schema file
    ///
    /// Example: `pkgs/products/{product}/infrastructure/hive-router/subgraphs/{service}.graphql`
    ///
    /// # Errors
    /// Returns error if current directory is inaccessible or not in a git repository
    pub fn subgraph_schema_path(&self) -> Result<PathBuf> {
        let pattern = self
            .service
            .graphql
            .subgraph_path
            .as_ref()
            .map(|s| s.as_str())
            .unwrap_or(
                "pkgs/products/{product}/infrastructure/hive-router/subgraphs/{service}.graphql",
            );

        let path_str = pattern
            .replace("{product}", &self.product.name)
            .replace("{service}", &self.service.name)
            .replace("{cluster}", &self.product.cluster)
            .replace("{environment}", &self.product.environment);

        let repo_root = Self::get_repo_root()?;
        Ok(repo_root.join(path_str))
    }

    /// Build path to supergraph router deployment
    ///
    /// Example: `nix/k8s/clusters/{cluster}/products/{product}-{environment}/hive-router/supergraph.graphql`
    ///
    /// # Errors
    /// Returns error if current directory is inaccessible or not in a git repository
    pub fn supergraph_router_path(&self) -> Result<PathBuf> {
        let pattern = self
            .service
            .graphql
            .supergraph_router_path
            .as_ref()
            .map(|s| s.as_str())
            .unwrap_or(
                "nix/k8s/clusters/{cluster}/products/{product}-{environment}/hive-router/supergraph.graphql",
            );

        let path_str = pattern
            .replace("{product}", &self.product.name)
            .replace("{service}", &self.service.name)
            .replace("{cluster}", &self.product.cluster)
            .replace("{environment}", &self.product.environment);

        let repo_root = Self::get_repo_root()?;
        Ok(repo_root.join(path_str))
    }

    /// Get Attic cache server name
    pub fn cache_server(&self) -> &str {
        &self.global.cache.server
    }

    /// Get product name
    pub fn product_name(&self) -> &str {
        &self.product.name
    }

    /// Get service name
    pub fn service_name(&self) -> &str {
        &self.service.name
    }

    /// Resolve an environment name through aliases
    ///
    /// Example: "production" → "production-a" (if aliased)
    pub fn resolve_environment(&self, env: &str) -> String {
        self.service
            .environment_aliases
            .get(env)
            .cloned()
            .unwrap_or_else(|| env.to_string())
    }

    /// Get environments to deploy to based on mode
    ///
    /// - "all": Returns all environments in order from release.environment_order
    /// - "staging": Returns just staging
    /// - Other: Returns just that environment (after alias resolution)
    pub fn get_deployment_environments(&self, mode: &str) -> Vec<String> {
        match mode {
            "all" => self.service.release.environment_order.clone(),
            "staging" => vec!["staging".to_string()],
            env => vec![self.resolve_environment(env)],
        }
    }

    /// Get the kustomization path for a specific environment
    ///
    /// Looks up the path in manifests section, falling back to computed path
    pub fn k8s_manifest_path_for_env(&self, env: &str) -> Result<PathBuf> {
        let resolved_env = self.resolve_environment(env);
        let repo_root = Self::get_repo_root()?;
        let product_dir = resolve_product_dir(&repo_root, &self.product.name);
        let manifest_root = resolve_k8s_repo_root(&self.product, &product_dir);

        // Look up in manifests section first
        if let Some(kustomization_path) =
            self.service.manifests.kustomization_for_env(&resolved_env)
        {
            return Ok(manifest_root.join(kustomization_path));
        }

        // Fall back to computed path pattern
        let env_config = self.service.environments.get(&resolved_env);
        let cluster = env_config
            .map(|e| e.cluster.as_str())
            .unwrap_or(&self.product.cluster);
        let namespace = env_config
            .map(|e| e.namespace.as_str())
            .unwrap_or(&self.product.environment);

        let pattern = &self.global.paths.k8s_manifest_pattern;
        let path_str = pattern
            .replace("{cluster}", cluster)
            .replace("{product}", &self.product.name)
            .replace("{environment}", &resolved_env)
            .replace("{service}", &self.service.name);

        Ok(manifest_root.join(path_str))
    }

    /// Get environment configuration by name
    pub fn get_environment_config(&self, env: &str) -> Option<&EnvironmentConfig> {
        let resolved = self.resolve_environment(env);
        self.service.environments.get(&resolved)
    }

    /// Get default release mode from config
    pub fn default_release_mode(&self) -> &str {
        &self.service.release.default_mode
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let global = GlobalConfig::default();
        assert_eq!(global.registry.host, "ghcr.io");
        assert_eq!(global.cache.server, "cache");
        assert_eq!(global.kubernetes.product_label_key, "product");
    }

    fn make_test_service_config(name: &str) -> ServiceConfig {
        ServiceConfig {
            name: name.to_string(),
            migration: ServiceMigrationConfig::default(),
            graphql: ServiceFederationConfig::default(),
            federation_tests: ServiceFederationTestsConfig::default(),
            federation_tests_service: FederationTestsServiceConfig::default(),
            deployment: None,
            federation: None,
            kubernetes: None,
            manifests: ManifestPathsConfig::default(),
            novasearch: NovaSearchConfig::default(),
            local: LocalConfig::default(),
            release: ReleaseConfig::default(),
            environments: std::collections::HashMap::new(),
            environment_aliases: std::collections::HashMap::new(),
            prerelease: PreReleaseGatesConfig::default(),
        }
    }

    #[test]
    fn test_registry_url_building() {
        let config = DeployConfig {
            global: GlobalConfig::default(),
            product: ProductConfig {
                name: "myproduct".to_string(),
                environment: "staging".to_string(),
                cluster: "mycluster".to_string(),
                release: None,
                k8s: None,
                domain: None,
                observability: Default::default(),
                seed: Default::default(),
                dirs: Default::default(),
                endpoints: Default::default(),
            },
            service: make_test_service_config("api"),
        };

        assert_eq!(config.registry_url(), "ghcr.io/org/project/myproduct-api");
    }

    #[test]
    fn test_kubernetes_namespace() {
        let config = DeployConfig {
            global: GlobalConfig::default(),
            product: ProductConfig {
                name: "myproduct".to_string(),
                environment: "staging".to_string(),
                cluster: "mycluster".to_string(),
                release: None,
                k8s: None,
                domain: None,
                observability: Default::default(),
                seed: Default::default(),
                dirs: Default::default(),
                endpoints: Default::default(),
            },
            service: make_test_service_config("api"),
        };

        assert_eq!(config.kubernetes_namespace(), "myproduct-staging");
    }

    #[test]
    fn test_label_selector() {
        let config = DeployConfig {
            global: GlobalConfig::default(),
            product: ProductConfig {
                name: "myproduct".to_string(),
                environment: "staging".to_string(),
                cluster: "mycluster".to_string(),
                release: None,
                k8s: None,
                domain: None,
                observability: Default::default(),
                seed: Default::default(),
                dirs: Default::default(),
                endpoints: Default::default(),
            },
            service: make_test_service_config("api"),
        };

        assert_eq!(
            config.kubernetes_label_selector(),
            "app=myproduct-api,product=myproduct"
        );
    }

    #[test]
    fn test_environment_resolution() {
        let mut service = make_test_service_config("backend");
        service
            .environment_aliases
            .insert("production".to_string(), "production-a".to_string());

        let config = DeployConfig {
            global: GlobalConfig::default(),
            product: ProductConfig {
                name: "testapp".to_string(),
                environment: "staging".to_string(),
                cluster: "cluster-a".to_string(),
                release: None,
                k8s: None,
                domain: None,
                observability: Default::default(),
                seed: Default::default(),
                dirs: Default::default(),
                endpoints: Default::default(),
            },
            service,
        };

        // Direct resolution
        assert_eq!(config.resolve_environment("staging"), "staging");
        // Alias resolution
        assert_eq!(config.resolve_environment("production"), "production-a");
        // Unknown passes through
        assert_eq!(
            config.resolve_environment("production-b"),
            "production-b"
        );
    }

    #[test]
    fn test_deployment_environments() {
        let mut service = make_test_service_config("backend");
        service.release = ReleaseConfig {
            default_mode: "all".to_string(),
            environment_order: vec![
                "staging".to_string(),
                "production-a".to_string(),
                "production-b".to_string(),
            ],
            wait_between_environments: false,
            continue_on_failure: false,
            build_environments: None,
            artifact: None,
            active_environments: None,
        };

        let config = DeployConfig {
            global: GlobalConfig::default(),
            product: ProductConfig {
                name: "testapp".to_string(),
                environment: "staging".to_string(),
                cluster: "cluster-a".to_string(),
                release: None,
                k8s: None,
                domain: None,
                observability: Default::default(),
                seed: Default::default(),
                dirs: Default::default(),
                endpoints: Default::default(),
            },
            service,
        };

        // Mode "all" returns all environments in order
        assert_eq!(
            config.get_deployment_environments("all"),
            vec!["staging", "production-a", "production-b"]
        );

        // Mode "staging" returns just staging
        assert_eq!(
            config.get_deployment_environments("staging"),
            vec!["staging"]
        );

        // Specific environment returns just that
        assert_eq!(
            config.get_deployment_environments("production-b"),
            vec!["production-b"]
        );
    }
}
