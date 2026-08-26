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
pub use release::{
    ArtifactInfo, AttestationInfoRecord, EnvironmentConfig, EnvironmentsConfig, ReleaseConfig,
};
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
    let content = std::fs::read_to_string(&deploy_path).with_context(|| {
        format!(
            "--product not specified and no deploy.yaml found at {}",
            deploy_path.display()
        )
    })?;
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
/// If the local path doesn't exist but `k8s.repo` is configured, auto-clone into a temp dir.
/// Otherwise, manifests are in the same repo (product_repo_root).
pub fn resolve_k8s_repo_root(product_config: &ProductConfig, product_repo_root: &Path) -> PathBuf {
    if let Some(k8s) = &product_config.k8s {
        let k8s_path = if Path::new(&k8s.local).is_absolute() {
            PathBuf::from(&k8s.local)
        } else {
            product_repo_root.join(&k8s.local)
        };

        if k8s_path.exists() {
            return k8s_path.canonicalize().unwrap_or(k8s_path);
        }

        // Auto-clone if repo URL is configured and local path doesn't exist
        if let Some(repo_url) = &k8s.repo {
            let clone_dir = std::env::temp_dir().join(format!(
                "forge-k8s-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis())
                    .unwrap_or(0)
            ));
            println!(
                "📦 Cloning k8s repo: {} → {}",
                repo_url,
                clone_dir.display()
            );
            // Binary resolution rides `crate::git::git_command_sync()` so a
            // Nix-hermetic runner's `GIT_BIN` override wins over ambient
            // `PATH` at k8s-repo clone time — same discipline the sync
            // sibling `commands/helm.rs::deploy` git-mutation sites honor
            // (0d922f6) and the async `commands/push.rs` /
            // `commands/rollback.rs` / `commands/codegen_validation.rs` /
            // `commands/federation.rs` sites drive through
            // `git_command_async`. Retains the pre-migration best-effort
            // `.status()` shape — the auto-clone is advisory, and callers
            // fall back to the local path on any failure via the
            // `Ok(s) if s.success()` gate below.
            let status = crate::git::git_command_sync()
                .args([
                    "clone",
                    "--depth",
                    "1",
                    "--branch",
                    &k8s.branch,
                    repo_url,
                    &clone_dir.to_string_lossy(),
                ])
                .status();
            match status {
                Ok(s) if s.success() => return clone_dir,
                Ok(s) => eprintln!(
                    "⚠️  k8s repo clone failed (exit {}), falling back to local path",
                    s.code().unwrap_or(-1)
                ),
                Err(e) => eprintln!(
                    "⚠️  Failed to run git clone: {}, falling back to local path",
                    e
                ),
            }
        }

        // Fall through: path doesn't exist and no repo URL (or clone failed)
        k8s_path
    } else {
        product_repo_root.to_path_buf()
    }
}

/// Resolve the path to a service's deploy.yaml.
///
/// Checks `{product_dir}/deploy/{service_name}.yaml` first (new convention that
/// keeps deploy configs outside Nix source trees), then falls back to
/// `{service_dir}/deploy.yaml` for backward compatibility with other products.
pub fn resolve_deploy_yaml_path(
    product_dir: &Path,
    service_name: &str,
    service_dir: &Path,
) -> PathBuf {
    let new_path = product_dir
        .join("deploy")
        .join(format!("{}.yaml", service_name));
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
    product_dir
        .join("deploy")
        .join(format!("{}.artifact.json", service_name))
}

/// Load artifact info from the JSON file, falling back to deploy.yaml for migration.
pub fn load_artifact_info(
    product_dir: &Path,
    service_name: &str,
    service_dir: &Path,
) -> Option<ArtifactInfo> {
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
        let service_dir = crate::repo::path_from_env(
            "SERVICE_DIR",
            "SERVICE_DIR environment variable not set.\n  \
             This tool requires the root flake pattern with --service-dir and --repo-root parameters.\n  \
             Service-level flakes are no longer supported.",
        )?;

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
                let mut release_config: ReleaseConfig = serde_yaml::from_value(release_val.clone())
                    .with_context(|| {
                        format!(
                            "Failed to parse release section in {}",
                            config_path.display()
                        )
                    })?;

                // Override artifact from JSON file (machine-managed, takes priority)
                if let Some(artifact) = load_artifact_info(&product_dir, service_name, &service_dir)
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

    /// Find the product directory by walking up from `start`.
    ///
    /// Delegates to [`crate::repo::find_product_dir`] with
    /// [`crate::repo::ProductDirLayout::MonorepoOrNamedStandalone`] — the
    /// fifth consumer of the shared parent-climb walker archetype (see
    /// that function's doc for the walker's mechanics and the fused site
    /// inventory). The `bail!` message here maps the archetype's `None`
    /// return to the `Result<PathBuf>` shape the rest of the config
    /// loader expects.
    fn find_product_directory(start: &Path) -> Result<PathBuf> {
        crate::repo::find_product_dir(
            start,
            crate::repo::ProductDirLayout::MonorepoOrNamedStandalone,
        )
        .ok_or_else(|| {
            anyhow!(
                "Could not find product directory (expected pkgs/products/{{product}} or standalone repo with deploy.yaml)"
            )
        })
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
        assert_eq!(config.resolve_environment("production-b"), "production-b");
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

    /// Regression-shield: the auto-clone spawn in
    /// [`resolve_k8s_repo_root`] MUST resolve `git` through
    /// [`crate::git::git_command_sync`] rather than the pre-lift
    /// `std::process::Command::new("git")` literal. Pre-migration the
    /// single site bypassed the `GIT_BIN` env override the
    /// `tools::get_tool_path(tools::GIT)` idiom
    /// (cli/src/tools.rs:102-105) resolves — the same class of bug
    /// the sibling `flux` / `cargo` / `doca` / free-function-`git` /
    /// `GitClient` / `commands/federation.rs` / `commands/push.rs` /
    /// `commands/codegen_validation.rs` / `commands/rollback.rs` /
    /// `commands/helm.rs::deploy` migrations redeemed at 621f827 /
    /// f0dfa12 / d3dd199 / 685642f / d6f6bc7 / dd5a212 / 673e4be /
    /// b02d4eb / 54a9985 / 139b37a / 818ed9a / badcdf4 / 8653403 /
    /// f6be190 / 81d7486 / 8a1958e / 0d922f6. Lifts the sync half of
    /// the routing discipline into the second consumer of
    /// `git_command_sync` — the first sync consumer landed on
    /// `helm::deploy` at 0d922f6.
    ///
    /// This test reads this module's own source via [`include_str!`]
    /// and asserts the raw `Command::new("git")` string does not
    /// reappear in `resolve_k8s_repo_root` while the delegation to
    /// `git_command_sync` does. A future regression that re-fuses
    /// the raw-spawn body fails here, not silently in production
    /// where a Nix-hermetic runner's `GIT_BIN`-provided `git` would
    /// lose to whatever `git` is first on `PATH` at k8s-repo clone
    /// time.
    ///
    /// The check is deliberately structural (substring on the source
    /// text) rather than behavioral — the end-to-end `GIT_BIN`-
    /// routing invariant is already pinned by
    /// [`crate::git::tests::test_git_command_sync_routes_through_git_bin_env_var`]
    /// on the primitive itself; this shield only certifies that the
    /// `resolve_k8s_repo_root` git spawn reads through that
    /// primitive. Mirrors the sibling shield on
    /// `commands/helm.rs::deploy` for the sync half of the surface.
    #[test]
    fn test_resolve_k8s_repo_root_routes_git_through_git_command_sync_not_raw_command() {
        const SOURCE: &str = include_str!("mod.rs");

        // Bound the scan to `resolve_k8s_repo_root` — the single git
        // spawn site lives inside it. Docstrings on the primitive and
        // sibling functions in this module legitimately reference the
        // pre-migration literal, so scoping the check to the target
        // function's body avoids false positives.
        // Bound the fn body between `resolve_k8s_repo_root`'s header
        // and the next top-level `pub fn` in source order
        // (`resolve_deploy_yaml_path`), which follows
        // `resolve_k8s_repo_root`.
        let fn_body = crate::test_support::fn_body_slice_between_markers(
            SOURCE,
            "config/mod.rs",
            "pub fn resolve_k8s_repo_root(",
            "\npub fn resolve_deploy_yaml_path(",
        );

        assert!(
            !fn_body.contains("Command::new(\"git\")"),
            "resolve_k8s_repo_root() must NOT spawn `git` directly — \
             route through `crate::git::git_command_sync()` so \
             `GIT_BIN` overrides land at the shared primitive. Found \
             the pre-migration spawn body in resolve_k8s_repo_root()."
        );
        assert!(
            fn_body.contains("crate::git::git_command_sync()"),
            "resolve_k8s_repo_root() must delegate the git spawn to \
             `crate::git::git_command_sync()` — the delegation string \
             was not found in resolve_k8s_repo_root()."
        );
    }

    /// Whole-module shield: every read of the `SERVICE_DIR` env var in
    /// this module's non-test body must route through the shared
    /// [`crate::repo::path_from_env`] primitive (introduced at
    /// `repo.rs:127` by d8e6626), never through an inline
    /// `std::env::var("SERVICE_DIR").context(...).map(PathBuf::from)?`
    /// stanza.
    ///
    /// Pre-lift the single consumer site — `DeployConfig::load_for_service`
    /// at `config/mod.rs:287` — spelled the same
    /// `env::var("SERVICE_DIR").context("SERVICE_DIR environment
    /// variable not set.\n  ...")?` + `.map(PathBuf::from)?` stanza
    /// verbatim, with a fourth distinct operator-facing miss wording
    /// (the multi-line prose naming the root-flake pattern and the
    /// removed service-level-flakes path) beyond the three d8e6626 and
    /// 1452f53 catalogued (`developer_tools`, `schema_validation`,
    /// `rust_service`). This shield closes the drift class at four on
    /// the same idiom — the three sibling shields (`developer_tools.rs`
    /// at 1121, `schema_validation.rs` at 450, `rust_service.rs` at
    /// 3170) cover their respective modules; this shield covers the
    /// last direct-inline caller of the pre-lift stanza.
    ///
    /// A future refinement of the `SERVICE_DIR` contract — a
    /// canonicalize hook, a substrate-path validation step, a
    /// telemetry sigil on the resolved path, or a swap to a typed
    /// `substrate::ServiceDir(PathBuf)` newtype — lands at ONE body
    /// ([`crate::repo::path_from_env`]) and reaches every consumer
    /// (this call + the three sibling shields' delegating call sites)
    /// by construction (THEORY §V — solve-once-at-the-primitive; §VI.1
    /// — recurring-shape-to-helper).
    ///
    /// Slice via [`crate::test_support::module_body_before_tests`]
    /// (`config/mod.rs` carries the canonical `#[cfg(test)]\nmod tests
    /// {` marker at line 1014, so the longer marker is the correct
    /// boundary and this shield's own docstring mentions of
    /// `env::var("SERVICE_DIR")` — living inside `mod tests {}` below
    /// that marker — stay out of scope). Every hit routes through
    /// [`crate::test_support::code_line_hits`] for anti-docstring-
    /// self-match discipline.
    #[test]
    fn test_config_service_dir_routes_through_path_from_env() {
        let body =
            crate::test_support::module_body_before_tests(include_str!("mod.rs"), "config/mod.rs");
        // Negative side: the raw `env::var("SERVICE_DIR")` needle must
        // NOT appear anywhere in the module body post-lift — the read
        // now lives at `crate::repo::path_from_env`, which owns the
        // read at ONE body across the crate. A future consumer that
        // re-copies the pre-lift stanza pushes this count above zero
        // and fails the shield before it can drift the miss wording or
        // the `PathBuf` projection away from the shared primitive's
        // single point of truth. Substring match catches both
        // `std::env::var("SERVICE_DIR")` and the shorter
        // `env::var("SERVICE_DIR")` (sibling modules spell both forms
        // and a future consumer here might spell either).
        let raw_env_needle = "env::var(\"SERVICE_DIR\")";
        let env_hits = crate::test_support::code_line_hits(body, raw_env_needle);
        assert!(
            env_hits.is_empty(),
            "config/mod.rs must NOT spell `{raw_env_needle}` inline in \
             the module body — every consumer must route through \
             `crate::repo::path_from_env`, the shared primitive that \
             owns the `env::var` read at ONE body across the crate. \
             Found {} code-line hit(s): {env_hits:#?}. A hand-rolled \
             inline copy re-opens the drift class the primitive was \
             landed to close.",
            env_hits.len()
        );
        // Positive side: the delegating call to
        // `crate::repo::path_from_env(` must appear at EXACTLY one
        // code line — the `DeployConfig::load_for_service` body. A
        // regression that dropped the delegation would leave the
        // negative scan trivially satisfied by absence (zero raw
        // `env::var` hits, but also zero delegating calls), and the
        // module would have stopped resolving `SERVICE_DIR` for
        // deploy-config load at all.
        let delegate_needle = "crate::repo::path_from_env(";
        let delegate_hits = crate::test_support::code_line_hits(body, delegate_needle);
        assert_eq!(
            delegate_hits.len(),
            1,
            "config/mod.rs must delegate `SERVICE_DIR` resolution to \
             `crate::repo::path_from_env(...)` at EXACTLY one code \
             line — the `DeployConfig::load_for_service` body. Found \
             {} code-line hit(s): {delegate_hits:#?}. A missing \
             delegation would leave the negative scan above trivially \
             satisfied by absence.",
            delegate_hits.len()
        );
        // Wording-preservation side: the domain-specific miss wording
        // — the fourth distinct wording across the SERVICE_DIR
        // consumer family (after `developer_tools`,
        // `schema_validation`, and `rust_service`) — must stay
        // grep-visible verbatim at the delegating call. A future
        // refactor that reshaped the miss wording (a swap to
        // `.with_context(||)` with drifted text, a lift to a typed
        // error variant, a canonicalize prefix landed in front) would
        // silently drift the multi-line prose the operator has been
        // coached to grep for. Match on the anchor phrase (the first
        // sentence, which is short enough to appear on a single
        // source line) rather than the whole multi-line wording so
        // rustfmt line-wrapping cannot silently drift the scan.
        let wording_needle = "SERVICE_DIR environment variable not set.";
        let wording_hits = crate::test_support::code_line_hits(body, wording_needle);
        assert!(
            !wording_hits.is_empty(),
            "config/mod.rs must preserve the canonical miss wording \
             `{wording_needle}` verbatim at the delegating call so a \
             refactor cannot silently drift the message every operator \
             has been coached to grep for. Found no code-line hit."
        );
    }
}
