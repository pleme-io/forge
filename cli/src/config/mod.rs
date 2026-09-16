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
mod nonblank;
mod prerelease;
mod product;
pub mod product_release;
mod registry;
mod release;
mod service;
mod validation_warning;

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
pub use validation_warning::write_validation_warning;

use anyhow::{anyhow, bail, Context, Result};
use std::path::{Path, PathBuf};

/// Resolve the product directory.
///
/// Standalone repo: deploy.yaml at repo root with matching `name:` field → repo root IS the product dir.
/// Monorepo: falls back to `{repo_root}/pkgs/products/{product}`.
pub fn resolve_product_dir(repo_root: &Path, product: &str) -> PathBuf {
    let root_deploy = repo_root.join("deploy.yaml");
    if let Some(yaml) = crate::repo::try_read_yaml_sync::<serde_yaml::Value>(&root_deploy) {
        if yaml.get("name").and_then(|n| n.as_str()) == Some(product) {
            return repo_root.to_path_buf();
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
    crate::repo::read_yaml_sync(&config_path)
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

/// Locate a service's `deploy.yaml` under the monorepo-fallback rule and
/// bail if it is missing.
///
/// Fuses the twelve-line `service_dir` → monorepo-`resolve_deploy_yaml_path`
/// with fallback → `.exists()` gate stanza that
/// [`commands/status::execute`](crate::commands::status) and
/// [`commands/integration_tests::execute_manual`](crate::commands::integration_tests)
/// each spelled verbatim immediately after
/// [`crate::repo::activate_root_flake`].
///
/// # Pre-lift shape
///
/// ```text
/// let service_dir_path = PathBuf::from(service_dir);
/// let deploy_yaml_path = if let Some(product_dir) =
///     crate::repo::find_product_dir(&service_dir_path, crate::repo::ProductDirLayout::Monorepo)
/// {
///     crate::config::resolve_deploy_yaml_path(&product_dir, service, &service_dir_path)
/// } else {
///     service_dir_path.join("deploy.yaml")
/// };
/// if !deploy_yaml_path.exists() {
///     anyhow::bail!("No deploy.yaml found at: {}", deploy_yaml_path.display());
/// }
/// ```
///
/// The primitive returns the resolved path so the caller can immediately
/// parse it via [`crate::repo::read_yaml_sync`] into a module-local
/// `RawDeployYaml` (the pre-lift consumers each carry their own
/// service-flavored deserialization type — status parses
/// `kubernetes`/`environments`, integration_tests parses
/// `deployment.integration_tests` — so the parse arm stays at the caller).
///
/// # Envelope
///
/// - Monorepo terminal via [`crate::repo::find_product_dir`] with
///   [`crate::repo::ProductDirLayout::Monorepo`], matching both pre-lift
///   consumers (a standalone-layout consumer would use a different
///   layout enum variant and would not share this shape).
/// - Path resolution via [`resolve_deploy_yaml_path`] when a product
///   directory is found; direct `{service_dir}/deploy.yaml` join
///   otherwise.
/// - Miss-arm bail wording is `"No deploy.yaml found at: {path.display()}"`
///   verbatim, so an operator who has been coached to grep for the
///   pre-lift phrasing still finds it in the crate.
///
/// # Errors
///
/// Returns `Err` if the resolved `deploy.yaml` does not exist on disk.
pub fn resolve_and_require_service_deploy_yaml_path(
    service: &str,
    service_dir: &str,
) -> Result<PathBuf> {
    let service_dir_path = PathBuf::from(service_dir);
    let deploy_yaml_path = if let Some(product_dir) =
        crate::repo::find_product_dir(&service_dir_path, crate::repo::ProductDirLayout::Monorepo)
    {
        resolve_deploy_yaml_path(&product_dir, service, &service_dir_path)
    } else {
        service_dir_path.join("deploy.yaml")
    };
    if !deploy_yaml_path.exists() {
        bail!("No deploy.yaml found at: {}", deploy_yaml_path.display());
    }
    Ok(deploy_yaml_path)
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
    if let Some(yaml) = crate::repo::try_read_yaml_sync::<serde_yaml::Value>(&yaml_path) {
        if let Some(release) = yaml.get("release") {
            if let Some(artifact) = release.get("artifact") {
                return serde_yaml::from_value(artifact.clone()).ok();
            }
        }
    }

    None
}

/// Persist [`ArtifactInfo`] to the service's `{service_name}.artifact.json`
/// under `{product_dir}/deploy/`, and return the resolved path.
///
/// The write-arm peer of [`load_artifact_info`] on the JSON surface: both
/// take the same `(product_dir, service_name)` tuple to resolve the file
/// via [`resolve_artifact_json_path`], and both target the same JSON
/// document — `load_artifact_info` deserializes via
/// `serde_json::from_str::<ArtifactInfo>`, this fn serializes via
/// `serde_json::to_string_pretty(&artifact)` and appends a trailing
/// newline so the file is line-terminated per POSIX. The
/// `.context("Failed to serialize artifact info")` envelope on the serde
/// step matches the two pre-lift sites verbatim.
///
/// # Envelope
///
/// Serialize failure surfaces `"Failed to serialize artifact info"`
/// (the pre-lift literal); the underlying write failure routes through
/// [`crate::repo::write_text_sync`]'s `"Failed to write {path}"` classifier,
/// so an operator can tell serde failures (a struct field carrying an
/// unrenderable value) from disk-side failures (EROFS, ENOSPC, EACCES)
/// without cross-referencing the caller.
///
/// The returned [`PathBuf`] is the resolved artifact-json path — every
/// pre-lift caller followed the write with a
/// `modified_files.push(crate::repo::path_to_string_lossy(&json_path))`
/// or a
/// [`commit_artifact_tags`](crate::commands::product_release) hand-off
/// that consumed the same path, so returning it removes the last
/// caller-side restatement of `resolve_artifact_json_path(product_dir,
/// service_name)` from the sibling class.
///
/// Pre-lift two sibling consumer sites spelled the primitive's shape
/// verbatim — `commands/product_release.rs::write_artifact_tags`
/// (b72c484:218–239) and `commands/rollback.rs::execute_rollback`
/// (b72c484:295–309) — each four-line stanza:
///
/// ```ignore
/// let json_path = crate::config::resolve_artifact_json_path(&product_dir, &<name>);
/// let json =
///     serde_json::to_string_pretty(&artifact).context("Failed to serialize artifact info")?;
/// crate::repo::write_text_sync(&json_path, format!("{}\n", json))?;
/// ```
///
/// Post-lift both collapse onto
/// `crate::config::write_artifact_info(&product_dir, &<name>, &artifact)?`,
/// with the returned [`PathBuf`] threaded into the caller's
/// `modified_files` accumulator.
pub fn write_artifact_info(
    product_dir: &Path,
    service_name: &str,
    artifact: &ArtifactInfo,
) -> Result<PathBuf> {
    let json_path = resolve_artifact_json_path(product_dir, service_name);
    let json =
        serde_json::to_string_pretty(artifact).context("Failed to serialize artifact info")?;
    crate::repo::write_text_sync(&json_path, format!("{}\n", json))?;
    Ok(json_path)
}

/// Product + service + config-path 4-tuple resolved from
/// `(product, service_path, repo_root)`.
///
/// Owns the 4-line preamble that three sibling
/// `DeployConfig::load_service_*` methods each spelled verbatim before
/// their yaml-parse step: [`DeployConfig::load_service_release_config`],
/// [`DeployConfig::load_service_registry_url`], and
/// [`DeployConfig::load_service_namespace`]. The four fields
/// (`product_dir`, `service_dir`, `service_name`, `config_path`) are
/// pure derivations of the input triple — a caller that has already
/// resolved them once should never re-derive.
///
/// Fields are exposed directly (public struct) rather than through
/// accessors so callers keep pattern-binding at the destructure site,
/// matching the pre-lift shape where the four bindings landed as four
/// `let` statements.
#[derive(Debug, Clone)]
pub struct ServiceDeployYamlLocation {
    /// Product-scoped directory: `resolve_product_dir(repo_root, product)`.
    pub product_dir: PathBuf,
    /// Service-scoped directory: `product_dir.join(service_path)`.
    pub service_dir: PathBuf,
    /// Service base name — the final path component of `service_path`,
    /// falling back to the full `service_path` when the input has no
    /// file-name component.
    pub service_name: String,
    /// Resolved `deploy.yaml` path via
    /// [`resolve_deploy_yaml_path(product_dir, service_name,
    /// service_dir)`](resolve_deploy_yaml_path).
    pub config_path: PathBuf,
}

/// Resolve the [`ServiceDeployYamlLocation`] 4-tuple from the
/// `(product, service_path, repo_root)` input triple that three sibling
/// `DeployConfig::load_service_*` methods each take.
///
/// # Pre-lift shape
///
/// ```ignore
/// let product_dir = resolve_product_dir(Path::new(repo_root), product);
/// let service_dir = product_dir.join(service_path);
/// let service_name = Path::new(service_path)
///     .file_name()
///     .and_then(|n| n.to_str())
///     .unwrap_or(service_path);
/// let config_path = resolve_deploy_yaml_path(&product_dir, service_name, &service_dir);
/// ```
///
/// Three consumer sites in this module spelled the stanza verbatim —
/// [`DeployConfig::load_service_release_config`],
/// [`DeployConfig::load_service_registry_url`], and
/// [`DeployConfig::load_service_namespace`] — before this primitive
/// landed. Post-lift each collapses onto
/// `let loc = locate_service_deploy_yaml(product, service_path, repo_root);`
/// and destructures the four fields at the caller.
pub fn locate_service_deploy_yaml(
    product: &str,
    service_path: &str,
    repo_root: &str,
) -> ServiceDeployYamlLocation {
    let product_dir = resolve_product_dir(Path::new(repo_root), product);
    let service_dir = product_dir.join(service_path);
    let service_name = Path::new(service_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(service_path)
        .to_string();
    let config_path = resolve_deploy_yaml_path(&product_dir, &service_name, &service_dir);
    ServiceDeployYamlLocation {
        product_dir,
        service_dir,
        service_name,
        config_path,
    }
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
            Some(crate::repo::read_yaml_sync_hinted(
                &service_config_path,
                &crate::repo::YamlLoadHints {
                    role: "service config",
                    read_hint: "Ensure the file is readable and not corrupted.",
                    parse_hint: "Check YAML syntax. Common issues:\n  \
                                 - Incorrect indentation\n  \
                                 - Missing quotes around strings with special characters\n  \
                                 - Invalid field names (see CONFIGURATION.md for reference)",
                },
            )?)
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
            Some(crate::repo::read_yaml_sync_hinted(
                &product_config_path,
                &crate::repo::YamlLoadHints {
                    role: "product config",
                    read_hint: "Ensure the file is readable.",
                    parse_hint: "Check YAML syntax (see CONFIGURATION.md)",
                },
            )?)
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
            crate::repo::read_yaml_sync_hinted(
                &global_config_path,
                &crate::repo::YamlLoadHints {
                    role: "global config",
                    read_hint: "Ensure the file is readable.",
                    parse_hint: "Check YAML syntax (see CONFIGURATION.md)",
                },
            )?
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

        let config: ProductConfig = crate::repo::read_yaml_sync(&config_path)?;
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

        let yaml: serde_yaml::Value = crate::repo::read_yaml_sync(&config_path)?;

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
        let ServiceDeployYamlLocation {
            product_dir,
            service_dir,
            service_name,
            config_path,
        } = locate_service_deploy_yaml(product, service_path, repo_root);

        if !config_path.exists() {
            return Ok(ReleaseConfig::default());
        }

        let yaml: serde_yaml::Value = crate::repo::read_yaml_sync(&config_path)?;

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
                if let Some(artifact) =
                    load_artifact_info(&product_dir, &service_name, &service_dir)
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
        let ServiceDeployYamlLocation { config_path, .. } =
            locate_service_deploy_yaml(product, service_path, repo_root);

        let yaml: serde_yaml::Value = crate::repo::read_yaml_sync(&config_path)?;

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
        let ServiceDeployYamlLocation { config_path, .. } =
            locate_service_deploy_yaml(product, service_path, repo_root);

        let yaml: serde_yaml::Value = crate::repo::read_yaml_sync(&config_path)?;

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

    /// Build path to the product directory under a caller-supplied
    /// `repo_root`. Structural base for every product-scoped path
    /// composition: `{repo_root}/{paths.products_root}/{product.name}`.
    ///
    /// Pure — no filesystem I/O, no `Result`. The caller resolves
    /// `repo_root` once (via `crate::git::get_repo_root()?`, a passed-in
    /// `k8s_repo_root`, or a test fixture) and hands it in.
    ///
    /// Sibling of [`Self::federation_directory`] which appends
    /// `paths.federation_path` to this same base; delegates through
    /// this method so the 2-hop `products_root + product.name` prefix
    /// lives at ONE body.
    ///
    /// Consumers under `commands/rust_service.rs` route
    /// `.version`-file writes, service-directory resolution for the
    /// pre-deployment / post-deployment test lookups, and the
    /// `product_dir` binding used by `resolve_deploy_yaml_path`
    /// through this same primitive — the 5 raw
    /// `repo_root.join(&deploy_config.global.paths.products_root)
    /// .join(&deploy_config.product.name)` stanzas collapsed onto
    /// this single method, and the negative caller shield below
    /// forbids the raw form under `cli/src/commands/`.
    pub fn product_directory_under(&self, repo_root: &Path) -> PathBuf {
        repo_root
            .join(&self.global.paths.products_root)
            .join(&self.product.name)
    }

    /// Build path to the service directory under a caller-supplied
    /// `repo_root`, branching on the `service == "web"` frontend
    /// convention: `web` lives at `{product_dir}/web` while every
    /// other (rust-service) name lives at
    /// `{product_dir}/{paths.services_path}/{service}`.
    ///
    /// Two byte-identical stanzas in
    /// `commands/rust_service.rs::deploy_and_verify` (the pre-
    /// deployment-test service-dir bind and the post-deployment-
    /// integration-tests service-dir bind) collapsed onto this
    /// method; the negative caller shield forbids the raw
    /// `if service == "web" { … .join("web") } else { … }` branching
    /// under `cli/src/commands/`.
    ///
    /// Delegates to [`Self::product_directory_under`] for the 2-hop
    /// base so a future change to that prefix ripples through both
    /// primitives.
    pub fn service_directory_under(&self, repo_root: &Path, service: &str) -> PathBuf {
        let product_dir = self.product_directory_under(repo_root);
        if service == "web" {
            product_dir.join("web")
        } else {
            product_dir
                .join(&self.global.paths.services_path)
                .join(service)
        }
    }

    /// Build path to Hive Router federation directory
    ///
    /// Example: `../../../../../../pkgs/products/{product}/infrastructure/hive-router`
    ///
    /// # Errors
    /// Returns error if current directory is inaccessible or not in a git repository
    pub fn federation_directory(&self) -> Result<PathBuf> {
        let repo_root = Self::get_repo_root()?;
        Ok(self
            .product_directory_under(&repo_root)
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

    /// [`write_artifact_info`] round-trips through [`load_artifact_info`]
    /// at the JSON surface and pins the on-disk envelope: pretty-printed
    /// JSON, trailing newline, path resolved via
    /// [`resolve_artifact_json_path`] (`{product_dir}/deploy/
    /// {service_name}.artifact.json`). Two pre-lift consumer sites
    /// (`commands/product_release.rs::write_artifact_tags`,
    /// `commands/rollback.rs::execute_rollback`) each spelled the
    /// primitive's shape verbatim; this shield seals the round-trip so a
    /// future drift onto a non-pretty encoder, a dropped trailing
    /// newline, or a differently-resolved json path is refused by the
    /// oracle rather than shipped past `cargo test`.
    #[test]
    fn test_write_artifact_info_round_trips_through_load_and_seals_disk_envelope() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let product_dir = tmp.path();
        std::fs::create_dir_all(product_dir.join("deploy")).expect("deploy dir");
        let service_name = "cart";

        let artifact = ArtifactInfo {
            tag: "abc123".to_string(),
            built_at: "2026-09-03T00:00:00Z".to_string(),
            previous_tag: "def456".to_string(),
            attestation: None,
        };

        // Positive side: the write returns the same path the resolver
        // computes — no caller-side restatement of the path resolver
        // survives the lift.
        let returned_path =
            write_artifact_info(product_dir, service_name, &artifact).expect("write_artifact_info");
        let expected_path = resolve_artifact_json_path(product_dir, service_name);
        assert_eq!(
            returned_path, expected_path,
            "write_artifact_info must return the same path \
             `resolve_artifact_json_path` computes; the two must be \
             indistinguishable at the caller so `modified_files` \
             pushes stay grep-visible under one resolver.",
        );

        // On-disk envelope: pretty-printed JSON with a trailing newline.
        // The `format!("{}\n", json)` at the primitive is what makes the
        // file POSIX-line-terminated; a drift onto plain
        // `serde_json::to_writer_pretty` or `to_string_pretty` alone
        // would drop the terminator silently. Anchor on the terminator
        // byte so a rewriter that reflows the JSON body still trips this.
        let on_disk = std::fs::read_to_string(&returned_path).expect("read back");
        let expected_body = serde_json::to_string_pretty(&artifact).expect("serialize");
        assert_eq!(
            on_disk,
            format!("{}\n", expected_body),
            "write_artifact_info's on-disk shape must be \
             `serde_json::to_string_pretty(&artifact) + \"\\n\"`; a \
             missing terminator, a compact encoding, or a differently \
             ordered field emission would drift the released \
             artifact.json under CI diff review.",
        );
        assert!(
            on_disk.ends_with('\n'),
            "write_artifact_info's on-disk shape MUST end with a \
             trailing newline so a POSIX line-oriented consumer \
             (grep, diff, git blame) reads the last field correctly. \
             Found no trailing `\\n` on {} bytes.",
            on_disk.len(),
        );

        // Load-arm round-trip: the primitive's write must be a legal
        // input to the peer read arm. A drift onto a non-JSON-compatible
        // encoder is caught by the loader's own `serde_json::from_str`
        // discipline, not deferred to a runtime deploy.
        let round_tripped = load_artifact_info(product_dir, service_name, product_dir)
            .expect("load_artifact_info round-trips its write-arm peer");
        assert_eq!(round_tripped.tag, artifact.tag);
        assert_eq!(round_tripped.built_at, artifact.built_at);
        assert_eq!(round_tripped.previous_tag, artifact.previous_tag);
    }

    /// Byte-oracle for the miss-arm bail wording of
    /// [`resolve_and_require_service_deploy_yaml_path`]. The pre-lift
    /// stanza at both consumer sites
    /// (`commands/status.rs::execute`,
    /// `commands/integration_tests.rs::execute_manual`) spelled the bail
    /// as `anyhow::bail!("No deploy.yaml found at: {}",
    /// deploy_yaml_path.display())` verbatim. Post-lift, the wording
    /// lives at ONE body inside this module — this test pins the
    /// on-error-`Display` bytes to
    /// `"No deploy.yaml found at: {resolved_path}"` so a rewrite that
    /// drifts onto `"deploy.yaml not found at:"` (the sibling
    /// `commands/rust_service.rs::deploy_rust_service_with_tag` wording
    /// which is deliberately out of scope for this lift because it
    /// gates on a caller-passed `&Path` rather than resolving through
    /// [`crate::repo::find_product_dir`]) or onto the
    /// [`repo::require_existing_path`] envelope (`"deploy.yaml not
    /// found: {path}"`) fails here rather than silently changing every
    /// coached operator's grep target.
    #[test]
    fn test_resolve_and_require_service_deploy_yaml_path_miss_arm_bail_bytes() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let service_dir = tmp.path().join("services").join("cart");
        std::fs::create_dir_all(&service_dir).expect("service dir");

        let err =
            resolve_and_require_service_deploy_yaml_path("cart", service_dir.to_str().unwrap())
                .expect_err(
                    "resolve_and_require_service_deploy_yaml_path must Err when \
                     neither `{product_dir}/deploy/{service_name}.yaml` nor \
                     `{service_dir}/deploy.yaml` exists",
                );

        // The pre-lift wording every operator was coached to grep for.
        // Interpolate the resolved path via `Display` because pre-lift
        // both call sites projected via `.display()`.
        let expected_path = service_dir.join("deploy.yaml");
        let expected = format!("No deploy.yaml found at: {}", expected_path.display());
        assert_eq!(
            err.to_string(),
            expected,
            "miss-arm bail bytes must be \
             `\"No deploy.yaml found at: {{path.display()}}\"` verbatim — \
             the pre-lift wording every operator has been coached to \
             grep for. A drift onto the sibling `\"deploy.yaml not found \
             at:\"` phrasing or the `require_existing_path` envelope \
             (`\"{{label}} not found: {{path}}\"`) silently changes the \
             message post-lift.",
        );
    }

    /// Pre-lift stanza scan: neither of the two consumer bodies
    /// (`commands/status.rs`, `commands/integration_tests.rs`) may
    /// re-open the pre-lift twelve-line
    ///
    /// ```text
    /// let service_dir_path = PathBuf::from(service_dir);
    /// let deploy_yaml_path = if let Some(product_dir) =
    ///     crate::repo::find_product_dir(&service_dir_path,
    ///         crate::repo::ProductDirLayout::Monorepo)
    /// {
    ///     crate::config::resolve_deploy_yaml_path(&product_dir, service, &service_dir_path)
    /// } else {
    ///     service_dir_path.join("deploy.yaml")
    /// };
    /// if !deploy_yaml_path.exists() {
    ///     anyhow::bail!("No deploy.yaml found at: {}", deploy_yaml_path.display());
    /// }
    /// ```
    ///
    /// stanza inline. The primitive
    /// [`resolve_and_require_service_deploy_yaml_path`] owns the
    /// monorepo-fallback locate + existence-gate at ONE body across the
    /// crate; a hand-rolled inline copy pushes the count above zero and
    /// fails this shield before the drift can ship. Anchors on both the
    /// `find_product_dir(...ProductDirLayout::Monorepo` walker
    /// invocation AND the `"No deploy.yaml found at:"` bail literal —
    /// either one re-appearing in a consumer body signals a drift.
    #[test]
    fn test_resolve_and_require_service_deploy_yaml_path_pre_lift_stanza_is_gone_at_both_consumers()
    {
        let status_body = crate::test_support::module_body_before_tests(
            include_str!("../commands/status.rs"),
            "commands/status.rs",
        );
        let integration_tests_body = crate::test_support::module_body_before_tests(
            include_str!("../commands/integration_tests.rs"),
            "commands/integration_tests.rs",
        );
        for (module_path, body) in [
            ("commands/status.rs", status_body),
            ("commands/integration_tests.rs", integration_tests_body),
        ] {
            for needle in [
                "\"No deploy.yaml found at: {}\"",
                "crate::repo::ProductDirLayout::Monorepo",
            ] {
                let hits = crate::test_support::code_line_hits(body, needle);
                assert!(
                    hits.is_empty(),
                    "{module_path} must NOT spell `{needle}` inline in \
                     the module body — the monorepo-fallback locate + \
                     `.exists()` gate lives at ONE body \
                     (`config::resolve_and_require_service_deploy_yaml_path`) \
                     across the crate. Found {} code-line hit(s): \
                     {hits:#?}. A hand-rolled inline copy re-opens the \
                     drift class the primitive was landed to close.",
                    hits.len(),
                );
            }
        }
    }

    /// Positive delegation shield: both post-lift consumer bodies must
    /// forward through the primitive at least once. Pre-lift each
    /// module inlined the stanza once; a refactor that removes the
    /// call without restoring the inline (dead-code deletion, an
    /// accidental early-return that bypasses the load) would be caught
    /// by the type checker on `raw_config` unused — this shield adds a
    /// grep-visible cross-check so the delegation is legible from the
    /// module's own text rather than only via the compile graph.
    #[test]
    fn test_resolve_and_require_service_deploy_yaml_path_is_called_at_both_consumers() {
        for (module_path, source) in [
            (
                "commands/status.rs",
                include_str!("../commands/status.rs") as &str,
            ),
            (
                "commands/integration_tests.rs",
                include_str!("../commands/integration_tests.rs") as &str,
            ),
        ] {
            let body = crate::test_support::module_body_before_tests(source, module_path);
            let needle = "resolve_and_require_service_deploy_yaml_path(";
            let hits = crate::test_support::code_line_hits(body, needle);
            assert!(
                !hits.is_empty(),
                "{module_path} must delegate to \
                 `crate::config::resolve_and_require_service_deploy_yaml_path(` \
                 at least once — the pre-lift twelve-line inline stanza \
                 was moved into the primitive, so every consumer that \
                 loaded a service-flavored `deploy.yaml` under the \
                 monorepo-fallback rule must now forward through it. \
                 Found zero delegation hits in the module body.",
            );
        }
    }

    /// Pre-lift stanza scan: neither of the two consumer bodies
    /// (`commands/product_release.rs`, `commands/rollback.rs`) may
    /// re-open the pre-lift `serde_json::to_string_pretty(&artifact)
    /// .context("Failed to serialize artifact info")` inline shape. The
    /// primitive [`write_artifact_info`] owns this composition at ONE
    /// body across the crate; a hand-rolled inline copy pushes the count
    /// above zero and fails this shield before the drift can ship.
    #[test]
    fn test_write_artifact_info_pre_lift_stanza_is_gone_at_both_consumers() {
        let product_release_body = crate::test_support::module_body_before_tests(
            include_str!("../commands/product_release.rs"),
            "commands/product_release.rs",
        );
        let rollback_body = crate::test_support::module_body_before_tests(
            include_str!("../commands/rollback.rs"),
            "commands/rollback.rs",
        );
        let needle = "\"Failed to serialize artifact info\"";
        for (module_path, body) in [
            ("commands/product_release.rs", product_release_body),
            ("commands/rollback.rs", rollback_body),
        ] {
            let hits = crate::test_support::code_line_hits(body, needle);
            assert!(
                hits.is_empty(),
                "{module_path} must NOT spell `{needle}` inline in the \
                 module body — the `serde_json::to_string_pretty(&artifact) \
                 .context(...)` composition lives at ONE body \
                 (`config::write_artifact_info`) across the crate. Found \
                 {} code-line hit(s): {hits:#?}. A hand-rolled inline copy \
                 re-opens the drift class the primitive was landed to close.",
                hits.len(),
            );
        }
    }

    // -------------------------------------------------------------------
    // product_directory_under / service_directory_under — the typed
    // product-scoped path-composition primitives that fold the pre-lift
    // 5 raw `repo_root.join(&deploy_config.global.paths.products_root)
    // .join(&deploy_config.product.name)[…]` stanzas across
    // `commands/rust_service.rs` (write_version_file × 1, deploy_and_verify
    // × 4) onto ONE body across the crate.
    // -------------------------------------------------------------------

    /// Byte-oracle for [`DeployConfig::product_directory_under`]:
    /// composes `{repo_root}/{paths.products_root}/{product.name}` on
    /// a defaults-config with `paths.products_root = "pkgs/products"`
    /// and `product.name = "myproduct"`, and pins the composed suffix
    /// on top of a fixed `/tmp/forge-fixture` repo-root prefix. Also
    /// pins the property that the primitive is PURE — repeated calls
    /// with the same inputs produce byte-identical outputs and no FS
    /// I/O side-effects (call twice, compare).
    #[test]
    fn test_product_directory_under_byte_oracle() {
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
        let repo_root = Path::new("/tmp/forge-fixture");
        let dir = config.product_directory_under(repo_root);
        assert_eq!(
            dir,
            PathBuf::from("/tmp/forge-fixture/pkgs/products/myproduct"),
            "product_directory_under must compose \
             `{{repo_root}}/{{paths.products_root}}/{{product.name}}` \
             exactly — a divergence at this byte-oracle means the 5 \
             pre-lift raw-join callers in commands/rust_service.rs \
             now compose a different service directory than they did \
             pre-lift, and the .version-file writes / integration-test \
             lookups target the wrong on-disk path"
        );
        let dir_again = config.product_directory_under(repo_root);
        assert_eq!(
            dir, dir_again,
            "product_directory_under must be pure — repeated calls with \
             the same (repo_root, config) inputs must produce \
             byte-identical outputs"
        );
    }

    /// Byte-oracle for [`DeployConfig::service_directory_under`]'s two
    /// arms: the `service == "web"` branch composes
    /// `{product_dir}/web` (no `paths.services_path` hop), while every
    /// other name composes `{product_dir}/{paths.services_path}/{service}`.
    /// Pins the exact split so the two sibling stanzas in
    /// `commands/rust_service.rs::deploy_and_verify` (the Step-0.5 pre-
    /// deployment-test service-dir bind and the Step-8 post-deployment-
    /// integration-tests service-dir bind) cannot drift on either side.
    #[test]
    fn test_service_directory_under_web_vs_rust_byte_oracle() {
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
        let repo_root = Path::new("/tmp/forge-fixture");
        assert_eq!(
            config.service_directory_under(repo_root, "web"),
            PathBuf::from("/tmp/forge-fixture/pkgs/products/myproduct/web"),
            "web-branch must resolve to `{{product_dir}}/web` with NO \
             `paths.services_path` hop — the frontend convention"
        );
        assert_eq!(
            config.service_directory_under(repo_root, "backend"),
            PathBuf::from("/tmp/forge-fixture/pkgs/products/myproduct/services/rust/backend"),
            "rust-service branch must resolve to \
             `{{product_dir}}/{{paths.services_path}}/{{service}}`"
        );
        assert_eq!(
            config.service_directory_under(repo_root, "cart"),
            PathBuf::from("/tmp/forge-fixture/pkgs/products/myproduct/services/rust/cart"),
            "rust-service branch must vary only on the trailing \
             `{{service}}` segment"
        );
    }

    /// Positive-delegation shield: `commands/rust_service.rs` must
    /// forward through [`DeployConfig::product_directory_under`] at
    /// AT LEAST the pre-lift consumer count so the ONE-body invariant
    /// is not silently rescinded by a caller re-inlining the raw
    /// 2-hop join. Pre-lift consumer count: 2 direct callers
    /// (`write_version_file`'s `.version`-file service-dir base, and
    /// `deploy_and_verify`'s `product_dir` bind under Step 8); the
    /// other 3 pre-lift sites forward through the sibling
    /// [`DeployConfig::service_directory_under`] (which itself
    /// delegates through `product_directory_under`).
    #[test]
    fn test_commands_rust_service_delegates_through_product_directory_under() {
        let body = crate::test_support::module_body_before_first_cfg_test(
            include_str!("../commands/rust_service.rs"),
            "commands/rust_service.rs",
        );
        let hits = crate::test_support::code_line_hits(body, ".product_directory_under(");
        assert!(
            hits.len() >= 2,
            "commands/rust_service.rs must forward through \
             `DeployConfig::product_directory_under` at AT LEAST 2 \
             call-sites — one for `write_version_file`'s \
             `.version`-file service-dir base, one for \
             `deploy_and_verify`'s `product_dir` bind. Found only \
             {} hit(s): {hits:#?}. A caller re-inlining the raw \
             `.join(&paths.products_root).join(&product.name)` 2-hop \
             re-opens the drift class the primitive was landed to close.",
            hits.len(),
        );
    }

    /// Positive-delegation shield: `commands/rust_service.rs` must
    /// forward through [`DeployConfig::service_directory_under`] at
    /// AT LEAST the pre-lift consumer count — 2 direct callers
    /// (`deploy_and_verify`'s Step-0.5 pre-deployment-test service-dir
    /// bind and the Step-8 post-deployment-integration-tests
    /// service-dir bind, both formerly spelling the identical
    /// `if service == "web" { … } else { … }` branching stanza).
    #[test]
    fn test_commands_rust_service_delegates_through_service_directory_under() {
        let body = crate::test_support::module_body_before_first_cfg_test(
            include_str!("../commands/rust_service.rs"),
            "commands/rust_service.rs",
        );
        let hits = crate::test_support::code_line_hits(body, ".service_directory_under(");
        assert!(
            hits.len() >= 2,
            "commands/rust_service.rs must forward through \
             `DeployConfig::service_directory_under` at AT LEAST 2 \
             call-sites — the two identical Step-0.5 / Step-8 \
             service-dir bind stanzas in `deploy_and_verify`. Found \
             only {} hit(s): {hits:#?}. A caller re-inlining the raw \
             `if service == \"web\" {{ … .join(\"web\") }} else {{ … \
             .join(&paths.services_path).join(&service) }}` branching \
             re-opens the drift class the primitive was landed to close.",
            hits.len(),
        );
    }

    /// Negative caller shield: `commands/rust_service.rs` must NOT
    /// spell the raw 2-hop
    /// `.join(&deploy_config.global.paths.products_root)` stanza
    /// inline in its module body. The typed
    /// [`DeployConfig::product_directory_under`] /
    /// [`DeployConfig::service_directory_under`] primitives own the
    /// composition at ONE body; a hand-rolled inline copy re-opens
    /// the drift class the primitives were landed to close.
    #[test]
    fn test_commands_rust_service_no_raw_products_root_join() {
        let body = crate::test_support::module_body_before_first_cfg_test(
            include_str!("../commands/rust_service.rs"),
            "commands/rust_service.rs",
        );
        let needle = ".join(&deploy_config.global.paths.products_root)";
        let hits = crate::test_support::code_line_hits(body, needle);
        assert!(
            hits.is_empty(),
            "commands/rust_service.rs must NOT spell `{needle}` inline \
             — route through `DeployConfig::product_directory_under` \
             (config/mod.rs) instead. Found {} code-line hit(s): \
             {hits:#?}. A hand-rolled inline copy re-opens the drift \
             class the primitive was landed to close.",
            hits.len(),
        );
    }

    /// Negative caller shield: `commands/rust_service.rs` must NOT
    /// spell the raw
    /// `.join(&deploy_config.global.paths.services_path)` stanza
    /// inline in its module body. The one legitimate consumer inside
    /// this module is `write_version_file`, which layers this join
    /// on top of [`DeployConfig::product_directory_under`] — that
    /// call-site is exempted by matching only the `deploy_config`-
    /// bound spelling and letting `write_version_file`'s local
    /// `deploy_config` binding count as the sole positive site.
    /// Every OTHER site must delegate through
    /// [`DeployConfig::service_directory_under`], which owns the
    /// `paths.services_path` join internally.
    #[test]
    fn test_commands_rust_service_services_path_join_bounded() {
        let body = crate::test_support::module_body_before_first_cfg_test(
            include_str!("../commands/rust_service.rs"),
            "commands/rust_service.rs",
        );
        let needle = ".join(&deploy_config.global.paths.services_path)";
        let hits = crate::test_support::code_line_hits(body, needle);
        assert!(
            hits.len() <= 1,
            "commands/rust_service.rs must spell \
             `{needle}` AT MOST once (the `write_version_file` \
             rust-only service-dir tail). Found {} hit(s): {hits:#?}. \
             Every other site must delegate through \
             `DeployConfig::service_directory_under` (config/mod.rs), \
             which owns the `paths.services_path` join internally.",
            hits.len(),
        );
    }

    /// Byte-oracle for [`locate_service_deploy_yaml`] under a
    /// monorepo layout: with `repo_root` at a tempdir root and a
    /// `services/rust/backend` service path, the four fields
    /// (`product_dir`, `service_dir`, `service_name`, `config_path`)
    /// must compose exactly the pre-lift 4-line stanza. The stanza's
    /// verbatim shape is what three sibling
    /// `DeployConfig::load_service_*` methods each spelled before
    /// this primitive landed; a drift in any of the four fields
    /// (a swapped file-name projection, a lost `services/rust/`
    /// segment, a `deploy.yaml`-file-path swap for `deploy/`
    /// -directory-file-path) would silently mis-route the deploy
    /// pipeline. No filesystem-side surprises: the primitive is a
    /// pure path composition (the `resolve_deploy_yaml_path` new-
    /// path branch only fires when `{product_dir}/deploy/{svc}.yaml`
    /// exists on disk, which this test does not create).
    #[test]
    fn test_locate_service_deploy_yaml_byte_oracle_monorepo_shape() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let repo_root = tmp.path();
        let repo_root_str = repo_root.to_str().expect("utf-8 repo root");

        let loc = locate_service_deploy_yaml("myproduct", "services/rust/backend", repo_root_str);

        assert_eq!(
            loc.product_dir,
            repo_root.join("pkgs/products/myproduct"),
            "product_dir must equal `resolve_product_dir(repo_root, \
             product)` — the pre-lift `let product_dir = \
             resolve_product_dir(Path::new(repo_root), product);` \
             line."
        );
        assert_eq!(
            loc.service_dir,
            repo_root.join("pkgs/products/myproduct/services/rust/backend"),
            "service_dir must equal `product_dir.join(service_path)` \
             — the pre-lift `let service_dir = \
             product_dir.join(service_path);` line, with the full \
             `services/rust/<name>` monorepo layout preserved."
        );
        assert_eq!(
            loc.service_name, "backend",
            "service_name must equal `Path::new(service_path).file_name() \
             .and_then(|n| n.to_str()).unwrap_or(service_path)` — the \
             pre-lift 3-line stanza projected to the base name."
        );
        assert_eq!(
            loc.config_path,
            repo_root.join("pkgs/products/myproduct/services/rust/backend/deploy.yaml"),
            "config_path must equal \
             `resolve_deploy_yaml_path(&product_dir, &service_name, \
             &service_dir)` under the fallback (service-scoped \
             deploy.yaml) branch — the pre-lift final line of the \
             4-line stanza. The `deploy/`-directory branch is a \
             disk-conditional switch; with nothing created on disk, \
             the primitive must return the fallback shape."
        );
    }

    /// The single-segment `service_path` case — a caller that passes
    /// just `"web"` rather than `"services/rust/web"` — must project
    /// `service_name` to the input verbatim (its own file-name) and
    /// compose `service_dir` as `{product_dir}/web`. Pins the
    /// pre-lift `unwrap_or(service_path)` fallback that fires when
    /// `Path::new(service_path).file_name()` is `None` for a rootless
    /// single-component path (empirically it does yield `Some("web")`
    /// here, but the semantic is the same: the base-name projection
    /// is idempotent on a single segment).
    #[test]
    fn test_locate_service_deploy_yaml_single_segment_service_path() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let repo_root_str = tmp.path().to_str().expect("utf-8 repo root");

        let loc = locate_service_deploy_yaml("myproduct", "web", repo_root_str);

        assert_eq!(loc.service_name, "web");
        assert_eq!(
            loc.service_dir,
            tmp.path().join("pkgs/products/myproduct/web"),
        );
        assert_eq!(
            loc.config_path,
            tmp.path().join("pkgs/products/myproduct/web/deploy.yaml"),
        );
    }

    /// Positive-delegation shield: this module's non-test body must
    /// call `locate_service_deploy_yaml(` at AT LEAST 3 sites — the
    /// three `DeployConfig::load_service_*` methods
    /// (`load_service_release_config`, `load_service_registry_url`,
    /// `load_service_namespace`) that shared the pre-lift 4-line
    /// preamble. A regression that re-inlines the preamble at any of
    /// the three sites drops this count below 3 and fails the shield
    /// before the drift can spread past `cargo test`.
    #[test]
    fn test_config_delegates_through_locate_service_deploy_yaml() {
        let body =
            crate::test_support::module_body_before_tests(include_str!("mod.rs"), "config/mod.rs");
        let hits = crate::test_support::code_line_hits(body, "locate_service_deploy_yaml(");
        assert!(
            hits.len() >= 3,
            "config/mod.rs must forward through \
             `locate_service_deploy_yaml(...)` at AT LEAST 3 \
             call-sites — the three `DeployConfig::load_service_*` \
             methods that shared the pre-lift 4-line preamble. Found \
             only {} hit(s): {hits:#?}. A caller re-inlining the raw \
             preamble re-opens the drift class the primitive was \
             landed to close.",
            hits.len(),
        );
    }

    /// Bounded caller shield: this module's non-test body must
    /// spell the file-name projection
    /// `let service_name = Path::new(service_path)` AT MOST once —
    /// the sole legitimate hit is the primitive
    /// [`locate_service_deploy_yaml`] itself. Every other consumer
    /// must destructure the 4-tuple that primitive returns; a
    /// regression that re-inlines the projection at any of the three
    /// sibling `DeployConfig::load_service_*` methods (or at any new
    /// caller) drives this count to ≥2 and fails the shield before
    /// the drift can spread past `cargo test`.
    #[test]
    fn test_config_service_name_projection_bounded_to_primitive() {
        let body =
            crate::test_support::module_body_before_tests(include_str!("mod.rs"), "config/mod.rs");
        let needle = "let service_name = Path::new(service_path)";
        let hits = crate::test_support::code_line_hits(body, needle);
        assert!(
            hits.len() <= 1,
            "config/mod.rs must spell `{needle}` AT MOST once — the \
             single legitimate site is the primitive \
             `locate_service_deploy_yaml`. Found {} code-line \
             hit(s): {hits:#?}. Every other consumer must \
             destructure the 4-tuple `locate_service_deploy_yaml` \
             returns; a hand-rolled inline copy re-opens the drift \
             class the primitive was landed to close.",
            hits.len(),
        );
    }
}
