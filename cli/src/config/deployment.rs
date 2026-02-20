//! Deployment operation configuration including pre-deployment tests.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// Production deployment strategy
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionStrategy {
    /// Deploy to all infrastructure at once (staging/dev default)
    Single,
    /// Deploy to infrastructure slices in sequence (A then B)
    AbSplit,
}

fn default_production_strategy() -> ProductionStrategy {
    ProductionStrategy::Single
}

/// A/B deployment slice configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbSliceConfig {
    /// Slice name (e.g., "a", "b")
    pub name: String,

    /// Flux kustomization name for this slice
    /// Supports placeholders: {product}, {environment}, {cluster}, {service}
    pub kustomization: String,

    /// Delay before deploying to this slice (seconds, 0 for first slice)
    #[serde(default)]
    pub delay_secs: u64,
}

impl AbSliceConfig {
    /// Validate slice configuration
    pub fn validate(&self, slice_index: usize) -> Result<()> {
        // Validate slice name is not empty
        if self.name.trim().is_empty() {
            bail!("Slice name cannot be empty (slice index {})", slice_index);
        }

        // Validate kustomization is not empty
        if self.kustomization.trim().is_empty() {
            bail!(
                "Kustomization name cannot be empty for slice '{}' (index {})",
                self.name,
                slice_index
            );
        }

        // Validate first slice has delay_secs = 0
        if slice_index == 0 && self.delay_secs != 0 {
            eprintln!(
                "⚠️  Warning: First slice '{}' has delay_secs = {}, should be 0 for immediate deployment",
                self.name,
                self.delay_secs
            );
        }

        // Warn if delay is very short (less than 30 seconds) for non-first slices
        if slice_index > 0 && self.delay_secs > 0 && self.delay_secs < 30 {
            eprintln!(
                "⚠️  Warning: Slice '{}' has delay_secs = {}s, which may not allow enough time for health checks",
                self.name,
                self.delay_secs
            );
        }

        Ok(())
    }
}

fn default_ab_slices() -> Vec<AbSliceConfig> {
    vec![
        AbSliceConfig {
            name: "a".to_string(),
            kustomization: "{product}-{environment}-a".to_string(),
            delay_secs: 0,
        },
        AbSliceConfig {
            name: "b".to_string(),
            kustomization: "{product}-{environment}-b".to_string(),
            delay_secs: 300, // 5 minutes after slice A
        },
    ]
}

/// Pre-deployment test suite configuration
/// Runs BEFORE push/deploy to catch issues early
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreDeploymentTestSuite {
    /// Test suite name (e.g., "unit", "lint", "type-check")
    pub name: String,

    /// Human-readable description
    pub description: String,

    /// Command to run (e.g., "npx vitest run --config vitest.config.unit.ts")
    pub command: String,

    /// Working directory relative to service directory
    #[serde(default = "default_test_working_dir")]
    pub working_dir: String,

    /// Timeout for test execution (e.g., "5m", "30s")
    #[serde(default = "default_pre_deploy_test_timeout")]
    pub timeout: String,

    /// Whether to retry on failure
    #[serde(default)]
    pub retry_on_failure: bool,

    /// Maximum retry attempts
    #[serde(default)]
    pub max_retries: u32,
}

fn default_test_working_dir() -> String {
    ".".to_string()
}

fn default_pre_deploy_test_timeout() -> String {
    "5m".to_string()
}

/// Pre-deployment test execution configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreDeploymentTestExecution {
    /// Run test suites in parallel
    #[serde(default)]
    pub parallel: bool,

    /// Stop on first failure
    #[serde(default = "default_fail_fast")]
    pub fail_fast: bool,
}

fn default_fail_fast() -> bool {
    true
}

impl Default for PreDeploymentTestExecution {
    fn default() -> Self {
        Self {
            parallel: false,
            fail_fast: default_fail_fast(),
        }
    }
}

/// Pre-deployment test failure action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreDeploymentTestOnFailure {
    /// Action on failure: "fail" (stop release) or "warn" (continue with warning)
    #[serde(default = "default_on_failure_action")]
    pub action: String,

    /// Notification channels
    #[serde(default)]
    pub notify: Vec<String>,
}

fn default_on_failure_action() -> String {
    "fail".to_string()
}

impl Default for PreDeploymentTestOnFailure {
    fn default() -> Self {
        Self {
            action: default_on_failure_action(),
            notify: vec![],
        }
    }
}

/// Pre-deployment tests configuration
/// These tests run BEFORE push/deploy to provide fast feedback
/// Unit tests should run here; integration tests run after deployment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreDeploymentTestsConfig {
    /// Whether pre-deployment tests are enabled
    #[serde(default)]
    pub enabled: bool,

    /// Test suites to run
    #[serde(default)]
    pub test_suites: Vec<PreDeploymentTestSuite>,

    /// Execution configuration
    #[serde(default)]
    pub execution: PreDeploymentTestExecution,

    /// Failure handling
    #[serde(default)]
    pub on_failure: PreDeploymentTestOnFailure,
}

impl Default for PreDeploymentTestsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            test_suites: vec![],
            execution: PreDeploymentTestExecution::default(),
            on_failure: PreDeploymentTestOnFailure::default(),
        }
    }
}

impl PreDeploymentTestsConfig {
    /// Validate pre-deployment tests configuration
    pub fn validate(&self, service_name: &str) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        if self.test_suites.is_empty() {
            eprintln!(
                "⚠️  Warning: pre_deployment_tests.enabled is true but no test_suites defined for '{}'",
                service_name
            );
        }

        for suite in &self.test_suites {
            if suite.name.trim().is_empty() {
                bail!(
                    "Pre-deployment test suite name cannot be empty for '{}'",
                    service_name
                );
            }
            if suite.command.trim().is_empty() {
                bail!(
                    "Pre-deployment test suite '{}' command cannot be empty for '{}'",
                    suite.name,
                    service_name
                );
            }
        }

        // Validate on_failure action
        if !["fail", "warn"].contains(&self.on_failure.action.as_str()) {
            bail!(
                "pre_deployment_tests.on_failure.action must be 'fail' or 'warn', got '{}' for '{}'",
                self.on_failure.action, service_name
            );
        }

        Ok(())
    }
}

/// Deployment operation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentConfig {
    /// Whether to perform GitOps deployment (update kustomization.yaml and trigger flux)
    #[serde(default = "default_deployment_enabled")]
    pub enabled: bool,

    /// Whether to skip the pre-release FluxCD health check
    /// Set to true for thin deployments that just push and commit (let FluxCD reconcile async)
    #[serde(default)]
    pub skip_flux_health_check: bool,

    /// Whether to wait for deployment rollout to complete
    /// Set to false for Job resources or services that don't use Deployment/StatefulSet
    #[serde(default = "default_wait_for_rollout")]
    pub wait_for_rollout: bool,

    /// Flux reconcile commands to run (supports: {product}, {environment}, {cluster})
    /// Default: ["flux reconcile kustomization {product}-{environment} --with-source"]
    #[serde(default = "default_flux_commands")]
    pub flux_commands: Vec<String>,

    /// Production deployment strategy (single or ab_split)
    #[serde(default = "default_production_strategy")]
    pub production_strategy: ProductionStrategy,

    /// A/B deployment slice configuration (only used when production_strategy = ab_split)
    #[serde(default = "default_ab_slices")]
    pub ab_slices: Vec<AbSliceConfig>,

    /// Timeout for waiting on Kubernetes deployment to become ready (in seconds)
    /// Only used when wait_for_rollout is true
    #[serde(default = "default_deployment_wait_timeout")]
    pub deployment_wait_timeout_secs: u64,

    /// Timeout for Nix operations (build, push) network connections (in seconds)
    #[serde(default = "default_nix_connect_timeout")]
    pub nix_connect_timeout_secs: u64,

    /// Pre-deployment tests configuration (runs BEFORE push/deploy)
    /// Unit tests, linting, type checks - fast feedback before expensive operations
    #[serde(default)]
    pub pre_deployment_tests: PreDeploymentTestsConfig,
}

fn default_deployment_enabled() -> bool {
    true
}

fn default_wait_for_rollout() -> bool {
    true
}

fn default_flux_commands() -> Vec<String> {
    vec!["flux reconcile kustomization {product}-{environment} --with-source".to_string()]
}

fn default_deployment_wait_timeout() -> u64 {
    600 // 10 minutes - allows time for FluxCD reconcile, image pull, pod scheduling
}

fn default_nix_connect_timeout() -> u64 {
    5 // 5 seconds
}

impl Default for DeploymentConfig {
    fn default() -> Self {
        Self {
            enabled: default_deployment_enabled(),
            skip_flux_health_check: false,
            wait_for_rollout: default_wait_for_rollout(),
            flux_commands: default_flux_commands(),
            production_strategy: default_production_strategy(),
            ab_slices: default_ab_slices(),
            deployment_wait_timeout_secs: default_deployment_wait_timeout(),
            nix_connect_timeout_secs: default_nix_connect_timeout(),
            pre_deployment_tests: PreDeploymentTestsConfig::default(),
        }
    }
}

impl DeploymentConfig {
    /// Validate deployment configuration
    pub fn validate(&self) -> Result<()> {
        if !self.enabled {
            return Ok(()); // Skip validation if deployment is disabled
        }

        // Validate flux commands are not empty
        if self.flux_commands.is_empty() {
            bail!("flux_commands cannot be empty when deployment is enabled");
        }

        // Validate each flux command is not just whitespace
        for (idx, cmd) in self.flux_commands.iter().enumerate() {
            if cmd.trim().is_empty() {
                bail!("flux_commands[{}] cannot be empty or whitespace-only", idx);
            }
        }

        // Validate timeouts are reasonable
        if self.deployment_wait_timeout_secs == 0 {
            bail!("deployment_wait_timeout_secs must be greater than 0");
        }

        if self.deployment_wait_timeout_secs > 3600 {
            eprintln!(
                "⚠️  Warning: deployment_wait_timeout_secs is {}s (>1 hour), this may be too long",
                self.deployment_wait_timeout_secs
            );
        }

        // Validate A/B slice configuration if using ab_split strategy
        if self.production_strategy == ProductionStrategy::AbSplit {
            if self.ab_slices.is_empty() {
                bail!("ab_split strategy requires at least one slice");
            }

            if self.ab_slices.len() < 2 {
                bail!(
                    "ab_split strategy requires at least 2 slices for A/B deployment, got {}",
                    self.ab_slices.len()
                );
            }

            // Validate slice names are unique
            let mut slice_names = std::collections::HashSet::new();
            for (idx, slice) in self.ab_slices.iter().enumerate() {
                // Validate individual slice
                slice
                    .validate(idx)
                    .with_context(|| format!("Invalid configuration for slice '{}'", slice.name))?;

                // Check for duplicate names
                if !slice_names.insert(&slice.name) {
                    bail!(
                        "Duplicate slice name '{}' in ab_slices configuration",
                        slice.name
                    );
                }
            }
        }

        Ok(())
    }
}

/// Cloudflare cache purging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudflareConfig {
    /// Whether to purge Cloudflare cache after deployment
    #[serde(default = "default_cloudflare_enabled")]
    pub enabled: bool,

    /// Cloudflare Zone ID
    #[serde(default)]
    pub zone_id: Option<String>,

    /// Cloudflare API token
    #[serde(default)]
    pub api_token: Option<String>,

    /// Files to purge from cache (supports wildcards)
    /// Examples: ["/env.js", "/version.json", "/index.html"]
    #[serde(default = "default_cloudflare_files")]
    pub files: Vec<String>,

    /// Base URL for the site (e.g., "https://staging.example.com")
    #[serde(default)]
    pub base_url: Option<String>,
}

fn default_cloudflare_enabled() -> bool {
    false
}

fn default_cloudflare_files() -> Vec<String> {
    vec!["/env.js".to_string(), "/version.json".to_string()]
}

impl Default for CloudflareConfig {
    fn default() -> Self {
        Self {
            enabled: default_cloudflare_enabled(),
            zone_id: None,
            api_token: None,
            files: default_cloudflare_files(),
            base_url: None,
        }
    }
}

impl CloudflareConfig {
    /// Validate Cloudflare configuration
    pub fn validate(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        if self.zone_id.is_none() {
            bail!("cloudflare.zone_id is required when cloudflare.enabled = true");
        }

        if self.api_token.is_none() {
            bail!("cloudflare.api_token is required when cloudflare.enabled = true");
        }

        if self.base_url.is_none() {
            bail!("cloudflare.base_url is required when cloudflare.enabled = true");
        }

        if let Some(ref base_url) = self.base_url {
            if !base_url.starts_with("http://") && !base_url.starts_with("https://") {
                bail!(
                    "cloudflare.base_url must start with http:// or https:// (got: '{}')",
                    base_url
                );
            }
        }

        if self.files.is_empty() {
            eprintln!("⚠️  Warning: cloudflare.files is empty, no files will be purged from cache");
        }

        Ok(())
    }
}
