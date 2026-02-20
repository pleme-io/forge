//! GraphQL Federation configuration for Apollo Router and Hive Router.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

/// Federation configuration for Apollo GraphQL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationConfig {
    /// Federation routing port (default: 8080)
    #[serde(default = "default_federation_port")]
    pub port: u16,

    /// Federation routing protocol (default: "http")
    #[serde(default = "default_federation_protocol")]
    pub protocol: String,

    /// Routing URL pattern (supports: {protocol}, {service}, {product}, {environment}, {port})
    #[serde(default = "default_routing_url_pattern")]
    pub routing_url_pattern: String,

    /// BFF admin URL for supergraph reload notification
    ///
    /// When set, the release process will call POST /admin/reload-supergraph
    /// on the BFF to trigger an immediate supergraph reload. This provides
    /// instant propagation without waiting for the file watcher polling interval.
    ///
    /// Examples:
    /// - In-cluster: "http://web.{product}-{environment}:8000"
    /// - External: "https://staging.example.com"
    #[serde(default)]
    pub bff_admin_url: Option<String>,
}

fn default_federation_port() -> u16 {
    8080
}

fn default_federation_protocol() -> String {
    "http".to_string()
}

fn default_routing_url_pattern() -> String {
    "{protocol}://{service}.{product}-{environment}:{port}/graphql".to_string()
}

impl Default for FederationConfig {
    fn default() -> Self {
        Self {
            port: default_federation_port(),
            protocol: default_federation_protocol(),
            routing_url_pattern: default_routing_url_pattern(),
            bff_admin_url: None,
        }
    }
}

/// Service-specific Apollo Federation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceFederationConfig {
    /// Whether this service exposes a GraphQL API
    #[serde(default = "default_federation_enabled")]
    pub enabled: bool,

    /// Schema extraction binary name (e.g., "extract-schema", "extract_schema")
    #[serde(default = "default_schema_extractor")]
    pub schema_extractor: String,

    /// Expected schema file output location (relative to subgraphs/)
    #[serde(default)]
    pub schema_output: Option<String>,

    /// GraphQL endpoint path (default: /graphql)
    #[serde(default = "default_graphql_path")]
    pub graphql_path: String,

    /// Whether schema extraction is required before deployment
    #[serde(default = "default_federation_required")]
    pub required: bool,

    /// Minimum expected schema size in bytes (quality check)
    #[serde(default = "default_min_schema_size")]
    pub min_schema_size: u64,

    /// Expected GraphQL types this service should expose (for validation)
    #[serde(default)]
    pub expected_types: Vec<String>,

    /// Path pattern for subgraph schema file (supports: {product}, {service}, {cluster}, {environment})
    /// Default: "pkgs/products/{product}/infrastructure/hive-router/subgraphs/{service}.graphql"
    #[serde(default)]
    pub subgraph_path: Option<String>,

    /// Path pattern for supergraph router deployment (supports: {product}, {service}, {cluster}, {environment})
    /// Default: "nix/k8s/clusters/{cluster}/products/{product}-{environment}/hive-router/supergraph.graphql"
    #[serde(default)]
    pub supergraph_router_path: Option<String>,

    /// Path pattern for hive-router deployment manifest (supports: {product}, {service}, {cluster}, {environment})
    /// Default: "nix/k8s/clusters/{cluster}/products/{product}-{environment}/hive-router/hive-router-deployment.yaml"
    #[serde(default)]
    pub hive_router_deployment_path: Option<String>,

    /// BFF admin URL override for this service
    /// If set, overrides the global federation.bff_admin_url
    #[serde(default)]
    pub bff_admin_url: Option<String>,
}

fn default_federation_enabled() -> bool {
    true
}

fn default_schema_extractor() -> String {
    "extract-schema".to_string()
}

fn default_graphql_path() -> String {
    "/graphql".to_string()
}

fn default_federation_required() -> bool {
    true
}

fn default_min_schema_size() -> u64 {
    100
}

impl Default for ServiceFederationConfig {
    fn default() -> Self {
        Self {
            enabled: default_federation_enabled(),
            schema_extractor: default_schema_extractor(),
            schema_output: None,
            graphql_path: default_graphql_path(),
            required: default_federation_required(),
            min_schema_size: default_min_schema_size(),
            expected_types: vec![],
            subgraph_path: None,
            supergraph_router_path: None,
            hive_router_deployment_path: None,
            bff_admin_url: None,
        }
    }
}

impl ServiceFederationConfig {
    /// Get the expected schema output filename
    /// Defaults to {service-name}.graphql if not specified
    pub fn schema_output_name(&self, service_name: &str) -> String {
        self.schema_output
            .clone()
            .unwrap_or_else(|| format!("{}.graphql", service_name))
    }

    /// Validate federation configuration
    pub fn validate(&self, service_name: &str) -> Result<()> {
        if !self.enabled {
            return Ok(()); // Skip validation for non-GraphQL services
        }

        // Validate schema extractor name is not empty
        if self.schema_extractor.is_empty() {
            bail!(
                "schema_extractor cannot be empty for service '{}'",
                service_name
            );
        }

        // Validate GraphQL path
        if !self.graphql_path.starts_with('/') {
            bail!(
                "graphql_path must start with '/' for service '{}' (got: '{}')",
                service_name,
                self.graphql_path
            );
        }

        // Validate minimum schema size is reasonable
        if self.min_schema_size < 50 {
            eprintln!(
                "⚠️  Warning: min_schema_size ({}) is very small for service '{}'. Typical schemas are 1000+ bytes.",
                self.min_schema_size,
                service_name
            );
        }

        Ok(())
    }
}

/// Federation tests service configuration
/// Used ONLY by the federation-tests service itself to mark it as the global test runner
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FederationTestsServiceConfig {
    /// Whether this service IS the global federation-tests runner
    /// When true, releasing this service updates its own image tag in deploy.yaml
    #[serde(default)]
    pub is_global: bool,
}

/// Service-specific federation integration tests configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceFederationTestsConfig {
    /// Whether to run federation tests after deployment
    #[serde(default = "default_federation_tests_enabled")]
    pub enabled: bool,

    /// Test suite to run (e.g., "auth", "cart", "all")
    /// Passed as --suite flag to federation-tests
    #[serde(default = "default_federation_tests_suite")]
    pub suite: String,

    /// Test execution timeout in seconds
    #[serde(default = "default_federation_tests_timeout")]
    pub timeout_seconds: u64,

    /// Stop on first test failure
    #[serde(default = "default_federation_tests_fail_fast")]
    pub fail_fast: bool,

    /// Hive Router GraphQL endpoint URL
    #[serde(default = "default_federation_tests_router_url")]
    pub router_url: String,

    /// Job name pattern (supports: {product}, {service}, {environment})
    /// Default: "{product}-{service}-federation-tests"
    #[serde(default)]
    pub job_name_pattern: Option<String>,

    /// Job namespace pattern (supports: {product}, {environment})
    /// Default: "{product}-{environment}"
    #[serde(default)]
    pub namespace_pattern: Option<String>,

    /// Federation-tests image tag to use for this service
    /// If not specified, falls back to federation-tests' own deploy.yaml
    /// Example: "amd64-960d3cbb78"
    #[serde(default)]
    pub image_tag: Option<String>,
}

fn default_federation_tests_enabled() -> bool {
    false // Disabled by default, services opt-in
}

fn default_federation_tests_suite() -> String {
    "all".to_string()
}

fn default_federation_tests_timeout() -> u64 {
    300 // 5 minutes
}

fn default_federation_tests_fail_fast() -> bool {
    true
}

fn default_federation_tests_router_url() -> String {
    "http://hive-router:4000/graphql".to_string()
}

impl Default for ServiceFederationTestsConfig {
    fn default() -> Self {
        Self {
            enabled: default_federation_tests_enabled(),
            suite: default_federation_tests_suite(),
            timeout_seconds: default_federation_tests_timeout(),
            fail_fast: default_federation_tests_fail_fast(),
            router_url: default_federation_tests_router_url(),
            job_name_pattern: None,
            namespace_pattern: None,
            image_tag: None,
        }
    }
}

impl ServiceFederationTestsConfig {
    /// Get the job name for this service's federation tests
    pub fn job_name(&self, product: &str, service: &str, environment: &str) -> String {
        self.job_name_pattern
            .clone()
            .unwrap_or_else(|| format!("{}-{}-federation-tests", product, service))
            .replace("{product}", product)
            .replace("{service}", service)
            .replace("{environment}", environment)
    }

    /// Get the namespace for federation tests
    pub fn namespace(&self, product: &str, environment: &str) -> String {
        self.namespace_pattern
            .clone()
            .unwrap_or_else(|| format!("{}-{}", product, environment))
            .replace("{product}", product)
            .replace("{environment}", environment)
    }

    /// Validate federation tests configuration
    pub fn validate(&self, service_name: &str) -> Result<()> {
        if !self.enabled {
            return Ok(()); // Skip validation if tests are disabled
        }

        // Validate suite name is not empty
        if self.suite.trim().is_empty() {
            bail!(
                "Federation test suite cannot be empty for service '{}'",
                service_name
            );
        }

        // Validate timeout is reasonable
        if self.timeout_seconds == 0 {
            bail!(
                "Federation test timeout must be greater than 0 for service '{}'",
                service_name
            );
        }

        if self.timeout_seconds > 3600 {
            eprintln!(
                "   ⚠️  Warning: Federation test timeout ({} seconds = {} minutes) is very long for service '{}'",
                self.timeout_seconds,
                self.timeout_seconds / 60,
                service_name
            );
            eprintln!(
                "       Consider reducing to < 600s (10 minutes) for faster deployment feedback"
            );
        }

        // Validate router URL
        if self.router_url.trim().is_empty() {
            bail!(
                "Federation test router_url cannot be empty for service '{}'",
                service_name
            );
        }

        if !self.router_url.starts_with("http://") && !self.router_url.starts_with("https://") {
            bail!(
                "Federation test router_url must start with http:// or https:// for service '{}' (got: '{}')",
                service_name,
                self.router_url
            );
        }

        Ok(())
    }
}

/// Federation integration tests configuration (global)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationTestsConfig {
    /// Blessed image tag for federation-tests
    /// This tag is used by ALL services when running federation tests
    /// Update after: cd tests/federation && nix run .#release
    #[serde(default = "default_federation_tests_image_tag")]
    pub image_tag: String,

    /// Image pattern for federation-tests
    /// Supports: {host}, {organization}, {project}, {image_tag}
    #[serde(default = "default_federation_tests_image_pattern")]
    pub image_pattern: String,
}

fn default_federation_tests_image_tag() -> String {
    "amd64-latest".to_string()
}

fn default_federation_tests_image_pattern() -> String {
    "{host}/{organization}/{project}/{product}-{service}:{image_tag}".to_string()
}

impl Default for FederationTestsConfig {
    fn default() -> Self {
        Self {
            image_tag: default_federation_tests_image_tag(),
            image_pattern: default_federation_tests_image_pattern(),
        }
    }
}
