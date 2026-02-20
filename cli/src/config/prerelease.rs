//! Pre-release gate configuration.
//!
//! Configures which gates run and how failures are handled during pre-release validation.

use serde::{Deserialize, Serialize};

/// Pre-release gate configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreReleaseGatesConfig {
    /// Whether pre-release gates are enabled (default: true)
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Whether gate failures should stop the release (default: true)
    #[serde(default = "default_fail_on_error")]
    pub fail_on_error: bool,

    /// Backend gate configuration
    #[serde(default)]
    pub backend: BackendGatesConfig,

    /// Migration gate configuration
    #[serde(default)]
    pub migrations: MigrationGatesConfig,

    /// Frontend gate configuration
    #[serde(default)]
    pub frontend: FrontendGatesConfig,

    /// Integration test gate configuration (G13)
    #[serde(default)]
    pub integration: IntegrationGatesConfig,

    /// E2E test gate configuration (G14)
    #[serde(default)]
    pub e2e: E2eGatesConfig,

    /// Post-deploy verification gate configuration (G15)
    #[serde(default)]
    pub post_deploy: PostDeployGatesConfig,
}

impl Default for PreReleaseGatesConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            fail_on_error: default_fail_on_error(),
            backend: BackendGatesConfig::default(),
            migrations: MigrationGatesConfig::default(),
            frontend: FrontendGatesConfig::default(),
            integration: IntegrationGatesConfig::default(),
            e2e: E2eGatesConfig::default(),
            post_deploy: PostDeployGatesConfig::default(),
        }
    }
}

fn default_enabled() -> bool {
    true
}

fn default_fail_on_error() -> bool {
    true
}

/// Backend gate configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendGatesConfig {
    /// Enable cargo check gate (default: true)
    #[serde(default = "default_true")]
    pub cargo_check: bool,

    /// Enable cargo clippy gate (default: true)
    #[serde(default = "default_true")]
    pub cargo_clippy: bool,

    /// Enable cargo fmt check gate (default: true)
    #[serde(default = "default_true")]
    pub cargo_fmt: bool,

    /// Enable cargo test gate (default: true)
    #[serde(default = "default_true")]
    pub cargo_test: bool,

    /// Enable extract-schema gate (default: true)
    #[serde(default = "default_true")]
    pub extract_schema: bool,
}

impl Default for BackendGatesConfig {
    fn default() -> Self {
        Self {
            cargo_check: true,
            cargo_clippy: true,
            cargo_fmt: true,
            cargo_test: true,
            extract_schema: true,
        }
    }
}

/// Migration gate configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationGatesConfig {
    /// Enable migration idempotency check for SQLx migrations (default: true)
    #[serde(default = "default_true")]
    pub idempotency_check: bool,

    /// Enable soft-delete compliance check (default: true)
    #[serde(default = "default_true")]
    pub soft_delete_check: bool,

    /// Enable SeaORM migration safety check (default: true)
    /// Checks for dangerous operations that require expand-contract pattern
    #[serde(default = "default_true")]
    pub seaorm_safety_check: bool,

    /// Migration files to exclude from validation
    /// These are typically already-executed migrations that predate the gate rules
    /// Supports glob patterns (e.g., "20230101*") or exact filenames
    #[serde(default)]
    pub excluded_files: Vec<String>,

    /// SeaORM migration files to exclude from safety validation
    /// Use for migrations that have already been deployed or have explicit approval
    #[serde(default)]
    pub seaorm_excluded_files: Vec<String>,

    /// Minimum migration filename prefix to check (e.g., "20240101")
    /// Migrations with timestamps before this are skipped
    /// This is useful for exempting all migrations before a certain date
    #[serde(default)]
    pub check_after: Option<String>,

    /// Minimum SeaORM migration filename prefix to check (e.g., "m20260128")
    /// SeaORM migrations with timestamps before this are skipped
    #[serde(default)]
    pub seaorm_check_after: Option<String>,

    /// Enable migration data completeness check (default: true)
    /// Verifies every SeaORM migration is assessed in migration-manifest.yaml
    #[serde(default = "default_true")]
    pub data_completeness_check: bool,
}

impl Default for MigrationGatesConfig {
    fn default() -> Self {
        Self {
            idempotency_check: true,
            soft_delete_check: true,
            seaorm_safety_check: true,
            excluded_files: Vec::new(),
            seaorm_excluded_files: Vec::new(),
            check_after: None,
            seaorm_check_after: None,
            data_completeness_check: true,
        }
    }
}

/// Frontend gate configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrontendGatesConfig {
    /// Enable codegen drift detection (default: true)
    #[serde(default = "default_true")]
    pub codegen_drift: bool,

    /// Enable type-check gate (default: true)
    #[serde(default = "default_true")]
    pub type_check: bool,

    /// Enable lint gate (default: true)
    #[serde(default = "default_true")]
    pub lint: bool,

    /// Linter to use: "biome" or "eslint" (default: "biome")
    #[serde(default = "default_linter")]
    pub linter: String,

    /// Enable unit tests gate (default: true)
    #[serde(default = "default_true")]
    pub unit_tests: bool,
}

impl Default for FrontendGatesConfig {
    fn default() -> Self {
        Self {
            codegen_drift: true,
            type_check: true,
            lint: true,
            linter: default_linter(),
            unit_tests: true,
        }
    }
}

/// Integration test gate configuration (G13)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationGatesConfig {
    /// Enable integration tests (default: true)
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Timeout in seconds for integration tests (default: 300)
    #[serde(default = "default_300")]
    pub timeout_secs: u64,
}

impl Default for IntegrationGatesConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            timeout_secs: default_300(),
        }
    }
}

/// E2E test gate configuration (G14)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eGatesConfig {
    /// Enable E2E tests (default: true)
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Timeout in seconds for E2E tests (default: 600)
    #[serde(default = "default_600")]
    pub timeout_secs: u64,

    /// Run browser in headless mode (default: true)
    #[serde(default = "default_true")]
    pub headless: bool,
}

impl Default for E2eGatesConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            timeout_secs: default_600(),
            headless: true,
        }
    }
}

/// Post-deploy verification gate configuration (G15)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostDeployGatesConfig {
    /// Enable smoke query validation (default: true)
    #[serde(default = "default_true")]
    pub smoke_queries: bool,

    /// Timeout in seconds for post-deploy verification (default: 30)
    #[serde(default = "default_30")]
    pub timeout_secs: u64,

    /// Number of retries for health/graphql checks (default: 3)
    #[serde(default = "default_3")]
    pub retries: u32,
}

impl Default for PostDeployGatesConfig {
    fn default() -> Self {
        Self {
            smoke_queries: true,
            timeout_secs: default_30(),
            retries: default_3(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_linter() -> String {
    "biome".to_string()
}

fn default_30() -> u64 {
    30
}

fn default_300() -> u64 {
    300
}

fn default_600() -> u64 {
    600
}

fn default_3() -> u32 {
    3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = PreReleaseGatesConfig::default();
        assert!(config.enabled);
        assert!(config.fail_on_error);
        assert!(config.backend.cargo_check);
        assert!(config.migrations.idempotency_check);
        assert!(config.frontend.lint);
        assert_eq!(config.frontend.linter, "biome");
    }

    #[test]
    fn test_default_integration_config() {
        let config = IntegrationGatesConfig::default();
        assert!(config.enabled);
        assert_eq!(config.timeout_secs, 300);
    }

    #[test]
    fn test_default_e2e_config() {
        let config = E2eGatesConfig::default();
        assert!(config.enabled);
        assert_eq!(config.timeout_secs, 600);
        assert!(config.headless);
    }

    #[test]
    fn test_default_post_deploy_config() {
        let config = PostDeployGatesConfig::default();
        assert!(config.smoke_queries);
        assert_eq!(config.timeout_secs, 30);
        assert_eq!(config.retries, 3);
    }

    #[test]
    fn test_prerelease_includes_all_gate_groups() {
        let config = PreReleaseGatesConfig::default();
        // Verify all gate groups are present with defaults
        assert!(config.backend.cargo_check);
        assert!(config.backend.cargo_clippy);
        assert!(config.backend.cargo_fmt);
        assert!(config.backend.cargo_test);
        assert!(config.backend.extract_schema);
        assert!(config.migrations.idempotency_check);
        assert!(config.migrations.soft_delete_check);
        assert!(config.migrations.seaorm_safety_check);
        assert!(config.migrations.data_completeness_check);
        assert!(config.frontend.codegen_drift);
        assert!(config.frontend.type_check);
        assert!(config.frontend.lint);
        assert!(config.frontend.unit_tests);
        assert!(config.integration.enabled);
        assert!(config.e2e.enabled);
        assert!(config.post_deploy.smoke_queries);
    }

    #[test]
    fn test_migration_exclusion() {
        let config = MigrationGatesConfig {
            excluded_files: vec!["20230101_initial.sql".to_string(), "20230201_*".to_string()],
            check_after: Some("20240101".to_string()),
            ..Default::default()
        };
        assert_eq!(config.excluded_files.len(), 2);
        assert_eq!(config.check_after, Some("20240101".to_string()));
    }

    // ====================================================================
    // YAML deserialization tests — verify deploy.yaml round-trips correctly
    // ====================================================================

    #[test]
    fn test_deserialize_empty_yaml_gives_defaults() {
        let yaml = "{}";
        let config: PreReleaseGatesConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.enabled);
        assert!(config.fail_on_error);
        assert!(config.integration.enabled);
        assert_eq!(config.integration.timeout_secs, 300);
        assert!(config.e2e.enabled);
        assert_eq!(config.e2e.timeout_secs, 600);
        assert!(config.e2e.headless);
        assert!(config.post_deploy.smoke_queries);
    }

    #[test]
    fn test_deserialize_integration_disabled() {
        let yaml = r#"
integration:
  enabled: false
  timeout_secs: 120
"#;
        let config: PreReleaseGatesConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(!config.integration.enabled);
        assert_eq!(config.integration.timeout_secs, 120);
        // Other groups should still be defaults
        assert!(config.backend.cargo_check);
        assert!(config.e2e.enabled);
    }

    #[test]
    fn test_deserialize_e2e_disabled_non_headless() {
        let yaml = r#"
e2e:
  enabled: false
  timeout_secs: 900
  headless: false
"#;
        let config: PreReleaseGatesConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(!config.e2e.enabled);
        assert_eq!(config.e2e.timeout_secs, 900);
        assert!(!config.e2e.headless);
    }

    #[test]
    fn test_deserialize_post_deploy_disabled() {
        let yaml = r#"
post_deploy:
  smoke_queries: false
  timeout_secs: 15
  retries: 1
"#;
        let config: PreReleaseGatesConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(!config.post_deploy.smoke_queries);
        assert_eq!(config.post_deploy.timeout_secs, 15);
        assert_eq!(config.post_deploy.retries, 1);
    }

    #[test]
    fn test_deserialize_partial_integration_uses_defaults() {
        let yaml = r#"
integration:
  enabled: false
"#;
        let config: PreReleaseGatesConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(!config.integration.enabled);
        // timeout_secs should default to 300
        assert_eq!(config.integration.timeout_secs, 300);
    }

    #[test]
    fn test_deserialize_partial_e2e_uses_defaults() {
        let yaml = r#"
e2e:
  timeout_secs: 1200
"#;
        let config: PreReleaseGatesConfig = serde_yaml::from_str(yaml).unwrap();
        // enabled and headless should default to true
        assert!(config.e2e.enabled);
        assert_eq!(config.e2e.timeout_secs, 1200);
        assert!(config.e2e.headless);
    }

    #[test]
    fn test_deserialize_full_config() {
        let yaml = r#"
enabled: true
fail_on_error: false
backend:
  cargo_check: true
  cargo_clippy: false
  cargo_fmt: true
  cargo_test: false
  extract_schema: true
migrations:
  idempotency_check: true
  soft_delete_check: false
  seaorm_safety_check: true
frontend:
  codegen_drift: false
  type_check: true
  lint: true
  linter: eslint
  unit_tests: true
integration:
  enabled: true
  timeout_secs: 180
e2e:
  enabled: false
  timeout_secs: 300
  headless: true
post_deploy:
  smoke_queries: true
  timeout_secs: 60
  retries: 5
"#;
        let config: PreReleaseGatesConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.enabled);
        assert!(!config.fail_on_error);
        assert!(!config.backend.cargo_clippy);
        assert!(!config.backend.cargo_test);
        assert!(!config.migrations.soft_delete_check);
        assert!(!config.frontend.codegen_drift);
        assert_eq!(config.frontend.linter, "eslint");
        assert!(config.integration.enabled);
        assert_eq!(config.integration.timeout_secs, 180);
        assert!(!config.e2e.enabled);
        assert_eq!(config.e2e.timeout_secs, 300);
        assert!(config.post_deploy.smoke_queries);
        assert_eq!(config.post_deploy.timeout_secs, 60);
        assert_eq!(config.post_deploy.retries, 5);
    }

    #[test]
    fn test_serialize_roundtrip() {
        let config = PreReleaseGatesConfig::default();
        let yaml = serde_yaml::to_string(&config).unwrap();
        let roundtripped: PreReleaseGatesConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(config.enabled, roundtripped.enabled);
        assert_eq!(config.fail_on_error, roundtripped.fail_on_error);
        assert_eq!(config.integration.enabled, roundtripped.integration.enabled);
        assert_eq!(
            config.integration.timeout_secs,
            roundtripped.integration.timeout_secs
        );
        assert_eq!(config.e2e.enabled, roundtripped.e2e.enabled);
        assert_eq!(config.e2e.timeout_secs, roundtripped.e2e.timeout_secs);
        assert_eq!(config.e2e.headless, roundtripped.e2e.headless);
        assert_eq!(
            config.post_deploy.smoke_queries,
            roundtripped.post_deploy.smoke_queries
        );
        assert_eq!(
            config.post_deploy.timeout_secs,
            roundtripped.post_deploy.timeout_secs
        );
        assert_eq!(config.post_deploy.retries, roundtripped.post_deploy.retries);
    }

    #[test]
    fn test_deserialize_from_real_deploy_yaml_prerelease_section() {
        // Simulates the actual deploy.yaml prerelease section
        let yaml = r#"
frontend:
  unit_tests: true
integration:
  enabled: true
  timeout_secs: 300
e2e:
  enabled: true
  timeout_secs: 600
  headless: true
post_deploy:
  smoke_queries: true
  timeout_secs: 30
  retries: 3
"#;
        let config: PreReleaseGatesConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.frontend.unit_tests);
        assert!(config.integration.enabled);
        assert_eq!(config.integration.timeout_secs, 300);
        assert!(config.e2e.enabled);
        assert_eq!(config.e2e.timeout_secs, 600);
        assert!(config.e2e.headless);
        assert!(config.post_deploy.smoke_queries);
        assert_eq!(config.post_deploy.timeout_secs, 30);
        assert_eq!(config.post_deploy.retries, 3);
    }

    #[test]
    fn test_deserialize_all_gates_disabled() {
        let yaml = r#"
enabled: false
backend:
  cargo_check: false
  cargo_clippy: false
  cargo_fmt: false
  cargo_test: false
  extract_schema: false
migrations:
  idempotency_check: false
  soft_delete_check: false
  seaorm_safety_check: false
frontend:
  codegen_drift: false
  type_check: false
  lint: false
  unit_tests: false
integration:
  enabled: false
e2e:
  enabled: false
post_deploy:
  smoke_queries: false
"#;
        let config: PreReleaseGatesConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(!config.enabled);
        assert!(!config.backend.cargo_check);
        assert!(!config.backend.cargo_clippy);
        assert!(!config.backend.cargo_fmt);
        assert!(!config.backend.cargo_test);
        assert!(!config.backend.extract_schema);
        assert!(!config.migrations.idempotency_check);
        assert!(!config.migrations.soft_delete_check);
        assert!(!config.migrations.seaorm_safety_check);
        assert!(!config.frontend.codegen_drift);
        assert!(!config.frontend.type_check);
        assert!(!config.frontend.lint);
        assert!(!config.frontend.unit_tests);
        assert!(!config.integration.enabled);
        assert!(!config.e2e.enabled);
        assert!(!config.post_deploy.smoke_queries);
    }
}
