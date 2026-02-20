//! Database migration and search sync configuration.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

/// Validate Kubernetes memory format (e.g., "128Mi", "1Gi")
/// Returns the parsed value in bytes for comparison
pub fn validate_memory_format(value: &str) -> Result<u64> {
    let value = value.trim();

    // Parse number and unit
    let (num_str, multiplier) = if value.ends_with("Gi") {
        (&value[..value.len() - 2], 1024 * 1024 * 1024)
    } else if value.ends_with("Mi") {
        (&value[..value.len() - 2], 1024 * 1024)
    } else if value.ends_with('G') {
        (&value[..value.len() - 1], 1000 * 1000 * 1000)
    } else if value.ends_with('M') {
        (&value[..value.len() - 1], 1000 * 1000)
    } else {
        bail!(
            "Invalid memory format '{}'. Must end with Mi, Gi, M, or G",
            value
        );
    };

    let num: u64 = num_str.parse().with_context(|| {
        format!(
            "Invalid memory value '{}'. Expected a number before the unit",
            value
        )
    })?;

    let bytes = num
        .checked_mul(multiplier)
        .ok_or_else(|| anyhow!("Memory value '{}' is too large", value))?;

    // Max 1024Gi = 1099511627776 bytes
    const MAX_MEMORY: u64 = 1024 * 1024 * 1024 * 1024;
    if bytes > MAX_MEMORY {
        bail!("Memory value '{}' exceeds maximum of 1024Gi", value);
    }

    Ok(bytes)
}

/// Validate Kubernetes CPU format (e.g., "100m", "0.5", "2")
/// Returns the parsed value in millicores for comparison
pub fn validate_cpu_format(value: &str) -> Result<u64> {
    let value = value.trim();

    let millicores = if value.ends_with('m') {
        // Millicores format (e.g., "100m")
        let num_str = &value[..value.len() - 1];
        num_str.parse::<u64>().with_context(|| {
            format!(
                "Invalid CPU millicores value '{}'. Expected a number before 'm'",
                value
            )
        })?
    } else {
        // Decimal cores format (e.g., "0.5", "2")
        let cores: f64 = value.parse()
            .with_context(|| format!("Invalid CPU value '{}'. Expected millicores (e.g., '100m') or decimal cores (e.g., '0.5')", value))?;
        (cores * 1000.0) as u64
    };

    // Max 128 cores = 128000 millicores
    const MAX_CPU_MILLICORES: u64 = 128_000;
    if millicores > MAX_CPU_MILLICORES {
        bail!("CPU value '{}' exceeds maximum of 128 cores", value);
    }

    Ok(millicores)
}

/// Service-specific migration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceMigrationConfig {
    /// Database type (postgres, postgresql, databend, clickhouse, elasticsearch, meilisearch, none)
    #[serde(default = "default_database_type")]
    pub database_type: String,

    /// Enable schema migrations (DDL changes)
    #[serde(default = "default_schema_migrations")]
    pub schema_migrations: bool,

    /// Enable data migrations (seed data, backfills)
    #[serde(default = "default_data_migrations")]
    pub data_migrations: bool,

    /// Path to schema migrations directory (relative to service root)
    #[serde(default = "default_schema_migrations_path")]
    pub schema_migrations_path: String,

    /// Path to data migrations directory (relative to service root)
    #[serde(default = "default_data_migrations_path")]
    pub data_migrations_path: String,

    /// Migration timeout in seconds
    #[serde(default = "default_migration_timeout")]
    pub timeout_secs: u64,

    /// Migration job memory request
    #[serde(default = "default_migration_memory_request")]
    pub memory_request: String,

    /// Migration job memory limit
    #[serde(default = "default_migration_memory_limit")]
    pub memory_limit: String,

    /// Migration job CPU request
    #[serde(default = "default_migration_cpu_request")]
    pub cpu_request: String,

    /// Migration job CPU limit
    #[serde(default = "default_migration_cpu_limit")]
    pub cpu_limit: String,

    /// Additional Kubernetes secrets to mount in migration jobs
    /// These are loaded via envFrom secretRef in the migration pod
    /// Example: ["myapp-postgres-connection", "myapp-backend-secrets"]
    #[serde(default)]
    pub secrets: Vec<String>,

    /// Wait for Shinka DatabaseMigration CRD after deploy
    /// When true, forge polls the CRD until it reaches "Ready" for the expected image tag
    #[serde(default)]
    pub shinka_gating: bool,

    /// Override CRD name (defaults to "{product}-{service}")
    #[serde(default)]
    pub shinka_migration_name: Option<String>,

    /// Timeout for Shinka wait in seconds (default: 600)
    #[serde(default = "default_shinka_timeout")]
    pub shinka_timeout_secs: u64,
}

fn default_database_type() -> String {
    "postgres".to_string()
}

fn default_schema_migrations() -> bool {
    true
}

fn default_data_migrations() -> bool {
    false
}

fn default_schema_migrations_path() -> String {
    "migrations".to_string()
}

fn default_data_migrations_path() -> String {
    "data-migrations".to_string()
}

fn default_migration_timeout() -> u64 {
    300
}

fn default_migration_memory_request() -> String {
    "128Mi".to_string()
}

fn default_migration_memory_limit() -> String {
    "256Mi".to_string()
}

fn default_migration_cpu_request() -> String {
    "100m".to_string()
}

fn default_migration_cpu_limit() -> String {
    "500m".to_string()
}

fn default_shinka_timeout() -> u64 {
    600
}

impl Default for ServiceMigrationConfig {
    fn default() -> Self {
        Self {
            database_type: default_database_type(),
            schema_migrations: default_schema_migrations(),
            data_migrations: default_data_migrations(),
            schema_migrations_path: default_schema_migrations_path(),
            data_migrations_path: default_data_migrations_path(),
            timeout_secs: default_migration_timeout(),
            memory_request: default_migration_memory_request(),
            memory_limit: default_migration_memory_limit(),
            cpu_request: default_migration_cpu_request(),
            cpu_limit: default_migration_cpu_limit(),
            secrets: Vec::new(),
            shinka_gating: false,
            shinka_migration_name: None,
            shinka_timeout_secs: default_shinka_timeout(),
        }
    }
}

impl ServiceMigrationConfig {
    /// Validate all resource specifications
    ///
    /// # Errors
    /// Returns error if any resource value has invalid format or exceeds limits
    pub fn validate(&self) -> Result<()> {
        // Validate memory formats
        let mem_req_bytes =
            validate_memory_format(&self.memory_request).context("Invalid memory_request")?;
        let mem_limit_bytes =
            validate_memory_format(&self.memory_limit).context("Invalid memory_limit")?;

        // Validate CPU formats
        let cpu_req_millicores =
            validate_cpu_format(&self.cpu_request).context("Invalid cpu_request")?;
        let cpu_limit_millicores =
            validate_cpu_format(&self.cpu_limit).context("Invalid cpu_limit")?;

        // Validate request <= limit relationships
        if mem_req_bytes > mem_limit_bytes {
            bail!(
                "memory_request ({}) cannot exceed memory_limit ({})",
                self.memory_request,
                self.memory_limit
            );
        }

        if cpu_req_millicores > cpu_limit_millicores {
            bail!(
                "cpu_request ({}) cannot exceed cpu_limit ({})",
                self.cpu_request,
                self.cpu_limit
            );
        }

        // Validate database_type
        let valid_db_types = [
            "postgres",
            "postgresql",
            "databend",
            "clickhouse",
            "elasticsearch",
            "meilisearch",
            "none",
        ];
        if !valid_db_types.contains(&self.database_type.as_str()) {
            bail!(
                "Invalid database_type '{}'. Must be one of: {}",
                self.database_type,
                valid_db_types.join(", ")
            );
        }

        // Validate migration paths are not empty
        if self.schema_migrations && self.schema_migrations_path.trim().is_empty() {
            bail!("schema_migrations_path cannot be empty when schema_migrations is enabled");
        }

        if self.data_migrations && self.data_migrations_path.trim().is_empty() {
            bail!("data_migrations_path cannot be empty when data_migrations is enabled");
        }

        // Validate shinka timeout is reasonable (30s to 1800s)
        if self.shinka_gating && (self.shinka_timeout_secs < 30 || self.shinka_timeout_secs > 1800)
        {
            bail!(
                "shinka_timeout_secs must be between 30 and 1800, got {}",
                self.shinka_timeout_secs
            );
        }

        Ok(())
    }
}

/// Search service GitOps configuration for post-deploy sync
/// Used by the search service to sync index/policy configs after K8s deployment
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NovaSearchConfig {
    /// Enable search service GitOps sync during release
    #[serde(default)]
    pub enabled: bool,

    /// Path to config directory (relative to service root)
    /// Contains kustomization.yaml and index/policy YAML files
    #[serde(default = "default_search_config_path")]
    pub config_path: String,

    /// Search service REST API URL
    #[serde(default = "default_search_api_url")]
    pub api_url: String,

    /// Dry-run mode (show what would be applied without making changes)
    #[serde(default)]
    pub dry_run: bool,

    /// Prune orphaned resources not in the config
    #[serde(default)]
    pub prune: bool,

    /// Timeout for sync operation (seconds)
    #[serde(default = "default_search_timeout")]
    pub timeout_secs: u64,
}

fn default_search_config_path() -> String {
    "config".to_string()
}

fn default_search_api_url() -> String {
    "http://localhost:8081".to_string()
}

fn default_search_timeout() -> u64 {
    120
}
