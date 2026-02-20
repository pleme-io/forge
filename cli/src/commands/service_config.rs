//! Service configuration and validation
//!
//! This module provides ServiceConfig for managing service-specific settings
//! including database types, migration parameters, and resource limits.

use anyhow::{anyhow, bail, Context, Result};

/// Database type for service migrations
#[derive(Debug, Clone, PartialEq)]
pub enum DatabaseType {
    /// PostgreSQL database (most services)
    Postgres,
    /// Databend analytical database (analytics service)
    Databend,
    /// Elasticsearch search engine (search service)
    Elasticsearch,
    /// No database migrations needed (stateless services)
    None,
}

/// Validate Kubernetes memory resource format (e.g., "128Mi", "1Gi")
fn validate_memory_resource(s: &str) -> Result<()> {
    if s.is_empty() {
        bail!("Memory resource cannot be empty");
    }

    if !s.ends_with("Mi") && !s.ends_with("Gi") && !s.ends_with("M") && !s.ends_with("G") {
        bail!(
            "Invalid memory format '{}'. Must end with Mi, Gi, M, or G (e.g., '128Mi', '1Gi')",
            s
        );
    }

    // Extract numeric part and validate
    let numeric_part = s.trim_end_matches(|c: char| c.is_alphabetic());
    if numeric_part.is_empty() {
        bail!("Invalid memory value '{}'. Missing numeric part", s);
    }

    let value = numeric_part.parse::<u64>().map_err(|_| {
        anyhow!(
            "Invalid memory value '{}'. Numeric part must be a positive integer",
            s
        )
    })?;

    // Validate reasonable limits (0 is invalid, max 1024Gi)
    if value == 0 {
        bail!("Invalid memory value '{}'. Must be greater than 0", s);
    }

    if s.ends_with("Gi") && value > 1024 {
        bail!("Invalid memory value '{}'. Maximum is 1024Gi", s);
    }

    Ok(())
}

/// Validate Kubernetes CPU resource format (e.g., "100m", "0.5", "2")
fn validate_cpu_resource(s: &str) -> Result<()> {
    if s.is_empty() {
        bail!("CPU resource cannot be empty");
    }

    // Check millicores format (e.g., "100m")
    if s.ends_with('m') {
        let numeric_part = s.trim_end_matches('m');
        if numeric_part.is_empty() {
            bail!("Invalid CPU value '{}'. Missing numeric part", s);
        }

        let value = numeric_part.parse::<u64>().map_err(|_| {
            anyhow!(
                "Invalid CPU millicores value '{}'. Must be a positive integer followed by 'm'",
                s
            )
        })?;

        // Validate reasonable limits (0 is invalid, max 128000m = 128 cores)
        if value == 0 {
            bail!("Invalid CPU value '{}'. Must be greater than 0", s);
        }

        if value > 128000 {
            bail!("Invalid CPU value '{}'. Maximum is 128000m (128 cores)", s);
        }

        return Ok(());
    }

    // Check decimal cores format (e.g., "0.5", "2")
    let value = s.parse::<f64>()
        .map_err(|_| anyhow!("Invalid CPU format '{}'. Must be millicores (e.g., '100m') or cores (e.g., '0.5', '2')", s))?;

    if value <= 0.0 {
        bail!("Invalid CPU value '{}'. Must be greater than 0", s);
    }

    if value > 128.0 {
        bail!("Invalid CPU value '{}'. Maximum is 128 cores", s);
    }

    Ok(())
}

/// Service configuration for release workflow
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    /// Service name (e.g., "auth", "analytics", "search")
    name: String,
    /// Database type for migrations
    database_type: DatabaseType,
    /// Migration job timeout in seconds (default: 300)
    migration_timeout_secs: u64,
    /// Migration job memory request (default: "128Mi")
    migration_memory_request: String,
    /// Migration job memory limit (default: "256Mi")
    migration_memory_limit: String,
    /// Migration job CPU request (default: "100m")
    migration_cpu_request: String,
    /// Migration job CPU limit (default: "500m")
    migration_cpu_limit: String,
}

impl ServiceConfig {
    /// Create default configuration for a service
    /// Automatically detects database type based on service name
    ///
    /// # Database-Specific Defaults
    /// - PostgreSQL: 300s timeout (standard migrations)
    /// - ClickHouse: 600s timeout (analytics migrations can be slow)
    /// - Elasticsearch: 450s timeout (index creation can be slow)
    pub fn new(name: String) -> Self {
        let database_type = match name.as_str() {
            "analytics" => DatabaseType::Databend,
            // search service uses PostgreSQL + MeiliSearch (not Elasticsearch)
            // MeiliSearch doesn't need migrations - it's a search engine with dynamic indices
            // All other services use PostgreSQL
            _ => DatabaseType::Postgres,
        };

        Self {
            name,
            database_type,
            migration_timeout_secs: 0, // Will be set from config
            migration_memory_request: String::new(),
            migration_memory_limit: String::new(),
            migration_cpu_request: String::new(),
            migration_cpu_limit: String::new(),
        }
    }

    /// Create from DeployConfig (preferred method)
    pub fn from_config(name: String, deploy_config: &crate::config::DeployConfig) -> Self {
        // Parse database_type from deploy.yaml string to enum
        let database_type = match deploy_config
            .service
            .migration
            .database_type
            .to_lowercase()
            .as_str()
        {
            "postgres" | "postgresql" => DatabaseType::Postgres,
            "databend" | "clickhouse" => DatabaseType::Databend,
            "elasticsearch" | "meilisearch" => DatabaseType::Elasticsearch, // Treat both as Elasticsearch-like
            "none" => DatabaseType::None,
            other => {
                eprintln!("⚠️  Warning: Unknown database_type '{}' in deploy.yaml, defaulting to postgres", other);
                DatabaseType::Postgres
            }
        };

        Self {
            name,
            database_type: database_type.clone(),
            migration_timeout_secs: deploy_config.service.migration.timeout_secs,
            migration_memory_request: deploy_config.service.migration.memory_request.clone(),
            migration_memory_limit: deploy_config.service.migration.memory_limit.clone(),
            migration_cpu_request: deploy_config.service.migration.cpu_request.clone(),
            migration_cpu_limit: deploy_config.service.migration.cpu_limit.clone(),
        }
    }

    /// Create custom configuration with overrides
    pub fn with_database_type(mut self, db_type: DatabaseType) -> Self {
        self.database_type = db_type;
        self
    }

    /// Set custom migration timeout
    pub fn with_migration_timeout(mut self, timeout_secs: u64) -> Self {
        self.migration_timeout_secs = timeout_secs;
        self
    }

    /// Set custom resource limits with validation
    ///
    /// # Errors
    /// Returns error if resource formats are invalid
    ///
    /// # Examples
    /// ```ignore
    /// config.with_resources("256Mi".into(), "512Mi".into(), "200m".into(), "1".into())?;
    /// ```
    pub fn with_resources(
        mut self,
        memory_request: String,
        memory_limit: String,
        cpu_request: String,
        cpu_limit: String,
    ) -> Result<Self> {
        // Validate all resource strings
        validate_memory_resource(&memory_request).context("Invalid memory request")?;
        validate_memory_resource(&memory_limit).context("Invalid memory limit")?;
        validate_cpu_resource(&cpu_request).context("Invalid CPU request")?;
        validate_cpu_resource(&cpu_limit).context("Invalid CPU limit")?;

        self.migration_memory_request = memory_request;
        self.migration_memory_limit = memory_limit;
        self.migration_cpu_request = cpu_request;
        self.migration_cpu_limit = cpu_limit;
        Ok(self)
    }

    // Getter methods

    /// Get service name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get database type
    pub fn database_type(&self) -> &DatabaseType {
        &self.database_type
    }

    /// Get migration timeout in seconds
    pub fn migration_timeout_secs(&self) -> u64 {
        self.migration_timeout_secs
    }

    /// Get migration memory request
    pub fn migration_memory_request(&self) -> &str {
        &self.migration_memory_request
    }

    /// Get migration memory limit
    pub fn migration_memory_limit(&self) -> &str {
        &self.migration_memory_limit
    }

    /// Get migration CPU request
    pub fn migration_cpu_request(&self) -> &str {
        &self.migration_cpu_request
    }

    /// Get migration CPU limit
    pub fn migration_cpu_limit(&self) -> &str {
        &self.migration_cpu_limit
    }
}
