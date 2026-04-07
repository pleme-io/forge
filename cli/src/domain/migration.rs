//! Migration domain types
//!
//! Defines database migration configuration and strategies.

use std::time::Duration;

/// Database types supported for migrations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseType {
    /// PostgreSQL (uses sqlx)
    Postgres,
    /// ClickHouse (uses clickhouse-rs)
    ClickHouse,
    /// Elasticsearch (uses elasticsearch-rs)
    Elasticsearch,
    /// Databend (uses sqlx, compatible with PostgreSQL wire protocol)
    Databend,
    /// No migrations needed
    None,
}

impl DatabaseType {
    /// Get the RUN_MODE value for this database type
    pub fn run_mode(&self) -> Option<&'static str> {
        match self {
            Self::Postgres => Some("migrate"),
            Self::ClickHouse => Some("migrate_clickhouse"),
            Self::Elasticsearch => Some("migrate_elasticsearch"),
            Self::Databend => Some("MIGRATE"),
            Self::None => None,
        }
    }

    /// Parse from string (case-insensitive)
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "postgres" | "postgresql" => Some(Self::Postgres),
            "clickhouse" => Some(Self::ClickHouse),
            "elasticsearch" | "elastic" | "es" => Some(Self::Elasticsearch),
            "databend" => Some(Self::Databend),
            "none" | "" => Some(Self::None),
            _ => None,
        }
    }

    /// Get human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            Self::Postgres => "PostgreSQL",
            Self::ClickHouse => "ClickHouse",
            Self::Elasticsearch => "Elasticsearch",
            Self::Databend => "Databend",
            Self::None => "None",
        }
    }
}

/// Configuration for running migrations
#[derive(Debug, Clone)]
pub struct MigrationConfig {
    /// Database type
    pub database_type: DatabaseType,
    /// Service name (used for job naming)
    pub service: String,
    /// Kubernetes namespace
    pub namespace: String,
    /// Container image to use
    pub image: String,
    /// Image tag
    pub tag: String,
    /// Timeout for migration job
    pub timeout: Duration,
    /// Resource limits
    pub resources: MigrationResources,
}

/// Resource limits for migration jobs
#[derive(Debug, Clone)]
pub struct MigrationResources {
    pub memory_request: String,
    pub memory_limit: String,
    pub cpu_request: String,
    pub cpu_limit: String,
}

impl Default for MigrationResources {
    fn default() -> Self {
        Self {
            memory_request: "128Mi".to_string(),
            memory_limit: "256Mi".to_string(),
            cpu_request: "100m".to_string(),
            cpu_limit: "500m".to_string(),
        }
    }
}

impl MigrationConfig {
    /// Create a new migration config
    pub fn new(
        database_type: DatabaseType,
        service: impl Into<String>,
        namespace: impl Into<String>,
    ) -> Self {
        Self {
            database_type,
            service: service.into(),
            namespace: namespace.into(),
            image: String::new(),
            tag: String::new(),
            timeout: Duration::from_secs(300),
            resources: MigrationResources::default(),
        }
    }

    /// Builder: set image
    pub fn with_image(mut self, image: impl Into<String>) -> Self {
        self.image = image.into();
        self
    }

    /// Builder: set tag
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = tag.into();
        self
    }

    /// Builder: set timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Get the Kubernetes job name for this migration
    pub fn job_name(&self) -> String {
        format!("{}-migration", self.service)
    }

    /// Get the full image reference
    pub fn image_ref(&self) -> String {
        if self.tag.is_empty() {
            self.image.clone()
        } else {
            format!("{}:{}", self.image, self.tag)
        }
    }

    /// Check if migrations should be skipped
    pub fn should_skip(&self) -> bool {
        self.database_type == DatabaseType::None
    }
}

/// Result of a migration execution
#[derive(Debug)]
pub struct MigrationResult {
    pub success: bool,
    pub duration: Duration,
    pub logs: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_type_from_str() {
        assert_eq!(
            DatabaseType::from_str("postgres"),
            Some(DatabaseType::Postgres)
        );
        assert_eq!(
            DatabaseType::from_str("PostgreSQL"),
            Some(DatabaseType::Postgres)
        );
        assert_eq!(
            DatabaseType::from_str("clickhouse"),
            Some(DatabaseType::ClickHouse)
        );
        assert_eq!(DatabaseType::from_str("none"), Some(DatabaseType::None));
        assert_eq!(DatabaseType::from_str("unknown"), None);
    }

    #[test]
    fn test_database_type_run_mode() {
        assert_eq!(DatabaseType::Postgres.run_mode(), Some("migrate"));
        assert_eq!(
            DatabaseType::ClickHouse.run_mode(),
            Some("migrate_clickhouse")
        );
        assert_eq!(DatabaseType::None.run_mode(), None);
    }

    #[test]
    fn test_migration_config() {
        let config = MigrationConfig::new(DatabaseType::Postgres, "api", "myproduct-staging")
            .with_image("ghcr.io/org/project/myproduct-api")
            .with_tag("amd64-abc1234");

        assert_eq!(config.job_name(), "api-migration");
        assert_eq!(
            config.image_ref(),
            "ghcr.io/org/project/myproduct-api:amd64-abc1234"
        );
        assert!(!config.should_skip());
    }

    #[test]
    fn test_database_type_from_str_all_variants() {
        assert_eq!(DatabaseType::from_str("postgresql"), Some(DatabaseType::Postgres));
        assert_eq!(DatabaseType::from_str("elasticsearch"), Some(DatabaseType::Elasticsearch));
        assert_eq!(DatabaseType::from_str("elastic"), Some(DatabaseType::Elasticsearch));
        assert_eq!(DatabaseType::from_str("es"), Some(DatabaseType::Elasticsearch));
        assert_eq!(DatabaseType::from_str("databend"), Some(DatabaseType::Databend));
        assert_eq!(DatabaseType::from_str(""), Some(DatabaseType::None));
        assert_eq!(DatabaseType::from_str("POSTGRES"), Some(DatabaseType::Postgres));
        assert_eq!(DatabaseType::from_str("ClickHouse"), Some(DatabaseType::ClickHouse));
    }

    #[test]
    fn test_database_type_run_mode_all_variants() {
        assert_eq!(DatabaseType::Elasticsearch.run_mode(), Some("migrate_elasticsearch"));
        assert_eq!(DatabaseType::Databend.run_mode(), Some("MIGRATE"));
    }

    #[test]
    fn test_database_type_name() {
        assert_eq!(DatabaseType::Postgres.name(), "PostgreSQL");
        assert_eq!(DatabaseType::ClickHouse.name(), "ClickHouse");
        assert_eq!(DatabaseType::Elasticsearch.name(), "Elasticsearch");
        assert_eq!(DatabaseType::Databend.name(), "Databend");
        assert_eq!(DatabaseType::None.name(), "None");
    }

    #[test]
    fn test_migration_config_image_ref_empty_tag() {
        let config = MigrationConfig::new(DatabaseType::Postgres, "api", "ns")
            .with_image("ghcr.io/org/img");
        assert_eq!(config.image_ref(), "ghcr.io/org/img");
    }

    #[test]
    fn test_migration_config_should_skip() {
        let config = MigrationConfig::new(DatabaseType::None, "api", "ns");
        assert!(config.should_skip());

        let config2 = MigrationConfig::new(DatabaseType::ClickHouse, "api", "ns");
        assert!(!config2.should_skip());
    }

    #[test]
    fn test_migration_config_with_timeout() {
        let config = MigrationConfig::new(DatabaseType::Postgres, "api", "ns")
            .with_timeout(Duration::from_secs(600));
        assert_eq!(config.timeout, Duration::from_secs(600));
    }

    #[test]
    fn test_migration_config_default_timeout() {
        let config = MigrationConfig::new(DatabaseType::Postgres, "api", "ns");
        assert_eq!(config.timeout, Duration::from_secs(300));
    }

    #[test]
    fn test_migration_resources_default() {
        let resources = MigrationResources::default();
        assert_eq!(resources.memory_request, "128Mi");
        assert_eq!(resources.memory_limit, "256Mi");
        assert_eq!(resources.cpu_request, "100m");
        assert_eq!(resources.cpu_limit, "500m");
    }

    #[test]
    fn test_migration_result_fields() {
        let result = MigrationResult {
            success: true,
            duration: Duration::from_secs(42),
            logs: Some("all good".to_string()),
        };
        assert!(result.success);
        assert_eq!(result.duration, Duration::from_secs(42));
        assert_eq!(result.logs.as_deref(), Some("all good"));
    }
}
