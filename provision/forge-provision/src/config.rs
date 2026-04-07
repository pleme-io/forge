//! Configuration structures for forge-provision
//!
//! Defines all configuration types for database and cache provisioning with sensible
//! defaults and comprehensive validation support.

use serde::{Deserialize, Serialize};

// =============================================================================
// PostgreSQL Configuration
// =============================================================================

/// Complete PostgreSQL provisioning configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PostgresConfig {
    /// Connection settings
    #[serde(default)]
    pub connection: ConnectionConfig,

    /// Database configuration
    pub database: DatabaseConfig,

    /// Application user configuration
    pub user: UserConfig,

    /// Extensions to enable
    #[serde(default)]
    pub extensions: Vec<String>,

    /// CDC configuration (optional)
    pub cdc: Option<CdcConfig>,
}

/// PostgreSQL connection configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConnectionConfig {
    /// PostgreSQL host
    #[serde(default = "default_host")]
    pub host: String,

    /// PostgreSQL port
    #[serde(default = "default_port")]
    pub port: u16,

    /// Admin user for database operations
    #[serde(default = "default_admin_user")]
    pub admin_user: String,

    /// Admin database to connect to initially (default: postgres)
    #[serde(default = "default_admin_database")]
    pub admin_database: String,

    /// Connection retry interval in seconds (default: 2, range: 1-60)
    #[serde(default = "default_retry_interval_secs")]
    pub retry_interval_secs: u64,

    /// Maximum retry attempts (0 = infinite, default: 30, range: 0-1000)
    #[serde(default = "default_max_retry_attempts")]
    pub max_retry_attempts: u32,

    /// Connection timeout in seconds (default: 10, range: 1-300)
    #[serde(default = "default_connection_timeout_secs")]
    pub connection_timeout_secs: u64,

    /// Maximum connections in admin pool (default: 2, range: 1-50)
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
}

impl ConnectionConfig {
    /// Validate connection configuration values are within reasonable bounds
    pub fn validate(&self) -> anyhow::Result<()> {
        use crate::validation::validate_numeric_range;

        if self.port == 0 {
            anyhow::bail!("PostgreSQL port cannot be 0");
        }

        validate_numeric_range(
            self.retry_interval_secs,
            "retry_interval_secs",
            1,
            60,
        )?;

        if self.max_retry_attempts > 1000 {
            anyhow::bail!(
                "max_retry_attempts must be <= 1000, got: {}",
                self.max_retry_attempts
            );
        }

        validate_numeric_range(
            self.connection_timeout_secs,
            "connection_timeout_secs",
            1,
            300,
        )?;

        validate_numeric_range(
            self.max_connections as u64,
            "max_connections",
            1,
            50,
        )?;

        Ok(())
    }
}

/// Database-specific configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DatabaseConfig {
    /// Database name
    pub name: String,

    /// Schema to use (default: public)
    #[serde(default = "default_schema")]
    pub schema: String,
}

/// Application user configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserConfig {
    /// Username
    pub name: String,

    /// Environment variable containing the password
    pub password_env: String,
}

/// Change Data Capture (CDC) configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CdcConfig {
    /// Replication user name
    #[serde(default = "default_cdc_user")]
    pub user: String,

    /// Environment variable containing the replication user password
    pub password_env: String,

    /// Publication name for logical replication
    #[serde(default = "default_publication")]
    pub publication: String,
}

// Default value functions
fn default_host() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    5432
}

fn default_admin_user() -> String {
    "postgres".to_string()
}

fn default_admin_database() -> String {
    "postgres".to_string()
}

fn default_retry_interval_secs() -> u64 {
    2
}

fn default_max_retry_attempts() -> u32 {
    30
}

fn default_connection_timeout_secs() -> u64 {
    10
}

fn default_max_connections() -> u32 {
    2
}

fn default_schema() -> String {
    "public".to_string()
}

fn default_cdc_user() -> String {
    "cdc_replication".to_string()
}

fn default_publication() -> String {
    "cdc_publication".to_string()
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            admin_user: default_admin_user(),
            admin_database: default_admin_database(),
            retry_interval_secs: default_retry_interval_secs(),
            max_retry_attempts: default_max_retry_attempts(),
            connection_timeout_secs: default_connection_timeout_secs(),
            max_connections: default_max_connections(),
        }
    }
}

// =============================================================================
// Attic Cache Configuration
// =============================================================================

/// Attic cache provisioning configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AtticProvisionConfig {
    /// Cache name to provision
    pub cache_name: String,

    /// Server configuration
    #[serde(default)]
    pub server: AtticServerConfig,

    /// Cache configuration options
    #[serde(default)]
    pub cache: CacheConfig,

    /// Environment variable containing JWT token
    pub token_env: String,

    /// Config directory path
    #[serde(default = "default_config_dir")]
    pub config_dir: String,

    /// HTTP request timeout in seconds (default: 30, range: 5-300)
    #[serde(default = "default_http_timeout_secs")]
    pub http_timeout_secs: u64,

    /// Maximum retry attempts for HTTP requests (default: 3, range: 0-10)
    #[serde(default = "default_http_max_retries")]
    pub http_max_retries: u32,

    /// Retry interval in seconds between HTTP attempts (default: 2, range: 1-60)
    #[serde(default = "default_http_retry_interval_secs")]
    pub http_retry_interval_secs: u64,
}

impl AtticProvisionConfig {
    /// Validate Attic configuration values are within reasonable bounds
    pub fn validate(&self) -> anyhow::Result<()> {
        use crate::validation::validate_numeric_range;

        if self.cache_name.is_empty() {
            anyhow::bail!("cache_name cannot be empty");
        }

        validate_numeric_range(self.http_timeout_secs, "http_timeout_secs", 5, 300)?;

        if self.http_max_retries > 10 {
            anyhow::bail!(
                "http_max_retries must be <= 10, got: {}",
                self.http_max_retries
            );
        }

        validate_numeric_range(
            self.http_retry_interval_secs,
            "http_retry_interval_secs",
            1,
            60,
        )?;

        Ok(())
    }
}

/// Attic server configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AtticServerConfig {
    /// Server endpoint URL
    #[serde(default = "default_attic_endpoint")]
    pub endpoint: String,

    /// Server name in config file
    #[serde(default = "default_attic_server_name")]
    pub name: String,
}

/// Cache-specific configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CacheConfig {
    /// Whether cache is public
    #[serde(default)]
    pub is_public: bool,

    /// Nix store directory
    #[serde(default = "default_store_dir")]
    pub store_dir: String,

    /// Cache priority (lower = higher priority)
    #[serde(default = "default_cache_priority")]
    pub priority: i32,

    /// Upstream cache key names
    #[serde(default)]
    pub upstream_cache_key_names: Vec<String>,

    /// Keypair strategy: "Generate" or custom base64 keypair (default: "Generate")
    #[serde(default = "default_keypair_strategy")]
    pub keypair_strategy: String,
}

/// Attic config file structure (TOML format)
#[derive(Debug, Serialize, Deserialize)]
pub struct AtticConfigFile {
    #[serde(rename = "default-server")]
    pub default_server: String,
    pub servers: std::collections::HashMap<String, ServerEntry>,
}

/// Individual server entry in config file
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerEntry {
    pub endpoint: String,
    pub token: String,
}

// Attic default value functions
fn default_attic_endpoint() -> String {
    "http://attic-cache:80".to_string()
}

fn default_attic_server_name() -> String {
    "local".to_string()
}

fn default_config_dir() -> String {
    // Use XDG_CONFIG_HOME if set, otherwise $HOME/.config, otherwise /tmp
    // This works for both root and non-root containers
    std::env::var("XDG_CONFIG_HOME")
        .ok()
        .map(|xdg| format!("{}/attic", xdg))
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(|home| format!("{}/.config/attic", home))
        })
        .unwrap_or_else(|| "/tmp/attic".to_string())
}

fn default_store_dir() -> String {
    "/nix/store".to_string()
}

fn default_cache_priority() -> i32 {
    40
}

fn default_keypair_strategy() -> String {
    "Generate".to_string()
}

fn default_http_timeout_secs() -> u64 {
    30
}

fn default_http_max_retries() -> u32 {
    3
}

fn default_http_retry_interval_secs() -> u64 {
    2
}

impl Default for AtticServerConfig {
    fn default() -> Self {
        Self {
            endpoint: default_attic_endpoint(),
            name: default_attic_server_name(),
        }
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            is_public: false,
            store_dir: default_store_dir(),
            priority: default_cache_priority(),
            upstream_cache_key_names: Vec::new(),
            keypair_strategy: default_keypair_strategy(),
        }
    }
}

// =============================================================================
// Nix Builder Configuration
// =============================================================================

/// Nix builder provisioning configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NixBuilderConfig {
    /// SSH server configuration
    #[serde(default)]
    pub ssh: SshConfig,

    /// Nix configuration
    #[serde(default)]
    pub nix: NixConfig,

    /// Attic cache configuration (optional)
    pub attic: Option<NixBuilderAtticConfig>,

    /// Environment variable containing SSH authorized_keys
    #[serde(default = "default_ssh_keys_env")]
    pub ssh_keys_env: String,
}

/// SSH server configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SshConfig {
    /// SSH port
    #[serde(default = "default_ssh_port")]
    pub port: u16,

    /// SSH host key types to generate
    #[serde(default = "default_ssh_key_types")]
    pub host_key_types: Vec<String>,

    /// Allow root login
    #[serde(default = "default_permit_root_login")]
    pub permit_root_login: bool,

    /// Use PAM authentication
    #[serde(default)]
    pub use_pam: bool,
}

/// Nix daemon configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NixConfig {
    /// Substituters (binary caches)
    #[serde(default = "default_substituters")]
    pub substituters: Vec<String>,

    /// Trusted public keys
    #[serde(default = "default_trusted_public_keys")]
    pub trusted_public_keys: Vec<String>,

    /// Max parallel jobs
    #[serde(default = "default_max_jobs")]
    pub max_jobs: String,

    /// Cores per job
    #[serde(default = "default_cores")]
    pub cores: u16,

    /// Experimental features
    #[serde(default = "default_experimental_features")]
    pub experimental_features: Vec<String>,

    /// Binaries to symlink in /usr/bin for SSH PATH
    #[serde(default = "default_nix_binaries")]
    pub binaries_to_symlink: Vec<String>,

    /// Packages to install into Nix profile during provisioning
    #[serde(default = "default_packages_to_install")]
    pub packages_to_install: Vec<String>,
}

/// Attic cache configuration for nix-builder
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NixBuilderAtticConfig {
    /// Attic cache URL
    pub cache_url: String,

    /// Cache name to use
    pub cache_name: String,

    /// Environment variable containing Attic token
    pub token_env: String,
}

// Nix Builder default value functions
fn default_ssh_keys_env() -> String {
    "SSH_AUTHORIZED_KEYS".to_string()
}

fn default_ssh_port() -> u16 {
    22
}

fn default_ssh_key_types() -> Vec<String> {
    vec!["rsa".to_string(), "ed25519".to_string()]
}

fn default_permit_root_login() -> bool {
    true
}

fn default_substituters() -> Vec<String> {
    vec!["https://cache.nixos.org".to_string()]
}

fn default_trusted_public_keys() -> Vec<String> {
    vec!["cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=".to_string()]
}

fn default_max_jobs() -> String {
    "auto".to_string()
}

fn default_cores() -> u16 {
    4
}

fn default_experimental_features() -> Vec<String> {
    vec!["nix-command".to_string(), "flakes".to_string()]
}

fn default_nix_binaries() -> Vec<String> {
    vec![
        "nix".to_string(),
        "nix-store".to_string(),
        "nix-instantiate".to_string(),
        "nix-env".to_string(),
        "nix-build".to_string(),
        "nix-shell".to_string(),
        "nix-channel".to_string(),
    ]
}

fn default_packages_to_install() -> Vec<String> {
    vec![
        "nixpkgs.openssh".to_string(),
        "nixpkgs.attic-client".to_string(),
        "nixpkgs.findutils".to_string(),
        "nixpkgs.bash".to_string(),
    ]
}

impl Default for SshConfig {
    fn default() -> Self {
        Self {
            port: default_ssh_port(),
            host_key_types: default_ssh_key_types(),
            permit_root_login: default_permit_root_login(),
            use_pam: false,
        }
    }
}

impl Default for NixConfig {
    fn default() -> Self {
        Self {
            substituters: default_substituters(),
            trusted_public_keys: default_trusted_public_keys(),
            max_jobs: default_max_jobs(),
            cores: default_cores(),
            experimental_features: default_experimental_features(),
            binaries_to_symlink: default_nix_binaries(),
            packages_to_install: default_packages_to_install(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_config_defaults() {
        let config = ConnectionConfig::default();
        assert_eq!(config.host, "127.0.0.1");
        assert_eq!(config.port, 5432);
        assert_eq!(config.admin_user, "postgres");
        assert_eq!(config.admin_database, "postgres");
        assert_eq!(config.retry_interval_secs, 2);
        assert_eq!(config.max_retry_attempts, 30);
        assert_eq!(config.connection_timeout_secs, 10);
        assert_eq!(config.max_connections, 2);
    }

    #[test]
    fn test_connection_config_validate_default_passes() {
        let config = ConnectionConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_connection_config_validate_zero_port() {
        let mut config = ConnectionConfig::default();
        config.port = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_connection_config_validate_retry_interval_out_of_range() {
        let mut config = ConnectionConfig::default();
        config.retry_interval_secs = 0;
        assert!(config.validate().is_err());

        config.retry_interval_secs = 100;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_connection_config_validate_max_retry_too_high() {
        let mut config = ConnectionConfig::default();
        config.max_retry_attempts = 1001;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_connection_config_validate_timeout_out_of_range() {
        let mut config = ConnectionConfig::default();
        config.connection_timeout_secs = 0;
        assert!(config.validate().is_err());

        config.connection_timeout_secs = 301;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_connection_config_validate_max_connections_out_of_range() {
        let mut config = ConnectionConfig::default();
        config.max_connections = 0;
        assert!(config.validate().is_err());

        config.max_connections = 51;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_attic_provision_config_validate_empty_cache_name() {
        let config = AtticProvisionConfig {
            cache_name: "".to_string(),
            server: AtticServerConfig::default(),
            cache: CacheConfig::default(),
            token_env: "TOKEN".to_string(),
            config_dir: "/tmp".to_string(),
            http_timeout_secs: 30,
            http_max_retries: 3,
            http_retry_interval_secs: 2,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_attic_provision_config_validate_timeout_out_of_range() {
        let config = AtticProvisionConfig {
            cache_name: "cache".to_string(),
            server: AtticServerConfig::default(),
            cache: CacheConfig::default(),
            token_env: "TOKEN".to_string(),
            config_dir: "/tmp".to_string(),
            http_timeout_secs: 1,
            http_max_retries: 3,
            http_retry_interval_secs: 2,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_attic_provision_config_validate_max_retries_too_high() {
        let config = AtticProvisionConfig {
            cache_name: "cache".to_string(),
            server: AtticServerConfig::default(),
            cache: CacheConfig::default(),
            token_env: "TOKEN".to_string(),
            config_dir: "/tmp".to_string(),
            http_timeout_secs: 30,
            http_max_retries: 11,
            http_retry_interval_secs: 2,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_attic_provision_config_validate_retry_interval_out_of_range() {
        let config = AtticProvisionConfig {
            cache_name: "cache".to_string(),
            server: AtticServerConfig::default(),
            cache: CacheConfig::default(),
            token_env: "TOKEN".to_string(),
            config_dir: "/tmp".to_string(),
            http_timeout_secs: 30,
            http_max_retries: 3,
            http_retry_interval_secs: 0,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_attic_provision_config_validate_valid() {
        let config = AtticProvisionConfig {
            cache_name: "cache".to_string(),
            server: AtticServerConfig::default(),
            cache: CacheConfig::default(),
            token_env: "TOKEN".to_string(),
            config_dir: "/tmp".to_string(),
            http_timeout_secs: 30,
            http_max_retries: 3,
            http_retry_interval_secs: 2,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_attic_server_config_defaults() {
        let config = AtticServerConfig::default();
        assert_eq!(config.endpoint, "http://attic-cache:80");
        assert_eq!(config.name, "local");
    }

    #[test]
    fn test_cache_config_defaults() {
        let config = CacheConfig::default();
        assert!(!config.is_public);
        assert_eq!(config.store_dir, "/nix/store");
        assert_eq!(config.priority, 40);
        assert_eq!(config.keypair_strategy, "Generate");
    }

    #[test]
    fn test_ssh_config_defaults() {
        let config = SshConfig::default();
        assert_eq!(config.port, 22);
        assert!(config.permit_root_login);
        assert!(!config.use_pam);
        assert!(config.host_key_types.contains(&"rsa".to_string()));
        assert!(config.host_key_types.contains(&"ed25519".to_string()));
    }

    #[test]
    fn test_nix_config_defaults() {
        let config = NixConfig::default();
        assert!(!config.substituters.is_empty());
        assert!(!config.trusted_public_keys.is_empty());
        assert_eq!(config.max_jobs, "auto");
        assert_eq!(config.cores, 4);
        assert!(config.experimental_features.contains(&"flakes".to_string()));
    }

    #[test]
    fn test_postgres_config_yaml_roundtrip() {
        let yaml = r#"
connection:
  host: "db.example.com"
  port: 5433
database:
  name: "mydb"
  schema: "public"
user:
  name: "appuser"
  password_env: "DB_PASSWORD"
extensions:
  - "uuid-ossp"
  - "pg_trgm"
"#;
        let config: PostgresConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.connection.host, "db.example.com");
        assert_eq!(config.connection.port, 5433);
        assert_eq!(config.database.name, "mydb");
        assert_eq!(config.user.name, "appuser");
        assert_eq!(config.extensions.len(), 2);
        assert!(config.cdc.is_none());
    }
}
