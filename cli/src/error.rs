//! Centralized error types for forge
//!
//! Uses thiserror for typed errors that can be matched on,
//! while still being compatible with anyhow for propagation.

use thiserror::Error;

/// Top-level error type for forge operations
#[derive(Error, Debug)]
pub enum DeployError {
    #[error("Registry error: {0}")]
    Registry(#[from] RegistryError),

    #[error("Git error: {0}")]
    Git(#[from] GitError),

    #[error("Nix build error: {0}")]
    NixBuild(#[from] NixBuildError),

    #[error("Kubernetes error: {0}")]
    Kubernetes(#[from] KubernetesError),

    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    #[error("Migration error: {0}")]
    Migration(#[from] MigrationError),
}

/// Container registry errors
#[derive(Error, Debug)]
pub enum RegistryError {
    #[error("GHCR token not found. Set GHCR_TOKEN env var or authenticate with `gh auth login`")]
    TokenNotFound,

    #[error("Invalid registry format: {registry}. Expected: host/organization/project/image")]
    InvalidFormat { registry: String },

    #[error("Push failed after {attempts} attempts: {message}")]
    PushFailed { attempts: u32, message: String },

    #[error("Image not found at path: {path}")]
    ImageNotFound { path: String },

    #[error("Manifest index creation failed: {message}")]
    ManifestFailed { message: String },
}

/// Git operation errors
#[derive(Error, Debug)]
pub enum GitError {
    #[error("Not a git repository")]
    NotARepository,

    #[error("Failed to get git SHA: {0}")]
    ShaFailed(String),

    #[error("Git command failed: {command}")]
    CommandFailed { command: String },

    #[error("Uncommitted changes detected")]
    DirtyWorkingTree,
}

/// Nix build errors
#[derive(Error, Debug)]
pub enum NixBuildError {
    #[error("Cargo.nix not found. Run `nix run .#generateCargoNix` first")]
    CargoNixMissing,

    #[error("Build failed for {flake_attr}: {message}")]
    BuildFailed { flake_attr: String, message: String },

    #[error("Flake not found at {path}")]
    FlakeNotFound { path: String },
}

/// Kubernetes errors
#[derive(Error, Debug)]
pub enum KubernetesError {
    #[error("Deployment {name} not found in namespace {namespace}")]
    DeploymentNotFound { name: String, namespace: String },

    #[error("Rollout timed out after {timeout_secs}s")]
    RolloutTimeout { timeout_secs: u64 },

    #[error("Flux reconciliation failed: {message}")]
    FluxReconcileFailed { message: String },

    #[error("Kustomization update failed: {path}")]
    KustomizationFailed { path: String },
}

/// Configuration errors
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Required configuration missing: {field}")]
    MissingField { field: String },

    #[error("Invalid configuration value for {field}: {value}")]
    InvalidValue { field: String, value: String },

    #[error("Config file not found: {path}")]
    FileNotFound { path: String },

    #[error("Failed to parse config: {message}")]
    ParseError { message: String },
}

/// Migration errors
#[derive(Error, Debug)]
pub enum MigrationError {
    #[error("Migration job failed: {job_name}")]
    JobFailed { job_name: String },

    #[error("Migration timed out after {timeout_secs}s")]
    Timeout { timeout_secs: u64 },

    #[error("Unknown database type: {db_type}")]
    UnknownDatabaseType { db_type: String },

    #[error("Database connection failed: {message}")]
    ConnectionFailed { message: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_error_display() {
        let err = RegistryError::TokenNotFound;
        assert!(err.to_string().contains("GHCR_TOKEN"));
    }

    #[test]
    fn test_error_conversion() {
        let registry_err = RegistryError::TokenNotFound;
        let deploy_err: DeployError = registry_err.into();
        assert!(matches!(deploy_err, DeployError::Registry(_)));
    }
}
