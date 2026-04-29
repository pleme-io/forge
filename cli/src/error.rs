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

    #[error("Tool error: {0}")]
    Tool(#[from] ToolError),

    #[error("Infrastructure error: {0}")]
    Infra(#[from] InfraError),
}

/// Container registry errors
///
/// Each fallible operation carries the exact input that failed (registry,
/// tag, image path) so callers can build precise telemetry, retry the
/// failing step in isolation, and produce attestation-grade failure
/// records without reconstructing context from logs.
#[derive(Error, Debug)]
pub enum RegistryError {
    #[error("GHCR token not found. Set GHCR_TOKEN env var or authenticate with `gh auth login`")]
    TokenNotFound,

    #[error("Invalid registry format: {registry}. Expected: host/organization/project/image")]
    InvalidFormat { registry: String },

    #[error("Push to {registry}:{tag} failed after {attempts} attempts: {message}")]
    PushFailed {
        registry: String,
        tag: String,
        attempts: u32,
        message: String,
    },

    #[error("Local image archive not found: {path}")]
    LocalImageNotFound { path: String },

    #[error("Remote image not found: {registry}:{tag}")]
    RemoteImageNotFound { registry: String, tag: String },

    #[error("Manifest index creation failed for {target}: {message}")]
    ManifestFailed { target: String, message: String },
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
///
/// Each variant carries the offending flake attribute (or full flake
/// reference) so callers can attach failure records to the exact build
/// step without parsing log output. `BuildFailed` keeps `exit_code` and
/// `stderr` as separate fields rather than a fused `message` string so
/// downstream telemetry, retry, and Phase 1 attestation records can
/// pattern-match on the failure shape (THEORY §V.4).
#[derive(Error, Debug)]
pub enum NixBuildError {
    #[error("Cargo.nix not found. Run `nix run .#generateCargoNix` first")]
    CargoNixMissing,

    #[error("Nix build failed for {flake_attr} (exit {exit_code:?}): {stderr}")]
    BuildFailed {
        flake_attr: String,
        exit_code: Option<i32>,
        stderr: String,
    },

    #[error("Nix build for {flake_attr} produced an empty store path")]
    EmptyStorePath { flake_attr: String },

    #[error("Failed to spawn nix for {flake_attr}: {message}")]
    ExecFailed { flake_attr: String, message: String },

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

/// Tool lifecycle errors (release, bump, check)
#[derive(Error, Debug)]
pub enum ToolError {
    #[error("Version not found in manifest: {manifest}")]
    VersionNotFound { manifest: String },

    #[error("Unsupported language: {language}")]
    UnsupportedLanguage { language: String },

    #[error("Tag already exists: {tag}")]
    TagAlreadyExists { tag: String },

    #[error("GitHub release failed: {message}")]
    GitHubReleaseFailed { message: String },
}

/// Infrastructure errors (docker, compose, services)
#[derive(Error, Debug)]
pub enum InfraError {
    #[error("Docker not available: {message}")]
    DockerNotAvailable { message: String },

    #[error("Compose file not found: {path}")]
    ComposeFileNotFound { path: String },

    #[error("Service timed out: {service} after {timeout_secs}s")]
    ServiceTimeout { service: String, timeout_secs: u64 },
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

    #[test]
    fn test_registry_error_invalid_format_display() {
        let err = RegistryError::InvalidFormat {
            registry: "bad-registry".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("bad-registry"));
        assert!(msg.contains("Invalid registry format"));
    }

    #[test]
    fn test_registry_error_push_failed_display() {
        let err = RegistryError::PushFailed {
            registry: "ghcr.io/myorg/myproj/svc".to_string(),
            tag: "amd64-abc1234".to_string(),
            attempts: 3,
            message: "network error".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("3"));
        assert!(msg.contains("network error"));
        assert!(
            msg.contains("ghcr.io/myorg/myproj/svc"),
            "registry must appear in display: {msg}"
        );
        assert!(
            msg.contains("amd64-abc1234"),
            "tag must appear in display: {msg}"
        );
    }

    #[test]
    fn test_registry_error_local_image_not_found_display() {
        let err = RegistryError::LocalImageNotFound {
            path: "/tmp/result".to_string(),
        };
        assert!(err.to_string().contains("/tmp/result"));
    }

    #[test]
    fn test_registry_error_remote_image_not_found_display() {
        let err = RegistryError::RemoteImageNotFound {
            registry: "ghcr.io/myorg/myproj/svc".to_string(),
            tag: "amd64-deadbeef".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("ghcr.io/myorg/myproj/svc"));
        assert!(msg.contains("amd64-deadbeef"));
    }

    #[test]
    fn test_registry_error_manifest_failed_display() {
        let err = RegistryError::ManifestFailed {
            target: "ghcr.io/myorg/myproj/svc:abc1234".to_string(),
            message: "index error".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("index error"));
        assert!(
            msg.contains("ghcr.io/myorg/myproj/svc:abc1234"),
            "target must appear in display: {msg}"
        );
    }

    /// Local vs remote image-not-found are distinct conditions and must not
    /// be representable by a single variant. This test pins the split so a
    /// future "merge them back" refactor fails the build.
    #[test]
    fn test_registry_error_image_not_found_split_is_typed() {
        fn classify(e: &RegistryError) -> &'static str {
            match e {
                RegistryError::LocalImageNotFound { .. } => "local",
                RegistryError::RemoteImageNotFound { .. } => "remote",
                _ => "other",
            }
        }
        assert_eq!(
            classify(&RegistryError::LocalImageNotFound {
                path: "/tmp/x".into(),
            }),
            "local"
        );
        assert_eq!(
            classify(&RegistryError::RemoteImageNotFound {
                registry: "ghcr.io/o/p/s".into(),
                tag: "amd64-x".into(),
            }),
            "remote"
        );
    }

    /// Push failures must always carry the registry+tag they targeted so
    /// downstream telemetry never has to reconstruct context from log lines.
    #[test]
    fn test_registry_error_push_failed_carries_target() {
        let err = RegistryError::PushFailed {
            registry: "ghcr.io/o/p/s".into(),
            tag: "arm64-cafebab".into(),
            attempts: 2,
            message: "exit 1".into(),
        };
        match err {
            RegistryError::PushFailed { registry, tag, .. } => {
                assert_eq!(registry, "ghcr.io/o/p/s");
                assert_eq!(tag, "arm64-cafebab");
            }
            _ => panic!("expected PushFailed"),
        }
    }

    #[test]
    fn test_git_error_variants() {
        assert!(GitError::NotARepository
            .to_string()
            .contains("git repository"));
        assert!(GitError::ShaFailed("bad ref".into())
            .to_string()
            .contains("bad ref"));
        assert!(GitError::CommandFailed {
            command: "push".into()
        }
        .to_string()
        .contains("push"));
        assert!(GitError::DirtyWorkingTree
            .to_string()
            .contains("Uncommitted"));
    }

    #[test]
    fn test_nix_build_error_variants() {
        assert!(NixBuildError::CargoNixMissing
            .to_string()
            .contains("Cargo.nix"));
        let err = NixBuildError::BuildFailed {
            flake_attr: ".#pkg".into(),
            exit_code: Some(101),
            stderr: "eval failed".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains(".#pkg"), "flake_attr must appear: {msg}");
        assert!(msg.contains("101"), "exit_code must appear: {msg}");
        assert!(msg.contains("eval failed"), "stderr must appear: {msg}");
        assert!(NixBuildError::FlakeNotFound {
            path: "/tmp".into()
        }
        .to_string()
        .contains("/tmp"));
    }

    /// Build-failed, empty-output, and exec-failed are distinct conditions
    /// and must not be representable by a single fused-message variant.
    /// This test pins the discriminator so downstream code can pattern-match
    /// on the failure shape without parsing strings.
    #[test]
    fn test_nix_build_error_failure_split_is_typed() {
        fn classify(e: &NixBuildError) -> &'static str {
            match e {
                NixBuildError::BuildFailed { .. } => "build",
                NixBuildError::EmptyStorePath { .. } => "empty",
                NixBuildError::ExecFailed { .. } => "exec",
                NixBuildError::CargoNixMissing => "cargo_nix",
                NixBuildError::FlakeNotFound { .. } => "flake",
            }
        }
        assert_eq!(
            classify(&NixBuildError::BuildFailed {
                flake_attr: ".#pkg".into(),
                exit_code: Some(1),
                stderr: "x".into(),
            }),
            "build"
        );
        assert_eq!(
            classify(&NixBuildError::EmptyStorePath {
                flake_attr: ".#pkg".into(),
            }),
            "empty"
        );
        assert_eq!(
            classify(&NixBuildError::ExecFailed {
                flake_attr: ".#pkg".into(),
                message: "no such file".into(),
            }),
            "exec"
        );
    }

    /// `BuildFailed` must surface the flake_attr it was invoked with — never
    /// only embed it in stderr — so attestation records and retry schedulers
    /// can recover the input without log scraping.
    #[test]
    fn test_nix_build_error_build_failed_carries_flake_attr() {
        let err = NixBuildError::BuildFailed {
            flake_attr: ".#postgres-bootstrap-image".into(),
            exit_code: Some(1),
            stderr: "error: attribute 'foo' missing".into(),
        };
        match err {
            NixBuildError::BuildFailed {
                flake_attr,
                exit_code,
                stderr,
            } => {
                assert_eq!(flake_attr, ".#postgres-bootstrap-image");
                assert_eq!(exit_code, Some(1));
                assert!(stderr.contains("attribute 'foo' missing"));
            }
            _ => panic!("expected BuildFailed"),
        }
    }

    #[test]
    fn test_nix_build_error_empty_store_path_display() {
        let err = NixBuildError::EmptyStorePath {
            flake_attr: ".#thing".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains(".#thing"));
        assert!(msg.contains("empty"));
    }

    #[test]
    fn test_nix_build_error_exec_failed_display() {
        let err = NixBuildError::ExecFailed {
            flake_attr: ".#thing".into(),
            message: "No such file or directory".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains(".#thing"));
        assert!(msg.contains("No such file"));
    }

    #[test]
    fn test_kubernetes_error_variants() {
        let err = KubernetesError::DeploymentNotFound {
            name: "web".into(),
            namespace: "prod".into(),
        };
        assert!(err.to_string().contains("web"));
        assert!(err.to_string().contains("prod"));

        let err = KubernetesError::RolloutTimeout { timeout_secs: 120 };
        assert!(err.to_string().contains("120"));

        let err = KubernetesError::FluxReconcileFailed {
            message: "conflict".into(),
        };
        assert!(err.to_string().contains("conflict"));

        let err = KubernetesError::KustomizationFailed {
            path: "k/path".into(),
        };
        assert!(err.to_string().contains("k/path"));
    }

    #[test]
    fn test_config_error_variants() {
        let err = ConfigError::MissingField {
            field: "name".into(),
        };
        assert!(err.to_string().contains("name"));

        let err = ConfigError::InvalidValue {
            field: "port".into(),
            value: "abc".into(),
        };
        assert!(err.to_string().contains("port"));
        assert!(err.to_string().contains("abc"));

        let err = ConfigError::FileNotFound {
            path: "/etc/config".into(),
        };
        assert!(err.to_string().contains("/etc/config"));

        let err = ConfigError::ParseError {
            message: "unexpected token".into(),
        };
        assert!(err.to_string().contains("unexpected token"));
    }

    #[test]
    fn test_migration_error_variants() {
        let err = MigrationError::JobFailed {
            job_name: "api-mig".into(),
        };
        assert!(err.to_string().contains("api-mig"));

        let err = MigrationError::Timeout { timeout_secs: 300 };
        assert!(err.to_string().contains("300"));

        let err = MigrationError::UnknownDatabaseType {
            db_type: "redis".into(),
        };
        assert!(err.to_string().contains("redis"));

        let err = MigrationError::ConnectionFailed {
            message: "refused".into(),
        };
        assert!(err.to_string().contains("refused"));
    }

    #[test]
    fn test_tool_error_variants() {
        let err = ToolError::VersionNotFound {
            manifest: "Cargo.toml".into(),
        };
        assert!(err.to_string().contains("Cargo.toml"));

        let err = ToolError::UnsupportedLanguage {
            language: "cobol".into(),
        };
        assert!(err.to_string().contains("cobol"));

        let err = ToolError::TagAlreadyExists {
            tag: "v1.0.0".into(),
        };
        assert!(err.to_string().contains("v1.0.0"));

        let err = ToolError::GitHubReleaseFailed {
            message: "403".into(),
        };
        assert!(err.to_string().contains("403"));
    }

    #[test]
    fn test_infra_error_variants() {
        let err = InfraError::DockerNotAvailable {
            message: "not running".into(),
        };
        assert!(err.to_string().contains("not running"));

        let err = InfraError::ComposeFileNotFound {
            path: "docker-compose.yaml".into(),
        };
        assert!(err.to_string().contains("docker-compose.yaml"));

        let err = InfraError::ServiceTimeout {
            service: "postgres".into(),
            timeout_secs: 60,
        };
        assert!(err.to_string().contains("postgres"));
        assert!(err.to_string().contains("60"));
    }

    #[test]
    fn test_all_deploy_error_from_conversions() {
        let _: DeployError = GitError::NotARepository.into();
        let _: DeployError = NixBuildError::CargoNixMissing.into();
        let _: DeployError = KubernetesError::RolloutTimeout { timeout_secs: 1 }.into();
        let _: DeployError = ConfigError::MissingField { field: "x".into() }.into();
        let _: DeployError = MigrationError::Timeout { timeout_secs: 1 }.into();
        let _: DeployError = ToolError::TagAlreadyExists { tag: "v1".into() }.into();
        let _: DeployError = InfraError::DockerNotAvailable {
            message: "no".into(),
        }
        .into();
    }

    #[test]
    fn test_deploy_error_display_wraps_inner() {
        let err: DeployError = GitError::NotARepository.into();
        assert!(err.to_string().contains("Git error"));

        let err: DeployError = ConfigError::MissingField { field: "x".into() }.into();
        assert!(err.to_string().contains("Configuration error"));
    }
}
