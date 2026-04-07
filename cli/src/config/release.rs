//! Release workflow configuration for build-once-promote pattern.
//!
//! This module handles multi-environment deployments where a single image
//! is built once and promoted across environments in order:
//! staging → production-a → production-b

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Release workflow configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseConfig {
    /// Default release mode: "all" (deploy to all envs) or "staging" (staging only)
    #[serde(default = "default_release_mode")]
    pub default_mode: String,

    /// ACTIVE environments - only these will receive deployments
    /// If not specified, defaults to environment_order (all environments)
    /// Use this to control which environments are currently being deployed to
    #[serde(default)]
    pub active_environments: Option<Vec<String>>,

    /// Order of environment deployments (CRITICAL: staging must be first)
    /// Defines the full promotion order, but only active_environments are deployed
    #[serde(default = "default_environment_order")]
    pub environment_order: Vec<String>,

    /// Whether to wait for each environment before proceeding to next
    #[serde(default)]
    pub wait_between_environments: bool,

    /// Whether to continue if an environment fails
    #[serde(default)]
    pub continue_on_failure: bool,

    /// Environments that trigger artifact build + push.
    /// If None, all active environments trigger build (backward compat).
    #[serde(default)]
    pub build_environments: Option<Vec<String>>,

    /// Current artifact information (written after build, read for deploy-only).
    #[serde(default)]
    pub artifact: Option<ArtifactInfo>,
}

/// Artifact information persisted in deploy.yaml after a build.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ArtifactInfo {
    /// Image tag (e.g., the git SHA suffix).
    #[serde(default)]
    pub tag: String,

    /// ISO 8601 timestamp of when the artifact was built.
    #[serde(default)]
    pub built_at: String,

    /// Previous image tag for rollback (set when a new tag is written).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub previous_tag: String,

    /// Attestation information (populated by Phase 1.5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<AttestationInfoRecord>,
}

/// Attestation record persisted in artifact.json.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationInfoRecord {
    /// Blake3 signature hash (prefixed: "blake3:abc...").
    pub signature: String,
    /// Certification hash (prefixed: "blake3:def...").
    pub certification_hash: String,
    /// Compliance hash if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compliance_hash: Option<String>,
    /// Whether the product certification passed.
    pub certified: bool,
}

fn default_release_mode() -> String {
    "staging".to_string()
}

fn default_environment_order() -> Vec<String> {
    vec!["staging".to_string()]
}

impl Default for ReleaseConfig {
    fn default() -> Self {
        Self {
            default_mode: default_release_mode(),
            active_environments: None, // None means use environment_order
            environment_order: default_environment_order(),
            wait_between_environments: false,
            continue_on_failure: false,
            build_environments: None,
            artifact: None,
        }
    }
}

impl ReleaseConfig {
    /// Get the effective active environments
    /// Returns active_environments if set, otherwise environment_order
    pub fn effective_environments(&self) -> &[String] {
        self.active_environments
            .as_ref()
            .map(|v| v.as_slice())
            .unwrap_or(&self.environment_order)
    }

    /// Whether this environment should trigger an artifact build + push.
    /// If `build_environments` is not set, all environments trigger build (backward compat).
    pub fn should_build_artifact(&self, env: &str) -> bool {
        self.build_environments
            .as_ref()
            .map(|envs| envs.iter().any(|e| e == env))
            .unwrap_or(true)
    }

    /// Validate release configuration
    pub fn validate(&self) -> Result<()> {
        // Validate default_mode
        if !["all", "staging"].contains(&self.default_mode.as_str()) {
            bail!(
                "release.default_mode must be 'all' or 'staging', got '{}'",
                self.default_mode
            );
        }

        // Validate environment_order is not empty
        if self.environment_order.is_empty() {
            bail!("release.environment_order cannot be empty");
        }

        // Validate active_environments if specified
        if let Some(active) = &self.active_environments {
            if active.is_empty() {
                bail!("release.active_environments cannot be empty if specified");
            }

            // Validate all active environments are in environment_order
            for env in active {
                if !self.environment_order.contains(env) {
                    bail!(
                        "Active environment '{}' not found in environment_order: {:?}",
                        env,
                        self.environment_order
                    );
                }
            }

            // Validate staging is first in active_environments (if it's included)
            if active.contains(&"staging".to_string()) && active[0] != "staging" {
                eprintln!(
                    "⚠️  Warning: 'staging' is in active_environments but not first. \
                     First environment is '{}'. This may cause migration ordering issues.",
                    active[0]
                );
            }
        }

        // Validate staging is first in environment_order (for promotion workflow)
        if self.environment_order.len() > 1 && self.environment_order[0] != "staging" {
            eprintln!(
                "⚠️  Warning: First environment in release order is '{}', not 'staging'. \
                 This may cause migration ordering issues.",
                self.environment_order[0]
            );
        }

        Ok(())
    }

    /// Get environments to deploy based on mode
    /// Respects active_environments filter
    pub fn get_environments(&self, mode: &str) -> Vec<String> {
        let active = self.effective_environments();

        match mode {
            "all" => {
                // Return only environments that are both in order AND active
                self.environment_order
                    .iter()
                    .filter(|env| active.contains(env))
                    .cloned()
                    .collect()
            }
            "staging" => {
                // Only staging if it's active
                if active.contains(&"staging".to_string()) {
                    vec!["staging".to_string()]
                } else {
                    eprintln!("⚠️  Warning: 'staging' requested but not in active_environments");
                    vec![]
                }
            }
            env => {
                // Specific environment - only if it's active
                if active.iter().any(|a| a == env) {
                    vec![env.to_string()]
                } else {
                    eprintln!(
                        "⚠️  Warning: Environment '{}' requested but not in active_environments: {:?}",
                        env, active
                    );
                    vec![]
                }
            }
        }
    }
}

/// Environment configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentConfig {
    /// Kubernetes cluster name (e.g., "cluster-a", "cluster-b")
    pub cluster: String,

    /// Kubernetes namespace (e.g., "myapp-staging")
    pub namespace: String,

    /// Enabled architectures (e.g., ["amd64"])
    #[serde(default = "default_architectures")]
    pub architectures: Vec<String>,
}

fn default_architectures() -> Vec<String> {
    vec!["amd64".to_string()]
}

/// All environment configurations
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnvironmentsConfig {
    /// Map of environment name to configuration
    #[serde(flatten)]
    pub environments: HashMap<String, EnvironmentConfig>,
}

impl EnvironmentsConfig {
    /// Get environment config, resolving aliases
    pub fn get(&self, name: &str, aliases: &HashMap<String, String>) -> Option<&EnvironmentConfig> {
        // Try direct lookup first
        if let Some(config) = self.environments.get(name) {
            return Some(config);
        }

        // Try alias resolution
        if let Some(resolved) = aliases.get(name) {
            return self.environments.get(resolved);
        }

        None
    }

    /// List all environment names
    pub fn names(&self) -> Vec<String> {
        self.environments.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_release_config_defaults() {
        let config = ReleaseConfig::default();
        assert_eq!(config.default_mode, "staging");
        assert!(config.active_environments.is_none());
        assert_eq!(config.environment_order, vec!["staging"]);
        assert!(!config.wait_between_environments);
        assert!(!config.continue_on_failure);
    }

    #[test]
    fn test_effective_environments_without_active() {
        let config = ReleaseConfig::default();
        assert_eq!(config.effective_environments(), &["staging"]);
    }

    #[test]
    fn test_effective_environments_with_active() {
        let config = ReleaseConfig {
            active_environments: Some(vec!["staging".to_string(), "production".to_string()]),
            environment_order: vec!["staging".to_string(), "production".to_string(), "production-b".to_string()],
            ..Default::default()
        };
        assert_eq!(config.effective_environments(), &["staging", "production"]);
    }

    #[test]
    fn test_should_build_artifact_no_build_envs() {
        let config = ReleaseConfig::default();
        assert!(config.should_build_artifact("staging"));
        assert!(config.should_build_artifact("production"));
    }

    #[test]
    fn test_should_build_artifact_with_build_envs() {
        let config = ReleaseConfig {
            build_environments: Some(vec!["staging".to_string()]),
            ..Default::default()
        };
        assert!(config.should_build_artifact("staging"));
        assert!(!config.should_build_artifact("production"));
    }

    #[test]
    fn test_validate_invalid_default_mode() {
        let mut config = ReleaseConfig::default();
        config.default_mode = "invalid".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_empty_environment_order() {
        let mut config = ReleaseConfig::default();
        config.environment_order = vec![];
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_active_env_not_in_order() {
        let config = ReleaseConfig {
            active_environments: Some(vec!["production".to_string()]),
            environment_order: vec!["staging".to_string()],
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_empty_active_environments() {
        let config = ReleaseConfig {
            active_environments: Some(vec![]),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_valid_multi_env() {
        let config = ReleaseConfig {
            default_mode: "all".to_string(),
            active_environments: Some(vec!["staging".to_string(), "production".to_string()]),
            environment_order: vec!["staging".to_string(), "production".to_string()],
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_get_environments_all_mode() {
        let config = ReleaseConfig {
            environment_order: vec!["staging".to_string(), "production".to_string()],
            ..Default::default()
        };
        let envs = config.get_environments("all");
        assert_eq!(envs, vec!["staging", "production"]);
    }

    #[test]
    fn test_get_environments_staging_mode() {
        let config = ReleaseConfig::default();
        let envs = config.get_environments("staging");
        assert_eq!(envs, vec!["staging"]);
    }

    #[test]
    fn test_get_environments_specific_env() {
        let config = ReleaseConfig {
            environment_order: vec!["staging".to_string(), "production".to_string()],
            ..Default::default()
        };
        let envs = config.get_environments("production");
        assert_eq!(envs, vec!["production"]);
    }

    #[test]
    fn test_get_environments_inactive_env_returns_empty() {
        let config = ReleaseConfig {
            active_environments: Some(vec!["staging".to_string()]),
            environment_order: vec!["staging".to_string(), "production".to_string()],
            ..Default::default()
        };
        let envs = config.get_environments("production");
        assert!(envs.is_empty());
    }

    #[test]
    fn test_get_environments_all_mode_respects_active() {
        let config = ReleaseConfig {
            active_environments: Some(vec!["staging".to_string()]),
            environment_order: vec!["staging".to_string(), "production".to_string()],
            ..Default::default()
        };
        let envs = config.get_environments("all");
        assert_eq!(envs, vec!["staging"]);
    }

    #[test]
    fn test_environments_config_get_direct() {
        let mut envs = EnvironmentsConfig::default();
        envs.environments.insert("staging".to_string(), EnvironmentConfig {
            cluster: "primary".to_string(),
            namespace: "ns".to_string(),
            architectures: vec!["amd64".to_string()],
        });
        let aliases = HashMap::new();
        assert!(envs.get("staging", &aliases).is_some());
        assert!(envs.get("production", &aliases).is_none());
    }

    #[test]
    fn test_environments_config_get_with_alias() {
        let mut envs = EnvironmentsConfig::default();
        envs.environments.insert("production-a".to_string(), EnvironmentConfig {
            cluster: "c".to_string(),
            namespace: "ns".to_string(),
            architectures: vec!["amd64".to_string()],
        });
        let mut aliases = HashMap::new();
        aliases.insert("production".to_string(), "production-a".to_string());
        assert!(envs.get("production", &aliases).is_some());
    }

    #[test]
    fn test_environments_config_names() {
        let mut envs = EnvironmentsConfig::default();
        envs.environments.insert("staging".to_string(), EnvironmentConfig {
            cluster: "c".to_string(),
            namespace: "ns".to_string(),
            architectures: vec!["amd64".to_string()],
        });
        let names = envs.names();
        assert_eq!(names.len(), 1);
        assert!(names.contains(&"staging".to_string()));
    }

    #[test]
    fn test_artifact_info_default() {
        let artifact = ArtifactInfo::default();
        assert!(artifact.tag.is_empty());
        assert!(artifact.built_at.is_empty());
        assert!(artifact.previous_tag.is_empty());
        assert!(artifact.attestation.is_none());
    }
}
