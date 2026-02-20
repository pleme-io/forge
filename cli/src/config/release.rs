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
