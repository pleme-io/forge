//! # Path Builder
//!
//! Centralized path construction for all deployment artifacts.
//! Eliminates hardcoded paths by computing them from configuration.
//!
//! ## Design Principles
//!
//! 1. **Single source of truth**: All paths derived from DeployConfig
//! 2. **Template substitution**: Support {product}, {service}, {cluster}, {environment}, etc.
//! 3. **Type safety**: Return PathBuf, not strings
//! 4. **Validation**: Ensure paths are within repo boundaries
//! 5. **Flexibility**: Support both product and infrastructure services
//!
//! ## Usage
//!
//! ```rust,ignore
//! let config = DeployConfig::load_for_service("cart")?;
//! let paths = PathBuilder::new(&config)?;
//!
//! let manifest = paths.k8s_manifest()?;
//! let schema = paths.subgraph_schema()?;
//! let supergraph = paths.supergraph_router()?;
//! ```

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use crate::config::DeployConfig;

/// Centralized path builder for all deployment artifacts
pub struct PathBuilder<'a> {
    config: &'a DeployConfig,
    repo_root: PathBuf,
}

impl<'a> PathBuilder<'a> {
    /// Create a new PathBuilder from a DeployConfig
    pub fn new(config: &'a DeployConfig) -> Result<Self> {
        // Try to get repo root from environment variable first (set by --repo-root parameter)
        // Otherwise use find_repo_root to walk up directory tree
        let repo_root = if let Ok(root) = std::env::var("REPO_ROOT") {
            PathBuf::from(root)
        } else {
            let current_dir = std::env::current_dir().context("Failed to get current directory")?;
            DeployConfig::find_repo_root(&current_dir)?
        };

        Ok(Self { config, repo_root })
    }

    /// Get the repository root directory
    pub fn repo_root(&self) -> &Path {
        &self.repo_root
    }

    // ========================================================================
    // Kubernetes Manifest Paths
    // ========================================================================

    /// Get the Kubernetes manifest path for this service
    /// Pattern: "nix/k8s/clusters/{cluster}/products/{product}-{environment}/services/{service}/kustomization.yaml"
    pub fn k8s_manifest(&self) -> Result<PathBuf> {
        let pattern = &self.config.global.paths.k8s_manifest_pattern;
        self.expand_pattern(pattern)
    }

    /// Get the service deployment manifest directory
    /// Pattern: "nix/k8s/clusters/{cluster}/products/{product}-{environment}/services/{service}"
    pub fn k8s_service_dir(&self) -> Result<PathBuf> {
        let manifest = self.k8s_manifest()?;
        manifest
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Manifest path has no parent directory"))
            .map(|p| p.to_path_buf())
    }

    /// Get the product deployment directory
    /// Pattern: "nix/k8s/clusters/{cluster}/products/{product}-{environment}"
    pub fn k8s_product_dir(&self) -> Result<PathBuf> {
        let pattern = "nix/k8s/clusters/{cluster}/products/{product}-{environment}";
        self.expand_pattern(pattern)
    }

    // ========================================================================
    // GraphQL Federation Paths
    // ========================================================================

    /// Get the subgraph schema file path for this service
    /// Pattern: "pkgs/products/{product}/infrastructure/hive-router/subgraphs/{service}.graphql"
    /// Overrideable via service.graphql.subgraph_path
    pub fn subgraph_schema(&self) -> Result<PathBuf> {
        if let Some(custom_pattern) = &self.config.service.graphql.subgraph_path {
            return self.expand_pattern(custom_pattern);
        }

        let pattern = format!(
            "{}/{}/hive-router/subgraphs/{{service}}.graphql",
            self.config.global.paths.products_root, self.config.product.name
        );
        self.expand_pattern(&pattern)
    }

    /// Get the supergraph router configuration path
    /// Pattern: "nix/k8s/clusters/{cluster}/products/{product}-{environment}/hive-router/supergraph.graphql"
    /// Overrideable via service.graphql.supergraph_router_path
    pub fn supergraph_router(&self) -> Result<PathBuf> {
        if let Some(custom_pattern) = &self.config.service.graphql.supergraph_router_path {
            return self.expand_pattern(custom_pattern);
        }

        let pattern = format!(
            "nix/k8s/clusters/{{cluster}}/products/{{product}}-{{environment}}/hive-router/supergraph.graphql"
        );
        self.expand_pattern(&pattern)
    }

    /// Get the hive-router deployment manifest path
    /// Pattern: "nix/k8s/clusters/{cluster}/products/{product}-{environment}/hive-router/hive-router-deployment.yaml"
    /// Overrideable via service.graphql.hive_router_deployment_path
    pub fn hive_router_deployment(&self) -> Result<PathBuf> {
        if let Some(custom_pattern) = &self.config.service.graphql.hive_router_deployment_path {
            return self.expand_pattern(custom_pattern);
        }

        let pattern = format!(
            "nix/k8s/clusters/{{cluster}}/products/{{product}}-{{environment}}/hive-router/hive-router-deployment.yaml"
        );
        self.expand_pattern(&pattern)
    }

    /// Get the supergraph config YAML path
    /// Pattern: "pkgs/products/{product}/infrastructure/hive-router/supergraph-config.yaml"
    pub fn supergraph_config(&self) -> Result<PathBuf> {
        let pattern = format!(
            "{}/{}/hive-router/supergraph-config.yaml",
            self.config.global.paths.products_root, self.config.product.name
        );
        self.expand_pattern(&pattern)
    }

    /// Get the subgraphs directory
    /// Pattern: "pkgs/products/{product}/infrastructure/hive-router/subgraphs"
    pub fn subgraphs_dir(&self) -> Result<PathBuf> {
        let pattern = format!(
            "{}/{}/hive-router/subgraphs",
            self.config.global.paths.products_root, self.config.product.name
        );
        self.expand_pattern(&pattern)
    }

    /// Get the hive-router directory in K8s manifests
    /// Pattern: "nix/k8s/clusters/{cluster}/products/{product}-{environment}/hive-router"
    pub fn k8s_hive_router_dir(&self) -> Result<PathBuf> {
        let pattern = "nix/k8s/clusters/{cluster}/products/{product}-{environment}/hive-router";
        self.expand_pattern(&pattern)
    }

    // ========================================================================
    // Product Structure Paths
    // ========================================================================

    /// Get the product root directory
    /// Pattern: "pkgs/products/{product}"
    pub fn product_root(&self) -> Result<PathBuf> {
        let pattern = format!("{}/{{product}}", self.config.global.paths.products_root);
        self.expand_pattern(&pattern)
    }

    /// Get the services directory for this product
    /// Pattern: "pkgs/products/{product}/services/rust"
    pub fn services_dir(&self) -> Result<PathBuf> {
        let pattern = format!(
            "{}/{{product}}/{}",
            self.config.global.paths.products_root, self.config.global.paths.services_path
        );
        self.expand_pattern(&pattern)
    }

    /// Get the service root directory
    /// Pattern: "pkgs/products/{product}/services/rust/{service}"
    pub fn service_root(&self) -> Result<PathBuf> {
        let pattern = format!(
            "{}/{{product}}/{}/{{service}}",
            self.config.global.paths.products_root, self.config.global.paths.services_path
        );
        self.expand_pattern(&pattern)
    }

    /// Get the federation directory for this product
    /// Pattern: "pkgs/products/{product}/infrastructure/hive-router"
    pub fn federation_dir(&self) -> Result<PathBuf> {
        let pattern = format!(
            "{}/{{product}}/{}",
            self.config.global.paths.products_root, self.config.global.paths.federation_path
        );
        self.expand_pattern(&pattern)
    }

    // ========================================================================
    // Build Artifact Paths
    // ========================================================================

    /// Get the .version file path for build tagging
    /// Pattern: "pkgs/products/{product}/services/rust/{service}/.version"
    pub fn version_file(&self) -> Result<PathBuf> {
        let service_root = self.service_root()?;
        Ok(service_root.join(".version"))
    }

    /// Get the Nix build result path
    /// Pattern: "pkgs/products/{product}/services/rust/{service}/result-{arch}"
    pub fn nix_result(&self, arch: &str) -> Result<PathBuf> {
        let service_root = self.service_root()?;
        Ok(service_root.join(format!("result-{}", arch)))
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    /// Expand a pattern by substituting template variables
    ///
    /// Supported variables:
    /// - {product}: Product name
    /// - {service}: Service name
    /// - {cluster}: Kubernetes cluster name
    /// - {environment}: Deployment environment (staging, production)
    /// - {namespace}: Kubernetes namespace (computed from product + environment)
    fn expand_pattern(&self, pattern: &str) -> Result<PathBuf> {
        let namespace = self.config.kubernetes_namespace();

        let expanded = pattern
            .replace("{product}", &self.config.product.name)
            .replace("{service}", &self.config.service.name)
            .replace("{cluster}", &self.config.product.cluster)
            .replace("{environment}", &self.config.product.environment)
            .replace("{namespace}", &namespace);

        Ok(self.repo_root.join(expanded))
    }

    /// Get a relative path from the repository root
    /// Useful for git operations and logging
    pub fn relative_path(&self, path: &Path) -> Result<PathBuf> {
        path.strip_prefix(&self.repo_root)
            .map(|p| p.to_path_buf())
            .context("Path is not within repository")
    }

    /// Convert an absolute path to a repository-relative path string
    /// Returns the path as-is if it's already relative or outside the repo
    pub fn to_relative_string(&self, path: &Path) -> String {
        self.relative_path(path)
            .unwrap_or_else(|_| path.to_path_buf())
            .display()
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_expansion() {
        // TODO: Add comprehensive tests for path expansion
        // This requires setting up a mock DeployConfig
    }
}
