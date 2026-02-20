//! Attic cache operations
//!
//! Handles pushing Nix closures to Attic binary cache.

use anyhow::{Context, Result};
use tokio::process::Command;
use tracing::{info, warn};

/// Client for Attic cache operations
pub struct AtticClient {
    cache_name: String,
    token: Option<String>,
}

impl AtticClient {
    /// Create a new Attic client
    pub fn new(cache_name: impl Into<String>) -> Self {
        Self {
            cache_name: cache_name.into(),
            token: None,
        }
    }

    /// Set authentication token
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    /// Discover Attic token from environment
    pub fn discover_token() -> Option<String> {
        std::env::var("ATTIC_TOKEN").ok().filter(|s| !s.is_empty())
    }

    /// Create client with auto-discovered token
    pub fn discover(cache_name: impl Into<String>) -> Self {
        let mut client = Self::new(cache_name);
        if let Some(token) = Self::discover_token() {
            client.token = Some(token);
        }
        client
    }

    /// Push a store path to the cache
    pub async fn push(&self, store_path: &str) -> Result<()> {
        info!("Pushing to Attic cache: {}", self.cache_name);

        let mut cmd = Command::new("attic");
        cmd.args(["push", &self.cache_name, store_path]);

        if let Some(ref token) = self.token {
            cmd.env("ATTIC_TOKEN", token);
        }

        let status = cmd.status().await.context("Failed to execute attic push")?;

        if !status.success() {
            anyhow::bail!("Attic push failed");
        }

        info!("Successfully pushed to Attic cache");
        Ok(())
    }

    /// Push a store path, ignoring failures (non-fatal)
    pub async fn push_optional(&self, store_path: &str) -> bool {
        match self.push(store_path).await {
            Ok(()) => {
                info!("Pushed to Attic cache: {}", self.cache_name);
                true
            }
            Err(e) => {
                warn!("Failed to push to Attic cache (non-fatal): {}", e);
                false
            }
        }
    }

    /// Login to Attic cache
    pub async fn login(&self, server_url: &str) -> Result<()> {
        let token = self
            .token
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Attic token required for login"))?;

        let status = Command::new("attic")
            .args(["login", &self.cache_name, server_url, token])
            .status()
            .await
            .context("Failed to execute attic login")?;

        if !status.success() {
            anyhow::bail!("Attic login failed");
        }

        Ok(())
    }

    /// Check if attic CLI is available
    pub async fn is_available() -> bool {
        Command::new("attic")
            .arg("--version")
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attic_client_creation() {
        let client = AtticClient::new("test-cache");
        assert_eq!(client.cache_name, "test-cache");
        assert!(client.token.is_none());
    }

    #[test]
    fn test_attic_client_with_token() {
        let client = AtticClient::new("test-cache").with_token("secret");
        assert!(client.token.is_some());
    }
}
