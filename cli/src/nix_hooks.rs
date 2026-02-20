//! Nix hooks discovery and configuration
//!
//! This module provides automatic discovery of the nix-hooks package for enabling
//! per-derivation caching with Attic via post-build-hook.
//!
//! ## How It Works
//!
//! The nix-hooks package contains the `attic-push-hook` binary which, when configured
//! as a post-build-hook, automatically pushes each built derivation to Attic cache.
//! This provides significant cache benefits:
//!
//! - **Per-derivation caching**: Each crate/dependency is cached individually
//! - **Incremental builds**: Only changed derivations are rebuilt
//! - **Faster CI**: Shared cache across all builds
//!
//! ## Discovery Process
//!
//! 1. Check `NIX_HOOKS_PATH` environment variable (explicit override)
//! 2. If not set, build `.#nix-hooks` package and get output path
//! 3. Cache the result for subsequent calls (within same process)
//!
//! ## Usage
//!
//! ```rust,ignore
//! use crate::nix_hooks::NixHooks;
//!
//! let hooks = NixHooks::discover().await?;
//! if let Some(hook_path) = hooks.attic_push_hook_path() {
//!     // Configure nix build with post-build-hook
//!     cmd.args(&["--option", "post-build-hook", &hook_path]);
//! }
//! ```

use anyhow::{Context, Result};
use std::env;
use std::path::PathBuf;
use std::sync::OnceLock;
use tokio::process::Command;
use tracing::{debug, info, warn};

/// Global cache for discovered nix-hooks path
static NIX_HOOKS_PATH: OnceLock<Option<PathBuf>> = OnceLock::new();

/// Nix hooks configuration for Attic cache integration
#[derive(Debug, Clone)]
pub struct NixHooks {
    /// Path to the nix-hooks package in the Nix store
    package_path: Option<PathBuf>,
}

impl NixHooks {
    /// Discover the nix-hooks package path
    ///
    /// Attempts to find the nix-hooks package using:
    /// 1. `NIX_HOOKS_PATH` environment variable (explicit override)
    /// 2. Building `.#nix-hooks` and getting the output path
    ///
    /// Results are cached for subsequent calls within the same process.
    pub async fn discover() -> Result<Self> {
        // Check cache first
        if let Some(cached) = NIX_HOOKS_PATH.get() {
            return Ok(Self {
                package_path: cached.clone(),
            });
        }

        // Try environment variable first
        if let Ok(path) = env::var("NIX_HOOKS_PATH") {
            let path_buf = PathBuf::from(&path);
            if path_buf.exists() {
                info!("🔧 Using NIX_HOOKS_PATH: {}", path);
                let _ = NIX_HOOKS_PATH.set(Some(path_buf.clone()));
                return Ok(Self {
                    package_path: Some(path_buf),
                });
            } else {
                warn!("⚠️  NIX_HOOKS_PATH is set but path doesn't exist: {}", path);
            }
        }

        // Build the nix-hooks package to get its path
        let package_path = Self::build_and_get_path().await?;
        let _ = NIX_HOOKS_PATH.set(package_path.clone());

        Ok(Self { package_path })
    }

    /// Build the nix-hooks package and return its store path
    async fn build_and_get_path() -> Result<Option<PathBuf>> {
        debug!("🔨 Building nix-hooks package to discover path...");

        // Get repo root
        let repo_root = crate::git::get_repo_root()
            .context("Failed to get repo root for nix-hooks discovery")?;

        // Build nix-hooks and get output path
        let output = Command::new("nix")
            .current_dir(&repo_root)
            .args(&[
                "build",
                ".#nix-hooks",
                "--no-link",
                "--print-out-paths",
                "--no-update-lock-file",
            ])
            .output()
            .await
            .context("Failed to run nix build for nix-hooks")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("⚠️  Failed to build nix-hooks package: {}", stderr.trim());
            return Ok(None);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let store_path = stdout.trim();

        if store_path.is_empty() {
            warn!("⚠️  nix build returned empty path for nix-hooks");
            return Ok(None);
        }

        let path_buf = PathBuf::from(store_path);
        if !path_buf.exists() {
            warn!("⚠️  nix-hooks store path doesn't exist: {}", store_path);
            return Ok(None);
        }

        info!("✅ Discovered nix-hooks at: {}", store_path);
        Ok(Some(path_buf))
    }

    /// Get the path to the attic-push-hook binary if available
    ///
    /// Returns `None` if nix-hooks is not available or the binary doesn't exist.
    pub fn attic_push_hook_path(&self) -> Option<String> {
        let package_path = self.package_path.as_ref()?;
        let hook_path = package_path.join("bin").join("attic-push-hook");

        if hook_path.exists() {
            Some(hook_path.to_string_lossy().to_string())
        } else {
            warn!(
                "⚠️  attic-push-hook binary not found at expected path: {:?}",
                hook_path
            );
            None
        }
    }

    /// Check if nix-hooks is available
    pub fn is_available(&self) -> bool {
        self.package_path.is_some()
    }

    /// Get the package path if available
    pub fn package_path(&self) -> Option<&PathBuf> {
        self.package_path.as_ref()
    }
}

/// Configure a nix build command with post-build-hook for Attic caching
///
/// This helper function configures a `tokio::process::Command` with:
/// - `--option post-build-hook <path-to-attic-push-hook>`
/// - Environment variables: `ATTIC_CACHE`, `ATTIC_SERVER`, `ATTIC_TOKEN`
///
/// Returns `true` if the hook was configured, `false` otherwise.
pub async fn configure_post_build_hook(
    cmd: &mut Command,
    cache_name: &str,
    cache_url: &str,
    attic_token: &str,
) -> bool {
    // Discover nix-hooks
    let hooks = match NixHooks::discover().await {
        Ok(h) => h,
        Err(e) => {
            warn!("⚠️  Failed to discover nix-hooks: {}", e);
            return false;
        }
    };

    // Get the hook path
    let hook_path = match hooks.attic_push_hook_path() {
        Some(p) => p,
        None => {
            debug!("nix-hooks not available, skipping post-build-hook");
            return false;
        }
    };

    // Configure the command
    cmd.args(&["--option", "post-build-hook", &hook_path]);

    // Set environment variables for the hook
    cmd.env("ATTIC_CACHE", cache_name);
    cmd.env("ATTIC_SERVER", cache_url);
    cmd.env("ATTIC_TOKEN", attic_token);

    info!("✅ Configured attic post-build-hook: {}", hook_path);
    info!("   (Uploads EVERY built derivation automatically)");

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nix_hooks_struct() {
        let hooks = NixHooks { package_path: None };
        assert!(!hooks.is_available());
        assert!(hooks.attic_push_hook_path().is_none());
    }

    #[test]
    fn test_nix_hooks_with_path() {
        // Use a path that exists in CI (the test binary itself)
        let hooks = NixHooks {
            package_path: Some(PathBuf::from("/tmp")),
        };
        assert!(hooks.is_available());
        // attic-push-hook won't exist in /tmp
        assert!(hooks.attic_push_hook_path().is_none());
    }
}
