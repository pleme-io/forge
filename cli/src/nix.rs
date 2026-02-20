//! Nix build utilities for forge
//!
//! Provides common Nix build operations like building images,
//! running crate2nix, and flake operations.

use anyhow::{Context, Result};
use std::process::Stdio;
use tokio::process::Command;
use tracing::{debug, info};

/// Result of a Nix build operation
#[derive(Debug, Clone)]
pub struct NixBuildResult {
    /// Path to the built artifact in the Nix store
    pub store_path: String,
    /// The flake attribute that was built
    #[allow(dead_code)]
    pub flake_attr: String,
}

/// Build a Nix flake attribute and return the store path
///
/// # Arguments
///
/// * `flake_attr` - The flake attribute to build (e.g., ".#postgres-bootstrap-image")
///
/// # Errors
///
/// Returns an error if the nix build command fails.
///
/// # Examples
///
/// ```rust,ignore
/// let result = build_flake_attr(".#my-package").await?;
/// println!("Built at: {}", result.store_path);
/// ```
pub async fn build_flake_attr(flake_attr: &str) -> Result<NixBuildResult> {
    debug!("Building Nix flake attribute: {}", flake_attr);

    // --impure required for path inputs like substrate in the root flake
    let output = Command::new("nix")
        .args([
            "build",
            flake_attr,
            "--no-link",
            "--print-out-paths",
            "--impure",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("Failed to execute nix build command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);

        anyhow::bail!(
            "Nix build failed for {}\n\n  \
             Exit code: {:?}\n  \
             Stderr: {}\n  \
             Stdout: {}",
            flake_attr,
            output.status.code(),
            stderr.trim(),
            stdout.trim()
        );
    }

    let store_path = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if store_path.is_empty() {
        anyhow::bail!(
            "Nix build succeeded but returned empty path for {}",
            flake_attr
        );
    }

    debug!("Built {} at: {}", flake_attr, store_path);

    Ok(NixBuildResult {
        store_path,
        flake_attr: flake_attr.to_string(),
    })
}

/// Build a Docker image using Nix
///
/// This is a convenience wrapper around `build_flake_attr` for image builds.
///
/// # Arguments
///
/// * `image_name` - The name of the image (e.g., "postgres-bootstrap")
/// * `suffix` - Optional suffix (e.g., "-image", defaults to "-image")
///
/// # Examples
///
/// ```rust,ignore
/// let result = build_docker_image("postgres-bootstrap", None).await?;
/// // Builds .#postgres-bootstrap-image
/// ```
pub async fn build_docker_image(image_name: &str, suffix: Option<&str>) -> Result<NixBuildResult> {
    let suffix = suffix.unwrap_or("-image");
    let flake_attr = format!(".#{}{}", image_name, suffix);

    info!("📦 Building {} with Nix...", image_name);

    let result = build_flake_attr(&flake_attr).await?;

    info!("   ✅ Built: {}", result.store_path);

    Ok(result)
}

/// Build a Docker image from a specific flake directory
///
/// This is used for sub-flakes that are not exposed in the root flake.
///
/// # Arguments
///
/// * `flake_dir` - Path to the flake directory
/// * `image_name` - The name of the image (e.g., "postgres-bootstrap")
/// * `suffix` - Optional suffix (e.g., "-image", defaults to "-image")
///
/// # Examples
///
/// ```rust,ignore
/// let result = build_docker_image_from_dir("/path/to/bootstrap", "postgres-bootstrap", None).await?;
/// ```
pub async fn build_docker_image_from_dir(
    flake_dir: &std::path::Path,
    image_name: &str,
    suffix: Option<&str>,
) -> Result<NixBuildResult> {
    let suffix = suffix.unwrap_or("-image");
    let flake_ref = format!("{}#{}{}", flake_dir.display(), image_name, suffix);

    info!(
        "📦 Building {} from {} with Nix...",
        image_name,
        flake_dir.display()
    );
    debug!("Flake reference: {}", flake_ref);

    // Build from the specific flake directory
    let output = Command::new("nix")
        .args(["build", &flake_ref, "--no-link", "--print-out-paths"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("Failed to execute nix build command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);

        anyhow::bail!(
            "Nix build failed for {}\n\n  \
             Exit code: {:?}\n  \
             Stderr: {}\n  \
             Stdout: {}",
            flake_ref,
            output.status.code(),
            stderr.trim(),
            stdout.trim()
        );
    }

    let store_path = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if store_path.is_empty() {
        anyhow::bail!(
            "Nix build succeeded but returned empty path for {}",
            flake_ref
        );
    }

    info!("   ✅ Built: {}", store_path);

    Ok(NixBuildResult {
        store_path,
        flake_attr: flake_ref,
    })
}

/// Run crate2nix to regenerate Cargo.nix
///
/// # Arguments
///
/// * `crate2nix_path` - Path to crate2nix binary (or just "crate2nix" if in PATH)
///
/// # Errors
///
/// Returns an error if crate2nix is not found or fails to generate.
pub async fn run_crate2nix(crate2nix_path: &str) -> Result<()> {
    info!("🔄 Running crate2nix generate...");

    let output = Command::new(crate2nix_path)
        .args(["generate"])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .with_context(|| {
            format!(
                "Failed to run crate2nix.\n\n  \
                 Path: {}\n  \
                 Is crate2nix installed?\n\n  \
                 Install with: nix run nixpkgs#crate2nix -- generate",
                crate2nix_path
            )
        })?;

    if !output.success() {
        anyhow::bail!(
            "crate2nix generate failed with exit code: {:?}",
            output.code()
        );
    }

    Ok(())
}

/// Run cargo update to refresh Cargo.lock
///
/// # Arguments
///
/// * `cargo_path` - Path to cargo binary (or just "cargo" if in PATH)
///
/// # Errors
///
/// Returns an error if cargo is not found or update fails.
pub async fn run_cargo_update(cargo_path: &str) -> Result<()> {
    info!("📦 Updating Cargo.lock...");

    let output = Command::new(cargo_path)
        .args(["update"])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .with_context(|| {
            format!(
                "Failed to run cargo update.\n\n  \
                 Path: {}\n  \
                 Is cargo installed?",
                cargo_path
            )
        })?;

    if !output.success() {
        anyhow::bail!("cargo update failed with exit code: {:?}", output.code());
    }

    Ok(())
}

/// Check if a Nix flake attribute exists
///
/// # Arguments
///
/// * `flake_attr` - The flake attribute to check
///
/// # Returns
///
/// `true` if the attribute exists, `false` otherwise.
#[allow(dead_code)]
pub async fn flake_attr_exists(flake_attr: &str) -> bool {
    let result = Command::new("nix")
        .args(["eval", "--json", flake_attr])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;

    matches!(result, Ok(status) if status.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_build_flake_attr_invalid() {
        // This should fail because the attribute doesn't exist
        let result = build_flake_attr(".#nonexistent-package-xyz").await;
        assert!(result.is_err());
    }
}
