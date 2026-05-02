//! Nix build utilities for forge
//!
//! Provides common Nix build operations like building images,
//! running crate2nix, and flake operations.

use anyhow::{Context, Result};
use std::process::Stdio;
use tokio::process::Command;
use tracing::{debug, info};

use crate::error::NixBuildError;
use crate::repo::get_tool_path;
use crate::retry::CapturedFailure;

/// Result of a Nix build operation
#[derive(Debug, Clone)]
pub struct NixBuildResult {
    /// Path to the built artifact in the Nix store
    pub store_path: String,
    /// The flake attribute that was built
    #[allow(dead_code)]
    pub flake_attr: String,
}

/// Run `nix build` with the given args and return the resulting store path.
///
/// `label` is the human-readable identifier (flake attribute or full
/// flake reference) attached to any returned `NixBuildError` so failure
/// records carry the offending input by construction.
///
/// Returns typed errors:
/// - [`NixBuildError::ExecFailed`] when `nix` cannot be spawned.
/// - [`NixBuildError::BuildFailed`] when nix exits non-zero. `exit_code`
///   and `stderr` are kept as separate fields rather than fused into a
///   single message so downstream telemetry / retry / Phase 1
///   attestation can pattern-match on the failure shape.
/// - [`NixBuildError::EmptyStorePath`] when nix exits zero but prints no
///   store path — a contract violation that callers must distinguish
///   from a real build failure.
async fn run_nix_build_typed(
    nix_bin: &str,
    args: &[&str],
    label: &str,
) -> Result<String, NixBuildError> {
    debug!("{} {}", nix_bin, args.join(" "));

    let output = Command::new(nix_bin)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| NixBuildError::ExecFailed {
            flake_attr: label.to_string(),
            message: e.to_string(),
        })?;

    if let Some(cf) = CapturedFailure::from_output_if_failed(&output) {
        return Err(NixBuildError::BuildFailed {
            flake_attr: label.to_string(),
            exit_code: cf.exit_code,
            stderr: cf.stderr,
        });
    }

    let store_path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if store_path.is_empty() {
        return Err(NixBuildError::EmptyStorePath {
            flake_attr: label.to_string(),
        });
    }

    Ok(store_path)
}

/// Build a Nix flake attribute and return the store path
///
/// # Arguments
///
/// * `flake_attr` - The flake attribute to build (e.g., ".#postgres-bootstrap-image")
///
/// # Errors
///
/// Returns an error if the nix build command fails. The underlying
/// [`NixBuildError`] is preserved across the anyhow boundary and can be
/// recovered with `err.downcast_ref::<NixBuildError>()`.
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
    let nix_bin = get_tool_path("NIX_BIN", "nix");
    let store_path = run_nix_build_typed(
        &nix_bin,
        &[
            "build",
            flake_attr,
            "--no-link",
            "--print-out-paths",
            "--impure",
        ],
        flake_attr,
    )
    .await?;

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

    let nix_bin = get_tool_path("NIX_BIN", "nix");
    let store_path = run_nix_build_typed(
        &nix_bin,
        &["build", &flake_ref, "--no-link", "--print-out-paths"],
        &flake_ref,
    )
    .await?;

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

    use crate::test_support::make_executable_shim;

    /// Write an executable shim script that pretends to be `nix`.
    /// Delegates to the shared
    /// `crate::test_support::make_executable_shim` so the shim
    /// discipline (absolute-path invocation, 0o755 chmod, tempdir
    /// lifetime) lives in one place — same primitive as
    /// `git.rs`'s `make_git_shim` and `attic.rs`'s `make_attic_shim`.
    fn make_nix_shim(body: &str) -> (tempfile::TempDir, String) {
        make_executable_shim("nix", body)
    }

    /// When the resolved nix binary cannot be spawned, `run_nix_build_typed`
    /// must surface `ExecFailed` carrying the offending label (not a stringly
    /// anyhow `Failed to execute nix build command`). Pins the typed split
    /// so telemetry can distinguish "nix missing" from "nix said no".
    #[tokio::test]
    async fn test_run_nix_build_typed_exec_failed_carries_label() {
        // Absolute path that does not exist — Command::spawn fails
        // deterministically without touching global PATH state.
        let result = run_nix_build_typed(
            "/nonexistent/path/to/nix-binary-that-does-not-exist",
            &["build", ".#x"],
            ".#x",
        )
        .await;
        let err = result.expect_err("missing nix binary must fail");
        match err {
            NixBuildError::ExecFailed { flake_attr, .. } => {
                assert_eq!(flake_attr, ".#x");
            }
            other => panic!("expected ExecFailed, got: {other:?}"),
        }
    }

    /// Build failures must produce `BuildFailed` carrying the flake
    /// attribute, an exit code, and the captured stderr — never a fused
    /// stringly bag. Uses a shim invoked by absolute path so the test is
    /// hermetic and parallel-safe.
    #[tokio::test]
    async fn test_run_nix_build_typed_build_failed_carries_structured_fields() {
        let (_dir, shim) = make_nix_shim("#!/bin/sh\necho 'attribute foo missing' 1>&2\nexit 7\n");
        let result = run_nix_build_typed(&shim, &["build", ".#thing"], ".#thing").await;
        let err = result.expect_err("nonzero exit must fail");
        match err {
            NixBuildError::BuildFailed {
                flake_attr,
                exit_code,
                stderr,
            } => {
                assert_eq!(flake_attr, ".#thing");
                assert_eq!(exit_code, Some(7));
                assert!(
                    stderr.contains("attribute foo missing"),
                    "stderr field must capture the nix stderr verbatim, got: {stderr:?}"
                );
            }
            other => panic!("expected BuildFailed, got: {other:?}"),
        }
    }

    /// A nix invocation that exits zero with empty stdout must produce
    /// `EmptyStorePath` — distinct from a real build failure — so callers
    /// can treat "contract violation" differently from "nix said no".
    #[tokio::test]
    async fn test_run_nix_build_typed_empty_store_path() {
        let (_dir, shim) = make_nix_shim("#!/bin/sh\nexit 0\n");
        let result = run_nix_build_typed(&shim, &["build", ".#empty"], ".#empty").await;
        let err = result.expect_err("empty stdout must fail");
        match err {
            NixBuildError::EmptyStorePath { flake_attr } => {
                assert_eq!(flake_attr, ".#empty");
            }
            other => panic!("expected EmptyStorePath, got: {other:?}"),
        }
    }

    /// On the success path, `run_nix_build_typed` must return the trimmed
    /// stdout verbatim as the store path.
    #[tokio::test]
    async fn test_run_nix_build_typed_success_returns_store_path() {
        let (_dir, shim) = make_nix_shim("#!/bin/sh\necho '/nix/store/abc123-out'\nexit 0\n");
        let store_path = run_nix_build_typed(&shim, &["build", ".#ok"], ".#ok")
            .await
            .expect("success path");
        assert_eq!(store_path, "/nix/store/abc123-out");
    }
}
