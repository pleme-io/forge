//! Nix build utilities for forge
//!
//! Provides common Nix build operations like building images,
//! running crate2nix, and flake operations.

use anyhow::{Context, Result};
use std::path::Path;
use std::process::Stdio;
use tokio::process::Command;
use tracing::{debug, info};

use crate::error::NixBuildError;
use crate::repo::get_tool_path;
use crate::retry::classify_capture_query;

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
/// `working_dir` is the directory the nix process is spawned in. `None`
/// keeps the parent process's CWD — the canonical shape for root-flake
/// builds. `Some(dir)` is the canonical shape for sub-flake builds where
/// the flake reference is a bare `.#attr` resolved relative to a
/// non-default directory (e.g. a tool-release flake under a sub-repo).
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
    working_dir: Option<&Path>,
) -> Result<String, NixBuildError> {
    debug!("{} {}", nix_bin, args.join(" "));

    let mut cmd = Command::new(nix_bin);
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    if let Some(dir) = working_dir {
        cmd.current_dir(dir);
    }
    let captured = cmd.output().await;

    // Spawn-vs-op dispatch flows through the canonical
    // [`classify_capture_query`] primitive — query-shape sibling of
    // `classify_capture` (the op-shape primitive `git.rs::git_capture`
    // and `infrastructure/registry.rs::create_manifest_index` drive).
    // Spawn failures (`Err(io::Error)` — nix not on PATH) route to
    // `NixBuildError::ExecFailed`; non-zero exits route to
    // `NixBuildError::BuildFailed` carrying the structural
    // `(exit_code, stderr)` tuple `CapturedFailure` extracts. The
    // canonical UTF-8-lossy-trim of the success-stdout is performed
    // by the primitive — no per-site re-derivation.
    let store_path = classify_capture_query(
        captured,
        |e| NixBuildError::ExecFailed {
            flake_attr: label.to_string(),
            message: e.to_string(),
        },
        |cf| NixBuildError::BuildFailed {
            flake_attr: label.to_string(),
            exit_code: cf.exit_code,
            stderr: cf.stderr,
        },
    )?;

    if store_path.is_empty() {
        return Err(NixBuildError::EmptyStorePath {
            flake_attr: label.to_string(),
        });
    }

    Ok(store_path)
}

/// Build a Nix flake attribute and return the store path.
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
    build_flake_attr_in(flake_attr, None).await
}

/// Build a Nix flake attribute, optionally relative to a working directory,
/// and return the store path.
///
/// Lifts the verbatim 13-line pattern
/// ```text
/// let output = tokio::process::Command::new("nix")
///     .args(["build", &flake_attr, "--no-link", "--print-out-paths", "--impure"])
///     .current_dir(dir)              // optional
///     .output().await
///     .with_context(|| format!("Failed to build {}", flake_attr))?;
/// if !output.status.success() {
///     let stderr = String::from_utf8_lossy(&output.stderr);
///     bail!("nix build {} failed: {}", flake_attr, stderr.trim());
/// }
/// let store_path = String::from_utf8_lossy(&output.stdout).trim().to_string();
/// if store_path.is_empty() {
///     bail!("nix build returned empty path for {}", flake_attr);
/// }
/// ```
/// that three command-module sites in forge carry verbatim modulo per-site
/// working_dir: `commands/local.rs::up` (no working_dir),
/// `commands/image_release.rs::build_nix_image` (working_dir = `&str` arg),
/// `commands/tool.rs::release` (working_dir = `&Path` arg). Three
/// identically-shaped bodies past the three-times threshold (THEORY §VI.1)
/// — this function is the law-redeeming consolidation for the "build a
/// flake attribute, return the store path, fail typed on every failure
/// shape" surface in forge.
///
/// `working_dir` is the directory the nix process is spawned in. `None`
/// keeps the parent process's CWD (the canonical shape for root-flake
/// builds — `commands/local.rs::up` and the existing
/// [`build_flake_attr`] callers). `Some(dir)` is the canonical shape for
/// builds against a sub-repo's flake — `commands/image_release.rs` and
/// `commands/tool.rs` both pass an explicit working directory.
///
/// # Errors
///
/// Returns an error if the nix build command fails. The underlying
/// [`NixBuildError`] is preserved across the anyhow boundary and can be
/// recovered with `err.downcast_ref::<NixBuildError>()` — the typed
/// `(BuildFailed | EmptyStorePath | ExecFailed | FlakeNotFound |
/// CargoNixMissing)` discrimination is structural to the typed-error
/// family and survives the anyhow envelope. Pre-migration the three
/// inline call sites fused stderr into a free-form `bail!` string, so a
/// downstream attestation / telemetry consumer that wanted the
/// `(exit_code, stderr)` tuple had to re-parse the message; post-
/// migration the tuple is recoverable by construction.
pub async fn build_flake_attr_in(
    flake_attr: &str,
    working_dir: Option<&Path>,
) -> Result<NixBuildResult> {
    debug!("Building Nix flake attribute: {}", flake_attr);

    // --impure required for path inputs like substrate in the root flake
    // and the sub-flake builds the migrated sites drive.
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
        working_dir,
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
        None,
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
            None,
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
        let result = run_nix_build_typed(&shim, &["build", ".#thing"], ".#thing", None).await;
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
        let result = run_nix_build_typed(&shim, &["build", ".#empty"], ".#empty", None).await;
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
        let store_path = run_nix_build_typed(&shim, &["build", ".#ok"], ".#ok", None)
            .await
            .expect("success path");
        assert_eq!(store_path, "/nix/store/abc123-out");
    }

    /// `working_dir = Some(dir)` must spawn the nix process inside `dir`.
    /// Pinned with a shim that prints its current working directory: the
    /// trimmed stdout is the path the shim observed, which must equal the
    /// directory the caller passed. Pre-migration, the three command-
    /// module sites that need a working directory drove `current_dir` on
    /// `tokio::process::Command` directly inline; post-migration the
    /// canonical primitive owns the wiring. A future regression that
    /// silently dropped the `current_dir` setter (e.g. via a refactor
    /// that moved the builder chain) would leave sub-flake builds
    /// resolving the wrong `flake.nix` — the canonical "wrong-tree" silent
    /// failure shape this test pins out.
    #[tokio::test]
    async fn test_run_nix_build_typed_honors_working_dir() {
        let (dir, shim) = make_nix_shim("#!/bin/sh\npwd\nexit 0\n");
        let work = tempfile::tempdir().expect("temp dir");
        let work_canonical = std::fs::canonicalize(work.path()).expect("canonicalize work");
        let store_path = run_nix_build_typed(&shim, &["build", ".#ok"], ".#ok", Some(work.path()))
            .await
            .expect("success path");
        let observed = std::fs::canonicalize(&store_path).expect("canonicalize observed");
        assert_eq!(
            observed, work_canonical,
            "shim's observed CWD must equal the working_dir passed to run_nix_build_typed"
        );
        drop(dir);
    }

    /// `working_dir = Some(missing_dir)` must surface a spawn-failure
    /// (`NixBuildError::ExecFailed`) with the offending label intact —
    /// the same typed contract `working_dir = None` provides. Pinned so a
    /// future regression that silently logged-and-swallowed the
    /// `current_dir` error (e.g. via a `.unwrap_or_default()` on the path)
    /// would surface here, not as a confusing "nix succeeded with empty
    /// stdout" downstream.
    #[tokio::test]
    async fn test_run_nix_build_typed_missing_working_dir_routes_to_exec_failed() {
        let (_dir, shim) = make_nix_shim("#!/bin/sh\necho '/nix/store/x'\nexit 0\n");
        let missing = std::path::Path::new(
            "/this/dir/does/not/exist-deliberately-for-the-nix-build-typed-test",
        );
        let result = run_nix_build_typed(&shim, &["build", ".#x"], ".#x", Some(missing)).await;
        let err = result.expect_err("missing working_dir must fail");
        match err {
            NixBuildError::ExecFailed { flake_attr, .. } => {
                assert_eq!(flake_attr, ".#x");
            }
            other => panic!("expected ExecFailed, got: {other:?}"),
        }
    }
}
