//! Multi-arch OCI image release
//!
//! Replaces image-release.nix::mkImageReleaseApp.
//! Builds (or uses pre-built) images for amd64/arm64, pushes via skopeo,
//! and creates a multi-arch manifest index.

use anyhow::{bail, Context, Result};
use std::fmt;
use std::path::Path;
use std::process::Command;
use tracing::info;

use crate::git;
use crate::nix::build_flake_attr_in;
use crate::tools::get_tool_path;

/// Release a multi-arch OCI image.
///
/// If `--amd64-attr` or `--arm64-attr` are provided, the image is built via `nix build` first.
/// Otherwise, `--amd64-image` / `--arm64-image` must point to pre-built image tarballs.
///
/// When `verify_elf` is true (the default), each resolved image is gated through
/// [`verify_image_arch`] *before* push — so an image whose binary can't run on the
/// arch it is being tagged under is refused at the gate, never shipped to crashloop
/// with `exec format error` (the hanabi 2026-06-14 amd64-tag-holding-aarch64 class).
pub async fn execute(
    name: &str,
    registry: &str,
    amd64_attr: Option<&str>,
    arm64_attr: Option<&str>,
    amd64_image: Option<&str>,
    arm64_image: Option<&str>,
    working_dir: &str,
    verify_elf: bool,
) -> Result<()> {
    let sha = git::get_short_sha()?;
    let skopeo = get_tool_path("skopeo");

    // Resolve amd64 image path
    let amd64_path = match (amd64_image, amd64_attr) {
        (Some(path), _) => path.to_string(),
        (None, Some(attr)) => build_nix_image(attr, working_dir).await?,
        (None, None) => bail!("Either --amd64-image or --amd64-attr is required"),
    };

    // Resolve arm64 image path (optional)
    let arm64_path = match (arm64_image, arm64_attr) {
        (Some(path), _) => Some(path.to_string()),
        (None, Some(attr)) => Some(build_nix_image(attr, working_dir).await?),
        (None, None) => None,
    };

    // Push amd64 — gate the loader before the push (default on).
    if verify_elf {
        info!("Verifying {} (amd64) image loader before push...", name);
        verify_image_arch(&skopeo, &amd64_path, "amd64")?;
    }
    let amd64_tag = format!("amd64-{}", sha);
    info!("Pushing {} (amd64) as {}:{}...", name, registry, amd64_tag);
    push_image(&skopeo, &amd64_path, registry, &amd64_tag)?;
    push_image(&skopeo, &amd64_path, registry, "amd64-latest")?;

    // Push arm64 if available
    if let Some(ref arm64) = arm64_path {
        if verify_elf {
            info!("Verifying {} (arm64) image loader before push...", name);
            verify_image_arch(&skopeo, arm64, "arm64")?;
        }
        let arm64_tag = format!("arm64-{}", sha);
        info!("Pushing {} (arm64) as {}:{}...", name, registry, arm64_tag);
        push_image(&skopeo, arm64, registry, &arm64_tag)?;
        push_image(&skopeo, arm64, registry, "arm64-latest")?;
    }

    // Create multi-arch manifest index if both architectures are present.
    //
    // Uses modern regctl `index create` (which accepts source per-arch
    // images via repeated `--ref` flags). The legacy `manifest put`
    // syntax — which took source refs as positional args — was removed
    // and now reads manifest content from stdin only.
    if arm64_path.is_some() {
        info!("Creating multi-arch manifest index...");

        let regctl = get_tool_path("regctl");

        // SHA-pinned multi-arch index.
        let status = Command::new(&regctl)
            .args([
                "index",
                "create",
                &format!("{}:{}", registry, sha),
                "--ref",
                &format!("{}:{}", registry, amd64_tag),
                "--ref",
                &format!("{}:arm64-{}", registry, sha),
            ])
            .status()
            .context("Failed to create multi-arch index (sha)")?;

        if !status.success() {
            bail!("regctl index create (sha) failed");
        }

        // Floating `latest` multi-arch index.
        let status = Command::new(&regctl)
            .args([
                "index",
                "create",
                &format!("{}:latest", registry),
                "--ref",
                &format!("{}:amd64-latest", registry),
                "--ref",
                &format!("{}:arm64-latest", registry),
            ])
            .status()
            .context("Failed to create multi-arch index (latest)")?;

        if !status.success() {
            bail!("regctl index create (latest) failed");
        }
    }

    // Build the actual list of tags pushed so the summary is accurate.
    // The previous summary printed a single misleading tag (`:sha`) which
    // didn't always exist (e.g. when arm64_path is None, no multi-arch
    // index is created and the unprefixed tag never gets created).
    let mut tags_pushed = vec![
        format!("{}:amd64-{}", registry, sha),
        format!("{}:amd64-latest", registry),
    ];
    if arm64_path.is_some() {
        tags_pushed.push(format!("{}:arm64-{}", registry, sha));
        tags_pushed.push(format!("{}:arm64-latest", registry));
        tags_pushed.push(format!("{}:{}", registry, sha));
        tags_pushed.push(format!("{}:latest", registry));
    }
    info!(
        "Image release complete — {} tags pushed for {}:",
        tags_pushed.len(),
        name
    );
    for tag in &tags_pushed {
        info!("  {}", tag);
    }
    Ok(())
}

// --- Helpers ---

/// Build a sub-flake attribute inside `working_dir` and return the resulting
/// store path. Thin wrapper that prepends the canonical `.#` prefix to the
/// caller-supplied `flake_attr` and delegates to the canonical
/// [`build_flake_attr_in`] primitive — the typed `NixBuildError`
/// `(BuildFailed | EmptyStorePath | ExecFailed)` discrimination is
/// recoverable across the anyhow boundary.
async fn build_nix_image(flake_attr: &str, working_dir: &str) -> Result<String> {
    info!("Building .#{}...", flake_attr);
    let result =
        build_flake_attr_in(&format!(".#{}", flake_attr), Some(Path::new(working_dir))).await?;
    Ok(result.store_path)
}

fn push_image(skopeo: &str, image_path: &str, registry: &str, tag: &str) -> Result<()> {
    let status = Command::new(skopeo)
        .args([
            "copy",
            "--insecure-policy",
            &format!("docker-archive:{}", image_path),
            &format!("docker://{}:{}", registry, tag),
        ])
        .status()
        .with_context(|| format!("Failed to push {}:{}", registry, tag))?;

    if !status.success() {
        bail!("skopeo copy failed for {}:{}", registry, tag);
    }

    Ok(())
}

// --- Loader verification (pre-push gate) ---

/// Why an image cannot be proven runnable on the arch it is being tagged under.
///
/// `ArchMismatch` / `MissingArchitecture` are implemented today — the cheap,
/// high-value guard that catches the "amd64 tag holding an aarch64 binary"
/// class (hanabi 2026-06-14 `exec format error`) from `skopeo inspect`'s
/// declared `Architecture` alone, reusing the skopeo forge already shells to.
///
/// THE DESTINATION (named next milestone, not yet built): a full ELF-loader
/// check that extracts the entrypoint binary from the image layers, parses its
/// `PT_INTERP` + `DT_NEEDED` (via the `object` crate, not a string-grep of
/// `ldd`), and confirms each is present in the image's layer closure — the
/// gaveta r19/r20 glibc-loader-not-in-the-minimal-image class. That needs
/// `object` + tar/flate2 layer-walking; it lands as the `MissingInterpreter`
/// / `MissingNeededLib` / `NotAnElf` variants below. Reserved here so the
/// gate's typed surface already names the full failure set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoaderError {
    /// The image declares an architecture other than the tag it is about to be
    /// pushed under (e.g. an `arm64` image about to become `amd64-<sha>`).
    ArchMismatch { expected: String, found: String },
    /// `skopeo inspect` returned no usable `Architecture` field.
    MissingArchitecture,
}

impl fmt::Display for LoaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoaderError::ArchMismatch { expected, found } => write!(
                f,
                "image architecture mismatch: about to push as '{expected}' but the image \
                 declares '{found}' — pushing it would crashloop with `exec format error`. \
                 Build the '{expected}' image attribute on a native-'{expected}' runner."
            ),
            LoaderError::MissingArchitecture => write!(
                f,
                "`skopeo inspect` returned no Architecture field — not a usable single-arch OCI image"
            ),
        }
    }
}

impl std::error::Error for LoaderError {}

/// Pure arch check over `skopeo inspect` JSON. Factored out from the skopeo
/// invocation so it is unit-testable without a registry or a real tarball.
fn check_inspect_arch(inspect_json: &[u8], expected_arch: &str) -> Result<(), LoaderError> {
    let v: serde_json::Value =
        serde_json::from_slice(inspect_json).map_err(|_| LoaderError::MissingArchitecture)?;
    let found = v
        .get("Architecture")
        .and_then(|a| a.as_str())
        .ok_or(LoaderError::MissingArchitecture)?;
    if found == expected_arch {
        Ok(())
    } else {
        Err(LoaderError::ArchMismatch {
            expected: expected_arch.to_string(),
            found: found.to_string(),
        })
    }
}

/// Verify that `image_path` (a docker-archive tarball) declares `expected_arch`
/// before it is pushed under an `<expected_arch>-<sha>` tag. Reuses the same
/// `skopeo` forge already shells to; bails with the typed [`LoaderError`] so a
/// wrong-arch image is refused at the gate instead of shipped to crashloop.
fn verify_image_arch(skopeo: &str, image_path: &str, expected_arch: &str) -> Result<()> {
    let output = Command::new(skopeo)
        .args(["inspect", &format!("docker-archive:{}", image_path)])
        .output()
        .with_context(|| format!("Failed to run skopeo inspect on {}", image_path))?;

    if !output.status.success() {
        bail!(
            "skopeo inspect failed for {}: {}",
            image_path,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    check_inspect_arch(&output.stdout, expected_arch)
        .map_err(|e| anyhow::anyhow!("{} (image: {})", e, image_path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arch_match_passes() {
        let json = br#"{"Name":"x","Architecture":"amd64","Os":"linux"}"#;
        assert!(check_inspect_arch(json, "amd64").is_ok());
    }

    #[test]
    fn arch_mismatch_is_typed() {
        // The hanabi class: an arm64 image about to be tagged amd64-<sha>.
        let json = br#"{"Architecture":"arm64","Os":"linux"}"#;
        let err = check_inspect_arch(json, "amd64").unwrap_err();
        assert_eq!(
            err,
            LoaderError::ArchMismatch {
                expected: "amd64".to_string(),
                found: "arm64".to_string(),
            }
        );
        // Display names the runtime symptom so the gate message is actionable.
        assert!(err.to_string().contains("exec format error"));
    }

    #[test]
    fn arm64_match_passes() {
        let json = br#"{"Architecture":"arm64"}"#;
        assert!(check_inspect_arch(json, "arm64").is_ok());
    }

    #[test]
    fn missing_architecture_field_is_typed() {
        let json = br#"{"Name":"x","Os":"linux"}"#;
        assert_eq!(
            check_inspect_arch(json, "amd64").unwrap_err(),
            LoaderError::MissingArchitecture
        );
    }

    #[test]
    fn non_json_inspect_output_is_typed() {
        assert_eq!(
            check_inspect_arch(b"not json at all", "amd64").unwrap_err(),
            LoaderError::MissingArchitecture
        );
    }
}
