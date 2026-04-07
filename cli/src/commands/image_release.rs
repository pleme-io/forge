//! Multi-arch OCI image release
//!
//! Replaces image-release.nix::mkImageReleaseApp.
//! Builds (or uses pre-built) images for amd64/arm64, pushes via skopeo,
//! and creates a multi-arch manifest index.

use anyhow::{Context, Result, bail};
use std::process::Command;
use tracing::info;

use crate::git;
use crate::tools::get_tool_path;

/// Release a multi-arch OCI image.
///
/// If `--amd64-attr` or `--arm64-attr` are provided, the image is built via `nix build` first.
/// Otherwise, `--amd64-image` / `--arm64-image` must point to pre-built image tarballs.
pub async fn execute(
    name: &str,
    registry: &str,
    amd64_attr: Option<&str>,
    arm64_attr: Option<&str>,
    amd64_image: Option<&str>,
    arm64_image: Option<&str>,
    working_dir: &str,
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

    // Push amd64
    let amd64_tag = format!("amd64-{}", sha);
    info!("Pushing {} (amd64) as {}:{}...", name, registry, amd64_tag);
    push_image(&skopeo, &amd64_path, registry, &amd64_tag)?;
    push_image(&skopeo, &amd64_path, registry, "amd64-latest")?;

    // Push arm64 if available
    if let Some(ref arm64) = arm64_path {
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

async fn build_nix_image(flake_attr: &str, working_dir: &str) -> Result<String> {
    info!("Building .#{}...", flake_attr);
    let output = tokio::process::Command::new("nix")
        .args([
            "build",
            &format!(".#{}", flake_attr),
            "--no-link",
            "--print-out-paths",
            "--impure",
        ])
        .current_dir(working_dir)
        .output()
        .await
        .with_context(|| format!("Failed to build .#{}", flake_attr))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("nix build .#{} failed: {}", flake_attr, stderr.trim());
    }

    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() {
        bail!("nix build returned empty path for .#{}", flake_attr);
    }

    Ok(path)
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
