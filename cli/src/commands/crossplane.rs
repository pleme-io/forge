//! Crossplane package lifecycle commands.
//!
//! Today: building + pushing a Crossplane **composition Function** package
//! (xpkg) from a Nix-built runtime image + a `package/crossplane.yaml`. This is
//! the typed core of the reusable function-package-release pattern; substrate's
//! `mkFunctionPackageReleaseApp` + the `crossplane-function-release` reusable
//! workflow wrap it, and a function repo (e.g. pitr-tools) consumes it with a
//! 3-line shim — the same shape as `forge image-release` + `mkImageReleaseApp`.
//!
//! Per Pillar 8 (Nix-only image building, no Dockerfiles): the runtime image is
//! built by Nix (`dockerTools`) and handed in as a `docker save` tarball; this
//! command only embeds + pushes it via the `crossplane` CLI.

use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::Command;
use tracing::info;

/// Build a Crossplane Function package (xpkg) from a Nix-built runtime image and
/// a `package/` root, then push it to `package_ref:tag`.
///
/// - `package_root` — directory containing `crossplane.yaml` (the Function meta).
/// - `runtime_image` — a `docker save` tarball of the function's runtime image
///   (built by Nix; e.g. `nix build .#functionImage`), NOT a Dockerfile build.
/// - `package_ref` — OCI repo to push to (e.g. `ghcr.io/pleme-io/function-pitr-drill`).
/// - `tag` — the package tag.
pub fn function_release(
    package_root: &str,
    runtime_image: &str,
    package_ref: &str,
    tag: &str,
) -> Result<()> {
    if !Path::new(package_root).join("crossplane.yaml").exists() {
        bail!("no crossplane.yaml under package-root {}", package_root);
    }
    if !Path::new(runtime_image).exists() {
        bail!("runtime image tarball not found: {}", runtime_image);
    }

    let out = format!(
        "{}/.xpkg-out.xpkg",
        std::env::temp_dir().to_string_lossy().trim_end_matches('/')
    );

    info!("crossplane xpkg build: {} + {} → {}", package_root, runtime_image, out);
    let build = Command::new("crossplane")
        .args([
            "xpkg",
            "build",
            "--package-root",
            package_root,
            "--embed-runtime-image-tarball",
            runtime_image,
            "--package-file",
            &out,
        ])
        .status()
        .context("failed to run `crossplane xpkg build` (is the crossplane CLI on PATH?)")?;
    if !build.success() {
        bail!("crossplane xpkg build failed");
    }

    let dest = format!("{}:{}", package_ref.trim_end_matches('/'), tag);
    info!("crossplane xpkg push → {}", dest);
    let push = Command::new("crossplane")
        .args(["xpkg", "push", "--package-files", &out, &dest])
        .status()
        .context("failed to run `crossplane xpkg push`")?;
    if !push.success() {
        bail!("crossplane xpkg push failed for {}", dest);
    }

    info!("Function package published: {}", dest);
    Ok(())
}

/// Build + push a Crossplane **Configuration** package (an XRD + Composition
/// bundle) from a `package/` root to `package_ref:tag`. Unlike a Function
/// package, a Configuration carries no runtime image — it is pure declarative
/// YAML (the XRDs/Compositions live alongside `crossplane.yaml`).
pub fn configuration_release(package_root: &str, package_ref: &str, tag: &str) -> Result<()> {
    if !Path::new(package_root).join("crossplane.yaml").exists() {
        bail!("no crossplane.yaml under package-root {}", package_root);
    }
    let out = format!(
        "{}/.xpkg-config.xpkg",
        std::env::temp_dir().to_string_lossy().trim_end_matches('/')
    );
    info!("crossplane xpkg build (configuration): {} → {}", package_root, out);
    let build = Command::new("crossplane")
        .args(["xpkg", "build", "--package-root", package_root, "--package-file", &out])
        .status()
        .context("failed to run `crossplane xpkg build`")?;
    if !build.success() {
        bail!("crossplane xpkg build failed");
    }
    let dest = format!("{}:{}", package_ref.trim_end_matches('/'), tag);
    info!("crossplane xpkg push → {}", dest);
    let push = Command::new("crossplane")
        .args(["xpkg", "push", "--package-files", &out, &dest])
        .status()
        .context("failed to run `crossplane xpkg push`")?;
    if !push.success() {
        bail!("crossplane xpkg push failed for {}", dest);
    }
    info!("Configuration package published: {}", dest);
    Ok(())
}

/// Render a composite against its Composition + functions (`crossplane render`) —
/// the SDLC's test surface. The rendered output goes to stdout so a caller can
/// snapshot/golden-test it. `observed` is an optional observed-resources file.
pub fn render(
    composite: &str,
    composition: &str,
    functions: &str,
    observed: Option<&str>,
) -> Result<()> {
    let mut args = vec!["render", composite, composition, functions];
    if let Some(o) = observed {
        args.push("--observed-resources");
        args.push(o);
    }
    let status = Command::new("crossplane")
        .args(&args)
        .status()
        .context("failed to run `crossplane render`")?;
    if !status.success() {
        bail!("crossplane render failed");
    }
    Ok(())
}

/// Validate resources against an extensions directory (`crossplane beta
/// validate`) — the SDLC's schema-validation surface.
pub fn validate(extensions: &str, resources: &str) -> Result<()> {
    let status = Command::new("crossplane")
        .args(["beta", "validate", extensions, resources])
        .status()
        .context("failed to run `crossplane beta validate`")?;
    if !status.success() {
        bail!("crossplane validate failed");
    }
    Ok(())
}
