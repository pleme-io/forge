//! Tool release lifecycle commands
//!
//! Provides release, bump, check, and regenerate operations for
//! standalone tool repos (Rust and Zig).
//! Replaces substrate's release-helpers.nix and rust-tool-release.nix.

use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::Command;
use tracing::info;

use crate::version;
use crate::git;

/// Release a tool: read version, verify clean tree, build targets, tag, push, create GitHub release.
pub async fn release(
    name: &str,
    repo: &str,
    language: &str,
    working_dir: &str,
    dry_run: bool,
) -> Result<()> {
    let dir = Path::new(working_dir);
    if !dir.exists() {
        bail!("Working directory not found: {}", working_dir);
    }

    // 1. Read version from the appropriate manifest
    let ver = read_version_for_language(dir, language)?;
    let tag = format!("v{}", ver);
    info!("{} version: {} (tag: {})", name, ver, tag);

    // 2. Verify clean working tree
    if !git::is_working_tree_clean()? {
        bail!("Working tree is dirty — commit or stash changes before releasing");
    }

    // 3. Check tag doesn't already exist
    if git::tag_exists(&tag)? {
        bail!("Tag {} already exists — bump the version first", tag);
    }

    // 4. Build targets
    let targets = [
        "x86_64-linux",
        "aarch64-linux",
        "x86_64-darwin",
        "aarch64-darwin",
    ];

    let tmp = tempfile::tempdir().context("Failed to create temp directory")?;
    let mut artifacts: Vec<String> = Vec::new();

    for target in &targets {
        let flake_attr = format!(".#{}-{}", name, target);
        info!("Building {}...", flake_attr);

        let output = tokio::process::Command::new("nix")
            .args([
                "build",
                &flake_attr,
                "--no-link",
                "--print-out-paths",
                "--impure",
            ])
            .current_dir(dir)
            .output()
            .await
            .with_context(|| format!("Failed to build {}", flake_attr))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Build failed for {}: {}", flake_attr, stderr.trim());
        }

        let store_path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if store_path.is_empty() {
            bail!("Build returned empty path for {}", flake_attr);
        }

        // Copy binary to temp dir with descriptive name
        let binary_name = format!("{}-{}", name, target);
        let dest = tmp.path().join(&binary_name);
        let src = Path::new(&store_path).join("bin").join(name);

        if src.exists() {
            std::fs::copy(&src, &dest)
                .with_context(|| format!("Failed to copy binary for {}", target))?;
            artifacts.push(dest.to_string_lossy().to_string());
            info!("  Collected: {}", binary_name);
        } else {
            // Some builds produce the binary directly at the store path
            std::fs::copy(&store_path, &dest)
                .with_context(|| format!("Failed to copy artifact for {}", target))?;
            artifacts.push(dest.to_string_lossy().to_string());
            info!("  Collected: {}", binary_name);
        }
    }

    // 5. Dry run check
    if dry_run {
        info!("Dry run — would create tag {} and GitHub release with {} artifacts", tag, artifacts.len());
        for a in &artifacts {
            info!("  {}", a);
        }
        return Ok(());
    }

    // 6. Create and push tag
    info!("Creating tag {}...", tag);
    git::create_tag(&tag, &format!("Release {} {}", name, ver))?;
    git::push_tag(&tag)?;
    info!("Tag {} pushed", tag);

    // 7. Create GitHub release with artifacts
    info!("Creating GitHub release...");
    let mut gh_args = vec![
        "release".to_string(),
        "create".to_string(),
        tag.clone(),
        "--repo".to_string(),
        repo.to_string(),
        "--title".to_string(),
        format!("{} {}", name, ver),
        "--generate-notes".to_string(),
    ];

    for artifact in &artifacts {
        gh_args.push(artifact.clone());
    }

    let gh_status = Command::new("gh")
        .args(&gh_args)
        .current_dir(dir)
        .status()
        .context("Failed to run gh release create")?;

    if !gh_status.success() {
        bail!("GitHub release creation failed for {}", tag);
    }

    info!("Released {} {} with {} artifacts", name, ver, artifacts.len());
    Ok(())
}

/// Bump the version for a tool.
pub fn bump(name: &str, language: &str, level: &str, working_dir: &str) -> Result<()> {
    let dir = Path::new(working_dir);
    if !dir.exists() {
        bail!("Working directory not found: {}", working_dir);
    }

    match language {
        "rust" => {
            // Use cargo set-version for Rust
            let status = Command::new("cargo")
                .args(["set-version", "--bump", level])
                .current_dir(dir)
                .status()
                .context("Failed to run cargo set-version (is cargo-edit installed?)")?;

            if !status.success() {
                bail!("cargo set-version --bump {} failed", level);
            }

            // Regenerate Cargo.nix if crate2nix is available
            if which::which("crate2nix").is_ok() {
                info!("Regenerating Cargo.nix...");
                let status = Command::new("crate2nix")
                    .args(["generate"])
                    .current_dir(dir)
                    .status()
                    .context("Failed to run crate2nix generate")?;

                if !status.success() {
                    bail!("crate2nix generate failed");
                }
            }

            let new_ver = version::read_cargo_version(&dir.join("Cargo.toml"))?;
            info!("{}: bumped to {} ({})", name, new_ver, level);
        }
        "zig" => {
            let zon_path = dir.join("build.zig.zon");
            let old_ver = version::read_zig_version(&zon_path)?;
            let new_ver = version::bump_semver(&old_ver, level)?;
            version::write_zig_version(&zon_path, &new_ver)?;
            info!("{}: {} → {} ({})", name, old_ver, new_ver, level);
        }
        _ => bail!("Unsupported language '{}' — use rust or zig", language),
    }

    Ok(())
}

/// Run checks for a tool (format, lint, test).
pub fn check(name: &str, language: &str, working_dir: &str) -> Result<()> {
    let dir = Path::new(working_dir);
    if !dir.exists() {
        bail!("Working directory not found: {}", working_dir);
    }

    match language {
        "rust" => {
            info!("{}: running cargo fmt --check...", name);
            run_cmd(dir, "cargo", &["fmt", "--check"])?;

            info!("{}: running cargo clippy...", name);
            run_cmd(dir, "cargo", &["clippy", "--", "-D", "warnings"])?;

            info!("{}: running cargo test...", name);
            run_cmd(dir, "cargo", &["test"])?;

            info!("{}: all checks passed", name);
        }
        "zig" => {
            info!("{}: running zig build...", name);
            run_cmd(dir, "zig", &["build"])?;

            info!("{}: running zig build test...", name);
            run_cmd(dir, "zig", &["build", "test"])?;

            info!("{}: all checks passed", name);
        }
        _ => bail!("Unsupported language '{}' — use rust or zig", language),
    }

    Ok(())
}

/// Regenerate lockfiles / build metadata.
pub fn regenerate(language: &str, working_dir: &str) -> Result<()> {
    let dir = Path::new(working_dir);
    if !dir.exists() {
        bail!("Working directory not found: {}", working_dir);
    }

    match language {
        "rust" => {
            info!("Running crate2nix generate...");
            run_cmd(dir, "crate2nix", &["generate"])?;
            info!("Cargo.nix regenerated");
        }
        "zig" => {
            info!("No regeneration needed for Zig");
        }
        _ => bail!("Unsupported language '{}' — use rust or zig", language),
    }

    Ok(())
}

// --- Helpers ---

fn read_version_for_language(dir: &Path, language: &str) -> Result<String> {
    match language {
        "rust" => version::read_cargo_version(&dir.join("Cargo.toml")),
        "zig" => version::read_zig_version(&dir.join("build.zig.zon")),
        _ => bail!("Unsupported language '{}' — use rust or zig", language),
    }
}

fn run_cmd(dir: &Path, program: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(program)
        .args(args)
        .current_dir(dir)
        .status()
        .with_context(|| format!("Failed to run {} {}", program, args.join(" ")))?;

    if !status.success() {
        bail!("{} {} failed", program, args.join(" "));
    }

    Ok(())
}
