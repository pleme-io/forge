//! Infrastructure lifecycle commands (docker compose up/down/clean)
//!
//! Replaces product-sdlc.nix::infra:up/down/clean.

use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::Command;
use tracing::info;

use crate::git;

/// Start infrastructure services via docker compose.
pub fn up(working_dir: &str, services: &[String]) -> Result<()> {
    let repo_root = resolve_repo_root(working_dir)?;
    let compose_file = find_compose_file(&repo_root)?;

    info!("Starting infrastructure services...");

    let mut args = vec![
        "compose".to_string(),
        "-f".to_string(),
        compose_file.to_string_lossy().to_string(),
        "up".to_string(),
        "-d".to_string(),
    ];

    for svc in services {
        args.push(svc.clone());
    }

    let status = Command::new("docker")
        .args(&args)
        .current_dir(&repo_root)
        .status()
        .context("Failed to run docker compose up")?;

    if !status.success() {
        bail!("docker compose up failed");
    }

    info!("Infrastructure services started");
    Ok(())
}

/// Stop infrastructure services via docker compose.
pub fn down(working_dir: &str) -> Result<()> {
    let repo_root = resolve_repo_root(working_dir)?;
    let compose_file = find_compose_file(&repo_root)?;

    info!("Stopping infrastructure services...");

    let status = Command::new("docker")
        .args([
            "compose",
            "-f",
            &compose_file.to_string_lossy(),
            "down",
        ])
        .current_dir(&repo_root)
        .status()
        .context("Failed to run docker compose down")?;

    if !status.success() {
        bail!("docker compose down failed");
    }

    info!("Infrastructure services stopped");
    Ok(())
}

/// Stop infrastructure and remove volumes + orphans.
pub fn clean(working_dir: &str) -> Result<()> {
    let repo_root = resolve_repo_root(working_dir)?;
    let compose_file = find_compose_file(&repo_root)?;

    info!("Cleaning infrastructure (removing volumes and orphans)...");

    let status = Command::new("docker")
        .args([
            "compose",
            "-f",
            &compose_file.to_string_lossy(),
            "down",
            "-v",
            "--remove-orphans",
        ])
        .current_dir(&repo_root)
        .status()
        .context("Failed to run docker compose down -v")?;

    if !status.success() {
        bail!("docker compose clean failed");
    }

    info!("Infrastructure cleaned");
    Ok(())
}

// --- Helpers ---

fn resolve_repo_root(working_dir: &str) -> Result<std::path::PathBuf> {
    if working_dir != "." {
        Ok(Path::new(working_dir).to_path_buf())
    } else {
        git::get_repo_root()
    }
}

fn find_compose_file(repo_root: &Path) -> Result<std::path::PathBuf> {
    let candidates = [
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
    ];

    for name in &candidates {
        let path = repo_root.join(name);
        if path.exists() {
            return Ok(path);
        }
    }

    bail!(
        "No docker compose file found in {}. Tried: {}",
        repo_root.display(),
        candidates.join(", ")
    )
}
