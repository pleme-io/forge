//! Local development service commands (build + run locally)
//!
//! Replaces web-build.nix::mkWebLocalApps.
//! Builds a Docker image via Nix, loads it, and runs it locally.

use anyhow::{Context, Result, bail};
use std::process::Command;
use tracing::info;

/// Build a Nix Docker image and run it locally.
pub async fn up(name: &str, flake_attr: &str, port: u16, compose_file: Option<&str>) -> Result<()> {
    // If a compose file is provided, use docker compose instead
    if let Some(cf) = compose_file {
        info!("Starting {} via docker compose...", name);
        let status = Command::new("docker")
            .args(["compose", "-f", cf, "up", "-d", name])
            .status()
            .context("Failed to run docker compose up")?;

        if !status.success() {
            bail!("docker compose up failed for {}", name);
        }

        info!("{} started via compose on port {}", name, port);
        return Ok(());
    }

    // Build the image via Nix
    info!("Building .#{}...", flake_attr);
    let output = tokio::process::Command::new("nix")
        .args(["build", &format!(".#{}", flake_attr), "--no-link", "--print-out-paths", "--impure"])
        .output()
        .await
        .context("Failed to run nix build")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("nix build .#{} failed: {}", flake_attr, stderr.trim());
    }

    let image_path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if image_path.is_empty() {
        bail!("nix build returned empty path for .#{}", flake_attr);
    }

    // Load the image into Docker
    info!("Loading image into Docker...");
    let load_status = Command::new("docker")
        .args(["load", "-i", &image_path])
        .status()
        .context("Failed to run docker load")?;

    if !load_status.success() {
        bail!("docker load failed for {}", image_path);
    }

    // Stop and remove any existing container with the same name
    let _ = Command::new("docker")
        .args(["stop", name])
        .output();
    let _ = Command::new("docker")
        .args(["rm", name])
        .output();

    // Run the container
    info!("Starting container {} on port {}...", name, port);
    let run_status = Command::new("docker")
        .args([
            "run",
            "-d",
            "-p",
            &format!("{}:80", port),
            "--name",
            name,
            name,
        ])
        .status()
        .context("Failed to run docker run")?;

    if !run_status.success() {
        bail!("docker run failed for {}", name);
    }

    info!("{} running at http://localhost:{}", name, port);
    Ok(())
}

/// Stop and remove a locally running container.
pub fn down(name: &str, compose_file: Option<&str>) -> Result<()> {
    if let Some(cf) = compose_file {
        info!("Stopping {} via docker compose...", name);
        let status = Command::new("docker")
            .args(["compose", "-f", cf, "down"])
            .status()
            .context("Failed to run docker compose down")?;

        if !status.success() {
            bail!("docker compose down failed for {}", name);
        }

        info!("{} stopped", name);
        return Ok(());
    }

    info!("Stopping container {}...", name);

    let stop_result = Command::new("docker")
        .args(["stop", name])
        .output()
        .context("Failed to run docker stop")?;

    if !stop_result.status.success() {
        let stderr = String::from_utf8_lossy(&stop_result.stderr);
        bail!("docker stop failed for {}: {}", name, stderr.trim());
    }

    let rm_result = Command::new("docker")
        .args(["rm", name])
        .output()
        .context("Failed to run docker rm")?;

    if !rm_result.status.success() {
        let stderr = String::from_utf8_lossy(&rm_result.stderr);
        bail!("docker rm failed for {}: {}", name, stderr.trim());
    }

    info!("{} stopped and removed", name);
    Ok(())
}
