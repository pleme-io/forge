//! Local development service commands (build + run locally)
//!
//! Replaces web-build.nix::mkWebLocalApps.
//! Builds a Docker image via Nix, loads it, and runs it locally.

use anyhow::{bail, Context, Result};
use std::process::Command;
use tracing::info;

use crate::nix::build_flake_attr;
use crate::retry::run_query_capture_sync;

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

    // Build the image via Nix through the canonical `build_flake_attr`
    // primitive — typed `(BuildFailed | EmptyStorePath | ExecFailed)`
    // discrimination, structured `(exit_code, stderr)` extraction,
    // canonical UTF-8-lossy-trim of the success-stdout. The typed
    // [`crate::error::NixBuildError`] is recoverable across the anyhow
    // boundary via `err.downcast_ref::<NixBuildError>()`.
    info!("Building .#{}...", flake_attr);
    let image_path = build_flake_attr(&format!(".#{}", flake_attr))
        .await?
        .store_path;

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
    let _ = Command::new("docker").args(["stop", name]).output();
    let _ = Command::new("docker").args(["rm", name]).output();

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

    // Stop + remove the container — captured output routes through the
    // canonical [`crate::retry::run_query_capture_sync`] primitive (the
    // `(cmd, args) -> Result<String>` consolidation for the sync no-cwd
    // "spawn an external CLI, capture trimmed stdout, surface the
    // structural-record tuple on failure" shape). Pre-this-commit the
    // two sites delegated through a private `run_command_output` wrapper
    // in this module; that wrapper was one of three identically-shaped
    // shape-adapters (`seed.rs::run_command_output`,
    // `sessions.rs::kubectl`) past THEORY §VI.1's three-is-a-law
    // threshold, all collapsed onto `run_query_capture_sync` in one
    // commit. Both sites bail on non-zero exit with the structural
    // `(cmd, args, exit_code, stderr)` tuple THEORY §V.4 attestation
    // records pattern-match on.
    run_query_capture_sync("docker", &["stop", name])?;
    run_query_capture_sync("docker", &["rm", name])?;

    info!("{} stopped and removed", name);
    Ok(())
}
