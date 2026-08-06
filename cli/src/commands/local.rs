//! Local development service commands (build + run locally)
//!
//! Replaces web-build.nix::mkWebLocalApps.
//! Builds a Docker image via Nix, loads it, and runs it locally.

use anyhow::{bail, Context, Result};
use std::process::Command;
use tracing::info;

use crate::nix::build_flake_attr;
use crate::retry::run_query_capture_sync;

/// Resolve the `docker` binary path via `DOCKER_BIN`, falling back to
/// `docker` on `PATH`. Wired through [`crate::tools::get_tool_path`] so a
/// Nix-hermetic runner's substrate-derived `DOCKER_BIN` lands at every
/// docker-spawning site in this module. Mirrors the sibling
/// `helm_bin` / `flux_bin` / `nix_bin` / `attic_bin` sigils — the one
/// bridge between the forge local-app surface and the substrate-
/// `mkRuntimeToolsEnv`-exported binary path. The pre-lift shape spelled
/// `"docker"` bare at every call site (5 `Command::new` spawns + 2
/// `run_query_capture_sync` spawns); each bypassed the env override, so
/// a Nix-hermetic runner's `DOCKER_BIN` lost to whatever `docker` was
/// first on PATH.
fn docker_bin() -> String {
    crate::tools::get_tool_path(crate::tools::tools::DOCKER)
}

/// Build a Nix Docker image and run it locally.
pub async fn up(name: &str, flake_attr: &str, port: u16, compose_file: Option<&str>) -> Result<()> {
    // If a compose file is provided, use docker compose instead
    if let Some(cf) = compose_file {
        info!("Starting {} via docker compose...", name);
        let status = Command::new(docker_bin())
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
    let load_status = Command::new(docker_bin())
        .args(["load", "-i", image_path.as_str()])
        .status()
        .context("Failed to run docker load")?;

    if !load_status.success() {
        bail!("docker load failed for {}", image_path);
    }

    // Stop and remove any existing container with the same name
    let _ = Command::new(docker_bin()).args(["stop", name]).output();
    let _ = Command::new(docker_bin()).args(["rm", name]).output();

    // Run the container
    info!("Starting container {} on port {}...", name, port);
    let run_status = Command::new(docker_bin())
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
        let status = Command::new(docker_bin())
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
    // records pattern-match on. Binary resolution routes through
    // [`docker_bin`] so `DOCKER_BIN` overrides land here too.
    run_query_capture_sync(&docker_bin(), &["stop", name])?;
    run_query_capture_sync(&docker_bin(), &["rm", name])?;

    info!("{} stopped and removed", name);
    Ok(())
}

#[cfg(test)]
mod docker_bin_routing_tests {
    /// Whole-module shield: no raw `"docker"`-literal spawn may live in
    /// `commands/local.rs`. Every docker spawn must resolve `DOCKER_BIN`
    /// via [`super::docker_bin`] first.
    ///
    /// Pre-lift the five `Command::new` sites (docker compose up / load /
    /// stop / rm / run) and the two `run_query_capture_sync` sites
    /// (stop / rm inside `down`) each spelled the bare `"docker"`
    /// literal verbatim, ignoring `DOCKER_BIN` at every site — a
    /// Nix-hermetic runner's substrate-derived docker path lost to
    /// whatever `docker` sat first on PATH.
    ///
    /// This shield scans the module's own source via
    /// [`include_str!`] and forbids both fused literal shapes. The
    /// forbidden shapes are reconstructed via [`format!`] so this
    /// shield's own source text does not false-match itself — the
    /// whole-module scan therefore covers both the top-of-file
    /// production body AND every sibling `#[cfg(test)]` block (any
    /// of which could otherwise silently re-introduce a raw literal).
    /// The end-to-end `DOCKER_BIN`-routing invariant of the underlying
    /// primitive is pinned separately by
    /// [`crate::tools::tests::test_get_tool_path_from_env`] and
    /// [`crate::tools::tests::test_uppercase_conversion`]; this
    /// shield only certifies that every docker-spawning site in this
    /// module reads through `docker_bin()`.
    #[test]
    fn test_docker_spawns_route_through_docker_bin_not_raw_literal() {
        const SOURCE: &str = include_str!("local.rs");

        // Reconstruct the two forbidden shapes at test time — the
        // format string here contains the shape frame (`{}("{}"...)`)
        // but never the fused literal, so this file's source text
        // does not match itself when this shield scans below.
        let bare = "docker";
        let raw_command = format!("Command::new(\"{}\")", bare);
        let raw_capture = format!("run_query_capture_sync(\"{}\",", bare);

        assert!(
            !SOURCE.contains(&raw_command),
            "commands/local.rs must not spawn `docker` via the bare \
             literal — every docker spawn must resolve `DOCKER_BIN` via \
             `docker_bin()` first. A raw literal at `Command::new` \
             bypasses the hermetic-runner contract substrate's \
             mkRuntimeToolsEnv exports."
        );
        assert!(
            !SOURCE.contains(&raw_capture),
            "commands/local.rs must not spawn `docker` via the bare \
             literal — every captured-output docker spawn must route \
             through `run_query_capture_sync(&docker_bin(), …)`. A raw \
             literal at `run_query_capture_sync` bypasses `DOCKER_BIN`."
        );
        assert!(
            SOURCE.contains("fn docker_bin()"),
            "commands/local.rs must define `docker_bin()` — the sigil \
             function that resolves the tools-registry `DOCKER_BIN` \
             override for every docker spawn."
        );
        assert!(
            SOURCE.contains("crate::tools::get_tool_path(crate::tools::tools::DOCKER)"),
            "`docker_bin()` must delegate to \
             `crate::tools::get_tool_path(crate::tools::tools::DOCKER)` \
             — the canonical lookup was not found in the module."
        );
    }
}
