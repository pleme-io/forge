//! Infrastructure lifecycle commands (docker compose up/down/clean)
//!
//! Replaces product-sdlc.nix::infra:up/down/clean.

use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::Command;
use tracing::info;

use crate::git;

/// Resolve the `docker` binary path via `DOCKER_BIN`, falling back to
/// `docker` on `PATH`. Wired through [`crate::repo::get_tool_path`] —
/// the two-arg env-var-or-fallback form every recent sibling sigil
/// (`e2e::docker_bin` at 23241a6, `local::docker_bin` unified in
/// this same commit, `test_ci::cargo_bin` at 916f1a4,
/// `crossplane::crossplane_bin` at 6b3ac16, `ps_bin` at 758dd6f,
/// `open_bin` at 8f4c717, `sh_bin` at b382b78) already rides. The
/// two-arg form lifts the substrate-exported env-var literal
/// (`DOCKER_BIN`) directly into the sigil site so a fleet-wide
/// `grep DOCKER_BIN` reaches this module — the deriving one-arg form
/// this module previously carried
/// (`crate::tools::get_tool_path(crate::tools::tools::DOCKER)`) hid
/// the env-var literal behind a `tools::DOCKER = "docker"` constant
/// plus an uppercase-suffix derivation, so the load-bearing name
/// never appeared in the source and a `DOCKER_BIN` audit missed the
/// site. Pre-lift the three `Command::new` sites (`up`, `down`,
/// `clean`) each spelled the bare `"docker"` literal verbatim,
/// ignoring `DOCKER_BIN` at every site — a Nix-hermetic runner's
/// substrate-derived docker path lost to whatever `docker` sat first
/// on PATH.
fn docker_bin() -> String {
    crate::repo::get_tool_path("DOCKER_BIN", "docker")
}

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

    let status = Command::new(docker_bin())
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

    let status = Command::new(docker_bin())
        .args(["compose", "-f", &compose_file.to_string_lossy(), "down"])
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

    let status = Command::new(docker_bin())
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

#[cfg(test)]
mod docker_bin_routing_tests {
    /// Whole-module shield: no raw `"docker"`-literal spawn may live in
    /// `commands/infra.rs`. Every docker spawn must resolve
    /// `DOCKER_BIN` via [`super::docker_bin`] first.
    ///
    /// Pre-lift the three `Command::new` sites — `up` (docker compose
    /// up -d), `down` (docker compose down), and `clean` (docker
    /// compose down -v --remove-orphans) — each spelled the bare
    /// `"docker"` literal verbatim, ignoring `DOCKER_BIN` at every
    /// site. A Nix-hermetic runner's substrate-derived docker path
    /// lost to whatever `docker` sat first on PATH — the same silent-
    /// PATH-fallback bug class the sibling `commands/local.rs` shield
    /// (1a984dd, `test_docker_spawns_route_through_docker_bin_not_raw_literal`)
    /// and `commands/e2e.rs` shield (23241a6) closed for the sibling
    /// docker surface.
    ///
    /// This shield scans the module's own source via [`include_str!`]
    /// and forbids the fused literal shape. The forbidden shape is
    /// reconstructed via [`format!`] so this shield's own source text
    /// does not false-match itself — the whole-module scan therefore
    /// covers both the top-of-file production body AND every sibling
    /// `#[cfg(test)]` block (any of which could otherwise silently re-
    /// introduce a raw literal). The end-to-end `DOCKER_BIN`-routing
    /// invariant of the underlying primitive is pinned separately by
    /// [`crate::tools::tests::test_get_tool_path_from_env`]; this
    /// shield only certifies that every docker-spawning site in this
    /// module reads through `docker_bin()`.
    #[test]
    fn test_docker_spawns_route_through_docker_bin_not_raw_literal() {
        const SOURCE: &str = include_str!("infra.rs");

        // Composed three-primitive stanza — bare-spawn refusal, sigil
        // definition, canonical two-arg delegation — through the
        // shared `assert_source_routes_bare_spawn_through_two_arg_sigil`
        // (e108260). Sigil name (`docker_bin`) and remediation
        // (`resolve \`DOCKER_BIN\` via \`docker_bin()\``) are derived
        // by the helper from `bare` and `env_var`.
        crate::test_support::assert_source_routes_bare_spawn_through_two_arg_sigil(
            SOURCE,
            "commands/infra.rs",
            "docker",
            "DOCKER_BIN",
        );
        // Also assert the pre-lift deriving one-arg constant-driven
        // form does NOT reappear at any *code* line. Sibling
        // constant-driven check at `commands/prerelease.rs` and
        // `commands/local.rs`.
        crate::test_support::assert_source_forbids_deriving_one_arg_sigil_constant_form(
            SOURCE,
            "commands/infra.rs",
            "DOCKER_BIN",
            "docker",
            "DOCKER",
        );
    }
}
