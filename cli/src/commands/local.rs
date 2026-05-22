//! Local development service commands (build + run locally)
//!
//! Replaces web-build.nix::mkWebLocalApps.
//! Builds a Docker image via Nix, loads it, and runs it locally.

use anyhow::{bail, Context, Result};
use std::process::Command;
use tracing::info;

use crate::nix::build_flake_attr;

/// Execute an external CLI and return its trimmed stdout.
///
/// Fourth sibling of the `run_command_output` shape-adapter family —
/// alongside `commands/seed.rs::run_command_output` (sync,
/// `std::process::Command` → `kubectl get pod` for CNPG primary
/// discovery), `commands/sessions.rs::kubectl` (sync, fixed-cmd kubectl
/// for valkey session flush), and `commands/attestation.rs::run_command_output`
/// (async, `tokio::process::Command` → git/nix/skopeo for Phase 1
/// attestation source/build/image records). All four shape-adapt for
/// [`crate::retry::classify_capture_query_anyhow`] — the canonical
/// "anyhow envelope over a queried external CLI" primitive — at the
/// sync (`std::process::Command`) and async (`tokio::process::Command`)
/// spawn surfaces respectively.
///
/// The pre-lift `down` body fused into a `.context("Failed to run
/// docker {stop|rm}")?` envelope on the spawn arm that dropped both
/// the offending args and the underlying `io::Error::Display`, plus
/// an `if !X.status.success() { bail!("docker {stop|rm} failed for
/// {name}: {trimmed_stderr}") }` op arm that dropped the exit code
/// entirely. Post-lift the spawn arm carries `Failed to spawn {cmd}
/// {args:?}: {io_error}` and the op arm carries `{cmd} {args:?}
/// failed (exit {code:?}): {trimmed_stderr}` — the `(cmd, args,
/// exit_code, stderr)` structural-record tuple THEORY §V.4 Phase 1
/// attestation telemetry pattern-matches on, identical-by-construction
/// across every consumer of the primitive.
fn run_command_output(cmd: &str, args: &[&str]) -> Result<String> {
    crate::retry::classify_capture_query_anyhow(Command::new(cmd).args(args).output(), cmd, args)
}

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

    // Stop the container — captured output routes through the canonical
    // `classify_capture_query_anyhow` primitive (sibling of seed.rs /
    // sessions.rs / attestation.rs shape-adapters). Bails on non-zero
    // exit with the structural `(cmd, args, exit_code, stderr)` tuple
    // THEORY §V.4 attestation records pattern-match on.
    run_command_output("docker", &["stop", name])?;

    // Remove the container — same canonical primitive. Two adjacent
    // sites past THEORY §VI.1's coincidence-vs-law threshold inside one
    // function (PRIME DIRECTIVE: ≥2), consolidated onto one shape-adapter.
    run_command_output("docker", &["rm", name])?;

    info!("{} stopped and removed", name);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::make_executable_shim;

    /// `run_command_output` on a successful spawn returns the trimmed
    /// stdout. Pins the canonical UTF-8-lossy-then-trim discipline at
    /// the sync `local.rs::down` surface so a future regression that
    /// dropped the trim would surface here as a stray-whitespace-bearing
    /// stdout — same shape `seed.rs::run_command_output`'s test
    /// (`test_run_command_output_success_returns_trimmed_stdout`) pins
    /// at the sync kubectl shape-adapter sibling.
    #[test]
    fn test_run_command_output_success_returns_trimmed_stdout() {
        let (_dir, shim) =
            make_executable_shim("echo-shim", "#!/bin/sh\necho '  container-id  '\n");
        let out = run_command_output(&shim, &[]).expect("shim must succeed");
        assert_eq!(
            out, "container-id",
            "trim must strip both leading/trailing ws"
        );
    }

    /// `run_command_output` on a non-zero exit surfaces the structural-
    /// record tuple in the error message: the operation label (`cmd` +
    /// `args` debug rendering), the exit code, and the trimmed stderr.
    /// Pre-lift the `bail!("docker stop failed for {name}: {stderr}")`
    /// envelope dropped both the exit code AND the args entirely — a
    /// future telemetry consumer that wanted to recover the offending
    /// `(cmd, args, exit_code, stderr)` tuple from a failed
    /// `down("svc", None)` step (THEORY §V.4 Phase 1 attestation
    /// record shape) had to scrape it back from host process accounting.
    /// A future regression that re-dropped the exit code or the args
    /// would fail this test rather than silently degrade the Phase 1
    /// record shape every other consumer of the primitive (sessions,
    /// seed, attestation) already produces.
    #[test]
    fn test_run_command_output_op_failure_carries_structural_tuple() {
        let (_dir, shim) = make_executable_shim(
            "fail-shim",
            "#!/bin/sh\necho 'Error: No such container: svc' 1>&2\nexit 1\n",
        );
        let err = run_command_output(&shim, &["stop", "svc"]).expect_err("nonzero exit must fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("(exit Some(1))"),
            "msg must carry exit code, got: {msg}"
        );
        assert!(
            msg.contains("No such container"),
            "msg must carry trimmed stderr, got: {msg}"
        );
        assert!(
            msg.contains("\"stop\"") && msg.contains("\"svc\""),
            "msg must carry args debug rendering, got: {msg}"
        );
    }

    /// `run_command_output` on a spawn failure (binary not on PATH /
    /// nonexistent absolute path) surfaces the canonical
    /// `Failed to spawn {cmd} {args:?}: {io_error}` envelope. Pre-lift
    /// the `.context("Failed to run docker stop")` envelope at both
    /// `down` sites dropped both the offending args AND the underlying
    /// `io::Error::Display`. Pins the spawn-vs-op discriminator the
    /// `classify_capture` (b75a273) primitive guarantees at the
    /// canonical surface — a future regression that re-fused the spawn
    /// arm into the op arm (or that dropped the args from the spawn
    /// envelope) would fail this test rather than silently collapse
    /// the typed-error structural shape.
    #[test]
    fn test_run_command_output_spawn_failure_carries_op_label() {
        let missing = "/nonexistent/forge-test-shim-must-not-exist-local";
        let err = run_command_output(missing, &["rm", "svc"])
            .expect_err("spawn against nonexistent path must fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("Failed to spawn"),
            "msg must carry spawn-arm envelope, got: {msg}"
        );
        assert!(
            msg.contains(missing),
            "msg must carry the offending cmd path, got: {msg}"
        );
        assert!(
            msg.contains("\"rm\"") && msg.contains("\"svc\""),
            "msg must carry args debug rendering, got: {msg}"
        );
    }
}
