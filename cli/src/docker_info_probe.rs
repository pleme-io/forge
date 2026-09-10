//! `docker info` daemon-liveness probe: the pre-lift 3 sibling
//! `Command::new(docker_bin()).arg("info").output().context("Failed to
//! run docker info")?` stanzas collapsed onto one typed primitive.
//!
//! # Pre-lift census — three sibling stanzas, one daemon-liveness spawn
//!
//! Three consumer sites in `commands/e2e.rs` each opened with the same
//! four-line `spawn `docker info`, capture output, propagate the spawn
//! error under a fixed `"Failed to run docker info"` context` stanza
//! before diverging on what to do with the resulting exit code:
//!
//! 1. `commands/e2e.rs::verify_docker` (:804 pre-lift) — the E2E-suite
//!    entry-path preflight where the daemon-liveness bool feeds directly
//!    into
//!    [`crate::docker_daemon_running_preflight::bail_unless_docker_daemon_running`].
//! 2. `commands/e2e.rs::ensure_docker_running` (:1189 pre-lift) —
//!    the pre-loop probe of the macOS-auto-start ladder, where a
//!    successful daemon-liveness exit skips the ladder entirely.
//! 3. `commands/e2e.rs::ensure_docker_running` (:1215 pre-lift) — the
//!    in-loop probe repeated inside the macOS auto-start ladder's
//!    bounded-poll body, where a successful daemon-liveness exit ends
//!    the retry loop with a `"Docker started after {}s"` success
//!    message.
//!
//! The shared surface — one spawn of `docker info`, capture the
//! `Output`, propagate any spawn error under the fixed
//! `"Failed to run docker info"` context, and return only the boolean
//! answer to the daemon-liveness question — is what this primitive
//! owns; the divergent post-probe control flow (feed a preflight,
//! short-circuit a loop, end a retry) stays at each caller.
//!
//! # Sibling of [`crate::docker_daemon_running_preflight`] and
//! # [`crate::docker_installed_preflight`]
//!
//! This primitive is the *probe* half of the docker-preflight family
//! whose *bail* halves are already lifted onto
//! [`crate::docker_daemon_running_preflight::bail_unless_docker_daemon_running`]
//! (`35caece`) and
//! [`crate::docker_installed_preflight::bail_unless_docker_installed`]
//! (`874daf3`). Pre-lift the probe half — the actual `docker info`
//! spawn plus its fixed `"Failed to run docker info"` context —
//! stayed spelled out three times inside `commands/e2e.rs`; a fourth
//! site landing (e.g. an integration-tests preflight, or a
//! nix-builder image-load precheck) would have re-emitted the same
//! four-line stanza a fourth time. Post-lift every caller collapses
//! to one line: `let running = probe_docker_daemon_running(...)?;`,
//! and each bail-half sibling composes with it via `?` at the call
//! site.
//!
//! # `Result<bool>`, not `Result<Output>` — the callers only ever
//! # read `.status.success()`
//!
//! All three pre-lift sites ignored every other field on the
//! [`std::process::Output`] the spawn returned. Only `status.success()`
//! flowed into the branching logic: two sites gated an `if …` on it,
//! and the third fed it into the preflight bail. Returning the whole
//! `Output` from the primitive would preserve the pre-lift shape but
//! also let a future caller drift into reading stdout/stderr fields
//! the pre-lift sites deliberately discarded (e.g. embedding parts of
//! `docker info`'s output in a follow-up log message, coupling the
//! preflight surface to a `docker info` stdout format that CLI
//! releases change). Returning a bare `bool` closes that surface at
//! the primitive boundary.
//!
//! # `docker_bin: &str` argument, not a self-resolved
//! # `get_tool_path("DOCKER_BIN", "docker")` call
//!
//! Every consumer already holds a resolved `docker_bin()` result on
//! the surrounding line — the `commands/e2e.rs::docker_bin()` sigil
//! (23241a6) that routes every `docker`-spawn in that module through
//! the `DOCKER_BIN` env override. The primitive accepts a `&str` so
//! the caller keeps its established sigil (and its whole-module
//! shield that asserts every `docker` spawn resolves through
//! `docker_bin()`), and this module stays sidecar-of-callers rather
//! than owning a duplicate `docker_bin()` helper of its own.

use anyhow::{Context, Result};
use std::process::Command;

/// The exact `.context(...)` string the three pre-lift sites attached
/// to their `docker info` spawn errors. Constant-lifted so the
/// byte-oracle test and the caller-shield remediation prose reference
/// the same source of truth, and a future adjustment (e.g. embedding
/// the `docker_bin` path in the message, or naming which preflight
/// asked) happens in exactly one place.
pub const DOCKER_INFO_SPAWN_CONTEXT: &str = "Failed to run docker info";

/// Spawn `<docker_bin> info` and return `Ok(true)` if the daemon
/// answered with a zero exit code (i.e. the daemon is running and
/// responsive), `Ok(false)` if the spawn completed but returned a
/// non-zero exit code (daemon down, unreachable, or refusing the
/// probe), and `Err(_)` with the pre-lift
/// [`DOCKER_INFO_SPAWN_CONTEXT`] context on any spawn failure
/// (missing binary, permission error, etc.).
///
/// Callers compose the returned `bool` with the sibling
/// [`crate::docker_daemon_running_preflight::bail_unless_docker_daemon_running`]
/// primitive at their own preflight site, or gate an `if …`
/// branch on it directly inside a bounded-poll retry loop:
///
/// ```ignore
/// fn verify_docker() -> Result<()> {
///     crate::docker_installed_preflight::bail_unless_docker_installed()?;
///     let running = probe_docker_daemon_running(&docker_bin())?;
///     crate::docker_daemon_running_preflight::bail_unless_docker_daemon_running(running)?;
///     ui::print_success("Docker daemon is running");
///     Ok(())
/// }
/// ```
pub fn probe_docker_daemon_running(docker_bin: &str) -> Result<bool> {
    let output = Command::new(docker_bin)
        .arg("info")
        .output()
        .context(DOCKER_INFO_SPAWN_CONTEXT)?;
    Ok(output.status.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Positive-shape (daemon-running branch): a binary whose exit
    /// code is 0 (`/bin/true`, the POSIX zero-return sentinel) makes
    /// the probe return `Ok(true)`. Pins the `.status.success()` →
    /// `Ok(true)` projection: a future refactor that swapped
    /// `.status.success()` for `.status.code() == Some(0)`
    /// (equivalent on Linux, divergent on signal-terminated
    /// children) still passes; one that inverted the boolean, or
    /// returned `Ok(false)` on zero-exit, regresses.
    #[test]
    fn probe_docker_daemon_running_on_zero_exit_returns_ok_true() {
        let running = probe_docker_daemon_running("/bin/true")
            .expect("/bin/true spawn should succeed on a POSIX host");
        assert!(
            running,
            "a binary that exits 0 must be reported as `running = true`; \
             `.status.success()` was expected to project onto `Ok(true)`."
        );
    }

    /// Positive-shape (daemon-down branch): a binary whose exit code
    /// is 1 (`/bin/false`, the POSIX one-return sentinel) makes the
    /// probe return `Ok(false)`. Pins the pre-lift observation that
    /// the primitive treats a completed non-zero exit as `Ok(false)`
    /// (a normal `daemon down` answer worth branching on) rather
    /// than as `Err(_)` (a spawn failure worth propagating).
    #[test]
    fn probe_docker_daemon_running_on_nonzero_exit_returns_ok_false() {
        let running = probe_docker_daemon_running("/bin/false")
            .expect("/bin/false spawn should succeed on a POSIX host");
        assert!(
            !running,
            "a binary that exits non-zero must be reported as `running = false`; \
             the primitive must NOT project a completed non-zero exit into `Err(_)`."
        );
    }

    /// Byte-oracle (spawn-failure branch): a probe whose target
    /// binary does not exist returns `Err(_)` whose `Display` opens
    /// with the pre-lift [`DOCKER_INFO_SPAWN_CONTEXT`] string. Pins
    /// the `.context("Failed to run docker info")` idiom every
    /// pre-lift site attached to its spawn error, so a future
    /// refactor that (a) dropped the context, (b) rotated the
    /// message to "docker info failed", or (c) swapped the context
    /// for a `?` bare propagation regresses.
    #[test]
    fn probe_docker_daemon_running_on_missing_binary_carries_prelift_context() {
        let err =
            probe_docker_daemon_running("/nonexistent/docker_info_probe_missing_binary_sentinel")
                .expect_err(
                    "a spawn against a nonexistent binary path must return `Err(_)`, \
             not `Ok(false)` — a fork+exec that never reached exec is \
             observably distinct from a completed non-zero exit.",
                );
        let msg = format!("{err:#}");
        assert!(
            msg.contains(DOCKER_INFO_SPAWN_CONTEXT),
            "spawn-failure `Err(_)` must carry the pre-lift \
             `{DOCKER_INFO_SPAWN_CONTEXT}` context; got: {msg}"
        );
    }

    /// Constant pin: the shared context string the byte-oracle and
    /// the caller-shield remediation reference is the pre-lift
    /// verbatim literal. A change here rotates both dependents in
    /// lockstep. Mirrors the sibling
    /// `docker_daemon_running_preflight::DOCKER_DAEMON_NOT_RUNNING_BAIL_MESSAGE`
    /// constant-pin discipline.
    #[test]
    fn docker_info_spawn_context_matches_prelift_literal() {
        assert_eq!(DOCKER_INFO_SPAWN_CONTEXT, "Failed to run docker info");
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` may spell the raw pre-lift
    /// `.context("Failed to run docker info")` idiom inline any
    /// more. The three pre-lift sites migrated; any future consumer
    /// that wants the same `docker info` daemon-liveness spawn
    /// reaches for [`probe_docker_daemon_running`] on first grep,
    /// not by copy-pasting the raw `.context(...)` tail from an
    /// existing module.
    ///
    /// Reconstructed at test time via [`format!`] so this shield's
    /// own source text does not false-match itself; the whole-scan
    /// therefore covers both the top-of-file production body AND
    /// every sibling `#[cfg(test)]` block. Line-comment and
    /// block-comment lines are skipped so a future module that
    /// quotes the pre-lift shape as historical prose does not trip
    /// the shield.
    #[test]
    fn no_command_module_still_spells_raw_docker_info_spawn_context_literal() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let commands_dir = crate_src.join("commands");

        // Reconstruct the forbidden literal via `format!` so this
        // shield's own source text does not false-match itself.
        let forbidden = format!(".context(\"{DOCKER_INFO_SPAWN_CONTEXT}\")");

        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        let read = std::fs::read_dir(&commands_dir)
            .unwrap_or_else(|_| panic!("expected {} to exist", commands_dir.display()));
        for entry in read.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let mut in_block_comment = false;
            for (idx, line) in source.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue;
                }
                if trimmed.starts_with("/*") {
                    in_block_comment = true;
                }
                if in_block_comment {
                    if trimmed.contains("*/") {
                        in_block_comment = false;
                    }
                    continue;
                }
                if line.contains(&forbidden) {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `.context(\"Failed to run docker info\")` literal(s) survive under \
             `commands/` — route each through \
             `crate::docker_info_probe::probe_docker_daemon_running(...)` instead:\n{offenders:#?}",
        );
    }

    /// Caller shield (positive half): the one pre-lift module that
    /// housed the three sites (`commands/e2e.rs`) MUST forward
    /// through [`probe_docker_daemon_running`] at least three
    /// times, so a migration that dropped a call site outright
    /// leaves the negative "no raw inline shape" scan trivially
    /// satisfied by absence but the positive count still fails.
    /// Mirrors the sibling
    /// `every_prelift_module_forwards_through_bail_unless_docker_daemon_running`
    /// shield the companion
    /// [`crate::docker_daemon_running_preflight`] primitive carries
    /// against the same module.
    #[test]
    fn every_prelift_module_forwards_through_probe_docker_daemon_running() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let expectations: &[(PathBuf, usize)] = &[(crate_src.join("commands").join("e2e.rs"), 3)];
        let needle = "probe_docker_daemon_running(";
        for (path, min_count) in expectations {
            let source = std::fs::read_to_string(path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{} must forward at least {} docker-info-probe site(s) through \
                 `{}`; found {}. A dropped call would leave the negative \
                 raw-shape scan satisfied by absence.",
                path.display(),
                min_count,
                needle,
                forwards,
            );
        }
    }
}
