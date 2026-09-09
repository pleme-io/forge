//! `docker`-daemon-running preflight gate: the pre-lift 2 sibling
//! `bail!("Docker daemon is not running. Please start Docker first.")`
//! stanzas across `commands/e2e.rs::{verify_docker, ensure_docker_running}`
//! collapsed onto one typed primitive.
//!
//! # Pre-lift census — two sibling stanzas, one daemon-liveness bail
//!
//! Two consumer sites in `commands/e2e.rs` each emitted the same bail
//! message on the "daemon liveness probe conclusively failed" branch,
//! after diverging paths reached the same conclusion:
//!
//! 1. `commands/e2e.rs::verify_docker` (:810 pre-lift) — inside the
//!    `if !info_output.status.success() { bail!(...); }` arm that fires
//!    when the initial `docker info` probe reports the daemon down.
//!    Consumed by the E2E-suite entry path where no auto-start is
//!    attempted.
//! 2. `commands/e2e.rs::ensure_docker_running` (:1238 pre-lift) — the
//!    terminal fall-through position on non-macOS (or after the macOS
//!    `open -a Docker` auto-start ladder timed out and no
//!    `Docker failed to start within Ns` bail applies), where the same
//!    "please start Docker" message is emitted with no auto-start left
//!    to try.
//!
//! The shared surface — one bail with the exact same operator-facing
//! message — is what this primitive owns; the divergent probe pathways
//! (single probe vs. macOS auto-start ladder) stay at the caller.
//!
//! # Companion to [`crate::docker_installed_preflight`]
//!
//! This primitive is the daemon-liveness peer of the sibling
//! [`crate::docker_installed_preflight::bail_unless_docker_installed`]
//! `docker`-binary-installed preflight gate (`874daf3`). Together they
//! cover the two failure modes a `forge e2e-*` entry point can face
//! before it ever spawns a container: (a) `docker` binary is missing on
//! PATH, and (b) `docker` binary is present but the daemon is not
//! running. Pre-lift both classes were spelled inline at every consumer;
//! post-lift each is a one-liner `?`-chained call to its owning
//! primitive, and a future adjustment (e.g. embedding a Docker Desktop
//! install URL in the "not installed" branch, or a docs URL in the "not
//! running" branch) happens in exactly one place per class.
//!
//! # `bail_unless_docker_daemon_running(bool)` — one primitive, two shapes
//!
//! Pre-lift site 1 wrapped the bail in
//! `if !info_output.status.success() { bail!(...); }` — a two-line
//! conditional. Pre-lift site 2 emitted the bail unconditionally at a
//! terminal fall-through position. Post-lift both route through the
//! same `bail_unless_docker_daemon_running(running: bool)` primitive:
//!
//! - site 1 passes `info_output.status.success()` (the boolean the
//!   pre-lift `if !` inverted);
//! - site 2 passes the literal `false` (the pre-lift terminal bail is
//!   equivalent to "running=false, unconditionally").
//!
//! Both invocations end in `?` and propagate the exact same
//! [`anyhow::Error`] on the bail branch. Unifying the two shapes on one
//! primitive means a future message rotation touches ONE place; a
//! `bool`-returning probe that each caller then converted to its own
//! bail stanza would re-open the pre-lift duplication class one level
//! deeper.

use anyhow::{bail, Result};

/// The exact bail-message string the two pre-lift sites emitted on the
/// daemon-not-running branch. Constant-lifted so the byte-oracle tests
/// and the caller-shield remediation prose reference the same source of
/// truth, and a future adjustment (e.g. embedding a Docker Desktop docs
/// URL, or softening "Please start Docker first." to "Please start the
/// Docker daemon.") happens in exactly one place.
///
/// The message string is what `.to_string()` on the returned
/// [`anyhow::Error`] renders — a `bail!(<literal>)` with a
/// non-format-string body wraps the literal into the error's root
/// `Display`, preserving pre-lift byte-for-byte behavior at the
/// operator-facing surface (e.g. what a `forge e2e-*` or
/// `forge integration-tests` failure prints on stderr when Docker is
/// installed but not running).
pub const DOCKER_DAEMON_NOT_RUNNING_BAIL_MESSAGE: &str =
    "Docker daemon is not running. Please start Docker first.";

/// Bail with the pre-lift `"Docker daemon is not running. Please start
/// Docker first."` message unless the caller's probe reports the daemon
/// running.
///
/// Returns `Ok(())` on the running branch so the caller composes it
/// with `?` at the site where its own `docker info` probe (or a
/// terminal fall-through) has decided the daemon-liveness question:
///
/// ```ignore
/// fn verify_docker() -> Result<()> {
///     // ... docker-installed-preflight ...
///     let info_output = Command::new(docker_bin()).arg("info").output()?;
///     bail_unless_docker_daemon_running(info_output.status.success())?;
///     Ok(())
/// }
/// ```
///
/// A terminal fall-through caller (no probe result to pass, but the
/// same operator-facing message is wanted) passes `false` explicitly:
///
/// ```ignore
/// fn ensure_docker_running() -> Result<()> {
///     // ... probe + macOS auto-start ladder ...
///     bail_unless_docker_daemon_running(false)?;
///     unreachable!()
/// }
/// ```
pub fn bail_unless_docker_daemon_running(running: bool) -> Result<()> {
    if !running {
        bail!("{}", DOCKER_DAEMON_NOT_RUNNING_BAIL_MESSAGE);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle (daemon-not-running branch): the returned
    /// [`anyhow::Error`]'s `Display` renders exactly the pre-lift
    /// bail message, byte-for-byte. A future refactor that
    /// (a) shortened the message ("Docker daemon down."),
    /// (b) added a docs URL tail, (c) swapped the sentence order, or
    /// (d) softened "Please start Docker first." to a hint form
    /// regresses this assertion — the operator-facing stderr line
    /// stays pinned.
    #[test]
    fn test_bail_unless_docker_daemon_running_false_emits_pre_lift_message() {
        let err = bail_unless_docker_daemon_running(false).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Docker daemon is not running. Please start Docker first."
        );
    }

    /// Byte-oracle (daemon-running branch): the primitive returns
    /// `Ok(())` with no side effect on the happy path — the caller
    /// composes it with `?` at the site where the daemon-liveness
    /// probe already reported success, expecting a plain `Ok` back.
    #[test]
    fn test_bail_unless_docker_daemon_running_true_returns_ok() {
        assert!(bail_unless_docker_daemon_running(true).is_ok());
    }

    /// Constant pin: the shared message string the byte-oracle and the
    /// caller-shield remediation reference is the pre-lift verbatim
    /// literal. A change here rotates both dependents in lockstep.
    #[test]
    fn test_docker_daemon_not_running_bail_message_matches_pre_lift_literal() {
        assert_eq!(
            DOCKER_DAEMON_NOT_RUNNING_BAIL_MESSAGE,
            "Docker daemon is not running. Please start Docker first."
        );
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` or `cli/src/services/` may spell the raw
    /// pre-lift `bail!("Docker daemon is not running. Please start
    /// Docker first.")` literal inline any more. The two pre-lift
    /// sites migrated; any future consumer that wants the same
    /// daemon-not-running bail message reaches for
    /// [`bail_unless_docker_daemon_running`] on first grep, not by
    /// copy-pasting the raw bail literal from an existing module.
    ///
    /// Reconstructed at test time via [`format!`] so this shield's own
    /// source text does not false-match itself; the whole-scan
    /// therefore covers both the top-of-file production body AND every
    /// sibling `#[cfg(test)]` block. Line-comment and block-comment
    /// lines are skipped so a future module that quotes the pre-lift
    /// shape as historical prose does not trip the shield.
    #[test]
    fn no_command_or_service_module_still_spells_raw_docker_daemon_not_running_bail_literal() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let scan_dirs = [crate_src.join("commands"), crate_src.join("services")];

        // Reconstruct the forbidden literal via `format!` so this
        // shield's own source text does not false-match itself.
        let forbidden = format!(
            "bail!(\"{}\")",
            "Docker daemon is not running. Please start Docker first."
        );

        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        for dir in scan_dirs.iter() {
            let read = match std::fs::read_dir(dir) {
                Ok(r) => r,
                Err(_) => continue,
            };
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
        }
        assert!(
            offenders.is_empty(),
            "raw `bail!(\"Docker daemon is not running. Please start Docker first.\")` \
             literal(s) survive under `commands/` or `services/` — route each \
             through `crate::docker_daemon_running_preflight::bail_unless_docker_daemon_running(...)` \
             instead:\n{:#?}",
            offenders
        );
    }

    /// Caller shield (positive half): the one pre-lift module that
    /// housed the two sites (`commands/e2e.rs`) MUST forward through
    /// [`bail_unless_docker_daemon_running`] at least twice, so a
    /// migration that dropped a call site outright leaves the negative
    /// "no raw inline shape" scan trivially satisfied by absence but
    /// the positive count still fails. Mirrors the sibling
    /// `every_prelift_module_forwards_through_bail_unless_docker_installed`
    /// shield the companion [`crate::docker_installed_preflight`]
    /// primitive carries against the same module.
    #[test]
    fn every_prelift_module_forwards_through_bail_unless_docker_daemon_running() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let expectations: &[(PathBuf, usize)] = &[(crate_src.join("commands").join("e2e.rs"), 2)];
        let needle = "bail_unless_docker_daemon_running(";
        for (path, min_count) in expectations {
            let source = std::fs::read_to_string(path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{} must forward at least {} docker-daemon-running-preflight site(s) through \
                 `{}`; found {}. A dropped call would leave the negative raw-shape \
                 scan satisfied by absence.",
                path.display(),
                min_count,
                needle,
                forwards,
            );
        }
    }
}
