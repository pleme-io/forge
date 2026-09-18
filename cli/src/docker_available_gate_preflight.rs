//! docker-availability gate-preflight: the pre-lift 2 sibling
//! `if let Err(e) = e2e::ensure_docker_running() { crate::ui::print_step_failure_with_error("Docker not available", &e); return Ok(false); }`
//! gate-preamble stanzas collapsed onto one typed primitive.
//!
//! # Pre-lift census — two sibling stanzas, one gate preflight
//!
//! Two consumer sites in `commands/prerelease.rs` each opened with the
//! same 4-line-code + 1-line-comment stanza verbatim before diverging
//! into their respective test-container harnesses:
//!
//! 1. `commands/prerelease.rs::run_integration_gate` (:907-911 pre-lift)
//!    — inside the G13 (integration tests) entry, ahead of the
//!    testcontainers-backed `cargo test --test '*'` spawn. Emits the
//!    `Docker not available: <err>` step-failure line and returns
//!    `Ok(false)` so the summary skips the gate rather than erroring
//!    the whole pre-release run.
//! 2. `commands/prerelease.rs::run_e2e_gate` (:1020-1024 pre-lift) —
//!    inside the G14 (E2E tests) entry, ahead of the
//!    chromiumoxide-backed `cargo test --test e2e_tests` spawn. Same
//!    failure line and same `Ok(false)` short-circuit.
//!
//! The shared surface — one probe + one operator-facing failure line
//! on the same label + one soft short-circuit — is what this primitive
//! owns; the divergent test-harness tail (integration testcontainers
//! vs. chromiumoxide E2E) stays at the caller.
//!
//! # Companion to [`crate::docker_daemon_running_preflight`] / [`crate::docker_installed_preflight`]
//!
//! Those two primitives own the HARD gate `verify_docker` / the
//! `ensure_docker_running` internal path takes: a `Result<()>`-shaped
//! bail on the daemon-not-running / not-installed branch that `?`
//! propagates up through the entry point. This primitive owns the
//! SOFT gate the two pre-release entries `run_integration_gate` /
//! `run_e2e_gate` take: on failure they emit an operator-facing step
//! line and short-circuit their own boolean summary channel, letting
//! the sibling gates continue running rather than halting the whole
//! pre-release run.
//!
//! # Why `bool`-returning, not `Result<()>`-returning
//!
//! Both pre-lift sites explicitly wanted `return Ok(false)` (a
//! summary-recorded skip), not `?` propagation (an aborted run). A
//! `Result<()>`-returning peer to `bail_unless_docker_daemon_running`
//! would force each caller to catch the error and re-map to `false`,
//! re-opening the same duplication class one level deeper. The
//! `bool` return keeps `false` == "the caller should short-circuit
//! its own summary channel" and moves the pre-lift `return Ok(false)`
//! stanza into a single one-line `if !ensure_docker_running_for_gate()
//! { return Ok(false); }` post-lift shape.

use crate::commands::e2e;

/// The exact `label` string the two pre-lift sites handed to
/// [`crate::ui::print_step_failure_with_error`] on the
/// docker-not-available branch. Constant-lifted so the byte-oracle
/// tests and the caller-shield remediation prose reference the same
/// source of truth, and a future adjustment (e.g. softening "Docker
/// not available" to "Docker daemon unreachable", or embedding a
/// diagnostics URL) happens in exactly one place.
///
/// The `InfraError::DockerNotAvailable` variant in [`crate::error`]
/// spells the same three-word prefix in its `#[error(...)]` template
/// (`"Docker not available: {message}"`), but that is a distinct
/// concern (a typed error's `Display` shape, not the pre-release
/// gate-preflight step-line label). Keeping this constant scoped to
/// the gate-preflight primitive lets a future rename of the label
/// happen here without dragging the typed error's `Display` shape
/// along with it — and vice versa.
pub const DOCKER_NOT_AVAILABLE_STEP_FAILURE_LABEL: &str = "Docker not available";

/// Probe `e2e::ensure_docker_running()`; on failure emit the pre-lift
/// `❌ Docker not available: <err>` step-failure line and return
/// `false` so the caller can short-circuit its own summary channel
/// with `return Ok(false)`.
///
/// Returns `true` on the docker-available branch so the caller
/// composes it with a boolean guard at the entry to its own
/// gate-specific spawn:
///
/// ```ignore
/// async fn run_integration_gate(config: &PreReleaseConfig) -> Result<bool> {
///     let start = crate::ui::print_step_heading_start("G13: Integration tests");
///     if !ensure_docker_running_for_gate() {
///         return Ok(false);
///     }
///     // ... cargo test --test '*' spawn ...
/// }
/// ```
///
/// The failure line's byte-for-byte shape is pinned by the
/// byte-oracle sibling [`write_docker_not_available_step_failure_line`]
/// below, so a future readout-format rotation reaches ONE place.
pub fn ensure_docker_running_for_gate() -> bool {
    match e2e::ensure_docker_running() {
        Ok(()) => true,
        Err(e) => {
            let _ = write_docker_not_available_step_failure_line(&mut std::io::stdout().lock(), &e);
            false
        }
    }
}

/// Writer-taking sibling to the print-side branch of
/// [`ensure_docker_running_for_gate`]. Emits the single
/// `   <❌.red()> Docker not available: <err>` line via
/// [`crate::ui::write_step_failure_with_error`] against the supplied
/// writer, using [`DOCKER_NOT_AVAILABLE_STEP_FAILURE_LABEL`] as the
/// label so the byte-oracle test can pin the pre-lift line shape
/// without having to trip the ambient `e2e::ensure_docker_running`
/// probe (which would depend on whichever docker daemon happens to be
/// up on the host running the suite).
pub fn write_docker_not_available_step_failure_line<W, E>(w: &mut W, err: &E) -> std::io::Result<()>
where
    W: std::io::Write,
    E: std::fmt::Display,
{
    crate::ui::write_step_failure_with_error(w, DOCKER_NOT_AVAILABLE_STEP_FAILURE_LABEL, err)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Constant pin: the shared label string the byte-oracle and the
    /// caller-shield remediation reference is the pre-lift verbatim
    /// literal. A change here rotates both dependents in lockstep.
    #[test]
    fn test_docker_not_available_step_failure_label_matches_pre_lift_literal() {
        assert_eq!(
            DOCKER_NOT_AVAILABLE_STEP_FAILURE_LABEL,
            "Docker not available"
        );
    }

    /// Byte-oracle: the writer sibling projects the pre-lift
    /// `crate::ui::print_step_failure_with_error("Docker not available",
    /// &e)` byte-shape verbatim — the same three-space indent, the
    /// same `❌ ` glyph, the same colon-space connective between
    /// label and error, and the caller-supplied `Display`-formatted
    /// error reproduced byte-for-byte. Both writes happen against the
    /// same process-global [`colored`] state at the same moment, so
    /// the equality holds whether ANSI is auto-enabled or auto-disabled
    /// on the host running the suite — the comparison pins the shared
    /// byte-shape, not either arm of the state machine.
    #[test]
    fn test_write_docker_not_available_step_failure_line_projects_prelift_shape() {
        let mut buf: Vec<u8> = Vec::new();
        let err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "connection refused");
        write_docker_not_available_step_failure_line(&mut buf, &err)
            .expect("write against a Vec<u8> writer must succeed");
        let mut peer: Vec<u8> = Vec::new();
        crate::ui::write_step_failure_with_error(&mut peer, "Docker not available", &err)
            .expect("peer write against a Vec<u8> writer must succeed");
        assert_eq!(
            buf, peer,
            "the primitive's writer sibling must project the same byte-shape as \
             `crate::ui::write_step_failure_with_error(w, \"Docker not available\", &err)`"
        );
        // And the emitted line must carry the operator-facing label +
        // error verbatim, independently of whether ANSI framing is on:
        // strip any ANSI escapes and assert the visible-content payload.
        let out = String::from_utf8(buf).expect("writer emits valid UTF-8");
        assert!(
            out.contains("Docker not available: connection refused"),
            "emitted line must carry the `<label>: <err>` payload verbatim; got {:?}",
            out
        );
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` or `cli/src/services/` may spell the raw
    /// pre-lift `print_step_failure_with_error("Docker not available",
    /// ...)` composition inline any more. The two pre-lift sites
    /// migrated; any future consumer that wants the same
    /// docker-not-available step-failure line reaches for
    /// [`ensure_docker_running_for_gate`] on first grep, not by
    /// copy-pasting the raw call from an existing module.
    ///
    /// Reconstructed at test time via [`format!`] so this shield's own
    /// source text does not false-match itself; the whole-scan
    /// therefore covers both the top-of-file production body AND every
    /// sibling `#[cfg(test)]` block. Line-comment and block-comment
    /// lines are skipped so a future module that quotes the pre-lift
    /// shape as historical prose does not trip the shield.
    #[test]
    fn no_command_or_service_module_still_spells_raw_docker_not_available_step_failure_call() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let scan_dirs = [crate_src.join("commands"), crate_src.join("services")];

        // Reconstruct the forbidden call via `format!` so this shield's
        // own source text does not false-match itself.
        let forbidden = format!(
            "print_step_failure_with_error(\"{}\"",
            "Docker not available"
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
            "raw `print_step_failure_with_error(\"Docker not available\", ...)` \
             call(s) survive under `commands/` or `services/` — route each \
             through `crate::docker_available_gate_preflight::ensure_docker_running_for_gate()` \
             instead:\n{:#?}",
            offenders
        );
    }

    /// Caller shield (positive half): the one pre-lift module that
    /// housed the two sites (`commands/prerelease.rs`) MUST forward
    /// through [`ensure_docker_running_for_gate`] at least twice, so a
    /// migration that dropped a call site outright leaves the negative
    /// "no raw inline shape" scan trivially satisfied by absence but
    /// the positive count still fails. Mirrors the sibling
    /// `every_prelift_module_forwards_through_*` shields the crate
    /// carries against every other typed primitive.
    #[test]
    fn every_prelift_module_forwards_through_ensure_docker_running_for_gate() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let expectations: &[(PathBuf, usize)] =
            &[(crate_src.join("commands").join("prerelease.rs"), 2)];
        let needle = "ensure_docker_running_for_gate(";
        for (path, min_count) in expectations {
            let source = std::fs::read_to_string(path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{} must forward at least {} docker-available-gate-preflight site(s) through \
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
