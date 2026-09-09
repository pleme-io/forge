//! `docker`-binary-installed preflight gate: the pre-lift 3-line
//! `if which::which("docker").is_err() { bail!("Docker is not installed.
//! Please install Docker first."); }` stanza collapsed onto one typed
//! primitive.
//!
//! # Pre-lift census — two sibling stanzas, one preflight gate
//!
//! Two consumer sites in `commands/e2e.rs` each opened with the same
//! 3-line-code + 4-line-comment stanza verbatim before diverging into
//! their respective daemon-liveness paths:
//!
//! 1. `commands/e2e.rs::verify_docker` (:792 pre-lift) — a simple
//!    `Result<()>`-returning preflight that (a) gates on
//!    `which::which("docker")`, (b) probes `docker info`, and (c) bails
//!    with `"Docker daemon is not running..."` on non-success. Consumed
//!    by the E2E-suite entry path where an ambient Docker is assumed.
//! 2. `commands/e2e.rs::ensure_docker_running` (:1175 pre-lift) — the
//!    same gate + probe, followed by a macOS-only auto-start branch
//!    that opens Docker Desktop and polls `docker info` under a bounded
//!    retry until the daemon is up, only then bailing with the same
//!    `"Docker daemon is not running..."` message on timeout.
//!
//! The shared prefix — three code lines under four lines of matching
//! explanatory comment — is what this primitive owns; the divergent
//! daemon-liveness tail (simple bail vs. macOS auto-start ladder) stays
//! at the caller.
//!
//! # Why a `Result<()>`-returning function, not a bool probe
//!
//! Every consumer wants the *same* early-exit shape on the "not
//! installed" branch — one bail on a fixed message string — so the
//! primitive owns both halves (the probe AND the bail) rather than
//! returning a `bool` that each caller then converts to its own bail
//! stanza. A `bool`-returning probe would let a future caller drift the
//! bail message (dropping "Please install Docker first.", swapping
//! "Docker" for "docker", or emitting a `warn!` instead of a `bail!`)
//! and re-introduce the pre-lift duplication class one level deeper.
//!
//! The shape mirrors [`crate::attic_configure_step::use_cache_and_
//! announce_success`] and [`crate::git::git_commit_or_bail`] — typed
//! primitives whose return type is `Result<()>` because the shared
//! failure-path shape is what the primitive is preserving, not just the
//! discovery.
//!
//! # Distinct from sibling `which::which("<tool>")` probes elsewhere
//!
//! `commands/search_sync.rs::check_novasearchctl_available` and
//! `commands/sync.rs::check_sea_orm_cli_available` (sibling `a46d580`
//! lifts) also route `which::which("<tool>")` — but they are
//! `bool`-returning probes whose non-installed branch is *soft*
//! (fall through to a `kubectl exec` pod-side fallback, or return
//! `Ok(false)` to skip the phase). This primitive owns the *hard* gate:
//! non-installed → `bail!`, no fallback. Collapsing them into one
//! primitive would erase the hard-vs-soft distinction the operator uses
//! to tell "the phase can proceed" from "the whole entry point cannot
//! be entered".
//!
//! # No fork+exec on the probe surface
//!
//! The pre-lift stanza already routed the probe through the in-process
//! [`which::which`] crate call rather than a `Command::new("which")`
//! subprocess spawn — the `a46d580` lift discipline every sibling
//! `<tool>_bin` probe surface across the crate already carries. This
//! primitive preserves that shape at ONE point of truth so a future
//! "just spawn `which docker`" regression cannot re-appear silently at
//! either caller.

use anyhow::{bail, Result};

/// The exact bail-message string the two pre-lift sites emitted on the
/// non-installed branch. Constant-lifted so the byte-oracle tests and
/// the caller-shield remediation prose reference the same source of
/// truth, and a future adjustment (e.g. embedding an installation URL)
/// happens in exactly one place.
///
/// The message string is what `.to_string()` on the returned
/// [`anyhow::Error`] renders — a `bail!(<literal>)` with a
/// non-format-string body wraps the literal into the error's root
/// `Display`, preserving pre-lift byte-for-byte behavior at the
/// operator-facing surface (e.g. what a `forge e2e-*` failure prints on
/// stderr).
pub const DOCKER_NOT_INSTALLED_BAIL_MESSAGE: &str =
    "Docker is not installed. Please install Docker first.";

/// Bail with the pre-lift `"Docker is not installed. Please install
/// Docker first."` message unless the `docker` binary resolves via
/// [`which::which`].
///
/// The probe routes through the in-process [`which::which`] crate call
/// — the same shape the sibling `a46d580` lifts already carry, and the
/// same shape the whole-module `bare_spawn_shapes` shield on
/// `commands/e2e.rs` continues to forbid drifting back to a
/// `Command::new("which")` subprocess spawn. No ambient dependency on
/// a `which`-binary existing on `PATH` itself.
///
/// Returns `Ok(())` on the installed branch so the caller composes it
/// with `?` at the entry to its own daemon-liveness probe:
///
/// ```ignore
/// fn verify_docker() -> Result<()> {
///     bail_unless_docker_installed()?;
///     // ... `docker info` probe + daemon-liveness bail ...
/// }
/// ```
pub fn bail_unless_docker_installed() -> Result<()> {
    bail_unless_docker_installed_with_probe(which::which("docker").is_ok())
}

/// Injectable probe-result variant used by the byte-oracle tests below
/// so both branches (installed → `Ok(())`, not-installed → `Err(_)`
/// carrying [`DOCKER_NOT_INSTALLED_BAIL_MESSAGE`]) are exercised
/// deterministically without depending on the ambient
/// [`which::which("docker")`] outcome of whichever host runs the
/// suite. Mirrors the pattern the sibling
/// [`crate::retry::classify_spawn_anyhow`] byte-oracles ride on — the
/// pure-function core is the byte oracle; the environment-touching
/// wrapper is one line above it.
pub(crate) fn bail_unless_docker_installed_with_probe(installed: bool) -> Result<()> {
    if !installed {
        bail!("{}", DOCKER_NOT_INSTALLED_BAIL_MESSAGE);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle (non-installed branch): the returned
    /// [`anyhow::Error`]'s `Display` renders exactly the pre-lift
    /// bail message, byte-for-byte. A future refactor that
    /// (a) shortened the message ("Docker not installed."),
    /// (b) added a URL tail, (c) swapped the sentence order, or
    /// (d) capitalized "Docker" differently regresses this
    /// assertion — the operator-facing stderr line stays pinned.
    #[test]
    fn test_bail_unless_docker_installed_with_probe_false_emits_pre_lift_message() {
        let err = bail_unless_docker_installed_with_probe(false).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Docker is not installed. Please install Docker first."
        );
    }

    /// Byte-oracle (installed branch): the primitive returns `Ok(())`
    /// with no side effect on the happy path — the caller composes it
    /// with `?` at the entry to its own daemon-liveness probe and
    /// expects a plain `Ok` on the installed branch.
    #[test]
    fn test_bail_unless_docker_installed_with_probe_true_returns_ok() {
        assert!(bail_unless_docker_installed_with_probe(true).is_ok());
    }

    /// Constant pin: the shared message string the byte-oracle and the
    /// caller-shield remediation reference is the pre-lift verbatim
    /// literal. A change here rotates both dependents in lockstep.
    #[test]
    fn test_docker_not_installed_bail_message_matches_pre_lift_literal() {
        assert_eq!(
            DOCKER_NOT_INSTALLED_BAIL_MESSAGE,
            "Docker is not installed. Please install Docker first."
        );
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` or `cli/src/services/` may spell the raw
    /// pre-lift `bail!("Docker is not installed. Please install
    /// Docker first.")` literal inline any more. The two pre-lift
    /// sites migrated; any future consumer that wants the same
    /// docker-installed-preflight gate reaches for
    /// [`bail_unless_docker_installed`] on first grep, not by
    /// copy-pasting the raw bail literal from an existing module.
    ///
    /// Reconstructed at test time via [`format!`] so this shield's own
    /// source text does not false-match itself; the whole-scan
    /// therefore covers both the top-of-file production body AND every
    /// sibling `#[cfg(test)]` block. Docstring `///` lines are
    /// skipped so a future module that quotes the pre-lift shape as
    /// historical prose does not trip the shield.
    #[test]
    fn no_command_or_service_module_still_spells_raw_docker_not_installed_bail_literal() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let scan_dirs = [crate_src.join("commands"), crate_src.join("services")];

        // Reconstruct the forbidden literal via `format!` so this
        // shield's own source text does not false-match itself.
        let forbidden = format!(
            "bail!(\"{}\")",
            "Docker is not installed. Please install Docker first."
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
            "raw `bail!(\"Docker is not installed. Please install Docker first.\")` \
             literal(s) survive under `commands/` or `services/` — route each \
             through `crate::docker_installed_preflight::bail_unless_docker_installed()` \
             instead:\n{:#?}",
            offenders
        );
    }

    /// Caller shield (positive half): the one pre-lift module that
    /// housed the two sites (`commands/e2e.rs`) MUST forward through
    /// [`bail_unless_docker_installed`] at least twice, so a migration
    /// that dropped a call site outright leaves the negative "no raw
    /// inline shape" scan trivially satisfied by absence but the
    /// positive count still fails. Mirrors the sibling
    /// `every_prelift_module_forwards_through_*` shields the crate
    /// carries against every other typed primitive.
    #[test]
    fn every_prelift_module_forwards_through_bail_unless_docker_installed() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let expectations: &[(PathBuf, usize)] = &[(crate_src.join("commands").join("e2e.rs"), 2)];
        let needle = "bail_unless_docker_installed(";
        for (path, min_count) in expectations {
            let source = std::fs::read_to_string(path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{} must forward at least {} docker-installed-preflight site(s) through \
                 `{}`; found {}. A dropped call would leave the negative raw-shape \
                 scan satisfied by absence.",
                path.display(),
                min_count,
                needle,
                forwards,
            );
        }
    }

    /// Sigil-body shield: the primitive's own body MUST route the
    /// probe through the in-process [`which::which`] crate call at a
    /// code line — not through a `Command::new("which")` subprocess
    /// spawn. Post-lift the crate-idiom moved from `commands/e2e.rs`
    /// into this module (the pre-lift `commands/e2e.rs` shield
    /// `assert_source_probes_via_which_which_code_line(..., "docker")`
    /// migrated with it).
    ///
    /// Mirrors the sibling shield on the sync-half of the `a46d580`
    /// lift family: whichever module OWNS the `<tool>`-preflight probe
    /// is the one whose source must contain the crate-idiom call. A
    /// silent drift back to a subprocess spawn regresses the hermetic-
    /// runner contract at ONE point of truth here.
    #[test]
    fn primitive_body_probes_via_which_which_crate_call() {
        const SOURCE: &str = include_str!("docker_installed_preflight.rs");
        crate::test_support::assert_source_probes_via_which_which_code_line(
            SOURCE,
            "docker_installed_preflight.rs",
            "docker",
        );
    }
}
