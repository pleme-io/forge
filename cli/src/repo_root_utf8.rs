//! `git::get_repo_root() → to_str() → owned String` UTF-8 repo-root
//! capture with the fleet-standard `Failed to find git repository` +
//! `Invalid repository path` error grammar collapsed onto one typed
//! primitive.
//!
//! # Pre-lift census — two sibling stanzas, one 4-line fusion
//!
//! Two consumer sites in `commands/{github_runner_ci,
//! comprehensive_release}.rs` each opened with the same 4-line stanza
//! verbatim:
//!
//! ```text
//! let repo_root = git::get_repo_root()
//!     .context("Failed to find git repository")?;
//! let repo_root_str = repo_root
//!     .to_str()
//!     .ok_or_else(|| anyhow::anyhow!("Invalid repository path"))?;
//! ```
//!
//! and both callers immediately discarded the [`std::path::PathBuf`]
//! binding — `repo_root_str: &str` was the only downstream consumer at
//! each site (`std::path::Path::new(repo_root_str).join(...)`). The
//! shared prefix — the discovery [`anyhow::Context`] label, the
//! [`std::path::Path::to_str`] validation, and the two error messages —
//! is what this primitive owns; every caller now binds the single owned
//! [`String`] the primitive returns and reaches for `Path::new(&s)` on
//! the borrowed form.
//!
//! # Why an owned `String`, not a borrowed `&str` behind a `PathBuf`
//!
//! Both pre-lift consumers held the [`std::path::PathBuf`] binding
//! solely as a lifetime anchor for the `&str` reborrow — neither site
//! consulted the [`std::path::PathBuf`] again. Returning an owned
//! [`String`] moves the UTF-8 payload out of the transient
//! [`std::path::PathBuf`] and lets each caller drop the two-line
//! binding into one, at the cost of one heap copy of a path that is
//! O(hundreds of bytes) at worst. The trade is measured: pre-lift the
//! `repo_root` intermediate leaked into the reader's model as though it
//! were consulted later, and neither site consulted it.
//!
//! A `Result<(PathBuf, String)>` variant would preserve both bindings
//! but is not called for by either pre-lift site; a
//! `Result<PathBuf>`-returning primitive that skipped the UTF-8 validation
//! would push the second half of the pre-lift stanza back to every
//! caller and re-open the duplication class this lift exists to close.
//!
//! # Distinct from `crate::git::get_repo_root` and `crate::repo::*`
//!
//! [`crate::git::get_repo_root`] owns the discovery shape itself — the
//! `REPO_ROOT`-env-var-then-`git rev-parse --show-toplevel` ladder —
//! and returns a raw [`std::path::PathBuf`]. That primitive stays as
//! the discovery ground; this module is one layer up, owning the
//! `discovery + UTF-8 validation + owned-string coercion` fusion that
//! two commands pre-lift spelled inline.
//!
//! Other `crate::repo` helpers ([`crate::repo::read_text_sync`],
//! [`crate::repo::require_existing_path_at`], …) sit on the filesystem
//! frontier; this primitive sits on the git-toolchain frontier and does
//! not touch the filesystem past what [`crate::git::get_repo_root`]
//! already probes.

use anyhow::{anyhow, Context, Result};
use std::path::PathBuf;

/// The [`anyhow::Context`] label attached to the discovery failure —
/// the pre-lift verbatim message every caller wrapped
/// [`crate::git::get_repo_root`] with.
///
/// Constant-lifted so the byte-oracle tests, the caller-shield
/// remediation prose, and every consumer reference the same source of
/// truth: a future adjustment (e.g. adding an `is inside a git repo?`
/// hint tail) happens in exactly one place.
pub const REPO_ROOT_DISCOVERY_FAILED_CONTEXT: &str = "Failed to find git repository";

/// The bail-message rendered when the discovered
/// [`std::path::PathBuf`] carries a non-UTF-8 byte sequence.
///
/// A repo checked out under a directory whose absolute-path bytes are
/// not valid UTF-8 (a foreign-locale filesystem where the working-tree
/// path contains an ISO-8859-1-encoded name) is what
/// [`std::path::Path::to_str`] rejects. The pre-lift wording — three
/// words, no path.display() interpolation — is what both sites emitted
/// verbatim; keeping it constant-lifted here preserves the byte-for-byte
/// operator-facing surface (`forge github-runner-ci` / `forge
/// comprehensive-release` failure printouts on a non-UTF-8 repo path).
pub const REPO_ROOT_NON_UTF8_BAIL_MESSAGE: &str = "Invalid repository path";

/// Fused `discovery + UTF-8 validation` for the working-tree root:
/// call [`crate::git::get_repo_root`] with the pre-lift discovery
/// [`anyhow::Context`], then coerce the resulting [`std::path::PathBuf`]
/// to an owned [`String`] via [`std::path::Path::to_str`] with the
/// pre-lift non-UTF-8 bail message on the reject branch.
///
/// Returns an owned [`String`] (not a `&str`) so the caller drops the
/// pre-lift two-line binding into one — see the module docs for the
/// lifetime-anchor rationale.
///
/// # Errors
///
/// - Discovery failure: [`crate::git::get_repo_root`] returned `Err`
///   (`REPO_ROOT` env var pointed at a non-existent path, or
///   `git rev-parse --show-toplevel` failed / this process is not
///   running inside a git working tree). The error carries the
///   [`REPO_ROOT_DISCOVERY_FAILED_CONTEXT`] label on top of the
///   underlying `git`/`io` envelope.
/// - Non-UTF-8 path: [`std::path::Path::to_str`] returned [`None`] on
///   the discovered [`std::path::PathBuf`]. The error carries the
///   [`REPO_ROOT_NON_UTF8_BAIL_MESSAGE`] literal as its root
///   [`std::fmt::Display`].
///
/// # Example
///
/// ```rust,ignore
/// let repo_root_str = crate::repo_root_utf8::get_repo_root_utf8_string()?;
/// let manifest_path = std::path::Path::new(&repo_root_str).join("deploy.yaml");
/// ```
pub fn get_repo_root_utf8_string() -> Result<String> {
    let repo_root = crate::git::get_repo_root().context(REPO_ROOT_DISCOVERY_FAILED_CONTEXT)?;
    coerce_repo_root_utf8(repo_root)
}

/// Injectable UTF-8-coercion core: takes an already-discovered
/// [`std::path::PathBuf`] and applies the pre-lift `.to_str() +
/// ok_or_else(anyhow!(REPO_ROOT_NON_UTF8_BAIL_MESSAGE))?` transformation.
///
/// The split preserves the fail-before-pass byte-oracle discipline the
/// rest of the crate rides on: the pure-function core is the byte
/// oracle (deterministic under any host repository); the
/// environment-touching wrapper ([`get_repo_root_utf8_string`]) is one
/// line above it and depends on the ambient
/// `REPO_ROOT`/`git rev-parse` outcome. Mirrors the pattern the sibling
/// [`crate::docker_installed_preflight::bail_unless_docker_installed_with_probe`]
/// byte-oracles ride on.
pub(crate) fn coerce_repo_root_utf8(repo_root: PathBuf) -> Result<String> {
    repo_root
        .to_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("{}", REPO_ROOT_NON_UTF8_BAIL_MESSAGE))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Constant pin: the discovery [`anyhow::Context`] label the
    /// byte-oracle and the caller-shield remediation reference is the
    /// pre-lift verbatim literal. A change here rotates both
    /// dependents in lockstep.
    #[test]
    fn test_repo_root_discovery_failed_context_matches_pre_lift_literal() {
        assert_eq!(
            REPO_ROOT_DISCOVERY_FAILED_CONTEXT,
            "Failed to find git repository"
        );
    }

    /// Constant pin: the non-UTF-8 bail-message literal is the pre-lift
    /// verbatim wording — three ASCII words, no `path.display()`
    /// interpolation. A change here rotates the byte-oracle and every
    /// consumer in lockstep.
    #[test]
    fn test_repo_root_non_utf8_bail_message_matches_pre_lift_literal() {
        assert_eq!(REPO_ROOT_NON_UTF8_BAIL_MESSAGE, "Invalid repository path");
    }

    /// Byte-oracle (UTF-8 branch): a valid UTF-8 [`std::path::PathBuf`]
    /// coerces to an owned [`String`] whose bytes match the input path,
    /// byte-for-byte. Exercises the happy path of
    /// [`coerce_repo_root_utf8`] without depending on the ambient
    /// [`crate::git::get_repo_root`] outcome.
    #[test]
    fn test_coerce_repo_root_utf8_valid_input_returns_owned_string() {
        let input = PathBuf::from("/home/operator/repos/pleme-io/forge");
        let got = coerce_repo_root_utf8(input).unwrap();
        assert_eq!(got, "/home/operator/repos/pleme-io/forge");
    }

    /// Byte-oracle (non-UTF-8 branch): a [`std::path::PathBuf`] built
    /// from an invalid-UTF-8 byte sequence returns the pre-lift
    /// [`REPO_ROOT_NON_UTF8_BAIL_MESSAGE`] literal as the returned
    /// [`anyhow::Error`]'s root [`std::fmt::Display`]. Uses
    /// [`std::os::unix::ffi::OsStrExt::from_bytes`] to inject the
    /// non-UTF-8 payload — a Unix-target-only path this crate already
    /// carries elsewhere ([`crate::probe_outcome`]).
    #[test]
    #[cfg(unix)]
    fn test_coerce_repo_root_utf8_invalid_utf8_emits_pre_lift_bail_message() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        // 0xFF is not a valid UTF-8 leading byte, so `Path::to_str`
        // must reject the resulting [`OsStr`] — matching a
        // foreign-locale checkout whose absolute-path bytes are not
        // valid UTF-8.
        let invalid: OsString = OsStringExt::from_vec(vec![b'/', 0xFF, b'r']);
        let path = PathBuf::from(invalid);
        let err = coerce_repo_root_utf8(path).unwrap_err();
        assert_eq!(err.to_string(), "Invalid repository path");
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` may spell either raw pre-lift literal
    /// (`Failed to find git repository`, `Invalid repository path`)
    /// inline any more. The two pre-lift sites migrated; any future
    /// consumer that wants the same discovery + UTF-8-coerce fusion
    /// reaches for [`get_repo_root_utf8_string`] on first grep, not by
    /// copy-pasting the raw literals from an existing module.
    ///
    /// Reconstructed at test time via [`format!`] so this shield's own
    /// source text does not false-match itself; comment lines (`//`,
    /// `//!`) are skipped so a future module that quotes the pre-lift
    /// literals as historical prose does not trip the shield.
    #[test]
    fn no_command_module_still_spells_raw_repo_root_utf8_prelift_literals() {
        let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let commands_dir = src_dir.join("commands");
        let forbidden_context = format!("\"{}\"", "Failed to find git repository");
        let forbidden_bail = format!("\"{}\"", "Invalid repository path");
        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            for (idx, line) in source.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue;
                }
                if line.contains(&forbidden_context) || line.contains(&forbidden_bail) {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `\"Failed to find git repository\"` / `\"Invalid repository path\"` \
             literal(s) survive under `commands/` — route each through \
             `crate::repo_root_utf8::get_repo_root_utf8_string()` instead \
             (returns `Result<String>` with the fleet-standard error grammar \
             on both discovery and UTF-8-coerce failure branches):\n{:#?}",
            offenders
        );
    }

    /// Caller shield (positive half): the two pre-lift modules
    /// (`commands/github_runner_ci.rs`, `commands/comprehensive_release.rs`)
    /// MUST each forward through [`get_repo_root_utf8_string`] at least
    /// once, so a migration that dropped a call site outright leaves
    /// the negative "no raw literals" scan trivially satisfied by
    /// absence but the positive count still fails. Mirrors the sibling
    /// `every_prelift_module_forwards_through_*` shields the crate
    /// carries against every other typed primitive.
    #[test]
    fn every_prelift_module_forwards_through_get_repo_root_utf8_string() {
        let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let expectations: &[(&str, usize)] = &[
            ("commands/github_runner_ci.rs", 1),
            ("commands/comprehensive_release.rs", 1),
        ];
        let needle = "get_repo_root_utf8_string(";
        for (rel, min_count) in expectations {
            let path = src_dir.join(rel);
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{rel} must forward at least {min_count} discovery + UTF-8-coerce \
                 site(s) through `crate::repo_root_utf8::{needle}); found \
                 {forwards}. A dropped call would leave the negative raw-literal \
                 scan satisfied by absence.",
            );
        }
    }
}
