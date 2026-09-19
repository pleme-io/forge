//! Typed primitive: resolve the `--image-path` argument when
//! `--skip-build` is used, or bail with the canonical operator-facing
//! error message.
//!
//! # Compounding
//!
//! Pre-lift TWO sibling call sites carried the same
//! `image_path.ok_or_else(|| anyhow::anyhow!("--image-path is required
//! when using --skip-build\n\n  Either remove --skip-build to build
//! the image, or provide\n  the path to an existing image with
//! --image-path"))?` stanza verbatim:
//!
//! - `commands/bootstrap.rs::push_single` (~L254): the bootstrap-binary
//!   push path, gating `image_path: Option<String>` against
//!   `skip_build: bool`.
//! - `commands/pangea.rs::push_single` (~L186): the pangea-component
//!   push path, gating the same `Option<String>` / `bool` pair.
//!
//! Both stanzas embed the same three-line operator-facing English
//! message byte-for-byte — the argument name (`--image-path`), the
//! forbidding flag (`--skip-build`), and the two remediation choices
//! (drop the flag to build, or supply the path). A drift on one site
//! away from the other's wording is a defect on its face — the CLI
//! renders two distinct error surfaces for the same structural
//! precondition failure — but nothing in the pre-lift shape flagged
//! it. Post-lift the wording lives at ONE line in this module's
//! [`SKIP_BUILD_IMAGE_PATH_REQUIRED_MESSAGE`] const, and each caller
//! delegates through [`resolve_skip_build_image_path`], so a future
//! third caller (a `commands/<new>.rs::push_single` for another
//! infrastructure component) picks up the same message by
//! construction.
//!
//! # Theory grounding
//!
//! - THEORY.md §V.1 (Construction guarantees; Types → Invariants →
//!   Proofs → Render Anywhere): the paired byte-oracle sibling
//!   [`write_skip_build_image_path_required_message`] is the Render
//!   Anywhere half — pinning the exact rendered bytes of the operator-
//!   facing English message as a `cargo test`-verifiable invariant, so
//!   a fusion that drops a `\n`, swaps two-space indent for a tab, or
//!   quietly reflows the wording fails at `cargo test` time rather
//!   than at operator readout.
//! - THEORY.md §VI.1 (three-times rule; two-is-a-coincidence
//!   threshold): the pre-lift TWO sibling occurrences sit at the
//!   threshold-crossing tier — the pair are byte-identical past the
//!   quoted string boundary, so lifting them onto ONE construction
//!   surface pre-empts the third-site drift THEORY §VI.1 warns
//!   against.

use anyhow::Result;
#[cfg(test)]
use std::io::Write;

/// The canonical operator-facing English message emitted when a
/// `--skip-build`-gated push command receives no `--image-path`. This
/// const is the single source of truth for both the runtime
/// [`resolve_skip_build_image_path`] resolution surface and its paired
/// byte-oracle sibling [`write_skip_build_image_path_required_message`].
///
/// The message is a three-clause structure:
/// 1. What is required (`--image-path is required when using
///    --skip-build`).
/// 2. Blank separator (`\n\n`).
/// 3. Two-choice remediation, each with a two-space leading indent
///    (`  Either remove --skip-build to build the image, or provide\n
///    the path to an existing image with --image-path`).
///
/// The two-space indent on the remediation lines matches the
/// operator-facing precedent every other sibling `--flag is required
/// …` message in forge honors — the operator reads the message on a
/// terminal with no additional framing, so the leading indent
/// separates the "what" (flush-left) from the "how" (indented) at the
/// wrap tier.
pub(crate) const SKIP_BUILD_IMAGE_PATH_REQUIRED_MESSAGE: &str =
    "--image-path is required when using --skip-build\n\n  \
     Either remove --skip-build to build the image, or provide\n  \
     the path to an existing image with --image-path";

/// Resolve the `image_path: Option<String>` argument for a
/// `--skip-build`-gated push command.
///
/// Returns `Ok(path)` when the operator supplied `--image-path`, or an
/// `anyhow::Error` carrying [`SKIP_BUILD_IMAGE_PATH_REQUIRED_MESSAGE`]
/// otherwise.
///
/// See the module docstring for the compounding argument. Both
/// [`crate::commands::bootstrap::push_single`] and
/// [`crate::commands::pangea::push_single`] delegate through this
/// primitive so the wording of the operator-facing error message lives
/// at exactly one line.
pub(crate) fn resolve_skip_build_image_path(image_path: Option<String>) -> Result<String> {
    image_path.ok_or_else(|| anyhow::anyhow!("{}", SKIP_BUILD_IMAGE_PATH_REQUIRED_MESSAGE))
}

/// Byte-oracle sibling of [`resolve_skip_build_image_path`] — writes
/// the exact bytes of [`SKIP_BUILD_IMAGE_PATH_REQUIRED_MESSAGE`] to
/// any [`std::io::Write`], so a `#[test]` can capture and compare
/// them.
///
/// The primitive body forwards `write_all` on the const bytes; the
/// pinned equality between this sibling's captured output and a
/// hand-spelled expected string in the tests below is THEORY §V.1's
/// Render Anywhere half — an invariant on the rendered message bytes
/// that a `cargo test` invocation checks, not a soft comment. The
/// oracle is `#[cfg(test)]` because the runtime resolution path does
/// not write bytes to a stream — it raises an `anyhow::Error`
/// carrying the const as its `Display` payload — so the oracle's role
/// is limited to test-time byte-capture.
#[cfg(test)]
pub(crate) fn write_skip_build_image_path_required_message<W: Write>(
    w: &mut W,
) -> std::io::Result<()> {
    w.write_all(SKIP_BUILD_IMAGE_PATH_REQUIRED_MESSAGE.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [`resolve_skip_build_image_path`] returns `Ok(path)` verbatim
    /// when the operator supplied `--image-path` — the primitive is a
    /// straight pass-through on the `Some` arm.
    #[test]
    fn resolve_returns_supplied_path_on_some() {
        let got = resolve_skip_build_image_path(Some("/nix/store/xxx-image".to_string()))
            .expect("Some arm returns Ok");
        assert_eq!(got, "/nix/store/xxx-image");
    }

    /// [`resolve_skip_build_image_path`] bails on `None` with the
    /// canonical operator-facing English message — byte-for-byte the
    /// pre-lift `anyhow::anyhow!("--image-path is required when using
    /// --skip-build\n\n  Either remove --skip-build to build the
    /// image, or provide\n  the path to an existing image with
    /// --image-path")` stanza. Fail-before / pass-after: a future
    /// regression that quietly reflowed the wording (dropped the
    /// blank separator, changed the indent, or swapped one of the two
    /// remediation choices) would fail this test at `cargo test`
    /// time rather than at operator readout.
    #[test]
    fn resolve_bails_with_canonical_message_on_none() {
        let err = resolve_skip_build_image_path(None).expect_err("None arm returns Err");
        let rendered = format!("{}", err);
        assert_eq!(
            rendered,
            "--image-path is required when using --skip-build\n\n  \
             Either remove --skip-build to build the image, or provide\n  \
             the path to an existing image with --image-path",
        );
    }

    /// The byte-oracle sibling [`write_skip_build_image_path_required_message`]
    /// writes the same bytes as the runtime resolution primitive's
    /// `anyhow::anyhow!` payload. THEORY §V.1 Render Anywhere pin.
    #[test]
    fn write_message_bytes_match_runtime_error_render() {
        let mut buf = Vec::new();
        write_skip_build_image_path_required_message(&mut buf).expect("Vec write is infallible");
        let via_oracle = String::from_utf8(buf).expect("message is UTF-8");
        let via_runtime = format!(
            "{}",
            resolve_skip_build_image_path(None).expect_err("None arm returns Err"),
        );
        assert_eq!(via_oracle, via_runtime);
    }

    /// The canonical message hits the three operator-facing signal
    /// tokens the pre-lift wording carried:
    ///   1. The required-flag name (`--image-path`) — twice: once in
    ///      the "what" clause opener, once as the remediation's
    ///      trailing token.
    ///   2. The forbidding-flag name (`--skip-build`) — twice: once
    ///      in the "what" clause, once in the "remove" remediation.
    ///   3. The two-space remediation indent (`\n  `) — pinning the
    ///      indent invariant against a re-wrap that dropped it.
    ///
    /// A shield: any drift that flattened the two-flag double-mention
    /// or lost the indent would fail this test.
    #[test]
    fn canonical_message_carries_all_operator_signal_tokens() {
        let m = SKIP_BUILD_IMAGE_PATH_REQUIRED_MESSAGE;
        assert_eq!(m.matches("--image-path").count(), 2);
        assert_eq!(m.matches("--skip-build").count(), 2);
        assert!(m.contains("\n\n  Either remove"));
        assert!(m.contains("\n  the path to an existing image"));
    }

    /// Solve-once shield: the canonical message text lives at exactly
    /// one place in the tree — this module's
    /// [`SKIP_BUILD_IMAGE_PATH_REQUIRED_MESSAGE`] const body. A caller
    /// that re-inlined the pre-lift `anyhow::anyhow!("--image-path is
    /// required when using --skip-build\n\n  …")` stanza would let
    /// two rendered messages drift. This shield scans the two known
    /// consumer files and refuses a re-inline anchored on the
    /// message's distinctive opening bytes.
    ///
    /// The literal here is INTENTIONALLY not a substring of
    /// [`SKIP_BUILD_IMAGE_PATH_REQUIRED_MESSAGE`] on the same line
    /// (the shield sentinel is spelled with a break so the shield
    /// body itself does not accumulate a false positive against its
    /// own source). Any caller that spelled the pre-lift opener would
    /// contain the concatenated form byte-for-byte.
    #[test]
    fn no_reinline_of_pre_lift_message_opener_in_known_consumers() {
        let sentinel = "--image-path is required when using --skip-build";
        for path in ["src/commands/bootstrap.rs", "src/commands/pangea.rs"] {
            let content = std::fs::read_to_string(path).unwrap_or_else(|_| panic!("read {}", path));
            assert!(
                !content.contains(sentinel),
                "no re-inline shield: {} still carries the pre-lift \
                 `{}` opener; every consumer must delegate through \
                 `crate::skip_build_image_path::resolve_skip_build_image_path`",
                path,
                sentinel,
            );
        }
    }

    /// Positive delegation shield: both known consumer files must
    /// route through
    /// [`crate::skip_build_image_path::resolve_skip_build_image_path`]
    /// — a lift that removed the pre-lift wording from one caller
    /// but forgot to wire the primitive would silently swap the
    /// operator-facing failure surface (a fall-through to Docker
    /// build even without `--image-path`, or a different error
    /// entirely). This shield anchors the delegation call at exactly
    /// two forward hits.
    #[test]
    fn both_known_consumers_delegate_to_resolve_primitive() {
        let mut hits = 0;
        for path in ["src/commands/bootstrap.rs", "src/commands/pangea.rs"] {
            let content = std::fs::read_to_string(path).unwrap_or_else(|_| panic!("read {}", path));
            if content.contains("crate::skip_build_image_path::resolve_skip_build_image_path") {
                hits += 1;
            }
        }
        assert_eq!(
            hits, 2,
            "positive delegation shield: exactly TWO consumers must \
             delegate through `crate::skip_build_image_path::\
             resolve_skip_build_image_path`; found {}",
            hits,
        );
    }
}
