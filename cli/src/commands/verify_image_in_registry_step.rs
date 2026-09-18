//! Verify-image-in-registry step — the two-line
//! `print_numbered_step_heading(<label>, "Verifying image in
//! registry...") + verify_image_in_registry(&registry, <tag>).await? +
//! println!("   📋 Captured digest: {}", pushed_digest)` ceremony that
//! opens the post-push registry-side digest capture on both the
//! push-only and the deploy-and-verify entry paths.
//!
//! # Pre-lift census — two sibling stanzas, one 3-line body
//!
//! Two consumer sites in `commands/rust_service.rs` each spelled the
//! same 3-line body verbatim, diverging on:
//!
//! 1. `commands/rust_service.rs::execute` (push / push-only path,
//!    Step 1.5 preamble around line 1401) with the plain `"1.5"`
//!    step-label and a `verify_tag: String` (`deploy_tag.clone()`)
//!    receiver bind on the returned digest.
//! 2. `commands/rust_service.rs::deploy_and_verify` (single-env
//!    deploy path, Step 2.5/9 preamble around line 2381) with the
//!    fractional `"2.5/9"` step-label and a `deploy_tag: &str`
//!    receiver bind.
//!
//! Both stanzas open the registry-side digest capture with the same
//! shape:
//!
//! ```ignore
//! crate::ui::print_numbered_step_heading(<label>, "Verifying image in registry...");
//! let pushed_digest = verify_image_in_registry(&registry, <tag>).await?;
//! println!("   📋 Captured digest: {}", pushed_digest);
//! ```
//!
//! and both feed the returned `pushed_digest` into a matching
//! `verify_image_digest_matches(&registry, <tag>, &pushed_digest).await?`
//! guard downstream (execute :1427; deploy_and_verify :2411). Two
//! identically-shaped bodies past the PRIME DIRECTIVE's
//! duplication-is-a-bug threshold (THEORY §VI.1). A drift to the
//! title copy (a rename to `"Verifying image digest..."`, dropping
//! the ellipsis, promoting it to U+2026), to the captured-digest ack
//! prefix (a swap for `"   🔒 Captured digest: "`, dropping the
//! three-space indent, or promoting the emoji glyph), or to the
//! shape of the `verify_image_in_registry` handoff had to hit both
//! sites in lockstep pre-lift; post-lift the drift hits ONE typed
//! body and both consumers inherit the change from the primitive.
//!
//! # Byte-oracle
//!
//! [`write_captured_digest_ack_line`] is the writer-taking sibling
//! for the captured-digest ack line — a `Vec<u8>` sink lets tests
//! pin the exact rendered bytes (the plain ASCII
//! `   📋 Captured digest: ` prefix + the caller's digest verbatim +
//! trailing `\n`) at one site rather than as two lockstep literals
//! across `rust_service.rs`. The heading branch composes an existing
//! typed primitive ([`crate::ui::print_numbered_step_heading`]) and
//! inherits its byte-shape from that primitive's own oracle.
//!
//! # Why an async `run_*` fuser, not a plain printer
//!
//! Both pre-lift sites spelled the whole
//! `heading + verify + captured-ack` composition, not just a print.
//! Two separate primitives (one for the heading, one for the ack)
//! would leave the composition-shape open to drift — a caller that
//! forwarded through one but forgot the other would silently reopen
//! a partial re-inline. The `run_*` fuser owns the whole ceremony
//! including the awaited handoff to
//! [`crate::commands::rust_service::verify_image_in_registry`] so
//! the two consumers each reduce to a single delegating `.await?`
//! that both prints the ack and returns the captured digest.

use anyhow::Result;
use std::io;

/// The invariant title every pre-lift heading spelled — the plain
/// ASCII `Verifying image in registry...` label handed to
/// [`crate::ui::print_numbered_step_heading`]. Named as a `const` so
/// a future re-branding (`"Verifying image digest..."`, dropping the
/// ellipsis, promoting it to U+2026) reaches ONE site rather than
/// two lockstep string literals.
pub const VERIFY_IMAGE_IN_REGISTRY_STEP_TITLE: &str = "Verifying image in registry...";

/// The invariant captured-digest ack prefix every pre-lift `println!`
/// spelled — three ASCII spaces, the 📋 clipboard glyph, one space,
/// the plain ASCII `Captured digest: ` label. Named as a `const` so
/// a future rebranding (a swap for `"   🔒 Captured digest: "`,
/// dropping the indent, or a translation of the label) reaches ONE
/// site.
pub const CAPTURED_DIGEST_ACK_PREFIX: &str = "   📋 Captured digest: ";

/// Emit the canonical `   📋 Captured digest: <digest>\n` ack line to
/// stdout. Called from [`run_verify_image_in_registry_step`] right
/// after the awaited `verify_image_in_registry` handoff returns.
///
/// Delegates to [`write_captured_digest_ack_line`] against
/// [`std::io::stdout`]; the writer split exists so the fail-before-
/// pass byte-oracle test pins the exact rendered bytes without
/// capturing stdout.
pub fn print_captured_digest_ack_line(digest: &str) {
    let _ = write_captured_digest_ack_line(&mut io::stdout().lock(), digest);
}

/// Writer-taking sibling to [`print_captured_digest_ack_line`].
/// Emits the single `   📋 Captured digest: <digest>\n` line via
/// [`writeln!`] against the supplied writer.
///
/// [`print_captured_digest_ack_line`] is the stdout adapter; this
/// variant exists so tests can pin the plain ASCII prefix (the
/// three-space indent, the 📋 glyph, the `Captured digest: `
/// label), the caller's `<digest>` verbatim, and the trailing `\n`
/// without capturing stdout.
pub fn write_captured_digest_ack_line<W: io::Write>(w: &mut W, digest: &str) -> io::Result<()> {
    writeln!(w, "{}{}", CAPTURED_DIGEST_ACK_PREFIX, digest)
}

/// Run the canonical verify-image-in-registry step: emit the
/// `Step <label>: Verifying image in registry....bold()` heading via
/// [`crate::ui::print_numbered_step_heading`], delegate to
/// [`crate::commands::rust_service::verify_image_in_registry`] for
/// the registry-side digest capture, emit the
/// `   📋 Captured digest: <digest>` ack line via
/// [`print_captured_digest_ack_line`], and return the captured
/// digest for the caller's downstream
/// `verify_image_digest_matches` guard.
///
/// # Errors
///
/// Propagates any `anyhow::Error` returned by
/// [`crate::commands::rust_service::verify_image_in_registry`]
/// verbatim (via the `?` operator) — the caller's downstream
/// `verify_image_digest_matches` guard is only reached on the `Ok`
/// arm, matching the pre-lift `?`-forward shape.
pub async fn run_verify_image_in_registry_step(
    step_label: &str,
    registry: &str,
    tag: &str,
) -> Result<String> {
    crate::ui::print_numbered_step_heading(step_label, VERIFY_IMAGE_IN_REGISTRY_STEP_TITLE);
    let pushed_digest =
        crate::commands::rust_service::verify_image_in_registry(registry, tag).await?;
    print_captured_digest_ack_line(&pushed_digest);
    Ok(pushed_digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fail-before-pass envelope for
    /// [`write_captured_digest_ack_line`] on a canonical
    /// `sha256:…` digest — pins the one-line body: the plain ASCII
    /// `   📋 Captured digest: ` prefix (three spaces, the 📋
    /// clipboard glyph, one space, the `Captured digest: ` label),
    /// the caller's digest verbatim, and the trailing `\n`. A
    /// silent drift a future rewrite might introduce — dropping
    /// the three-space indent, swapping the emoji glyph, renaming
    /// the label — flips this assertion rather than compiling and
    /// silently diverging the two consumer sites' visual grammar.
    #[test]
    fn write_captured_digest_ack_line_emits_prefix_digest_newline() {
        let mut buf: Vec<u8> = Vec::new();
        write_captured_digest_ack_line(
            &mut buf,
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .expect("write against a Vec<u8> sink must succeed");
        let out = String::from_utf8(buf)
            .expect("ack line must emit valid UTF-8 (the pre-lift println! did)");
        assert_eq!(
            out,
            "   📋 Captured digest: sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
            "captured-digest ack line must render as the exact pre-lift \
             bytes: three-space indent, 📋 clipboard glyph, space, \
             `Captured digest: ` label, digest verbatim, trailing `\\n`. Got {out:?}"
        );
    }

    /// Second byte-oracle: forward the caller's digest verbatim
    /// through the ack line. A future rewrite that normalised the
    /// digest (a `to_lowercase`, a length-clip, a `sha256:` prefix
    /// injection) would silently diverge from the pre-lift
    /// `println!("   📋 Captured digest: {}", pushed_digest)` shape,
    /// which handed the digest verbatim from the registry probe. Pin
    /// the verbatim-forwarding contract with a non-canonical digest
    /// so a normaliser trips it.
    #[test]
    fn write_captured_digest_ack_line_forwards_digest_verbatim() {
        let mut buf: Vec<u8> = Vec::new();
        write_captured_digest_ack_line(&mut buf, "NOT-A-REAL-DIGEST/but valid bytes").unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("NOT-A-REAL-DIGEST/but valid bytes"),
            "ack line must forward the caller's digest verbatim — no \
             case-fold, no length-clip, no prefix injection. Got {out:?}"
        );
        assert!(
            out.ends_with('\n'),
            "ack line must terminate with a single trailing `\\n` \
             (pre-lift `println!` did). Got {out:?}"
        );
    }

    /// Pin the title constant — pre-lift both sites spelled the
    /// literal `"Verifying image in registry..."` verbatim as the
    /// title argument to [`crate::ui::print_numbered_step_heading`].
    /// A drift (a rename to `"Verifying image digest..."`, dropping
    /// the ellipsis, promoting it to U+2026, or adding a leading
    /// emoji) reaches ONE site through the const.
    #[test]
    fn title_constant_is_pre_lift_literal() {
        assert_eq!(
            VERIFY_IMAGE_IN_REGISTRY_STEP_TITLE, "Verifying image in registry...",
            "VERIFY_IMAGE_IN_REGISTRY_STEP_TITLE must project the \
             pre-lift literal both call sites handed to \
             `crate::ui::print_numbered_step_heading`. Got {:?}",
            VERIFY_IMAGE_IN_REGISTRY_STEP_TITLE
        );
    }

    /// Pin the ack-prefix constant — pre-lift both sites spelled the
    /// literal `"   📋 Captured digest: "` verbatim inside the
    /// `println!` template. A drift (dropping the three-space
    /// indent, swapping the 📋 glyph for 🔒 or ✅, renaming the
    /// label to `Digest`) reaches ONE site through the const.
    #[test]
    fn ack_prefix_constant_is_pre_lift_literal() {
        assert_eq!(
            CAPTURED_DIGEST_ACK_PREFIX, "   📋 Captured digest: ",
            "CAPTURED_DIGEST_ACK_PREFIX must project the pre-lift \
             literal both call sites spelled inside the `println!` \
             template. Got {:?}",
            CAPTURED_DIGEST_ACK_PREFIX
        );
    }

    /// Whole-module negative caller shield: no raw
    /// `"Verifying image in registry..."` title literal may live in
    /// `commands/rust_service.rs` outside of a delegation to
    /// [`VERIFY_IMAGE_IN_REGISTRY_STEP_TITLE`]. Post-lift the two
    /// pre-lift sites each forward through
    /// [`run_verify_image_in_registry_step`]; a future re-inline
    /// (a "just call `print_numbered_step_heading` directly, it's
    /// shorter" cleanup) silently reopens the two-site duplication
    /// class this lift closed.
    ///
    /// Enforced against the module body BEFORE its first
    /// `#[cfg(test)]` region so a test-support mention of the raw
    /// shape does not defeat the shield.
    #[test]
    fn no_raw_title_literal_survives_in_rust_service() {
        const SOURCE: &str = include_str!("rust_service.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            SOURCE,
            "commands/rust_service.rs",
        );
        const NEEDLE: &str = "\"Verifying image in registry...\"";
        for (i, line) in body.lines().enumerate() {
            assert!(
                !line.contains(NEEDLE),
                "commands/rust_service.rs:{lineno} spells the pre-lift \
                 raw `\"Verifying image in registry...\"` title literal \
                 — that shape was lifted onto \
                 `crate::commands::verify_image_in_registry_step::\
                 VERIFY_IMAGE_IN_REGISTRY_STEP_TITLE` and reaches \
                 stdout through `run_verify_image_in_registry_step`. \
                 A re-inline silently reopens the two-site duplication \
                 class this shield exists to close. Offending line: {line:?}",
                lineno = i + 1
            );
        }
    }

    /// Sibling negative shield: no raw `"   📋 Captured digest: "`
    /// ack-prefix literal may live in `commands/rust_service.rs`
    /// outside of a delegation to [`CAPTURED_DIGEST_ACK_PREFIX`].
    /// Pins the captured-digest ack line alongside the title
    /// shield above so a re-inline that copied only the heading
    /// call (dropping the ack, or vice versa) still trips a
    /// shield.
    #[test]
    fn no_raw_captured_digest_ack_literal_survives_in_rust_service() {
        const SOURCE: &str = include_str!("rust_service.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            SOURCE,
            "commands/rust_service.rs",
        );
        const NEEDLE: &str = "\"   📋 Captured digest: {}\"";
        for (i, line) in body.lines().enumerate() {
            assert!(
                !line.contains(NEEDLE),
                "commands/rust_service.rs:{lineno} spells the pre-lift \
                 raw `\"   📋 Captured digest: {{}}\"` ack-line template \
                 — that shape was lifted onto \
                 `crate::commands::verify_image_in_registry_step::\
                 write_captured_digest_ack_line` and its \
                 `CAPTURED_DIGEST_ACK_PREFIX` const. Offending line: {line:?}",
                lineno = i + 1
            );
        }
    }

    /// Positive delegation shield — `commands/rust_service.rs` must
    /// forward through [`run_verify_image_in_registry_step`] at
    /// exactly two sites (one per pre-lift consumer: the push /
    /// push-only Step 1.5 preamble in `execute` and the deploy-and-
    /// verify Step 2.5/9 preamble in `deploy_and_verify`). A fusion
    /// that folded the two sites into one call or dropped one of
    /// the preambles silently fails here — the negative halves
    /// above would still pass, but the positive count would fall
    /// below the pre-lift census.
    #[test]
    fn rust_service_forwards_through_run_step_primitive_twice() {
        const SOURCE: &str = include_str!("rust_service.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            SOURCE,
            "commands/rust_service.rs",
        );
        const FORWARD_NEEDLE: &str =
            "verify_image_in_registry_step::run_verify_image_in_registry_step(";
        let forward_hits = body.matches(FORWARD_NEEDLE).count();
        assert_eq!(
            forward_hits, 2,
            "commands/rust_service.rs body must forward to \
             `crate::commands::verify_image_in_registry_step::\
             run_verify_image_in_registry_step(...)` at exactly 2 \
             sites — one per pre-lift consumer (the push / push-only \
             Step 1.5 preamble in `execute` and the deploy-and-verify \
             Step 2.5/9 preamble in `deploy_and_verify`). Found \
             {forward_hits} forwarding hits."
        );
    }
}
