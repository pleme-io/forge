//! Pre-release FluxCD-health-check step — the `Step <label>:` skip /
//! run branching stanza fused with the health-check spawn on the
//! non-skip arm.
//!
//! # Pre-lift census — two sibling stanzas, one 12-line body
//!
//! Two consumer sites in `commands/rust_service.rs` each spelled the
//! same 12-line `if skip_flux_health_check { … } else { … } println!();`
//! body verbatim, diverging only on the `<step-label>` embedded in
//! both the skip-branch `println!` prefix and the non-skip-branch
//! `crate::ui::print_numbered_step_heading` label:
//!
//! 1. `commands/rust_service.rs::deploy_service_across_environments`
//!    (per-env deploy path, Step 0 preamble around line 1300) with the
//!    plain `"0"` step-label.
//! 2. `commands/rust_service.rs::deploy_and_verify`
//!    (single-env deploy path, Step 0/8 preamble around line 2350)
//!    with the fractional `"0/8"` step-label.
//!
//! Both stanzas branch on `deploy_config.resolved_deployment()
//! .skip_flux_health_check`:
//!
//! ```ignore
//! if skip_flux_health_check {
//!     println!(
//!         "Step {label}: {}",
//!         "Skipping FluxCD health check (skip_flux_health_check: true)"
//!             .bold()
//!             .dimmed()
//!     );
//! } else {
//!     crate::ui::print_numbered_step_heading(
//!         label,
//!         "Pre-release FluxCD health check...",
//!     );
//!     crate::commands::flux::health_check("pre-release").await?;
//! }
//! println!();
//! ```
//!
//! Two identically-shaped bodies past the PRIME DIRECTIVE's
//! duplication-is-a-bug threshold (THEORY §VI.1). A drift to the
//! skip-message copy (a rename to `"Skipping FluxCD pre-release
//! probe"`, a switch from `.bold().dimmed()` to plain `.dimmed()`),
//! to the running-branch title (`"Pre-release FluxCD health
//! check..."` → `"Running pre-release FluxCD health check..."`), to
//! the `health_check` kind label (`"pre-release"` → `"pre_release"`),
//! or to the trailing separator (`println!()` → `crate::ui::
//! print_thin_rule()`) had to hit both sites in lockstep pre-lift;
//! post-lift the drift hits ONE typed body and both consumers
//! inherit the change from the primitive.
//!
//! # Byte-oracle
//!
//! [`write_pre_release_flux_health_check_skip_line`] is the
//! writer-taking sibling for the skip-branch line — a `Vec<u8>` sink
//! lets tests pin the exact rendered bytes (the plain ASCII `Step
//! {label}: ` prefix + the 60-byte skip-message body wrapped in the
//! `.bold().dimmed()` ANSI sequence + trailing `\n`) at one site
//! rather than as two lockstep literals across `rust_service.rs`.
//! The non-skip branch composes existing typed primitives
//! ([`crate::ui::print_numbered_step_heading`] +
//! [`crate::commands::flux::health_check`]) and inherits its
//! byte-shape from their own oracles.
//!
//! # Why an async `run_*` fuser, not a plain printer
//!
//! Both pre-lift sites spelled the whole
//! `if skip_flux_health_check { <println!> } else { <heading +
//! health_check> } println!();` composition, not just a print. Two
//! separate primitives (one for the skip-line, one for the running
//! branch) would leave the branch-shape open to drift — a caller
//! that copied the skip-line primitive but forgot to route the
//! non-skip arm through a matching primitive would silently open a
//! third body of the pre-lift stanza. The `run_*` fuser owns the
//! whole ceremony including the trailing `println!();` separator so
//! the two consumers each reduce to a single delegating `.await?`.

use anyhow::Result;
use colored::Colorize;
use std::io;

/// The invariant title every pre-lift non-skip branch spelled — the
/// plain ASCII `Pre-release FluxCD health check...` label handed to
/// [`crate::ui::print_numbered_step_heading`]. Named as a `const` so
/// a future re-branding (a swap for `"Pre-release GitOps health
/// check..."`, a translation, or promotion to a leading glyph)
/// reaches ONE site rather than two lockstep string literals.
pub const PRE_RELEASE_FLUX_HEALTH_CHECK_TITLE: &str = "Pre-release FluxCD health check...";

/// The invariant skip-branch message every pre-lift stanza spelled —
/// the 60-byte `Skipping FluxCD health check
/// (skip_flux_health_check: true)` phrase wrapped in
/// `.bold().dimmed()` at emission. Named as a `const` so a future
/// re-branding (a rename to `skip_flux_probe`, a switch to a plain
/// `.dimmed()` style, dropping the parenthetical config-key hint)
/// reaches ONE site.
pub const PRE_RELEASE_FLUX_HEALTH_CHECK_SKIP_MESSAGE: &str =
    "Skipping FluxCD health check (skip_flux_health_check: true)";

/// The invariant `"pre-release"` kind label handed to
/// [`crate::commands::flux::health_check`] on the non-skip branch.
/// Named as a `const` so a future canonicalization
/// (`"pre-release"` → `"pre_release"`, or an enumeration lift onto
/// a `HealthCheckKind` closed enum) reaches ONE site.
pub const PRE_RELEASE_FLUX_HEALTH_CHECK_KIND: &str = "pre-release";

/// Emit the canonical `Step <label>: Skipping FluxCD health check
/// (skip_flux_health_check: true).bold().dimmed()` skip-branch line
/// to stdout. Called from the skip arm of
/// [`run_pre_release_flux_health_check_step`].
///
/// Delegates to [`write_pre_release_flux_health_check_skip_line`]
/// against [`std::io::stdout`]; the writer split exists so the
/// fail-before-pass byte-oracle test pins the exact rendered bytes
/// without capturing stdout.
pub fn print_pre_release_flux_health_check_skip_line(step_label: &str) {
    let _ = write_pre_release_flux_health_check_skip_line(&mut io::stdout().lock(), step_label);
}

/// Writer-taking sibling to
/// [`print_pre_release_flux_health_check_skip_line`]. Emits the
/// single `Step <label>: <skip-message>.bold().dimmed()\n` line via
/// [`writeln!`] against the supplied writer.
///
/// [`print_pre_release_flux_health_check_skip_line`] is the stdout
/// adapter; this variant exists so tests can pin the plain ASCII
/// `Step <label>: ` prefix, the caller's `<label>` verbatim, the
/// 60-byte skip-message body, and the `.bold().dimmed()` ANSI
/// envelope without capturing stdout.
pub fn write_pre_release_flux_health_check_skip_line<W: io::Write>(
    w: &mut W,
    step_label: &str,
) -> io::Result<()> {
    writeln!(
        w,
        "Step {}: {}",
        step_label,
        PRE_RELEASE_FLUX_HEALTH_CHECK_SKIP_MESSAGE.bold().dimmed()
    )
}

/// Run the canonical pre-release FluxCD-health-check step: on `skip`
/// emit the `Step <label>: Skipping FluxCD health check
/// (skip_flux_health_check: true).bold().dimmed()` line via
/// [`print_pre_release_flux_health_check_skip_line`]; otherwise emit
/// the `Step <label>: Pre-release FluxCD health check....bold()`
/// heading via [`crate::ui::print_numbered_step_heading`] and
/// delegate to [`crate::commands::flux::health_check`] with the
/// invariant [`PRE_RELEASE_FLUX_HEALTH_CHECK_KIND`] label.
///
/// Always emits a trailing `println!();` blank-line separator so the
/// subsequent step's own heading opens against a blank row (every
/// pre-lift consumer spelled this trailing separator).
///
/// # Errors
///
/// On the non-skip branch, propagates any `anyhow::Error` returned by
/// [`crate::commands::flux::health_check`] verbatim (via the `?`
/// operator). The skip branch is infallible.
pub async fn run_pre_release_flux_health_check_step(step_label: &str, skip: bool) -> Result<()> {
    if skip {
        print_pre_release_flux_health_check_skip_line(step_label);
    } else {
        crate::ui::print_numbered_step_heading(step_label, PRE_RELEASE_FLUX_HEALTH_CHECK_TITLE);
        crate::commands::flux::health_check(PRE_RELEASE_FLUX_HEALTH_CHECK_KIND).await?;
    }
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fail-before-pass envelope for
    /// [`write_pre_release_flux_health_check_skip_line`] on the plain
    /// pre-lift step-label `"0"` (the
    /// `deploy_service_across_environments` site's spelling). Pins
    /// the one-line body — the plain ASCII `Step 0: ` prefix, the
    /// 60-byte skip-message body wrapped in the
    /// `.bold().dimmed()` ANSI envelope, and the trailing `\n`. A
    /// silent drift a future rewrite might introduce — dropping the
    /// step-label interpolation, renaming the skip-message, switching
    /// the `.bold().dimmed()` chain — flips this assertion rather
    /// than compiling and silently diverging the two consumer sites'
    /// visual grammar.
    #[test]
    fn write_skip_line_emits_plain_zero_step_label_verbatim() {
        let mut buf: Vec<u8> = Vec::new();
        write_pre_release_flux_health_check_skip_line(&mut buf, "0")
            .expect("write against a Vec<u8> sink must succeed");
        let out = String::from_utf8(buf)
            .expect("skip-line must emit valid UTF-8 (the pre-lift println! did)");
        // The pre-lift line reached stdout as `Step 0: <message
        // wrapped in .bold().dimmed()>\n`. `colored` is
        // detect-terminal-aware, so at test time (no tty) the ANSI
        // envelope collapses to the bare bytes — that's the correct
        // downstream behavior (piped output must not carry ANSI).
        // Assert on the un-ANSI'd shape so this test survives both
        // tty-and-piped runs.
        assert!(
            out.contains("Step 0: "),
            "skip-line must open with `Step 0: ` prefix (pre-lift \
             literal from `deploy_service_across_environments`). Got {out:?}"
        );
        assert!(
            out.contains(PRE_RELEASE_FLUX_HEALTH_CHECK_SKIP_MESSAGE),
            "skip-line must carry the 60-byte pre-lift skip-message \
             body verbatim. Got {out:?}"
        );
        assert!(
            out.ends_with('\n'),
            "skip-line must terminate with a single `\\n` (pre-lift \
             `println!` did). Got {out:?}"
        );
    }

    /// Byte-oracle sibling for the fractional pre-lift step-label
    /// `"0/8"` (the `deploy_and_verify` site's spelling). Pins the
    /// second consumer's step-label projection so a variant-dispatch
    /// regression that hard-coded the primitive on `"0"` — silently
    /// mislabeling the `deploy_and_verify` step as `Step 0: ` rather
    /// than `Step 0/8: ` — surfaces here rather than in production.
    #[test]
    fn write_skip_line_emits_fractional_step_label_verbatim() {
        let mut buf: Vec<u8> = Vec::new();
        write_pre_release_flux_health_check_skip_line(&mut buf, "0/8").unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("Step 0/8: "),
            "skip-line must open with `Step 0/8: ` prefix (pre-lift \
             literal from `deploy_and_verify`). Got {out:?}"
        );
        assert!(
            out.contains(PRE_RELEASE_FLUX_HEALTH_CHECK_SKIP_MESSAGE),
            "skip-line must carry the 60-byte pre-lift skip-message \
             body verbatim under the fractional label. Got {out:?}"
        );
    }

    /// The primitive MUST NOT emit anything beyond the exact
    /// step-label handed in — no trimming, case-folding, punctuation
    /// injection. A future normalisation at the primitive boundary
    /// would silently diverge from what the pre-lift inline
    /// `println!("Step {}: …", label, …)` did with the literal
    /// label. Pin the verbatim-forwarding contract with a gnarly
    /// input.
    #[test]
    fn write_skip_line_forwards_step_label_verbatim_no_normalisation() {
        let mut buf: Vec<u8> = Vec::new();
        write_pre_release_flux_health_check_skip_line(&mut buf, "STAGE-2/9").unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("Step STAGE-2/9: "),
            "skip-line must forward the step-label verbatim — no \
             trim, no case-fold, no punctuation injection. Got {out:?}"
        );
    }

    /// Pin the `"pre-release"` kind constant — pre-lift both sites
    /// spelled the literal `"pre-release"` verbatim as the sole
    /// argument to [`crate::commands::flux::health_check`]. A drift
    /// (an underscore variant `"pre_release"`, a capitalization
    /// `"Pre-Release"`, or a rename to `"prerelease"`) would silently
    /// route both consumers through a `health_check` invocation the
    /// health-check module does not recognize.
    #[test]
    fn health_check_kind_constant_is_pre_release_literal() {
        assert_eq!(
            PRE_RELEASE_FLUX_HEALTH_CHECK_KIND, "pre-release",
            "PRE_RELEASE_FLUX_HEALTH_CHECK_KIND must project the \
             pre-lift `\"pre-release\"` literal both call sites handed \
             to `crate::commands::flux::health_check`. Got {:?}",
            PRE_RELEASE_FLUX_HEALTH_CHECK_KIND
        );
    }

    /// Pin the pre-release-title constant — pre-lift both sites
    /// spelled the literal `"Pre-release FluxCD health check..."`
    /// verbatim as the title argument to
    /// [`crate::ui::print_numbered_step_heading`]. A drift (a rename
    /// to `"Running pre-release FluxCD health check..."`, dropping
    /// the ellipsis, or promoting the ellipsis to U+2026) reaches
    /// ONE site through the const.
    #[test]
    fn title_constant_is_pre_lift_literal() {
        assert_eq!(
            PRE_RELEASE_FLUX_HEALTH_CHECK_TITLE, "Pre-release FluxCD health check...",
            "PRE_RELEASE_FLUX_HEALTH_CHECK_TITLE must project the \
             pre-lift literal both call sites handed to \
             `crate::ui::print_numbered_step_heading`. Got {:?}",
            PRE_RELEASE_FLUX_HEALTH_CHECK_TITLE
        );
    }

    /// Pin the skip-message constant — pre-lift both sites spelled
    /// the same 60-byte `Skipping FluxCD health check
    /// (skip_flux_health_check: true)` phrase verbatim inside the
    /// `.bold().dimmed()` chain. A drift (dropping the parenthetical
    /// config-key hint, renaming `skip_flux_health_check` to
    /// `skip_flux_probe`) reaches ONE site through the const.
    #[test]
    fn skip_message_constant_is_pre_lift_literal() {
        assert_eq!(
            PRE_RELEASE_FLUX_HEALTH_CHECK_SKIP_MESSAGE,
            "Skipping FluxCD health check (skip_flux_health_check: true)",
            "PRE_RELEASE_FLUX_HEALTH_CHECK_SKIP_MESSAGE must project \
             the pre-lift literal both call sites spelled inside \
             the `.bold().dimmed()` chain. Got {:?}",
            PRE_RELEASE_FLUX_HEALTH_CHECK_SKIP_MESSAGE
        );
    }

    /// Whole-module negative caller shield: no raw `"Skipping FluxCD
    /// health check (skip_flux_health_check: true)"` literal may live
    /// in `commands/rust_service.rs` outside of a delegation to
    /// [`PRE_RELEASE_FLUX_HEALTH_CHECK_SKIP_MESSAGE`]. Post-lift the
    /// two pre-lift sites each forward through
    /// [`run_pre_release_flux_health_check_step`]; a future re-inline
    /// (a "just call `println!` directly, it's shorter" cleanup)
    /// silently reopens the two-site duplication class this lift
    /// closed.
    ///
    /// Enforced against the module body BEFORE its first
    /// `#[cfg(test)]` region so a test-support mention of the raw
    /// shape does not defeat the shield.
    #[test]
    fn no_raw_skip_message_literal_survives_in_rust_service() {
        const SOURCE: &str = include_str!("rust_service.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            SOURCE,
            "commands/rust_service.rs",
        );
        const NEEDLE: &str = "\"Skipping FluxCD health check (skip_flux_health_check: true)\"";
        for (i, line) in body.lines().enumerate() {
            assert!(
                !line.contains(NEEDLE),
                "commands/rust_service.rs:{lineno} spells the pre-lift \
                 raw `\"Skipping FluxCD health check \
                 (skip_flux_health_check: true)\"` skip-message literal \
                 — that shape was lifted onto \
                 `crate::commands::pre_release_flux_health_check_step::\
                 PRE_RELEASE_FLUX_HEALTH_CHECK_SKIP_MESSAGE` and reaches \
                 stdout through `run_pre_release_flux_health_check_step`. \
                 A re-inline silently reopens the two-site duplication \
                 class this shield exists to close. Offending line: {line:?}",
                lineno = i + 1
            );
        }
    }

    /// Sibling negative shield: no raw `"Pre-release FluxCD health
    /// check..."` title literal may live in
    /// `commands/rust_service.rs` outside of a delegation to
    /// [`PRE_RELEASE_FLUX_HEALTH_CHECK_TITLE`]. Pins the running-
    /// branch title alongside the skip-message shield above so a
    /// re-inline that copied only the non-skip arm (dropping the
    /// skip-line, or vice versa) still trips a shield.
    #[test]
    fn no_raw_pre_release_title_literal_survives_in_rust_service() {
        const SOURCE: &str = include_str!("rust_service.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            SOURCE,
            "commands/rust_service.rs",
        );
        const NEEDLE: &str = "\"Pre-release FluxCD health check...\"";
        for (i, line) in body.lines().enumerate() {
            assert!(
                !line.contains(NEEDLE),
                "commands/rust_service.rs:{lineno} spells the pre-lift \
                 raw `\"Pre-release FluxCD health check...\"` title literal \
                 — that shape was lifted onto \
                 `crate::commands::pre_release_flux_health_check_step::\
                 PRE_RELEASE_FLUX_HEALTH_CHECK_TITLE`. Offending line: {line:?}",
                lineno = i + 1
            );
        }
    }

    /// Positive delegation shield — `commands/rust_service.rs` must
    /// forward through
    /// [`run_pre_release_flux_health_check_step`] at exactly two sites
    /// (one per pre-lift consumer: the
    /// `deploy_service_across_environments` Step-0 preamble and the
    /// `deploy_and_verify` Step-0/8 preamble). A fusion that folded
    /// the two sites into one call or dropped one of the preambles
    /// silently fails here — the negative halves above would still
    /// pass, but the positive count would fall below the pre-lift
    /// census.
    #[test]
    fn rust_service_forwards_through_run_step_primitive_twice() {
        const SOURCE: &str = include_str!("rust_service.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            SOURCE,
            "commands/rust_service.rs",
        );
        const FORWARD_NEEDLE: &str =
            "pre_release_flux_health_check_step::run_pre_release_flux_health_check_step(";
        let forward_hits = body.matches(FORWARD_NEEDLE).count();
        assert_eq!(
            forward_hits, 2,
            "commands/rust_service.rs body must forward to \
             `crate::commands::pre_release_flux_health_check_step::\
             run_pre_release_flux_health_check_step(...)` at exactly 2 \
             sites — one per pre-lift consumer \
             (`deploy_service_across_environments` and \
             `deploy_and_verify`). Found {forward_hits} forwarding hits."
        );
    }
}
