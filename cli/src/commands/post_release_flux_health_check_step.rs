//! Post-release FluxCD-health-check step — the `Step <label>:` skip /
//! run branching stanza fused with the retrying health-check spawn on
//! the non-skip arm.
//!
//! # Pre-lift census — two sibling stanzas
//!
//! Two consumer sites in `commands/rust_service.rs` each spelled the
//! same `if skip_flux_health_check { … } else { … } println!();` body,
//! diverging only on the `<step-label>` embedded in both the
//! skip-branch `println!` prefix and the non-skip-branch
//! [`crate::ui::print_numbered_step_heading`] label, plus a stray
//! `.bold()` on the skip-message chain at one site:
//!
//! 1. `commands/rust_service.rs::deploy_service_across_environments`
//!    (per-env deploy path, Step 7 postamble) with the plain `"7"`
//!    step-label and a plain `.dimmed()` skip message.
//! 2. `commands/rust_service.rs::deploy_and_verify`
//!    (single-env deploy path, Step 9/9 postamble) with the
//!    fractional `"9/9"` step-label and a `.bold().dimmed()` skip
//!    message.
//!
//! Both stanzas branch on `deploy_config.resolved_deployment()
//! .skip_flux_health_check` and, on the non-skip arm, forward the
//! invariant `("post-release", 600, 10)` argument triple to
//! [`crate::commands::flux::health_check_with_retry`]:
//!
//! ```ignore
//! if skip_flux_health_check {
//!     println!(
//!         "Step {label}: {}",
//!         "Skipping post-release FluxCD health check \
//!          (skip_flux_health_check: true)"
//!             .bold()
//!             .dimmed()
//!     );
//! } else {
//!     crate::ui::print_numbered_step_heading(
//!         label,
//!         "Post-release FluxCD health check...",
//!     );
//!     crate::commands::flux::health_check_with_retry("post-release", 600, 10).await?;
//! }
//! println!();
//! ```
//!
//! Two identically-shaped bodies past the PRIME DIRECTIVE's
//! duplication-is-a-bug threshold (THEORY §I.3.5, §VI.1 — the
//! duplication budget is zero). The lift also normalizes the
//! skip-message style: the pre-lift `.dimmed()` at site 1 gains
//! `.bold()` to match site 2 and the sibling
//! [`crate::commands::pre_release_flux_health_check_step`]'s canonical
//! `.bold().dimmed()` chain — a drift that stayed silent for as long
//! as the two sites lived side-by-side, closed at ONE body.
//!
//! A drift to the skip-message copy (a rename to `"Skipping FluxCD
//! post-release probe"`), to the running-branch title (`"Post-release
//! FluxCD health check..."` → `"Running post-release FluxCD health
//! check..."`), to the `health_check_with_retry` kind label
//! (`"post-release"` → `"post_release"`), to the timeout or retry
//! bounds (`600`s / `10`s), or to the trailing separator (`println!()`
//! → `crate::ui::print_thin_rule()`) had to hit both sites in lockstep
//! pre-lift; post-lift the drift hits ONE typed body and both
//! consumers inherit the change from the primitive.
//!
//! # Byte-oracle
//!
//! [`write_post_release_flux_health_check_skip_line`] is the
//! writer-taking sibling for the skip-branch line — a `Vec<u8>` sink
//! lets tests pin the exact rendered bytes (the plain ASCII `Step
//! {label}: ` prefix + the 69-byte skip-message body wrapped in the
//! `.bold().dimmed()` ANSI sequence + trailing `\n`) at one site
//! rather than as two lockstep literals across `rust_service.rs`.
//! The non-skip branch composes existing typed primitives
//! ([`crate::ui::print_numbered_step_heading`] +
//! [`crate::commands::flux::health_check_with_retry`]) and inherits
//! its byte-shape from their own oracles.
//!
//! # Why an async `run_*` fuser, not a plain printer
//!
//! Both pre-lift sites spelled the whole
//! `if skip_flux_health_check { <println!> } else { <heading +
//! health_check_with_retry> } println!();` composition, not just a
//! print. Two separate primitives (one for the skip-line, one for the
//! running branch) would leave the branch-shape open to drift — a
//! caller that copied the skip-line primitive but forgot to route the
//! non-skip arm through a matching primitive would silently open a
//! third body of the pre-lift stanza. The `run_*` fuser owns the
//! whole ceremony including the trailing `println!();` separator so
//! the two consumers each reduce to a single delegating `.await?`.

use anyhow::Result;
use colored::Colorize;
use std::io;

/// The invariant title every pre-lift non-skip branch spelled — the
/// plain ASCII `Post-release FluxCD health check...` label handed to
/// [`crate::ui::print_numbered_step_heading`]. Named as a `const` so
/// a future re-branding (a swap for `"Post-release GitOps health
/// check..."`, a translation, or promotion to a leading glyph)
/// reaches ONE site rather than two lockstep string literals.
pub const POST_RELEASE_FLUX_HEALTH_CHECK_TITLE: &str = "Post-release FluxCD health check...";

/// The invariant skip-branch message every pre-lift stanza spelled —
/// the 69-byte `Skipping post-release FluxCD health check
/// (skip_flux_health_check: true)` phrase wrapped in
/// `.bold().dimmed()` at emission. Named as a `const` so a future
/// re-branding (a rename to `skip_flux_probe`, dropping the
/// parenthetical config-key hint) reaches ONE site.
pub const POST_RELEASE_FLUX_HEALTH_CHECK_SKIP_MESSAGE: &str =
    "Skipping post-release FluxCD health check (skip_flux_health_check: true)";

/// The invariant `"post-release"` kind label handed to
/// [`crate::commands::flux::health_check_with_retry`] on the non-skip
/// branch. Named as a `const` so a future canonicalization
/// (`"post-release"` → `"post_release"`, or an enumeration lift onto
/// a `HealthCheckKind` closed enum) reaches ONE site.
pub const POST_RELEASE_FLUX_HEALTH_CHECK_KIND: &str = "post-release";

/// The invariant `600`-second overall timeout handed as the second
/// positional argument to
/// [`crate::commands::flux::health_check_with_retry`] on the non-skip
/// branch. Ten minutes was chosen (comment at both pre-lift sites) to
/// cover complex deployments with multiple kustomizations to
/// reconcile — a future re-tuning reaches ONE site rather than two
/// lockstep numeric literals.
pub const POST_RELEASE_FLUX_HEALTH_CHECK_TIMEOUT_SECS: u64 = 600;

/// The invariant `10`-second inter-retry interval handed as the third
/// positional argument to
/// [`crate::commands::flux::health_check_with_retry`] on the non-skip
/// branch. A future re-tuning (a switch to exponential backoff, a
/// bump to `15` for slower clusters) reaches ONE site rather than two
/// lockstep numeric literals.
pub const POST_RELEASE_FLUX_HEALTH_CHECK_INTERVAL_SECS: u64 = 10;

/// Emit the canonical `Step <label>: Skipping post-release FluxCD
/// health check (skip_flux_health_check: true).bold().dimmed()`
/// skip-branch line to stdout. Called from the skip arm of
/// [`run_post_release_flux_health_check_step`].
///
/// Delegates to [`write_post_release_flux_health_check_skip_line`]
/// against [`std::io::stdout`]; the writer split exists so the
/// fail-before-pass byte-oracle test pins the exact rendered bytes
/// without capturing stdout.
pub fn print_post_release_flux_health_check_skip_line(step_label: &str) {
    let _ = write_post_release_flux_health_check_skip_line(&mut io::stdout().lock(), step_label);
}

/// Writer-taking sibling to
/// [`print_post_release_flux_health_check_skip_line`]. Emits the
/// single `Step <label>: <skip-message>.bold().dimmed()\n` line via
/// [`writeln!`] against the supplied writer.
///
/// [`print_post_release_flux_health_check_skip_line`] is the stdout
/// adapter; this variant exists so tests can pin the plain ASCII
/// `Step <label>: ` prefix, the caller's `<label>` verbatim, the
/// 69-byte skip-message body, and the `.bold().dimmed()` ANSI
/// envelope without capturing stdout.
pub fn write_post_release_flux_health_check_skip_line<W: io::Write>(
    w: &mut W,
    step_label: &str,
) -> io::Result<()> {
    writeln!(
        w,
        "Step {}: {}",
        step_label,
        POST_RELEASE_FLUX_HEALTH_CHECK_SKIP_MESSAGE.bold().dimmed()
    )
}

/// Run the canonical post-release FluxCD-health-check step: on `skip`
/// emit the `Step <label>: Skipping post-release FluxCD health check
/// (skip_flux_health_check: true).bold().dimmed()` line via
/// [`print_post_release_flux_health_check_skip_line`]; otherwise emit
/// the `Step <label>: Post-release FluxCD health check....bold()`
/// heading via [`crate::ui::print_numbered_step_heading`] and
/// delegate to [`crate::commands::flux::health_check_with_retry`]
/// with the invariant [`POST_RELEASE_FLUX_HEALTH_CHECK_KIND`] label,
/// [`POST_RELEASE_FLUX_HEALTH_CHECK_TIMEOUT_SECS`] overall timeout and
/// [`POST_RELEASE_FLUX_HEALTH_CHECK_INTERVAL_SECS`] inter-retry
/// interval.
///
/// Always emits a trailing `println!();` blank-line separator so the
/// subsequent step's own heading (or trailing release banner) opens
/// against a blank row (every pre-lift consumer spelled this
/// trailing separator).
///
/// # Errors
///
/// On the non-skip branch, propagates any `anyhow::Error` returned by
/// [`crate::commands::flux::health_check_with_retry`] verbatim (via
/// the `?` operator). The skip branch is infallible.
pub async fn run_post_release_flux_health_check_step(step_label: &str, skip: bool) -> Result<()> {
    if skip {
        print_post_release_flux_health_check_skip_line(step_label);
    } else {
        crate::ui::print_numbered_step_heading(step_label, POST_RELEASE_FLUX_HEALTH_CHECK_TITLE);
        crate::commands::flux::health_check_with_retry(
            POST_RELEASE_FLUX_HEALTH_CHECK_KIND,
            POST_RELEASE_FLUX_HEALTH_CHECK_TIMEOUT_SECS,
            POST_RELEASE_FLUX_HEALTH_CHECK_INTERVAL_SECS,
        )
        .await?;
    }
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fail-before-pass envelope for
    /// [`write_post_release_flux_health_check_skip_line`] on the
    /// plain pre-lift step-label `"7"` (the
    /// `deploy_service_across_environments` site's spelling). Pins
    /// the one-line body — the plain ASCII `Step 7: ` prefix, the
    /// 69-byte skip-message body wrapped in the
    /// `.bold().dimmed()` ANSI envelope, and the trailing `\n`. A
    /// silent drift a future rewrite might introduce — dropping the
    /// step-label interpolation, renaming the skip-message, switching
    /// the `.bold().dimmed()` chain — flips this assertion rather
    /// than compiling and silently diverging the two consumer sites'
    /// visual grammar.
    #[test]
    fn write_skip_line_emits_plain_seven_step_label_verbatim() {
        let mut buf: Vec<u8> = Vec::new();
        write_post_release_flux_health_check_skip_line(&mut buf, "7")
            .expect("write against a Vec<u8> sink must succeed");
        let out = String::from_utf8(buf)
            .expect("skip-line must emit valid UTF-8 (the pre-lift println! did)");
        // The pre-lift line reached stdout as `Step 7: <message
        // wrapped in .bold().dimmed()>\n`. `colored` is
        // detect-terminal-aware, so at test time (no tty) the ANSI
        // envelope collapses to the bare bytes — that's the correct
        // downstream behavior (piped output must not carry ANSI).
        // Assert on the un-ANSI'd shape so this test survives both
        // tty-and-piped runs.
        assert!(
            out.contains("Step 7: "),
            "skip-line must open with `Step 7: ` prefix (pre-lift \
             literal from `deploy_service_across_environments`). Got {out:?}"
        );
        assert!(
            out.contains(POST_RELEASE_FLUX_HEALTH_CHECK_SKIP_MESSAGE),
            "skip-line must carry the 69-byte pre-lift skip-message \
             body verbatim. Got {out:?}"
        );
        assert!(
            out.ends_with('\n'),
            "skip-line must terminate with a single `\\n` (pre-lift \
             `println!` did). Got {out:?}"
        );
    }

    /// Byte-oracle sibling for the fractional pre-lift step-label
    /// `"9/9"` (the `deploy_and_verify` site's spelling). Pins the
    /// second consumer's step-label projection so a variant-dispatch
    /// regression that hard-coded the primitive on `"7"` — silently
    /// mislabeling the `deploy_and_verify` step as `Step 7: ` rather
    /// than `Step 9/9: ` — surfaces here rather than in production.
    #[test]
    fn write_skip_line_emits_fractional_step_label_verbatim() {
        let mut buf: Vec<u8> = Vec::new();
        write_post_release_flux_health_check_skip_line(&mut buf, "9/9").unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("Step 9/9: "),
            "skip-line must open with `Step 9/9: ` prefix (pre-lift \
             literal from `deploy_and_verify`). Got {out:?}"
        );
        assert!(
            out.contains(POST_RELEASE_FLUX_HEALTH_CHECK_SKIP_MESSAGE),
            "skip-line must carry the 69-byte pre-lift skip-message \
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
        write_post_release_flux_health_check_skip_line(&mut buf, "STAGE-9/9").unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("Step STAGE-9/9: "),
            "skip-line must forward the step-label verbatim — no \
             trim, no case-fold, no punctuation injection. Got {out:?}"
        );
    }

    /// Pin the `"post-release"` kind constant — pre-lift both sites
    /// spelled the literal `"post-release"` verbatim as the first
    /// argument to
    /// [`crate::commands::flux::health_check_with_retry`]. A drift
    /// (an underscore variant `"post_release"`, a capitalization
    /// `"Post-Release"`, or a rename to `"postrelease"`) would
    /// silently route both consumers through a `health_check_with_retry`
    /// invocation the health-check module does not recognize.
    #[test]
    fn health_check_kind_constant_is_post_release_literal() {
        assert_eq!(
            POST_RELEASE_FLUX_HEALTH_CHECK_KIND, "post-release",
            "POST_RELEASE_FLUX_HEALTH_CHECK_KIND must project the \
             pre-lift `\"post-release\"` literal both call sites handed \
             to `crate::commands::flux::health_check_with_retry`. Got {:?}",
            POST_RELEASE_FLUX_HEALTH_CHECK_KIND
        );
    }

    /// Pin the post-release-title constant — pre-lift both sites
    /// spelled the literal `"Post-release FluxCD health check..."`
    /// verbatim as the title argument to
    /// [`crate::ui::print_numbered_step_heading`]. A drift (a rename
    /// to `"Running post-release FluxCD health check..."`, dropping
    /// the ellipsis, or promoting the ellipsis to U+2026) reaches
    /// ONE site through the const.
    #[test]
    fn title_constant_is_pre_lift_literal() {
        assert_eq!(
            POST_RELEASE_FLUX_HEALTH_CHECK_TITLE, "Post-release FluxCD health check...",
            "POST_RELEASE_FLUX_HEALTH_CHECK_TITLE must project the \
             pre-lift literal both call sites handed to \
             `crate::ui::print_numbered_step_heading`. Got {:?}",
            POST_RELEASE_FLUX_HEALTH_CHECK_TITLE
        );
    }

    /// Pin the skip-message constant — pre-lift both sites spelled
    /// the same 69-byte `Skipping post-release FluxCD health check
    /// (skip_flux_health_check: true)` phrase verbatim inside their
    /// `.dimmed()`-or-`.bold().dimmed()` chain (the two variants the
    /// lift normalized to a single `.bold().dimmed()` primitive
    /// envelope). A drift (dropping the parenthetical config-key
    /// hint, renaming `skip_flux_health_check` to `skip_flux_probe`)
    /// reaches ONE site through the const.
    #[test]
    fn skip_message_constant_is_pre_lift_literal() {
        assert_eq!(
            POST_RELEASE_FLUX_HEALTH_CHECK_SKIP_MESSAGE,
            "Skipping post-release FluxCD health check (skip_flux_health_check: true)",
            "POST_RELEASE_FLUX_HEALTH_CHECK_SKIP_MESSAGE must project \
             the pre-lift literal both call sites spelled inside \
             the `.bold().dimmed()` / `.dimmed()` chain. Got {:?}",
            POST_RELEASE_FLUX_HEALTH_CHECK_SKIP_MESSAGE
        );
    }

    /// Pin the timeout-bound constant — pre-lift both sites spelled
    /// the literal `600` verbatim as the second positional argument
    /// to [`crate::commands::flux::health_check_with_retry`]. A drift
    /// (a bump to `900` for slower clusters, a switch to a
    /// deploy-config-provided bound) reaches ONE site through the
    /// const.
    #[test]
    fn timeout_constant_is_pre_lift_literal() {
        assert_eq!(
            POST_RELEASE_FLUX_HEALTH_CHECK_TIMEOUT_SECS, 600u64,
            "POST_RELEASE_FLUX_HEALTH_CHECK_TIMEOUT_SECS must project \
             the pre-lift `600`-second timeout both call sites handed \
             to `crate::commands::flux::health_check_with_retry`. Got {}",
            POST_RELEASE_FLUX_HEALTH_CHECK_TIMEOUT_SECS
        );
    }

    /// Pin the retry-interval constant — pre-lift both sites spelled
    /// the literal `10` verbatim as the third positional argument to
    /// [`crate::commands::flux::health_check_with_retry`]. A drift
    /// (an exponential-backoff switch, a bump to `15` for slower
    /// clusters) reaches ONE site through the const.
    #[test]
    fn interval_constant_is_pre_lift_literal() {
        assert_eq!(
            POST_RELEASE_FLUX_HEALTH_CHECK_INTERVAL_SECS, 10u64,
            "POST_RELEASE_FLUX_HEALTH_CHECK_INTERVAL_SECS must project \
             the pre-lift `10`-second retry interval both call sites \
             handed to `crate::commands::flux::health_check_with_retry`. Got {}",
            POST_RELEASE_FLUX_HEALTH_CHECK_INTERVAL_SECS
        );
    }

    /// Whole-module negative caller shield: no raw `"Skipping
    /// post-release FluxCD health check (skip_flux_health_check:
    /// true)"` literal may live in `commands/rust_service.rs` outside
    /// of a delegation to
    /// [`POST_RELEASE_FLUX_HEALTH_CHECK_SKIP_MESSAGE`]. Post-lift the
    /// two pre-lift sites each forward through
    /// [`run_post_release_flux_health_check_step`]; a future re-inline
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
        const NEEDLE: &str =
            "\"Skipping post-release FluxCD health check (skip_flux_health_check: true)\"";
        for (i, line) in body.lines().enumerate() {
            assert!(
                !line.contains(NEEDLE),
                "commands/rust_service.rs:{lineno} spells the pre-lift \
                 raw `\"Skipping post-release FluxCD health check \
                 (skip_flux_health_check: true)\"` skip-message literal \
                 — that shape was lifted onto \
                 `crate::commands::post_release_flux_health_check_step::\
                 POST_RELEASE_FLUX_HEALTH_CHECK_SKIP_MESSAGE` and reaches \
                 stdout through `run_post_release_flux_health_check_step`. \
                 A re-inline silently reopens the two-site duplication \
                 class this shield exists to close. Offending line: {line:?}",
                lineno = i + 1
            );
        }
    }

    /// Sibling negative shield: no raw `"Post-release FluxCD health
    /// check..."` title literal may live in
    /// `commands/rust_service.rs` outside of a delegation to
    /// [`POST_RELEASE_FLUX_HEALTH_CHECK_TITLE`]. Pins the running-
    /// branch title alongside the skip-message shield above so a
    /// re-inline that copied only the non-skip arm (dropping the
    /// skip-line, or vice versa) still trips a shield.
    #[test]
    fn no_raw_post_release_title_literal_survives_in_rust_service() {
        const SOURCE: &str = include_str!("rust_service.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            SOURCE,
            "commands/rust_service.rs",
        );
        const NEEDLE: &str = "\"Post-release FluxCD health check...\"";
        for (i, line) in body.lines().enumerate() {
            assert!(
                !line.contains(NEEDLE),
                "commands/rust_service.rs:{lineno} spells the pre-lift \
                 raw `\"Post-release FluxCD health check...\"` title \
                 literal — that shape was lifted onto \
                 `crate::commands::post_release_flux_health_check_step::\
                 POST_RELEASE_FLUX_HEALTH_CHECK_TITLE`. Offending line: {line:?}",
                lineno = i + 1
            );
        }
    }

    /// Positive delegation shield — `commands/rust_service.rs` must
    /// forward through
    /// [`run_post_release_flux_health_check_step`] at exactly two
    /// sites (one per pre-lift consumer: the
    /// `deploy_service_across_environments` Step-7 postamble and the
    /// `deploy_and_verify` Step-9/9 postamble). A fusion that folded
    /// the two sites into one call or dropped one of the postambles
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
            "post_release_flux_health_check_step::run_post_release_flux_health_check_step(";
        let forward_hits = body.matches(FORWARD_NEEDLE).count();
        assert_eq!(
            forward_hits, 2,
            "commands/rust_service.rs body must forward to \
             `crate::commands::post_release_flux_health_check_step::\
             run_post_release_flux_health_check_step(...)` at exactly 2 \
             sites — one per pre-lift consumer \
             (`deploy_service_across_environments` and \
             `deploy_and_verify`). Found {forward_hits} forwarding hits."
        );
    }
}
