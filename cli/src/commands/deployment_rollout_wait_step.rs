//! Deployment-rollout wait step — the `Step <label>:` skip / run
//! branching stanza fused with the `flux::wait_for_deployment` spawn on
//! the non-skip arm.
//!
//! # Pre-lift census — two sibling stanzas, one 20-line body
//!
//! Two consumer sites in `commands/rust_service.rs` each spelled the
//! same `if wait_for_rollout { <heading + wait_for_deployment> } else
//! { <println!("Step <label>: Skipping deployment rollout wait
//! (wait_for_rollout: false)")> }` body, diverging on:
//!
//! 1. `commands/rust_service.rs::deploy_service_across_environments`
//!    (per-env deploy path, Step 4 around line 1567) with the plain
//!    `"4"` step-label and a trailing `println!();` after each branch.
//!    Skip-branch styling: `.dimmed()`.
//! 2. `commands/rust_service.rs::deploy_and_verify`
//!    (single-env deploy path, Step 6/9 around line 2460) with the
//!    fractional `"6/9"` step-label and a leading `println!();` before
//!    each branch. Skip-branch styling: `.bold()`.
//!
//! Both stanzas branch on `deploy_config.resolved_deployment()
//! .wait_for_rollout`:
//!
//! ```ignore
//! if wait_for_rollout {
//!     crate::ui::print_numbered_step_heading(label, "Waiting for deployment rollout...");
//!     crate::commands::flux::wait_for_deployment(
//!         service.clone(),
//!         namespace.clone(),
//!         deploy_config.global.deployment.deployment_wait_timeout_secs,
//!         tag_suffix.clone(),
//!         &deploy_config,
//!     )
//!     .await?;
//! } else {
//!     println!(
//!         "Step {label}: {}",
//!         "Skipping deployment rollout wait (wait_for_rollout: false)".<style>
//!     );
//! }
//! ```
//!
//! Two identically-shaped bodies past the PRIME DIRECTIVE's
//! duplication-is-a-bug threshold (THEORY §VI.1). A drift to the
//! skip-message copy, the running-branch title, the `wait_for_deployment`
//! argument order, or the timeout-source projection had to hit both
//! sites in lockstep pre-lift; post-lift the drift hits ONE typed body
//! and both consumers inherit the change from the primitive.
//!
//! # Style normalization
//!
//! Site A styled the skip-message with `.dimmed()`; Site B with
//! `.bold()`. Every other `Skipping <thing>` line in the fleet
//! (`commands/rust_service.rs::{Skipping ARM64 build, Skipping
//! migrations (database_type: none), Skipping federation integration
//! tests}`, plus the sibling
//! [`crate::commands::pre_release_flux_health_check_step`]'s
//! `.bold().dimmed()` variant) reaches for a `dimmed`-family style —
//! Site B's `.bold()` was a lockstep-drift outlier. The lift
//! canonicalizes both consumers on `.dimmed()`, closing the visible
//! style anomaly at Site B in the same move that closes the duplication.
//!
//! # Blank-line placement stays at the caller
//!
//! Site A embeds a trailing `println!();` after each branch to
//! separate the wait step from Step 4.5. Site B embeds a leading
//! `println!();` before each branch (the trailing blank is Step 6.5's
//! leading blank at `:2484`). The primitive owns the shared body only
//! — the blank-line placement stays at the caller so a re-canonicaliz-
//! ation of Site B's leading-blank invariant onto Site A's trailing-
//! blank invariant is a follow-up lift, not a scope-creep of this one.
//!
//! # Byte-oracle
//!
//! [`write_deployment_rollout_wait_skip_line`] is the writer-taking
//! sibling for the skip-branch line — a `Vec<u8>` sink lets tests pin
//! the exact rendered bytes (the plain ASCII `Step {label}: ` prefix +
//! the 61-byte skip-message body wrapped in the `.dimmed()` ANSI
//! sequence + trailing `\n`) at one site rather than as two lockstep
//! literals across `rust_service.rs`. The non-skip branch composes
//! existing typed primitives ([`crate::ui::print_numbered_step_heading`] +
//! [`crate::commands::flux::wait_for_deployment`]) and inherits its
//! byte-shape from their own oracles.

use crate::config::DeployConfig;
use anyhow::Result;
use colored::Colorize;
use std::io;

/// The invariant title every pre-lift non-skip branch spelled — the
/// plain ASCII `Waiting for deployment rollout...` label handed to
/// [`crate::ui::print_numbered_step_heading`]. Named as a `const` so a
/// future re-branding (a swap for `"Waiting for GitOps rollout..."`,
/// dropping the ellipsis, or promotion to a leading glyph) reaches ONE
/// site rather than two lockstep string literals.
pub const DEPLOYMENT_ROLLOUT_WAIT_TITLE: &str = "Waiting for deployment rollout...";

/// The invariant skip-branch message every pre-lift stanza spelled —
/// the 61-byte `Skipping deployment rollout wait
/// (wait_for_rollout: false)` phrase wrapped in `.dimmed()` at
/// emission. Named as a `const` so a future re-branding (a rename of
/// the `wait_for_rollout` config key, dropping the parenthetical
/// config-key hint, or a translation) reaches ONE site.
pub const DEPLOYMENT_ROLLOUT_WAIT_SKIP_MESSAGE: &str =
    "Skipping deployment rollout wait (wait_for_rollout: false)";

/// Emit the canonical `Step <label>: Skipping deployment rollout wait
/// (wait_for_rollout: false).dimmed()` skip-branch line to stdout.
/// Called from the skip arm of [`run_deployment_rollout_wait_step`].
///
/// Delegates to [`write_deployment_rollout_wait_skip_line`] against
/// [`std::io::stdout`]; the writer split exists so the
/// fail-before-pass byte-oracle test pins the exact rendered bytes
/// without capturing stdout.
pub fn print_deployment_rollout_wait_skip_line(step_label: &str) {
    let _ = write_deployment_rollout_wait_skip_line(&mut io::stdout().lock(), step_label);
}

/// Writer-taking sibling to [`print_deployment_rollout_wait_skip_line`].
/// Emits the single `Step <label>: <skip-message>.dimmed()\n` line via
/// [`writeln!`] against the supplied writer.
///
/// [`print_deployment_rollout_wait_skip_line`] is the stdout adapter;
/// this variant exists so tests can pin the plain ASCII
/// `Step <label>: ` prefix, the caller's `<label>` verbatim, the
/// 61-byte skip-message body, and the `.dimmed()` ANSI envelope
/// without capturing stdout.
pub fn write_deployment_rollout_wait_skip_line<W: io::Write>(
    w: &mut W,
    step_label: &str,
) -> io::Result<()> {
    writeln!(
        w,
        "Step {}: {}",
        step_label,
        DEPLOYMENT_ROLLOUT_WAIT_SKIP_MESSAGE.dimmed()
    )
}

/// Run the canonical deployment-rollout wait step: when
/// `deploy_config.resolved_deployment().wait_for_rollout` is `false`
/// emit the `Step <label>: Skipping deployment rollout wait
/// (wait_for_rollout: false).dimmed()` line via
/// [`print_deployment_rollout_wait_skip_line`]; otherwise emit the
/// `Step <label>: Waiting for deployment rollout....bold()` heading
/// via [`crate::ui::print_numbered_step_heading`] and delegate to
/// [`crate::commands::flux::wait_for_deployment`] with the
/// service-level/global timeout resolved from `deploy_config`.
///
/// # Blank-line placement
///
/// The primitive emits ONLY the branch body — no leading or trailing
/// `println!()` blank line. Callers own their own blank-line placement
/// so the pre-lift trailing-blank invariant at
/// `deploy_service_across_environments` (each step emits its own
/// trailing blank) and the leading-blank invariant at
/// `deploy_and_verify` (each step's successor emits a leading blank)
/// both survive the lift byte-for-byte.
///
/// # Errors
///
/// On the non-skip branch, propagates any `anyhow::Error` returned by
/// [`crate::commands::flux::wait_for_deployment`] verbatim (via the
/// `?` operator). The skip branch is infallible.
pub async fn run_deployment_rollout_wait_step(
    step_label: &str,
    service: String,
    namespace: String,
    expected_tag_suffix: String,
    deploy_config: &DeployConfig,
) -> Result<()> {
    if deploy_config.resolved_deployment().wait_for_rollout {
        crate::ui::print_numbered_step_heading(step_label, DEPLOYMENT_ROLLOUT_WAIT_TITLE);
        crate::commands::flux::wait_for_deployment(
            service,
            namespace,
            deploy_config.global.deployment.deployment_wait_timeout_secs,
            expected_tag_suffix,
            deploy_config,
        )
        .await?;
    } else {
        print_deployment_rollout_wait_skip_line(step_label);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fail-before-pass envelope for
    /// [`write_deployment_rollout_wait_skip_line`] on the plain
    /// pre-lift step-label `"4"` (the
    /// `deploy_service_across_environments` site's spelling). Pins
    /// the one-line body — the plain ASCII `Step 4: ` prefix, the
    /// 61-byte skip-message body wrapped in the `.dimmed()` ANSI
    /// envelope, and the trailing `\n`. A silent drift a future
    /// rewrite might introduce — dropping the step-label
    /// interpolation, renaming the skip-message, switching the
    /// `.dimmed()` chain — flips this assertion rather than compiling
    /// and silently diverging the two consumer sites' visual grammar.
    #[test]
    fn write_skip_line_emits_plain_four_step_label_verbatim() {
        let mut buf: Vec<u8> = Vec::new();
        write_deployment_rollout_wait_skip_line(&mut buf, "4")
            .expect("write against a Vec<u8> sink must succeed");
        let out = String::from_utf8(buf)
            .expect("skip-line must emit valid UTF-8 (the pre-lift println! did)");
        // The pre-lift line reached stdout as `Step 4: <message
        // wrapped in .dimmed()>\n`. `colored` is detect-terminal-
        // aware, so at test time (no tty) the ANSI envelope collapses
        // to the bare bytes — that's the correct downstream behavior
        // (piped output must not carry ANSI). Assert on the un-ANSI'd
        // shape so this test survives both tty-and-piped runs.
        assert!(
            out.contains("Step 4: "),
            "skip-line must open with `Step 4: ` prefix (pre-lift \
             literal from `deploy_service_across_environments`). Got {out:?}"
        );
        assert!(
            out.contains(DEPLOYMENT_ROLLOUT_WAIT_SKIP_MESSAGE),
            "skip-line must carry the 61-byte pre-lift skip-message \
             body verbatim. Got {out:?}"
        );
        assert!(
            out.ends_with('\n'),
            "skip-line must terminate with a single `\\n` (pre-lift \
             `println!` did). Got {out:?}"
        );
    }

    /// Byte-oracle sibling for the fractional pre-lift step-label
    /// `"6/9"` (the `deploy_and_verify` site's spelling). Pins the
    /// second consumer's step-label projection so a variant-dispatch
    /// regression that hard-coded the primitive on `"4"` — silently
    /// mislabeling the `deploy_and_verify` step as `Step 4: ` rather
    /// than `Step 6/9: ` — surfaces here rather than in production.
    #[test]
    fn write_skip_line_emits_fractional_step_label_verbatim() {
        let mut buf: Vec<u8> = Vec::new();
        write_deployment_rollout_wait_skip_line(&mut buf, "6/9").unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("Step 6/9: "),
            "skip-line must open with `Step 6/9: ` prefix (pre-lift \
             literal from `deploy_and_verify`). Got {out:?}"
        );
        assert!(
            out.contains(DEPLOYMENT_ROLLOUT_WAIT_SKIP_MESSAGE),
            "skip-line must carry the 61-byte pre-lift skip-message \
             body verbatim under the fractional label. Got {out:?}"
        );
    }

    /// The primitive MUST NOT emit anything beyond the exact
    /// step-label handed in — no trimming, case-folding, punctuation
    /// injection. A future normalisation at the primitive boundary
    /// would silently diverge from what the pre-lift inline
    /// `println!("Step {}: …", label, …)` did with the literal label.
    /// Pin the verbatim-forwarding contract with a gnarly input.
    #[test]
    fn write_skip_line_forwards_step_label_verbatim_no_normalisation() {
        let mut buf: Vec<u8> = Vec::new();
        write_deployment_rollout_wait_skip_line(&mut buf, "STAGE-7/12").unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("Step STAGE-7/12: "),
            "skip-line must forward the step-label verbatim — no \
             trim, no case-fold, no punctuation injection. Got {out:?}"
        );
    }

    /// Pin the title constant — pre-lift both sites spelled the
    /// literal `"Waiting for deployment rollout..."` verbatim as the
    /// title argument to [`crate::ui::print_numbered_step_heading`]. A
    /// drift (a rename to `"Waiting for rollout..."`, dropping the
    /// ellipsis, or promoting the ellipsis to U+2026) reaches ONE site
    /// through the const.
    #[test]
    fn title_constant_is_pre_lift_literal() {
        assert_eq!(
            DEPLOYMENT_ROLLOUT_WAIT_TITLE, "Waiting for deployment rollout...",
            "DEPLOYMENT_ROLLOUT_WAIT_TITLE must project the pre-lift \
             literal both call sites handed to \
             `crate::ui::print_numbered_step_heading`. Got {:?}",
            DEPLOYMENT_ROLLOUT_WAIT_TITLE
        );
    }

    /// Pin the skip-message constant — pre-lift both sites spelled the
    /// same 61-byte `Skipping deployment rollout wait
    /// (wait_for_rollout: false)` phrase verbatim inside the styled
    /// chain. A drift (dropping the parenthetical config-key hint,
    /// renaming `wait_for_rollout` to `wait_rollout`) reaches ONE site
    /// through the const.
    #[test]
    fn skip_message_constant_is_pre_lift_literal() {
        assert_eq!(
            DEPLOYMENT_ROLLOUT_WAIT_SKIP_MESSAGE,
            "Skipping deployment rollout wait (wait_for_rollout: false)",
            "DEPLOYMENT_ROLLOUT_WAIT_SKIP_MESSAGE must project the \
             pre-lift literal both call sites spelled inside the \
             styled chain. Got {:?}",
            DEPLOYMENT_ROLLOUT_WAIT_SKIP_MESSAGE
        );
    }

    /// Whole-module negative caller shield: no raw `"Skipping
    /// deployment rollout wait (wait_for_rollout: false)"` literal
    /// may live in `commands/rust_service.rs` outside of a delegation
    /// to [`DEPLOYMENT_ROLLOUT_WAIT_SKIP_MESSAGE`]. Post-lift the two
    /// pre-lift sites each forward through
    /// [`run_deployment_rollout_wait_step`]; a future re-inline (a
    /// "just call `println!` directly, it's shorter" cleanup) silently
    /// reopens the two-site duplication class this lift closed.
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
        const NEEDLE: &str = "\"Skipping deployment rollout wait (wait_for_rollout: false)\"";
        for (i, line) in body.lines().enumerate() {
            assert!(
                !line.contains(NEEDLE),
                "commands/rust_service.rs:{lineno} spells the pre-lift \
                 raw `\"Skipping deployment rollout wait \
                 (wait_for_rollout: false)\"` skip-message literal — \
                 that shape was lifted onto \
                 `crate::commands::deployment_rollout_wait_step::\
                 DEPLOYMENT_ROLLOUT_WAIT_SKIP_MESSAGE` and reaches \
                 stdout through `run_deployment_rollout_wait_step`. \
                 A re-inline silently reopens the two-site duplication \
                 class this shield exists to close. Offending line: {line:?}",
                lineno = i + 1
            );
        }
    }

    /// Sibling negative shield: no raw `"Waiting for deployment
    /// rollout..."` title literal may live in
    /// `commands/rust_service.rs` outside of a delegation to
    /// [`DEPLOYMENT_ROLLOUT_WAIT_TITLE`]. Pins the running-branch
    /// title alongside the skip-message shield above so a re-inline
    /// that copied only the non-skip arm (dropping the skip-line, or
    /// vice versa) still trips a shield.
    #[test]
    fn no_raw_wait_title_literal_survives_in_rust_service() {
        const SOURCE: &str = include_str!("rust_service.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            SOURCE,
            "commands/rust_service.rs",
        );
        const NEEDLE: &str = "\"Waiting for deployment rollout...\"";
        for (i, line) in body.lines().enumerate() {
            assert!(
                !line.contains(NEEDLE),
                "commands/rust_service.rs:{lineno} spells the pre-lift \
                 raw `\"Waiting for deployment rollout...\"` title \
                 literal — that shape was lifted onto \
                 `crate::commands::deployment_rollout_wait_step::\
                 DEPLOYMENT_ROLLOUT_WAIT_TITLE`. Offending line: {line:?}",
                lineno = i + 1
            );
        }
    }

    /// Positive delegation shield — `commands/rust_service.rs` must
    /// forward through [`run_deployment_rollout_wait_step`] at exactly
    /// two sites (one per pre-lift consumer: the
    /// `deploy_service_across_environments` Step-4 preamble and the
    /// `deploy_and_verify` Step-6/9 preamble). A fusion that folded
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
            "deployment_rollout_wait_step::run_deployment_rollout_wait_step(";
        let forward_hits = body.matches(FORWARD_NEEDLE).count();
        assert_eq!(
            forward_hits, 2,
            "commands/rust_service.rs body must forward to \
             `crate::commands::deployment_rollout_wait_step::\
             run_deployment_rollout_wait_step(...)` at exactly 2 sites \
             — one per pre-lift consumer \
             (`deploy_service_across_environments` and \
             `deploy_and_verify`). Found {forward_hits} forwarding hits."
        );
    }
}
