//! Product-release phase-skipped announce — the four sibling
//! `crate::ui::print_phase_skipped("Phase <N>: Skipping <phase-verb>
//! [(<cause>)]")` stanzas across
//! `commands/product_release.rs::execute` lifted onto one typed body.
//!
//! # Pre-lift census — four sibling stanzas, two axes of variation
//!
//! Four consumer sites in `commands/product_release.rs::execute` each
//! spelled the same `crate::ui::print_phase_skipped(<literal>)`
//! one-liner, diverging on two orthogonal axes:
//!
//! 1. Which phase — Phase 4 (dashboard sync) or Phase 5 (post-deploy
//!    verification). Each phase carries a fixed `<N>: Skipping
//!    <phase-verb>` prefix.
//! 2. Whether a `(<cause>)` annotation follows the phase-verb. The
//!    pre-lift census carries a single cause literal — `(--build-only)`
//!    — at the two `--build-only` short-circuit sites, and no annotation
//!    at the two config-gated sites.
//!
//! Sites (pre-lift, all in `commands/product_release.rs::execute`):
//!
//! - `~L655` — Phase 4 short-circuit, `--build-only` branch:
//!   `"Phase 4: Skipping dashboard sync (--build-only)"`.
//! - `~L656` — Phase 5 short-circuit, `--build-only` branch:
//!   `"Phase 5: Skipping post-deploy verification (--build-only)"`.
//! - `~L780` — Phase 4 config-gated `else` branch (skip when
//!   `--skip-dashboards` or `product.dashboards = false`):
//!   `"Phase 4: Skipping dashboard sync"`.
//! - `~L803` — Phase 5 config-gated `else` branch (skip when
//!   `env != staging` or `product.post_deploy = false`):
//!   `"Phase 5: Skipping post-deploy verification"`.
//!
//! Two identical `Phase 4: Skipping dashboard sync` prefixes and two
//! identical `Phase 5: Skipping post-deploy verification` prefixes,
//! carried inline four times through
//! [`crate::ui::print_phase_skipped`]. A drift to the phase number, the
//! phase verb, or the `(--build-only)` cause spelling had to hit each
//! affected site in lockstep pre-lift; post-lift the drift hits ONE
//! typed body and every consumer inherits the change from the primitive.
//! Past the PRIME DIRECTIVE's duplication-is-a-bug threshold
//! (THEORY.md §VI.1) at four consumer sites.
//!
//! # Typed catalog
//!
//! [`ProductReleaseSkippablePhase`] is a closed two-variant enum —
//! `DashboardSync` (Phase 4) and `PostDeployVerification` (Phase 5).
//! The pre-lift `Phase <N>: Skipping <phase-verb>` literal is projected
//! by [`ProductReleaseSkippablePhase::phase_label`] and
//! [`ProductReleaseSkippablePhase::skip_verb`]. A future extension
//! (a Phase 3.5 gate, a rename of `post_deploy` to `smoke`, a swap of
//! `Skipping` for a leaner glyph) reaches ONE variant body rather than
//! every affected caller.
//!
//! # Cause slot
//!
//! The optional `(<cause>)` annotation is a caller-supplied `&str`
//! rather than a second closed enum. The pre-lift census carries only
//! one cause literal (`"--build-only"`); constraining the slot to a
//! closed enum here would force a two-line change (variant + arm) at
//! every future short-circuit gate for a slot with no measured
//! duplication cost yet. When a second cause enters the census (e.g. a
//! `--skip-dashboards --skip-post-deploy` fused short-circuit) the slot
//! can promote to a closed enum without disturbing the phase catalog.
//!
//! # Byte-oracle
//!
//! [`compose_product_release_phase_skipped_message`] returns the exact
//! `Phase <N>: Skipping <phase-verb> [(<cause>)]` `String` — a
//! plain-`String` result lets tests pin the composed bytes without
//! capturing stdout or shelling out. The outer `.dimmed()` framing of
//! the composed line remains at [`crate::ui::print_phase_skipped`]
//! (its own byte-oracle already covers the ANSI envelope and framing
//! blank).

/// Closed catalog of the two `Phase <N>: Skipping <phase-verb>` stanzas
/// pre-lift spelled inline four times across
/// `commands/product_release.rs::execute`.
///
/// Adding a third skippable phase (e.g. a Phase 3.5 attestation-verify
/// short-circuit) is a one-variant edit here plus the two accessor arms
/// — every caller then reaches the new phase through the same
/// [`print_product_release_phase_skipped`] entry point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductReleaseSkippablePhase {
    /// Phase 4 — dashboard sync. Pre-lift spelled at
    /// `commands/product_release.rs::execute` ~L655 (`--build-only`
    /// short-circuit branch) and ~L780 (config-gated `else` branch when
    /// `--skip-dashboards` or `product.dashboards = false`).
    DashboardSync,
    /// Phase 5 — post-deploy verification. Pre-lift spelled at
    /// `commands/product_release.rs::execute` ~L656 (`--build-only`
    /// short-circuit branch) and ~L803 (config-gated `else` branch when
    /// `env != staging` or `product.post_deploy = false`).
    PostDeployVerification,
}

impl ProductReleaseSkippablePhase {
    /// The pre-lift `Phase <N>` prefix — the `"4"` and `"5"` phase
    /// numbers exactly as they appeared inside the composed skip
    /// literal at each of the four consumer sites.
    pub const fn phase_label(&self) -> &'static str {
        match self {
            Self::DashboardSync => "4",
            Self::PostDeployVerification => "5",
        }
    }

    /// The pre-lift `Skipping <phase-verb>` phase-verb — the
    /// `"dashboard sync"` and `"post-deploy verification"` phrases
    /// exactly as they appeared inside the composed skip literal at
    /// each of the four consumer sites.
    pub const fn skip_verb(&self) -> &'static str {
        match self {
            Self::DashboardSync => "dashboard sync",
            Self::PostDeployVerification => "post-deploy verification",
        }
    }
}

/// The canonical `--build-only` cause literal pre-lift spelled at both
/// short-circuit sites (`commands/product_release.rs::execute` ~L655
/// and ~L656). Named as a `const` so the flag rename that touches the
/// clap surface reaches ONE site here rather than two lockstep string
/// literals inside the composed skip messages.
pub const PRODUCT_RELEASE_SKIP_CAUSE_BUILD_ONLY: &str = "--build-only";

/// Compose the exact `Phase <N>: Skipping <phase-verb> [(<cause>)]`
/// message string — the payload
/// [`print_product_release_phase_skipped`] hands to the ui adapter.
///
/// Returning a `String` (rather than emitting through an `io::Write`)
/// mirrors the pre-lift call shape at each of the four consumer sites
/// — a bare string literal handed to
/// [`crate::ui::print_phase_skipped`]. The plain-`String` byte-oracle
/// tests below pin the composed bytes exactly.
pub fn compose_product_release_phase_skipped_message(
    phase: ProductReleaseSkippablePhase,
    cause: Option<&str>,
) -> String {
    match cause {
        None => format!(
            "Phase {}: Skipping {}",
            phase.phase_label(),
            phase.skip_verb()
        ),
        Some(c) => format!(
            "Phase {}: Skipping {} ({})",
            phase.phase_label(),
            phase.skip_verb(),
            c,
        ),
    }
}

/// Emit the canonical `Phase <N>: Skipping <phase-verb> [(<cause>)]`
/// phase-skipped announce line via [`crate::ui::print_phase_skipped`].
/// Called from each of the four pre-lift stanzas in
/// `commands/product_release.rs::execute`.
///
/// # Message shape
///
/// - `cause = None` → `"Phase <N>: Skipping <phase-verb>"`.
/// - `cause = Some(<c>)` → `"Phase <N>: Skipping <phase-verb> (<c>)"`.
///
/// The `<c>` slot is forwarded verbatim — no trim, no case-fold, no
/// escape. Callers pin the cause spelling through the
/// [`PRODUCT_RELEASE_SKIP_CAUSE_BUILD_ONLY`] const (or a future sibling
/// const) rather than an inline literal.
///
/// # Framing
///
/// The composed message is handed to [`crate::ui::print_phase_skipped`]
/// unchanged, so the two-line body (`<message>.dimmed()` then a framing
/// blank) is inherited byte-for-byte from the shared ui adapter and its
/// existing byte-oracle. The
/// [`compose_product_release_phase_skipped_message`] sibling pins the
/// composed message string; the outer framing is covered by
/// `crate::ui::write_phase_skipped`.
pub fn print_product_release_phase_skipped(
    phase: ProductReleaseSkippablePhase,
    cause: Option<&str>,
) {
    crate::ui::print_phase_skipped(&compose_product_release_phase_skipped_message(phase, cause));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the phase-label projection for the `DashboardSync` variant
    /// — pre-lift both dashboard-sync sites spelled the literal `"4"`
    /// inside their composed skip message. A drift (a re-numbering to
    /// `"3.5"`) reaches ONE arm here rather than two lockstep literals.
    #[test]
    fn dashboard_sync_phase_label_is_pre_lift_literal() {
        assert_eq!(
            ProductReleaseSkippablePhase::DashboardSync.phase_label(),
            "4",
            "DashboardSync must project the pre-lift `Phase 4` label"
        );
    }

    /// Pin the phase-label projection for the `PostDeployVerification`
    /// variant — pre-lift both post-deploy-verification sites spelled
    /// the literal `"5"` inside their composed skip message.
    #[test]
    fn post_deploy_verification_phase_label_is_pre_lift_literal() {
        assert_eq!(
            ProductReleaseSkippablePhase::PostDeployVerification.phase_label(),
            "5",
            "PostDeployVerification must project the pre-lift `Phase 5` label"
        );
    }

    /// Pin the skip-verb projection for the `DashboardSync` variant —
    /// pre-lift both dashboard-sync sites spelled the literal
    /// `"dashboard sync"` inside their composed skip message.
    #[test]
    fn dashboard_sync_skip_verb_is_pre_lift_literal() {
        assert_eq!(
            ProductReleaseSkippablePhase::DashboardSync.skip_verb(),
            "dashboard sync",
            "DashboardSync must project the pre-lift `dashboard sync` phase-verb"
        );
    }

    /// Pin the skip-verb projection for the `PostDeployVerification`
    /// variant — pre-lift both post-deploy-verification sites spelled
    /// the literal `"post-deploy verification"` inside their composed
    /// skip message.
    #[test]
    fn post_deploy_verification_skip_verb_is_pre_lift_literal() {
        assert_eq!(
            ProductReleaseSkippablePhase::PostDeployVerification.skip_verb(),
            "post-deploy verification",
            "PostDeployVerification must project the pre-lift `post-deploy verification` phase-verb"
        );
    }

    /// Pin the `--build-only` cause const — pre-lift both short-circuit
    /// sites (`~L655` and `~L656`) spelled the literal `--build-only`
    /// inside the parenthetical suffix of their composed skip message.
    #[test]
    fn build_only_cause_constant_is_pre_lift_literal() {
        assert_eq!(
            PRODUCT_RELEASE_SKIP_CAUSE_BUILD_ONLY, "--build-only",
            "PRODUCT_RELEASE_SKIP_CAUSE_BUILD_ONLY must project the \
             pre-lift `--build-only` cause spelling"
        );
    }

    /// Byte-oracle for the un-caused `DashboardSync` composition — pins
    /// the `~L780` pre-lift literal `"Phase 4: Skipping dashboard sync"`
    /// exactly, no leading or trailing whitespace, no cause parenthetical.
    #[test]
    fn compose_message_uncaused_dashboard_sync_verbatim() {
        let out = compose_product_release_phase_skipped_message(
            ProductReleaseSkippablePhase::DashboardSync,
            None,
        );
        assert_eq!(
            out, "Phase 4: Skipping dashboard sync",
            "un-caused DashboardSync must reproduce the pre-lift `~L780` \
             literal verbatim, no cause parenthetical"
        );
    }

    /// Byte-oracle for the caused `DashboardSync` composition — pins
    /// the `~L655` pre-lift literal `"Phase 4: Skipping dashboard sync
    /// (--build-only)"` exactly, with the `--build-only` cause inside a
    /// leading-space parenthetical.
    #[test]
    fn compose_message_build_only_dashboard_sync_verbatim() {
        let out = compose_product_release_phase_skipped_message(
            ProductReleaseSkippablePhase::DashboardSync,
            Some(PRODUCT_RELEASE_SKIP_CAUSE_BUILD_ONLY),
        );
        assert_eq!(
            out, "Phase 4: Skipping dashboard sync (--build-only)",
            "caused DashboardSync must reproduce the pre-lift `~L655` \
             `(--build-only)` literal verbatim"
        );
    }

    /// Byte-oracle for the un-caused `PostDeployVerification`
    /// composition — pins the `~L803` pre-lift literal
    /// `"Phase 5: Skipping post-deploy verification"` exactly.
    #[test]
    fn compose_message_uncaused_post_deploy_verification_verbatim() {
        let out = compose_product_release_phase_skipped_message(
            ProductReleaseSkippablePhase::PostDeployVerification,
            None,
        );
        assert_eq!(
            out, "Phase 5: Skipping post-deploy verification",
            "un-caused PostDeployVerification must reproduce the pre-lift \
             `~L803` literal verbatim"
        );
    }

    /// Byte-oracle for the caused `PostDeployVerification` composition
    /// — pins the `~L656` pre-lift literal `"Phase 5: Skipping
    /// post-deploy verification (--build-only)"` exactly.
    #[test]
    fn compose_message_build_only_post_deploy_verification_verbatim() {
        let out = compose_product_release_phase_skipped_message(
            ProductReleaseSkippablePhase::PostDeployVerification,
            Some(PRODUCT_RELEASE_SKIP_CAUSE_BUILD_ONLY),
        );
        assert_eq!(
            out, "Phase 5: Skipping post-deploy verification (--build-only)",
            "caused PostDeployVerification must reproduce the pre-lift \
             `~L656` literal verbatim"
        );
    }

    /// Cause slot must forward the caller's `&str` verbatim — no trim,
    /// no case-fold, no escape. A future normalisation at the primitive
    /// boundary would silently diverge from what a pre-lift inline
    /// `format!(..., "(<cause>)", ...)` did with a literal cause.
    #[test]
    fn compose_message_forwards_cause_verbatim_no_normalisation() {
        let out = compose_product_release_phase_skipped_message(
            ProductReleaseSkippablePhase::DashboardSync,
            Some("  MIXED-Case cause  "),
        );
        assert_eq!(
            out, "Phase 4: Skipping dashboard sync (  MIXED-Case cause  )",
            "cause slot must forward its `&str` verbatim (no trim, no \
             case-fold, no escape)"
        );
    }

    /// The two enum variants must produce distinct `Phase <N>` labels
    /// — a variant-dispatch bug that returned the same label for both
    /// variants would silently mislabel one consumer site's phase in
    /// production.
    #[test]
    fn phase_labels_are_distinct_across_variants() {
        assert_ne!(
            ProductReleaseSkippablePhase::DashboardSync.phase_label(),
            ProductReleaseSkippablePhase::PostDeployVerification.phase_label(),
            "the two skippable-phase variants must carry distinct \
             `Phase <N>` labels — a merged projection silently \
             mislabels one consumer in production"
        );
    }

    /// The two enum variants must produce distinct skip-verbs — a
    /// variant-dispatch bug that returned the same verb for both
    /// variants would silently mislabel one consumer site's action in
    /// production.
    #[test]
    fn skip_verbs_are_distinct_across_variants() {
        assert_ne!(
            ProductReleaseSkippablePhase::DashboardSync.skip_verb(),
            ProductReleaseSkippablePhase::PostDeployVerification.skip_verb(),
            "the two skippable-phase variants must carry distinct \
             skip-verbs — a merged projection silently mislabels one \
             consumer's action in production"
        );
    }

    /// Whole-module negative caller shield: no raw `"Phase 4: Skipping
    /// dashboard sync"` literal may live in
    /// `commands/product_release.rs` outside a delegation to
    /// [`ProductReleaseSkippablePhase::DashboardSync`]. Post-lift the
    /// two pre-lift dashboard-sync sites forward through
    /// [`print_product_release_phase_skipped`]; a future re-inline
    /// silently reopens the two-site duplication class this lift
    /// closed. Also catches the caused variant, since the caused
    /// literal contains the uncaused prefix as a substring.
    #[test]
    fn no_raw_dashboard_sync_literal_survives_in_product_release() {
        const SOURCE: &str = include_str!("product_release.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            SOURCE,
            "commands/product_release.rs",
        );
        const NEEDLE: &str = "\"Phase 4: Skipping dashboard sync";
        for (i, line) in body.lines().enumerate() {
            assert!(
                !line.contains(NEEDLE),
                "commands/product_release.rs:{lineno} spells the pre-lift \
                 raw `\"Phase 4: Skipping dashboard sync[ (--build-only)]\"` \
                 literal — that shape was lifted onto \
                 `crate::commands::product_release_phase_skipped::\
                 ProductReleaseSkippablePhase::DashboardSync` and reaches \
                 stdout through `print_product_release_phase_skipped`. \
                 A re-inline silently reopens the two-site duplication \
                 class this shield exists to close. Offending line: {line:?}",
                lineno = i + 1
            );
        }
    }

    /// Sibling negative shield: no raw `"Phase 5: Skipping post-deploy
    /// verification"` literal may live in
    /// `commands/product_release.rs` outside a delegation to
    /// [`ProductReleaseSkippablePhase::PostDeployVerification`].
    #[test]
    fn no_raw_post_deploy_verification_literal_survives_in_product_release() {
        const SOURCE: &str = include_str!("product_release.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            SOURCE,
            "commands/product_release.rs",
        );
        const NEEDLE: &str = "\"Phase 5: Skipping post-deploy verification";
        for (i, line) in body.lines().enumerate() {
            assert!(
                !line.contains(NEEDLE),
                "commands/product_release.rs:{lineno} spells the pre-lift \
                 raw `\"Phase 5: Skipping post-deploy verification[ \
                 (--build-only)]\"` literal — that shape was lifted onto \
                 `crate::commands::product_release_phase_skipped::\
                 ProductReleaseSkippablePhase::PostDeployVerification` \
                 and reaches stdout through \
                 `print_product_release_phase_skipped`. Offending line: {line:?}",
                lineno = i + 1
            );
        }
    }

    /// Positive delegation shield — `commands/product_release.rs` must
    /// forward through [`print_product_release_phase_skipped`] at
    /// exactly four sites (one per pre-lift consumer: two
    /// `--build-only` short-circuit branches at `~L655`/`~L656` and two
    /// config-gated `else` branches at `~L780`/`~L803`). A fusion that
    /// folded any pair into one call — or dropped one of the sites —
    /// silently fails here even though the negative halves above would
    /// still pass.
    #[test]
    fn product_release_forwards_through_print_primitive_four_times() {
        const SOURCE: &str = include_str!("product_release.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            SOURCE,
            "commands/product_release.rs",
        );
        const FORWARD_NEEDLE: &str =
            "product_release_phase_skipped::print_product_release_phase_skipped(";
        let forward_hits = body.matches(FORWARD_NEEDLE).count();
        assert_eq!(
            forward_hits, 4,
            "commands/product_release.rs body must forward to \
             `crate::commands::product_release_phase_skipped::\
             print_product_release_phase_skipped(...)` at exactly 4 \
             sites — one per pre-lift consumer (two `--build-only` \
             short-circuit branches and two config-gated `else` \
             branches). Found {forward_hits} forwarding hits."
        );
    }
}
