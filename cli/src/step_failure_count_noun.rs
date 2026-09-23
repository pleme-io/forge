//! Canonical `print_step_failure(&msg_with_count_noun_secs_1(<label>,
//! <count>, <noun>, duration))` step-failure stanza for the three
//! sibling single-count failure arms across the backend + frontend
//! validation gates.
//!
//! # Duplication being lifted
//!
//! Three byte-identical sibling stanzas — one in
//! `commands/frontend_validation.rs` and two in `commands/prerelease.rs`
//! — each restated:
//!
//! ```ignore
//! crate::ui::print_step_failure(&crate::repo::msg_with_count_noun_secs_1(
//!     "<label>",
//!     <count>,
//!     "<noun>",
//!     duration,
//! ));
//! ```
//!
//! byte-for-byte, differing only in the label literal, the count
//! expression, and the noun literal:
//!
//! 1. `commands/frontend_validation.rs::run_type_check` failure arm
//!    (`<label>` = `"Type check failed"`, `<count>` = `error_count`,
//!    `<noun>` = `"errors"`).
//! 2. `commands/prerelease.rs::run_cargo_clippy` failure arm
//!    (`<label>` = `"Clippy failed"`, `<count>` = `warning_count`,
//!    `<noun>` = `"warnings"`).
//! 3. `commands/prerelease.rs::run_cargo_fmt_check` verify-failure
//!    arm (`<label>` = `"Code formatting check failed after
//!    auto-fix"`, `<count>` = `unformatted_files.len()`, `<noun>` =
//!    `"files"`).
//!
//! Three sibling occurrences clear THEORY.md §VI.1's "two is a
//! coincidence, three is a law" threshold. Post-lift the three
//! stanzas route through [`print_step_failure_count_noun`]; a drift
//! in the (paren shape, count/noun ordering, seconds unit, red `❌`
//! glyph, three-space indent) grammar lands at ONE typed body and
//! reaches all three consumers by construction.
//!
//! # Distinct from the sibling primitives
//!
//! [`crate::repo::msg_with_count_noun_secs_1`] is the byte-form owner
//! of the `<msg> ({count} {noun}, {:.1}s)` grammar; it does NOT pin
//! [`crate::ui::print_step_failure`] as the sink. This module owns
//! the fusion of the failure-sink and the count-noun-secs render.
//!
//! [`crate::test_count_pass_step::print_test_count_pass_step`]
//! (158e7d0) is the SUCCESS-arm sibling on the specialised
//! `test_count.unwrap_or(0) + "tests"` shape — pass instead of
//! failure, `Option<usize>` instead of `usize`, noun pinned to
//! `"tests"` instead of generic. Non-overlapping.
//!
//! [`crate::frontend_lint_failure_report::report_frontend_lint_failure`]
//! (a01e9c5) is the two-count failure fusion — one message plus TWO
//! count/noun tuples (errors + warnings) — and routes through
//! [`crate::repo::msg_with_two_counts_and_secs_1`] instead. This
//! primitive is the single-count peer on the same failure sink.
//!
//! # THEORY grounding
//!
//! - THEORY.md §I.5 (duplication budget zero; every recurring shape
//!   becomes a helper before it becomes duplicated code): three
//!   byte-identical sibling stanzas past the three-times threshold.
//!   The primitive collapses the fusion at ONE construction surface.
//! - THEORY.md §V.1 (Construction guarantees): the "print a red
//!   step-failure row whose message body carries a single count and
//!   noun and a one-decimal-place seconds tag" invariant lives at
//!   ONE construction surface and its byte-oracle tests pin the paren
//!   shape, the count/noun ordering, the seconds unit, and the
//!   fused sink identity as `cargo test`-verifiable invariants
//!   rather than as consumer-site conventions.
//! - THEORY.md §VI.1 (Generation over composition; three-times rule):
//!   three sibling occurrences past the "two is a coincidence, three
//!   is a law" threshold, so the fused body lifts onto ONE typed
//!   body and all three consumers cite it.

/// Render the pre-lift step-failure message body — the `<label>
/// ({count} {noun}, {:.1}s)` composition every consumer spliced
/// through [`crate::repo::msg_with_count_noun_secs_1`]. Byte-oracle
/// sibling of [`print_step_failure_count_noun`] for tests that need
/// the composed string without the print side effect.
pub fn render_step_failure_count_noun<L: std::fmt::Display, C: std::fmt::Display>(
    label: L,
    count: C,
    noun: &str,
    duration: std::time::Duration,
) -> String {
    crate::repo::msg_with_count_noun_secs_1(label, count, noun, duration)
}

/// Print the pre-lift `❌ <label> ({count} {noun}, {:.1}s)`
/// step-failure row to stdout via [`crate::ui::print_step_failure`]
/// with the canonical [`render_step_failure_count_noun`] message body.
///
/// `label` accepts any [`std::fmt::Display`] so both `&'static str`
/// (`"Clippy failed"`) and owned `String` (a future
/// `format!("{} failed", suite)`-shaped label) flow through without
/// an intermediate `.to_string()` at the call site — mirrors
/// [`crate::repo::msg_with_count_noun_secs_1`]'s own `M: Display`
/// bound.
///
/// `count` accepts any [`std::fmt::Display`] so both an `usize`
/// (`error_count`, `warning_count`) and any other displayable count
/// type (`unformatted_files.len()` returns `usize` too — the bound
/// stays wide so a future `u32` / `u64` / `i64` count source flows
/// without conversion) render into the same `{count}` slot.
pub fn print_step_failure_count_noun<L: std::fmt::Display, C: std::fmt::Display>(
    label: L,
    count: C,
    noun: &str,
    duration: std::time::Duration,
) {
    crate::ui::print_step_failure(&render_step_failure_count_noun(
        label, count, noun, duration,
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::Duration;

    /// Byte-oracle for the general render: pins the pre-lift
    /// `<label> ({count} {noun}, {:.1}s)` composition — the four
    /// grammar invariants (single space between label and paren,
    /// count-space-noun ordering, `, ` comma-space separator, one
    /// decimal-place seconds tag) — at one place. A drift in any
    /// of the four regresses this assertion.
    #[test]
    fn render_matches_pre_lift_byte_form() {
        assert_eq!(
            render_step_failure_count_noun(
                "Clippy failed",
                3_usize,
                "warnings",
                Duration::from_millis(1234)
            ),
            "Clippy failed (3 warnings, 1.2s)"
        );
    }

    /// Full-text byte-oracle for the
    /// `commands/frontend_validation.rs::run_type_check` failure arm:
    /// the pre-lift label was `"Type check failed"` verbatim, the
    /// noun was `"errors"` verbatim. Ensures a rename to `"TS check
    /// failed"` or `"type-check failed"` regresses this assertion.
    #[test]
    fn frontend_type_check_full_text_matches_pre_lift_literal() {
        assert_eq!(
            render_step_failure_count_noun(
                "Type check failed",
                12_usize,
                "errors",
                Duration::from_millis(2100)
            ),
            "Type check failed (12 errors, 2.1s)"
        );
    }

    /// Full-text byte-oracle for the
    /// `commands/prerelease.rs::run_cargo_clippy` failure arm: the
    /// pre-lift label was `"Clippy failed"` verbatim, the noun was
    /// `"warnings"` verbatim.
    #[test]
    fn prerelease_clippy_full_text_matches_pre_lift_literal() {
        assert_eq!(
            render_step_failure_count_noun(
                "Clippy failed",
                5_usize,
                "warnings",
                Duration::from_millis(500)
            ),
            "Clippy failed (5 warnings, 0.5s)"
        );
    }

    /// Full-text byte-oracle for the
    /// `commands/prerelease.rs::run_cargo_fmt_check` verify-failure
    /// arm: the pre-lift label was `"Code formatting check failed
    /// after auto-fix"` verbatim, the noun was `"files"` verbatim.
    #[test]
    fn prerelease_fmt_check_full_text_matches_pre_lift_literal() {
        assert_eq!(
            render_step_failure_count_noun(
                "Code formatting check failed after auto-fix",
                2_usize,
                "files",
                Duration::from_millis(340),
            ),
            "Code formatting check failed after auto-fix (2 files, 0.3s)"
        );
    }

    /// Zero-count render: `count = 0` produces `"(0 <noun>, {:.1}s)"`
    /// verbatim rather than omitting the count or the noun. A future
    /// edit that shortened the zero-count form (say to `"(<:.1}s)"`
    /// or `"(no <noun>, {:.1}s)"`) trips this assertion before the
    /// change reaches any consumer.
    #[test]
    fn render_with_zero_count_preserves_full_shape() {
        assert_eq!(
            render_step_failure_count_noun(
                "Suite failed",
                0_usize,
                "cases",
                Duration::from_millis(100)
            ),
            "Suite failed (0 cases, 0.1s)"
        );
    }

    /// Display-bound coverage: the `L: Display` bound flows both a
    /// borrowed `&'static str` and an owned `String` through the same
    /// primitive without an intermediate `.to_string()` at the call
    /// site.
    #[test]
    fn label_accepts_display_bound_owned_and_borrowed() {
        let owned: String = format!("{} failed", "Backend");
        assert_eq!(
            render_step_failure_count_noun(&owned, 1_usize, "errors", Duration::from_millis(100)),
            "Backend failed (1 errors, 0.1s)"
        );
        assert_eq!(
            render_step_failure_count_noun(
                "Static failed",
                1_usize,
                "errors",
                Duration::from_millis(100)
            ),
            "Static failed (1 errors, 0.1s)"
        );
    }

    /// Signature pin: the print helper accepts four generic
    /// arguments in the fixed order (label, count, noun, duration).
    /// A future edit that reordered the arguments or narrowed the
    /// bounds would ripple to every caller and trip the type check.
    #[test]
    fn print_helper_signature_pins_four_arg_shape() {
        let _: fn(&'static str, usize, &str, Duration) = print_step_failure_count_noun;
    }

    /// Slice the module's own source to the production body so the
    /// tests below can count delegation call sites without matching
    /// against needle-mentions inside their own `assert!` diagnostic
    /// messages.
    fn production_body() -> String {
        let source = include_str!("step_failure_count_noun.rs");
        let cutoff = source
            .find("#[cfg(test)]")
            .expect("production body ends at the test cfg attr");
        source[..cutoff].to_string()
    }

    /// Delegation pin: the render helper's body MUST forward through
    /// [`crate::repo::msg_with_count_noun_secs_1`] exactly once. A
    /// future edit that inlined the `format!` template here
    /// (bypassing the peer primitive) trips this assertion — the
    /// four-invariant grammar (paren shape, tuple ordering, seconds
    /// unit, one decimal place) lives at exactly ONE body.
    #[test]
    fn render_helper_delegates_through_msg_primitive_once() {
        let body = production_body();
        let hits =
            crate::test_support::code_line_hits(&body, "crate::repo::msg_with_count_noun_secs_1(");
        assert_eq!(
            hits.len(),
            1,
            "production body must forward through \
             `crate::repo::msg_with_count_noun_secs_1(...)` at \
             exactly one site — the render helper's body. Found {}: \
             {:#?}",
            hits.len(),
            hits
        );
    }

    /// Delegation pin: the print helper's body MUST forward through
    /// [`crate::ui::print_step_failure`] exactly once. A future edit
    /// that swapped in a sibling sink ([`crate::ui::print_step_warn`]
    /// or [`crate::ui::print_step_failure_timed`]) trips this
    /// assertion.
    #[test]
    fn print_helper_delegates_through_ui_print_step_failure_once() {
        let body = production_body();
        let hits = crate::test_support::code_line_hits(&body, "crate::ui::print_step_failure(");
        assert_eq!(
            hits.len(),
            1,
            "production body must forward through \
             `crate::ui::print_step_failure(...)` at exactly one \
             site — the print helper's body. Found {}: {:#?}",
            hits.len(),
            hits
        );
    }

    /// Positive delegation shield for
    /// `commands/frontend_validation.rs`: the `run_type_check`
    /// failure arm MUST forward through this primitive at least once.
    /// A migration that dropped the site outright would leave the
    /// negative "no raw stanza survives" scan (below) trivially
    /// satisfied by absence but this positive count still fails.
    #[test]
    fn frontend_validation_module_forwards_through_print_helper() {
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let path = commands_dir.join("frontend_validation.rs");
        let source = std::fs::read_to_string(&path).unwrap();
        let forwards =
            crate::test_support::code_line_hits(&source, "print_step_failure_count_noun(").len();
        assert!(
            forwards >= 1,
            "frontend_validation.rs must forward at least 1 \
             single-count step-failure stanza through \
             `crate::step_failure_count_noun::print_step_failure_count_noun(`; \
             found {forwards}. A dropped call would leave the \
             negative raw-stanza scan satisfied by absence.",
        );
    }

    /// Positive delegation shield for `commands/prerelease.rs`: the
    /// module owns TWO failure arms that migrate onto this primitive
    /// (`run_cargo_clippy` and `run_cargo_fmt_check`), so the
    /// expected count is 2. A migration that dropped either site
    /// leaves the negative "no raw stanza survives" scan satisfied
    /// by absence but this positive count still fails.
    #[test]
    fn prerelease_module_forwards_through_print_helper_at_least_twice() {
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let path = commands_dir.join("prerelease.rs");
        let source = std::fs::read_to_string(&path).unwrap();
        let forwards =
            crate::test_support::code_line_hits(&source, "print_step_failure_count_noun(").len();
        assert!(
            forwards >= 2,
            "prerelease.rs must forward at least 2 single-count \
             step-failure stanzas through \
             `crate::step_failure_count_noun::print_step_failure_count_noun(`; \
             found {forwards}. Both `run_cargo_clippy` and \
             `run_cargo_fmt_check` failure arms must route through \
             the primitive.",
        );
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` may respell the fused stanza inline any
    /// more. The needle is the two-token fusion
    /// `crate::ui::print_step_failure(&crate::repo::msg_with_count_noun_secs_1(`
    /// on the same source line. Any future consumer that wants the
    /// same row reaches for [`print_step_failure_count_noun`] on
    /// first grep, not by copy-pasting the stanza from an existing
    /// site.
    ///
    /// The needle is reconstructed at test time from three
    /// sub-tokens so this shield's own source text does not
    /// false-match itself.
    #[test]
    fn no_command_module_still_respells_raw_step_failure_count_noun_stanza() {
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        // Reconstruct the fused-sink needle at test time so this
        // shield's own source text does not false-match itself.
        let fused_needle = format!(
            "crate::ui::{}(&crate::repo::{}(",
            "print_step_failure", "msg_with_count_noun_secs_1"
        );
        let mut offenders: Vec<(PathBuf, Vec<String>)> = Vec::new();
        for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let hits = crate::test_support::code_line_hits(&source, &fused_needle);
            if !hits.is_empty() {
                offenders.push((path, hits));
            }
        }
        assert!(
            offenders.is_empty(),
            "raw fused `print_step_failure(&msg_with_count_noun_secs_1(...))` \
             stanza(s) survive under `commands/` — route each through \
             `crate::step_failure_count_noun::print_step_failure_count_noun(\
             <label>, <count>, <noun>, <duration>)` instead:\n{offenders:#?}"
        );
    }
}
