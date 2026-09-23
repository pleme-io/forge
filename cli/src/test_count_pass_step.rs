//! Canonical `print_step_pass(&msg_with_count_noun_secs_1(<label>,
//! test_count.unwrap_or(0), "tests", duration))` step-pass stanza for
//! the two sibling test-count success arms.
//!
//! # Duplication being lifted
//!
//! Two byte-close sibling
//! `crate::ui::print_step_pass(&crate::repo::msg_with_count_noun_secs_1(
//! <label>, test_count.unwrap_or(0), "tests", duration))` stanzas
//! survived across a pair of test-run success arms:
//!
//! - `commands/prerelease.rs::run_cargo_test` (G4 success branch,
//!   `<label>` = `"Tests passed"`, `test_count: Option<usize>` parsed
//!   from `cargo test`'s `"test result: ok. X passed; ..."` line via
//!   the module-local `parse_test_count`-shaped inline walk).
//! - `commands/frontend_validation.rs::run_unit_tests` (vitest success
//!   branch, `<label>` = `"Unit tests passed"`, `test_count:
//!   Option<usize>` parsed from vitest's summary line via
//!   [`crate::commands::frontend_validation::parse_test_count`]).
//!
//! Both sites share four grammar invariants byte-for-byte:
//!
//! 1. The sink is [`crate::ui::print_step_pass`] — a green
//!    `✓ <msg>` step-pass render, not [`crate::ui::print_step_check`]
//!    or [`crate::ui::print_bright_step_pass`].
//! 2. The msg body is composed through
//!    [`crate::repo::msg_with_count_noun_secs_1`] — the parenthesized
//!    `({count} {noun}, {:.1}s)` count/noun/seconds grammar owner.
//! 3. The count is `test_count.unwrap_or(0)` on an
//!    `Option<usize>` — a `None` test-count parse (empty output, a
//!    format the parser did not recognize) falls back to `0`
//!    rather than propagating an error or omitting the count from
//!    the render.
//! 4. The noun is the literal `&'static str` `"tests"` — not
//!    `"cases"`, `"assertions"`, or a plural variant, and pinned as
//!    a `pub const` so a rename lands in one place.
//!
//! Two pre-lift sites past the "two occurrences is a coincidence,
//! three is a law" floor (THEORY.md §VI.1) — pinning the fusion here
//! forecloses the third-site copy-paste before it lands. A future
//! `commands/test.rs::run_rust_tests` success-arm addition, a
//! forthcoming `commands/e2e.rs` unit-count reporter, or a migration
//! of the `commands/integration_tests.rs` per-suite step-pass onto
//! the same shape all reach for this primitive on first grep rather
//! than by copy-pasting the four-argument stanza.
//!
//! # Distinct from the sibling msg-composition primitives
//!
//! [`crate::repo::msg_with_count_noun_secs_1`] is the byte-form owner
//! of the `<msg> ({count} {noun}, {:.1}s)` grammar itself and
//! consumes an arbitrary noun; it does NOT pin the noun,
//! [`crate::ui::print_step_pass`] as the sink, or `test_count.
//! unwrap_or(0)` as the count-resolution. This module owns the
//! four-invariant fusion the two `test_count.unwrap_or(0) + "tests"
//! + print_step_pass` sites share.
//!
//! [`crate::repo::msg_with_two_counts_and_secs_1`] (59ac6f0) is the
//! two-count-per-line dialect — one message plus two count/noun
//! tuples — and does not overlap: this primitive is single-count.
//!
//! [`crate::frontend_lint_failure_report::report_frontend_lint_failure`]
//! (a01e9c5) is the sibling fusion on the FAILURE arm — it composes
//! `print_step_failure` + `msg_with_two_counts_and_secs_1` +
//! diagnostic collection. This primitive is that fusion's peer on
//! the SUCCESS arm.
//!
//! # THEORY grounding
//!
//! - THEORY.md §I.5 (duplication budget zero; every recurring shape
//!   becomes a helper before it becomes duplicated code): two byte-
//!   close sibling stanzas past the two-occurrence coincidence
//!   threshold. The primitive collapses the fusion at ONE
//!   construction surface.
//! - THEORY.md §II.1 invariant 5 (composition preserves proofs):
//!   composing [`crate::ui::print_step_pass`] and
//!   [`crate::repo::msg_with_count_noun_secs_1`] here inherits each
//!   peer's contract without repetition — a drift at either lands at
//!   ONE peer and reaches this fusion by construction.
//! - THEORY.md §V.2 (typed absorption): the "print-step-pass +
//!   count-noun-secs render + `test_count.unwrap_or(0)` on `Option<
//!   usize>`" composition is a single named concept; both callers
//!   cite it rather than restating the four-argument stanza.

/// The canonical noun every pre-lift consumer spelled as the third
/// argument to [`crate::repo::msg_with_count_noun_secs_1`]. Pinning
/// it as a `pub const` closes the drift class so a future rename
/// (say to `"test cases"` or `"unit tests"`) lands at ONE line
/// rather than at every consumer.
pub const TEST_COUNT_PASS_NOUN: &str = "tests";

/// Render the pre-lift step-pass message body — the
/// `<label> ({count} tests, {:.1}s)` composition every consumer
/// spliced through [`crate::repo::msg_with_count_noun_secs_1`] with
/// [`TEST_COUNT_PASS_NOUN`] as the noun and `test_count.unwrap_or(0)`
/// as the count. Byte-oracle sibling of [`print_test_count_pass_step`]
/// for tests that need the composed string without the print side
/// effect.
pub fn render_test_count_pass_step<L: std::fmt::Display>(
    label: L,
    test_count: Option<usize>,
    duration: std::time::Duration,
) -> String {
    crate::repo::msg_with_count_noun_secs_1(
        label,
        test_count.unwrap_or(0),
        TEST_COUNT_PASS_NOUN,
        duration,
    )
}

/// Print the pre-lift `✓ <label> ({count} tests, {:.1}s)`
/// step-pass row to stdout via [`crate::ui::print_step_pass`] with
/// the canonical [`render_test_count_pass_step`] message body.
///
/// `label` accepts any [`std::fmt::Display`] so both `&'static str`
/// (`"Tests passed"`) and owned `String` (a future
/// `format!("{} tests passed", suite)`-shaped label) flow through
/// without an intermediate `.to_string()` at the call site — mirrors
/// [`crate::repo::msg_with_count_noun_secs_1`]'s own `M: Display`
/// bound.
///
/// `test_count` is an `Option<usize>` — `None` falls back to `0`,
/// matching every pre-lift caller's `.unwrap_or(0)` spelling. A `None`
/// means the caller's own count parser could not recognize the tool's
/// summary line; falling back to `0` keeps the render honest (the
/// row still shows "0 tests" rather than omitting the count) and
/// leaves the responsibility for warning about unexpected output on
/// the caller (`commands/frontend_validation.rs::run_unit_tests`
/// short-circuits to a [`crate::ui::print_step_warn`] `"No unit tests
/// found"` row before reaching this success arm on `test_count ==
/// Some(0)`).
pub fn print_test_count_pass_step<L: std::fmt::Display>(
    label: L,
    test_count: Option<usize>,
    duration: std::time::Duration,
) {
    crate::ui::print_step_pass(&render_test_count_pass_step(label, test_count, duration));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::Duration;

    /// Pin the exact byte content of the noun const. A future edit
    /// that renamed the noun (say to `"test cases"` or `"unit
    /// tests"`) trips this assertion before the change reaches any
    /// consumer.
    #[test]
    fn noun_const_matches_pre_lift_byte_form() {
        assert_eq!(TEST_COUNT_PASS_NOUN, "tests");
    }

    /// Byte-oracle for the Some-branch render: pins the pre-lift
    /// `<label> ({count} tests, {:.1}s)` composition — the four
    /// grammar invariants (single space between label and paren,
    /// count-space-noun ordering, `, ` comma-space separator, one
    /// decimal-place seconds tag) — at one place.
    #[test]
    fn render_with_some_count_matches_pre_lift_byte_form() {
        assert_eq!(
            render_test_count_pass_step("Tests passed", Some(42), Duration::from_millis(1234)),
            "Tests passed (42 tests, 1.2s)"
        );
    }

    /// Byte-oracle for the None-branch fallback: `test_count.
    /// unwrap_or(0)` renders as `"0 tests"`, matching every pre-lift
    /// caller's fallback spelling. A future edit that swapped
    /// `.unwrap_or(0)` for `.unwrap_or(1)` or dropped the fallback
    /// (propagating `None` as `"? tests"` or omitting the count
    /// altogether) trips this assertion.
    #[test]
    fn render_with_none_count_falls_back_to_zero() {
        assert_eq!(
            render_test_count_pass_step("Unit tests passed", None, Duration::from_millis(500)),
            "Unit tests passed (0 tests, 0.5s)"
        );
    }

    /// Full-text byte-oracle for the `commands/prerelease.rs::
    /// run_cargo_test` G4 success arm: the pre-lift label was
    /// `"Tests passed"` verbatim. Ensures a rename to `"Cargo tests
    /// passed"` or `"Backend tests passed"` regresses this assertion.
    #[test]
    fn prerelease_g4_full_text_matches_pre_lift_literal() {
        assert_eq!(
            render_test_count_pass_step("Tests passed", Some(5531), Duration::from_millis(2100)),
            "Tests passed (5531 tests, 2.1s)"
        );
    }

    /// Full-text byte-oracle for the
    /// `commands/frontend_validation.rs::run_unit_tests` vitest
    /// success arm: the pre-lift label was `"Unit tests passed"`
    /// verbatim.
    #[test]
    fn frontend_unit_tests_full_text_matches_pre_lift_literal() {
        assert_eq!(
            render_test_count_pass_step("Unit tests passed", Some(12), Duration::from_millis(340)),
            "Unit tests passed (12 tests, 0.3s)"
        );
    }

    /// Display-bound coverage: the `L: Display` bound flows both a
    /// borrowed `&'static str` and an owned `String` through the same
    /// primitive without an intermediate `.to_string()` at the call
    /// site. A regression that narrowed the bound (say to `&str`
    /// alone) would ripple to every caller-side `format!(...)`-shaped
    /// label at the type check.
    #[test]
    fn label_accepts_display_bound_owned_and_borrowed() {
        let owned: String = format!("{} tests passed", "Backend");
        assert_eq!(
            render_test_count_pass_step(&owned, Some(1), Duration::from_millis(100)),
            "Backend tests passed (1 tests, 0.1s)"
        );
        assert_eq!(
            render_test_count_pass_step("Tests passed", Some(1), Duration::from_millis(100)),
            "Tests passed (1 tests, 0.1s)"
        );
    }

    /// Signature pin: the print helper accepts a `L: Display` label,
    /// an `Option<usize>` count, and a `Duration`, and returns `()`.
    /// A future edit that widened the signature (say to take a
    /// noun override, or to return `io::Result<()>`) would ripple to
    /// every caller and trip the type check.
    #[test]
    fn print_helper_signature_pins_three_arg_shape() {
        let _: fn(&'static str, Option<usize>, Duration) = print_test_count_pass_step;
    }

    /// Slice the module's own source to the production body so the
    /// tests below can count delegation call sites without matching
    /// against needle-mentions inside their own `assert!` diagnostic
    /// messages.
    fn production_body() -> String {
        let source = include_str!("test_count_pass_step.rs");
        let cutoff = source
            .find("#[cfg(test)]")
            .expect("production body ends at the test cfg attr");
        source[..cutoff].to_string()
    }

    /// Delegation pin: the render helper's body MUST forward through
    /// [`crate::repo::msg_with_count_noun_secs_1`] exactly once. A
    /// future edit that inlined the `format!` template here (bypassing
    /// the peer primitive) trips this assertion — the four-invariant
    /// grammar (paren shape, tuple ordering, seconds unit, one
    /// decimal place) lives at exactly ONE body.
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
    /// [`crate::ui::print_step_pass`] exactly once. A future edit
    /// that swapped in a sibling sink ([`crate::ui::print_step_check`]
    /// or [`crate::ui::print_bright_step_pass`]) trips this
    /// assertion.
    #[test]
    fn print_helper_delegates_through_ui_print_step_pass_once() {
        let body = production_body();
        let hits = crate::test_support::code_line_hits(&body, "crate::ui::print_step_pass(");
        assert_eq!(
            hits.len(),
            1,
            "production body must forward through \
             `crate::ui::print_step_pass(...)` at exactly one site — \
             the print helper's body. Found {}: {:#?}",
            hits.len(),
            hits
        );
    }

    /// Positive delegation shield for `commands/prerelease.rs`: the
    /// G4 `run_cargo_test` success arm MUST forward through this
    /// primitive at least once. A migration that dropped the site
    /// outright would leave the negative "no raw stanza survives"
    /// scan (below) trivially satisfied by absence but this positive
    /// count still fails.
    #[test]
    fn prerelease_module_forwards_through_print_helper() {
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let path = commands_dir.join("prerelease.rs");
        let source = std::fs::read_to_string(&path).unwrap();
        let forwards =
            crate::test_support::code_line_hits(&source, "print_test_count_pass_step(").len();
        assert!(
            forwards >= 1,
            "prerelease.rs must forward at least 1 test-count \
             step-pass stanza through \
             `crate::test_count_pass_step::print_test_count_pass_step(`; \
             found {forwards}. A dropped call would leave the negative \
             raw-stanza scan satisfied by absence.",
        );
    }

    /// Positive delegation shield for
    /// `commands/frontend_validation.rs`: the `run_unit_tests`
    /// vitest success arm MUST forward through this primitive at
    /// least once.
    #[test]
    fn frontend_validation_module_forwards_through_print_helper() {
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let path = commands_dir.join("frontend_validation.rs");
        let source = std::fs::read_to_string(&path).unwrap();
        let forwards =
            crate::test_support::code_line_hits(&source, "print_test_count_pass_step(").len();
        assert!(
            forwards >= 1,
            "frontend_validation.rs must forward at least 1 \
             test-count step-pass stanza through \
             `crate::test_count_pass_step::print_test_count_pass_step(`; \
             found {forwards}.",
        );
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` may respell the fused stanza inline any
    /// more. The needle is the two-line fusion
    /// `crate::ui::print_step_pass(&crate::repo::msg_with_count_noun_secs_1(`
    /// on the same source line, WITH a `"tests"` third argument
    /// somewhere in the same call. Any future consumer that wants
    /// the same row reaches for
    /// [`print_test_count_pass_step`] on first grep, not by
    /// copy-pasting the stanza from an existing site.
    ///
    /// The scan permits the fused sink for OTHER nouns (a future
    /// `("Files scanned", n, "files", d)` composition is not a
    /// respelling of this primitive) — the noun literal `"tests"`
    /// is the discriminator.
    #[test]
    fn no_command_module_still_respells_raw_test_count_pass_stanza() {
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        // Reconstruct the fused-sink needle at test time so this
        // shield's own source text does not false-match itself.
        let fused_needle = format!(
            "crate::ui::print_step_pass(&crate::repo::{}(",
            "msg_with_count_noun_secs_1"
        );
        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let lines: Vec<&str> = source.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                let t = line.trim_start();
                if t.starts_with("//") {
                    continue;
                }
                if !line.contains(&fused_needle) {
                    continue;
                }
                // Look forward up to 6 lines for the `"tests"`
                // noun literal on the third-argument position.
                // The pre-lift stanza spans five lines from the
                // opening `crate::ui::print_step_pass(` down to the
                // closing `));`, and the noun literal lands on
                // either the third or fourth of those lines.
                let end = (i + 6).min(lines.len());
                let window = &lines[i..end];
                let has_tests_noun = window.iter().any(|w| {
                    let wt = w.trim_start();
                    if wt.starts_with("//") {
                        return false;
                    }
                    // Match the exact `"tests",` third-argument
                    // spelling (with or without trailing comma) so
                    // a `"tests passed"` label substring does not
                    // false-match.
                    let trimmed = w.trim();
                    trimmed == "\"tests\"," || trimmed == "\"tests\""
                });
                if has_tests_noun {
                    offenders.push((path.clone(), i + 1, line.trim().to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw fused `print_step_pass(&msg_with_count_noun_secs_1(<label>, \
             <count>, \"tests\", <d>))` stanza(s) survive under \
             `commands/` — route each through \
             `crate::test_count_pass_step::print_test_count_pass_step(\
             <label>, <test_count>, <duration>)` instead:\n{offenders:#?}"
        );
    }
}
