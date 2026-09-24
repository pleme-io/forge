//! Pre-deployment test-suite outcome step: the pre-lift 2 sibling
//! `crate::ui::print_step_{pass|failure}(&format!("{} - {:.2}s{}",
//! suite.name, result.duration.as_secs_f64(), test_info.bright_white()))`
//! stanzas collapsed onto one typed primitive.
//!
//! # Pre-lift census — two sibling stanzas, one outcome grammar
//!
//! Two consumer sites in
//! `commands/integration_tests.rs::execute_pre_deployment_test_suite`
//! each spelled the same 10-line
//! `let test_info = result.test_counts.as_ref().map(|c| format!(...)).unwrap_or_default();
//!  crate::ui::print_step_{pass|failure}(&format!("{} - {:.2}s{}", suite.name,
//!  result.duration.as_secs_f64(), test_info.bright_white()));`
//! composition inline against the per-branch counts formatter:
//!
//! 1. `commands/integration_tests.rs::execute_pre_deployment_test_suite`
//!    (pre-lift `if result.success { … }` pass branch, counts
//!    formatter `format!(" [{} passed]", c.passed)`,
//!    `print_step_pass` dispatch).
//! 2. `commands/integration_tests.rs::execute_pre_deployment_test_suite`
//!    (pre-lift `else { … }` fail branch, counts formatter
//!    `format!(" [{} passed, {} failed]", c.passed, c.failed)`,
//!    `print_step_failure` dispatch).
//!
//! Both stanzas share the outer message shape
//! `"{} - {:.2}s{}"` (suite name + `" - "` connective + two-decimal
//! seconds + `s` unit + painted test_info tail) and the
//! `test_info.bright_white()` ANSI painting on the tail. The two
//! divergences are (a) the `format!(" [<counts>]", …)` template inside
//! the counts fragment, and (b) the `print_step_{pass|failure}`
//! dispatch. Both divergences ride on the same `success: bool`
//! discriminator the pre-lift branch already carried.
//!
//! # Companion typed enum vs. bool
//!
//! The enum makes the two divergences one — the same `TestOutcome`
//! variant selects both the counts template and the step-print
//! dispatch. Pre-lift, a caller that swapped `print_step_pass` for
//! `print_step_failure` but forgot to swap the counts formatter (or
//! vice versa) had no structural block; post-lift the pair is
//! projected from the single [`PreDeploymentTestSuiteOutcome`]
//! variant. The two-arm rendering carries no operator-visible
//! divergence at the byte level — this is a positive-shape
//! consolidation, not a defect fix.
//!
//! # Byte-oracle discipline
//!
//! The `write_*` sibling projects the same bytes the pre-lift stanza
//! produced through `write_step_{pass|failure}` composed with the same
//! `format!("{} - {:.2}s{}", …)` message. A byte-oracle test wires the
//! primitive against `write_step_{pass|failure}` on the composed
//! message and asserts equality on the underlying `Vec<u8>` so the
//! three-space indent, the pass-side green `✅ ` glyph and the
//! fail-side red `❌ ` glyph, and the `.bright_white()` ANSI wrapper
//! on the test-info tail all reproduce byte-for-byte.

use colored::Colorize;
use std::fmt::Write as _;
use std::io;
use std::time::Duration;

use crate::commands::integration_tests::TestCounts;

/// The literal `" - "` connective the pre-lift two sites spelled
/// between the suite name and the duration. Constant-lifted so a
/// future rewording (a `" · "` middle-dot, a `" @ "` at-sign) lands
/// on exactly one line and both sibling arms stay in lockstep.
pub const PRE_DEPLOYMENT_TEST_SUITE_OUTCOME_NAME_DUR_CONNECTIVE: &str = " - ";

/// The literal `" ["` counts-fragment opener the pre-lift two sites
/// spelled before the counts payload. Split from
/// [`PRE_DEPLOYMENT_TEST_SUITE_OUTCOME_COUNTS_CLOSER`] so the two
/// bracket halves can be pinned independently and a future refinement
/// (a `" ("`-`")"` parenthesis pair, a `" ⟨"`-`"⟩"` angle-bracket
/// pair) rotates one side at a time.
pub const PRE_DEPLOYMENT_TEST_SUITE_OUTCOME_COUNTS_OPENER: &str = " [";

/// The literal `"]"` counts-fragment closer the pre-lift two sites
/// spelled after the counts payload. Split from
/// [`PRE_DEPLOYMENT_TEST_SUITE_OUTCOME_COUNTS_OPENER`].
pub const PRE_DEPLOYMENT_TEST_SUITE_OUTCOME_COUNTS_CLOSER: &str = "]";

/// The closed set of pre-deployment test-suite outcomes that emit
/// through this primitive. Each variant pins BOTH the counts fragment
/// shape (`" [{passed} passed]"` vs `" [{passed} passed, {failed}
/// failed]"`) AND the step-print dispatch (`print_step_pass` vs
/// `print_step_failure`) in one match-arm — the pre-lift `success:
/// bool` gated both selections separately, and a caller that flipped
/// one but not the other had no structural block. The enum makes the
/// pair one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreDeploymentTestSuiteOutcome {
    /// Pre-lift `if result.success { … }` pass branch. Counts
    /// fragment: `" [{passed} passed]"` (only the pass count is
    /// operator-visible on the pass arm). Dispatched through
    /// [`crate::ui::print_step_pass`] with the green `✅ ` glyph.
    Passed,
    /// Pre-lift `else { … }` fail branch. Counts fragment:
    /// `" [{passed} passed, {failed} failed]"` (both counts are
    /// operator-visible on the fail arm — the pass count contextualises
    /// how many tests ran successfully before the fail). Dispatched
    /// through [`crate::ui::print_step_failure`] with the red `❌ `
    /// glyph.
    Failed,
}

impl PreDeploymentTestSuiteOutcome {
    /// The pre-lift `format!(" [{...}]", ...)` counts-fragment
    /// projection the two sibling stanzas spelled inline through
    /// `result.test_counts.as_ref().map(|c| format!(...)).unwrap_or_default()`.
    /// A `None` counts value collapses to an empty fragment — the
    /// pre-lift `.unwrap_or_default()` reached the same shape.
    pub fn counts_fragment(&self, counts: Option<&TestCounts>) -> String {
        match (self, counts) {
            (Self::Passed, Some(c)) => format!(
                "{}{} passed{}",
                PRE_DEPLOYMENT_TEST_SUITE_OUTCOME_COUNTS_OPENER,
                c.passed,
                PRE_DEPLOYMENT_TEST_SUITE_OUTCOME_COUNTS_CLOSER,
            ),
            (Self::Failed, Some(c)) => format!(
                "{}{} passed, {} failed{}",
                PRE_DEPLOYMENT_TEST_SUITE_OUTCOME_COUNTS_OPENER,
                c.passed,
                c.failed,
                PRE_DEPLOYMENT_TEST_SUITE_OUTCOME_COUNTS_CLOSER,
            ),
            (_, None) => String::new(),
        }
    }
}

/// Compose the pre-lift `format!("{} - {:.2}s{}", suite.name,
/// duration.as_secs_f64(), test_info.bright_white())` message shape
/// without touching the writer. Split from
/// [`print_pre_deployment_test_suite_outcome_step`] so the pure-string
/// projection can be pinned by unit tests without capturing stdout.
///
/// The `counts_fragment_painted` argument is the caller's pre-painted
/// counts fragment (the pre-lift stanzas fed
/// `test_info.bright_white()` here — an ANSI-wrapped `String`). Split
/// so the byte-oracle test can compose the same painted bytes without
/// re-deriving the color grammar.
pub fn format_pre_deployment_test_suite_outcome_message(
    suite_name: &str,
    duration: Duration,
    counts_fragment_painted: &str,
) -> String {
    let mut out = String::new();
    // `write!` into `String` never fails.
    let _ = write!(
        out,
        "{}{}{:.2}s{}",
        suite_name,
        PRE_DEPLOYMENT_TEST_SUITE_OUTCOME_NAME_DUR_CONNECTIVE,
        duration.as_secs_f64(),
        counts_fragment_painted,
    );
    out
}

/// Print the one-line `   {glyph} <suite> - <secs>s<counts>`
/// pre-deployment test-suite outcome grammar through
/// [`crate::ui::print_step_pass`] (Passed) or
/// [`crate::ui::print_step_failure`] (Failed), composing the message
/// through [`format_pre_deployment_test_suite_outcome_message`] with
/// the `.bright_white()`-painted counts fragment so the pre-lift
/// ANSI palette on the counts tail reproduces byte-for-byte.
pub fn print_pre_deployment_test_suite_outcome_step(
    outcome: PreDeploymentTestSuiteOutcome,
    suite_name: &str,
    duration: Duration,
    counts: Option<&TestCounts>,
) {
    let painted = outcome.counts_fragment(counts).bright_white().to_string();
    let message = format_pre_deployment_test_suite_outcome_message(suite_name, duration, &painted);
    match outcome {
        PreDeploymentTestSuiteOutcome::Passed => crate::ui::print_step_pass(&message),
        PreDeploymentTestSuiteOutcome::Failed => crate::ui::print_step_failure(&message),
    }
}

/// Writer-taking sibling to
/// [`print_pre_deployment_test_suite_outcome_step`]. Emits the same
/// one-line `   {glyph} <suite> - <secs>s<counts>` via
/// [`crate::ui::write_step_pass`] or [`crate::ui::write_step_failure`]
/// against the supplied writer so tests can pin the pre-lift
/// byte-shape (three-space indent, per-variant glyph and ANSI palette
/// on the glyph, `" - "` name-duration connective, `{:.2}s` seconds
/// projection, `.bright_white()` ANSI wrapper on the counts tail, and
/// the per-variant counts template) without capturing stdout.
pub fn write_pre_deployment_test_suite_outcome_step<W: io::Write>(
    w: &mut W,
    outcome: PreDeploymentTestSuiteOutcome,
    suite_name: &str,
    duration: Duration,
    counts: Option<&TestCounts>,
) -> io::Result<()> {
    let painted = outcome.counts_fragment(counts).bright_white().to_string();
    let message = format_pre_deployment_test_suite_outcome_message(suite_name, duration, &painted);
    match outcome {
        PreDeploymentTestSuiteOutcome::Passed => crate::ui::write_step_pass(w, &message),
        PreDeploymentTestSuiteOutcome::Failed => crate::ui::write_step_failure(w, &message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Constant pin: the name-duration connective the pre-lift two
    /// sites spelled between the suite name and the duration is the
    /// verbatim `" - "` fragment.
    #[test]
    fn pre_deployment_test_suite_outcome_name_dur_connective_matches_pre_lift_literal() {
        assert_eq!(PRE_DEPLOYMENT_TEST_SUITE_OUTCOME_NAME_DUR_CONNECTIVE, " - ");
    }

    /// Constant pin: the counts-fragment opener the pre-lift two
    /// sites spelled before the counts payload is the verbatim `" ["`
    /// fragment.
    #[test]
    fn pre_deployment_test_suite_outcome_counts_opener_matches_pre_lift_literal() {
        assert_eq!(PRE_DEPLOYMENT_TEST_SUITE_OUTCOME_COUNTS_OPENER, " [");
    }

    /// Constant pin: the counts-fragment closer the pre-lift two
    /// sites spelled after the counts payload is the verbatim `"]"`
    /// fragment.
    #[test]
    fn pre_deployment_test_suite_outcome_counts_closer_matches_pre_lift_literal() {
        assert_eq!(PRE_DEPLOYMENT_TEST_SUITE_OUTCOME_COUNTS_CLOSER, "]");
    }

    /// Counts-fragment pin (Passed, Some): the pre-lift
    /// `format!(" [{} passed]", c.passed)` template projects
    /// byte-identically through the primitive.
    #[test]
    fn counts_fragment_passed_some_matches_pre_lift_template() {
        let counts = TestCounts {
            passed: 42,
            failed: 0,
            skipped: 0,
        };
        assert_eq!(
            PreDeploymentTestSuiteOutcome::Passed.counts_fragment(Some(&counts)),
            " [42 passed]",
        );
    }

    /// Counts-fragment pin (Failed, Some): the pre-lift
    /// `format!(" [{} passed, {} failed]", c.passed, c.failed)`
    /// template projects byte-identically through the primitive.
    #[test]
    fn counts_fragment_failed_some_matches_pre_lift_template() {
        let counts = TestCounts {
            passed: 17,
            failed: 3,
            skipped: 0,
        };
        assert_eq!(
            PreDeploymentTestSuiteOutcome::Failed.counts_fragment(Some(&counts)),
            " [17 passed, 3 failed]",
        );
    }

    /// Counts-fragment pin (None): the pre-lift
    /// `.map(...).unwrap_or_default()` produced an empty `String` when
    /// `test_counts` was `None`; both variants project the same empty
    /// fragment through the primitive.
    #[test]
    fn counts_fragment_none_projects_empty_for_both_variants() {
        assert_eq!(
            PreDeploymentTestSuiteOutcome::Passed.counts_fragment(None),
            "",
        );
        assert_eq!(
            PreDeploymentTestSuiteOutcome::Failed.counts_fragment(None),
            "",
        );
    }

    /// Format pin: the message projection composes exactly
    /// `"<suite> - <secs>s<counts_painted>"` — the pre-lift
    /// `format!(...)` byte-shape both sibling sites spelled inline.
    /// Uses an empty painted fragment so the assertion pins the outer
    /// shape without depending on the runtime ANSI-detection heuristic.
    #[test]
    fn format_pre_deployment_test_suite_outcome_message_matches_pre_lift_shape() {
        assert_eq!(
            format_pre_deployment_test_suite_outcome_message(
                "integration-suite",
                Duration::from_millis(1_234),
                "",
            ),
            "integration-suite - 1.23s",
        );
        assert_eq!(
            format_pre_deployment_test_suite_outcome_message(
                "e2e-suite",
                Duration::from_millis(12_500),
                " [42 passed, 3 failed]",
            ),
            "e2e-suite - 12.50s [42 passed, 3 failed]",
        );
    }

    /// Byte-oracle (Passed, Some): the writer sibling projects the
    /// pre-lift `crate::ui::print_step_pass(&format!("{} - {:.2}s{}",
    /// suite.name, result.duration.as_secs_f64(),
    /// test_info.bright_white()))` byte-shape verbatim — the same
    /// three-space indent, the same green `✅ ` glyph and its ANSI
    /// palette, the same `" - "` name-duration connective, the same
    /// `{:.2}s` seconds projection, the same `.bright_white()` ANSI
    /// wrapper on the counts tail, and the pass-variant `" [{} passed]"`
    /// counts template. Compares against a direct
    /// [`crate::ui::write_step_pass`] against the same composed
    /// message so the pin holds whether ANSI is auto-enabled or
    /// auto-disabled on the host running the suite.
    #[test]
    fn write_pre_deployment_test_suite_outcome_step_passed_matches_pre_lift_shape() {
        let counts = TestCounts {
            passed: 42,
            failed: 0,
            skipped: 0,
        };
        let mut primitive: Vec<u8> = Vec::new();
        write_pre_deployment_test_suite_outcome_step(
            &mut primitive,
            PreDeploymentTestSuiteOutcome::Passed,
            "integration-suite",
            Duration::from_millis(1_234),
            Some(&counts),
        )
        .expect("write against a Vec<u8> writer must succeed");

        // Reconstruct the pre-lift composition byte-for-byte: the same
        // `format!("{} - {:.2}s{}", …, test_info.bright_white())` fed
        // through `crate::ui::write_step_pass`.
        let painted = " [42 passed]".bright_white().to_string();
        let expected_message = format!(
            "{}{}{:.2}s{}",
            "integration-suite",
            PRE_DEPLOYMENT_TEST_SUITE_OUTCOME_NAME_DUR_CONNECTIVE,
            Duration::from_millis(1_234).as_secs_f64(),
            painted,
        );
        let mut peer: Vec<u8> = Vec::new();
        crate::ui::write_step_pass(&mut peer, &expected_message)
            .expect("peer write against a Vec<u8> writer must succeed");
        assert_eq!(
            primitive, peer,
            "the primitive's writer sibling must project the same byte-shape as \
             `crate::ui::write_step_pass(w, &format!(\"{{}} - {{:.2}}s{{}}\", \
             \"integration-suite\", 1.234, \" [42 passed]\".bright_white()))`",
        );
    }

    /// Byte-oracle (Failed, Some): the writer sibling projects the
    /// pre-lift `crate::ui::print_step_failure(&format!("{} - {:.2}s{}",
    /// suite.name, result.duration.as_secs_f64(),
    /// test_info.bright_white()))` byte-shape verbatim — the fail
    /// arm's red `❌ ` glyph and the `" [{} passed, {} failed]"`
    /// counts template both reproduce.
    #[test]
    fn write_pre_deployment_test_suite_outcome_step_failed_matches_pre_lift_shape() {
        let counts = TestCounts {
            passed: 17,
            failed: 3,
            skipped: 0,
        };
        let mut primitive: Vec<u8> = Vec::new();
        write_pre_deployment_test_suite_outcome_step(
            &mut primitive,
            PreDeploymentTestSuiteOutcome::Failed,
            "e2e-suite",
            Duration::from_millis(12_500),
            Some(&counts),
        )
        .expect("write against a Vec<u8> writer must succeed");

        let painted = " [17 passed, 3 failed]".bright_white().to_string();
        let expected_message = format!(
            "{}{}{:.2}s{}",
            "e2e-suite",
            PRE_DEPLOYMENT_TEST_SUITE_OUTCOME_NAME_DUR_CONNECTIVE,
            Duration::from_millis(12_500).as_secs_f64(),
            painted,
        );
        let mut peer: Vec<u8> = Vec::new();
        crate::ui::write_step_failure(&mut peer, &expected_message)
            .expect("peer write against a Vec<u8> writer must succeed");
        assert_eq!(
            primitive, peer,
            "the primitive's writer sibling must project the same byte-shape as \
             `crate::ui::write_step_failure(w, &format!(\"{{}} - {{:.2}}s{{}}\", \
             \"e2e-suite\", 12.500, \" [17 passed, 3 failed]\".bright_white()))`",
        );
    }

    /// Byte-oracle (None-counts): the writer sibling projects the
    /// pre-lift shape when `test_counts` is absent — the counts
    /// fragment collapses to empty, and the `.bright_white()` ANSI
    /// wrapper on an empty string projects the same bytes both sides
    /// spelled inline.
    #[test]
    fn write_pre_deployment_test_suite_outcome_step_none_counts_matches_pre_lift_shape() {
        let mut primitive: Vec<u8> = Vec::new();
        write_pre_deployment_test_suite_outcome_step(
            &mut primitive,
            PreDeploymentTestSuiteOutcome::Passed,
            "solo-suite",
            Duration::from_millis(500),
            None,
        )
        .expect("write against a Vec<u8> writer must succeed");

        let painted = "".bright_white().to_string();
        let expected_message = format!(
            "{}{}{:.2}s{}",
            "solo-suite",
            PRE_DEPLOYMENT_TEST_SUITE_OUTCOME_NAME_DUR_CONNECTIVE,
            Duration::from_millis(500).as_secs_f64(),
            painted,
        );
        let mut peer: Vec<u8> = Vec::new();
        crate::ui::write_step_pass(&mut peer, &expected_message)
            .expect("peer write against a Vec<u8> writer must succeed");
        assert_eq!(
            primitive, peer,
            "the primitive's writer sibling must project the same byte-shape as \
             `crate::ui::write_step_pass(w, &format!(\"{{}} - {{:.2}}s{{}}\", \
             \"solo-suite\", 0.500, \"\".bright_white()))`",
        );
    }

    /// Negative caller shield: no consumer under `src/commands/`
    /// re-spells the pre-lift inline
    /// `crate::ui::print_step_{pass|failure}(&format!("{} - {:.2}s{}",
    /// suite.name, result.duration.as_secs_f64(),
    /// test_info.bright_white()))` composition against this primitive.
    /// Grep for the outer signature `- {:.2}s{}` inside a
    /// `print_step_{pass|failure}(&format!(` head in any file under
    /// `commands/`; any hit resurrects the pre-lift shape and must
    /// route through
    /// [`print_pre_deployment_test_suite_outcome_step`] instead.
    #[test]
    fn no_command_file_re_spells_pre_deployment_test_suite_outcome_shape_inline() {
        use std::fs;
        use std::path::Path;

        let commands_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/commands");
        let residue: Vec<String> = fs::read_dir(&commands_dir)
            .expect("commands/ dir must be readable")
            .flatten()
            .filter_map(|entry| {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                    return None;
                }
                let src = fs::read_to_string(&path).ok()?;
                if src.contains("- {:.2}s{}")
                    && (src.contains("print_step_pass(&format!(")
                        || src.contains("print_step_failure(&format!("))
                    && src.contains(".bright_white()")
                {
                    Some(
                        path.strip_prefix(env!("CARGO_MANIFEST_DIR"))
                            .unwrap_or(&path)
                            .display()
                            .to_string(),
                    )
                } else {
                    None
                }
            })
            .collect();
        assert!(
            residue.is_empty(),
            "the pre-lift `print_step_{{pass|failure}}(&format!(\"{{}} - {{:.2}}s{{}}\", \
             suite.name, dur.as_secs_f64(), test_info.bright_white()))` composition \
             must not resurface inline under src/commands/ — every consumer must \
             route through \
             `print_pre_deployment_test_suite_outcome_step`. Residual sites: {:?}",
            residue,
        );
    }

    /// Positive-delegation shield: this module's own source must
    /// forward BOTH the `Passed` and the `Failed` variant through
    /// `crate::ui::{print_step_pass, print_step_failure}(` at a bounded
    /// number of construction sites. Both `commands/integration_tests.rs`
    /// was struck from the ui.rs `print_step_{pass|failure}_callers_
    /// delegate_through_primitive` shield lists because the sibling
    /// primitive is now the sole caller for the pre-lift stanza; the
    /// invariant "every step-pass / step-failure grammar in the crate
    /// delegates through the ui primitives" holds through THIS module
    /// instead. Two positive delegations (one per outcome), pinned
    /// here so a well-meaning refactor that inlined the primitives
    /// (rebuilding the `format!("   ✅ ..." / "   ❌ ..."` shape from
    /// raw bytes) or routed through a different sink (`tracing::info!`
    /// / `println!`) fails the shield and rotates back through the
    /// intended primitives.
    #[test]
    fn primitive_body_delegates_through_ui_step_pass_and_step_failure() {
        const SOURCE: &str = include_str!("pre_deployment_test_suite_outcome_step.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            SOURCE,
            "pre_deployment_test_suite_outcome_step.rs",
        );
        assert!(
            body.contains("crate::ui::print_step_pass("),
            "the module body must forward the `Passed` variant through \
             `crate::ui::print_step_pass(` — the `Passed` arm's step-print \
             dispatch lives at exactly this construction surface."
        );
        assert!(
            body.contains("crate::ui::print_step_failure("),
            "the module body must forward the `Failed` variant through \
             `crate::ui::print_step_failure(` — the `Failed` arm's step-print \
             dispatch lives at exactly this construction surface."
        );
        assert!(
            body.contains("crate::ui::write_step_pass("),
            "the module body must forward the writer-taking `Passed` variant \
             through `crate::ui::write_step_pass(` — the byte-oracle sibling \
             pins this delegation and a future rewrite that skipped the writer \
             split would break both the fail-before-pass tests and the pre-lift \
             ANSI grammar contract."
        );
        assert!(
            body.contains("crate::ui::write_step_failure("),
            "the module body must forward the writer-taking `Failed` variant \
             through `crate::ui::write_step_failure(` — the byte-oracle sibling \
             pins this delegation."
        );
    }
}
