//! Frontend-lint failure reporting primitive — the fused
//! "two-count `print_step_failure` header + `print_and_collect_lint_
//! diagnostic_lines` collection" grammar the two sibling failure
//! branches of `commands/frontend_validation.rs::{run_lint_with_config
//! (ESLint arm), run_biome_lint (check arm)}` respell byte-for-byte
//! pre-lift.
//!
//! # Pre-lift census — two sibling stanzas
//!
//! Both sites (post the 59ac6f0 two-count and 584c20c collection
//! lifts) shared the identical fused shape:
//!
//! ```ignore
//! crate::ui::print_step_failure(&crate::repo::msg_with_two_counts_and_secs_1(
//!     <label>,
//!     <errors>,
//!     "errors",
//!     <warnings>,
//!     "warnings",
//!     duration,
//! ));
//!
//! let details =
//!     crate::frontend_lint_diagnostic_collect::print_and_collect_lint_diagnostic_lines(
//!         &combined,
//!     );
//!
//! Ok((false, details))
//! ```
//!
//! Only the `<label>`, `<errors>`, `<warnings>`, `duration`, and
//! `combined` values differ across the two sites; the wiring — the
//! `"errors"` / `"warnings"` noun pair passed to
//! [`crate::repo::msg_with_two_counts_and_secs_1`], the fixed
//! print-step-failure header rendering, the collection pass over
//! `combined`, and the returned `Vec<String>` funnelled into
//! `Ok((false, details))` — was identical.
//!
//! 1. `commands/frontend_validation.rs::run_lint_with_config`
//!    (pre-lift ~L249-263) — the ESLint `bun run lint` failure branch,
//!    `<label> = format!("{} failed", linter_name)`,
//!    `<errors> = error_count`, `<warnings> = warning_count`.
//! 2. `commands/frontend_validation.rs::run_biome_lint` (pre-lift
//!    ~L333-347) — the Biome `bun x biome check src` failure branch,
//!    `<label> = "Biome check failed"`, `<errors> = errors`,
//!    `<warnings> = warnings`.
//!
//! Post-lift both consumers route through
//! [`report_frontend_lint_failure`]; the two constituent primitives
//! ([`crate::ui::print_step_failure`] +
//! [`crate::repo::msg_with_two_counts_and_secs_1`] +
//! [`crate::frontend_lint_diagnostic_collect::print_and_collect_lint_diagnostic_lines`])
//! keep their own contracts and are composed here at ONE landing
//! point. A future refinement of the failure-report grammar (a bump of
//! the `"errors"` / `"warnings"` noun labels to alternative renderings
//! under an operator-lang variant, an OTLP
//! `frontend_lint_failure_reported` span, a promotion of the two-count
//! header to a structured event) lands at this one primitive and
//! reaches both consumers by construction.
//!
//! # Distinct from every peer failure-report helper
//!
//! - [`crate::ui::print_step_failure`] owns the one-line
//!   `   ❌.red() <message>` render and is the header adapter this
//!   primitive consumes internally. The primitive owns the FUSION with
//!   the collection pass, not the render itself.
//! - [`crate::repo::msg_with_two_counts_and_secs_1`] owns the
//!   `<msg> (<c1> <n1>, <c2> <n2>, {:.1}s)` two-count grammar and is
//!   the message adapter this primitive consumes internally. A drift
//!   in that grammar reaches this primitive by composition — the
//!   primitive does not restate the two-count body.
//! - [`crate::frontend_lint_diagnostic_collect::print_and_collect_lint_diagnostic_lines`]
//!   owns the 15-line walk + three-keyword filter + collect algebra and
//!   is the collection adapter this primitive consumes internally. A
//!   bump of the cap or a change to the keyword set lands there, not
//!   here.
//! - `commands/frontend_validation.rs::run_type_check` renders a
//!   ONE-count failure header via
//!   [`crate::repo::msg_with_count_noun_secs_1`] (not the two-count
//!   variant), collects via a distinct
//!   `crate::ui::print_diagnostic_error_line`-driven loop, and reaches
//!   `.take(20)` on the walk rather than `.take(15)`. That third
//!   consumer is out of scope: its message adapter, print helper, and
//!   walk cap are all distinct, and a collapse would force this
//!   primitive to grow three optional axes its two-site sibling family
//!   does not exercise.
//!
//! # THEORY grounding
//!
//! - `THEORY.md §I.5` (duplication budget zero, generation before
//!   pattern before duplication): the two sibling fused stanzas were
//!   past the two-occurrence coincidence threshold post the 59ac6f0
//!   two-count and 584c20c collection lifts. This primitive collapses
//!   the fusion at ONE construction surface.
//! - `THEORY.md §V.2` (typed absorption): the "print-header + print-
//!   and-collect + return details" composition is a single named
//!   concept; both callers cite it rather than restating its three
//!   component steps.
//! - `THEORY.md §II.1` invariant 5 (composition preserves proofs):
//!   composing [`crate::ui::print_step_failure`],
//!   [`crate::repo::msg_with_two_counts_and_secs_1`], and
//!   [`crate::frontend_lint_diagnostic_collect::print_and_collect_lint_diagnostic_lines`]
//!   here inherits each adapter's contract without repetition — a
//!   drift at any of the three lands at ONE peer and reaches this
//!   fusion by construction, not through a mirrored second edit.
//!
//! # Frontier grounding
//!
//! Bazel BEP's `TestFailure` event emits a summary header, a bounded
//! captured-output body, and returns the captured rows as structured
//! `FailureDetail` payloads for the higher-level report. This primitive
//! is the same shape at the CLI-ceremony surface: header line + bounded
//! captured-output body + returned `Vec<String>` for the pre-release
//! summary renderer at [`crate::commands::prerelease`] to display
//! alongside the per-gate verdicts.

use std::time::Duration;

/// Fuse the two-count `print_step_failure` header and the
/// `print_and_collect_lint_diagnostic_lines` collection pass into ONE
/// typed primitive.
///
/// Prints the failure header:
///
/// ```text
///    ❌ <label> (<errors> errors, <warnings> warnings, {:.1}s)
/// ```
///
/// then walks `combined` via
/// [`crate::frontend_lint_diagnostic_collect::print_and_collect_lint_diagnostic_lines`],
/// printing each matched row through [`crate::ui::print_diagnostic_line`]
/// and returning the collected rows as owned `String`s for the caller's
/// `Ok((false, details))` return payload.
///
/// # Pre-lift consumers
///
/// - `commands/frontend_validation.rs::run_lint_with_config` (ESLint
///   arm failure branch, `<label> = format!("{} failed", linter_name)`)
/// - `commands/frontend_validation.rs::run_biome_lint` (check-arm
///   failure branch, `<label> = "Biome check failed"`)
///
/// Both delegate through this function post-lift; the fused two-count
/// header + collection stanza no longer respells at either site.
///
/// # Type-parameterized `label`
///
/// `L: std::fmt::Display` matches
/// [`crate::repo::msg_with_two_counts_and_secs_1`]'s `M: Display`
/// bound so a caller can pass either a `String`
/// (`format!("{} failed", linter_name)`) or a `&'static str`
/// (`"Biome check failed"`) without an intermediate `.to_string()` at
/// the call site.
pub fn report_frontend_lint_failure<L: std::fmt::Display>(
    label: L,
    errors: usize,
    warnings: usize,
    duration: Duration,
    combined: &str,
) -> Vec<String> {
    crate::ui::print_step_failure(&crate::repo::msg_with_two_counts_and_secs_1(
        label, errors, "errors", warnings, "warnings", duration,
    ));
    crate::frontend_lint_diagnostic_collect::print_and_collect_lint_diagnostic_lines(combined)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Return-shape oracle: the collected rows are the same rows
    /// [`crate::frontend_lint_diagnostic_collect::print_and_collect_lint_diagnostic_lines`]
    /// would return for the same `combined` input — the primitive
    /// composes the collection adapter without re-classifying or
    /// re-filtering.
    #[test]
    fn report_frontend_lint_failure_returns_the_lifted_collection_rows() {
        let combined = "\
alpha error one
beta plain
gamma warning two
delta ✖ three
epsilon nothing
";
        let details = report_frontend_lint_failure(
            "ESLint failed",
            2_usize,
            1_usize,
            Duration::from_millis(1500),
            combined,
        );
        assert_eq!(
            details,
            vec![
                "alpha error one".to_string(),
                "gamma warning two".to_string(),
                "delta ✖ three".to_string(),
            ],
        );
    }

    /// Empty-input oracle: an empty `combined` yields an empty
    /// `Vec<String>`, so a caller's `Ok((false, details))` return
    /// carries no phantom rows into the pre-release summary.
    #[test]
    fn report_frontend_lint_failure_on_empty_combined_returns_empty_vec() {
        let details = report_frontend_lint_failure(
            "Biome check failed",
            0_usize,
            0_usize,
            Duration::from_millis(0),
            "",
        );
        assert!(details.is_empty());
    }

    /// Type-parameter oracle: the primitive accepts BOTH a `String`
    /// label (the ESLint arm's `format!("{} failed", linter_name)`
    /// payload) and a `&'static str` label (the Biome arm's
    /// `"Biome check failed"` payload) — the caller does not need to
    /// `.to_string()` at the call site.
    #[test]
    fn report_frontend_lint_failure_accepts_string_and_static_str_labels() {
        // String label
        let via_string = report_frontend_lint_failure(
            format!("{} failed", "ESLint"),
            3_usize,
            2_usize,
            Duration::from_millis(500),
            "",
        );
        assert!(via_string.is_empty());
        // &'static str label
        let via_str = report_frontend_lint_failure(
            "Biome check failed",
            3_usize,
            2_usize,
            Duration::from_millis(500),
            "",
        );
        assert!(via_str.is_empty());
    }

    /// Caller shield (positive half): `commands/frontend_validation.rs`
    /// must forward through [`report_frontend_lint_failure`] at least
    /// the pre-lift stanza count (2). A drift that dropped one call
    /// site would leave the negative "no raw fused stanza survives"
    /// scan trivially satisfied by absence but the positive count
    /// check would still fail. Mirrors the sibling
    /// `every_prelift_module_forwards_through_*` shields the crate
    /// carries against every other typed primitive.
    #[test]
    fn frontend_validation_forwards_through_report_frontend_lint_failure() {
        use std::path::PathBuf as StdPathBuf;
        let path = StdPathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands")
            .join("frontend_validation.rs");
        let source = std::fs::read_to_string(&path).unwrap();
        let needle = "report_frontend_lint_failure(";
        let forwards = source
            .lines()
            .filter(|line| {
                let trimmed = line.trim_start();
                !trimmed.starts_with("//") && !trimmed.starts_with("///")
            })
            .filter(|line| line.contains(needle))
            .count();
        assert!(
            forwards >= 2,
            "commands/frontend_validation.rs must forward at least 2 \
             fused lint-failure report stanzas through `{needle}`; found {forwards}. \
             A dropped call would leave the negative fused-stanza scan \
             satisfied by absence.",
        );
    }

    /// Caller shield (negative half): no `.rs` file under
    /// `cli/src/commands/` may spell the pre-lift raw
    /// `crate::ui::print_step_failure(&crate::repo::msg_with_two_counts_and_secs_1(`
    /// fused header inline any more. The two
    /// `commands/frontend_validation.rs` sites migrated; a future
    /// consumer that wants the same fused failure-and-collect grammar
    /// reaches for [`report_frontend_lint_failure`] on first grep, not
    /// by copy-pasting the fused header from an existing command
    /// module.
    ///
    /// The shield's own docstring mentions of the fused fragment above
    /// (and the identical mention inside the `#[cfg(test)] mod tests`
    /// block that houses THIS assertion) stay out of scope because the
    /// walk targets `cli/src/commands/`, and this module lives at
    /// `cli/src/` — one directory up.
    #[test]
    fn no_command_module_still_spells_raw_two_count_step_failure_header() {
        use std::path::PathBuf as StdPathBuf;
        let commands_dir = StdPathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        // Reconstruct via format! so this shield's own source text
        // does not false-match itself.
        let needle = format!(
            "{}(&{}(",
            "crate::ui::print_step_failure", "crate::repo::msg_with_two_counts_and_secs_1",
        );
        let mut offenders: Vec<(StdPathBuf, usize, String)> = Vec::new();
        for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            for (idx, line) in source.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("///") {
                    continue;
                }
                if line.contains(&needle) {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `{needle}` fused header survives under `commands/` — route each through \
             `crate::frontend_lint_failure_report::report_frontend_lint_failure(\
             <label>, <errors>, <warnings>, <duration>, <combined>)` instead:\n{:#?}",
            offenders,
        );
    }
}
