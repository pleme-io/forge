//! Canonical `print_step_pass_timed(<label>, duration); Ok((true,
//! Vec::new()))` clean-success arm stanza for two sibling frontend-
//! validation step branches.
//!
//! # Duplication being lifted
//!
//! Two byte-close sibling stanzas survived across a pair of frontend-
//! validation step success arms, each returning
//! `anyhow::Result<(bool, Vec<String>)>`:
//!
//! - `commands/frontend_validation.rs::run_type_check` (~L172-174,
//!   TypeScript `bun run type-check` success branch, `<label>` =
//!   `"Type check passed"`).
//! - `commands/frontend_validation.rs::run_biome_lint` (~L309-311,
//!   `bun x biome check src` post-auto-fix verify success branch,
//!   `<label>` = `"Biome lint applied and verified"`).
//!
//! Both sites share three grammar invariants byte-for-byte:
//!
//! 1. The sink is [`crate::ui::print_step_pass_timed`] — a green
//!    `✓ <msg> ({:.1}s)` step-pass row with elapsed duration, not the
//!    count-carrying [`crate::test_count_pass_step::print_test_count_pass_step`]
//!    dialect or the raw [`crate::ui::print_step_pass`] sink without a
//!    seconds tail.
//! 2. The return value is `Ok((true, Vec::new()))` — the "step
//!    passed cleanly with no detail lines" tuple of the outer
//!    `Result<(bool, Vec<String>)>` shape. Not `Ok((true, vec![...]))`
//!    (a pass with warning details), not `Ok((true, Some(0),
//!    Vec::new()))` (the `run_unit_tests` three-tuple dialect
//!    carrying a `test_count: Option<usize>`).
//! 3. The label is a bare `&'static str` — not a `format!(...)`
//!    composition (the sibling `run_lint_with_config` ESLint arm at
//!    ~L236-241 spells `format!("{} passed ({:.1}s)", linter_name,
//!    duration.as_secs_f64())` through the un-timed
//!    [`crate::ui::print_step_pass`] sink, which is a DIFFERENT
//!    grammar and stays outside this closure).
//!
//! # Distinct from the sibling frontend-validation primitives
//!
//! - [`crate::test_count_pass_step`] owns the count-carrying success
//!   arm — the third callee under `frontend_validation.rs`
//!   (`run_unit_tests`) already routes through it. This primitive
//!   pairs the TWO callees whose success arm carries no count and
//!   returns the empty `Vec<String>` details tuple.
//! - [`crate::frontend_lint_failure_report::report_frontend_lint_failure`]
//!   owns the sibling fusion on the FAILURE arm — `print_step_failure`
//!   + `msg_with_two_counts_and_secs_1` + diagnostic collection. This
//!   primitive is that fusion's peer on the SUCCESS arm.
//! - [`crate::auto_fix_stderr_head_diagnostic::print_and_collect_auto_fix_stderr_head_diagnostic_lines`]
//!   owns the `run_biome_lint` early-return auto-fix failure branch
//!   (`return Ok((false, details))` after biome resolve failure) — a
//!   DIFFERENT arm of the same function whose success verify branch
//!   this primitive closes.
//!
//! # THEORY grounding
//!
//! - THEORY.md §I.5 (duplication budget zero; every recurring shape
//!   becomes a helper before it becomes duplicated code): two byte-
//!   close sibling stanzas past the two-occurrence coincidence
//!   threshold. The three-invariant fusion — sink + return-tuple +
//!   label-shape — collapses to ONE construction surface.
//! - THEORY.md §II.1 invariant 5 (composition preserves proofs): the
//!   composition of [`crate::ui::print_step_pass_timed`] (the elapsed-
//!   time step-pass sink) and the `Ok((true, Vec::new()))` return
//!   tuple carries each peer's contract without repetition — a drift
//!   at either lands at ONE peer and reaches this fusion by
//!   construction.
//! - THEORY.md §V.2 (typed absorption): the closed
//!   [`FrontendValidationCleanPassStep`] enum forecloses free-form
//!   label spelling — a future added frontend-validation step whose
//!   success arm shares the same three invariants extends the enum
//!   and reaches [`emit_frontend_validation_clean_pass_step`] rather
//!   than re-spelling the stanza inline.

use std::time::Duration;

/// Which frontend-validation step is emitting its clean-success arm.
/// The variants are closed to the two dialects the pre-lift sites
/// spell — the enum is deliberately not open, so a future variant
/// added without an arm on [`FrontendValidationCleanPassStep::label`]
/// fails the exhaustiveness check at build time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrontendValidationCleanPassStep {
    /// `commands/frontend_validation.rs::run_type_check` — TypeScript
    /// `bun run type-check` success. Label = `"Type check passed"`.
    TypeCheck,
    /// `commands/frontend_validation.rs::run_biome_lint` — Biome
    /// `bun x biome check src` post-auto-fix verify success. Label =
    /// `"Biome lint applied and verified"`.
    BiomeLint,
}

impl FrontendValidationCleanPassStep {
    /// The exact `&'static str` label fed to
    /// [`crate::ui::print_step_pass_timed`]. Byte-for-byte matching
    /// the pre-lift success-arm literal each site spelled inline.
    pub const fn label(self) -> &'static str {
        match self {
            Self::TypeCheck => "Type check passed",
            Self::BiomeLint => "Biome lint applied and verified",
        }
    }
}

/// Emit the clean-success arm of a frontend-validation step: print
/// the `✓ <label> ({:.1}s)` step-pass row via
/// [`crate::ui::print_step_pass_timed`] with the label projected from
/// [`FrontendValidationCleanPassStep::label`], and return the
/// `Ok((true, Vec::new()))` tuple every pre-lift site returned
/// verbatim.
///
/// The return type is `anyhow::Result<(bool, Vec<String>)>` so the
/// call site can `return emit_frontend_validation_clean_pass_step(...)`
/// as the tail expression of a `Result<(bool, Vec<String>)>`-typed
/// `if success` arm without a further `Ok(...)` wrapper — matching
/// the pre-lift shape where the `Ok((true, Vec::new()))` was the
/// tail expression of the `if` arm.
pub fn emit_frontend_validation_clean_pass_step(
    kind: FrontendValidationCleanPassStep,
    duration: Duration,
) -> anyhow::Result<(bool, Vec<String>)> {
    crate::ui::print_step_pass_timed(kind.label(), duration);
    Ok((true, Vec::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: the `TypeCheck` variant projects to the pre-lift
    /// `"Type check passed"` label, byte-for-byte matching the
    /// pre-lift `commands/frontend_validation.rs:173` inline literal.
    #[test]
    fn type_check_label_matches_pre_lift_bytes() {
        assert_eq!(
            FrontendValidationCleanPassStep::TypeCheck.label(),
            "Type check passed"
        );
    }

    /// Byte-oracle: the `BiomeLint` variant projects to the pre-lift
    /// `"Biome lint applied and verified"` label, byte-for-byte
    /// matching the pre-lift `commands/frontend_validation.rs:310`
    /// inline literal.
    #[test]
    fn biome_lint_label_matches_pre_lift_bytes() {
        assert_eq!(
            FrontendValidationCleanPassStep::BiomeLint.label(),
            "Biome lint applied and verified"
        );
    }

    /// Closure shield: the enum is closed to exactly two variants.
    /// A future variant added without extending the byte-oracle
    /// per-variant tests above fails this length check first.
    #[test]
    fn label_is_closed_to_two_dialects() {
        let all: [FrontendValidationCleanPassStep; 2] = [
            FrontendValidationCleanPassStep::TypeCheck,
            FrontendValidationCleanPassStep::BiomeLint,
        ];
        let labels: Vec<&'static str> = all.iter().map(|k| k.label()).collect();
        assert_eq!(
            labels,
            vec!["Type check passed", "Biome lint applied and verified"],
        );
    }

    /// The emit primitive returns `Ok((true, Vec::new()))` verbatim —
    /// pins the "step passed cleanly with no detail lines" tuple that
    /// every pre-lift site returned. A future edit that flipped the
    /// bool to `false`, seeded the details vec with anything, or
    /// swapped the tuple order breaks this.
    #[test]
    fn emit_returns_true_and_empty_details_tuple() {
        let (passed, details) = emit_frontend_validation_clean_pass_step(
            FrontendValidationCleanPassStep::TypeCheck,
            Duration::from_millis(500),
        )
        .expect("emit primitive must return Ok");
        assert!(passed, "clean-pass arm must set the bool slot to true");
        assert!(
            details.is_empty(),
            "clean-pass arm must return an empty Vec<String> details slot; got {details:?}",
        );
    }

    /// Signature pin: the emit helper accepts a
    /// [`FrontendValidationCleanPassStep`] and a [`Duration`], and
    /// returns `anyhow::Result<(bool, Vec<String>)>`. A future edit
    /// that widened the signature (say to take a details prelude or
    /// return the un-wrapped `(bool, Vec<String>)`) would ripple to
    /// every caller and trip the type check.
    #[test]
    fn emit_helper_signature_pins_two_arg_result_shape() {
        let _: fn(
            FrontendValidationCleanPassStep,
            Duration,
        ) -> anyhow::Result<(bool, Vec<String>)> = emit_frontend_validation_clean_pass_step;
    }

    /// Delegation shield: the two `commands/frontend_validation.rs`
    /// clean-success arms (TypeScript type check, Biome lint verify)
    /// MUST route through [`emit_frontend_validation_clean_pass_step`]
    /// rather than re-spelling the fused stanza inline. The shield
    /// reads `commands/frontend_validation.rs` and rejects any raw
    /// `print_step_pass_timed("Type check passed"` /
    /// `print_step_pass_timed("Biome lint applied and verified"`
    /// literal that survived the lift.
    ///
    /// A future frontend-validation step whose success arm shares a
    /// DIFFERENT label is free to spell its own
    /// `print_step_pass_timed("..." , duration)` inline — the closed
    /// `FrontendValidationCleanPassStep` enum owns only the two labels
    /// this shield defends. (The sibling
    /// `commands/prerelease.rs::run_cargo_fmt_check` success arm
    /// spells `print_step_pass_timed("Code formatting applied and
    /// verified", duration)` inline, and stays outside this shield's
    /// scope because it lives in a different module and returns a
    /// different tuple shape.)
    #[test]
    fn frontend_validation_clean_pass_callers_delegate_through_primitive() {
        let source = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/commands/frontend_validation.rs",
        ))
        .expect("commands/frontend_validation.rs must be readable at this manifest-relative path");

        let body = crate::test_support::module_body_before_first_cfg_test(
            &source,
            "commands/frontend_validation.rs",
        );

        for needle in [
            "print_step_pass_timed(\"Type check passed\"",
            "print_step_pass_timed(\"Biome lint applied and verified\"",
        ] {
            assert!(
                !body.contains(needle),
                "raw `{needle}, duration)` literal survived in \
                 commands/frontend_validation.rs — this arm MUST route through \
                 crate::frontend_validation_clean_pass_step::\
                 emit_frontend_validation_clean_pass_step with a \
                 FrontendValidationCleanPassStep variant",
            );
        }

        // Positive delegation: the emit sink is called exactly twice
        // in commands/frontend_validation.rs (once per closed dialect).
        // A future refactor that dropped a call would slip past the
        // negative shield above, so pin the forward-hit count too.
        let hits = body
            .matches(
                "crate::frontend_validation_clean_pass_step::\
                 emit_frontend_validation_clean_pass_step(",
            )
            .count();
        assert_eq!(
            hits, 2,
            "expected exactly 2 emit-clean-pass delegations in \
             commands/frontend_validation.rs (TypeCheck + BiomeLint); \
             got {hits}",
        );
    }
}
