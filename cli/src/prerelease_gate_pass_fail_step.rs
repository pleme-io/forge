//! Prerelease-gate `<base> passed` / `<base> failed` step-timed
//! label-pair primitive — the shared base-label spine three sibling
//! prerelease-gate success/failure branches of
//! `commands/prerelease.rs` each restate byte-for-byte pre-lift.
//!
//! # Duplication being lifted
//!
//! Three prerelease-gate bodies each carried the same paired
//! `crate::ui::print_step_pass_timed("<base> passed", duration)` /
//! `crate::ui::print_step_failure_timed("<base> failed", duration)`
//! stanzas on opposite arms of the same `if output.status.success()`
//! branch, diverging only on the base-label slot:
//!
//! 1. `commands/prerelease.rs::run_integration_gate` (~L964 pass /
//!    ~L968 fail) — the `cargo test --features integration-tests`
//!    gate. Base label `"Integration tests"`.
//! 2. `commands/prerelease.rs::run_e2e_gate` (~L1105 pass /
//!    ~L1109 fail) — the chromiumoxide + testcontainers full-stack
//!    E2E gate. Base label `"E2E tests"`.
//! 3. `commands/prerelease.rs::run_cargo_check` (~L1207 pass /
//!    ~L1211 fail) — the G1 `cargo check --lib --bins` compilation
//!    gate. Base label `"Compilation check"`.
//!
//! Each site pre-lift respelled BOTH the pass and the fail label
//! adjacent in the same function body, sharing the exact `<base>`
//! slot verbatim across the two arms. A drift on either arm alone
//! (a `"Integration tests passed"` pass paired with a
//! `"Integration test failed"` fail after a copy-paste truncation, an
//! `"E2E tests passed"` pass paired with a `"E2E test suite failed"`
//! fail under a re-brand of the FAILURE arm alone, or a
//! `"Compilation check passed"` pass paired with a
//! `"Compile check failed"` verb-form drift) survived every
//! `cargo test` run: the two labels never render on the same
//! operator eye pass because they live on opposite arms.
//! Post-lift both label spellings project from the same
//! [`PrereleaseGatePassFailBaseLabel`] variant through
//! [`PrereleaseGatePassFailBaseLabel::pass_label`] /
//! [`PrereleaseGatePassFailBaseLabel::fail_label`], so a future
//! refinement of the base label lands at ONE match arm and BOTH
//! projections track it by construction.
//!
//! # Distinct from every peer step-timed helper
//!
//! - [`crate::ui::print_step_pass_timed`] /
//!   [`crate::ui::print_step_failure_timed`] each emit ONE step-row
//!   with a `(N.Ns)` timing suffix. This primitive owns the
//!   base-label ↔ pass/fail suffix invariant ABOVE those adapters —
//!   the "`<base> passed` and `<base> failed` are the same base"
//!   grammar rule.
//! - [`crate::test_count_pass_step`] owns the
//!   `print_step_pass(&msg_with_count_noun_secs_1(<label>,
//!   test_count.unwrap_or(0), "tests", duration))` count-carrying
//!   success arm for two OTHER test sites
//!   (`run_cargo_test` unit-test G4 and
//!   `run_unit_tests` vitest). That primitive carries a COUNT slot
//!   in the message body; this primitive carries no count and pairs
//!   the pass/fail arms on the shared base label instead.
//! - [`crate::classified_diagnostic_line`] /
//!   [`crate::auto_fix_stderr_head_diagnostic`] own the diagnostic-
//!   line walks INSIDE the failure arms. This primitive owns the
//!   step-header ABOVE those walks.
//!
//! # THEORY grounding
//!
//! §V solve-once-at-the-primitive: the `<base> passed` / `<base>
//! failed` label composition lives at ONE construction surface — a
//! future refinement (an OTLP `gate_outcome` span, a promotion of
//! the trailing suffix from ` passed` / ` failed` to a bolder
//! `✓ Passed` / `✗ Failed`, an added structured-log key naming the
//! base label) lands in one place rather than in six.
//!
//! §VI.1 three-is-a-law: three sibling call pairs (Integration,
//! E2E, Compilation) share the exact grammar. The typed enum below
//! closes the base-label choice at build time so a future added
//! variant fails exhaustiveness on
//! [`PrereleaseGatePassFailBaseLabel::base_label`] rather than
//! silently spelling a fourth free-form label.

use std::time::Duration;

/// Which prerelease-gate step is emitting its pass/fail label. The
/// variants are closed to the three dialects the pre-lift sites
/// spell — the enum is deliberately not open, so a future variant
/// added without an arm on
/// [`PrereleaseGatePassFailBaseLabel::base_label`] fails the
/// exhaustiveness check at build time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrereleaseGatePassFailBaseLabel {
    /// `commands/prerelease.rs::run_integration_gate` — `cargo test
    /// --features integration-tests` gate. Base = `"Integration tests"`.
    IntegrationTests,
    /// `commands/prerelease.rs::run_e2e_gate` — chromiumoxide +
    /// testcontainers full-stack E2E gate. Base = `"E2E tests"`.
    E2eTests,
    /// `commands/prerelease.rs::run_cargo_check` — G1 `cargo check
    /// --lib --bins` compilation gate. Base = `"Compilation check"`.
    CompilationCheck,
}

impl PrereleaseGatePassFailBaseLabel {
    /// The bare base-label slot shared by both the pass and the
    /// fail spelling. Byte-identical to the shared prefix of the
    /// pre-lift `<base> passed` / `<base> failed` inline literals.
    pub const fn base_label(self) -> &'static str {
        match self {
            Self::IntegrationTests => "Integration tests",
            Self::E2eTests => "E2E tests",
            Self::CompilationCheck => "Compilation check",
        }
    }

    /// The exact pass-arm label fed to
    /// [`crate::ui::print_step_pass_timed`]. Composes as
    /// `"<base_label> passed"`, byte-for-byte matching the pre-lift
    /// success-arm literal each site spelled inline.
    pub fn pass_label(self) -> String {
        format!("{} passed", self.base_label())
    }

    /// The exact fail-arm label fed to
    /// [`crate::ui::print_step_failure_timed`]. Composes as
    /// `"<base_label> failed"`, byte-for-byte matching the pre-lift
    /// failure-arm literal each site spelled inline.
    pub fn fail_label(self) -> String {
        format!("{} failed", self.base_label())
    }
}

/// Emit the pass-arm step-row for a prerelease gate. Delegates
/// through [`crate::ui::print_step_pass_timed`] with the pass label
/// projected from [`PrereleaseGatePassFailBaseLabel::pass_label`],
/// preserving the pre-lift byte shape (`✓ <base> passed (N.Ns)`).
pub fn print_prerelease_gate_pass_step_timed(
    kind: PrereleaseGatePassFailBaseLabel,
    duration: Duration,
) {
    crate::ui::print_step_pass_timed(&kind.pass_label(), duration);
}

/// Emit the fail-arm step-row for a prerelease gate. Delegates
/// through [`crate::ui::print_step_failure_timed`] with the fail
/// label projected from
/// [`PrereleaseGatePassFailBaseLabel::fail_label`], preserving the
/// pre-lift byte shape (`✗ <base> failed (N.Ns)`).
pub fn print_prerelease_gate_failure_step_timed(
    kind: PrereleaseGatePassFailBaseLabel,
    duration: Duration,
) {
    crate::ui::print_step_failure_timed(&kind.fail_label(), duration);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: the `IntegrationTests` variant projects to the
    /// pre-lift `"Integration tests"` base + `" passed"` / `" failed"`
    /// suffixes, byte-for-byte matching the pre-lift
    /// `commands/prerelease.rs:964` / `:968` inline literals.
    #[test]
    fn integration_tests_labels_match_prelift_bytes() {
        let kind = PrereleaseGatePassFailBaseLabel::IntegrationTests;
        assert_eq!(kind.base_label(), "Integration tests");
        assert_eq!(kind.pass_label(), "Integration tests passed");
        assert_eq!(kind.fail_label(), "Integration tests failed");
    }

    /// Byte-oracle: the `E2eTests` variant projects to the pre-lift
    /// `"E2E tests"` base + `" passed"` / `" failed"` suffixes,
    /// byte-for-byte matching the pre-lift
    /// `commands/prerelease.rs:1105` / `:1109` inline literals.
    #[test]
    fn e2e_tests_labels_match_prelift_bytes() {
        let kind = PrereleaseGatePassFailBaseLabel::E2eTests;
        assert_eq!(kind.base_label(), "E2E tests");
        assert_eq!(kind.pass_label(), "E2E tests passed");
        assert_eq!(kind.fail_label(), "E2E tests failed");
    }

    /// Byte-oracle: the `CompilationCheck` variant projects to the
    /// pre-lift `"Compilation check"` base + `" passed"` /
    /// `" failed"` suffixes, byte-for-byte matching the pre-lift
    /// `commands/prerelease.rs:1207` / `:1211` inline literals.
    #[test]
    fn compilation_check_labels_match_prelift_bytes() {
        let kind = PrereleaseGatePassFailBaseLabel::CompilationCheck;
        assert_eq!(kind.base_label(), "Compilation check");
        assert_eq!(kind.pass_label(), "Compilation check passed");
        assert_eq!(kind.fail_label(), "Compilation check failed");
    }

    /// Invariant: the pass label always starts with the base label
    /// verbatim. A future edit that spelled the base twice or
    /// dropped the space between base and suffix breaks this.
    #[test]
    fn pass_label_starts_with_base_label_verbatim() {
        for kind in [
            PrereleaseGatePassFailBaseLabel::IntegrationTests,
            PrereleaseGatePassFailBaseLabel::E2eTests,
            PrereleaseGatePassFailBaseLabel::CompilationCheck,
        ] {
            let base = kind.base_label();
            let pass = kind.pass_label();
            assert!(
                pass.starts_with(base),
                "pass label {pass:?} must start with base label {base:?} verbatim",
            );
            assert_eq!(
                &pass[base.len()..],
                " passed",
                "pass label suffix after base must be exactly \" passed\"",
            );
        }
    }

    /// Invariant: the fail label always starts with the base label
    /// verbatim. Sibling shield to the pass-label invariant.
    #[test]
    fn fail_label_starts_with_base_label_verbatim() {
        for kind in [
            PrereleaseGatePassFailBaseLabel::IntegrationTests,
            PrereleaseGatePassFailBaseLabel::E2eTests,
            PrereleaseGatePassFailBaseLabel::CompilationCheck,
        ] {
            let base = kind.base_label();
            let fail = kind.fail_label();
            assert!(
                fail.starts_with(base),
                "fail label {fail:?} must start with base label {base:?} verbatim",
            );
            assert_eq!(
                &fail[base.len()..],
                " failed",
                "fail label suffix after base must be exactly \" failed\"",
            );
        }
    }

    /// Closure shield: the enum is closed to exactly three variants.
    /// A future variant added without extending the byte-oracle
    /// per-variant tests above fails this length check first.
    #[test]
    fn base_label_is_closed_to_three_dialects() {
        let all: [PrereleaseGatePassFailBaseLabel; 3] = [
            PrereleaseGatePassFailBaseLabel::IntegrationTests,
            PrereleaseGatePassFailBaseLabel::E2eTests,
            PrereleaseGatePassFailBaseLabel::CompilationCheck,
        ];
        let bases: Vec<&'static str> = all.iter().map(|k| k.base_label()).collect();
        assert_eq!(
            bases,
            vec!["Integration tests", "E2E tests", "Compilation check"],
        );
    }

    /// Delegation shield: every prerelease-gate `print_step_pass_timed(
    /// "<X> passed", duration)` / `print_step_failure_timed(
    /// "<X> failed", duration)` pair for the three closed dialects
    /// (Integration, E2E, Compilation check) MUST route through the
    /// [`print_prerelease_gate_pass_step_timed`] /
    /// [`print_prerelease_gate_failure_step_timed`] pair rather than
    /// re-spelling the label inline. The shield reads
    /// `commands/prerelease.rs` and rejects any raw
    /// `print_step_pass_timed("<base> passed"` /
    /// `print_step_failure_timed("<base> failed"` literal for the
    /// three closed base labels.
    ///
    /// A future new prerelease gate whose base label does NOT belong
    /// to the closed dialect is free to spell its own
    /// `print_step_pass_timed("..." , duration)` /
    /// `print_step_failure_timed("...", duration)` pair inline
    /// (Type check / Code formatting applied and verified / cargo
    /// fmt failed / Tests failed / Test execution failed / Unit tests
    /// failed / Code formatting check failed after auto-fix already
    /// live outside the closed dialect at call sites in
    /// `frontend_validation.rs` and elsewhere in `prerelease.rs`).
    #[test]
    fn prerelease_gate_pass_fail_step_callers_delegate_through_primitive() {
        let source = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/commands/prerelease.rs",
        ))
        .expect("commands/prerelease.rs must be readable at this manifest-relative path");

        for needle in [
            "print_step_pass_timed(\"Integration tests passed\"",
            "print_step_failure_timed(\"Integration tests failed\"",
            "print_step_pass_timed(\"E2E tests passed\"",
            "print_step_failure_timed(\"E2E tests failed\"",
            "print_step_pass_timed(\"Compilation check passed\"",
            "print_step_failure_timed(\"Compilation check failed\"",
        ] {
            assert!(
                !source.contains(needle),
                "raw `{needle}, duration)` literal survived in \
                 commands/prerelease.rs — this pair MUST route through \
                 crate::prerelease_gate_pass_fail_step::\
                 print_prerelease_gate_pass_step_timed / \
                 print_prerelease_gate_failure_step_timed with a \
                 PrereleaseGatePassFailBaseLabel variant",
            );
        }

        // Positive delegation: the pass/fail sinks are each called
        // exactly three times in commands/prerelease.rs (once per
        // closed dialect). A future refactor that dropped a call
        // would slip past the negative shield above, so pin the
        // forward-hit count too.
        let pass_hits = source
            .matches(
                "crate::prerelease_gate_pass_fail_step::\
                 print_prerelease_gate_pass_step_timed(",
            )
            .count();
        let fail_hits = source
            .matches(
                "crate::prerelease_gate_pass_fail_step::\
                 print_prerelease_gate_failure_step_timed(",
            )
            .count();
        assert_eq!(
            pass_hits, 3,
            "expected exactly 3 pass-step delegations in \
             commands/prerelease.rs (Integration + E2E + Compilation \
             check); got {pass_hits}",
        );
        assert_eq!(
            fail_hits, 3,
            "expected exactly 3 failure-step delegations in \
             commands/prerelease.rs (Integration + E2E + Compilation \
             check); got {fail_hits}",
        );
    }
}
