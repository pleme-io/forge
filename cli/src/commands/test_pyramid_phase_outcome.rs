//! Test-pyramid phase outcome recorder — the shared closed-enum-typed
//! `if result.is_err() { all_passed = false; if fail_fast { return
//! result; } ui::print_error("<phase> failed"); } else {
//! ui::print_success("<phase> passed"); }` stanza that
//! `commands/e2e.rs::run_test_pyramid` spells verbatim FIVE times —
//! once per test phase (Backend Unit, Frontend Unit, Backend
//! Integration, E2E arm A after just-prepared images, E2E arm B when
//! images already exist).
//!
//! # Pre-lift census — five sibling stanzas, one 10-line body
//!
//! All five stanzas share the exact shape:
//!
//! ```ignore
//! if result.is_err() {
//!     all_passed = false;
//!     if fail_fast {
//!         return result;
//!     }
//!     ui::print_error("<phase> failed");
//! } else {
//!     ui::print_success("<phase> passed");
//! }
//! ```
//!
//! diverging ONLY on the two labels — and the two labels are
//! themselves correlated on a single test-pyramid-phase axis (Backend
//! Unit / Frontend Unit / Backend Integration / E2E). The `<phase>`
//! string opens the success label AND the failure label at each site;
//! a drift where a rewrite gave the success arm "Backend unit tests"
//! and the failure arm "backend unit tests" (or "Backend unit test",
//! or "Backend-unit-tests") would compile silently pre-lift because
//! the two arms have no shared literal.
//!
//! Post-lift the correlated (`success_label`, `failure_label`) tuple
//! lives on ONE closed [`TestPyramidPhase`] enum variant. A new
//! test-pyramid phase added without extending the enum fails
//! exhaustiveness at build time; a re-branding of a phase reaches
//! ONE arm, and the success/failure labels stay in lockstep by
//! construction because they read from the same enum discriminant.
//!
//! # Fail-fast semantics
//!
//! The pre-lift stanza's `fail_fast` arm does TWO things: it flags
//! `all_passed = false` for the run-level summary, and it early-
//! returns the caller's `Result<()>` verbatim (short-circuiting the
//! remaining phases). The `?`-friendly primitive here matches both
//! behaviors: on `Err` under `fail_fast` it sets
//! `*all_passed = false` and returns `Err(e)` unchanged so the caller's
//! trailing `?` short-circuits. On `Err` under `!fail_fast` it sets
//! `*all_passed = false`, emits the failure label via
//! [`crate::ui::print_error`], and returns `Ok(())` so the caller
//! continues to the next phase. On `Ok(())` it emits the success
//! label via [`crate::ui::print_success`] and returns `Ok(())`.
//!
//! # Deliberately outside the primitive's body
//!
//! The pre-lift stanzas each emit a trailing `println!();` blank line
//! that separates the phase's outcome from the next `ui::print_header`.
//! Site 3 (Backend Integration) wraps its trailing blank OUTSIDE the
//! `if let Err(e) = verify_docker()` guard — the blank fires whether
//! or not the phase ran — while sites 1, 2, 4, and 5 emit the blank
//! from inside the phase body. Absorbing the blank into the primitive
//! would either force site 3's `Skipping integration tests` branch to
//! drop the trailing blank (a visible regression) or force sites 1/2/4/5
//! to double-emit it. Blank-line placement stays at the caller.

use anyhow::Result;

use crate::ui;

/// The four typed test-pyramid phases the primitive supports. Closed
/// under the pre-lift census — the five call sites in
/// `commands/e2e.rs::run_test_pyramid` cover exactly these four
/// discriminants (the `E2eTests` variant is used at two sibling
/// call sites that share the same labels but branch on whether
/// images were just prepared or already existed).
///
/// The correlated (`success_label`, `failure_label`) tuple lives on
/// each variant — see [`TestPyramidPhase::success_label`] /
/// [`TestPyramidPhase::failure_label`]. Adding a new variant without
/// extending both `match` arms fails the exhaustiveness check at
/// build time.
// The `Tests` postfix on every variant is intentional: each variant
// names a test-pyramid phase whose printed label ends in ` tests`
// (`Backend unit tests`, `Frontend unit tests`, `Backend integration
// tests`, `E2E tests`) — the enum owns the label mapping, and
// dropping `Tests` from the variant names would decouple the variant
// discriminant from the printed noun (`BackendUnit` no longer reads
// as the container of `Backend unit tests`).
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestPyramidPhase {
    /// Phase 1 of the test pyramid — `run_backend_unit_tests`. Success
    /// label `"Backend unit tests passed"`; failure label
    /// `"Backend unit tests failed"`.
    BackendUnitTests,
    /// Phase 2 of the test pyramid — `run_frontend_unit_tests`. Success
    /// label `"Frontend unit tests passed"`; failure label
    /// `"Frontend unit tests failed"`.
    FrontendUnitTests,
    /// Phase 3 of the test pyramid — `run_backend_integration_tests`.
    /// Success label `"Backend integration tests passed"`; failure
    /// label `"Backend integration tests failed"`.
    BackendIntegrationTests,
    /// Phase 4 of the test pyramid — `run_e2e_tests`. Success label
    /// `"E2E tests passed"`; failure label `"E2E tests failed"`. Two
    /// pre-lift call sites (post-prepare arm and images-already-exist
    /// arm) share this variant.
    E2eTests,
}

impl TestPyramidPhase {
    /// The `<phase> passed` sentence [`crate::ui::print_success`]
    /// receives on the `Ok(())` arm. Every pre-lift caller spelled
    /// this literal verbatim; the enum owns the mapping so the two
    /// arms of each stanza inherit the same `<phase>` prefix by
    /// construction.
    pub const fn success_label(self) -> &'static str {
        match self {
            Self::BackendUnitTests => "Backend unit tests passed",
            Self::FrontendUnitTests => "Frontend unit tests passed",
            Self::BackendIntegrationTests => "Backend integration tests passed",
            Self::E2eTests => "E2E tests passed",
        }
    }

    /// The `<phase> failed` sentence [`crate::ui::print_error`]
    /// receives on the `Err(_)` arm when `fail_fast` is off. Every
    /// pre-lift caller spelled this literal verbatim; the enum owns
    /// the mapping so a re-branding of a phase's noun reaches BOTH
    /// arms from one edit.
    pub const fn failure_label(self) -> &'static str {
        match self {
            Self::BackendUnitTests => "Backend unit tests failed",
            Self::FrontendUnitTests => "Frontend unit tests failed",
            Self::BackendIntegrationTests => "Backend integration tests failed",
            Self::E2eTests => "E2E tests failed",
        }
    }
}

/// Record one test-pyramid phase's outcome onto the shared
/// `all_passed` flag and emit the phase-labeled
/// [`crate::ui::print_success`] / [`crate::ui::print_error`] line.
/// On the `Err(_)` arm under `fail_fast` returns the error unchanged
/// (WITHOUT printing the failure label), so the caller's trailing
/// `?` short-circuits the remaining phases; on the `Err(_)` arm
/// under `!fail_fast` flips `*all_passed = false`, prints the
/// failure label, and returns `Ok(())` so the caller continues.
///
/// # Fail-fast label suppression
///
/// The pre-lift stanzas print `ui::print_error("<phase> failed")` ONLY
/// after the `if fail_fast { return result; }` early-return arm — so a
/// fail-fast run does NOT emit the phase-specific failure label
/// (anyhow's own error rendering carries the diagnostic upward). The
/// primitive preserves that exact ordering.
pub fn record_test_pyramid_phase_outcome(
    result: Result<()>,
    phase: TestPyramidPhase,
    all_passed: &mut bool,
    fail_fast: bool,
) -> Result<()> {
    match result {
        Ok(()) => {
            ui::print_success(phase.success_label());
            Ok(())
        }
        Err(e) => {
            *all_passed = false;
            if fail_fast {
                Err(e)
            } else {
                ui::print_error(phase.failure_label());
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle for [`TestPyramidPhase::success_label`] — pins the
    /// exact `"<phase> passed"` sentence every pre-lift caller
    /// spelled to [`crate::ui::print_success`]. A silent rename (e.g.
    /// `"Backend Unit tests passed"` → `"Backend unit tests passed"`)
    /// on either arm would let the two arms of a stanza drift out of
    /// lockstep pre-lift; post-lift this test pins the exact bytes.
    #[test]
    fn success_labels_match_pre_lift_literals() {
        assert_eq!(
            TestPyramidPhase::BackendUnitTests.success_label(),
            "Backend unit tests passed",
        );
        assert_eq!(
            TestPyramidPhase::FrontendUnitTests.success_label(),
            "Frontend unit tests passed",
        );
        assert_eq!(
            TestPyramidPhase::BackendIntegrationTests.success_label(),
            "Backend integration tests passed",
        );
        assert_eq!(
            TestPyramidPhase::E2eTests.success_label(),
            "E2E tests passed",
        );
    }

    /// Byte-oracle for [`TestPyramidPhase::failure_label`] — pins the
    /// exact `"<phase> failed"` sentence every pre-lift caller
    /// spelled to [`crate::ui::print_error`].
    #[test]
    fn failure_labels_match_pre_lift_literals() {
        assert_eq!(
            TestPyramidPhase::BackendUnitTests.failure_label(),
            "Backend unit tests failed",
        );
        assert_eq!(
            TestPyramidPhase::FrontendUnitTests.failure_label(),
            "Frontend unit tests failed",
        );
        assert_eq!(
            TestPyramidPhase::BackendIntegrationTests.failure_label(),
            "Backend integration tests failed",
        );
        assert_eq!(
            TestPyramidPhase::E2eTests.failure_label(),
            "E2E tests failed",
        );
    }

    /// The success/failure label pair shares the same `<phase>` prefix
    /// across each variant. Guards against a lockstep-drift regression
    /// where a rename hits only one of the two arms — the pair now
    /// lives on the same enum discriminant, so a `<phase>`-prefix drift
    /// is only possible by editing both arms in lockstep (which this
    /// test then catches).
    #[test]
    fn success_and_failure_labels_share_phase_prefix() {
        for phase in [
            TestPyramidPhase::BackendUnitTests,
            TestPyramidPhase::FrontendUnitTests,
            TestPyramidPhase::BackendIntegrationTests,
            TestPyramidPhase::E2eTests,
        ] {
            let success = phase.success_label();
            let failure = phase.failure_label();
            let success_prefix = success
                .strip_suffix(" passed")
                .expect("success label must end with ` passed`");
            let failure_prefix = failure
                .strip_suffix(" failed")
                .expect("failure label must end with ` failed`");
            assert_eq!(
                success_prefix, failure_prefix,
                "success and failure labels for {phase:?} must share the same \
                 `<phase>` prefix; got success={success:?} vs failure={failure:?}",
            );
        }
    }

    /// `Ok(())` outcome leaves `all_passed` unchanged (starts true;
    /// stays true) and returns `Ok(())`.
    #[test]
    fn ok_outcome_preserves_all_passed_flag() {
        let mut all_passed = true;
        let out = record_test_pyramid_phase_outcome(
            Ok(()),
            TestPyramidPhase::BackendUnitTests,
            &mut all_passed,
            false,
        );
        assert!(out.is_ok(), "Ok outcome must return Ok");
        assert!(
            all_passed,
            "Ok outcome must NOT flip the all_passed flag from true"
        );
    }

    /// `Err` outcome under `!fail_fast` flips `all_passed` to false
    /// and returns `Ok(())` — the pre-lift stanza's non-fail-fast arm
    /// prints the failure label and falls through to the next phase.
    #[test]
    fn err_outcome_non_fail_fast_flips_all_passed_and_returns_ok() {
        let mut all_passed = true;
        let out = record_test_pyramid_phase_outcome(
            Err(anyhow::anyhow!("simulated backend unit test failure")),
            TestPyramidPhase::BackendUnitTests,
            &mut all_passed,
            false,
        );
        assert!(
            out.is_ok(),
            "Err outcome under !fail_fast must return Ok so the caller \
             continues to the next phase; got {out:?}"
        );
        assert!(
            !all_passed,
            "Err outcome under !fail_fast must flip all_passed to false"
        );
    }

    /// `Err` outcome under `fail_fast` flips `all_passed` to false
    /// AND propagates the error unchanged — the pre-lift stanza's
    /// fail-fast arm does `all_passed = false; return result;`
    /// verbatim, and this test pins that both effects happen in one
    /// primitive call.
    #[test]
    fn err_outcome_fail_fast_flips_all_passed_and_propagates_err() {
        let mut all_passed = true;
        let out = record_test_pyramid_phase_outcome(
            Err(anyhow::anyhow!("simulated e2e failure")),
            TestPyramidPhase::E2eTests,
            &mut all_passed,
            true,
        );
        let err = out.expect_err("Err outcome under fail_fast must propagate the Err");
        assert!(
            err.to_string().contains("simulated e2e failure"),
            "propagated Err must carry the caller's original error verbatim; got {err:?}"
        );
        assert!(
            !all_passed,
            "Err outcome under fail_fast must ALSO flip all_passed to false, \
             so the run-level summary counts the failure even though the caller \
             short-circuits"
        );
    }

    /// Caller shield (positive half): the one pre-lift module that
    /// housed the five stanzas (`commands/e2e.rs`) MUST forward
    /// through [`record_test_pyramid_phase_outcome`] at least five
    /// times, so a migration that drops a call site outright leaves
    /// the negative "no raw inline stanza" scan trivially satisfied
    /// by absence but the positive count still fails.
    #[test]
    fn e2e_module_forwards_at_least_five_test_pyramid_phase_outcomes() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let target = crate_src.join("commands").join("e2e.rs");
        let source = std::fs::read_to_string(&target)
            .unwrap_or_else(|_| panic!("expected {} to exist", target.display()));
        let needle = "record_test_pyramid_phase_outcome(";
        let forwards = crate::test_support::code_line_hits(&source, needle).len();
        assert!(
            forwards >= 5,
            "commands/e2e.rs must forward at least 5 test-pyramid-phase-outcome sites through \
             `{needle}`; found {forwards}. A dropped call would leave the negative \
             raw-stanza scan satisfied by absence."
        );
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` may spell the pre-lift raw failure-label
    /// literals for the four test-pyramid phases inline any more.
    /// The five pre-lift sites migrated; any future consumer that wants
    /// the same phase-labeled failure emission reaches for
    /// [`record_test_pyramid_phase_outcome`] on first grep, not by
    /// copy-pasting the raw `ui::print_error("<phase> failed")` literal.
    ///
    /// # Why failure labels only
    ///
    /// The success-label literals (`"<phase> passed"`) appear at two
    /// SIBLING call sites in `commands/e2e.rs::run_unit_tests` — a
    /// structurally distinct stanza that runs the same test suites in
    /// a different orchestration shape (no `all_passed` flag, no
    /// `fail_fast` branching, frontend failure demoted to a warning),
    /// so migrating those sites through this primitive would change
    /// semantics. The failure-label literals (`"<phase> failed"`), by
    /// contrast, appear ONLY at the five pre-lift `run_test_pyramid`
    /// stanzas; anchoring the shield to the failure labels catches
    /// every migration regression without false-tripping on the
    /// unrelated `run_unit_tests` sites.
    ///
    /// Reconstructed at test time via [`format!`] so this shield's own
    /// source text does not false-match itself.
    #[test]
    fn no_command_module_still_spells_raw_test_pyramid_failure_label_literals() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let commands_dir = crate_src.join("commands");
        let this_file = commands_dir.join("test_pyramid_phase_outcome.rs");

        let forbidden_failure_labels: &[&str] = &[
            "Backend unit tests failed",
            "Frontend unit tests failed",
            "Backend integration tests failed",
            "E2E tests failed",
        ];

        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        let read = std::fs::read_dir(&commands_dir).expect("commands dir must be readable");
        for entry in read.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            // The primitive's own module owns the labels — its enum
            // arms name them by construction and its shield tests
            // reconstruct them as reference literals. Exclude it from
            // the negative scan so those legitimate mentions do not
            // false-trip the shield.
            if path == this_file {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            for (idx, line) in source.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("///")
                    || trimmed.starts_with("//!")
                    || trimmed.starts_with("//")
                {
                    continue;
                }
                for failure_lit in forbidden_failure_labels {
                    let raw_failure = format!("print_error(\"{failure_lit}\")");
                    if line.contains(&raw_failure) {
                        offenders.push((path.clone(), idx + 1, line.to_string()));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `ui::print_error(\"<phase> failed\")` literal(s) survive under \
             `commands/` — route each through \
             `crate::commands::test_pyramid_phase_outcome::record_test_pyramid_phase_outcome(...)` \
             instead:\n{:#?}",
            offenders
        );
    }
}
