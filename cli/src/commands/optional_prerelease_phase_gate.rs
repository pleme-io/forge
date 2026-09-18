//! Optional pre-release phase-gate step — the two-armed
//! `skip-or-run` ceremony that Phase 0b and Phase 0c of the
//! pre-release orchestrator each spelled inline.
//!
//! # Pre-lift census — two sibling stanzas, one 30-line body
//!
//! Two consumer sites in `commands/prerelease.rs::run_prerelease` each
//! spelled the same `if <skip-or-disabled> { <skip-line> } else {
//! <phase-heading> + match <runner>().await { <classify> } }` body,
//! diverging only on:
//!
//! 1. Phase 0b (line 447-479): `SKIP_INTEGRATION` env-var flag,
//!    `config.gates.integration.enabled`, tag `"G13: Integration
//!    tests"`, phase-heading `"Phase 0b: Integration Tests (G13)"`,
//!    error-label `"Integration tests error"`, runner
//!    `run_integration_gate(&config)`.
//! 2. Phase 0c (line 481-511): `SKIP_E2E` env-var flag,
//!    `config.gates.e2e.enabled`, tag `"G14: E2E tests"`,
//!    phase-heading `"Phase 0c: E2E Tests (G14)"`, error-label
//!    `"E2E tests error"`, runner `run_e2e_gate(&config)`.
//!
//! Both stanzas spelled the same ceremony verbatim:
//!
//! ```ignore
//! let skip_flag = crate::repo::truthy_flag_from_env(<SKIP_ENV>);
//! if skip_flag || !enabled {
//!     let reason = if skip_flag { "<SKIP_ENV>=true" } else { "disabled" };
//!     summary.skipped.push(format!("{} ({})", <tag>, reason));
//! } else {
//!     println!();
//!     crate::ui::print_phase_heading(<phase-heading>);
//!     match <runner>(&config).await {
//!         Ok(passed) => {
//!             if passed { summary.passed.push(<tag>.to_string()); }
//!             else      { summary.failed.push(<tag>.to_string()); }
//!         }
//!         Err(e) => {
//!             ui::print_step_failure_with_error(<error-label>, &e);
//!             summary.failed.push(<tag>.to_string());
//!         }
//!     }
//! }
//! ```
//!
//! Two 30-line bodies past the PRIME DIRECTIVE's duplication-is-a-bug
//! threshold (THEORY §VI.1 — construction over composition; every
//! recurring shape becomes a library before it becomes duplicated
//! code). A drift to any of the shape's five moving parts — the
//! skip-reason grammar (`"<env>=true"` vs. `"skipped via <env>"`),
//! the `enabled=false` reason (`"disabled"` vs. `"gate disabled"`),
//! the leading blank-line separator before the heading, the
//! `Ok(true)`/`Ok(false)`/`Err(_)` classification, or the trailing
//! `print_step_failure_with_error` invocation on the error arm — had
//! to hit both sites in lockstep pre-lift; post-lift the drift hits
//! ONE typed body and both consumers inherit the change from the
//! primitive.
//!
//! # Env-var lookup stays at the caller
//!
//! The caller pre-resolves `truthy_flag_from_env(<SKIP_ENV>)` and
//! passes the boolean plus the env-var name — the boolean drives the
//! skip decision, the name is used only to compose the skip-reason
//! string (`"<SKIP_ENV>=true"`). Keeping the env-var lookup at the
//! caller preserves the pre-existing whole-module shield in
//! `commands/prerelease.rs` that enforces every `SKIP_*` flag routes
//! through [`crate::repo::truthy_flag_from_env`] at exactly its two
//! canonical delegation sites.
//!
//! # Deferred runner via `FnOnce() -> Future`
//!
//! The runner is handed in as `F: FnOnce() -> Fut` rather than an
//! already-constructed `Fut`. That preserves the pre-lift laziness —
//! on the skip arm the future is never constructed, matching the
//! pre-lift behavior where `run_integration_gate(&config)` /
//! `run_e2e_gate(&config)` were spelled inside the `else` block.
//! An eager `runner: Fut` shape would build the future even on skip,
//! changing semantics for any future async gate whose construction
//! carries side effects.

use anyhow::Result;
use std::future::Future;

use super::prerelease::GateSummary;

/// Format the skip-reason substring for a gate that was NOT run.
///
/// Pre-lift both sites spelled `if skip_flag { "<SKIP_ENV>=true" }
/// else { "disabled" }` inline. Extracted as a plain synchronous
/// helper so the classification is exercisable in tests without an
/// async runtime, and so a drift to either arm (dropping `=true`,
/// renaming `disabled` to `gate-disabled`) reaches ONE site.
pub fn format_prerelease_phase_gate_skip_reason(
    skip_flag: bool,
    skip_env_var_name: &str,
) -> String {
    if skip_flag {
        format!("{skip_env_var_name}=true")
    } else {
        "disabled".to_string()
    }
}

/// Format the full `<tag> (<reason>)` entry pushed onto
/// `summary.skipped` when a gate was skipped. Pre-lift both sites
/// spelled `format!("{} ({})", <tag>, reason)` inline.
pub fn format_prerelease_phase_gate_skip_entry(tag: &str, reason: &str) -> String {
    format!("{tag} ({reason})")
}

/// Classify a gate-runner's `Result<bool>` outcome onto
/// [`GateSummary`]: `Ok(true)` → `summary.passed`; `Ok(false)` →
/// `summary.failed`; `Err(e)` → emit
/// [`crate::ui::print_step_failure_with_error`] against the caller's
/// `<error-label>` and the error's `Display`, then push `<tag>` onto
/// `summary.failed`.
///
/// Extracted as a synchronous helper so tests can exercise the
/// `Ok(true)` / `Ok(false)` / `Err(_)` arms without an async runtime.
pub fn classify_prerelease_phase_gate_outcome(
    summary: &mut GateSummary,
    tag: &str,
    error_label: &str,
    outcome: Result<bool>,
) {
    match outcome {
        Ok(passed) => {
            if passed {
                summary.passed.push(tag.to_string());
            } else {
                summary.failed.push(tag.to_string());
            }
        }
        Err(e) => {
            crate::ui::print_step_failure_with_error(error_label, &e);
            summary.failed.push(tag.to_string());
        }
    }
}

/// Run one optional pre-release phase gate — the fused
/// `skip-or-run` ceremony both Phase 0b (integration tests, G13) and
/// Phase 0c (E2E tests, G14) spelled inline pre-lift.
///
/// Behavior:
///
/// - On `skip_flag || !enabled`: push a skip-entry onto
///   `summary.skipped` composed via
///   [`format_prerelease_phase_gate_skip_entry`] — the runner is
///   NEVER invoked (the future is never constructed, since `runner`
///   is a `FnOnce() -> Fut` deferred by design).
/// - Otherwise: emit a blank-line separator, then the phase heading
///   via [`crate::ui::print_phase_heading`], then invoke `runner()`
///   and route its `Result<bool>` through
///   [`classify_prerelease_phase_gate_outcome`].
///
/// The `skip_env_var_name` parameter is used ONLY to compose the
/// `"<env>=true"` skip-reason string on the env-var-driven skip arm.
/// The env-var lookup itself stays at the caller so the pre-existing
/// [`crate::repo::truthy_flag_from_env`] delegation shield in
/// `commands/prerelease.rs` continues to fire.
#[allow(clippy::too_many_arguments)]
pub async fn run_optional_prerelease_phase_gate<F, Fut>(
    summary: &mut GateSummary,
    skip_env_var_name: &str,
    skip_flag: bool,
    enabled: bool,
    tag: &str,
    phase_heading: &str,
    error_label: &str,
    runner: F,
) where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<bool>>,
{
    if skip_flag || !enabled {
        let reason = format_prerelease_phase_gate_skip_reason(skip_flag, skip_env_var_name);
        summary
            .skipped
            .push(format_prerelease_phase_gate_skip_entry(tag, &reason));
        return;
    }
    println!();
    crate::ui::print_phase_heading(phase_heading);
    classify_prerelease_phase_gate_outcome(summary, tag, error_label, runner().await);
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;

    /// Pin the `<SKIP_ENV>=true` skip-reason format on the env-var
    /// skip arm. Pre-lift both sites spelled the literal
    /// `"SKIP_INTEGRATION=true"` / `"SKIP_E2E=true"` directly; the
    /// lift composes the same shape via [`format!`] over the passed
    /// env-var name. A drift (dropping `=true`, renaming to
    /// `skipped_via`, adding parentheses) trips here.
    #[test]
    fn skip_reason_env_var_arm_formats_env_name_equals_true() {
        assert_eq!(
            format_prerelease_phase_gate_skip_reason(true, "SKIP_INTEGRATION"),
            "SKIP_INTEGRATION=true",
        );
        assert_eq!(
            format_prerelease_phase_gate_skip_reason(true, "SKIP_E2E"),
            "SKIP_E2E=true",
        );
    }

    /// Pin the plain `"disabled"` skip-reason on the
    /// `enabled=false` arm. Pre-lift both sites spelled the literal
    /// `"disabled"` verbatim. A drift (`"gate-disabled"`,
    /// `"Disabled"`, appending punctuation) trips here.
    #[test]
    fn skip_reason_disabled_arm_is_plain_disabled_literal() {
        assert_eq!(
            format_prerelease_phase_gate_skip_reason(false, "SKIP_INTEGRATION"),
            "disabled",
        );
        assert_eq!(
            format_prerelease_phase_gate_skip_reason(false, "SKIP_E2E"),
            "disabled",
        );
    }

    /// Pin the `<tag> (<reason>)` skip-entry format. Pre-lift both
    /// sites spelled `format!("{} ({})", tag, reason)` verbatim onto
    /// `summary.skipped`. A drift (dropping the space before the
    /// paren, swapping to square brackets, promoting `reason` to a
    /// second line) trips here.
    #[test]
    fn skip_entry_format_is_tag_space_paren_reason() {
        assert_eq!(
            format_prerelease_phase_gate_skip_entry(
                "G13: Integration tests",
                "SKIP_INTEGRATION=true",
            ),
            "G13: Integration tests (SKIP_INTEGRATION=true)",
        );
        assert_eq!(
            format_prerelease_phase_gate_skip_entry("G14: E2E tests", "disabled"),
            "G14: E2E tests (disabled)",
        );
    }

    /// `Ok(true)` classification: push `tag` onto `summary.passed`,
    /// leave `summary.failed` empty. Pre-lift both sites spelled
    /// `summary.passed.push(<tag>.to_string())` on the `passed=true`
    /// arm.
    #[test]
    fn classify_ok_true_pushes_tag_onto_passed() {
        let mut summary = GateSummary::default();
        classify_prerelease_phase_gate_outcome(
            &mut summary,
            "G13: Integration tests",
            "Integration tests error",
            Ok(true),
        );
        assert_eq!(summary.passed, vec!["G13: Integration tests".to_string()]);
        assert!(summary.failed.is_empty());
        assert!(summary.skipped.is_empty());
    }

    /// `Ok(false)` classification: push `tag` onto `summary.failed`,
    /// leave `summary.passed` empty. Pre-lift both sites spelled
    /// `summary.failed.push(<tag>.to_string())` on the `passed=false`
    /// arm.
    #[test]
    fn classify_ok_false_pushes_tag_onto_failed() {
        let mut summary = GateSummary::default();
        classify_prerelease_phase_gate_outcome(
            &mut summary,
            "G14: E2E tests",
            "E2E tests error",
            Ok(false),
        );
        assert_eq!(summary.failed, vec!["G14: E2E tests".to_string()]);
        assert!(summary.passed.is_empty());
        assert!(summary.skipped.is_empty());
    }

    /// `Err(_)` classification: push `tag` onto `summary.failed`
    /// (same as `Ok(false)`), AND emit the
    /// `print_step_failure_with_error(<error-label>, &e)` line.
    /// The stdout-side effect is validated by the caller shield —
    /// here we pin the summary mutation.
    #[test]
    fn classify_err_pushes_tag_onto_failed() {
        let mut summary = GateSummary::default();
        classify_prerelease_phase_gate_outcome(
            &mut summary,
            "G13: Integration tests",
            "Integration tests error",
            Err(anyhow!("spawn failed")),
        );
        assert_eq!(summary.failed, vec!["G13: Integration tests".to_string()]);
        assert!(summary.passed.is_empty());
        assert!(summary.skipped.is_empty());
    }

    /// End-to-end async orchestrator: on `skip_flag=true` the
    /// runner is never invoked and a skip-entry with the
    /// `<env>=true` reason lands on `summary.skipped`.
    #[tokio::test]
    async fn run_gate_skip_flag_arm_pushes_env_true_reason_and_skips_runner() {
        let mut summary = GateSummary::default();
        let mut invoked = false;
        run_optional_prerelease_phase_gate(
            &mut summary,
            "SKIP_INTEGRATION",
            true,
            true,
            "G13: Integration tests",
            "Phase 0b: Integration Tests (G13)",
            "Integration tests error",
            || async {
                invoked = true;
                Ok(true)
            },
        )
        .await;
        assert!(
            !invoked,
            "runner MUST NOT be invoked on the skip-flag arm — pre-lift the future was \
             constructed inside the else block and never reached the skip arm"
        );
        assert_eq!(
            summary.skipped,
            vec!["G13: Integration tests (SKIP_INTEGRATION=true)".to_string()],
        );
        assert!(summary.passed.is_empty());
        assert!(summary.failed.is_empty());
    }

    /// End-to-end async orchestrator: on `enabled=false` and
    /// `skip_flag=false` the runner is never invoked and a
    /// skip-entry with the `disabled` reason lands on
    /// `summary.skipped`.
    #[tokio::test]
    async fn run_gate_disabled_arm_pushes_disabled_reason_and_skips_runner() {
        let mut summary = GateSummary::default();
        let mut invoked = false;
        run_optional_prerelease_phase_gate(
            &mut summary,
            "SKIP_E2E",
            false,
            false,
            "G14: E2E tests",
            "Phase 0c: E2E Tests (G14)",
            "E2E tests error",
            || async {
                invoked = true;
                Ok(true)
            },
        )
        .await;
        assert!(!invoked);
        assert_eq!(
            summary.skipped,
            vec!["G14: E2E tests (disabled)".to_string()],
        );
        assert!(summary.passed.is_empty());
        assert!(summary.failed.is_empty());
    }

    /// End-to-end async orchestrator: on the run arm the runner is
    /// invoked and its `Ok(true)` outcome classifies the tag onto
    /// `summary.passed`.
    #[tokio::test]
    async fn run_gate_run_arm_ok_true_pushes_tag_onto_passed() {
        let mut summary = GateSummary::default();
        run_optional_prerelease_phase_gate(
            &mut summary,
            "SKIP_INTEGRATION",
            false,
            true,
            "G13: Integration tests",
            "Phase 0b: Integration Tests (G13)",
            "Integration tests error",
            || async { Ok(true) },
        )
        .await;
        assert_eq!(summary.passed, vec!["G13: Integration tests".to_string()]);
        assert!(summary.failed.is_empty());
        assert!(summary.skipped.is_empty());
    }

    /// End-to-end async orchestrator: on the run arm an `Err(_)`
    /// outcome classifies the tag onto `summary.failed`.
    #[tokio::test]
    async fn run_gate_run_arm_err_pushes_tag_onto_failed() {
        let mut summary = GateSummary::default();
        run_optional_prerelease_phase_gate(
            &mut summary,
            "SKIP_E2E",
            false,
            true,
            "G14: E2E tests",
            "Phase 0c: E2E Tests (G14)",
            "E2E tests error",
            || async { Err(anyhow!("spawn failure")) },
        )
        .await;
        assert_eq!(summary.failed, vec!["G14: E2E tests".to_string()]);
        assert!(summary.passed.is_empty());
        assert!(summary.skipped.is_empty());
    }

    /// Positive delegation shield: `commands/prerelease.rs` must
    /// forward through [`run_optional_prerelease_phase_gate`] at
    /// exactly two sites — one per pre-lift consumer (the Phase 0b
    /// integration-tests gate and the Phase 0c E2E-tests gate). A
    /// fusion that folded the two sites into one call or dropped one
    /// of the phases silently fails here.
    #[test]
    fn prerelease_forwards_through_run_gate_primitive_twice() {
        const SOURCE: &str = include_str!("prerelease.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            SOURCE,
            "commands/prerelease.rs",
        );
        const FORWARD_NEEDLE: &str =
            "optional_prerelease_phase_gate::run_optional_prerelease_phase_gate(";
        let forward_hits = body.matches(FORWARD_NEEDLE).count();
        assert_eq!(
            forward_hits, 2,
            "commands/prerelease.rs body must forward to \
             `crate::commands::optional_prerelease_phase_gate::\
             run_optional_prerelease_phase_gate(...)` at exactly 2 sites — \
             one per pre-lift consumer (Phase 0b integration tests, \
             Phase 0c E2E tests). Found {forward_hits} forwarding hits."
        );
    }

    /// Negative caller shield: no raw
    /// `crate::ui::print_step_failure_with_error("Integration tests error"`
    /// or `crate::ui::print_step_failure_with_error("E2E tests error"`
    /// pair may live in `commands/prerelease.rs` on the phase-gate
    /// classification path — those two labels reach stdout through
    /// [`classify_prerelease_phase_gate_outcome`] post-lift. Pins
    /// the classification body's ONE-site invariant against a
    /// re-inline that copied the classification back into the
    /// caller.
    ///
    /// Only checks the module body before the first `#[cfg(test)]`
    /// region so test-support mentions do not defeat the shield.
    #[test]
    fn no_raw_phase_gate_error_label_survives_in_prerelease_body() {
        const SOURCE: &str = include_str!("prerelease.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            SOURCE,
            "commands/prerelease.rs",
        );
        for needle in [
            "print_step_failure_with_error(\"Integration tests error\"",
            "print_step_failure_with_error(\"E2E tests error\"",
        ] {
            for (i, line) in body.lines().enumerate() {
                assert!(
                    !line.contains(needle),
                    "commands/prerelease.rs:{lineno} spells the pre-lift \
                     `{needle}...` classification-path literal — that shape \
                     was lifted onto \
                     `crate::commands::optional_prerelease_phase_gate::\
                     classify_prerelease_phase_gate_outcome`. A re-inline \
                     silently reopens the two-site duplication class this \
                     shield exists to close. Offending line: {line:?}",
                    lineno = i + 1
                );
            }
        }
    }
}
