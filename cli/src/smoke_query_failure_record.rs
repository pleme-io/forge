//! Smoke-query failure-record tail: the pre-lift 4 sibling
//! `results.push(SmokeQueryResult { name: smoke.name.clone(), passed:
//! false, latency_ms: <opt>, error: Some(<note>) }); all_passed =
//! false;` fused push-then-flip stanzas collapsed onto one typed body.
//!
//! # Pre-lift census — four sibling stanzas, one composition
//!
//! Four consumer sites in
//! `commands/post_deploy_verification.rs::verify_smoke_queries` each
//! restated the same fused 6-line tail verbatim after emitting a
//! per-site failure line — the four sites cover the four ways a smoke
//! query can fail inside the request/response loop:
//!
//! 1. **HTTP non-2xx.** `Ok((response, latency_ms))` outer arm,
//!    `!response.status().is_success()` inner branch (pre-lift line
//!    446–453). Error note: `format!("HTTP {}", status)`. Ends with
//!    `continue;`.
//! 2. **Missing / mismatched data field.** `Ok((response, latency_ms))`
//!    outer arm, `Ok(json)` json-parse arm, `!has_field` inner branch
//!    (pre-lift line 488–494). Error note: pre-bound `error_msg`
//!    covering both the `GraphQL errors: …` and `Missing expected
//!    field '<name>' in response` variants.
//! 3. **JSON parse failure.** `Ok((response, latency_ms))` outer arm,
//!    `Err(e)` json-parse arm (pre-lift line 502–508). Error note:
//!    `format!("Parse error: {}", e)`.
//! 4. **Transport error.** `Err(e)` outer arm (pre-lift line 514–520).
//!    Error note: `e.to_string()`. Latency: `None` (no response
//!    arrived).
//!
//! Post-lift all four sites reach for
//! [`record_smoke_query_failure`]; the `results.push(SmokeQueryResult
//! { name, passed: false, latency_ms, error: Some(note) })`
//! construction AND the `all_passed = false;` flag mutation land at
//! ONE body. The per-site failure-line print stays at the caller
//! because its message shape differs across the four sites (three
//! spell `format!("{name}: <detail> ({latency}ms)")` with three
//! distinct detail templates; the fourth uses
//! `print_step_failure_with_error(&smoke.name, &e)`) — a shared
//! print-primitive would have to carry a `SmokeQueryFailureMessage`
//! closed enum with four arms just to reproduce those distinct shapes,
//! more scaffolding than payoff. The tail — the SmokeQueryResult
//! construction and the flag flip — is the shape that recurs
//! verbatim.
//!
//! # THEORY grounding
//!
//! §V solve-once-at-the-primitive: the "record one smoke-query
//! failure" composition (push a `passed: false` result, flip the
//! aggregate `all_passed` flag) lives at ONE surface, so a future
//! refinement (an OTLP `post_deploy_smoke_query_failure` counter wired
//! alongside the push, a promotion of `error_note: String` to a typed
//! [`SmokeQueryFailureClassification`] closed enum, a swap of
//! `passed: false` for a
//! [`SmokeQueryResult::failed(name, latency_ms, note)`] constructor,
//! a hand-off to a `Vec<SmokeQueryResult>` newtype that owns the
//! aggregate `all_passed` flag intrinsically) lands here and reaches
//! all four consumers by construction.
//!
//! §VI.1 recurring-shape-to-helper: four sibling stanzas across ONE
//! function body materially exceed the recurring-shape criterion; the
//! primitive body is the promotion. The `all_passed` flag and the
//! `results` accumulator are linked by an invariant — a `passed:
//! false` push MUST be paired with `all_passed = false` — that the
//! pre-lift split-stanza shape let drift silently. The fused body
//! forecloses that drift class by construction.

use crate::commands::post_deploy_verification::SmokeQueryResult;

/// Record a failed smoke query — push a `passed: false`
/// [`SmokeQueryResult`] into `results` AND flip `all_passed` to
/// `false`, in that order.
///
/// Lifts the 4 sibling `results.push(SmokeQueryResult { name:
/// smoke.name.clone(), passed: false, latency_ms: <opt>, error:
/// Some(<note>) }); all_passed = false;` fused push-then-flip stanzas
/// at
/// [`crate::commands::post_deploy_verification::verify_smoke_queries`]
/// onto ONE typed body. The four pre-lift stanzas differed only in
/// the `smoke_name`, `latency_ms`, and `error_note` payloads — the
/// [`SmokeQueryResult::passed`] `false` sentinel and the
/// `all_passed = false` flip are structural invariants the primitive
/// owns once.
///
/// # Why fuse push + flip
///
/// The two lines carry an invariant link — a `passed: false` push
/// MUST be paired with `all_passed = false` for the outer
/// [`crate::commands::post_deploy_verification::verify_smoke_queries`]
/// return to correctly signal aggregate failure. A split lift (a
/// bare `push_smoke_query_failure` + a caller-side `all_passed =
/// false`) would silently allow a future consumer to push a failure
/// without flipping the flag — the aggregate return would then
/// spuriously report "all passed" while the results vec carried a
/// `passed: false` entry. The fused body closes that drift class:
/// a caller cannot record a failure without flipping the flag, and
/// vice versa.
///
/// # Owned `error_note`
///
/// The `error_note: String` receiver is owned rather than
/// `&str`-borrowed because three of the four pre-lift sites already
/// constructed the note via `format!(…)` (an owned `String`) and the
/// fourth via `e.to_string()` (also owned). A `&str` receiver would
/// force the callers to hold the temporary alive across the call
/// site, adding a `let note = format!(…); record_…(&note)` two-line
/// stanza where the pre-lift had one; the owned receiver keeps the
/// call sites at one line each.
pub fn record_smoke_query_failure(
    results: &mut Vec<SmokeQueryResult>,
    all_passed: &mut bool,
    smoke_name: &str,
    latency_ms: Option<u64>,
    error_note: String,
) {
    results.push(SmokeQueryResult {
        name: smoke_name.to_string(),
        passed: false,
        latency_ms,
        error: Some(error_note),
    });
    *all_passed = false;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Pin the push-shape contract: the recorded [`SmokeQueryResult`]
    /// carries the caller-supplied `smoke_name` (owned via
    /// `to_string()`), `passed: false`, the caller-supplied
    /// `latency_ms` verbatim, and `Some(error_note)`. A drift of any
    /// field — a `passed: true` typo, a swap of the `Some`/`None`
    /// error slot, a rename of the smoke_name-to-name projection —
    /// compile-flips at the field level.
    #[test]
    fn record_smoke_query_failure_pins_smoke_query_result_shape() {
        let mut results: Vec<SmokeQueryResult> = Vec::new();
        let mut all_passed = true;
        record_smoke_query_failure(
            &mut results,
            &mut all_passed,
            "Schema introspection",
            Some(1234),
            "HTTP 502 Bad Gateway".to_string(),
        );
        assert_eq!(results.len(), 1);
        let entry = &results[0];
        assert_eq!(entry.name, "Schema introspection");
        assert!(!entry.passed);
        assert_eq!(entry.latency_ms, Some(1234));
        assert_eq!(entry.error.as_deref(), Some("HTTP 502 Bad Gateway"));
    }

    /// Pin the flag-flip contract: the aggregate `all_passed` flag
    /// flips to `false` whenever a failure is recorded, regardless of
    /// its pre-existing value. A caller that starts the loop with
    /// `true` and a caller that already saw a prior failure (flag
    /// already `false`) both see `false` after this call — the flip
    /// is idempotent under multiple invocations. A regression that
    /// dropped the flip line would let the aggregate return spuriously
    /// report "all passed" while a `passed: false` entry sits in the
    /// results vec; this test compile-flips at the assertion.
    #[test]
    fn record_smoke_query_failure_flips_all_passed_to_false_from_either_state() {
        let mut results: Vec<SmokeQueryResult> = Vec::new();

        let mut fresh = true;
        record_smoke_query_failure(&mut results, &mut fresh, "q1", Some(10), "err".to_string());
        assert!(!fresh);

        let mut already_false = false;
        record_smoke_query_failure(
            &mut results,
            &mut already_false,
            "q2",
            None,
            "err".to_string(),
        );
        assert!(!already_false);
    }

    /// Pin the append-not-replace contract: repeated calls extend the
    /// results vec rather than replacing prior entries. A drift that
    /// swapped `push` for `insert(0, …)` would reorder aggregate
    /// output, and a drift that cleared the vec first would drop prior
    /// failure records silently — both classes compile-flip at the
    /// length + ordering assertions here.
    #[test]
    fn record_smoke_query_failure_appends_repeated_records_in_call_order() {
        let mut results: Vec<SmokeQueryResult> = Vec::new();
        let mut all_passed = true;
        record_smoke_query_failure(
            &mut results,
            &mut all_passed,
            "first",
            Some(10),
            "a".to_string(),
        );
        record_smoke_query_failure(
            &mut results,
            &mut all_passed,
            "second",
            None,
            "b".to_string(),
        );
        record_smoke_query_failure(
            &mut results,
            &mut all_passed,
            "third",
            Some(30),
            "c".to_string(),
        );
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].name, "first");
        assert_eq!(results[1].name, "second");
        assert_eq!(results[2].name, "third");
        assert!(!all_passed);
    }

    /// Pin the latency-is-forwarded-verbatim contract: both
    /// `Some(latency_ms)` (the three response-arrival failure sites)
    /// and `None` (the transport-error site whose failure precedes any
    /// response) round-trip into
    /// [`SmokeQueryResult::latency_ms`] byte-identical to the caller
    /// supplied value. A drift that mapped `None` to `Some(0)` or
    /// otherwise fabricated a synthetic latency would silently rewrite
    /// the transport-error record's diagnostics; this test
    /// compile-flips at the direct equality.
    #[test]
    fn record_smoke_query_failure_forwards_latency_ms_verbatim() {
        let mut results: Vec<SmokeQueryResult> = Vec::new();
        let mut all_passed = true;
        record_smoke_query_failure(&mut results, &mut all_passed, "some", Some(42), "x".into());
        record_smoke_query_failure(&mut results, &mut all_passed, "none", None, "y".into());
        assert_eq!(results[0].latency_ms, Some(42));
        assert_eq!(results[1].latency_ms, None);
    }

    /// Positive-delegation shield: the pre-lift consumer must forward
    /// at least the four sibling failure-record sites through
    /// [`record_smoke_query_failure`]. A dropped call site would leave
    /// the negative "no raw `passed: false,` push" scan trivially
    /// satisfied by absence; this positive count keeps that failure
    /// visible.
    ///
    /// The needle is
    /// `crate::smoke_query_failure_record::record_smoke_query_failure(`
    /// — the fully-qualified path callers use — so a rename of the
    /// primitive without updating this shield compile-flips loudly.
    #[test]
    fn verify_smoke_queries_forwards_all_four_sibling_sites_through_the_primitive() {
        let source = std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("src")
                .join("commands")
                .join("post_deploy_verification.rs"),
        )
        .unwrap();
        let forwards = source
            .matches(
                "crate::smoke_query_failure_record::\
                 record_smoke_query_failure(",
            )
            .count();
        assert!(
            forwards >= 4,
            "commands/post_deploy_verification.rs must forward at \
             least 4 smoke-query-failure sites through \
             `crate::smoke_query_failure_record::\
             record_smoke_query_failure(`; found {forwards}. A \
             dropped call would leave the negative raw-shape scan \
             satisfied by absence.",
        );
    }

    /// Negative caller shield: the pre-`#[cfg(test)]` module body of
    /// `commands/post_deploy_verification.rs` must hold ZERO code-line
    /// hits for the raw `passed: false,` push-shape needle. The four
    /// pre-lift failure-push stanzas each spelled that field literally;
    /// after the lift, the ONE remaining `SmokeQueryResult { … }`
    /// caller-side construction in the pre-cfg body is the pass-branch
    /// push (`passed: true`), which does NOT match this needle. Test
    /// fixtures inside `#[cfg(test)]` that construct
    /// [`SmokeQueryResult`] with `passed: false` fall outside the
    /// slice and do not contribute to the count.
    ///
    /// A re-inline at any consumer site pushes the count above zero
    /// and compile-flips this shield; a caller that keeps the raw
    /// push while forwarding the aggregate flag flip through the
    /// primitive also compile-flips loudly.
    #[test]
    fn post_deploy_verification_pre_cfg_body_holds_no_raw_passed_false_push() {
        let source = include_str!("commands/post_deploy_verification.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            source,
            "commands/post_deploy_verification.rs",
        );
        let needle = format!("{}{}", "passed:", " false,");
        let hits = crate::test_support::code_line_hits(body, &needle);
        assert_eq!(
            hits.len(),
            0,
            "expected ZERO code-line hits for the raw `passed: false,` \
             push-shape needle in the pre-`#[cfg(test)]` module body \
             of `commands/post_deploy_verification.rs` (the four \
             pre-lift smoke-query-failure sites all forward through \
             `crate::smoke_query_failure_record::\
             record_smoke_query_failure`, which owns the sole \
             remaining `passed: false,` push at ONE body in \
             `cli/src/smoke_query_failure_record.rs`); got {}. A \
             count above 0 means a caller site re-inlined the \
             pre-lift push stanza. Offending lines: {:#?}",
            hits.len(),
            hits,
        );
    }
}
