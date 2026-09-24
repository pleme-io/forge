//! Smoke-query name-prefixed, latency-suffixed step-failure envelope:
//! the pre-lift 3 sibling `crate::ui::print_step_failure(&format!("{}:
//! <detail> ({}ms)", smoke.name, ..., latency_ms))` stanzas at
//! `commands/post_deploy_verification.rs::verify_smoke_queries`
//! collapsed onto one typed body.
//!
//! # Pre-lift census — three sibling stanzas, one envelope grammar
//!
//! Three consumer sites inside the request/response loop of
//! [`crate::commands::post_deploy_verification::verify_smoke_queries`]
//! each spelled the same `print_step_failure` + `format!("{}: <detail>
//! ({}ms)", smoke.name, …, latency_ms)` composition inline before
//! either reaching for
//! [`crate::smoke_query_failure_record::record_smoke_query_failure`]
//! or short-circuiting the outer loop:
//!
//! 1. **HTTP non-2xx.** `Ok((response, latency_ms))` outer arm,
//!    `!response.status().is_success()` inner branch. Detail:
//!    `format!("HTTP {}", status)`.
//! 2. **Missing / mismatched data field.** `Ok((response, latency_ms))`
//!    outer arm, `Ok(json)` json-parse arm, `!has_field` inner branch.
//!    Detail: pre-bound `error_msg` covering both the `"GraphQL errors:
//!    …"` and `"Missing expected field '<name>' in response"` variants.
//! 3. **JSON parse failure.** `Ok((response, latency_ms))` outer arm,
//!    `Err(e)` json-parse arm. Detail: `format!("Failed to parse
//!    response: {}", e)`.
//!
//! All three carry the same envelope: `<smoke-name>: <detail> (<u64
//! latency>ms)`, printed via [`crate::ui::print_step_failure`]. The
//! `<detail>` slot differs across the three sites; the surrounding
//! `"{}: "` prefix and `" ({}ms)"` suffix are the invariant grammar
//! this primitive owns.
//!
//! The fourth failure site in the same loop — the transport-error arm
//! (`Err(e)` outer arm) — routes through
//! [`crate::ui::print_step_failure_with_error`] rather than a
//! `format!(...)` envelope (no `latency_ms` is available, and the
//! `<name>: <err>` grammar is the shared step-failure-with-error
//! shape), so it is intentionally out of scope here.
//!
//! # THEORY grounding
//!
//! §V solve-once-at-the-primitive: the "smoke-query step-failure with
//! latency" envelope grammar — the `":"` connective between name and
//! detail, the `" ("` parenthesized-latency opener, the decimal
//! projection of the `u64` latency, and the `"ms)"` closer — lives at
//! ONE surface, so a future refinement (a shift to `" (took {latency}
//! ms)"`, a promotion to a
//! [`std::time::Duration`]-typed [`Display`] projection, an OTLP
//! `post_deploy_smoke_query_failure_latency_ms` observability event
//! wired alongside the print, a nanosecond-precision refinement) lands
//! here and reaches all three consumers by construction.
//!
//! §VI.1 recurring-shape-to-helper: three sibling stanzas across ONE
//! function body materially exceed the recurring-shape criterion; the
//! primitive body is the promotion. A future fourth smoke-query
//! failure classification (e.g. a schema-mismatch arm) that reaches for
//! the same envelope inherits the wording, connective, latency-render,
//! and closing byte-shape by construction — the drift class the
//! three-fold pre-lift stanzas were open to (a comma vs colon
//! connective, a `ms` vs `msec` unit, a space vs no-space separator) is
//! closed once and for all.
//!
//! # Companion primitives
//!
//! - [`crate::smoke_query_failure_record::record_smoke_query_failure`]
//!   owns the fused `results.push(...)` + `all_passed = false;` tail
//!   that each of these three sites reaches for AFTER printing this
//!   envelope; the two primitives compose without either owning the
//!   other's concern.
//! - [`crate::post_deploy_endpoint_check_pass::print_post_deploy_endpoint_check_pass`]
//!   owns the pass-branch `"<label> ({}ms)"` grammar for the sibling
//!   `verify_health_endpoint` / `verify_graphql_endpoint` gates. This
//!   primitive is the smoke-query failure peer: the pass-branch
//!   grammar and the failure-branch envelope both project through
//!   typed bodies, and a future reworking of the parenthesized-latency
//!   tail lands on both.

use std::fmt::Write as _;

/// The literal `": "` connective the pre-lift three sites spelled
/// between the smoke-query name and the failure detail. Constant-lifted
/// so the byte-oracle test and the caller-shield remediation prose
/// reference the same source of truth, and a future rewording (a `" — "`
/// em-dash separator, a `"::"` doubled-colon connective) lands on
/// exactly one line.
pub const SMOKE_QUERY_STEP_FAILURE_NAME_DETAIL_CONNECTIVE: &str = ": ";

/// The literal parenthesized-latency opener the pre-lift three sites
/// spelled between the detail and the `u64` latency. Split from
/// [`SMOKE_QUERY_STEP_FAILURE_LATENCY_MS_CLOSE`] so the two halves can
/// be pinned independently and a future refinement (a `" @ "` prefix,
/// a `" ["`-`"]"` bracket pair) rotates one side at a time.
pub const SMOKE_QUERY_STEP_FAILURE_LATENCY_MS_OPEN: &str = " (";

/// The literal `"ms)"` closer the pre-lift three sites spelled after
/// the latency integer. Split from
/// [`SMOKE_QUERY_STEP_FAILURE_LATENCY_MS_OPEN`] so a future unit-change
/// (e.g. `"μs)"` or `"s)"`) lands on exactly one constant.
pub const SMOKE_QUERY_STEP_FAILURE_LATENCY_MS_CLOSE: &str = "ms)";

/// Compose the pre-lift `format!("{}: {} ({}ms)", smoke.name, detail,
/// latency_ms)` message shape without touching the writer. Split from
/// [`print_smoke_query_step_failure_with_latency`] so the pure-string
/// projection can be pinned by unit tests without capturing stdout,
/// and so a caller that wants to log or record the same message
/// alongside a diagnostics event does not have to re-derive it.
pub fn format_smoke_query_step_failure_with_latency(
    smoke_name: &str,
    detail: &str,
    latency_ms: u64,
) -> String {
    let mut out = String::new();
    // `write!` into `String` never fails; unwrap-free via `let _ =`.
    let _ = write!(
        out,
        "{}{}{}{}{}{}",
        smoke_name,
        SMOKE_QUERY_STEP_FAILURE_NAME_DETAIL_CONNECTIVE,
        detail,
        SMOKE_QUERY_STEP_FAILURE_LATENCY_MS_OPEN,
        latency_ms,
        SMOKE_QUERY_STEP_FAILURE_LATENCY_MS_CLOSE,
    );
    out
}

/// Print the one-line `   ❌ <name>: <detail> (<latency>ms)`
/// step-failure grammar via [`crate::ui::print_step_failure`], composing
/// the message through [`format_smoke_query_step_failure_with_latency`]
/// so the pre-lift wording, connective, latency-render, and closing
/// byte-shape lift onto ONE typed body.
pub fn print_smoke_query_step_failure_with_latency(
    smoke_name: &str,
    detail: &str,
    latency_ms: u64,
) {
    crate::ui::print_step_failure(&format_smoke_query_step_failure_with_latency(
        smoke_name, detail, latency_ms,
    ));
}

/// Writer-taking sibling to
/// [`print_smoke_query_step_failure_with_latency`]. Emits the same
/// one-line `   ❌ <name>: <detail> (<latency>ms)` via
/// [`crate::ui::write_step_failure`] against the supplied writer so
/// tests can pin the pre-lift byte-shape (three-space indent, `❌ `
/// glyph, `\x1b[31m` red ANSI palette on the glyph, the `": "`
/// name-detail connective, the `" ("` latency opener, the `u64`
/// latency's decimal projection, and the trailing `"ms)"` closer)
/// without capturing stdout.
pub fn write_smoke_query_step_failure_with_latency<W>(
    w: &mut W,
    smoke_name: &str,
    detail: &str,
    latency_ms: u64,
) -> std::io::Result<()>
where
    W: std::io::Write,
{
    crate::ui::write_step_failure(
        w,
        &format_smoke_query_step_failure_with_latency(smoke_name, detail, latency_ms),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Constant pin: the name-detail connective the pre-lift three sites
    /// spelled between the smoke-query name and the failure detail is
    /// the verbatim `": "` fragment.
    #[test]
    fn smoke_query_step_failure_name_detail_connective_matches_pre_lift_literal() {
        assert_eq!(SMOKE_QUERY_STEP_FAILURE_NAME_DETAIL_CONNECTIVE, ": ");
    }

    /// Constant pin: the latency-open half the pre-lift three sites
    /// spelled between the detail and the latency integer is the
    /// verbatim `" ("` fragment.
    #[test]
    fn smoke_query_step_failure_latency_ms_open_matches_pre_lift_literal() {
        assert_eq!(SMOKE_QUERY_STEP_FAILURE_LATENCY_MS_OPEN, " (");
    }

    /// Constant pin: the latency-close half the pre-lift three sites
    /// spelled after the latency integer is the verbatim `"ms)"`
    /// fragment.
    #[test]
    fn smoke_query_step_failure_latency_ms_close_matches_pre_lift_literal() {
        assert_eq!(SMOKE_QUERY_STEP_FAILURE_LATENCY_MS_CLOSE, "ms)");
    }

    /// Format pin: the message projection composes exactly
    /// `"<name>: <detail> (<latency>ms)"` — the pre-lift
    /// `format!(...)` byte-shape all three sibling sites spelled
    /// inline against their per-site `<detail>` slot.
    #[test]
    fn format_smoke_query_step_failure_with_latency_matches_pre_lift_shape() {
        // Site 1: HTTP non-2xx.
        assert_eq!(
            format_smoke_query_step_failure_with_latency("Schema introspection", "HTTP 502", 42,),
            "Schema introspection: HTTP 502 (42ms)",
        );
        // Site 2: missing / mismatched data field.
        assert_eq!(
            format_smoke_query_step_failure_with_latency(
                "Schema introspection",
                "Missing expected field '__schema' in response",
                137,
            ),
            "Schema introspection: Missing expected field '__schema' in response (137ms)",
        );
        // Site 3: JSON parse failure.
        assert_eq!(
            format_smoke_query_step_failure_with_latency(
                "Schema introspection",
                "Failed to parse response: expected value at line 1 column 1",
                7,
            ),
            "Schema introspection: Failed to parse response: expected value at line 1 column 1 (7ms)",
        );
    }

    /// Format pin (boundary): a zero-latency probe (an unlikely-but-
    /// possible sub-millisecond localhost path) reads as `"(0ms)"`
    /// without eliding the parentheses. A future refactor that
    /// collapsed the `latency_ms == 0` case would surface here.
    #[test]
    fn format_smoke_query_step_failure_with_latency_zero_latency_renders_zero() {
        assert_eq!(
            format_smoke_query_step_failure_with_latency("q", "d", 0),
            "q: d (0ms)",
        );
    }

    /// Byte-oracle: the writer sibling projects the pre-lift
    /// `crate::ui::print_step_failure(&format!("{}: <detail> ({}ms)",
    /// smoke.name, …, latency_ms))` byte-shape verbatim — the same
    /// three-space indent, the same red `❌ ` glyph, the same `": "`
    /// name-detail connective, the same `" ("` latency opener, and the
    /// same `"ms)"` closer. Compares against a direct
    /// [`crate::ui::write_step_failure`] against the same composed
    /// message so the pin holds whether ANSI is auto-enabled or
    /// auto-disabled on the host running the suite.
    #[test]
    fn write_smoke_query_step_failure_with_latency_projects_prelift_shape() {
        for (smoke_name, detail, latency_ms, expected_payload) in [
            (
                "Schema introspection",
                "HTTP 502",
                42u64,
                "Schema introspection: HTTP 502 (42ms)",
            ),
            (
                "Schema introspection",
                "Missing expected field '__schema' in response",
                137u64,
                "Schema introspection: Missing expected field '__schema' in response (137ms)",
            ),
        ] {
            let mut buf: Vec<u8> = Vec::new();
            write_smoke_query_step_failure_with_latency(&mut buf, smoke_name, detail, latency_ms)
                .expect("write against a Vec<u8> writer must succeed");
            let mut peer: Vec<u8> = Vec::new();
            crate::ui::write_step_failure(&mut peer, expected_payload)
                .expect("peer write against a Vec<u8> writer must succeed");
            assert_eq!(
                buf, peer,
                "the primitive's writer sibling must project the same byte-shape as \
                 `crate::ui::write_step_failure(w, \"{expected_payload}\")`",
            );
            let out = String::from_utf8(buf).expect("writer emits valid UTF-8");
            assert!(
                out.contains(expected_payload),
                "emitted line must carry the `<name>: <detail> (<latency>ms)` payload \
                 verbatim; got {out:?}",
            );
        }
    }

    /// Caller shield (positive half): the one pre-lift module that
    /// housed all three sites
    /// (`commands/post_deploy_verification.rs`) MUST forward through
    /// [`print_smoke_query_step_failure_with_latency`] at least three
    /// times, so a migration that dropped a call site outright leaves
    /// the negative "no raw inline shape" scan trivially satisfied by
    /// absence but the positive count still fails. Mirrors the sibling
    /// `verify_smoke_queries_forwards_all_four_sibling_sites_through_the_primitive`
    /// shield the crate carries against
    /// [`crate::smoke_query_failure_record::record_smoke_query_failure`].
    #[test]
    fn verify_smoke_queries_forwards_three_step_failure_sites_through_the_primitive() {
        use std::path::PathBuf;
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands")
            .join("post_deploy_verification.rs");
        let needle = "print_smoke_query_step_failure_with_latency(";
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
        let forwards = source.matches(needle).count();
        assert!(
            forwards >= 3,
            "{} must forward at least 3 smoke-query step-failure envelope site(s) through \
             `{}`; found {}. A dropped call would leave the negative raw-shape scan \
             satisfied by absence.",
            path.display(),
            needle,
            forwards,
        );
    }

    /// Caller shield (negative half): the pre-`#[cfg(test)]` module
    /// body of `commands/post_deploy_verification.rs` must hold ZERO
    /// code-line hits for any of the three verbatim pre-lift
    /// failure-envelope format-string literals — `"{}: HTTP {} ({}ms)"`,
    /// `"{}: {} ({}ms)"`, and `"{}: Failed to parse response: {} ({}ms)"`
    /// — that the three pre-lift sites each spelled inline. After the
    /// lift, all three forward through
    /// [`print_smoke_query_step_failure_with_latency`], which owns the
    /// sole remaining `": "` + `" ("` + `"ms)"` composition inside
    /// [`format_smoke_query_step_failure_with_latency`] at ONE body in
    /// `cli/src/smoke_query_step_failure_with_latency.rs`.
    ///
    /// The pass-branch sibling literal `"{}: OK ({}ms)"` — a
    /// two-slot format-string with a hard-coded `OK` — is deliberately
    /// outside this shield's scope: it is a `print_step_pass` line
    /// naming the successful smoke-query response, not a failure
    /// envelope, and its lift is tracked at a peer primitive (see
    /// [`crate::post_deploy_endpoint_check_pass::print_post_deploy_endpoint_check_pass`]
    /// for the endpoint-side pass grammar).
    ///
    /// The three needles are reconstructed via [`format!`] so this
    /// shield's own source text does not false-match itself; the
    /// whole-scan therefore covers both the top-of-file production
    /// body AND every sibling `#[cfg(test)]` block in that command
    /// module.
    #[test]
    fn post_deploy_verification_holds_no_raw_smoke_query_failure_envelope_literal() {
        let source = include_str!("commands/post_deploy_verification.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            source,
            "commands/post_deploy_verification.rs",
        );
        let three_slot_mid = format!("\"{}: {} ({}ms)\"", "{}", "{}", "{}");
        let http_envelope = format!("\"{}: HTTP {} ({}ms)\"", "{}", "{}", "{}");
        let parse_envelope = format!(
            "\"{}: Failed to parse response: {} ({}ms)\"",
            "{}", "{}", "{}"
        );
        for needle in [three_slot_mid, http_envelope, parse_envelope] {
            let hits = crate::test_support::code_line_hits(body, &needle);
            assert_eq!(
                hits.len(),
                0,
                "expected ZERO code-line hits for the raw pre-lift failure-envelope \
                 format-string `{needle}` in the pre-`#[cfg(test)]` module body of \
                 `commands/post_deploy_verification.rs` (the three pre-lift sites all \
                 forward through \
                 `crate::smoke_query_step_failure_with_latency::\
                 print_smoke_query_step_failure_with_latency`, which owns the sole \
                 remaining `\": \" + \" (\" + \"ms)\"` composition at ONE body in \
                 `cli/src/smoke_query_step_failure_with_latency.rs`); got {}. \
                 Offending lines: {:#?}",
                hits.len(),
                hits,
            );
        }
    }
}
