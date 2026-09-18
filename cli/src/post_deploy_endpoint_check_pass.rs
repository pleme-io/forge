//! Post-deploy endpoint pass-branch announce line: the pre-lift 2
//! sibling `crate::ui::print_step_pass(&format!("<label> ({}ms)",
//! latency_ms))` stanzas collapsed onto one typed primitive.
//!
//! # Pre-lift census — two sibling stanzas, one pass-branch grammar
//!
//! Two consumer sites in `commands/post_deploy_verification.rs` each
//! spelled the same `print_step_pass` + `format!("<label> ({}ms)",
//! latency_ms)` composition inline on the successful response branch
//! before returning `Ok((true, Some(latency_ms)))`:
//!
//! 1. `commands/post_deploy_verification.rs::verify_health_endpoint`
//!    (pre-lift `Ok(response) => { if response.status().is_success() {
//!    … } }` branch at line 299, `<label>` = `"Health check passed"`,
//!    `latency_ms` = pre-bound `start.elapsed().as_millis() as u64`).
//! 2. `commands/post_deploy_verification.rs::verify_graphql_endpoint`
//!    (pre-lift `Ok((response, latency_ms)) => { if
//!    response.status().is_success() { … data.is_some() … }` branch at
//!    lines 361-364, `<label>` = `"GraphQL responding"`, `latency_ms`
//!    = destructured from
//!    [`crate::post_deploy_graphql_query::send_graphql_query_timed`]'s
//!    tuple).
//!
//! Both call sites already delegate the failure-branch announce
//! through
//! [`crate::post_deploy_endpoint_status_failure::print_post_deploy_endpoint_status_failure`]
//! against the same
//! [`crate::post_deploy_endpoint_status_failure::PostDeployEndpointCheck`]
//! enum, so this primitive completes the pair: one owner for the two
//! branches' shared `"<label> ({}ms)"` grammar, and one place to
//! reword or restructure the parenthesized latency tail (an eventual
//! shift to a canonical [`std::time::Duration`] projection, an OTLP
//! `post_deploy_check_latency_ms` observability event wired alongside
//! the print, a nanosecond-precision refinement) without hunting
//! through the two sibling verify entries.
//!
//! # Companion to the status-failure branch
//!
//! [`crate::post_deploy_endpoint_status_failure::print_post_deploy_endpoint_status_failure`]
//! owns the status-failure branch and shares the
//! [`PostDeployEndpointCheck`] enum with this primitive. Both branches
//! now project through per-variant string accessors —
//! [`PostDeployEndpointCheck::check_failed_label`] on the failure
//! branch and [`PostDeployEndpointCheck::check_passed_label`] on the
//! pass branch — so a future rename of either half's endpoint label
//! rotates only that half's arm without touching the sibling.
//!
//! # Why extend the existing closed enum rather than introduce a new one
//!
//! The pre-lift pass-branch labels do not name a fresh classification
//! — they name the same two post-deploy verification gates
//! (`verify_health_endpoint`, `verify_graphql_endpoint`) the
//! status-failure branch already discriminates. A parallel enum with
//! variants `HealthPass`/`GraphqlPass` would duplicate the
//! endpoint-classification axis and let the two branches drift; the
//! extension pins that both axes share ONE variant per endpoint.

use std::fmt::Write as _;

use crate::post_deploy_endpoint_status_failure::PostDeployEndpointCheck;

/// The literal parenthesized-latency tail composition the pre-lift
/// `format!("<label> ({}ms)", latency_ms)` sites spelled after the
/// endpoint pass label. Constant-lifted so the byte-oracle test and
/// the caller-shield remediation prose reference the same source of
/// truth, and a future adjustment (a shift to `" ({latency}ms elapsed)"`,
/// a promotion to a `std::time::Duration`-typed [`Display`] projection,
/// a swap to `" (took {latency}ms)"`) happens in exactly one place.
///
/// The leading space is intentional and load-bearing — it separates
/// the endpoint pass label from the parenthesized latency without a
/// second `format!` join. A future refactor that fuses this constant
/// with [`POST_DEPLOY_ENDPOINT_LATENCY_MS_CLOSE`] must preserve the
/// leading space or a byte-oracle diff surfaces immediately.
pub const POST_DEPLOY_ENDPOINT_LATENCY_MS_OPEN: &str = " (";

/// The literal `"ms)"` closer the pre-lift `format!("<label> ({}ms)",
/// latency_ms)` sites spelled after the latency integer. Split from
/// [`POST_DEPLOY_ENDPOINT_LATENCY_MS_OPEN`] so the byte-oracle test
/// can pin the two halves independently and a future unit-change
/// (e.g. `"μs)"` or `"s)"`) lands on exactly one constant.
pub const POST_DEPLOY_ENDPOINT_LATENCY_MS_CLOSE: &str = "ms)";

/// Compose the pre-lift `format!("<label> ({}ms)", latency_ms)`
/// message shape without touching the writer. Split from
/// [`print_post_deploy_endpoint_check_pass`] so the pure-string
/// projection can be pinned by unit tests without capturing stdout,
/// and so a caller that wants to log or record the same message
/// alongside a diagnostics event does not have to re-derive it.
pub fn format_post_deploy_endpoint_check_pass_message(
    check: PostDeployEndpointCheck,
    latency_ms: u64,
) -> String {
    let mut out = String::new();
    // `write!` into `String` never fails; unwrap-free via `let _ =`.
    let _ = write!(
        out,
        "{}{}{}{}",
        check.check_passed_label(),
        POST_DEPLOY_ENDPOINT_LATENCY_MS_OPEN,
        latency_ms,
        POST_DEPLOY_ENDPOINT_LATENCY_MS_CLOSE,
    );
    out
}

/// Print the one-line `   ✅ <label> (<latency>ms)` step-pass grammar
/// via [`crate::ui::print_step_pass`], composing the message through
/// [`format_post_deploy_endpoint_check_pass_message`] so the pre-lift
/// wording, connective, latency-render, and closing byte-shape lift
/// onto ONE typed body.
pub fn print_post_deploy_endpoint_check_pass(check: PostDeployEndpointCheck, latency_ms: u64) {
    crate::ui::print_step_pass(&format_post_deploy_endpoint_check_pass_message(
        check, latency_ms,
    ));
}

/// Writer-taking sibling to [`print_post_deploy_endpoint_check_pass`].
/// Emits the same one-line `   ✅ <label> (<latency>ms)` via
/// [`crate::ui::write_step_pass`] against the supplied writer so tests
/// can pin the pre-lift byte-shape (three-space indent, `✅ ` glyph,
/// `\x1b[32m` green ANSI palette on the glyph, the leading `" ("`
/// separator between label and latency, the latency `u64`'s decimal
/// projection, and the trailing `"ms)"` closer) without capturing
/// stdout.
pub fn write_post_deploy_endpoint_check_pass<W>(
    w: &mut W,
    check: PostDeployEndpointCheck,
    latency_ms: u64,
) -> std::io::Result<()>
where
    W: std::io::Write,
{
    crate::ui::write_step_pass(
        w,
        &format_post_deploy_endpoint_check_pass_message(check, latency_ms),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Constant pin: the latency-open half the pre-lift two sites
    /// spelled between the pass label and the latency integer is the
    /// verbatim `" ("` fragment. A change here rotates both sibling
    /// call sites in lockstep.
    #[test]
    fn test_post_deploy_endpoint_latency_ms_open_matches_pre_lift_literal() {
        assert_eq!(POST_DEPLOY_ENDPOINT_LATENCY_MS_OPEN, " (");
    }

    /// Constant pin: the latency-close half the pre-lift two sites
    /// spelled after the latency integer is the verbatim `"ms)"`
    /// fragment.
    #[test]
    fn test_post_deploy_endpoint_latency_ms_close_matches_pre_lift_literal() {
        assert_eq!(POST_DEPLOY_ENDPOINT_LATENCY_MS_CLOSE, "ms)");
    }

    /// Label pin: each `PostDeployEndpointCheck` variant projects the
    /// pre-lift pass-branch label verbatim. The two labels are
    /// deliberately asymmetric — `"Health check passed"` vs `"GraphQL
    /// responding"` — matching the pre-lift wording at the two sites
    /// exactly. A homogenisation to `"<Endpoint> check passed"` at
    /// either site fails here rather than silently changing the
    /// operator-facing grammar.
    #[test]
    fn test_post_deploy_endpoint_check_passed_label_matches_pre_lift_literals() {
        assert_eq!(
            PostDeployEndpointCheck::Health.check_passed_label(),
            "Health check passed",
        );
        assert_eq!(
            PostDeployEndpointCheck::Graphql.check_passed_label(),
            "GraphQL responding",
        );
    }

    /// Format pin: the message projection composes exactly
    /// `"<label> (<latency>ms)"` — the pre-lift `format!(...)`
    /// byte-shape both sibling sites spelled inline.
    #[test]
    fn test_format_post_deploy_endpoint_check_pass_message_matches_pre_lift_shape() {
        assert_eq!(
            format_post_deploy_endpoint_check_pass_message(PostDeployEndpointCheck::Health, 42),
            "Health check passed (42ms)",
        );
        assert_eq!(
            format_post_deploy_endpoint_check_pass_message(PostDeployEndpointCheck::Graphql, 137),
            "GraphQL responding (137ms)",
        );
    }

    /// Format pin (boundary): a zero-latency probe (an unlikely-but-
    /// possible sub-millisecond localhost path) reads as `"(0ms)"`
    /// without eliding the parentheses. A future refactor that
    /// collapsed the `latency_ms == 0` case would surface here.
    #[test]
    fn test_format_post_deploy_endpoint_check_pass_message_zero_latency_renders_zero() {
        assert_eq!(
            format_post_deploy_endpoint_check_pass_message(PostDeployEndpointCheck::Health, 0),
            "Health check passed (0ms)",
        );
    }

    /// Byte-oracle: the writer sibling projects the pre-lift
    /// `crate::ui::print_step_pass(&format!("<label> ({}ms)",
    /// latency_ms))` byte-shape verbatim — the same three-space
    /// indent, the same green `✅ ` glyph, the same leading `" ("`
    /// separator between label and latency, and the same trailing
    /// `"ms)"` closer. Compares against a direct
    /// [`crate::ui::write_step_pass`] against the same composed
    /// message so the pin holds whether ANSI is auto-enabled or
    /// auto-disabled on the host running the suite.
    #[test]
    fn test_write_post_deploy_endpoint_check_pass_projects_prelift_shape() {
        for (check, latency_ms, expected_payload) in [
            (
                PostDeployEndpointCheck::Health,
                42u64,
                "Health check passed (42ms)",
            ),
            (
                PostDeployEndpointCheck::Graphql,
                137u64,
                "GraphQL responding (137ms)",
            ),
        ] {
            let mut buf: Vec<u8> = Vec::new();
            write_post_deploy_endpoint_check_pass(&mut buf, check, latency_ms)
                .expect("write against a Vec<u8> writer must succeed");
            let mut peer: Vec<u8> = Vec::new();
            crate::ui::write_step_pass(&mut peer, expected_payload)
                .expect("peer write against a Vec<u8> writer must succeed");
            assert_eq!(
                buf, peer,
                "the primitive's writer sibling must project the same byte-shape as \
                 `crate::ui::write_step_pass(w, \"{expected_payload}\")`",
            );
            let out = String::from_utf8(buf).expect("writer emits valid UTF-8");
            assert!(
                out.contains(expected_payload),
                "emitted line must carry the `<label> (<latency>ms)` payload verbatim; \
                 got {out:?}",
            );
        }
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` may spell the raw pre-lift
    /// `format!("<pass-label> ({}ms)", …)` composition inline any
    /// more. The two pre-lift sites migrated; any future consumer
    /// that wants the same pass-branch grammar reaches for
    /// [`print_post_deploy_endpoint_check_pass`] on first grep, not
    /// by copy-pasting the raw `format!` from an existing module.
    ///
    /// Reconstructed at test time via [`format!`] so this shield's
    /// own source text does not false-match itself; the whole-scan
    /// therefore covers both the top-of-file production body AND
    /// every sibling `#[cfg(test)]` block. Line-comment and
    /// block-comment lines are skipped so a future module that
    /// quotes the pre-lift shape as historical prose does not trip
    /// the shield.
    #[test]
    fn no_command_module_still_spells_raw_endpoint_pass_latency_ms_format() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let scan_dir = crate_src.join("commands");

        let forbidden_needles = [
            format!("\"Health check passed{}{{}}{}\"", " (", "ms)"),
            format!("\"GraphQL responding{}{{}}{}\"", " (", "ms)"),
        ];

        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        let read = std::fs::read_dir(&scan_dir).expect("commands dir must be readable");
        for entry in read.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let mut in_block_comment = false;
            for (idx, line) in source.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue;
                }
                if trimmed.starts_with("/*") {
                    in_block_comment = true;
                }
                if in_block_comment {
                    if trimmed.contains("*/") {
                        in_block_comment = false;
                    }
                    continue;
                }
                for forbidden in forbidden_needles.iter() {
                    if line.contains(forbidden) {
                        offenders.push((path.clone(), idx + 1, line.to_string()));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `format!(\"<pass-label> ({{}}ms)\", …)` composition(s) survive under \
             `commands/` — route each through \
             `crate::post_deploy_endpoint_check_pass::print_post_deploy_endpoint_check_pass` \
             instead:\n{offenders:#?}",
        );
    }

    /// Caller shield (positive half): the one pre-lift module that
    /// housed both sites (`commands/post_deploy_verification.rs`)
    /// MUST forward through [`print_post_deploy_endpoint_check_pass`]
    /// at least twice, so a migration that dropped a call site
    /// outright leaves the negative "no raw inline shape" scan
    /// trivially satisfied by absence but the positive count still
    /// fails. Mirrors the sibling
    /// `commands_post_deploy_verification_forwards_through_print_post_deploy_endpoint_status_failure`
    /// shield the crate carries against the failure-branch peer.
    #[test]
    fn commands_post_deploy_verification_forwards_through_print_post_deploy_endpoint_check_pass() {
        use std::path::PathBuf;
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands")
            .join("post_deploy_verification.rs");
        let needle = "print_post_deploy_endpoint_check_pass(";
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
        let forwards = source.matches(needle).count();
        assert!(
            forwards >= 2,
            "{} must forward at least 2 post-deploy endpoint pass-branch site(s) through \
             `{}`; found {}. A dropped call would leave the negative raw-shape scan \
             satisfied by absence.",
            path.display(),
            needle,
            forwards,
        );
    }
}
