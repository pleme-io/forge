//! Post-deploy endpoint transport-error branch line: the pre-lift 2
//! sibling `crate::ui::print_step_failure_with_error("<Endpoint> check
//! failed", &e); return Ok((false, None));` stanzas collapsed onto one
//! typed primitive.
//!
//! # Pre-lift census — two sibling stanzas, one transport-error grammar
//!
//! Two consumer sites in `commands/post_deploy_verification.rs` each
//! spelled the same `print_step_failure_with_error(<label>, &e)` call
//! on the `send()` transport-error branch of their outer response
//! match (the branch reached when the HTTP client returned an
//! `Err(reqwest::Error)` after the caller-driven retry budget was
//! exhausted for the health probe, or on the first send-error for the
//! GraphQL probe):
//!
//! 1. `commands/post_deploy_verification.rs::verify_health_endpoint`
//!    (pre-lift `Err(e) => { … } else { print_step_failure_with_error(
//!    "Health check failed", &e); return Ok((false, None)); }` branch
//!    at line 331 — reached when the outer `for attempt in 0..=retries`
//!    loop drained its budget with a transport error).
//! 2. `commands/post_deploy_verification.rs::verify_graphql_endpoint`
//!    (pre-lift `Err(e) => { print_step_failure_with_error("GraphQL
//!    check failed", &e); return Ok((false, None)); }` branch at line
//!    394 — reached on the first `send_graphql_query_timed` transport
//!    error).
//!
//! Both call sites already delegate the status-failure branch through
//! [`crate::post_deploy_endpoint_status_failure::print_post_deploy_endpoint_status_failure`]
//! and the pass branch through
//! [`crate::post_deploy_endpoint_check_pass::print_post_deploy_endpoint_check_pass`]
//! against the same
//! [`crate::post_deploy_endpoint_status_failure::PostDeployEndpointCheck`]
//! closed enum, so this primitive completes the third and final axis:
//! one owner for the transport-error branch's `"<Endpoint> check
//! failed"` label (already pinned by
//! [`PostDeployEndpointCheck::check_failed_label`]), and one place to
//! extend the transport-error branch with future concerns (an OTLP
//! `post_deploy_check_transport_error` observability event wired
//! alongside the print, a canonical `reqwest::Error`-kind projection
//! that splits `is_timeout()`/`is_connect()`/`is_redirect()` into
//! sub-messages, an attestation emitter that records the failed probe
//! kind for downstream verifiers) without hunting through the two
//! sibling verify entries.
//!
//! # Sibling triangle around one closed enum
//!
//! With this primitive landed, the three response-branch axes for each
//! [`PostDeployEndpointCheck`] variant project through a matching
//! typed primitive that shares the enum:
//!
//! | Response branch          | Primitive                                                                                       | Accessor                                          |
//! | ------------------------ | ----------------------------------------------------------------------------------------------- | ------------------------------------------------- |
//! | HTTP success + valid     | [`crate::post_deploy_endpoint_check_pass::print_post_deploy_endpoint_check_pass`]              | [`PostDeployEndpointCheck::check_passed_label`]   |
//! | HTTP non-success status  | [`crate::post_deploy_endpoint_status_failure::print_post_deploy_endpoint_status_failure`]      | [`PostDeployEndpointCheck::check_failed_label`]   |
//! | Transport-layer error    | [`print_post_deploy_endpoint_transport_failure`] (this primitive)                              | [`PostDeployEndpointCheck::check_failed_label`]   |
//!
//! The status-failure and transport-error branches deliberately share
//! the `check_failed_label` accessor: pre-lift both spelled the
//! identical `"<Endpoint> check failed"` prefix, and the enum pins that
//! sharing so a future rename of the shared prefix (say a shift to
//! `"<Endpoint> gate failed"`) rotates BOTH branches by editing one
//! match-arm. A future refactor that wanted the two axes to diverge
//! would introduce a second accessor (e.g. `transport_failed_label`)
//! rather than duplicate the label at the call sites.
//!
//! # Why extend the existing closed enum rather than introduce a new one
//!
//! The pre-lift transport-error labels do not name a fresh
//! classification — they name the same two post-deploy verification
//! gates the status-failure and pass branches already discriminate. A
//! parallel enum with variants `HealthTransportError`/
//! `GraphqlTransportError` would duplicate the endpoint-classification
//! axis and let the three branches drift; the extension pins that all
//! three axes share ONE variant per endpoint.

use crate::post_deploy_endpoint_status_failure::PostDeployEndpointCheck;

/// Print the one-line `   ❌ <Endpoint> check failed: <err>`
/// step-failure grammar via
/// [`crate::ui::print_step_failure_with_error`], projecting the
/// endpoint's pre-lift label through
/// [`PostDeployEndpointCheck::check_failed_label`] so the transport-
/// error branch shares one source of truth for the label with the
/// status-failure branch's sibling primitive.
pub fn print_post_deploy_endpoint_transport_failure(
    check: PostDeployEndpointCheck,
    err: &dyn std::fmt::Display,
) {
    crate::ui::print_step_failure_with_error(check.check_failed_label(), err);
}

/// Writer-taking sibling to
/// [`print_post_deploy_endpoint_transport_failure`]. Emits the same
/// one-line `   ❌ <Endpoint> check failed: <err>` via
/// [`crate::ui::write_step_failure_with_error`] against the supplied
/// writer so tests can pin the pre-lift byte-shape (three-space
/// indent, `❌ ` glyph, `\x1b[31m` red ANSI palette on the glyph, the
/// literal `": "` connective between label and error, and the caller-
/// supplied `Display`-formatted error reproduced byte-for-byte)
/// without capturing stdout.
pub fn write_post_deploy_endpoint_transport_failure<W>(
    w: &mut W,
    check: PostDeployEndpointCheck,
    err: &dyn std::fmt::Display,
) -> std::io::Result<()>
where
    W: std::io::Write,
{
    crate::ui::write_step_failure_with_error(w, check.check_failed_label(), err)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Label reuse pin: the transport-error branch reads the SAME
    /// `check_failed_label` accessor the status-failure branch reads.
    /// Pre-lift the two spelled identical `"<Endpoint> check failed"`
    /// prefixes, and this primitive pins that sharing. A future
    /// divergence (a fresh `transport_failed_label` accessor) is a
    /// deliberate change: it would replace this delegation and trip
    /// this test.
    #[test]
    fn transport_failure_label_reads_check_failed_label_accessor() {
        assert_eq!(
            PostDeployEndpointCheck::Health.check_failed_label(),
            "Health check failed",
        );
        assert_eq!(
            PostDeployEndpointCheck::Graphql.check_failed_label(),
            "GraphQL check failed",
        );
    }

    /// Byte-oracle: the writer sibling projects the pre-lift
    /// `crate::ui::print_step_failure_with_error(<label>, &e)`
    /// byte-shape verbatim — the same three-space indent, the same
    /// red `❌ ` glyph, the same literal `": "` connective between
    /// label and error, and the caller-supplied error's byte-for-byte
    /// reproduction. Compares against a direct
    /// [`crate::ui::write_step_failure_with_error`] against the same
    /// label + error so the pin holds whether ANSI is auto-enabled or
    /// auto-disabled on the host running the suite.
    #[test]
    fn write_post_deploy_endpoint_transport_failure_projects_prelift_shape() {
        for (check, error, expected_label) in [
            (
                PostDeployEndpointCheck::Health,
                "connection refused",
                "Health check failed",
            ),
            (
                PostDeployEndpointCheck::Graphql,
                "dns lookup timed out",
                "GraphQL check failed",
            ),
        ] {
            let mut buf: Vec<u8> = Vec::new();
            write_post_deploy_endpoint_transport_failure(&mut buf, check, &error)
                .expect("write against a Vec<u8> writer must succeed");
            let mut peer: Vec<u8> = Vec::new();
            crate::ui::write_step_failure_with_error(&mut peer, expected_label, &error)
                .expect("peer write against a Vec<u8> writer must succeed");
            assert_eq!(
                buf, peer,
                "the primitive's writer sibling must project the same byte-shape as \
                 `crate::ui::write_step_failure_with_error(w, \"{expected_label}\", &error)`",
            );
            let out = String::from_utf8(buf).expect("writer emits valid UTF-8");
            assert!(
                out.contains(expected_label),
                "emitted line must carry the `<label>` prefix verbatim; got {out:?}",
            );
            assert!(
                out.contains(error),
                "emitted line must carry the caller-supplied error's Display projection \
                 verbatim; got {out:?}",
            );
        }
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` may spell the raw pre-lift
    /// `crate::ui::print_step_failure_with_error("<Endpoint> check
    /// failed", …)` composition inline any more. The two pre-lift
    /// sites migrated; any future consumer that wants the same
    /// transport-error grammar reaches for
    /// [`print_post_deploy_endpoint_transport_failure`] on first grep,
    /// not by copy-pasting the raw call from an existing module.
    ///
    /// Reconstructed at test time via [`format!`] so this shield's
    /// own source text does not false-match itself; the whole-scan
    /// therefore covers both the top-of-file production body AND
    /// every sibling `#[cfg(test)]` block. Line-comment and
    /// block-comment lines are skipped so a future module that
    /// quotes the pre-lift shape as historical prose does not trip
    /// the shield.
    #[test]
    fn no_command_module_still_spells_raw_endpoint_transport_failure_call() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let scan_dir = crate_src.join("commands");

        let call_prefix = format!("crate::ui::print_step_failure_with_error({}", "\"");
        let forbidden_needles = [
            format!("{}Health check failed\"", call_prefix),
            format!("{}GraphQL check failed\"", call_prefix),
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
            "raw `crate::ui::print_step_failure_with_error(\"<Endpoint> check failed\", …)` \
             call(s) survive under `commands/` — route each through \
             `crate::post_deploy_endpoint_transport_failure::print_post_deploy_endpoint_transport_failure` \
             instead:\n{offenders:#?}",
        );
    }

    /// Caller shield (positive half): the one pre-lift module that
    /// housed both sites (`commands/post_deploy_verification.rs`)
    /// MUST forward through
    /// [`print_post_deploy_endpoint_transport_failure`] at least
    /// twice, so a migration that dropped a call site outright leaves
    /// the negative "no raw inline shape" scan trivially satisfied by
    /// absence but the positive count still fails. Mirrors the sibling
    /// `commands_post_deploy_verification_forwards_through_print_post_deploy_endpoint_status_failure`
    /// and
    /// `commands_post_deploy_verification_forwards_through_print_post_deploy_endpoint_check_pass`
    /// shields the crate carries against the other two branches.
    #[test]
    fn commands_post_deploy_verification_forwards_through_print_post_deploy_endpoint_transport_failure(
    ) {
        use std::path::PathBuf;
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands")
            .join("post_deploy_verification.rs");
        let needle = "print_post_deploy_endpoint_transport_failure(";
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
        let forwards = source.matches(needle).count();
        assert!(
            forwards >= 2,
            "{} must forward at least 2 post-deploy endpoint transport-error site(s) through \
             `{}`; found {}. A dropped call would leave the negative raw-shape scan \
             satisfied by absence.",
            path.display(),
            needle,
            forwards,
        );
    }
}
