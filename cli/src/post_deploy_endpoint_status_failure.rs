//! Post-deploy endpoint status-failure line: the pre-lift 2 sibling
//! `crate::ui::print_step_failure(&format!("<Endpoint> check failed: Status {}", <status>))`
//! stanzas collapsed onto one typed primitive.
//!
//! # Pre-lift census — two sibling stanzas, one status-failure grammar
//!
//! Two consumer sites in `commands/post_deploy_verification.rs` each
//! spelled the same 4-line `print_step_failure` + `format!("<label>:
//! Status {}", <status>)` composition inline before the response-body
//! branch handed control back to the outer summary channel:
//!
//! 1. `commands/post_deploy_verification.rs::verify_health_endpoint`
//!    (pre-lift `Ok(response) => { … } else { … } else { … }` non-success
//!    branch, `<label>` = `"Health check failed"`, `<status>` = a
//!    pre-bound `let status = response.status();`).
//! 2. `commands/post_deploy_verification.rs::verify_graphql_endpoint`
//!    (pre-lift `Ok((response, latency_ms)) => { … } else { … }`
//!    non-success branch, `<label>` = `"GraphQL check failed"`,
//!    `<status>` = an inline `response.status()`).
//!
//! Both call sites already delegate the transport-error branch through
//! [`crate::ui::print_step_failure_with_error`] against the same
//! `"<Endpoint> check failed"` label, so this primitive completes the
//! pair: one owner for the two branches' shared `"<Endpoint> check
//! failed"` prefix, and one place to reword or restructure the "Status
//! {code}" tail (an eventual `reqwest::StatusCode`-aware split into
//! `<code> <canonical-reason>`, an OTLP `post_deploy_check_status`
//! observability event wired alongside the print) without hunting
//! through the two sibling verify entries.
//!
//! # Companion to the transport-error branch
//!
//! [`crate::ui::print_step_failure_with_error`] owns the transport-error
//! branch: `Err(e) => crate::ui::print_step_failure_with_error("<Endpoint>
//! check failed", &e)`. That primitive is invoked by both entries with
//! the same [`PostDeployEndpointCheck::check_failed_label`] the
//! status-failure branch reaches through here, so a future rename of
//! the shared `"<Endpoint> check failed"` prefix rotates both branches
//! in lockstep by editing [`PostDeployEndpointCheck::check_failed_label`]
//! alone.
//!
//! # Why a closed enum, not a `&str` label
//!
//! The two pre-lift labels are not arbitrary strings; they name the
//! post-deploy verification gate that failed and belong to a closed set
//! the module's public entries enumerate (`verify_health_endpoint`,
//! `verify_graphql_endpoint`). A closed enum keeps the caller side
//! type-directed — a new entry cannot silently ship with a fresh string
//! that drifts from its sibling's grammar — and moves the pre-lift
//! copy of the label into one match-arm accessor whose branches enum
//! exhaustiveness pins.

use std::fmt::Display;

/// The literal connective the pre-lift `format!("<label>: Status {}",
/// <status>)` composition placed between the check label and the
/// stringified status. Constant-lifted so the byte-oracle test and the
/// caller-shield remediation prose reference the same source of truth,
/// and a future adjustment (a shift to `" — status: "`, an
/// `.underline()` on the connective, a normalisation to
/// `<code> <canonical-reason>`) happens in exactly one place.
pub const POST_DEPLOY_ENDPOINT_STATUS_FAILURE_CONNECTIVE: &str = ": Status ";

/// The closed set of post-deploy endpoint verification gates that emit
/// a status-failure line through this primitive. Each variant maps to
/// one `commands/post_deploy_verification.rs` entry
/// (`verify_health_endpoint` / `verify_graphql_endpoint`) and pins its
/// operator-facing `"<Endpoint> check failed"` label via
/// [`PostDeployEndpointCheck::check_failed_label`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostDeployEndpointCheck {
    /// G12: `verify_health_endpoint` — the health probe's non-success
    /// response branch. Pre-lift label: `"Health check failed"`.
    Health,
    /// G13: `verify_graphql_endpoint` — the introspection probe's
    /// non-success response branch. Pre-lift label: `"GraphQL check
    /// failed"`.
    Graphql,
}

impl PostDeployEndpointCheck {
    /// The pre-lift `"<Endpoint> check failed"` label the two sibling
    /// sites handed to `format!("<label>: Status {}", <status>)`. Same
    /// label the transport-error branch of each entry passes to
    /// [`crate::ui::print_step_failure_with_error`], so the two
    /// branches share one source of truth.
    pub const fn check_failed_label(self) -> &'static str {
        match self {
            Self::Health => "Health check failed",
            Self::Graphql => "GraphQL check failed",
        }
    }

    /// The pre-lift `"<pass-label>"` label the two sibling `Ok`-branch
    /// sites in `commands/post_deploy_verification.rs` handed to
    /// `format!("<label> ({}ms)", latency_ms)` before returning
    /// `Ok((true, Some(latency_ms)))`. Consumed by
    /// [`crate::post_deploy_endpoint_check_pass::print_post_deploy_endpoint_check_pass`].
    ///
    /// The two labels are **not symmetric** with
    /// [`Self::check_failed_label`] — the pre-lift wording differs
    /// deliberately: the health probe reports `"Health check passed"`
    /// (a verb-past-tense discharge of the health assertion) while the
    /// GraphQL probe reports `"GraphQL responding"` (a present-tense
    /// liveness ack matching the introspection probe's semantics). The
    /// enum pins that asymmetry in one match-arm so a well-meaning
    /// homogenisation to `"<Endpoint> check passed"` at either site
    /// fails the label-pin test rather than silently changing the
    /// operator-facing grammar.
    pub const fn check_passed_label(self) -> &'static str {
        match self {
            Self::Health => "Health check passed",
            Self::Graphql => "GraphQL responding",
        }
    }
}

/// Compose the pre-lift `format!("<Endpoint> check failed: Status {}",
/// <status>)` message shape without touching the writer. Split from
/// [`print_post_deploy_endpoint_status_failure`] so the pure-string
/// projection can be pinned by unit tests without capturing stdout,
/// and so a caller that wants to log or record the same message
/// alongside a diagnostics event does not have to re-derive it.
pub fn format_post_deploy_endpoint_status_failure_message<S: Display>(
    check: PostDeployEndpointCheck,
    status: S,
) -> String {
    format!(
        "{}{}{}",
        check.check_failed_label(),
        POST_DEPLOY_ENDPOINT_STATUS_FAILURE_CONNECTIVE,
        status,
    )
}

/// Print the one-line `   ❌ <Endpoint> check failed: Status <status>`
/// step-failure grammar via [`crate::ui::print_step_failure`],
/// composing the message through
/// [`format_post_deploy_endpoint_status_failure_message`] so the
/// pre-lift wording, connective, and status-render byte-shape lift
/// onto ONE typed body.
pub fn print_post_deploy_endpoint_status_failure<S: Display>(
    check: PostDeployEndpointCheck,
    status: S,
) {
    crate::ui::print_step_failure(&format_post_deploy_endpoint_status_failure_message(
        check, status,
    ));
}

/// Writer-taking sibling to [`print_post_deploy_endpoint_status_failure`].
/// Emits the same one-line `   ❌ <Endpoint> check failed: Status
/// <status>` via [`crate::ui::write_step_failure`] against the supplied
/// writer so tests can pin the pre-lift byte-shape (three-space indent,
/// `❌ ` glyph, `\x1b[31m` red ANSI palette on the glyph, the literal
/// `: Status ` connective between label and status, and the caller-
/// supplied `Display`-formatted status reproduced byte-for-byte)
/// without capturing stdout.
pub fn write_post_deploy_endpoint_status_failure<W, S>(
    w: &mut W,
    check: PostDeployEndpointCheck,
    status: S,
) -> std::io::Result<()>
where
    W: std::io::Write,
    S: Display,
{
    crate::ui::write_step_failure(
        w,
        &format_post_deploy_endpoint_status_failure_message(check, status),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Constant pin: the connective the pre-lift two sites spelled
    /// between the check label and the stringified status is the
    /// verbatim `": Status "` fragment. A change here rotates both
    /// sibling call sites in lockstep.
    #[test]
    fn test_post_deploy_endpoint_status_failure_connective_matches_pre_lift_literal() {
        assert_eq!(POST_DEPLOY_ENDPOINT_STATUS_FAILURE_CONNECTIVE, ": Status ");
    }

    /// Label pin: each `PostDeployEndpointCheck` variant projects the
    /// pre-lift `"<Endpoint> check failed"` label verbatim. Both
    /// sibling call sites shared the same `<Endpoint> check failed`
    /// suffix; the enum's arm-accessor is the one source of truth.
    #[test]
    fn test_post_deploy_endpoint_check_failed_label_matches_pre_lift_literals() {
        assert_eq!(
            PostDeployEndpointCheck::Health.check_failed_label(),
            "Health check failed",
        );
        assert_eq!(
            PostDeployEndpointCheck::Graphql.check_failed_label(),
            "GraphQL check failed",
        );
    }

    /// Format pin: the message projection composes exactly
    /// `"<Endpoint> check failed: Status <status>"` — the pre-lift
    /// `format!(...)` byte-shape both sibling sites spelled inline.
    #[test]
    fn test_format_post_deploy_endpoint_status_failure_message_matches_pre_lift_shape() {
        assert_eq!(
            format_post_deploy_endpoint_status_failure_message(
                PostDeployEndpointCheck::Health,
                503,
            ),
            "Health check failed: Status 503",
        );
        assert_eq!(
            format_post_deploy_endpoint_status_failure_message(
                PostDeployEndpointCheck::Graphql,
                "500 Internal Server Error",
            ),
            "GraphQL check failed: Status 500 Internal Server Error",
        );
    }

    /// Byte-oracle: the writer sibling projects the pre-lift
    /// `crate::ui::print_step_failure(&format!("<Endpoint> check failed:
    /// Status {}", <status>))` byte-shape verbatim — the same
    /// three-space indent, the same red `❌ ` glyph, the same literal
    /// `: Status ` connective between label and status, and the same
    /// caller-supplied status reproduced byte-for-byte. Compares
    /// against a direct [`crate::ui::write_step_failure`] against the
    /// same composed message so the pin holds whether ANSI is
    /// auto-enabled or auto-disabled on the host running the suite.
    #[test]
    fn test_write_post_deploy_endpoint_status_failure_projects_prelift_shape() {
        for (check, status_str, expected_payload) in [
            (
                PostDeployEndpointCheck::Health,
                "503",
                "Health check failed: Status 503",
            ),
            (
                PostDeployEndpointCheck::Graphql,
                "500 Internal Server Error",
                "GraphQL check failed: Status 500 Internal Server Error",
            ),
        ] {
            let mut buf: Vec<u8> = Vec::new();
            write_post_deploy_endpoint_status_failure(&mut buf, check, status_str)
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
                "emitted line must carry the `<Endpoint> check failed: Status <status>` \
                 payload verbatim; got {out:?}",
            );
        }
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` may spell the raw pre-lift
    /// `format!("<Endpoint> check failed: Status {}", …)` composition
    /// inline any more. The two pre-lift sites migrated; any future
    /// consumer that wants the same status-failure grammar reaches for
    /// [`print_post_deploy_endpoint_status_failure`] on first grep,
    /// not by copy-pasting the raw `format!` from an existing module.
    ///
    /// Reconstructed at test time via [`format!`] so this shield's own
    /// source text does not false-match itself; the whole-scan
    /// therefore covers both the top-of-file production body AND every
    /// sibling `#[cfg(test)]` block. Line-comment and block-comment
    /// lines are skipped so a future module that quotes the pre-lift
    /// shape as historical prose does not trip the shield.
    #[test]
    fn no_command_module_still_spells_raw_endpoint_check_failed_status_format() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let scan_dir = crate_src.join("commands");

        let forbidden_needles = [
            format!("\"Health{}Status {{}}\"", " check failed: ".to_string(),),
            format!("\"GraphQL{}Status {{}}\"", " check failed: ".to_string(),),
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
            "raw `format!(\"<Endpoint> check failed: Status {{}}\", …)` composition(s) \
             survive under `commands/` — route each through \
             `crate::post_deploy_endpoint_status_failure::print_post_deploy_endpoint_status_failure` \
             instead:\n{offenders:#?}",
        );
    }

    /// Caller shield (positive half): the one pre-lift module that
    /// housed both sites (`commands/post_deploy_verification.rs`) MUST
    /// forward through [`print_post_deploy_endpoint_status_failure`] at
    /// least twice, so a migration that dropped a call site outright
    /// leaves the negative "no raw inline shape" scan trivially
    /// satisfied by absence but the positive count still fails. Mirrors
    /// the sibling `every_prelift_module_forwards_through_*` shields
    /// the crate carries against every other typed primitive.
    #[test]
    fn commands_post_deploy_verification_forwards_through_print_post_deploy_endpoint_status_failure(
    ) {
        use std::path::PathBuf;
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands")
            .join("post_deploy_verification.rs");
        let needle = "print_post_deploy_endpoint_status_failure(";
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
        let forwards = source.matches(needle).count();
        assert!(
            forwards >= 2,
            "{} must forward at least 2 post-deploy endpoint status-failure site(s) through \
             `{}`; found {}. A dropped call would leave the negative raw-shape scan \
             satisfied by absence.",
            path.display(),
            needle,
            forwards,
        );
    }
}
