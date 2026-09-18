//! Post-deploy verification gate preamble — the three sibling
//! `crate::ui::print_step_heading("G<N>: <title>") +
//! let client = crate::post_deploy_http_client::build_post_deploy_http_client(timeout)?`
//! fused two-line stanzas collapsed onto one typed primitive.
//!
//! # Pre-lift census — three sibling gate-entry preambles, one grammar
//!
//! Three post-deploy verification entries in
//! `commands/post_deploy_verification.rs` each opened with the same
//! two-line ceremony verbatim: the bold `Gxx: <title>` step heading
//! followed by the lenient staging TLS client bind. Each carried its
//! own `Gxx: <title>` string and shared the `timeout` binding pattern
//! for the client's timeout clamp:
//!
//! 1. `verify_health_endpoint` (G12 heading `"G12: Health endpoint
//!    check"`, `timeout: Duration` parameter).
//! 2. `verify_graphql_endpoint` (G13 heading `"G13: GraphQL
//!    introspection check"`, `timeout: Duration` parameter).
//! 3. `verify_smoke_queries` (G15 heading `"G15: Smoke query
//!    validation"`, `timeout: Duration` parameter).
//!
//! All three entries then consume the resulting [`reqwest::Client`]
//! against a caller-supplied post-deploy URL. Post-lift each entry
//! reaches for [`announce_and_build_post_deploy_gate_client`] and the
//! `(gate-heading + build-client)` pair is decided once here rather
//! than at three independent call sites.
//!
//! # Why fuse the heading with the client construction
//!
//! The pre-lift shape allowed the heading label to drift from the
//! entry's function body — an entry that gained a new probe step
//! could silently be introduced without its `Gxx: <title>` heading,
//! or worse, with a heading that named a different gate. Fusing the
//! two-line preamble onto one typed body pins the invariant that
//! every post-deploy gate entry announces itself and constructs its
//! client through the same call, and closes on the pre-existing
//! [`crate::post_deploy_http_client::build_post_deploy_http_client`]
//! discipline (one place for the security-sensitive
//! `danger_accept_invalid_certs(true)` decision, one place for the
//! `Failed to build HTTP client` context envelope).
//!
//! # Why a closed enum, not a `&str` heading
//!
//! The three pre-lift heading strings are not arbitrary — they name
//! the specific post-deploy verification gate and its `Gxx` catalog
//! index. A closed enum keeps the caller side type-directed: a new
//! gate entry cannot silently ship with a fresh heading string that
//! drifts from the sibling grammar. The heading label lives in one
//! match-arm accessor whose branches enum exhaustiveness pins, so a
//! future rename (`Gxx` → `V<n>`, a shift to `"Post-deploy G<n>:
//! …"`, an OTLP `post_deploy_gate` observability event wired
//! alongside the heading) rotates all three entries in lockstep.
//!
//! # Frontier grounding — Bazel / Buck2 / Tekton typed gate entries
//!
//! Hermetic build systems and pipeline orchestrators (Bazel remote
//! test entries, Buck2 audit passes, Tekton `Task` gate steps) each
//! carry a typed gate-entry surface: one enum, one label accessor,
//! one central construction point. The per-entry copy-paste of the
//! heading + client-build preamble is a known anti-pattern in that
//! lineage. This primitive brings the same single-body discipline to
//! forge's post-deploy verification surface: one gate enum, one
//! heading accessor, one place a preamble-shape change lands.
//!
//! # THEORY grounding
//!
//! THEORY.md §V.1 (Construction guarantees): "Define Rust types that
//! make invalid states unrepresentable." The pre-lift shape allowed a
//! silent divergence between the three sibling gate-entry preambles
//! — a mis-typed `Gxx` prefix, a heading that named the wrong gate,
//! a client built without the shared lenient-TLS envelope. The typed
//! primitive makes each divergence unrepresentable: every entry
//! projects its heading through the same enum accessor and builds
//! its client through the same constructor.

use anyhow::Result;
use reqwest::Client;
use std::time::Duration;

/// The closed set of post-deploy verification gate entries that emit
/// a two-line `print_step_heading + build_post_deploy_http_client`
/// preamble through this primitive. Each variant maps to one
/// `commands/post_deploy_verification.rs` entry
/// (`verify_health_endpoint` / `verify_graphql_endpoint` /
/// `verify_smoke_queries`) and pins its operator-facing
/// `"Gxx: <title>"` heading via
/// [`PostDeployGate::heading_title`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostDeployGate {
    /// G12: `verify_health_endpoint` — the health probe's gate entry.
    /// Pre-lift heading: `"G12: Health endpoint check"`.
    Health,
    /// G13: `verify_graphql_endpoint` — the introspection probe's
    /// gate entry. Pre-lift heading: `"G13: GraphQL introspection
    /// check"`.
    Graphql,
    /// G15: `verify_smoke_queries` — the smoke-query gate entry.
    /// Pre-lift heading: `"G15: Smoke query validation"`.
    SmokeQueries,
}

impl PostDeployGate {
    /// The pre-lift `"Gxx: <title>"` heading string the three sibling
    /// entries handed to [`crate::ui::print_step_heading`]. Named by
    /// arm-accessor so a new gate entry cannot silently ship with a
    /// fresh string that drifts from the pre-lift catalog.
    pub const fn heading_title(self) -> &'static str {
        match self {
            Self::Health => "G12: Health endpoint check",
            Self::Graphql => "G13: GraphQL introspection check",
            Self::SmokeQueries => "G15: Smoke query validation",
        }
    }
}

/// Print the gate's bold `Gxx: <title>` step heading and construct
/// the lenient-TLS post-deploy [`reqwest::Client`] the three sibling
/// entries share. Fuses the pre-lift two-line
/// `print_step_heading("Gxx: <title>") + let client =
/// build_post_deploy_http_client(timeout)?` stanza onto ONE typed
/// call so a future adjustment (a heading rename, an OTLP
/// `post_deploy_gate` observability event fired alongside the
/// heading, a security-hardening pass on the shared client's TLS
/// envelope) rotates all three gate entries in lockstep.
///
/// # Errors
///
/// Returns the error from
/// [`crate::post_deploy_http_client::build_post_deploy_http_client`]
/// verbatim — the pre-lift `?`-propagating shape at each of the three
/// sibling entries.
pub fn announce_and_build_post_deploy_gate_client(
    gate: PostDeployGate,
    timeout: Duration,
) -> Result<Client> {
    crate::ui::print_step_heading(gate.heading_title());
    crate::post_deploy_http_client::build_post_deploy_http_client(timeout)
}

/// Writer-taking sibling that emits the pre-lift `print_step_heading`
/// line via [`crate::ui::write_step_heading`] so tests can pin the
/// two-line preamble's heading half's byte-shape (the `<title>.bold()`
/// projection, the `\n` terminator, the exact `Gxx: <title>` payload)
/// without capturing stdout OR building a client. Split from
/// [`announce_and_build_post_deploy_gate_client`] because the client
/// construction is I/O-touching (a `reqwest::Client` still binds even
/// against no host, but the byte-oracle wants a pure heading pin).
pub fn write_post_deploy_gate_heading<W>(w: &mut W, gate: PostDeployGate) -> std::io::Result<()>
where
    W: std::io::Write,
{
    crate::ui::write_step_heading(w, gate.heading_title())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Label pin: each `PostDeployGate` variant projects the pre-lift
    /// `"Gxx: <title>"` heading verbatim. All three sibling call
    /// sites shared these exact strings; the enum's arm-accessor is
    /// the one source of truth. A change here rotates the three
    /// entries in lockstep.
    #[test]
    fn test_post_deploy_gate_heading_title_matches_pre_lift_literals() {
        assert_eq!(
            PostDeployGate::Health.heading_title(),
            "G12: Health endpoint check",
        );
        assert_eq!(
            PostDeployGate::Graphql.heading_title(),
            "G13: GraphQL introspection check",
        );
        assert_eq!(
            PostDeployGate::SmokeQueries.heading_title(),
            "G15: Smoke query validation",
        );
    }

    /// Byte-oracle: the writer sibling projects the pre-lift
    /// `crate::ui::print_step_heading("Gxx: <title>")` byte-shape
    /// verbatim — the same `<title>.bold()` projection, the same
    /// `\n` terminator, the same caller-supplied heading payload
    /// reproduced byte-for-byte. Compares against a direct
    /// [`crate::ui::write_step_heading`] against the same title so
    /// the pin holds whether ANSI is auto-enabled or auto-disabled
    /// on the host running the suite.
    #[test]
    fn test_write_post_deploy_gate_heading_projects_prelift_shape() {
        for gate in [
            PostDeployGate::Health,
            PostDeployGate::Graphql,
            PostDeployGate::SmokeQueries,
        ] {
            let mut buf: Vec<u8> = Vec::new();
            write_post_deploy_gate_heading(&mut buf, gate)
                .expect("write against a Vec<u8> writer must succeed");
            let mut peer: Vec<u8> = Vec::new();
            crate::ui::write_step_heading(&mut peer, gate.heading_title())
                .expect("peer write against a Vec<u8> writer must succeed");
            assert_eq!(
                buf, peer,
                "the primitive's writer sibling must project the same byte-shape as \
                 `crate::ui::write_step_heading(w, <gate>.heading_title())` for {gate:?}",
            );
            let out = String::from_utf8(buf).expect("writer emits valid UTF-8");
            assert!(
                out.contains(gate.heading_title()),
                "emitted line must carry the `Gxx: <title>` payload verbatim; got {out:?}",
            );
        }
    }

    /// Constructor pin: the fused call builds a usable
    /// [`reqwest::Client`] for any positive timeout. Confirms the
    /// primitive delegates to
    /// [`crate::post_deploy_http_client::build_post_deploy_http_client`]
    /// (which itself accepts a caller-supplied `Duration` at every
    /// site the pre-lift census enumerated).
    #[test]
    fn test_announce_and_build_post_deploy_gate_client_builds_a_client() {
        for gate in [
            PostDeployGate::Health,
            PostDeployGate::Graphql,
            PostDeployGate::SmokeQueries,
        ] {
            announce_and_build_post_deploy_gate_client(gate, Duration::from_secs(30))
                .unwrap_or_else(|_| panic!("client must build for gate {gate:?}"));
        }
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` may spell the raw pre-lift
    /// `crate::ui::print_step_heading("G12: Health endpoint check")` /
    /// `"G13: GraphQL introspection check"` /
    /// `"G15: Smoke query validation"` heading inline any more.
    /// The three pre-lift sites migrated; any future consumer that
    /// wants the same gate preamble reaches for
    /// [`announce_and_build_post_deploy_gate_client`] on first grep,
    /// not by copy-pasting the raw `print_step_heading` from an
    /// existing verify function.
    ///
    /// Line-comment and block-comment lines are skipped so a future
    /// module that quotes the pre-lift shape as historical prose
    /// does not trip the shield.
    #[test]
    fn no_command_module_still_spells_raw_post_deploy_gate_heading() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let scan_dir = crate_src.join("commands");

        let forbidden_needles = [
            format!("print_step_heading(\"{}\")", "G12: Health endpoint check"),
            format!(
                "print_step_heading(\"{}\")",
                "G13: GraphQL introspection check",
            ),
            format!("print_step_heading(\"{}\")", "G15: Smoke query validation"),
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
            "raw `print_step_heading(\"Gxx: <title>\")` spelling(s) survive under \
             `commands/` — route each through \
             `crate::post_deploy_gate_preamble::announce_and_build_post_deploy_gate_client` \
             instead:\n{offenders:#?}",
        );
    }

    /// Caller shield (positive half): the one pre-lift module that
    /// housed all three sites (`commands/post_deploy_verification.rs`)
    /// MUST forward through
    /// [`announce_and_build_post_deploy_gate_client`] at least the
    /// three sibling entries, so a migration that dropped a call
    /// site outright leaves the negative "no raw heading" scan
    /// trivially satisfied by absence but the positive count still
    /// fails. Mirrors the sibling
    /// `every_prelift_module_forwards_through_*` shields the crate
    /// carries against every other typed primitive.
    #[test]
    fn commands_post_deploy_verification_forwards_through_announce_and_build_post_deploy_gate_client(
    ) {
        use std::path::PathBuf;
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands")
            .join("post_deploy_verification.rs");
        let needle = "announce_and_build_post_deploy_gate_client(";
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
        let forwards = source.matches(needle).count();
        assert!(
            forwards >= 3,
            "{} must forward at least 3 post-deploy gate-preamble site(s) through \
             `{}`; found {}. A dropped call would leave the negative raw-shape scan \
             satisfied by absence.",
            path.display(),
            needle,
            forwards,
        );
    }
}
