//! Timed GraphQL POST primitive for post-deploy verification.
//!
//! Two sibling stanzas in `commands/post_deploy_verification.rs`
//! respell the same "wrap a query string in a
//! `{ \"query\": <str> }` JSON body, `POST` it to the GraphQL
//! endpoint with a `Content-Type: application/json` header, and
//! bracket the request in an [`Instant`]-based millisecond latency
//! capture" grammar verbatim pre-lift:
//!
//! ```ignore
//! let query = serde_json::json!({ "query": <query_str> });
//! let start = Instant::now();
//! match client
//!     .post(graphql_url)
//!     .header("Content-Type", "application/json")
//!     .json(&query)
//!     .send()
//!     .await
//! {
//!     Ok(response) => {
//!         let latency_ms = start.elapsed().as_millis() as u64;
//!         /* … Ok arm … */
//!     }
//!     Err(e) => { /* … Err arm … */ }
//! }
//! ```
//!
//! Pre-lift the two sites lived at:
//!
//! 1. `commands/post_deploy_verification.rs::verify_graphql_endpoint`
//!    (G13 introspection probe): fixed query
//!    `"{ __typename }"`, `latency_ms` fed to
//!    `print_step_pass(&format!("GraphQL responding ({}ms)", …))` on
//!    the success arm.
//! 2. `commands/post_deploy_verification.rs::verify_smoke_queries`
//!    (G15 smoke-query loop body): caller-supplied `smoke.query`,
//!    `latency_ms` fed to per-smoke `print_step_pass(&format!("{}: OK
//!    ({}ms)", smoke.name, latency_ms))` on the success arm.
//!
//! Post-lift both consumers route through
//! [`send_graphql_query_timed`]; the wrapped `Content-Type` header,
//! the `serde_json::json!({ "query": … })` body shape, and the
//! [`Instant`]-based `u64` millisecond projection all live at one
//! construction surface. A future refinement — a swap of the
//! `Content-Type` for `application/graphql-response+json` per the
//! finalized [GraphQL-over-HTTP] spec, a promotion of the timing
//! sample to an OpenTelemetry `graphql.request.duration_ms` histogram,
//! a retry-with-jitter wrapper on transient transport failures, a
//! `X-Request-Id` header injection for cross-service correlation —
//! lands at ONE typed body and reaches both consumers by construction.
//!
//! # Frontier grounding
//!
//! Every hermetic-build system in the Bazel / Buck2 / Pants /
//! BuildKit lineage funnels its remote-artifact probes through a
//! single typed HTTP-request surface (Bazel's `HttpBlobStore`,
//! BuildKit `client/client.go`, Buck2 `re_client`). The per-call-site
//! restatement of a `builder(...).method(...).header(...).body(...)`
//! chain is a known frontier anti-pattern: it hides which sites
//! attach `Content-Type`, which measure latency, which propagate a
//! request id, and it lets those attributes drift silently between
//! callers. This primitive brings the same single-body discipline to
//! forge's post-deploy verification surface.
//!
//! # Errors, and why the error path drops latency
//!
//! On [`reqwest::Error`] the primitive returns the transport error
//! without a latency sample. Both pre-lift call sites match the
//! `Err` arm with a `(false, None)` return, discarding any partial
//! timing information — the `send`-error surface (name resolution
//! failure, TLS handshake abort, connection refused) is not a
//! well-formed request-response transaction and its elapsed time
//! carries no comparable meaning against the success-path latency.
//! Preserving that pre-lift discipline avoids two subtle defects:
//!
//! 1. A DNS-failure `latency_ms` (typically <1ms) landing next to a
//!    successful 200ms probe would falsely lower an aggregated
//!    p50/p99 latency histogram on the operator dashboard.
//! 2. A transport-error return of `Some(latency_ms)` would tempt a
//!    downstream summariser to render "GraphQL failed in 0ms" — a
//!    literally-correct claim that misleads about whether the probe
//!    reached the server or died at the socket layer.
//!
//! # THEORY grounding
//!
//! - `THEORY.md §I.5` (duplication budget zero): two byte-identical
//!   4-line request-construction stanzas across two sibling gates
//!   crossed the two-occurrence coincidence threshold. Post-lift the
//!   grammar owns one construction surface.
//! - `THEORY.md §II.1` invariant 4 (types are theorems): the
//!   `Result<(Response, u64), reqwest::Error>` return type makes the
//!   "latency is available if and only if the request completed"
//!   invariant unrepresentable in error, closing the two defects
//!   above by construction.
//! - `THEORY.md §V.1` (construction guarantees): every post-deploy
//!   GraphQL probe funnels through one body; a security-hardening or
//!   observability change lands once and reaches every consumer.
//!
//! [GraphQL-over-HTTP]: https://graphql.github.io/graphql-over-http/

use reqwest::{Client, Response};
use std::time::Instant;

/// The single `Content-Type` header value the two pre-lift call sites
/// spelled `"application/json"` verbatim. Lifted to a constant so a
/// future migration to `application/graphql-response+json` (per the
/// finalized GraphQL-over-HTTP spec) lands here.
pub(crate) const GRAPHQL_REQUEST_CONTENT_TYPE: &str = "application/json";

/// The JSON key under which the query string is wrapped in the POST
/// body. Both pre-lift sites spelled `"query"` verbatim. A future
/// promotion to a `{ "query": …, "variables": …, "operationName": … }`
/// three-key envelope lands here.
pub(crate) const GRAPHQL_REQUEST_QUERY_KEY: &str = "query";

/// POST `query_str` (wrapped as `{ "query": <query_str> }`) to
/// `graphql_url` via `client`, and return the response paired with
/// its request-completion latency in milliseconds.
///
/// The latency sample brackets from just before `send()` is invoked
/// to just after the future resolves to a `Response`. It captures
/// the full request round-trip — DNS, connect, TLS, request write,
/// server processing, response headers — but NOT the response-body
/// read (which the pre-lift stanzas also excluded, since the body
/// deserialization runs after the `match` arm binds `latency_ms`).
///
/// # Errors
///
/// Returns the [`reqwest::Error`] from a transport-layer failure
/// (name resolution, TLS handshake, connection reset, request-timeout
/// deadline). See the module docstring for why the latency sample is
/// intentionally not returned on this arm.
pub async fn send_graphql_query_timed(
    client: &Client,
    graphql_url: &str,
    query_str: &str,
) -> Result<(Response, u64), reqwest::Error> {
    let body = serde_json::json!({ GRAPHQL_REQUEST_QUERY_KEY: query_str });
    let start = Instant::now();
    let response = client
        .post(graphql_url)
        .header("Content-Type", GRAPHQL_REQUEST_CONTENT_TYPE)
        .json(&body)
        .send()
        .await?;
    let latency_ms = start.elapsed().as_millis() as u64;
    Ok((response, latency_ms))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `GRAPHQL_REQUEST_CONTENT_TYPE` pins the pre-lift byte-literal
    /// `"application/json"` header value. A change here is a
    /// deliberate migration of the request `Content-Type` (e.g. to
    /// `application/graphql-response+json`) and cascades to both
    /// consumers by construction — not a silent drift.
    #[test]
    fn graphql_request_content_type_pins_application_json_verbatim() {
        assert_eq!(GRAPHQL_REQUEST_CONTENT_TYPE, "application/json");
    }

    /// `GRAPHQL_REQUEST_QUERY_KEY` pins the pre-lift JSON body key
    /// `"query"`. A future promotion to a full
    /// `{ "query": …, "variables": …, "operationName": … }` envelope
    /// starts with a widening of the primitive's signature; this
    /// constant guards the single-key shape that pre-lift both
    /// consumers depended on.
    #[test]
    fn graphql_request_query_key_pins_query_verbatim() {
        assert_eq!(GRAPHQL_REQUEST_QUERY_KEY, "query");
    }

    /// Positive delegation shield: the two pre-lift stanzas in
    /// `commands/post_deploy_verification.rs` must delegate through
    /// [`send_graphql_query_timed`]. Post-lift the source file
    /// carries exactly two call-line references to the primitive
    /// (the `verify_graphql_endpoint` G13 introspection site and the
    /// `verify_smoke_queries` G15 per-smoke loop-body site) plus
    /// zero re-inlined restatements of the pre-lift builder chain.
    ///
    /// A refactor that splits or fuses either call site adjusts this
    /// count deliberately; a refactor that re-inlines the pre-lift
    /// stanza at either site fails the assertion.
    #[test]
    fn commands_post_deploy_verification_delegates_via_send_graphql_query_timed() {
        let source = include_str!("./commands/post_deploy_verification.rs");
        let hits = crate::test_support::code_line_hits(source, "send_graphql_query_timed(");
        assert_eq!(
            hits.len(),
            2,
            "commands/post_deploy_verification.rs must call \
             `send_graphql_query_timed(` at exactly two sites \
             (verify_graphql_endpoint G13 + verify_smoke_queries G15 \
             loop body); found {} hits: {hits:?}",
            hits.len(),
        );
    }

    /// Caller-shield (negative half): the pre-lift raw
    /// `.header("Content-Type", "application/json")` stanza no longer
    /// appears in `commands/post_deploy_verification.rs`. Both
    /// consumer sites migrated onto [`send_graphql_query_timed`],
    /// which owns the header attachment at ONE construction surface.
    ///
    /// The three-space indent inside the pre-lift builder chain is
    /// specific enough that a future reader who reaches for the same
    /// stanza by copy-paste — bypassing the primitive — fails this
    /// shield rather than silently re-adding a duplicate.
    #[test]
    fn commands_post_deploy_verification_carries_no_raw_content_type_header_stanza() {
        let source = include_str!("./commands/post_deploy_verification.rs");
        let hits = crate::test_support::code_line_hits(
            source,
            ".header(\"Content-Type\", \"application/json\")",
        );
        assert!(
            hits.is_empty(),
            "commands/post_deploy_verification.rs must not spell the \
             pre-lift raw `.header(\"Content-Type\", \
             \"application/json\")` builder line — both call sites \
             migrated onto `send_graphql_query_timed` which owns \
             that header attachment; found: {hits:?}",
        );
    }

    /// Caller-shield (negative half): the pre-lift
    /// `serde_json::json!({ "query": …` body-wrap opener no longer
    /// appears in `commands/post_deploy_verification.rs`. Post-lift
    /// the body-wrap lives at [`send_graphql_query_timed`]'s body.
    #[test]
    fn commands_post_deploy_verification_carries_no_raw_query_body_wrap_stanza() {
        let source = include_str!("./commands/post_deploy_verification.rs");
        let hits = crate::test_support::code_line_hits(source, "serde_json::json!({");
        assert!(
            hits.is_empty(),
            "commands/post_deploy_verification.rs must not spell the \
             pre-lift `serde_json::json!({{` body-wrap opener — both \
             GraphQL POST call sites migrated onto \
             `send_graphql_query_timed` which owns the \
             `{{ \"query\": <str> }}` body-wrap; found: {hits:?}",
        );
    }

    /// The primitive's own source names both consumer functions in
    /// its module docstring — the "who calls this" question resolves
    /// at this file's head, not by grepping the workspace. Pins both
    /// mentions so a future rename of either consumer function is
    /// caught here and its docstring updated in step.
    #[test]
    fn module_docstring_names_both_pre_lift_consumer_functions() {
        let source = include_str!("./post_deploy_graphql_query.rs");
        assert!(
            source.contains("verify_graphql_endpoint"),
            "module docstring must name `verify_graphql_endpoint` — \
             the G13 introspection consumer",
        );
        assert!(
            source.contains("verify_smoke_queries"),
            "module docstring must name `verify_smoke_queries` — the \
             G15 smoke-query loop-body consumer",
        );
    }
}
