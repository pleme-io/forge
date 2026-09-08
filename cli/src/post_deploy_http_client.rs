//! Lenient HTTPS client for post-deploy verification probes.
//!
//! Four pre-lift sibling sites across
//! `commands/post_deploy_verification.rs`
//! (`verify_health_endpoint`, `verify_graphql_endpoint`,
//! `verify_smoke_queries`, `quick_health_check`) each restated the same
//! five-line [`reqwest::ClientBuilder`] chain verbatim:
//!
//! ```ignore
//! let client = Client::builder()
//!     .timeout(timeout)
//!     .danger_accept_invalid_certs(true) // For staging self-signed certs
//!     .build()
//!     .context("Failed to build HTTP client")?;
//! ```
//!
//! Post-lift each caller reaches for [`build_post_deploy_http_client`]
//! and the load-bearing `danger_accept_invalid_certs(true)` decision —
//! required by staging environments that terminate TLS with self-signed
//! or expired certificates — is decided once here rather than at four
//! independent call sites. A future security-hardening pass that scopes
//! the invalid-cert acceptance to a specific SAN, an environment gate,
//! or a caller-supplied trust anchor lands at ONE body and reaches
//! every post-deploy probe by construction.
//!
//! # The `danger_accept_invalid_certs(true)` decision, centralized
//!
//! Accepting invalid TLS certificates is a security-sensitive
//! configuration. The pre-lift stanzas each spelled the flag inline
//! next to a `// For staging self-signed certs` comment at one site
//! and no comment at three others. Centralizing the decision here
//! surfaces the WHY in one docstring where a security review lands
//! once, not four times. The primitive intentionally names itself
//! `build_post_deploy_http_client` — not `build_lenient_http_client`
//! or `build_https_client` — so a future caller reaching for it from a
//! non-post-deploy context (a webhook client, an outbound API call)
//! encounters a name mismatch and either narrows the primitive's
//! contract or reaches for a strict-verification sibling instead.
//!
//! # The `.context("Failed to build HTTP client")` envelope
//!
//! Three of the four pre-lift sites attached
//! `.context("Failed to build HTTP client")` on the `.build()?` — the
//! fourth (`quick_health_check`) omitted it. Post-lift every caller
//! inherits the same context envelope through the primitive, which
//! strictly improves the diagnostic surface of `quick_health_check`
//! without changing any of the three sites that already carried the
//! context.
//!
//! # Frontier grounding — Bazel / Buck2 / BuildKit hermetic clients
//!
//! Hermetic build systems (Bazel remote-cache, Buck2 remote-execution,
//! BuildKit's export layer) each carry a single, typed HTTP client
//! configuration surface for their remote-artifact probes — the
//! per-call reconstruction of a bare builder chain is a known
//! anti-pattern (see BuildKit `client/client.go` and Bazel's
//! `RemoteRetrier`). This primitive brings the same single-body
//! discipline to forge's post-deploy verification surface: one client
//! constructor, one timeout parameter, one place a security-hardening
//! change lands.
//!
//! # THEORY grounding
//!
//! THEORY.md §V.1 (Construction guarantees): "Define Rust types that
//! make invalid states unrepresentable." The pre-lift shape allowed a
//! silent divergence between the three-with-context and one-without-
//! context callers; the typed primitive makes the divergence
//! unrepresentable — every caller inherits the same envelope.

use anyhow::{Context, Result};
use reqwest::Client;
use std::time::Duration;

/// Build the canonical [`reqwest::Client`] every post-deploy verification
/// probe in `commands/post_deploy_verification.rs` shares — a `timeout`
/// clamp, `danger_accept_invalid_certs(true)` for staging self-signed
/// TLS, and a `Failed to build HTTP client` context envelope on the
/// `.build()?` step.
///
/// # Why `danger_accept_invalid_certs(true)`
///
/// Staging environments terminate TLS with self-signed or long-lived
/// certificates that the system trust store rejects. The pre-lift
/// stanzas each accepted invalid certs inline; centralizing the
/// decision here means a future security-hardening pass (scoping the
/// acceptance to a specific SAN, gating on an environment name,
/// injecting a caller-supplied trust anchor) lands at ONE body and
/// reaches every post-deploy probe by construction.
///
/// # Why this primitive is `post-deploy`-scoped, not generic
///
/// The `danger_accept_invalid_certs(true)` flag is a security-sensitive
/// default that should NOT be silently inherited by a webhook client,
/// an outbound API call, or any other non-post-deploy HTTP consumer.
/// The name intentionally binds this constructor to the post-deploy
/// verification surface so a stray reuse fails a code review before
/// the security posture drifts.
///
/// # Errors
///
/// Returns the error from [`reqwest::ClientBuilder::build`] wrapped
/// in the `Failed to build HTTP client` context — matches the
/// three pre-lift context-carrying call sites verbatim and strictly
/// improves the fourth (`quick_health_check`), which pre-lift dropped
/// context entirely.
pub fn build_post_deploy_http_client(timeout: Duration) -> Result<Client> {
    Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(true)
        .build()
        .context("Failed to build HTTP client")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The primitive returns a usable [`Client`] for any positive
    /// timeout — the pre-lift stanzas passed a caller-supplied
    /// `Duration` at three sites and the literal `Duration::from_secs(10)`
    /// at the fourth. Confirm the constructor accepts both regimes.
    #[test]
    fn build_post_deploy_http_client_accepts_a_caller_supplied_timeout() {
        build_post_deploy_http_client(Duration::from_secs(30))
            .expect("client must build for a 30s timeout");
    }

    #[test]
    fn build_post_deploy_http_client_accepts_the_pre_lift_quick_health_check_10s_timeout() {
        build_post_deploy_http_client(Duration::from_secs(10))
            .expect("client must build for the pre-lift `quick_health_check` 10s timeout");
    }

    /// Zero is a legal [`Duration`] and [`reqwest`] does not reject
    /// it at build time. Pin that the primitive does not itself
    /// introduce a positive-timeout precondition — the pre-lift
    /// stanzas passed whatever the caller supplied without validation.
    #[test]
    fn build_post_deploy_http_client_does_not_reject_a_zero_timeout() {
        build_post_deploy_http_client(Duration::from_secs(0))
            .expect("primitive must not add a positive-timeout precondition post-lift");
    }

    /// Caller shield: no code line in
    /// `commands/post_deploy_verification.rs` may spell the pre-lift
    /// raw `Client::builder()\n        .timeout(...)\n        \
    /// .danger_accept_invalid_certs(true)\n        .build()` chain
    /// inline any more. The four pre-lift sites migrated onto
    /// [`build_post_deploy_http_client`]; any future post-deploy
    /// probe that wants the same lenient HTTPS client reaches for the
    /// primitive on first grep, not by copy-pasting the raw chain
    /// from an existing verify function.
    ///
    /// The needle is the `.danger_accept_invalid_certs(true)` line
    /// specifically — the shape's most security-sensitive step and
    /// the one that must NOT survive at four independent sites. A
    /// caller that legitimately needs a stricter client for a
    /// non-post-deploy purpose reaches for its own constructor, not
    /// this primitive, so the shield's scope is narrow.
    #[test]
    fn no_post_deploy_verification_line_reinlines_danger_accept_invalid_certs() {
        const SOURCE: &str = include_str!("commands/post_deploy_verification.rs");
        let hits =
            crate::test_support::code_line_hits(SOURCE, ".danger_accept_invalid_certs(true)");
        assert!(
            hits.is_empty(),
            "commands/post_deploy_verification.rs must NOT re-inline \
             the `.danger_accept_invalid_certs(true)` builder step — \
             route every post-deploy probe through \
             `crate::post_deploy_http_client::build_post_deploy_http_client(timeout)` \
             so the security-sensitive lenient-TLS decision lives at \
             exactly ONE body. Offending lines: {hits:?}"
        );
    }

    /// Positive half of the shield: `post_deploy_verification.rs` MUST
    /// forward through
    /// `crate::post_deploy_http_client::build_post_deploy_http_client(`
    /// at least the pre-lift census's four times, so a migration that
    /// dropped a call site outright leaves the negative "no raw
    /// `.danger_accept_invalid_certs(true)`" scan trivially satisfied
    /// by absence but the positive count still fails.
    #[test]
    fn post_deploy_verification_forwards_through_build_post_deploy_http_client_at_all_four_sites() {
        const SOURCE: &str = include_str!("commands/post_deploy_verification.rs");
        let forwards = SOURCE
            .matches("crate::post_deploy_http_client::build_post_deploy_http_client(")
            .count();
        assert!(
            forwards >= 4,
            "commands/post_deploy_verification.rs must forward at \
             least 4 post-deploy HTTP-client construction sites \
             through \
             `crate::post_deploy_http_client::build_post_deploy_http_client(` \
             (pre-lift census: verify_health_endpoint, \
             verify_graphql_endpoint, verify_smoke_queries, \
             quick_health_check); found {forwards}. A dropped call \
             would leave the negative raw-shape scan satisfied by \
             absence."
        );
    }
}
