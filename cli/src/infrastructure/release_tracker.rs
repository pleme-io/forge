//! Release Tracker client for communicating with the release tracker service
//!
//! The release tracker service provides GitOps-native release observability.
//! This client allows forge to:
//! - Register projects on startup
//! - Create releases when starting a deployment
//! - Update release phases as work progresses
//! - Complete releases when done
//!
//! ## Configuration
//!
//! Set `RELEASE_TRACKER_URL` environment variable to enable:
//! ```bash
//! export RELEASE_TRACKER_URL=http://release-tracker.namespace.svc.cluster.local:8080
//! ```
//!
//! If not set, release tracking is disabled and all operations are no-ops.

use anyhow::{Context, Result};
use reqwest::{Client, Response, StatusCode};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use uuid::Uuid;

/// Format the diagnostic emitted when a release-tracker HTTP request
/// lands with a non-2xx status. Names the load-bearing
/// `"<operation> failed with status <status>: <body>"` shape at ONE
/// typed helper so every consumer of [`ensure_success`] reads the
/// same string, and a future edit that reshapes the diagnostic (say,
/// prepending a request-id header or swapping to a structured
/// tracing field) lands at one site rather than five.
///
/// Consumed by [`ensure_success`] on the failure branch; pure-function
/// tests pin the shape verbatim so a downstream reader relying on the
/// pre-lift `"<op> failed with status <status>: <body>"` grep target
/// (an operator scanning forge stderr, a log-based alert regex, an
/// SLSA attestation-parse rule) does not silently drift when a future
/// edit reshapes the string.
fn format_failure(operation: &str, status: StatusCode, body: &str) -> String {
    format!("{operation} failed with status {status}: {body}")
}

/// Consume a [`Response`], returning it on 2xx or bailing with the
/// [`format_failure`] diagnostic — the single primitive every HTTP
/// call site in this module lifts through.
///
/// Pre-lift five sibling call sites (`register_project`,
/// `create_release`, `update_phase`, `complete_release`,
/// `health_check`) each open-coded the same
/// `if !response.status().is_success() { let status = ...; let body =
/// ...; anyhow::bail!(...) }` branch — five occurrences well past
/// THEORY §VI.1's three-times threshold ("two occurrences is a
/// coincidence; three is a law"). Four of the five read the response
/// body into the diagnostic; the fifth — `health_check` — silently
/// dropped it, so a `503 Service Unavailable` returning a helpful
/// upstream error body (`{"error":"database unreachable"}`, the shape
/// the release-tracker service actually emits) landed at the caller
/// as a bare `"Release tracker health check failed with status 503
/// Service Unavailable"` with the body-carried root cause discarded
/// before it could be surfaced. Post-lift every site consumes this
/// one primitive and every diagnostic carries the body, closing the
/// error-fidelity drift at ONE named surface.
async fn ensure_success(response: Response, operation: &str) -> Result<Response> {
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    anyhow::bail!("{}", format_failure(operation, status, &body));
}

/// Release tracker client
pub struct ReleaseTrackerClient {
    client: Client,
    base_url: String,
}

/// Request to register a project
#[derive(Debug, Clone, Serialize)]
pub struct RegisterProjectRequest {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environments: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub components: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flux_pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace_pattern: Option<String>,
}

/// Response from registering a project
#[derive(Debug, Clone, Deserialize)]
pub struct RegisterProjectResponse {
    pub id: String,
    pub created: bool,
}

/// Request to create a release
#[derive(Debug, Clone, Serialize)]
pub struct CreateReleaseRequest {
    pub product: String,
    pub environment: String,
    pub git_commit: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_branch: Option<String>,
    pub components: Vec<CreateComponentRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initiated_by: Option<String>,
}

/// Component in a release
#[derive(Debug, Clone, Serialize)]
pub struct CreateComponentRequest {
    pub name: String,
    pub image_tag: String,
}

/// Response from creating a release
#[derive(Debug, Clone, Deserialize)]
pub struct CreateReleaseResponse {
    pub id: Uuid,
    pub status: String,
}

/// Request to update a phase
#[derive(Debug, Clone, Serialize)]
pub struct UpdatePhaseRequest {
    pub phase_name: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Request to complete a release
#[derive(Debug, Clone, Serialize)]
pub struct CompleteReleaseRequest {
    pub status: String,
}

impl ReleaseTrackerClient {
    /// Create a new client from environment variable
    pub fn from_env() -> Option<Self> {
        let base_url = std::env::var("RELEASE_TRACKER_URL").ok()?;

        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .build()
            .ok()?;

        Some(Self { client, base_url })
    }

    /// Get the base URL
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Register or update a project
    pub async fn register_project(
        &self,
        request: RegisterProjectRequest,
    ) -> Result<RegisterProjectResponse> {
        let url = format!("{}/api/projects", self.base_url);

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .context("Failed to send project registration request")?;

        ensure_success(response, "Project registration")
            .await?
            .json()
            .await
            .context("Failed to parse project registration response")
    }

    /// Create a new release
    pub async fn create_release(
        &self,
        request: CreateReleaseRequest,
    ) -> Result<CreateReleaseResponse> {
        let url = format!("{}/api/releases", self.base_url);

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .context("Failed to send create release request")?;

        ensure_success(response, "Create release")
            .await?
            .json()
            .await
            .context("Failed to parse create release response")
    }

    /// Update a release phase
    pub async fn update_phase(&self, release_id: Uuid, request: UpdatePhaseRequest) -> Result<()> {
        let url = format!("{}/api/releases/{}/phases", self.base_url, release_id);

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .context("Failed to send update phase request")?;

        ensure_success(response, "Update phase").await?;
        Ok(())
    }

    /// Complete a release
    pub async fn complete_release(
        &self,
        release_id: Uuid,
        request: CompleteReleaseRequest,
    ) -> Result<()> {
        let url = format!("{}/api/releases/{}/complete", self.base_url, release_id);

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .context("Failed to send complete release request")?;

        ensure_success(response, "Complete release").await?;
        Ok(())
    }

    /// Health check
    pub async fn health_check(&self) -> Result<()> {
        let url = format!("{}/healthz", self.base_url);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to send health check request")?;

        ensure_success(response, "Release tracker health check").await?;
        Ok(())
    }
}

/// Release tracking helper that wraps the client with optional behavior
///
/// If the release tracker URL is not configured, all operations are no-ops.
pub struct ReleaseTracker {
    client: Option<ReleaseTrackerClient>,
    release_id: Option<Uuid>,
}

impl ReleaseTracker {
    /// Create a new release tracker from environment
    pub fn from_env() -> Self {
        Self {
            client: ReleaseTrackerClient::from_env(),
            release_id: None,
        }
    }

    /// Check if tracking is enabled
    pub fn is_enabled(&self) -> bool {
        self.client.is_some()
    }

    /// Get the current release ID
    pub fn release_id(&self) -> Option<Uuid> {
        self.release_id
    }

    /// Register a project (best effort, logs errors)
    pub async fn register_project(&self, request: RegisterProjectRequest) {
        if let Some(client) = &self.client {
            match client.register_project(request).await {
                Ok(response) => {
                    if response.created {
                        tracing::info!(project_id = %response.id, "Registered new project with release tracker");
                    } else {
                        tracing::debug!(project_id = %response.id, "Updated existing project in release tracker");
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to register project with release tracker");
                }
            }
        }
    }

    /// Start a release (HARD FAIL if tracker is enabled but unreachable)
    pub async fn start_release(&mut self, request: CreateReleaseRequest) -> Result<Option<Uuid>> {
        if let Some(client) = &self.client {
            let response = client.create_release(request).await?;
            self.release_id = Some(response.id);
            tracing::info!(release_id = %response.id, "Started release tracking");
            Ok(Some(response.id))
        } else {
            Ok(None)
        }
    }

    /// Update the current release phase (best effort, logs errors)
    pub async fn update_phase(&self, phase_name: &str, status: &str, message: Option<String>) {
        if let (Some(client), Some(release_id)) = (&self.client, self.release_id) {
            let request = UpdatePhaseRequest {
                phase_name: phase_name.to_string(),
                status: status.to_string(),
                message,
            };

            if let Err(e) = client.update_phase(release_id, request).await {
                tracing::warn!(
                    release_id = %release_id,
                    phase = %phase_name,
                    error = %e,
                    "Failed to update release phase"
                );
            } else {
                tracing::debug!(
                    release_id = %release_id,
                    phase = %phase_name,
                    status = %status,
                    "Updated release phase"
                );
            }
        }
    }

    /// Complete the current release (best effort, logs errors)
    pub async fn complete(&self, succeeded: bool) {
        if let (Some(client), Some(release_id)) = (&self.client, self.release_id) {
            let status = if succeeded { "succeeded" } else { "failed" };
            let request = CompleteReleaseRequest {
                status: status.to_string(),
            };

            if let Err(e) = client.complete_release(release_id, request).await {
                tracing::warn!(
                    release_id = %release_id,
                    status = %status,
                    error = %e,
                    "Failed to complete release"
                );
            } else {
                tracing::info!(
                    release_id = %release_id,
                    status = %status,
                    "Completed release tracking"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tracker_from_env_without_url() {
        // Without RELEASE_TRACKER_URL, should be disabled
        std::env::remove_var("RELEASE_TRACKER_URL");
        let tracker = ReleaseTracker::from_env();
        assert!(!tracker.is_enabled());
    }

    /// Pin the [`format_failure`] diagnostic verbatim: the pre-lift
    /// four sibling `anyhow::bail!("<op> failed with status {}: {}",
    /// status, body)` shapes and the pre-lift `health_check` shape
    /// (extended to include the body, closing the pre-lift fidelity
    /// drift) collapse onto one composition. This shield forbids a
    /// silent drift in the shared diagnostic string a downstream
    /// operator-facing grep target or a log-based alert regex may
    /// depend on.
    #[test]
    fn test_format_failure_matches_pre_lift_shape_with_body() {
        assert_eq!(
            format_failure("Project registration", StatusCode::CONFLICT, "duplicate id"),
            "Project registration failed with status 409 Conflict: duplicate id"
        );
        assert_eq!(
            format_failure("Create release", StatusCode::INTERNAL_SERVER_ERROR, "boom"),
            "Create release failed with status 500 Internal Server Error: boom"
        );
        assert_eq!(
            format_failure("Update phase", StatusCode::NOT_FOUND, "unknown release"),
            "Update phase failed with status 404 Not Found: unknown release"
        );
        assert_eq!(
            format_failure(
                "Complete release",
                StatusCode::UNPROCESSABLE_ENTITY,
                "bad status"
            ),
            "Complete release failed with status 422 Unprocessable Entity: bad status"
        );
    }

    /// The pre-lift `health_check` bail dropped the response body — a
    /// `503 Service Unavailable` returning an upstream root-cause
    /// payload landed as a bare status-only diagnostic. Post-lift
    /// this site consumes [`ensure_success`], which composes
    /// [`format_failure`], and every diagnostic carries the body.
    /// This shield pins the fidelity fix directly: the emitted
    /// string, at the exact operation label the `health_check` call
    /// site passes, includes the body verbatim.
    #[test]
    fn test_format_failure_closes_pre_lift_health_check_body_drop_defect() {
        let msg = format_failure(
            "Release tracker health check",
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"database unreachable"}"#,
        );
        assert!(
            msg.contains(r#"{"error":"database unreachable"}"#),
            "the post-lift health-check diagnostic must include the \
             response body (the pre-lift bail at `health_check` \
             dropped it); got: {msg}"
        );
        assert_eq!(
            msg,
            r#"Release tracker health check failed with status 503 Service Unavailable: {"error":"database unreachable"}"#
        );
    }

    /// Empty response bodies (a `502 Bad Gateway` from a
    /// pathological reverse proxy that returns no body) format as a
    /// trailing `": "` — pinned so a future edit that tries to
    /// "clean up" the trailing separator does not silently reshape
    /// the diagnostic every downstream reader has already parsed.
    #[test]
    fn test_format_failure_preserves_trailing_separator_on_empty_body() {
        assert_eq!(
            format_failure("Any op", StatusCode::BAD_GATEWAY, ""),
            "Any op failed with status 502 Bad Gateway: "
        );
    }

    /// The load-bearing production-slice shield: after the lift,
    /// every `response.status().is_success()` reader in the module's
    /// PRODUCTION half (above the `#[cfg(test)]` marker) is
    /// [`ensure_success`]'s own body — exactly ONE code-line hit.
    /// A future HTTP call site that open-codes the pre-lift
    /// `if !response.status().is_success() { ... }` branch reappears
    /// as a second hit and this shield fires, catching the regression
    /// before it can silently duplicate the diagnostic shape.
    ///
    /// The scan is bounded to `SOURCE[..end_of_production]` — the
    /// slice strictly above `\n#[cfg(test)]\n` — so this shield's
    /// own literal-string needle (living in `#[cfg(test)]` code
    /// below the marker) does not self-match, and
    /// [`crate::test_support::code_line_hits`] filters `///` /
    /// `//!` / `//` prose comments so `ensure_success`'s docstring
    /// (which cites the pre-lift branch by verbatim quotation as
    /// context for the five defects the lift closes) stays out of
    /// scope. Same production-slice-plus-code-line-filter
    /// discipline sibling shields at
    /// `commands/e2e.rs::test_ensure_docker_running_consumes_typed_poll_delay_not_bare_fixed_sleep`
    /// (49abd0c) use.
    #[test]
    fn test_ensure_success_is_the_only_status_is_success_reader() {
        const SOURCE: &str = include_str!("release_tracker.rs");
        let test_marker = "\n#[cfg(test)]\n";
        let end = SOURCE.find(test_marker).expect(
            "release_tracker.rs must contain a `#[cfg(test)]` marker \
             — the shield's production-slice boundary depends on it",
        );
        let production = &SOURCE[..end];
        let hits = crate::test_support::code_line_hits(production, ".status().is_success()");
        assert_eq!(
            hits.len(),
            1,
            "release_tracker.rs must consume `ensure_success` at every \
             HTTP call site in production code; expected exactly one \
             `.status().is_success()` reader (the `ensure_success` \
             helper body). Found: {hits:#?}"
        );
    }

    /// Sibling shield to
    /// [`test_ensure_success_is_the_only_status_is_success_reader`]
    /// on the failure-branch reading path: after the lift, the only
    /// `response.text().await` reader in the module's PRODUCTION
    /// half is [`ensure_success`]'s own body — ONE code-line hit.
    /// Pre-lift four sibling sites each read the body inline into
    /// their local bail; a future site that re-fuses that pattern
    /// reappears as a second hit and this shield fires. Together
    /// with the `.status().is_success()` shield above, the two pin
    /// the consumption of `ensure_success` at every existing site
    /// AND forbid the reintroduction of either half of the pre-lift
    /// branch at any future site. Same production-slice boundary
    /// discipline as the sibling shield.
    #[test]
    fn test_ensure_success_is_the_only_response_body_reader() {
        const SOURCE: &str = include_str!("release_tracker.rs");
        let test_marker = "\n#[cfg(test)]\n";
        let end = SOURCE.find(test_marker).expect(
            "release_tracker.rs must contain a `#[cfg(test)]` marker \
             — the shield's production-slice boundary depends on it",
        );
        let production = &SOURCE[..end];
        let hits = crate::test_support::code_line_hits(production, "response.text().await");
        assert_eq!(
            hits.len(),
            1,
            "release_tracker.rs must consume `ensure_success` at every \
             HTTP call site in production code; expected exactly one \
             `response.text().await` reader (the `ensure_success` \
             helper body). Found: {hits:#?}"
        );
    }

    /// Whole-module PRODUCTION-slice shield: after the lift, the
    /// only site that emits the load-bearing `"... failed with
    /// status ..."` diagnostic prose is [`format_failure`]'s own
    /// `format!` body — exactly ONE code-line hit. Pre-lift five
    /// sibling sites each open-coded that prose in an
    /// `anyhow::bail!("<op> failed with status {}: {}", ...)`
    /// literal; a future consumer that re-fuses the pre-lift shape
    /// inline reappears as a second hit and this shield fires.
    /// Same production-slice boundary discipline as the sibling
    /// shields.
    #[test]
    fn test_format_failure_owns_the_only_failed_with_status_diagnostic_prose() {
        const SOURCE: &str = include_str!("release_tracker.rs");
        let test_marker = "\n#[cfg(test)]\n";
        let end = SOURCE.find(test_marker).expect(
            "release_tracker.rs must contain a `#[cfg(test)]` marker \
             — the shield's production-slice boundary depends on it",
        );
        let production = &SOURCE[..end];
        let hits = crate::test_support::code_line_hits(production, "failed with status");
        assert_eq!(
            hits.len(),
            1,
            "release_tracker.rs production code must not re-fuse the \
             pre-lift `\"... failed with status ...\"` diagnostic prose \
             — every failure diagnostic must ground through \
             `format_failure`'s single format-string authorship. \
             Expected exactly one hit (the `format_failure` body). \
             Found: {hits:#?}"
        );
    }

    /// Every consumer of [`ensure_success`] in this module passes
    /// the operation label as a `&'static str` literal at the call
    /// site — this shield pins the five expected labels' presence at
    /// executable code lines, so a future rename that silently
    /// diverges from the pre-lift diagnostic prose (a operator-facing
    /// grep target, a log-based alert regex) surfaces here at
    /// compile-in test time rather than in production stderr.
    #[test]
    fn test_every_ensure_success_call_carries_its_pre_lift_operation_label() {
        const SOURCE: &str = include_str!("release_tracker.rs");
        for label in [
            "ensure_success(response, \"Project registration\")",
            "ensure_success(response, \"Create release\")",
            "ensure_success(response, \"Update phase\")",
            "ensure_success(response, \"Complete release\")",
            "ensure_success(response, \"Release tracker health check\")",
        ] {
            let hits = crate::test_support::code_line_hits(SOURCE, label);
            assert!(
                !hits.is_empty(),
                "release_tracker.rs must retain the pre-lift operation \
                 label at `{label}` — the diagnostic string is a \
                 stable grep target for operator-facing tooling. \
                 Found no code-line hits."
            );
        }
    }
}
