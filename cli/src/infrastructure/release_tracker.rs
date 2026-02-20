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
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use uuid::Uuid;

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

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!(
                "Project registration failed with status {}: {}",
                status,
                body
            );
        }

        response
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

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Create release failed with status {}: {}", status, body);
        }

        response
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

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Update phase failed with status {}: {}", status, body);
        }

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

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Complete release failed with status {}: {}", status, body);
        }

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

        if !response.status().is_success() {
            anyhow::bail!(
                "Release tracker health check failed with status {}",
                response.status()
            );
        }

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
}
