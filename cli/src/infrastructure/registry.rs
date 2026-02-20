//! Container registry operations
//!
//! Handles pushing images to GHCR using skopeo.
//! Extracts token discovery and push retry logic for reuse.

use anyhow::{Context, Result};
use std::process::Stdio;
use tokio::process::Command;
use tracing::{info, warn};

use crate::error::RegistryError;
use crate::repo::get_tool_path;

/// Registry credentials for authentication
#[derive(Clone)]
pub struct RegistryCredentials {
    pub organization: String,
    pub token: String,
}

impl RegistryCredentials {
    /// Create credentials from organization and token
    pub fn new(organization: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            organization: organization.into(),
            token: token.into(),
        }
    }

    /// Discover GHCR token from various sources
    ///
    /// Priority:
    /// 1. Provided token parameter
    /// 2. GHCR_TOKEN environment variable
    /// 3. GITHUB_TOKEN environment variable
    /// 4. gh CLI auth token
    /// 5. kubectl secret from github-actions namespace
    pub fn discover_token(token: Option<String>) -> Result<String, RegistryError> {
        token
            .or_else(|| std::env::var("GHCR_TOKEN").ok())
            .or_else(|| std::env::var("GITHUB_TOKEN").ok())
            .or_else(Self::try_gh_cli_token)
            .or_else(Self::try_kubectl_secret)
            .ok_or(RegistryError::TokenNotFound)
    }

    fn try_gh_cli_token() -> Option<String> {
        std::process::Command::new("gh")
            .args(["auth", "token"])
            .output()
            .ok()
            .and_then(|o| {
                if o.status.success() {
                    String::from_utf8(o.stdout)
                        .ok()
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                } else {
                    None
                }
            })
    }

    fn try_kubectl_secret() -> Option<String> {
        std::process::Command::new("kubectl")
            .args([
                "get",
                "secret",
                "github-runner-secret",
                "-n",
                "github-actions",
                "-o",
                "jsonpath={.data.GHCR_TOKEN}",
            ])
            .output()
            .ok()
            .and_then(|o| {
                if o.status.success() {
                    String::from_utf8(o.stdout)
                        .ok()
                        .and_then(|s| base64::decode(s.trim()).ok())
                        .and_then(|b| String::from_utf8(b).ok())
                } else {
                    None
                }
            })
    }
}

/// Client for container registry operations
pub struct RegistryClient {
    credentials: RegistryCredentials,
    default_retries: u32,
}

impl RegistryClient {
    /// Create a new registry client
    pub fn new(credentials: RegistryCredentials) -> Self {
        Self {
            credentials,
            default_retries: 3,
        }
    }

    /// Create client by discovering token automatically
    pub fn discover(token: Option<String>, organization: impl Into<String>) -> Result<Self> {
        let token = RegistryCredentials::discover_token(token)?;
        Ok(Self::new(RegistryCredentials::new(organization, token)))
    }

    /// Set default retry count
    pub fn with_retries(mut self, retries: u32) -> Self {
        self.default_retries = retries;
        self
    }

    /// Push an image to the registry with retries
    pub async fn push(
        &self,
        image_path: &str,
        registry: &str,
        tag: &str,
    ) -> Result<(), RegistryError> {
        self.push_with_retries(image_path, registry, tag, self.default_retries)
            .await
    }

    /// Push an image with custom retry count
    pub async fn push_with_retries(
        &self,
        image_path: &str,
        registry: &str,
        tag: &str,
        retries: u32,
    ) -> Result<(), RegistryError> {
        // Verify image exists
        if !tokio::fs::try_exists(image_path).await.unwrap_or(false) {
            return Err(RegistryError::ImageNotFound {
                path: image_path.to_string(),
            });
        }

        let mut attempts = 0;

        loop {
            attempts += 1;

            let skopeo = get_tool_path("SKOPEO_BIN", "skopeo");
            let result = Command::new(&skopeo)
                .args([
                    "copy",
                    "--insecure-policy",
                    &format!("--retry-times={}", retries),
                    &format!(
                        "--dest-creds={}:{}",
                        self.credentials.organization, self.credentials.token
                    ),
                    &format!("docker-archive:{}", image_path),
                    &format!("docker://{}:{}", registry, tag),
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .status()
                .await;

            match result {
                Ok(status) if status.success() => return Ok(()),
                Ok(_) | Err(_) if attempts < retries => {
                    warn!("Push attempt {} failed, retrying...", attempts);
                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                    continue;
                }
                Ok(status) => {
                    return Err(RegistryError::PushFailed {
                        attempts,
                        message: format!("Exit code: {:?}", status.code()),
                    });
                }
                Err(e) => {
                    return Err(RegistryError::PushFailed {
                        attempts,
                        message: e.to_string(),
                    });
                }
            }
        }
    }

    /// Verify an image tag exists in the registry.
    ///
    /// Uses `skopeo inspect` to check if the tag is present.
    /// Returns the image digest on success.
    pub async fn verify_tag_exists(
        &self,
        registry: &str,
        tag: &str,
    ) -> Result<String, RegistryError> {
        let skopeo = get_tool_path("SKOPEO_BIN", "skopeo");
        let output = Command::new(&skopeo)
            .args([
                "inspect",
                &format!(
                    "--creds={}:{}",
                    self.credentials.organization, self.credentials.token
                ),
                "--format",
                "{{.Digest}}",
                &format!("docker://{}:{}", registry, tag),
            ])
            .output()
            .await
            .map_err(|e| RegistryError::PushFailed {
                attempts: 1,
                message: format!("skopeo inspect failed: {}", e),
            })?;

        if !output.status.success() {
            return Err(RegistryError::ImageNotFound {
                path: format!("{}:{}", registry, tag),
            });
        }

        let digest = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if digest.is_empty() {
            return Err(RegistryError::ImageNotFound {
                path: format!("{}:{} (empty digest)", registry, tag),
            });
        }

        Ok(digest)
    }

    /// Push multiple tags for the same image
    pub async fn push_tags(
        &self,
        image_path: &str,
        registry: &str,
        tags: &[String],
    ) -> Result<Vec<String>> {
        let mut pushed = Vec::new();

        for tag in tags {
            info!("Pushing {}:{}", registry, tag);
            self.push(image_path, registry, tag).await?;
            pushed.push(format!("{}:{}", registry, tag));
        }

        Ok(pushed)
    }
}

/// Extract organization name from registry URL
///
/// Example: "ghcr.io/org/project/service" -> "org"
pub fn extract_organization(registry: &str) -> Result<String, RegistryError> {
    let parts: Vec<&str> = registry.split('/').collect();
    if parts.len() < 2 {
        return Err(RegistryError::InvalidFormat {
            registry: registry.to_string(),
        });
    }
    Ok(parts[1].to_string())
}

/// Generate architecture-prefixed tags
///
/// Returns tags like ["amd64-abc1234", "amd64-latest"] for the given architecture
pub async fn generate_auto_tags(arch: &str, sha: &str) -> Vec<String> {
    vec![format!("{}-{}", arch, sha), format!("{}-latest", arch)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_organization() {
        assert_eq!(
            extract_organization("ghcr.io/myorg/myproject/service").unwrap(),
            "myorg"
        );
    }

    #[test]
    fn test_extract_organization_invalid() {
        assert!(extract_organization("invalid").is_err());
    }

    #[test]
    fn test_generate_auto_tags() {
        let tags = tokio_test::block_on(generate_auto_tags("amd64", "abc1234"));
        assert_eq!(tags, vec!["amd64-abc1234", "amd64-latest"]);
    }
}
