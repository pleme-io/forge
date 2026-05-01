//! Container registry operations
//!
//! Handles pushing images to GHCR using skopeo and multi-arch manifest
//! creation using regctl. All push paths in forge converge here.

use anyhow::{Context, Result};
use std::process::Stdio;
use tokio::process::Command;
use tracing::{info, warn};

use crate::error::RegistryError;
use crate::repo::get_tool_path;
use crate::retry::{is_transient_network_stderr, run_with_policy, RetryPolicy};

/// An architecture-specific image to push
#[derive(Clone, Debug)]
pub struct ArchImage {
    /// Architecture name (e.g., "amd64", "arm64")
    pub arch: String,
    /// Path to docker-archive image file
    pub path: String,
}

/// Result of a multi-arch push operation
#[derive(Debug)]
pub struct MultiArchPushResult {
    /// Tags pushed per architecture (e.g., ["amd64-abc1234", "amd64-latest"])
    pub arch_tags: Vec<String>,
    /// Manifest index tags (e.g., ["abc1234", "latest"]) — empty if single arch
    pub manifest_tags: Vec<String>,
    /// The git SHA used for tagging
    pub tag_suffix: String,
}

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

    /// Push an image with custom retry count.
    ///
    /// Drives [`crate::retry::run_with_policy`] with a network-shaped
    /// schedule (exponential backoff capped at 30s, see
    /// [`RetryPolicy::network`]) so transient skopeo failures retry on
    /// 250ms / 500ms / 1s / ... instead of the legacy fixed 2s. Every
    /// non-zero exit produces a typed `RegistryError::PushFailed`
    /// carrying the final `attempts` count, the registry+tag tuple, and
    /// the structured `(exit_code, stderr)` pair the canonical retry
    /// classifier consumes. Spawn failures (skopeo not on PATH) surface
    /// as `RegistryError::ExecFailed`, distinct from a real push
    /// failure — same discipline as `AtticError::ExecFailed`,
    /// `NixBuildError::ExecFailed`, and `GitError::ExecFailed`.
    pub async fn push_with_retries(
        &self,
        image_path: &str,
        registry: &str,
        tag: &str,
        retries: u32,
    ) -> Result<(), RegistryError> {
        // Verify image exists
        if !tokio::fs::try_exists(image_path).await.unwrap_or(false) {
            return Err(RegistryError::LocalImageNotFound {
                path: image_path.to_string(),
            });
        }

        let policy = {
            let net = RetryPolicy::network();
            RetryPolicy::new(
                retries.max(1),
                net.initial_backoff,
                net.factor,
                net.max_backoff,
            )
        };

        run_with_policy(
            &policy,
            |e: &RegistryError| match e {
                // Only `PushFailed` carries captured stderr; every other
                // variant is a structural precondition failure
                // (`ExecFailed`, `LocalImageNotFound`, `RemoteImageNotFound`,
                // `TokenNotFound`, `ManifestFailed`, etc.) and must
                // short-circuit so a permanent failure does not burn retry
                // budget. The classifier inspects the typed `stderr` field
                // directly (not a fused `message` string), so a synthetic
                // "Exit code: Some(503)" embedded in a serialized message
                // can never trip the 5xx markers — the structural shape
                // pins what is and isn't transient.
                RegistryError::PushFailed { stderr, .. } => is_transient_network_stderr(stderr),
                _ => false,
            },
            |attempt| async move {
                let skopeo = get_tool_path("SKOPEO_BIN", "skopeo");
                let output = Command::new(&skopeo)
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
                    .output()
                    .await;

                match output {
                    Ok(out) if out.status.success() => Ok(()),
                    Ok(out) => {
                        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                        if attempt < policy.max_attempts {
                            warn!("Push attempt {} failed, retrying...", attempt);
                        }
                        Err(RegistryError::PushFailed {
                            registry: registry.to_string(),
                            tag: tag.to_string(),
                            attempts: attempt,
                            exit_code: out.status.code(),
                            stderr,
                        })
                    }
                    Err(e) => Err(RegistryError::ExecFailed {
                        operation: format!("push {}:{}", registry, tag),
                        message: e.to_string(),
                    }),
                }
            },
        )
        .await
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
            .map_err(|e| RegistryError::ExecFailed {
                operation: format!("inspect {}:{}", registry, tag),
                message: e.to_string(),
            })?;

        if !output.status.success() {
            return Err(RegistryError::RemoteImageNotFound {
                registry: registry.to_string(),
                tag: tag.to_string(),
            });
        }

        let digest = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if digest.is_empty() {
            return Err(RegistryError::RemoteImageNotFound {
                registry: registry.to_string(),
                tag: tag.to_string(),
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

    /// Push one or more architecture-specific images and create a manifest index.
    ///
    /// This is the unified multi-arch push strategy. All push paths in forge
    /// should converge here.
    ///
    /// For each image in `images`:
    ///   - Pushes as `{registry}:{arch}-{tag_suffix}` and `{registry}:{arch}-latest`
    ///
    /// If more than one architecture is provided:
    ///   - Creates an OCI manifest index under `{registry}:{tag_suffix}` and `{registry}:latest`
    ///     using regctl
    pub async fn push_multiarch(
        &self,
        registry: &str,
        images: &[ArchImage],
        tag_suffix: &str,
    ) -> Result<MultiArchPushResult, RegistryError> {
        if images.is_empty() {
            return Err(RegistryError::PushFailed {
                registry: registry.to_string(),
                tag: tag_suffix.to_string(),
                attempts: 0,
                exit_code: None,
                stderr: "no images provided to multi-arch push".to_string(),
            });
        }

        let mut arch_tags = Vec::new();
        let mut source_refs = Vec::new();

        // Step 1: Push each architecture image with arch-prefixed tags
        for image in images {
            let tags = vec![
                format!("{}-{}", image.arch, tag_suffix),
                format!("{}-latest", image.arch),
            ];

            for tag in &tags {
                info!("Pushing {}:{}", registry, tag);
                self.push(&image.path, registry, tag).await?;
                arch_tags.push(format!("{}:{}", registry, tag));
            }

            // Track the immutable arch-sha tag as source for manifest index
            source_refs.push(format!("{}:{}-{}", registry, image.arch, tag_suffix));
        }

        // Step 2: Create manifest index if multiple architectures
        let manifest_tags = if images.len() > 1 {
            let tags = vec![tag_suffix.to_string(), "latest".to_string()];

            info!("Creating multi-arch manifest index...");
            self.create_manifest_index(registry, &tags, &source_refs)
                .await?;

            tags.iter().map(|t| format!("{}:{}", registry, t)).collect()
        } else {
            Vec::new()
        };

        Ok(MultiArchPushResult {
            arch_tags,
            manifest_tags,
            tag_suffix: tag_suffix.to_string(),
        })
    }

    /// Create an OCI manifest index from arch-tagged images already in the registry.
    ///
    /// Uses regctl to create a manifest list. Falls back gracefully if regctl
    /// is not available (logs warning, skips manifest creation).
    async fn create_manifest_index(
        &self,
        registry: &str,
        tags: &[String],
        source_refs: &[String],
    ) -> Result<(), RegistryError> {
        let regctl = get_tool_path("REGCTL_BIN", "regctl");

        for tag in tags {
            let target = format!("{}:{}", registry, tag);
            let mut cmd = Command::new(&regctl);
            cmd.args(["index", "create", &target]);

            for source in source_refs {
                cmd.args(["--ref", source]);
            }

            // Authenticate via regctl host config (inline JSON)
            let host = RegistryRef::parse(registry)
                .map(|r| r.host().to_string())
                .unwrap_or_else(|_| "ghcr.io".to_string());
            let host = host.as_str();
            cmd.env(
                "regclient_hosts",
                format!(
                    "{{\"{}\":{{\"user\":\"{}\",\"pass\":\"{}\"}}}}",
                    host, self.credentials.organization, self.credentials.token
                ),
            );

            cmd.stdout(Stdio::inherit());
            cmd.stderr(Stdio::piped());

            let output = cmd
                .output()
                .await
                .map_err(|e| RegistryError::ManifestFailed {
                    target: target.clone(),
                    message: format!("Failed to run regctl: {}", e),
                })?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(RegistryError::ManifestFailed {
                    target: target.clone(),
                    message: format!("regctl index create failed: {}", stderr.trim()),
                });
            }

            info!("Created manifest index: {}", target);
        }

        Ok(())
    }
}

/// Typed reference to a container registry path.
///
/// Parses a registry string of the shape `host/organization[/path...]` into
/// its components once at the boundary, so downstream code never has to
/// re-`split('/')` and re-validate. An invalid registry string fails to
/// construct — invalid pipelines become structurally impossible.
///
/// Grammar:
/// - `host`: first non-empty segment (e.g., `ghcr.io`)
/// - `organization`: second non-empty segment (e.g., `pleme-io`)
/// - `path`: remaining segments; the last is the conventional image name
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryRef {
    host: String,
    organization: String,
    path: Vec<String>,
}

impl RegistryRef {
    /// Parse a registry string into its typed components.
    ///
    /// Rejects strings without at least `host/organization`. Empty segments
    /// (leading, trailing, or doubled slashes) are rejected too — the
    /// concrete failure carries the offending input.
    pub fn parse(registry: &str) -> Result<Self, RegistryError> {
        let trimmed = registry.trim();
        if trimmed.is_empty() {
            return Err(RegistryError::InvalidFormat {
                registry: registry.to_string(),
            });
        }
        let parts: Vec<&str> = trimmed.split('/').collect();
        if parts.len() < 2 || parts.iter().any(|p| p.is_empty()) {
            return Err(RegistryError::InvalidFormat {
                registry: registry.to_string(),
            });
        }
        let host = parts[0].to_string();
        let organization = parts[1].to_string();
        let path = parts[2..].iter().map(|s| (*s).to_string()).collect();
        Ok(Self {
            host,
            organization,
            path,
        })
    }

    /// Registry host (e.g., `ghcr.io`).
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Owning organization (e.g., `pleme-io`).
    pub fn organization(&self) -> &str {
        &self.organization
    }

    /// Conventional image name — the last path segment, falling back to the
    /// organization when the registry has no project/image components.
    pub fn image_name(&self) -> &str {
        self.path.last().map_or(&self.organization, |s| s.as_str())
    }
}

impl std::fmt::Display for RegistryRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.host, self.organization)?;
        for segment in &self.path {
            write!(f, "/{segment}")?;
        }
        Ok(())
    }
}

/// Extract organization name from registry URL.
///
/// Example: `ghcr.io/org/project/service` -> `org`.
///
/// Thin wrapper over [`RegistryRef::parse`] preserved for callers that only
/// need the organization string. New code should use `RegistryRef` directly
/// to keep the parsed structure available.
pub fn extract_organization(registry: &str) -> Result<String, RegistryError> {
    RegistryRef::parse(registry).map(|r| r.organization)
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

    /// Pushing a non-existent local archive must produce a typed
    /// `LocalImageNotFound` carrying the offending path — not a stringly
    /// `PushFailed`. This pins the discriminator so callers can pattern-match
    /// "missing local artifact" without parsing error strings.
    #[test]
    fn test_push_missing_local_archive_returns_local_image_not_found() {
        let client = RegistryClient::new(RegistryCredentials::new("org", "tok"));
        let missing = "/tmp/forge-test-missing-image-archive-does-not-exist";
        let err = tokio_test::block_on(client.push_with_retries(
            missing,
            "ghcr.io/o/p/s",
            "amd64-deadbeef",
            1,
        ))
        .expect_err("push of nonexistent archive must fail");
        match err {
            RegistryError::LocalImageNotFound { path } => assert_eq!(path, missing),
            other => panic!("expected LocalImageNotFound, got: {other:?}"),
        }
    }

    /// Multi-arch push with empty image list must surface the registry +
    /// tag_suffix it was invoked with. This guarantees structured
    /// provenance even on the trivially-empty input failure path. The
    /// precondition variant carries `exit_code: None` and `attempts: 0`
    /// so callers can distinguish "never attempted" from "attempted and
    /// failed."
    #[test]
    fn test_push_multiarch_empty_carries_target() {
        let client = RegistryClient::new(RegistryCredentials::new("org", "tok"));
        let registry = "ghcr.io/o/p/s";
        let suffix = "abc1234";
        let err = tokio_test::block_on(client.push_multiarch(registry, &[], suffix))
            .expect_err("empty multiarch push must fail");
        match err {
            RegistryError::PushFailed {
                registry: r,
                tag,
                attempts,
                exit_code,
                stderr,
            } => {
                assert_eq!(r, registry);
                assert_eq!(tag, suffix);
                assert_eq!(attempts, 0);
                assert_eq!(exit_code, None, "precondition failure: never spawned");
                assert!(stderr.contains("no images"));
            }
            other => panic!("expected PushFailed, got: {other:?}"),
        }
    }

    #[test]
    fn test_registry_ref_parse_full_four_part() {
        let r = RegistryRef::parse("ghcr.io/myorg/myproject/service").unwrap();
        assert_eq!(r.host(), "ghcr.io");
        assert_eq!(r.organization(), "myorg");
        assert_eq!(r.image_name(), "service");
    }

    #[test]
    fn test_registry_ref_parse_three_part() {
        let r = RegistryRef::parse("ghcr.io/pleme-io/shinryu-mcp").unwrap();
        assert_eq!(r.host(), "ghcr.io");
        assert_eq!(r.organization(), "pleme-io");
        assert_eq!(r.image_name(), "shinryu-mcp");
    }

    #[test]
    fn test_registry_ref_parse_two_part_image_falls_back_to_org() {
        let r = RegistryRef::parse("ghcr.io/pleme-io").unwrap();
        assert_eq!(r.host(), "ghcr.io");
        assert_eq!(r.organization(), "pleme-io");
        // No path segments: image_name falls back to organization.
        assert_eq!(r.image_name(), "pleme-io");
    }

    #[test]
    fn test_registry_ref_parse_rejects_single_segment() {
        let err = RegistryRef::parse("ghcr.io").unwrap_err();
        assert!(matches!(err, RegistryError::InvalidFormat { .. }));
        assert!(err.to_string().contains("ghcr.io"));
    }

    #[test]
    fn test_registry_ref_parse_rejects_empty() {
        assert!(matches!(
            RegistryRef::parse("").unwrap_err(),
            RegistryError::InvalidFormat { .. }
        ));
        assert!(matches!(
            RegistryRef::parse("   ").unwrap_err(),
            RegistryError::InvalidFormat { .. }
        ));
    }

    #[test]
    fn test_registry_ref_parse_rejects_empty_segments() {
        // Leading slash, trailing slash, doubled slash all produce empty segments.
        assert!(RegistryRef::parse("/ghcr.io/org").is_err());
        assert!(RegistryRef::parse("ghcr.io/org/").is_err());
        assert!(RegistryRef::parse("ghcr.io//org").is_err());
    }

    #[test]
    fn test_registry_ref_display_round_trips() {
        for input in [
            "ghcr.io/myorg/myproject/service",
            "ghcr.io/pleme-io/shinryu-mcp",
            "ghcr.io/pleme-io",
        ] {
            let r = RegistryRef::parse(input).unwrap();
            assert_eq!(r.to_string(), input, "round-trip failed for {input}");
        }
    }

    #[test]
    fn test_registry_ref_trims_whitespace() {
        let r = RegistryRef::parse("  ghcr.io/myorg/img  ").unwrap();
        assert_eq!(r.host(), "ghcr.io");
        assert_eq!(r.image_name(), "img");
    }

    #[test]
    fn test_extract_organization_delegates_to_registry_ref() {
        // The legacy helper now routes through RegistryRef::parse.
        assert_eq!(
            extract_organization("ghcr.io/pleme-io/forge").unwrap(),
            "pleme-io"
        );
        // Same rejection semantics.
        assert!(extract_organization("ghcr.io").is_err());
        assert!(extract_organization("").is_err());
    }

    /// Classifier wired into `push_with_retries` must consume the
    /// `is_transient_network_stderr` primitive on `PushFailed.stderr`
    /// (the typed structural field, NOT a fused `message: String`).
    /// A representative skopeo "503 Service Unavailable" trips it; a
    /// "401 Unauthorized" does not. Other variants (no captured stderr)
    /// are unconditionally terminal.
    ///
    /// Mirrors the closure shape inside `push_with_retries` so a future
    /// drift between the two surfaces fails this test, not production.
    #[test]
    fn test_push_classifier_distinguishes_transient_from_terminal() {
        use crate::retry::is_transient_network_stderr;

        let classify = |e: &RegistryError| match e {
            RegistryError::PushFailed { stderr, .. } => is_transient_network_stderr(stderr),
            _ => false,
        };

        let transient = RegistryError::PushFailed {
            registry: "ghcr.io/o/p/s".into(),
            tag: "amd64-abc1234".into(),
            attempts: 1,
            exit_code: Some(1),
            stderr: "received unexpected HTTP status: 503 Service Unavailable".into(),
        };
        assert!(classify(&transient), "5xx must classify as transient");

        let terminal_401 = RegistryError::PushFailed {
            registry: "ghcr.io/o/p/s".into(),
            tag: "amd64-abc1234".into(),
            attempts: 1,
            exit_code: Some(1),
            stderr: "401 Unauthorized: bad credentials".into(),
        };
        assert!(
            !classify(&terminal_401),
            "auth failure must not burn retry budget"
        );

        let terminal_404 = RegistryError::PushFailed {
            registry: "ghcr.io/o/p/s".into(),
            tag: "amd64-abc1234".into(),
            attempts: 1,
            exit_code: Some(1),
            stderr: "404 manifest unknown".into(),
        };
        assert!(
            !classify(&terminal_404),
            "manifest-unknown must not burn retry budget"
        );

        let other = RegistryError::TokenNotFound;
        assert!(
            !classify(&other),
            "non-PushFailed variants must short-circuit (no captured stderr)"
        );

        let local_missing = RegistryError::LocalImageNotFound {
            path: "/nonexistent".into(),
        };
        assert!(!classify(&local_missing));

        // ExecFailed (the spawn-failure path) is structurally distinct
        // from PushFailed and must short-circuit. A skopeo-not-on-PATH
        // precondition has no stderr to inspect; burning 5 attempts ×
        // exponential backoff against it would produce only the same
        // ENOENT five times.
        let exec_missing = RegistryError::ExecFailed {
            operation: "push ghcr.io/o/p/s:tag".into(),
            message: "No such file or directory".into(),
        };
        assert!(!classify(&exec_missing));
    }

    /// Pre-migration regression guard. The `push_with_retries` classifier
    /// used to inspect a fused `message: String` of the form
    /// "Exit code: Some(N); stderr: ...", so a synthetic exit code
    /// of 500–504 (numerically a 5xx HTTP marker) trip the transient
    /// classifier even when the actual stderr was terminal. Splitting
    /// `message` into typed `(exit_code, stderr)` makes that ambiguity
    /// structurally impossible: the classifier inspects the typed
    /// `stderr` field directly. This test pins the new shape so a
    /// regression that re-fuses the message can never reintroduce the
    /// false-transient.
    #[test]
    fn test_push_classifier_inspects_typed_stderr_not_synthetic_message() {
        use crate::retry::is_transient_network_stderr;

        let classify = |e: &RegistryError| match e {
            RegistryError::PushFailed { stderr, .. } => is_transient_network_stderr(stderr),
            _ => false,
        };

        // A terminal 401 with a literal "504" exit code must NOT trip
        // the transient classifier — the classifier only inspects the
        // typed stderr field, not a synthetic concatenation.
        let terminal_with_5xx_exit_code = RegistryError::PushFailed {
            registry: "ghcr.io/o/p/s".into(),
            tag: "amd64-abc1234".into(),
            attempts: 1,
            exit_code: Some(504),
            stderr: "401 Unauthorized: bad credentials".into(),
        };
        assert!(
            !classify(&terminal_with_5xx_exit_code),
            "exit_code is structurally separate from stderr; \
             a non-5xx stderr must short-circuit even if exit_code happens to match a 5xx marker"
        );

        // Symmetric: a transient 503 stderr must trip the classifier
        // even when exit_code is a non-5xx number.
        let transient_with_non_5xx_exit_code = RegistryError::PushFailed {
            registry: "ghcr.io/o/p/s".into(),
            tag: "amd64-abc1234".into(),
            attempts: 1,
            exit_code: Some(1),
            stderr: "received unexpected HTTP status: 503".into(),
        };
        assert!(classify(&transient_with_non_5xx_exit_code));
    }
}
