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
use crate::retry::{retry_command, CapturedFailure, CommandAttemptFailure, RetryPolicy};

/// Dispatch a post-`retry_command` `CommandAttemptFailure` to the typed
/// `RegistryError` variant whose structural shape matches the captured
/// failure. Spawn-failure (skopeo not on PATH) routes to `ExecFailed`
/// carrying the operation label and the spawn-error message; non-zero
/// exit routes to `PushFailed` carrying `(registry, tag, attempts,
/// exit_code, stderr)` — the structural-record tuple the canonical retry
/// classifier and Phase 1 attestation records (THEORY §V.4) consume.
///
/// Lifting the match into a small named helper keeps the `push_with_retries`
/// body short, makes the typed-error mapping unit-testable without driving
/// a real subprocess, and pins the dispatch on the typed
/// [`crate::retry::CommandAttemptFailure::is_spawn_failure`] predicate
/// (not a substring-match on the failure string).
fn classify_push_failure(
    failure: CommandAttemptFailure,
    registry: &str,
    tag: &str,
) -> RegistryError {
    if failure.is_spawn_failure() {
        RegistryError::ExecFailed {
            operation: failure.operation,
            message: failure.stdout,
        }
    } else {
        RegistryError::PushFailed {
            registry: registry.to_string(),
            tag: tag.to_string(),
            attempts: failure.attempt,
            exit_code: failure.exit_code,
            stderr: failure.stderr,
        }
    }
}

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
    /// Drives [`crate::retry::retry_command`] with a network-shaped
    /// schedule (exponential backoff capped at 30s, see
    /// [`RetryPolicy::network`]) so transient skopeo failures retry on
    /// 250ms / 500ms / 1s / ... instead of the legacy fixed 2s. The
    /// canonical primitive composes the canonical
    /// `is_transient_network_stderr` classifier with the canonical
    /// `CommandAttemptFailure::from_capture` mapping in one call, so this
    /// site no longer carries the `run_with_policy + classifier +
    /// from_capture` triple inline (commit 26ddcef migrated three sibling
    /// retry call sites onto `retry_command`; this commit closes the arc
    /// by migrating the fourth — the only remaining hand-rolled
    /// `run_with_policy` call site in forge).
    ///
    /// On exhaustion, the returned `CommandAttemptFailure` is dispatched
    /// to one of two typed-error variants via
    /// [`crate::retry::CommandAttemptFailure::is_spawn_failure`]:
    /// - spawn failure (skopeo not on PATH) → `RegistryError::ExecFailed`
    ///   carrying the `push {registry}:{tag}` op label and the underlying
    ///   spawn-error message.
    /// - non-zero exit → `RegistryError::PushFailed` carrying the
    ///   registry+tag tuple, the final `attempts` count (recovered from
    ///   the typed record's `attempt` field — preserves the pre-migration
    ///   semantics), and the structured `(exit_code, stderr)` pair.
    ///
    /// The split between `ExecFailed` (could not spawn) and `PushFailed`
    /// (skopeo ran and rejected) matches the discipline already
    /// established for `AtticError::ExecFailed`,
    /// `NixBuildError::ExecFailed`, `GitError::ExecFailed`, and
    /// `KubernetesError::ExecFailed` — same arc, fifth surface migrated.
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
        let max_attempts = policy.max_attempts;
        let op = format!("push {}:{}", registry, tag);

        let result = retry_command(&policy, &op, |attempt| async move {
            let skopeo = get_tool_path("SKOPEO_BIN", "skopeo");
            let outcome = Command::new(&skopeo)
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
            if outcome
                .as_ref()
                .map(|o| !o.status.success())
                .unwrap_or(true)
                && attempt < max_attempts
            {
                warn!("Push attempt {} failed, retrying...", attempt);
            }
            outcome
        })
        .await;

        result
            .map(|_| ())
            .map_err(|failure| classify_push_failure(failure, registry, tag))
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

            let output = cmd.output().await.map_err(|e| RegistryError::ExecFailed {
                operation: format!("create manifest index for {}", target),
                message: e.to_string(),
            })?;

            if let Some(cf) = CapturedFailure::from_output_if_failed(&output) {
                return Err(RegistryError::ManifestFailed {
                    target: target.clone(),
                    exit_code: cf.exit_code,
                    stderr: cf.stderr,
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

    /// `classify_push_failure` dispatches a post-`retry_command`
    /// `CommandAttemptFailure` to the typed `RegistryError` variant whose
    /// structural shape matches. Pre-migration this dispatch was inline
    /// in `push_with_retries` (the `Err(e) => Err(ExecFailed)` arm vs the
    /// `Ok(out) non-success => Err(PushFailed)` arm of the `match output`
    /// body). Post-migration the dispatch is one named helper consuming
    /// the typed [`crate::retry::CommandAttemptFailure::is_spawn_failure`]
    /// predicate. Pinning the four-case mapping lets the typed-error
    /// surface evolve (e.g., adding a `RegistryError::PushTimeout`
    /// variant) without subtle drift between this site and the canonical
    /// retry primitive.
    #[test]
    fn test_classify_push_failure_dispatches_on_spawn_vs_op() {
        // Spawn-failure (skopeo not on PATH): empty stderr, exit_code
        // None, spawn-error message in stdout. Must produce
        // `RegistryError::ExecFailed` — never `PushFailed` — because
        // the underlying CLI never ran. Same discipline the four
        // sibling typed-error families (Atti, Nix, Git, Kubernetes)
        // already encode for their `ExecFailed` variants.
        let spawn = CommandAttemptFailure {
            operation: "push ghcr.io/o/p/s:tag".to_string(),
            attempt: 1,
            exit_code: None,
            stderr: String::new(),
            stdout: "failed to spawn process: No such file or directory".to_string(),
        };
        match classify_push_failure(spawn, "ghcr.io/o/p/s", "amd64-abc1234") {
            RegistryError::ExecFailed { operation, message } => {
                assert_eq!(operation, "push ghcr.io/o/p/s:tag");
                assert!(
                    message.contains("No such file or directory"),
                    "spawn-error message must flow through stdout: {message}"
                );
            }
            other => panic!("expected ExecFailed, got: {other:?}"),
        }

        // Op-failure with transient stderr (HTTP 503): exit_code Some,
        // stderr populated. Must produce `RegistryError::PushFailed`
        // carrying the structural-record tuple — registry, tag, the
        // typed `attempt` count, exit_code, and stderr — verbatim.
        let transient = CommandAttemptFailure {
            operation: "push ghcr.io/o/p/s:tag".to_string(),
            attempt: 5,
            exit_code: Some(1),
            stderr: "received unexpected HTTP status: 503 Service Unavailable".to_string(),
            stdout: String::new(),
        };
        match classify_push_failure(transient, "ghcr.io/o/p/s", "amd64-abc1234") {
            RegistryError::PushFailed {
                registry,
                tag,
                attempts,
                exit_code,
                stderr,
            } => {
                assert_eq!(registry, "ghcr.io/o/p/s");
                assert_eq!(tag, "amd64-abc1234");
                assert_eq!(
                    attempts, 5,
                    "attempts must be recovered from CommandAttemptFailure.attempt"
                );
                assert_eq!(exit_code, Some(1));
                assert!(stderr.contains("503"));
            }
            other => panic!("expected PushFailed, got: {other:?}"),
        }

        // Op-failure with terminal stderr (HTTP 401): same `PushFailed`
        // shape — the dispatch does NOT inspect transient-vs-terminal
        // (that classification happens INSIDE `retry_command` to decide
        // whether to retry). By the time the helper is called, the
        // retry loop has already exhausted; the dispatch only chooses
        // between `ExecFailed` and `PushFailed` based on whether the
        // CLI actually ran.
        let terminal = CommandAttemptFailure {
            operation: "push ghcr.io/o/p/s:tag".to_string(),
            attempt: 1,
            exit_code: Some(1),
            stderr: "401 Unauthorized: bad credentials".to_string(),
            stdout: String::new(),
        };
        match classify_push_failure(terminal, "ghcr.io/o/p/s", "amd64-abc1234") {
            RegistryError::PushFailed {
                attempts, stderr, ..
            } => {
                assert_eq!(
                    attempts, 1,
                    "terminal failure short-circuits at attempt 1; helper preserves that"
                );
                assert!(stderr.contains("401"));
            }
            other => panic!("expected PushFailed, got: {other:?}"),
        }
    }

    /// Regression guard for the `is_spawn_failure` predicate at the
    /// dispatch site. A spawn-failure record carries `exit_code: None`
    /// AND empty `stderr`. A non-zero-exit record with empty `stderr`
    /// (a CLI that ran, exited non-zero, and emitted nothing) is
    /// structurally distinct: it must dispatch to `PushFailed`, not
    /// `ExecFailed`, because the CLI did run. Pinning this guards
    /// against a future regression that drops the `exit_code.is_none()`
    /// half of the predicate.
    #[test]
    fn test_classify_push_failure_silent_op_failure_routes_to_push_failed() {
        let silent_op = CommandAttemptFailure {
            operation: "push ghcr.io/o/p/s:tag".to_string(),
            attempt: 2,
            exit_code: Some(125),
            stderr: String::new(),
            stdout: String::new(),
        };
        // Sanity: this is NOT a spawn failure (exit_code is Some).
        assert!(!silent_op.is_spawn_failure());
        match classify_push_failure(silent_op, "ghcr.io/o/p/s", "amd64-abc1234") {
            RegistryError::PushFailed {
                attempts,
                exit_code,
                stderr,
                ..
            } => {
                assert_eq!(attempts, 2);
                assert_eq!(exit_code, Some(125));
                assert!(stderr.is_empty());
            }
            other => panic!("expected PushFailed, got: {other:?}"),
        }
    }
}
