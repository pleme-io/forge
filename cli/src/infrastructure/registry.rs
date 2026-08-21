//! Container registry operations
//!
//! Handles pushing images to GHCR using skopeo and multi-arch manifest
//! creation using regctl. All push paths in forge converge here.

use anyhow::{Context, Result};
use std::process::Stdio;
use tokio::process::Command;
use tracing::info;

use crate::error::RegistryError;
use crate::repo::get_tool_path;
use crate::retry::{
    classify_attempt_failure, classify_capture, classify_capture_query, retry_command_logged,
    CommandAttemptFailure, RetryPolicy,
};

/// Module-scoped sigil: resolve the `oci-push` (`doca`) binary via the
/// canonical two-argument `DOCA_BIN`-first / `oci-push`-fallback
/// lookup. Every production site in `infrastructure/registry.rs` that
/// spawns `doca` — the `push_with_retries` retry-loop body and the
/// `verify_tag_exists` capture — routes through this sigil, so the
/// substrate-exported `DOCA_BIN` env-var contract is honored at
/// exactly ONE code line in the module.
///
/// Pre-lift the module carried two respells of the two-argument
/// resolve, one inside the `retry_command` closure of
/// [`RegistryClient::push_with_retries`] and one inside
/// [`RegistryClient::verify_tag_exists`]. That was 2 occurrences —
/// THEORY §VI.1's coincidence tier — and the second respell silently
/// bypassed the module's own single-point-of-truth for tool
/// resolution: a future edit to the resolve contract at the push site
/// would have left the verify site stranded at the pre-edit form. The
/// sibling `<tool>_bin()` sigil family — `attic_bin()`
/// (`infrastructure/attic.rs`, 559adae), `cargo_bin()`
/// (`commands/comprehensive_release.rs`, fceeecc), `nc_bin()`
/// (`commands/nix_builder.rs`, b5e632a), `flux_bin()` (flux_get /
/// flux_reconcile, 5ad341e / ba3e615), plus the broader CARGO /
/// NIX_BIN / DOCKER_BIN / BUN_BIN / CRATE2NIX surfaces — has already
/// crossed the three-times threshold on the sigil discipline itself,
/// so lifting `DOCA_BIN` here now brings the last production `doca`
/// spawn family in `infrastructure/*` under the same discipline.
///
/// The lift is load-bearing beyond deduplication: `DOCA_BIN` names
/// [the doca RFC bug that shipped and hid for a release cycle]
/// (`cli/src/tools.rs::doca_resolves_from_doca_bin_and_the_deriving_lookup_does_not`)
/// — `tools::DOCA`'s value is `"oci-push"`, so the one-argument
/// deriving `get_tool_path(tools::DOCA)` reads `OCI_PUSH_BIN` which
/// nothing exports. Routing every consumer through this sigil pins
/// the two-argument form at a single named site, so a future
/// "tidy-up" to the deriving form cannot silently re-open the
/// silent-PATH-fallback bug on both `push` and `verify`.
///
/// THEORY §I.5 (Generation over composition, duplication budget
/// zero); THEORY §VI.1 (three-times rule at the sigil-pattern level).
fn doca_bin() -> String {
    get_tool_path("DOCA_BIN", "oci-push")
}

/// Dispatch a post-`retry_command` `CommandAttemptFailure` to the typed
/// `RegistryError` variant whose structural shape matches the captured
/// failure. Spawn-failure (skopeo not on PATH) routes to `ExecFailed`
/// carrying the operation label and the spawn-error message; non-zero
/// exit routes to `PushFailed` carrying `(registry, tag, attempts,
/// exit_code, stderr)` — the structural-record tuple the canonical retry
/// classifier and Phase 1 attestation records (THEORY §V.4) consume.
///
/// Drives the canonical [`classify_attempt_failure`] primitive — sibling
/// of [`classify_capture`] for the post-retry shape. The dispatch (which
/// closure runs) lives in the primitive; this site only owns the
/// per-family variant constructors, so the `(registry, tag)` and
/// `operation` lookups stay at the call site where they're meaningful.
/// Mirror of `infrastructure/attic.rs::classify_attic_push_failure`.
fn classify_push_failure(
    failure: CommandAttemptFailure,
    registry: &str,
    tag: &str,
) -> RegistryError {
    classify_attempt_failure(
        failure,
        |spawn| RegistryError::ExecFailed {
            operation: spawn.operation,
            message: spawn.stdout,
        },
        |op| RegistryError::PushFailed {
            registry: registry.to_string(),
            tag: tag.to_string(),
            attempts: op.attempt,
            exit_code: op.exit_code,
            stderr: op.stderr,
        },
    )
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
        let gh = get_tool_path("GH_BIN", "gh");
        std::process::Command::new(&gh)
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
        crate::infrastructure::kubectl::fetch_secret_value(
            "github-runner-secret",
            "github-actions",
            "GHCR_TOKEN",
        )
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

        let policy = RetryPolicy::network_with_max_attempts(retries);
        let op = format!("push {}:{}", registry, tag);

        // doca wants --registry/--image separately where skopeo took one
        // composed reference. Split on the FIRST '/' and REFUSE a base with no
        // '/': a wrong split pushes to the wrong repository rather than
        // failing, so guessing here would be worse than erroring.
        let (host, image) =
            registry
                .split_once('/')
                .ok_or_else(|| RegistryError::LocalImageNotFound {
                    path: format!("registry {registry:?} has no '/', cannot split host from image"),
                })?;
        let host = host.to_string();
        let image = image.to_string();

        let result = retry_command_logged(&policy, &op, |_attempt| {
            let host = host.clone();
            let image = image.clone();
            async move {
                let doca = doca_bin();
                // ── CREDENTIALS BY ENV, NEVER ARGV. ─────────────────────────
                // This previously passed `--dest-creds=<org>:<token>` on the
                // command line. /proc/<pid>/cmdline is world-readable, so on a
                // shared runner any co-tenant process could read the GHCR token
                // for as long as the push ran. doca reads INPUT_DEST_USER /
                // INPUT_DEST_PASS from the environment, which is not.
                //
                // skopeo's `--retry-times` is dropped deliberately, not lost:
                // it was a second retry loop nested inside forge's own
                // retry_command above, and doca's push_with_retry already backs
                // off exponentially while distinguishing transient failures
                // from permanent ones (a 401 does not burn the budget).
                Command::new(&doca)
                    .args([
                        "push",
                        "--tarball",
                        image_path,
                        "--registry",
                        &host,
                        "--image",
                        &image,
                        "--tag",
                        tag,
                    ])
                    .env("INPUT_DEST_USER", &self.credentials.organization)
                    .env("INPUT_DEST_PASS", &self.credentials.token)
                    .stdout(Stdio::null())
                    .stderr(Stdio::piped())
                    .output()
                    .await
            }
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
    ///
    /// Spawn-vs-op dispatch flows through the canonical
    /// [`classify_capture_query`] primitive — the query-shape dual of
    /// `classify_capture` (the op-shape primitive `create_manifest_index`
    /// already drives). Spawn failures (`Err(io::Error)` — skopeo not on
    /// PATH) route to `RegistryError::ExecFailed` carrying the operation
    /// label and the underlying spawn-error message; non-zero exits route
    /// to `RegistryError::RemoteImageNotFound` carrying the (registry, tag)
    /// tuple. The op-failure variant deliberately discards `(exit_code,
    /// stderr)` — `RemoteImageNotFound` is a precondition variant ("the
    /// queried tag isn't there"), not a structural CLI failure that needs
    /// the captured tuple. The `_cf` ignore in the op-failure closure
    /// makes that intent structural at the call site.
    pub async fn verify_tag_exists(
        &self,
        registry: &str,
        tag: &str,
    ) -> Result<String, RegistryError> {
        let doca = doca_bin();
        // CREDENTIALS BY ENV, NEVER ARGV — `--creds=<org>:<token>` put the
        // token in /proc/<pid>/cmdline, readable by any co-tenant process on a
        // shared runner. doca reads INPUT_USER / INPUT_PASS from the
        // environment instead.
        //
        // `--digest-only` replaces skopeo's `--format {{.Digest}}`: both print
        // the OCI manifest digest (`sha256:…`) and nothing else, so the caller's
        // parsing is unchanged.
        let captured = Command::new(&doca)
            .args([
                "inspect",
                "--ref",
                &format!("{}:{}", registry, tag),
                "--digest-only",
            ])
            .env("INPUT_USER", &self.credentials.organization)
            .env("INPUT_PASS", &self.credentials.token)
            .output()
            .await;

        let digest = classify_capture_query(
            captured,
            |e| RegistryError::ExecFailed {
                operation: format!("inspect {}:{}", registry, tag),
                message: e.to_string(),
            },
            |_cf| RegistryError::RemoteImageNotFound {
                registry: registry.to_string(),
                tag: tag.to_string(),
            },
        )?;

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
            pushed.push(crate::oci_manifest::image_reference(registry, tag));
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
            // Precondition failure — no CLI was spawned, no attempt was
            // made — distinct by construction from `PushFailed` (which
            // represents a real push attempt the registry rejected).
            // Pre-migration this site synthesized `PushFailed { attempts:
            // 0, exit_code: None, stderr: "no images provided..." }`,
            // requiring callers to interpret `attempts == 0` as the
            // discriminator. The typed `NoImagesProvided` variant
            // (cli/src/error.rs) makes that invalid state — a
            // `PushFailed` with `attempts: 0` — structurally
            // unrepresentable (THEORY §V.1).
            return Err(RegistryError::NoImagesProvided {
                registry: registry.to_string(),
                tag_suffix: tag_suffix.to_string(),
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
                arch_tags.push(crate::oci_manifest::image_reference(registry, tag));
            }

            // Track the immutable arch-sha tag as source for manifest index
            source_refs.push(crate::oci_manifest::image_reference(
                registry,
                &format!("{}-{}", image.arch, tag_suffix),
            ));
        }

        // Step 2: Create manifest index if multiple architectures
        let manifest_tags = if images.len() > 1 {
            let tags = vec![tag_suffix.to_string(), "latest".to_string()];

            info!("Creating multi-arch manifest index...");
            self.create_manifest_index(registry, &tags, &source_refs)
                .await?;

            tags.iter()
                .map(|t| crate::oci_manifest::image_reference(registry, t))
                .collect()
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
            let target = crate::oci_manifest::image_reference(registry, tag);
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

            // Spawn-vs-op dispatch flows through the canonical
            // [`classify_capture`] primitive — same shape as
            // `git.rs::git_capture` and `nix.rs::run_nix_build_typed`.
            // Spawn failures (`Err(io::Error)` — regctl not on PATH)
            // route to `RegistryError::ExecFailed`; non-zero exits route
            // to `RegistryError::ManifestFailed` carrying the
            // structural `(target, exit_code, stderr)` tuple
            // `CapturedFailure` extracts.
            let target_for_err = target.clone();
            classify_capture(
                cmd.output().await,
                |e| RegistryError::ExecFailed {
                    operation: format!("create manifest index for {}", target),
                    message: e.to_string(),
                },
                |cf| RegistryError::ManifestFailed {
                    target: target_for_err,
                    exit_code: cf.exit_code,
                    stderr: cf.stderr,
                },
            )?;

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

    /// Multi-arch push with empty image list must surface
    /// `NoImagesProvided` carrying the (registry, tag_suffix) tuple it
    /// was invoked with — never a synthesized `PushFailed { attempts: 0,
    /// exit_code: None, stderr: "no images..." }`. The precondition
    /// failure (no CLI was spawned, no attempt was made) is structurally
    /// distinct from `PushFailed` (a real push attempt the registry
    /// rejected); pinning the typed variant makes the invalid state — a
    /// `PushFailed` carrying `attempts: 0` — structurally unrepresentable
    /// (THEORY §V.1). Same arc as the typed ExecFailed / OpFailed split
    /// established for AtticError, NixBuildError, GitError, and
    /// KubernetesError.
    #[test]
    fn test_push_multiarch_empty_returns_no_images_provided() {
        let client = RegistryClient::new(RegistryCredentials::new("org", "tok"));
        let registry = "ghcr.io/o/p/s";
        let suffix = "abc1234";
        let err = tokio_test::block_on(client.push_multiarch(registry, &[], suffix))
            .expect_err("empty multiarch push must fail");
        match err {
            RegistryError::NoImagesProvided {
                registry: r,
                tag_suffix,
            } => {
                assert_eq!(r, registry);
                assert_eq!(tag_suffix, suffix);
            }
            other => panic!("expected NoImagesProvided, got: {other:?}"),
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

    /// Whole-module shield: no `Command::new`-with-bare-`gh`-literal
    /// may live in `infrastructure/registry.rs`. Every `gh` spawn must
    /// resolve `GH_BIN` via [`crate::repo::get_tool_path`] first.
    ///
    /// Pre-lift the sole `gh` spawn site — `try_gh_cli_token`'s
    /// `gh auth token` fetch on the GHCR-credential-discovery path —
    /// spelled the bare `"gh"` literal verbatim, ignoring `GH_BIN` at
    /// the site. A Nix-hermetic runner's substrate-derived `gh` path
    /// was lost to whatever `gh` sat first on PATH — the same silent-
    /// PATH-fallback bug class the sibling `DOCA_BIN` / `REGCTL_BIN`
    /// lookups in this file already avoid, and the discipline the
    /// sibling `docker` / `kubectl` / `nix` / `git` / `helm` /
    /// `crossplane` / `flux` / `attic` / `redis-cli` surfaces
    /// converged on across the prior claude-routine commits.
    ///
    /// This shield scans the module's own source via [`include_str!`]
    /// and forbids the fused literal shape. The forbidden shape is
    /// reconstructed via [`format!`] so this shield's own source text
    /// does not false-match itself — the whole-module scan therefore
    /// covers both the top-of-file production body AND every sibling
    /// `#[cfg(test)]` block (any of which could otherwise silently re-
    /// introduce a raw literal). The end-to-end `GH_BIN`-routing
    /// invariant of the underlying primitive is pinned separately by
    /// [`crate::repo::test_get_tool_path_with_env`]; this shield only
    /// certifies that every `gh`-spawning site in this module resolves
    /// through the `get_tool_path` canonical lookup first.
    #[test]
    fn test_gh_spawn_routes_through_gh_bin_not_raw_literal() {
        const SOURCE: &str = include_str!("registry.rs");

        crate::test_support::assert_source_forbids_bare_spawn_shapes(
            SOURCE,
            "infrastructure/registry.rs",
            "gh",
            "resolve the substrate-exported `GH_BIN` env override via `get_tool_path`",
        );
        crate::test_support::assert_source_has_get_tool_path_two_arg_call_code_line(
            SOURCE,
            "infrastructure/registry.rs",
            "GH_BIN",
            "gh",
        );
    }

    /// Whole-module shield: `fn doca_bin()` — the module-scoped
    /// sigil that resolves the `oci-push` (`doca`) binary via the
    /// canonical two-argument `DOCA_BIN`-first / `oci-push`-fallback
    /// call — MUST be defined at a code line in this module AND the
    /// two-argument resolve MUST appear at exactly ONE code line in
    /// the module body (only in the sigil definition).
    ///
    /// Pre-lift the module carried two respells of the two-argument
    /// resolve — one inside the `retry_command` closure of
    /// [`RegistryClient::push_with_retries`] (the push retry-loop
    /// body's `Command::new(&doca)` invocation) and one inside
    /// [`RegistryClient::verify_tag_exists`] (the capture-shape
    /// digest probe). The second respell silently bypassed the
    /// module's own single-point-of-truth: a future edit to the
    /// resolve contract at the push site would have left the verify
    /// site stranded at the pre-edit form and vice versa. Post-lift
    /// each consumer routes through `doca_bin()` and the resolve
    /// appears at exactly ONE place (the sigil body). The
    /// `resolve_count == 1` assertion fails-before at 2, passes-after
    /// at 1 — the canonical fail-before-pass-after arc matching the
    /// sibling `<tool>_bin()` shield discipline landed on
    /// `infrastructure/attic.rs::attic_bin` (559adae),
    /// `commands/comprehensive_release.rs::cargo_bin` (fceeecc),
    /// `cli/src/nix.rs::nix_bin` (6b2ea15),
    /// `commands/rust_service.rs::nix_bin` (63d4fe7),
    /// `commands/tool.rs::{cargo,crate2nix}_bin` (9f6046b / 7561329),
    /// `commands/nix_builder.rs::nc_bin` (b5e632a),
    /// `commands/flux_{get,reconcile}.rs::flux_bin` (5ad341e /
    /// ba3e615), and the broader `<tool>_bin()` sigil family.
    ///
    /// The scan bounds on the whole-module boundary (from the file
    /// start to the FIRST `\n#[cfg(test)]\nmod tests {` marker in
    /// source order — the outer test module's opener at line 599 in
    /// the current layout) so this shield's own docstring mentions of
    /// the two-argument resolve form — living inside the
    /// `#[cfg(test)]` block below that marker — stay out of scope
    /// AND every current or future `doca`-spawning helper landing
    /// anywhere in the top-level module body cannot silently ride
    /// along without going through `doca_bin()`.
    ///
    /// The two-argument-resolve needle is reconstructed via `format!`
    /// inside [`crate::test_support::get_tool_path_two_arg_call_needle`]
    /// and the sigil-definition needle via
    /// [`crate::test_support::sigil_bin_fn_definition_needle`], so
    /// this shield's own source never contains a concrete
    /// `get_tool_path("DOCA_BIN", "oci-push")` or `fn doca_bin()`
    /// literal at a code line and cannot false-match itself on either
    /// assertion. Both positive assertions route through
    /// [`crate::test_support::code_line_hits`] to preserve the
    /// anti-docstring-self-match discipline.
    #[test]
    fn test_registry_routes_doca_through_doca_bin_sigil_not_raw_resolve() {
        let body = crate::test_support::module_body_before_tests(
            include_str!("registry.rs"),
            "infrastructure/registry.rs",
        );

        let sigil_needle = crate::test_support::sigil_bin_fn_definition_needle("doca_bin");
        let sigil_hits = crate::test_support::code_line_hits(body, &sigil_needle);
        assert!(
            !sigil_hits.is_empty(),
            "infrastructure/registry.rs must define `doca_bin()` at a \
             code line in the module body — the sigil function that \
             resolves the substrate-exported `DOCA_BIN` override for \
             every `doca`/`oci-push` binary lookup (both the push \
             retry-loop body in `push_with_retries` and the capture \
             probe in `verify_tag_exists`). Mirrors the sibling \
             `<tool>_bin()` sigils across the ATTIC_BIN / CARGO / \
             NIX_BIN / DOCKER_BIN / BUN_BIN / CRATE2NIX / FLUX_BIN / \
             NC_BIN surfaces."
        );

        let two_arg_needle =
            crate::test_support::get_tool_path_two_arg_call_needle("DOCA_BIN", "oci-push");
        let resolve_hits = crate::test_support::code_line_hits(body, &two_arg_needle);
        assert_eq!(
            resolve_hits.len(),
            1,
            "the two-argument resolve `{two_arg_needle}` must appear \
             at exactly ONE code line in the module body (only in the \
             `doca_bin()` sigil), not {} — every consumer must route \
             through `doca_bin()`, not re-copy the resolve inline. A \
             future edit to the resolve contract (a substrate-path \
             validation step, a per-spawn env-injection hook, a \
             telemetry sigil on the resolved path) must land at the \
             sigil body once, not at each drifted call site. \
             `DOCA_BIN` is doubly load-bearing: the deriving-form \
             lookup `get_tool_path(tools::DOCA)` would read \
             `OCI_PUSH_BIN` which nothing exports (see \
             `tools.rs::doca_resolves_from_doca_bin_and_the_deriving_lookup_does_not`), \
             so any drift here silently re-opens the shipped-and-hid \
             image-release bug. Found {} code-line hit(s): \
             {resolve_hits:#?}",
            resolve_hits.len(),
            resolve_hits.len()
        );
    }
}
