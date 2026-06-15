//! Attic cache operations
//!
//! Handles pushing Nix closures to Attic binary cache. Failure paths
//! produce typed `AtticError` values carrying the offending input
//! (cache, store path, server URL, exit code, captured stderr) so
//! callers can attach failure records to the exact attic step without
//! parsing log output. Same arc as `RegistryError` and `NixBuildError`.

use std::process::Stdio;
use tokio::process::Command;
use tracing::{info, warn};

use crate::error::AtticError;
use crate::repo::get_tool_path;
use crate::retry::{
    classify_attempt_failure, classify_capture, log_retry_attempt, retry_command,
    CommandAttemptFailure, RetryPolicy,
};

/// Dispatch a post-`retry_command` `CommandAttemptFailure` to the typed
/// `AtticError` variant whose structural shape matches the captured
/// failure. Spawn-failure (attic not on PATH) routes to `ExecFailed`
/// carrying the cache name and the spawn-error message; non-zero exit
/// routes to `PushFailed` carrying `(cache, store_path, attempts,
/// exit_code, stderr)` — the structural-record tuple Phase 1
/// attestation records (THEORY §V.4) consume.
///
/// Drives the canonical [`classify_attempt_failure`] primitive — same
/// helper `infrastructure/registry.rs::classify_push_failure` consumes,
/// so the `is_spawn_failure` discriminator lives in one place across
/// both retry-driven typed-error producer surfaces. The two helpers
/// together close the post-`retry_command` dispatch surface for every
/// typed-error producer in forge that wraps a network-shaped CLI in
/// `retry_command`.
fn classify_attic_push_failure(
    failure: CommandAttemptFailure,
    cache: &str,
    store_path: &str,
) -> AtticError {
    classify_attempt_failure(
        failure,
        |spawn| AtticError::ExecFailed {
            cache: cache.to_string(),
            message: spawn.stdout,
        },
        |op| AtticError::PushFailed {
            cache: cache.to_string(),
            store_path: store_path.to_string(),
            attempts: op.attempt,
            exit_code: op.exit_code,
            stderr: op.stderr,
        },
    )
}

/// Client for Attic cache operations
pub struct AtticClient {
    cache_name: String,
    token: Option<String>,
    attic_bin: Option<String>,
    default_retries: u32,
}

impl AtticClient {
    /// Create a new Attic client
    pub fn new(cache_name: impl Into<String>) -> Self {
        Self {
            cache_name: cache_name.into(),
            token: None,
            attic_bin: None,
            default_retries: 3,
        }
    }

    /// Set authentication token
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    /// Override the default retry budget for [`Self::push`]. Mirrors
    /// `RegistryClient::with_retries`. Tests pin the schedule by
    /// constructing the client with `with_retries(N)` and a hermetic
    /// shim; production callers leave the default of 3 in place.
    #[cfg(test)]
    pub fn with_retries(mut self, retries: u32) -> Self {
        self.default_retries = retries;
        self
    }

    /// Override the path to the `attic` binary. Used by tests to point at
    /// a hermetic shim; production code should leave this unset and let
    /// `get_tool_path("ATTIC_BIN", "attic")` resolve it from the
    /// environment or PATH.
    #[cfg(test)]
    pub fn with_attic_bin(mut self, bin: impl Into<String>) -> Self {
        self.attic_bin = Some(bin.into());
        self
    }

    fn resolve_attic_bin(&self) -> String {
        self.attic_bin
            .clone()
            .unwrap_or_else(|| get_tool_path("ATTIC_BIN", "attic"))
    }

    /// Discover Attic token from environment
    pub fn discover_token() -> Option<String> {
        std::env::var("ATTIC_TOKEN").ok().filter(|s| !s.is_empty())
    }

    /// Create client with auto-discovered token
    pub fn discover(cache_name: impl Into<String>) -> Self {
        let mut client = Self::new(cache_name);
        if let Some(token) = Self::discover_token() {
            client.token = Some(token);
        }
        client
    }

    /// Push a store path to the cache, retrying transient network
    /// failures.
    ///
    /// Drives [`crate::retry::retry_command`] with a network-shaped
    /// schedule (exponential backoff capped at 30s, see
    /// [`RetryPolicy::network`]) so transient attic failures (HTTP 5xx
    /// from the cache backend, mid-stream EOF, connection refused) retry
    /// on 250ms / 500ms / 1s / ... — same idiom the registry surface
    /// adopted for `skopeo copy` (commit b0db1da). The structural
    /// equivalence between attic-push and skopeo-copy on the typed-error
    /// producer surface (both wrap an idempotent network upload that
    /// can transiently fail with a retryable HTTP marker) collapses
    /// onto one primitive instead of two divergent retry loops.
    ///
    /// Returns typed errors:
    /// - [`AtticError::ExecFailed`] when `attic` cannot be spawned.
    /// - [`AtticError::PushFailed`] when attic exhausts the retry budget
    ///   or fails terminally, carrying the offending cache, store path,
    ///   final attempt count, exit code, and captured stderr.
    pub async fn push(&self, store_path: &str) -> Result<(), AtticError> {
        self.push_with_retries(store_path, self.default_retries)
            .await
    }

    /// Push with an explicit retry budget. The budget is clamped to `>=
    /// 1` by [`RetryPolicy::new`], so a degenerate `0` cannot silently
    /// turn the loop into a no-op. The transient-vs-terminal classifier
    /// is the canonical `is_transient_network_stderr` substring matcher
    /// — same one `RegistryClient::push_with_retries` uses; pinning one
    /// classifier across both surfaces means a future addition to the
    /// transient-marker list (e.g., a new attic-server-flavored error
    /// shape) lights up retries on both surfaces in the same commit.
    ///
    /// On exhaustion the returned `CommandAttemptFailure` is dispatched
    /// to one of two typed-error variants via
    /// [`crate::retry::CommandAttemptFailure::is_spawn_failure`]:
    /// - spawn failure (attic not on PATH) → `AtticError::ExecFailed`
    ///   carrying the cache name and the spawn-error message.
    /// - non-zero exit → `AtticError::PushFailed` carrying the
    ///   structural-record tuple (cache, store_path, attempts,
    ///   exit_code, stderr) — the same shape
    ///   `RegistryError::PushFailed` carries on the sibling registry
    ///   surface, so a downstream consumer (telemetry, replay,
    ///   attestation) can write one destructure pattern that works
    ///   across both push surfaces.
    pub async fn push_with_retries(
        &self,
        store_path: &str,
        retries: u32,
    ) -> Result<(), AtticError> {
        info!("Pushing to Attic cache: {}", self.cache_name);

        let policy = RetryPolicy::network_with_max_attempts(retries);
        let max_attempts = policy.max_attempts;
        let attic_bin = self.resolve_attic_bin();
        let cache = self.cache_name.clone();
        let token = self.token.clone();
        let op = format!("push {} to {}", store_path, cache);

        let result = retry_command(&policy, &op, |attempt| {
            let attic_bin = attic_bin.clone();
            let cache = cache.clone();
            let token = token.clone();
            let op = op.clone();
            async move {
                let mut cmd = Command::new(&attic_bin);
                cmd.args(["push", &cache, store_path])
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                if let Some(t) = token.as_deref() {
                    cmd.env("ATTIC_TOKEN", t);
                }
                log_retry_attempt(cmd.output().await, &op, attempt, max_attempts)
            }
        })
        .await;

        result.map(|_| ()).map_err(|failure| {
            classify_attic_push_failure(failure, &self.cache_name, store_path)
        })?;

        info!("Successfully pushed to Attic cache");
        Ok(())
    }

    /// Push a store path, ignoring failures (non-fatal)
    pub async fn push_optional(&self, store_path: &str) -> bool {
        match self.push(store_path).await {
            Ok(()) => {
                info!("Pushed to Attic cache: {}", self.cache_name);
                true
            }
            Err(e) => {
                warn!("Failed to push to Attic cache (non-fatal): {}", e);
                false
            }
        }
    }

    /// Push a whole Nix closure to the Attic cache via
    /// `attic push <cache_name> --stdin`.
    ///
    /// Spawns `attic push <cache_name> --stdin` with stdin piped (writes
    /// `closure_bytes` then drops stdin so attic sees EOF) and
    /// stdout/stderr piped (captured for the typed-error payload). The
    /// byte stream is the canonical `nix path-info --recursive <path>`
    /// stdout — one store path per line — which attic consumes as a
    /// batch of upload jobs.
    ///
    /// Sibling of [`Self::push`]: same cache + token + binary
    /// resolution, same `ExecFailed` typed variant on spawn failure.
    /// The split between the two is the input shape:
    /// - [`Self::push`] takes one `store_path` arg ↦
    ///   `attic push <cache> <path>` ↦ [`AtticError::PushFailed`]
    ///   carrying the single store path.
    /// - [`Self::push_closure_via_stdin`] takes a byte stream ↦
    ///   `attic push <cache> --stdin` ↦
    ///   [`AtticError::ClosurePushFailed`] carrying no per-path field
    ///   (the input is a stdin-fed batch, not a single CLI arg).
    ///
    /// Lifts the verbatim ~22-line stanza repeated three times across
    /// `commands/build.rs::execute` (single closure push after a
    /// successful image build) and
    /// `commands/rust_service.rs::push_rust_service` (AMD64 + ARM64
    /// sibling closures). Pre-lift each site spelled out the same
    /// `Command::new("attic").args(["push", &cache, "--stdin"])` /
    /// `.stdin(Stdio::piped()).spawn().context(...)` /
    /// `stdin.take().write_all(...).await? + drop(stdin)` / `wait()` /
    /// `if !status.success() { warn! } else { info! }` body. Three
    /// occurrences past THEORY §VI.1's three-is-a-law threshold
    /// (PRIME DIRECTIVE: duplication budget is zero) consolidate onto
    /// this typed primitive.
    ///
    /// # Token forwarding
    ///
    /// Same shape as [`Self::push`]: when `self.token` is `Some`,
    /// `ATTIC_TOKEN` is set on the spawned process's environment;
    /// otherwise the env var is left unmodified (tokio inherits the
    /// parent's env by default, so a parent-provided `ATTIC_TOKEN`
    /// still flows through). This matches the behavior the three
    /// pre-lift sites relied on — none of them set `ATTIC_TOKEN`
    /// explicitly on the `attic push --stdin` invocation; they relied
    /// on the env having been seeded earlier in the calling command.
    ///
    /// # Returns
    ///
    /// - [`AtticError::ExecFailed`] when `attic` cannot be spawned, or
    ///   when stdin cannot be acquired from the spawned child (the
    ///   `child.stdin.take()` returning `None` case — should be
    ///   structurally impossible with `Stdio::piped()` but is mapped
    ///   to `ExecFailed` for completeness).
    /// - [`AtticError::ClosurePushFailed`] when `attic` exits non-zero,
    ///   carrying the cache name, exit code, and trimmed UTF-8-lossy
    ///   stderr — the structural-record tuple Phase 1 attestation
    ///   records (THEORY §V.4) consume.
    pub async fn push_closure_via_stdin(&self, closure_bytes: &[u8]) -> Result<(), AtticError> {
        let attic_bin = self.resolve_attic_bin();
        let mut cmd = Command::new(&attic_bin);
        cmd.args(["push", &self.cache_name, "--stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(t) = self.token.as_deref() {
            cmd.env("ATTIC_TOKEN", t);
        }

        let mut child = cmd.spawn().map_err(|e| AtticError::ExecFailed {
            cache: self.cache_name.clone(),
            message: e.to_string(),
        })?;

        // Stdio::piped() guarantees child.stdin is Some; the `take`
        // returning None case is structurally impossible. We map it to
        // ExecFailed so the typed surface is total.
        let mut stdin = child.stdin.take().ok_or_else(|| AtticError::ExecFailed {
            cache: self.cache_name.clone(),
            message: "child stdin missing despite Stdio::piped()".to_string(),
        })?;
        use tokio::io::AsyncWriteExt;
        stdin
            .write_all(closure_bytes)
            .await
            .map_err(|e| AtticError::ExecFailed {
                cache: self.cache_name.clone(),
                message: format!("write to attic stdin: {}", e),
            })?;
        drop(stdin);

        let output = child
            .wait_with_output()
            .await
            .map_err(|e| AtticError::ExecFailed {
                cache: self.cache_name.clone(),
                message: format!("wait for attic push: {}", e),
            })?;

        if output.status.success() {
            Ok(())
        } else {
            Err(AtticError::ClosurePushFailed {
                cache: self.cache_name.clone(),
                exit_code: output.status.code(),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            })
        }
    }

    /// Login to Attic cache.
    ///
    /// Returns typed errors:
    /// - [`AtticError::TokenRequired`] if no token was configured (no
    ///   side effects performed).
    /// - [`AtticError::ExecFailed`] when `attic` cannot be spawned.
    /// - [`AtticError::LoginFailed`] when attic exits non-zero, carrying
    ///   cache, server URL, exit code, and captured stderr.
    ///
    /// Spawn-vs-op dispatch flows through
    /// [`crate::retry::classify_capture`] — same shape as
    /// [`Self::push`], with the op-failure closure producing
    /// `LoginFailed` (carrying `(cache, server_url, exit_code, stderr)`)
    /// instead of `PushFailed`. The token enters the call as a CLI
    /// argument, NOT as `ATTIC_TOKEN`, so no env injection happens
    /// here — preserving the discriminator the test fixture in this
    /// module pins.
    pub async fn login(&self, server_url: &str) -> Result<(), AtticError> {
        let token = self
            .token
            .as_deref()
            .ok_or_else(|| AtticError::TokenRequired {
                cache: self.cache_name.clone(),
                server_url: server_url.to_string(),
            })?;

        let attic_bin = self.resolve_attic_bin();
        let mut cmd = Command::new(&attic_bin);
        cmd.args(["login", &self.cache_name, server_url, token])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        classify_capture(
            cmd.output().await,
            |e| AtticError::ExecFailed {
                cache: self.cache_name.clone(),
                message: e.to_string(),
            },
            |cf| AtticError::LoginFailed {
                cache: self.cache_name.clone(),
                server_url: server_url.to_string(),
                exit_code: cf.exit_code,
                stderr: cf.stderr,
            },
        )?;

        Ok(())
    }

    /// Check if attic CLI is available
    pub async fn is_available() -> bool {
        let attic_bin = get_tool_path("ATTIC_BIN", "attic");
        Command::new(&attic_bin)
            .arg("--version")
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attic_client_creation() {
        let client = AtticClient::new("test-cache");
        assert_eq!(client.cache_name, "test-cache");
        assert!(client.token.is_none());
    }

    #[test]
    fn test_attic_client_with_token() {
        let client = AtticClient::new("test-cache").with_token("secret");
        assert!(client.token.is_some());
    }

    use crate::test_support::make_executable_shim;

    /// Write an executable shim script that pretends to be `attic`.
    /// Delegates to the shared
    /// `crate::test_support::make_executable_shim` so the shim
    /// discipline (absolute-path invocation, 0o755 chmod, tempdir
    /// lifetime) lives in one place — same primitive as
    /// `git.rs`'s `make_git_shim` and `nix.rs`'s `make_nix_shim`.
    fn make_attic_shim(body: &str) -> (tempfile::TempDir, String) {
        make_executable_shim("attic", body)
    }

    /// When the `attic` binary cannot be spawned, `push` must surface
    /// `ExecFailed` carrying the cache name — never a stringly anyhow
    /// "Failed to execute attic push". Pins the typed split so telemetry
    /// can distinguish "attic missing" from "attic said no". Uses an
    /// absolute path that does not exist, injected via `with_attic_bin`,
    /// so the test is hermetic and parallel-safe (no env mutation).
    #[tokio::test]
    async fn test_push_returns_exec_failed_when_attic_missing() {
        let client = AtticClient::new("cache-x")
            .with_attic_bin("/nonexistent/path/to/attic-binary-does-not-exist");
        let err = client
            .push("/nix/store/anything")
            .await
            .expect_err("missing attic must fail");
        match err {
            AtticError::ExecFailed { cache, .. } => assert_eq!(cache, "cache-x"),
            other => panic!("expected ExecFailed, got: {other:?}"),
        }
    }

    /// `push` failures must produce `PushFailed` carrying cache,
    /// store_path, attempts, exit code, and captured stderr — never a
    /// fused `bail!("Attic push failed")`. Uses a shim invoked by
    /// absolute path so the test is hermetic and parallel-safe. The
    /// `cache full` stderr is terminal under
    /// `is_transient_network_stderr`, so the retry loop short-circuits
    /// at attempt 1 — pinning that the typed `attempts` field tracks the
    /// real attempt count, not the retry budget.
    #[tokio::test]
    async fn test_push_returns_push_failed_with_structured_fields() {
        let (_dir, shim) = make_attic_shim("#!/bin/sh\necho 'cache full' 1>&2\nexit 17\n");
        let client = AtticClient::new("cache-y")
            .with_attic_bin(&shim)
            .with_retries(5);
        let err = client
            .push("/nix/store/zzz-thing")
            .await
            .expect_err("nonzero exit must fail");
        match err {
            AtticError::PushFailed {
                cache,
                store_path,
                attempts,
                exit_code,
                stderr,
            } => {
                assert_eq!(cache, "cache-y");
                assert_eq!(store_path, "/nix/store/zzz-thing");
                assert_eq!(
                    attempts, 1,
                    "terminal stderr ('cache full') must short-circuit at attempt 1 even with retries=5"
                );
                assert_eq!(exit_code, Some(17));
                assert!(
                    stderr.contains("cache full"),
                    "stderr field must capture attic stderr verbatim, got: {stderr:?}"
                );
            }
            other => panic!("expected PushFailed, got: {other:?}"),
        }
    }

    /// On the success path, `push` must complete without error.
    #[tokio::test]
    async fn test_push_success_path() {
        let (_dir, shim) = make_attic_shim("#!/bin/sh\nexit 0\n");
        let client = AtticClient::new("cache-ok").with_attic_bin(&shim);
        client
            .push("/nix/store/aaa-ok")
            .await
            .expect("success path must succeed");
    }

    /// `login` without a configured token must produce `TokenRequired`
    /// carrying the cache and server URL — and must NOT spawn attic.
    /// Pins the precondition check at the type level so callers can
    /// pattern-match the "no token" case distinctly from a network
    /// failure.
    #[tokio::test]
    async fn test_login_token_required_carries_cache_and_server() {
        let client = AtticClient::new("cache-z");
        let err = client
            .login("https://attic.example.com")
            .await
            .expect_err("missing token must fail");
        match err {
            AtticError::TokenRequired { cache, server_url } => {
                assert_eq!(cache, "cache-z");
                assert_eq!(server_url, "https://attic.example.com");
            }
            other => panic!("expected TokenRequired, got: {other:?}"),
        }
    }

    /// `login` failures must produce `LoginFailed` carrying cache,
    /// server URL, exit code, and captured stderr — never a fused
    /// `bail!("Attic login failed")`.
    #[tokio::test]
    async fn test_login_returns_login_failed_with_structured_fields() {
        let (_dir, shim) = make_attic_shim("#!/bin/sh\necho 'invalid token' 1>&2\nexit 5\n");
        let client = AtticClient::new("cache-w")
            .with_token("bad-tok")
            .with_attic_bin(&shim);
        let err = client
            .login("https://attic.example.com")
            .await
            .expect_err("bad creds must fail");
        match err {
            AtticError::LoginFailed {
                cache,
                server_url,
                exit_code,
                stderr,
            } => {
                assert_eq!(cache, "cache-w");
                assert_eq!(server_url, "https://attic.example.com");
                assert_eq!(exit_code, Some(5));
                assert!(
                    stderr.contains("invalid token"),
                    "stderr field must capture attic stderr verbatim, got: {stderr:?}"
                );
            }
            other => panic!("expected LoginFailed, got: {other:?}"),
        }
    }

    /// `push_closure_via_stdin` on a spawn failure (attic binary
    /// missing) must surface [`AtticError::ExecFailed`] carrying the
    /// cache name — same shape as `push`. Pins the spawn-vs-op split
    /// at the closure-push surface so telemetry can distinguish
    /// "attic missing" from "attic said no" without parsing strings.
    #[tokio::test]
    async fn test_push_closure_via_stdin_returns_exec_failed_when_attic_missing() {
        let client = AtticClient::new("cache-closure-x")
            .with_attic_bin("/nonexistent/path/to/attic-binary-does-not-exist");
        let err = client
            .push_closure_via_stdin(b"/nix/store/aaa\n")
            .await
            .expect_err("missing attic must fail");
        match err {
            AtticError::ExecFailed { cache, .. } => {
                assert_eq!(cache, "cache-closure-x")
            }
            other => panic!("expected ExecFailed, got: {other:?}"),
        }
    }

    /// `push_closure_via_stdin` on a non-zero exit must surface
    /// [`AtticError::ClosurePushFailed`] carrying (cache, exit_code,
    /// captured stderr) — the structural-record tuple Phase 1
    /// attestation records (THEORY §V.4) consume. Pre-lift each of
    /// the three call sites (`commands/build.rs::execute` and
    /// `commands/rust_service.rs::push_rust_service` AMD64/ARM64
    /// arms) collapsed the op-failure path into a `warn!("⚠️  Failed
    /// to push closure to Attic (non-fatal)")` log line that dropped
    /// the exit code, the cache identity, AND the underlying stderr
    /// entirely. Post-lift each site recovers the typed tuple via
    /// the `Err(AtticError::ClosurePushFailed { .. })` destructure
    /// even when the call-site chooses to log the failure as
    /// non-fatal. A future regression that re-fused the fields or
    /// dropped any of them would fail this test rather than silently
    /// degrade the Phase 1 record shape.
    #[tokio::test]
    async fn test_push_closure_via_stdin_returns_closure_push_failed_with_structured_fields() {
        let (_dir, shim) =
            make_attic_shim("#!/bin/sh\necho 'cache write rejected' 1>&2\nexit 19\n");
        let client = AtticClient::new("cache-closure-y").with_attic_bin(&shim);
        let err = client
            .push_closure_via_stdin(b"/nix/store/xxx\n/nix/store/yyy\n")
            .await
            .expect_err("nonzero exit must fail");
        match err {
            AtticError::ClosurePushFailed {
                cache,
                exit_code,
                stderr,
            } => {
                assert_eq!(cache, "cache-closure-y");
                assert_eq!(exit_code, Some(19));
                assert!(
                    stderr.contains("cache write rejected"),
                    "stderr field must capture attic stderr verbatim, got: {stderr:?}"
                );
            }
            other => panic!("expected ClosurePushFailed, got: {other:?}"),
        }
    }

    /// `push_closure_via_stdin` on the success path returns `Ok(())`.
    /// Pins the success-path floor every lifted call site relies on:
    /// `build.rs::execute` (after a successful image build) and
    /// `rust_service.rs::push_rust_service` (after AMD64/ARM64
    /// closures complete) flow through this typed surface and treat
    /// `Ok(())` as the "✅ closure cached" log branch.
    #[tokio::test]
    async fn test_push_closure_via_stdin_success_path() {
        // Shim drains stdin so the parent's write_all doesn't block on
        // a full pipe buffer before the child exits.
        let (_dir, shim) = make_attic_shim("#!/bin/sh\ncat >/dev/null\nexit 0\n");
        let client = AtticClient::new("cache-closure-ok").with_attic_bin(&shim);
        client
            .push_closure_via_stdin(b"/nix/store/aaa\n")
            .await
            .expect("success path must succeed");
    }

    /// `push_closure_via_stdin` must feed `closure_bytes` to the
    /// spawned `attic` process's stdin verbatim. Pre-lift the bytes
    /// were fed via the inline `stdin.take().write_all(...).await?`
    /// stanza at each of the three call sites; the typed primitive
    /// owns the discipline now. The shim cats stdin to stderr and
    /// exits non-zero so the captured stderr in
    /// `ClosurePushFailed.stderr` round-trips the observed bytes.
    #[tokio::test]
    async fn test_push_closure_via_stdin_feeds_bytes_to_attic_stdin() {
        let (_dir, shim) = make_attic_shim("#!/bin/sh\ncat 1>&2\nexit 23\n");
        let client = AtticClient::new("cache-feed").with_attic_bin(&shim);
        let err = client
            .push_closure_via_stdin(b"/nix/store/feed-marker-zzz\n")
            .await
            .expect_err("nonzero exit must fail");
        match err {
            AtticError::ClosurePushFailed { stderr, .. } => {
                assert!(
                    stderr.contains("feed-marker-zzz"),
                    "stdin bytes must reach the spawned attic process verbatim; got stderr: {stderr:?}"
                );
            }
            other => panic!("expected ClosurePushFailed, got: {other:?}"),
        }
    }

    /// `push_closure_via_stdin` must forward `self.token` to the
    /// spawned `attic` process as the `ATTIC_TOKEN` env var — same
    /// shape as `push`. Pre-lift the three call sites relied on
    /// ambient env inheritance (`ATTIC_TOKEN` already in the parent's
    /// environment); the typed primitive supports both paths
    /// (explicit `with_token` or ambient inheritance), and this test
    /// pins the explicit path so a future drift that drops the
    /// `cmd.env("ATTIC_TOKEN", t)` line surfaces here rather than
    /// silently producing an unauthenticated closure push.
    #[tokio::test]
    async fn test_push_closure_via_stdin_forwards_token_as_attic_token_env() {
        let (_dir, shim) = make_attic_shim(
            "#!/bin/sh\ncat >/dev/null\necho \"observed-token=$ATTIC_TOKEN\" 1>&2\nexit 29\n",
        );
        let client = AtticClient::new("cache-tok-closure")
            .with_token("closure-sekrit-456")
            .with_attic_bin(&shim);
        let err = client
            .push_closure_via_stdin(b"/nix/store/anything\n")
            .await
            .expect_err("nonzero exit must fail");
        match err {
            AtticError::ClosurePushFailed { stderr, .. } => {
                assert!(
                    stderr.contains("observed-token=closure-sekrit-456"),
                    "ATTIC_TOKEN must be forwarded verbatim; got stderr: {stderr:?}"
                );
            }
            other => panic!("expected ClosurePushFailed, got: {other:?}"),
        }
    }

    /// `push_optional` must swallow typed errors into a boolean (the
    /// existing behavior) without producing panics. This pins the bridge
    /// so future refactors don't accidentally turn a non-fatal push into
    /// a fatal one.
    #[tokio::test]
    async fn test_push_optional_returns_false_on_failure() {
        let (_dir, shim) = make_attic_shim("#!/bin/sh\nexit 1\n");
        let client = AtticClient::new("cache-opt").with_attic_bin(&shim);
        let ok = client.push_optional("/nix/store/whatever").await;
        assert!(!ok, "push_optional must return false on failure");
    }

    /// `push` must forward `self.token` to the spawned `attic` process
    /// as the `ATTIC_TOKEN` env var. Pre-migration this invariant was
    /// owned by the (now-deleted) `run_attic_capture` helper; post-
    /// migration the env injection lives inline at the call site, so
    /// pinning it as a structural test guards against a future drift
    /// that drops the `cmd.env("ATTIC_TOKEN", t)` line and silently
    /// produces an unauthenticated push (which `attic` would reject
    /// with a 401 — not visibly broken in a test that doesn't assert
    /// on the token surface).
    ///
    /// Uses a shim that emits the observed `ATTIC_TOKEN` value on
    /// stderr and exits non-zero, then matches the typed
    /// `AtticError::PushFailed.stderr` against the expected token.
    /// Hermetic and parallel-safe: shim invoked by absolute path; no
    /// process-global env mutation.
    #[tokio::test]
    async fn test_push_forwards_token_as_attic_token_env() {
        let (_dir, shim) =
            make_attic_shim("#!/bin/sh\necho \"observed-token=$ATTIC_TOKEN\" 1>&2\nexit 11\n");
        let client = AtticClient::new("cache-tok")
            .with_token("sekrit-123")
            .with_attic_bin(&shim);
        let err = client
            .push("/nix/store/anything")
            .await
            .expect_err("nonzero exit must fail");
        match err {
            AtticError::PushFailed { stderr, .. } => {
                assert!(
                    stderr.contains("observed-token=sekrit-123"),
                    "ATTIC_TOKEN must be forwarded verbatim; got stderr: {stderr:?}"
                );
            }
            other => panic!("expected PushFailed, got: {other:?}"),
        }
    }

    /// `login` must NOT inject `ATTIC_TOKEN` into the spawned `attic`
    /// process — the token is supplied as a CLI argument. Pre-migration
    /// this was the discriminator between the two call sites of
    /// `run_attic_capture` (the `token: Option<&str>` parameter); post-
    /// migration `login` simply omits the `cmd.env("ATTIC_TOKEN", ...)`
    /// line. Pinning the absent-env property at the structural level
    /// guards against a future "harmonize the two call sites" refactor
    /// that adds env injection back to `login` (which would leak the
    /// real token into both the env AND the argv, broadening the
    /// attack surface for `ps`-style observation on shared hosts).
    ///
    /// The shim emits `LOGIN_SAW_TOKEN=<value>` on stderr; absent the
    /// env, the value is empty.
    #[tokio::test]
    async fn test_login_does_not_inject_attic_token_env() {
        let (_dir, shim) =
            make_attic_shim("#!/bin/sh\necho \"LOGIN_SAW_TOKEN=$ATTIC_TOKEN\" 1>&2\nexit 5\n");
        let client = AtticClient::new("cache-login")
            .with_token("must-not-leak-into-env")
            .with_attic_bin(&shim);
        let err = client
            .login("https://attic.example.com")
            .await
            .expect_err("nonzero exit must fail");
        match err {
            AtticError::LoginFailed { stderr, .. } => {
                assert!(
                    stderr.contains("LOGIN_SAW_TOKEN="),
                    "shim must observe the env var probe; got stderr: {stderr:?}"
                );
                assert!(
                    !stderr.contains("LOGIN_SAW_TOKEN=must-not-leak-into-env"),
                    "login MUST NOT forward token via ATTIC_TOKEN env; got stderr: {stderr:?}"
                );
            }
            other => panic!("expected LoginFailed, got: {other:?}"),
        }
    }

    /// `classify_attic_push_failure` dispatches a post-`retry_command`
    /// `CommandAttemptFailure` to the typed `AtticError` variant whose
    /// structural shape matches. Mirror of
    /// `infrastructure/registry.rs::test_classify_push_failure_dispatches_on_spawn_vs_op`
    /// for the attic surface. A pure unit test of the dispatch helper
    /// — no subprocess, no shim, no retry-loop driving — so the typed
    /// mapping can evolve (e.g., adding `AtticError::PushTimeout`)
    /// without subtle drift between this site and the canonical retry
    /// primitive.
    #[test]
    fn test_classify_attic_push_failure_dispatches_on_spawn_vs_op() {
        // Spawn-failure (attic not on PATH): empty stderr, exit_code
        // None, spawn-error message in stdout. Must produce
        // `AtticError::ExecFailed` — never `PushFailed` — because the
        // CLI never ran. Same discipline the four sibling typed-error
        // families (Registry, Nix, Git, Kubernetes) encode for their
        // `ExecFailed` variants.
        let spawn = CommandAttemptFailure {
            operation: "push /nix/store/abc to cache-x".to_string(),
            attempt: 1,
            exit_code: None,
            stderr: String::new(),
            stdout: "failed to spawn process: No such file or directory".to_string(),
        };
        match classify_attic_push_failure(spawn, "cache-x", "/nix/store/abc") {
            AtticError::ExecFailed { cache, message } => {
                assert_eq!(cache, "cache-x");
                assert!(
                    message.contains("No such file or directory"),
                    "spawn-error message must flow through stdout: {message}"
                );
            }
            other => panic!("expected ExecFailed, got: {other:?}"),
        }

        // Op-failure with transient stderr (HTTP 503): exit_code Some,
        // stderr populated, attempt > 1 (the typed record's attempt
        // count after the retry loop exhausted). Must produce
        // `AtticError::PushFailed` carrying the structural-record
        // tuple — cache, store_path, the typed `attempt` count,
        // exit_code, and stderr — verbatim.
        let transient = CommandAttemptFailure {
            operation: "push /nix/store/abc to cache-x".to_string(),
            attempt: 5,
            exit_code: Some(1),
            stderr: "received unexpected HTTP status: 503 Service Unavailable".to_string(),
            stdout: String::new(),
        };
        match classify_attic_push_failure(transient, "cache-x", "/nix/store/abc") {
            AtticError::PushFailed {
                cache,
                store_path,
                attempts,
                exit_code,
                stderr,
            } => {
                assert_eq!(cache, "cache-x");
                assert_eq!(store_path, "/nix/store/abc");
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
        // (that classification happens INSIDE `retry_command` to
        // decide whether to retry). By the time the helper is called,
        // the retry loop has already exhausted; the dispatch only
        // chooses between `ExecFailed` and `PushFailed` based on
        // whether the CLI actually ran.
        let terminal = CommandAttemptFailure {
            operation: "push /nix/store/abc to cache-x".to_string(),
            attempt: 1,
            exit_code: Some(1),
            stderr: "401 Unauthorized: bad token".to_string(),
            stdout: String::new(),
        };
        match classify_attic_push_failure(terminal, "cache-x", "/nix/store/abc") {
            AtticError::PushFailed {
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
    /// attic dispatch site. A spawn-failure record carries `exit_code:
    /// None` AND empty `stderr`. A non-zero-exit record with empty
    /// `stderr` (a CLI that ran, exited non-zero, and emitted nothing)
    /// is structurally distinct: it must dispatch to `PushFailed`, not
    /// `ExecFailed`, because the CLI did run. Pinning this guards
    /// against a future regression that drops the `exit_code.is_none()`
    /// half of the predicate. Mirror of
    /// `infrastructure/registry.rs::test_classify_push_failure_silent_op_failure_routes_to_push_failed`.
    #[test]
    fn test_classify_attic_push_failure_silent_op_failure_routes_to_push_failed() {
        let silent_op = CommandAttemptFailure {
            operation: "push /nix/store/abc to cache-x".to_string(),
            attempt: 2,
            exit_code: Some(125),
            stderr: String::new(),
            stdout: String::new(),
        };
        // Sanity: this is NOT a spawn failure (exit_code is Some).
        assert!(!silent_op.is_spawn_failure());
        match classify_attic_push_failure(silent_op, "cache-x", "/nix/store/abc") {
            AtticError::PushFailed {
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

    /// Transient stderr (HTTP 503) drives `retry_command` through every
    /// attempt in the retry budget. Pins:
    /// - the typed `attempts` field tracks the real attempt count
    ///   (matches `retries`, not the network policy's default 5).
    /// - the canonical `is_transient_network_stderr` classifier matches
    ///   attic-flavored 5xx markers — pre-migration the attic surface
    ///   had no retry loop at all, so a transient 5xx during a release
    ///   surfaced as a hard `PushFailed` with `attempts: 1`. Post-
    ///   migration it surfaces with `attempts: retries`, the typed
    ///   shape `RegistryError::PushFailed` already encoded for the
    ///   sibling registry surface.
    ///
    /// Uses `retries=2` so the test costs ~250ms (one delay between
    /// attempts 1 and 2 under `RetryPolicy::network()`'s 250ms initial
    /// backoff) — fast enough to run in the unit-test loop.
    #[tokio::test]
    async fn test_push_transient_stderr_exhausts_retries() {
        let (_dir, shim) = make_attic_shim(
            "#!/bin/sh\necho 'received unexpected HTTP status: 503 Service Unavailable' 1>&2\nexit 1\n",
        );
        let client = AtticClient::new("cache-503")
            .with_attic_bin(&shim)
            .with_retries(2);
        let err = client
            .push("/nix/store/transient")
            .await
            .expect_err("transient stderr must exhaust retries and fail");
        match err {
            AtticError::PushFailed {
                cache,
                store_path,
                attempts,
                exit_code,
                stderr,
            } => {
                assert_eq!(cache, "cache-503");
                assert_eq!(store_path, "/nix/store/transient");
                assert_eq!(
                    attempts, 2,
                    "transient stderr must drive the retry loop through every attempt; \
                     got attempts={attempts}, expected 2 (matches retries=2)"
                );
                assert_eq!(exit_code, Some(1));
                assert!(
                    stderr.contains("503"),
                    "stderr must capture the transient marker verbatim, got: {stderr:?}"
                );
            }
            other => panic!("expected PushFailed, got: {other:?}"),
        }
    }

    /// Terminal stderr (HTTP 401) short-circuits the retry loop at
    /// attempt 1, even with a generous retry budget. Pins that the
    /// canonical `is_transient_network_stderr` classifier returns
    /// `false` on auth failures, and that the typed `attempts` field
    /// reflects the short-circuit (1, not the retries budget). Without
    /// this pin, a future regression that broadens the transient
    /// classifier to match `Unauthorized` would silently turn every
    /// auth failure into a five-attempt retry storm against the cache
    /// backend — visible only in elapsed-time telemetry, not in the
    /// typed-error surface.
    #[tokio::test]
    async fn test_push_terminal_stderr_short_circuits_at_attempt_1() {
        let (_dir, shim) =
            make_attic_shim("#!/bin/sh\necho '401 Unauthorized: bad token' 1>&2\nexit 1\n");
        let client = AtticClient::new("cache-401")
            .with_attic_bin(&shim)
            .with_retries(5);
        let err = client
            .push("/nix/store/auth-fail")
            .await
            .expect_err("terminal stderr must short-circuit");
        match err {
            AtticError::PushFailed {
                attempts, stderr, ..
            } => {
                assert_eq!(
                    attempts, 1,
                    "terminal stderr ('401 Unauthorized') must short-circuit at attempt 1 \
                     even with retries=5; got attempts={attempts}"
                );
                assert!(stderr.contains("401"));
            }
            other => panic!("expected PushFailed, got: {other:?}"),
        }
    }

    /// `push_with_retries(_, 0)` must clamp to `>= 1` (one attempt) via
    /// `RetryPolicy::new`'s clamping discipline — never silently turn
    /// the loop into a no-op that succeeds without ever spawning the
    /// CLI. Pins the load-bearing invariant at the public-API
    /// boundary: a degenerate retries=0 input from a future caller
    /// must produce a real attempt, not a synthesized success.
    #[tokio::test]
    async fn test_push_with_retries_zero_clamps_to_one_attempt() {
        let (_dir, shim) = make_attic_shim("#!/bin/sh\necho 'fail' 1>&2\nexit 1\n");
        let client = AtticClient::new("cache-zero").with_attic_bin(&shim);
        let err = client
            .push_with_retries("/nix/store/x", 0)
            .await
            .expect_err("retries=0 must still drive at least one attempt that fails");
        match err {
            AtticError::PushFailed { attempts, .. } => {
                assert_eq!(
                    attempts, 1,
                    "retries=0 must clamp to >= 1; got attempts={attempts}"
                );
            }
            other => panic!("expected PushFailed, got: {other:?}"),
        }
    }
}
