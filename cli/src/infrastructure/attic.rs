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
use crate::retry::CapturedFailure;

/// Spawn `attic` with the given args, capture stderr, and return the
/// non-success outcome as a typed [`CapturedFailure`]. Returns `None` on
/// success.
///
/// Spawn failures (the `attic` binary cannot be executed at all) surface
/// as `AtticError::ExecFailed` carrying `cache` so callers can
/// distinguish "attic missing" from "attic said no" without parsing
/// strings. The `(exit_code, stderr)` extraction discipline lives in
/// [`CapturedFailure`] so this site cannot drift on UTF-8-lossy decode
/// or trim — same canonical extraction the typed-error producer sites
/// in `git.rs`, `nix.rs`, and `infrastructure/registry.rs` consume.
async fn run_attic_capture(
    attic_bin: &str,
    args: &[&str],
    cache: &str,
    token: Option<&str>,
) -> Result<Option<CapturedFailure>, AtticError> {
    let mut cmd = Command::new(attic_bin);
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    if let Some(t) = token {
        cmd.env("ATTIC_TOKEN", t);
    }

    let output = cmd.output().await.map_err(|e| AtticError::ExecFailed {
        cache: cache.to_string(),
        message: e.to_string(),
    })?;

    Ok(CapturedFailure::from_output_if_failed(&output))
}

/// Client for Attic cache operations
pub struct AtticClient {
    cache_name: String,
    token: Option<String>,
    attic_bin: Option<String>,
}

impl AtticClient {
    /// Create a new Attic client
    pub fn new(cache_name: impl Into<String>) -> Self {
        Self {
            cache_name: cache_name.into(),
            token: None,
            attic_bin: None,
        }
    }

    /// Set authentication token
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
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

    /// Push a store path to the cache.
    ///
    /// Returns typed errors:
    /// - [`AtticError::ExecFailed`] when `attic` cannot be spawned.
    /// - [`AtticError::PushFailed`] when attic exits non-zero, carrying
    ///   the offending cache, store path, exit code, and captured stderr.
    pub async fn push(&self, store_path: &str) -> Result<(), AtticError> {
        info!("Pushing to Attic cache: {}", self.cache_name);

        let attic_bin = self.resolve_attic_bin();
        let outcome = run_attic_capture(
            &attic_bin,
            &["push", &self.cache_name, store_path],
            &self.cache_name,
            self.token.as_deref(),
        )
        .await?;

        if let Some(cf) = outcome {
            return Err(AtticError::PushFailed {
                cache: self.cache_name.clone(),
                store_path: store_path.to_string(),
                exit_code: cf.exit_code,
                stderr: cf.stderr,
            });
        }

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

    /// Login to Attic cache.
    ///
    /// Returns typed errors:
    /// - [`AtticError::TokenRequired`] if no token was configured (no
    ///   side effects performed).
    /// - [`AtticError::ExecFailed`] when `attic` cannot be spawned.
    /// - [`AtticError::LoginFailed`] when attic exits non-zero, carrying
    ///   cache, server URL, exit code, and captured stderr.
    pub async fn login(&self, server_url: &str) -> Result<(), AtticError> {
        let token = self
            .token
            .as_deref()
            .ok_or_else(|| AtticError::TokenRequired {
                cache: self.cache_name.clone(),
                server_url: server_url.to_string(),
            })?;

        let attic_bin = self.resolve_attic_bin();
        let outcome = run_attic_capture(
            &attic_bin,
            &["login", &self.cache_name, server_url, token],
            &self.cache_name,
            None,
        )
        .await?;

        if let Some(cf) = outcome {
            return Err(AtticError::LoginFailed {
                cache: self.cache_name.clone(),
                server_url: server_url.to_string(),
                exit_code: cf.exit_code,
                stderr: cf.stderr,
            });
        }

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

    /// Write an executable shim script that pretends to be `attic`. The
    /// returned tempdir keeps the shim alive until the caller drops it.
    /// Tests invoke the shim by absolute path (via `ATTIC_BIN`) so they
    /// don't have to mutate global PATH (which races under parallel test
    /// execution).
    fn make_attic_shim(body: &str) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().expect("tempdir");
        let shim = dir.path().join("attic");
        std::fs::write(&shim, body).expect("write shim");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&shim).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&shim, perms).unwrap();
        }
        let path = shim.display().to_string();
        (dir, path)
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
    /// store_path, exit code, and captured stderr — never a fused
    /// `bail!("Attic push failed")`. Uses a shim invoked by absolute
    /// path so the test is hermetic and parallel-safe.
    #[tokio::test]
    async fn test_push_returns_push_failed_with_structured_fields() {
        let (_dir, shim) = make_attic_shim("#!/bin/sh\necho 'cache full' 1>&2\nexit 17\n");
        let client = AtticClient::new("cache-y").with_attic_bin(&shim);
        let err = client
            .push("/nix/store/zzz-thing")
            .await
            .expect_err("nonzero exit must fail");
        match err {
            AtticError::PushFailed {
                cache,
                store_path,
                exit_code,
                stderr,
            } => {
                assert_eq!(cache, "cache-y");
                assert_eq!(store_path, "/nix/store/zzz-thing");
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
}
