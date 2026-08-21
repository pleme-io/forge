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
    classify_attempt_failure, classify_capture, retry_command_logged, CommandAttemptFailure,
    RetryPolicy,
};

/// Module-scoped sigil: resolve the `attic` binary via the canonical
/// two-argument `get_tool_path("ATTIC_BIN", "attic")` call. Every
/// production site in `infrastructure/attic.rs` that needs the
/// resolved binary path (with no `with_attic_bin` test override in
/// play) routes through this sigil, so the substrate-exported
/// `ATTIC_BIN` env-var contract is honored at exactly ONE code line
/// in the module regardless of whether the caller has `&self` (the
/// `resolve_attic_bin` fallback) or not (the static `is_available`
/// probe).
///
/// Pre-lift the module carried two respells of the two-argument
/// resolve — one in [`AtticClient::resolve_attic_bin`]'s fallback
/// branch, one in [`AtticClient::is_available`]'s inline probe.
/// Post-lift both consumers route through this sigil, so a future
/// widening of the resolve contract (e.g., a substrate-path
/// validation step, a per-spawn env-injection hook, or a telemetry
/// sigil on the resolved path) lands at ONE body and cannot silently
/// degrade one site's resolution without the other noticing.
///
/// Sibling of the `<tool>_bin()` sigils landed on the CARGO surface
/// across `commands/{test_ci,prerelease,developer_tools,tool,e2e,
/// comprehensive_release}.rs`, the NIX_BIN surface across
/// `commands/{build,developer_tools,rust_service,nix_builder,e2e,
/// tool}.rs`, and the DOCKER_BIN / BUN_BIN / CRATE2NIX surfaces —
/// the same per-module single-point-of-truth discipline applied to
/// the ATTIC surface here. THEORY §I.5 (Generation over composition,
/// duplication budget zero) and §VI.1 (three-times rule).
fn attic_bin() -> String {
    get_tool_path("ATTIC_BIN", "attic")
}

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
        |spawn| AtticError::exec_failed(cache, spawn.stdout),
        |op| AtticError::PushFailed {
            cache: cache.to_string(),
            store_path: store_path.to_string(),
            attempts: op.attempt,
            exit_code: op.exit_code,
            stderr: op.stderr,
        },
    )
}

/// Sibling of [`classify_attic_push_failure`] on the login surface.
/// Dispatches a post-`retry_command` `CommandAttemptFailure` to the
/// typed [`AtticError`] variant whose structural shape matches the
/// captured failure: spawn-failure (attic not on PATH) routes to
/// [`AtticError::ExecFailed`] carrying the cache name and the
/// spawn-error message; non-zero exit routes to
/// [`AtticError::LoginFailed`] carrying `(cache, server_url,
/// exit_code, stderr)` — the structural-record tuple Phase 1
/// attestation records (THEORY §V.4) consume on the login step,
/// symmetric to the push-step tuple `PushFailed` carries.
///
/// Drives the canonical [`classify_attempt_failure`] primitive —
/// same helper `classify_attic_push_failure` and
/// `infrastructure/registry.rs::classify_push_failure` consume — so
/// the `is_spawn_failure` discriminator lives in one place across
/// every retry-driven typed-error producer in forge. Adding a third
/// retry-driven attic subcommand (e.g., a future `attic gc` with a
/// network-transient stderr surface) reuses this dispatch shape
/// without retyping the ExecFailed / op-variant split.
fn classify_attic_login_failure(
    failure: CommandAttemptFailure,
    cache: &str,
    server_url: &str,
) -> AtticError {
    classify_attempt_failure(
        failure,
        |spawn| AtticError::exec_failed(cache, spawn.stdout),
        |op| AtticError::LoginFailed {
            cache: cache.to_string(),
            server_url: server_url.to_string(),
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
        self.attic_bin.clone().unwrap_or_else(attic_bin)
    }

    /// Build a fresh `tokio::process::Command` targeting the resolved
    /// `attic` binary. Callers chain `.args(...)` / `.stdin(...)` /
    /// `.stdout(...)` / `.stderr(...)` / `.env(...)` to compose the
    /// operation-specific spawn shape.
    ///
    /// # Why this primitive
    ///
    /// Three `&self` methods on `AtticClient` —
    /// [`Self::push_closure_via_stdin`], [`Self::login`], and
    /// [`Self::use_cache`] — each spelled the identical two-line
    /// preamble verbatim:
    ///
    /// ```text
    /// let attic_bin = self.resolve_attic_bin();
    /// let mut cmd = Command::new(&attic_bin);
    /// ```
    ///
    /// Three occurrences is THEORY §VI.1's three-is-a-law threshold
    /// ("two occurrences is a coincidence; three is a law"); this
    /// primitive is the law-redeeming consolidation, symmetric to the
    /// just-landed [`crate::infrastructure::git::GitClient::command`]
    /// carve-out on the sibling `git` client (commit b388f85). The
    /// binary-resolution lives at ONE body and each consumer method
    /// composes only its own argv + stdio wiring.
    ///
    /// # Why the two retry-driven consumers keep the local capture
    ///
    /// [`Self::push_with_retries`] and [`Self::login_with_retries`]
    /// drive [`crate::retry::retry_command`] with an `FnMut(u32) ->
    /// impl Future` closure whose returned future must be `'static`;
    /// `&self` cannot cross the `async move` boundary, so each retry
    /// site clones the resolved binary into a `String` outside the
    /// closure and re-spawns `Command::new(&attic_bin)` inside the
    /// async block. Those two sites therefore keep the local-capture
    /// shape while the three direct-`&self` consumers migrate onto
    /// this helper — the same shape asymmetry the sibling GitClient
    /// carve-out (b388f85) landed with (all six GitClient methods are
    /// direct-`&self`; GitClient has no retry-driven consumers).
    ///
    /// # What compounds
    ///
    /// A future edit that widens [`Self::resolve_attic_bin`] (e.g., a
    /// per-spawn env-injection hook, a substrate-path validation step,
    /// or a telemetry sigil on the resolved path) lands at ONE
    /// direct-`&self` caller instead of three — silently degrading one
    /// site's resolution without the other two noticing is impossible
    /// post-lift. The end-to-end `ATTIC_BIN`-routing contract is
    /// unchanged: the resolved binary and its `with_attic_bin` test
    /// override still travel through this helper unchanged.
    fn command(&self) -> Command {
        Command::new(self.resolve_attic_bin())
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
        let attic_bin = self.resolve_attic_bin();
        let cache = self.cache_name.clone();
        let token = self.token.clone();
        let op = format!("push {} to {}", store_path, cache);

        let result = retry_command_logged(&policy, &op, |_attempt| {
            let attic_bin = attic_bin.clone();
            let cache = cache.clone();
            let token = token.clone();
            async move {
                let mut cmd = Command::new(&attic_bin);
                cmd.args(["push", &cache, store_path])
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                if let Some(t) = token.as_deref() {
                    cmd.env("ATTIC_TOKEN", t);
                }
                cmd.output().await
            }
        })
        .await;

        result.map(|_| ()).map_err(|failure| {
            classify_attic_push_failure(failure, &self.cache_name, store_path)
        })?;

        info!("Successfully pushed to Attic cache");
        Ok(())
    }

    /// Push a store path, ignoring failures (non-fatal). Wraps
    /// [`Self::push`] so the wrapped body inherits the `ATTIC_BIN` env
    /// resolution, the [`RetryPolicy::network`] schedule (250ms ×
    /// factor=2 capped at 30s, canonical frontier shape), and the typed
    /// [`AtticError`] dispatch — a caller that wants the non-fatal
    /// contract but the load-bearing wrapping (retry + typed error +
    /// env override) can compose the three by calling this method
    /// directly instead of hand-rolling
    /// `Command::new("attic").args(["push", cache, path]).status()`
    /// (which drops all three).
    ///
    /// The [`warn!`] on the failure arm carries the typed error, so a
    /// downstream reader sees the offending `AtticError` variant
    /// (`ExecFailed` vs `PushFailed`) — not just a bare
    /// "push failed" line.
    ///
    /// # Consumers
    ///
    /// Canonical non-fatal attic-push primitive. Consumed by
    /// `commands/push.rs::execute` for the `--push-attic` code path (a
    /// pre-migration `Command::new("attic").args(["push", cache, path])
    /// .status()` inline body that bypassed all three load-bearing
    /// properties this wrapper carries). Future non-fatal attic-push
    /// call sites should compose through this method rather than
    /// spawning `attic` directly.
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
        let mut cmd = self.command();
        cmd.args(["push", &self.cache_name, "--stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(t) = self.token.as_deref() {
            cmd.env("ATTIC_TOKEN", t);
        }

        let mut child = cmd
            .spawn()
            .map_err(|e| AtticError::exec_failed(&self.cache_name, e.to_string()))?;

        // Stdio::piped() guarantees child.stdin is Some; the `take`
        // returning None case is structurally impossible. We map it to
        // ExecFailed so the typed surface is total.
        let mut stdin = child.stdin.take().ok_or_else(|| {
            AtticError::exec_failed(
                &self.cache_name,
                "child stdin missing despite Stdio::piped()",
            )
        })?;
        use tokio::io::AsyncWriteExt;
        stdin.write_all(closure_bytes).await.map_err(|e| {
            AtticError::exec_failed(&self.cache_name, format!("write to attic stdin: {}", e))
        })?;
        drop(stdin);

        let output = child.wait_with_output().await.map_err(|e| {
            AtticError::exec_failed(&self.cache_name, format!("wait for attic push: {}", e))
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

        let mut cmd = self.command();
        cmd.args(["login", &self.cache_name, server_url, token])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        classify_capture(
            cmd.output().await,
            |e| AtticError::exec_failed(&self.cache_name, e.to_string()),
            |cf| AtticError::LoginFailed {
                cache: self.cache_name.clone(),
                server_url: server_url.to_string(),
                exit_code: cf.exit_code,
                stderr: cf.stderr,
            },
        )?;

        Ok(())
    }

    /// Login to Attic cache, ignoring failures (non-fatal). Sibling of
    /// [`Self::push_optional`] on the login surface — wraps [`Self::login`]
    /// so the wrapped body inherits the `ATTIC_BIN` env resolution
    /// (`get_tool_path("ATTIC_BIN", "attic")` at
    /// [`Self::resolve_attic_bin`]) and the typed [`AtticError`] dispatch
    /// (`ExecFailed` / `LoginFailed` / `TokenRequired`) — a caller that
    /// wants the non-fatal contract but the load-bearing wrapping (env
    /// override + typed error) can compose the two by calling this method
    /// directly instead of hand-rolling
    /// `Command::new("attic").args(["login", server, url, token]).status()`
    /// (which drops both).
    ///
    /// The [`warn!`] on the failure arm carries the typed error, so a
    /// downstream reader sees the offending `AtticError` variant
    /// (`ExecFailed` vs `LoginFailed` vs `TokenRequired`) — not just a
    /// bare "login failed" line, and not silent as the pre-migration
    /// `Stdio::null()` + un-checked exit body was.
    ///
    /// # Consumers
    ///
    /// Canonical non-fatal attic-login primitive. Consumed by
    /// `commands/build.rs::execute` for the pre-Nix-build cache
    /// configuration step (a pre-migration
    /// `Command::new("attic").args(["login", server, url, token])
    /// .stdout(null).stderr(null).status()` inline body that bypassed
    /// both load-bearing properties this wrapper carries). Future
    /// non-fatal attic-login call sites should compose through this
    /// method rather than spawning `attic` directly.
    pub async fn login_optional(&self, server_url: &str) -> bool {
        match self.login(server_url).await {
            Ok(()) => {
                info!("Logged in to Attic cache: {}", self.cache_name);
                true
            }
            Err(e) => {
                warn!("Failed to login to Attic cache (non-fatal): {}", e);
                false
            }
        }
    }

    /// Login with an explicit retry budget on transient network
    /// failures. Sibling of [`Self::push_with_retries`] on the login
    /// surface — same [`RetryPolicy::network_with_max_attempts`]
    /// schedule (250ms × factor=2 capped at 30s, canonical
    /// Bazel/Buck2/SLSA network shape), same
    /// `is_transient_network_stderr` classifier, same
    /// [`classify_attempt_failure`] dispatch — so a future addition
    /// to the transient-marker set (e.g. an attic-server-flavored
    /// 5xx shape) lights up retries on both surfaces in the same
    /// commit. Pre-migration the retry loop over the login step
    /// lived in `commands/github_runner_ci.rs::attic_command_with_retry`
    /// as a stringly `args: &[&str]` wrapper that produced only
    /// untyped `anyhow::Error`; migration onto this primitive lands
    /// the typed [`AtticError::LoginFailed`] / [`AtticError::ExecFailed`]
    /// split and lets the helper be retired entirely (it was the
    /// last remaining call site).
    ///
    /// The retry budget is clamped to `>= 1` by
    /// [`RetryPolicy::new`], so a degenerate `0` cannot silently
    /// turn the loop into a no-op that reports success without ever
    /// spawning the CLI. The token enters the call as a CLI
    /// argument, NOT as `ATTIC_TOKEN`, preserving the discriminator
    /// sibling [`Self::login`] pins — `ps`-style observation on
    /// shared hosts sees the same argv shape both single-shot and
    /// retry-driven login paths produce.
    ///
    /// Returns typed errors:
    /// - [`AtticError::TokenRequired`] if no token was configured
    ///   (no side effects, no retry — the token check runs
    ///   pre-loop).
    /// - [`AtticError::ExecFailed`] when `attic` cannot be spawned.
    /// - [`AtticError::LoginFailed`] when attic exhausts the retry
    ///   budget or fails terminally, carrying the offending cache,
    ///   server URL, final attempt count's exit code, and captured
    ///   stderr — the structural-record tuple Phase 1 attestation
    ///   records (THEORY §V.4) consume.
    pub async fn login_with_retries(
        &self,
        server_url: &str,
        retries: u32,
    ) -> Result<(), AtticError> {
        let token = self
            .token
            .as_deref()
            .ok_or_else(|| AtticError::TokenRequired {
                cache: self.cache_name.clone(),
                server_url: server_url.to_string(),
            })?;

        info!("Logging in to Attic cache: {}", self.cache_name);

        let policy = RetryPolicy::network_with_max_attempts(retries);
        let attic_bin = self.resolve_attic_bin();
        let cache = self.cache_name.clone();
        let server_url_owned = server_url.to_string();
        let token_owned = token.to_string();
        let op = format!("login to Attic cache {}", cache);

        let result = retry_command_logged(&policy, &op, |_attempt| {
            let attic_bin = attic_bin.clone();
            let cache = cache.clone();
            let server_url_owned = server_url_owned.clone();
            let token_owned = token_owned.clone();
            async move {
                let mut cmd = Command::new(&attic_bin);
                cmd.args(["login", &cache, &server_url_owned, &token_owned])
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                cmd.output().await
            }
        })
        .await;

        result.map(|_| ()).map_err(|failure| {
            classify_attic_login_failure(failure, &self.cache_name, server_url)
        })?;

        Ok(())
    }

    /// Select `<server>:<cache_name>` as the active Attic cache for
    /// subsequent commands (`attic use <server>:<cache_name>`).
    ///
    /// Post-login sibling of [`Self::login`]: after `login` seeds the
    /// server token in the local attic config, `use_cache` selects the
    /// server-scoped cache reference as the current one so subsequent
    /// `attic push` / `nix build --substituters` calls route through
    /// it. The cache identity comes from `self.cache_name`; the server
    /// alias arrives as `server`. The ref is joined here (not by the
    /// caller) so a future change to the ref shape — e.g. an attic
    /// upgrade that adds a shard qualifier — lands in one place.
    ///
    /// Spawn-vs-op dispatch flows through
    /// [`crate::retry::classify_capture`] — same shape as
    /// [`Self::login`], with the op-failure closure producing
    /// [`AtticError::UseFailed`] carrying `(cache, server, exit_code,
    /// stderr)` — the structural-record tuple Phase 1 attestation
    /// records (THEORY §V.4) consume. The `attic use` subcommand does
    /// not consume a token (auth is already seeded by the prior
    /// `login`), so no `ATTIC_TOKEN` env injection happens here —
    /// mirroring the token-passing discipline `login` established.
    ///
    /// Returns typed errors:
    /// - [`AtticError::ExecFailed`] when `attic` cannot be spawned.
    /// - [`AtticError::UseFailed`] when attic exits non-zero, carrying
    ///   cache, server alias, exit code, and captured stderr.
    ///
    /// # Consumers
    ///
    /// Canonical `attic use` primitive. Consumed by
    /// `commands/build.rs::execute` for the post-login cache selection
    /// step (a pre-migration `Command::new("attic").args(&["use",
    /// &format!("{server}:{cache}")]).stdout(Stdio::null()).stderr(
    /// Stdio::null()).status()` inline body that bypassed both
    /// load-bearing properties this wrapper carries: `ATTIC_BIN` env
    /// resolution via [`Self::resolve_attic_bin`], and typed-error
    /// dispatch — a spawn failure vs. a non-zero exit landed as an
    /// untyped `Result<ExitStatus>` and `Stdio::null()` hid the
    /// stderr entirely, so a "wrong cache alias" error surfaced only
    /// as a mysterious substituter-fetch failure from the next `nix
    /// build`). Future `attic use` call sites (e.g.
    /// `commands/github_runner_ci.rs::execute` — currently routes
    /// through the domain-agnostic `attic_command_with_retry`) should
    /// compose through this method rather than spawning `attic use`
    /// directly.
    pub async fn use_cache(&self, server: &str) -> Result<(), AtticError> {
        let cache_ref = format!("{}:{}", server, self.cache_name);
        let mut cmd = self.command();
        cmd.args(["use", &cache_ref])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        classify_capture(
            cmd.output().await,
            |e| AtticError::exec_failed(&self.cache_name, e.to_string()),
            |cf| AtticError::UseFailed {
                cache: self.cache_name.clone(),
                server: server.to_string(),
                exit_code: cf.exit_code,
                stderr: cf.stderr,
            },
        )?;

        info!(
            "Selected active Attic cache: {}:{}",
            server, self.cache_name
        );
        Ok(())
    }

    /// Check if attic CLI is available
    pub async fn is_available() -> bool {
        Command::new(attic_bin())
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

    /// Regression shield: no production site in this module constructs
    /// [`AtticError::ExecFailed`] via the struct literal
    /// `AtticError::ExecFailed { cache: ..., message: ... }`. Every
    /// spawn / io-failure arm must route through the
    /// [`AtticError::exec_failed`] typed factory
    /// (`cli/src/error.rs`) so the "cache + message" tuple is
    /// constructed at exactly one call shape across the eight sites
    /// this module previously carried:
    ///
    /// - `classify_attic_push_failure` and `classify_attic_login_failure`
    ///   spawn arms of [`crate::retry::classify_attempt_failure`]
    /// - `AtticClient::push_closure_via_stdin` — four sites across
    ///   `Command::spawn`, `child.stdin.take`, `AsyncWriteExt::write_all`,
    ///   and `child.wait_with_output`
    /// - `AtticClient::login` and `AtticClient::use_cache` spawn arms
    ///   of [`crate::retry::classify_capture`]
    ///
    /// Structural, not behavioral — reads this module's own source
    /// via `include_str!` and inspects the production body slice
    /// (bounded above by the enum-consumer preamble, below by the
    /// `\n#[cfg(test)]` tests-module marker) so the shield's own
    /// docstring — which legitimately spells the pre-migration
    /// `AtticError::ExecFailed {` literal for context — is excluded
    /// from the scan. A future regression that re-introduces the
    /// struct literal — even without changing observable behavior —
    /// fails this test rather than silently drifting a call site off
    /// the typed factory (which would leave a future extension to the
    /// variant's field list stranded at the drifted site).
    ///
    /// Sibling of the shield family in
    /// `commands/github_runner_ci.rs` (`test_execute_routes_attic_*_through_attic_client_not_helper`)
    /// — same `include_str!`-plus-slice-boundary technique, applied
    /// on the typed-error construction surface here instead of the
    /// stringly-helper call surface there. THEORY §VI.1 (three-times
    /// rule / duplication budget) redeemed by the factory; this
    /// shield keeps it redeemed.
    #[test]
    fn test_no_bare_attic_error_exec_failed_literal_in_production_body() {
        let source = include_str!("attic.rs");
        // Bound the search at the `\n#[cfg(test)]` tests-module marker
        // so this test's own docstring (which spells the pre-migration
        // literal for context) is excluded from the production-body
        // scan — same boundary technique the sibling
        // `test_execute_routes_attic_*_through_attic_client_not_helper`
        // shields in `commands/github_runner_ci.rs` use.
        let tests_marker = "\n#[cfg(test)]";
        let tests_start = source
            .find(tests_marker)
            .expect("attic.rs must contain a `#[cfg(test)]` tests-module marker");
        let production_body = &source[..tests_start];

        // The load-bearing marker: `AtticError::ExecFailed {` — the
        // struct-literal opener the eight migrated sites previously
        // carried verbatim. Post-migration every production site
        // routes through `AtticError::exec_failed(cache, message)`
        // instead, which never spells the `{` opener.
        let literal_marker = "AtticError::ExecFailed {";
        assert!(
            !production_body.contains(literal_marker),
            "no production site in `infrastructure/attic.rs` may construct \
             `AtticError::ExecFailed {{ cache: ..., message: ... }}` via the \
             struct literal — route it through the typed factory \
             `crate::error::AtticError::exec_failed(cache, message)` instead. \
             A future extension to the `ExecFailed` variant's field list \
             (e.g. an `operation` context field) must land in the factory \
             once, not at each drifted call site."
        );

        // Positive form: the migration is present. Pins that a future
        // regression that strips the factory calls entirely (leaving
        // the ExecFailed construction to some other surface) fails
        // this test rather than silently un-migrating.
        assert!(
            production_body.contains("AtticError::exec_failed("),
            "the typed factory `AtticError::exec_failed(...)` must be the \
             sole construction surface for `ExecFailed` in this module — \
             the call was not found in the production body."
        );
    }

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

    /// `login_with_retries` on the spawn-failure path (attic binary
    /// missing) must surface [`AtticError::ExecFailed`] carrying the
    /// cache name — same shape as `push` and `push_with_retries` on
    /// their spawn-failure paths. Pins the spawn-vs-op split on the
    /// retry-driven login surface at the type level so telemetry can
    /// distinguish "attic missing" from "attic said no" without
    /// parsing strings. Uses an absolute path that does not exist,
    /// injected via `with_attic_bin`, so the test is hermetic and
    /// parallel-safe (no env mutation).
    #[tokio::test]
    async fn test_login_with_retries_returns_exec_failed_when_attic_missing() {
        let client = AtticClient::new("cache-login-retry-x")
            .with_token("any-tok")
            .with_attic_bin("/nonexistent/path/to/attic-binary-does-not-exist");
        let err = client
            .login_with_retries("https://attic.example.com", 3)
            .await
            .expect_err("missing attic must fail");
        match err {
            AtticError::ExecFailed { cache, .. } => {
                assert_eq!(cache, "cache-login-retry-x");
            }
            other => panic!("expected ExecFailed, got: {other:?}"),
        }
    }

    /// `login_with_retries` failures must produce
    /// [`AtticError::LoginFailed`] carrying cache, server URL, exit
    /// code, and captured stderr — never a fused
    /// `bail!("Attic login failed")` and never the pre-migration
    /// stringly `anyhow::anyhow!("{}", e)` the domain-agnostic
    /// `attic_command_with_retry` helper produced. Terminal stderr
    /// ('invalid token') short-circuits the retry loop at attempt 1,
    /// pinning that `is_transient_network_stderr` returns `false` on
    /// auth failures at the login surface (same discipline as
    /// `test_push_terminal_stderr_short_circuits_at_attempt_1`).
    #[tokio::test]
    async fn test_login_with_retries_returns_login_failed_with_structured_fields() {
        let (_dir, shim) = make_attic_shim("#!/bin/sh\necho 'invalid token' 1>&2\nexit 5\n");
        let client = AtticClient::new("cache-login-retry-y")
            .with_token("bad-tok")
            .with_attic_bin(&shim);
        let err = client
            .login_with_retries("https://attic.example.com", 5)
            .await
            .expect_err("bad creds must fail");
        match err {
            AtticError::LoginFailed {
                cache,
                server_url,
                exit_code,
                stderr,
            } => {
                assert_eq!(cache, "cache-login-retry-y");
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

    /// `login_with_retries` on the success path must return `Ok(())`
    /// after one attempt — pinning the affirmative floor
    /// `commands/github_runner_ci.rs::execute` (the retired
    /// `attic_command_with_retry` helper's last remaining call site)
    /// relies on before the subsequent `use_cache` and Nix-build
    /// steps.
    #[tokio::test]
    async fn test_login_with_retries_success_path() {
        let (_dir, shim) = make_attic_shim("#!/bin/sh\nexit 0\n");
        let client = AtticClient::new("cache-login-retry-ok")
            .with_token("good-tok")
            .with_attic_bin(&shim);
        client
            .login_with_retries("https://attic.example.com", 3)
            .await
            .expect("success path must succeed");
    }

    /// `login_with_retries` without a configured token must produce
    /// [`AtticError::TokenRequired`] AND must NOT spawn attic — the
    /// token check runs pre-loop, so a retry budget of any size
    /// cannot silently burn cycles on a call that is doomed by
    /// construction. Sibling of
    /// [`test_login_token_required_carries_cache_and_server`] on the
    /// single-shot surface; the two together pin the third
    /// error-variant arm across both login paths.
    #[tokio::test]
    async fn test_login_with_retries_token_required_carries_cache_and_server() {
        let client = AtticClient::new("cache-login-retry-notoken");
        let err = client
            .login_with_retries("https://attic.example.com", 5)
            .await
            .expect_err("missing token must fail");
        match err {
            AtticError::TokenRequired { cache, server_url } => {
                assert_eq!(cache, "cache-login-retry-notoken");
                assert_eq!(server_url, "https://attic.example.com");
            }
            other => panic!("expected TokenRequired, got: {other:?}"),
        }
    }

    /// Transient stderr (HTTP 503) drives `retry_command` through
    /// every attempt in the retry budget on the login surface. Pins
    /// the `attempts` symmetry with the push surface — pre-migration
    /// the login step's retry loop was driven by
    /// `commands/github_runner_ci.rs::attic_command_with_retry` with
    /// the canonical `RetryPolicy::network` schedule; post-migration
    /// the loop is driven by [`Self::login_with_retries`] with the
    /// same `is_transient_network_stderr` classifier and the same
    /// exponential schedule. A future regression that narrows the
    /// classifier on the login surface would fail here (attempts=1
    /// instead of retries=2).
    ///
    /// Uses `retries=2` so the test costs ~250ms (one delay between
    /// attempts 1 and 2 under `RetryPolicy::network`'s 250ms initial
    /// backoff) — fast enough for the unit-test loop. The
    /// `LoginFailed.exit_code` reflects the shim's exit and the
    /// `stderr` field captures the 503 verbatim.
    #[tokio::test]
    async fn test_login_with_retries_transient_stderr_exhausts_retries() {
        let (_dir, shim) = make_attic_shim(
            "#!/bin/sh\necho 'received unexpected HTTP status: 503 Service Unavailable' 1>&2\nexit 1\n",
        );
        let client = AtticClient::new("cache-login-503")
            .with_token("any-tok")
            .with_attic_bin(&shim);
        let err = client
            .login_with_retries("https://attic.example.com", 2)
            .await
            .expect_err("transient stderr must exhaust retries and fail");
        match err {
            AtticError::LoginFailed {
                cache,
                server_url,
                exit_code,
                stderr,
            } => {
                assert_eq!(cache, "cache-login-503");
                assert_eq!(server_url, "https://attic.example.com");
                assert_eq!(exit_code, Some(1));
                assert!(
                    stderr.contains("503"),
                    "stderr must capture the transient marker verbatim, got: {stderr:?}"
                );
            }
            other => panic!("expected LoginFailed, got: {other:?}"),
        }
    }

    /// `login_with_retries(_, 0)` must clamp to `>= 1` (one attempt)
    /// via [`RetryPolicy::new`]'s clamping discipline — never
    /// silently turn the loop into a no-op that succeeds without
    /// ever spawning the CLI. Sibling of
    /// [`test_push_with_retries_zero_clamps_to_one_attempt`] on the
    /// login surface; the two together pin the public-API boundary
    /// against a degenerate `retries=0` from a future caller
    /// producing a synthesized success.
    #[tokio::test]
    async fn test_login_with_retries_zero_clamps_to_one_attempt() {
        let (_dir, shim) = make_attic_shim("#!/bin/sh\necho 'fail' 1>&2\nexit 1\n");
        let client = AtticClient::new("cache-login-zero")
            .with_token("any-tok")
            .with_attic_bin(&shim);
        let err = client
            .login_with_retries("https://attic.example.com", 0)
            .await
            .expect_err("retries=0 must still drive at least one attempt that fails");
        match err {
            AtticError::LoginFailed { exit_code, .. } => {
                // Op ran (exit_code is Some) — pre-loop pass-through
                // did not synthesize a success. The exact `attempts`
                // count is not exposed on `LoginFailed` (unlike
                // `PushFailed`), so the pin is on the "op actually
                // ran" invariant via `exit_code.is_some()`.
                assert_eq!(exit_code, Some(1));
            }
            other => panic!("expected LoginFailed, got: {other:?}"),
        }
    }

    /// `login_with_retries` must NOT inject `ATTIC_TOKEN` into the
    /// spawned `attic` process — the token is supplied as a CLI
    /// argument. Sibling of
    /// [`test_login_does_not_inject_attic_token_env`] on the
    /// retry-driven login path; the two together pin the
    /// token-passing floor across both login primitives so a future
    /// "harmonize the two login paths to forward the token" refactor
    /// that added env injection would fail here rather than leak the
    /// token into both the env AND the argv (broadening the attack
    /// surface for `ps`-style observation on shared CI hosts).
    #[tokio::test]
    async fn test_login_with_retries_does_not_inject_attic_token_env() {
        let (_dir, shim) = make_attic_shim(
            "#!/bin/sh\necho \"LOGIN_RETRY_SAW_TOKEN=$ATTIC_TOKEN\" 1>&2\nexit 5\n",
        );
        let client = AtticClient::new("cache-login-retry-env")
            .with_token("must-not-leak-into-env-retry")
            .with_attic_bin(&shim);
        let err = client
            .login_with_retries("https://attic.example.com", 1)
            .await
            .expect_err("nonzero exit must fail");
        match err {
            AtticError::LoginFailed { stderr, .. } => {
                assert!(
                    stderr.contains("LOGIN_RETRY_SAW_TOKEN="),
                    "shim must observe the env var probe; got stderr: {stderr:?}"
                );
                assert!(
                    !stderr.contains("LOGIN_RETRY_SAW_TOKEN=must-not-leak-into-env-retry"),
                    "login_with_retries MUST NOT forward token via ATTIC_TOKEN env; \
                     got stderr: {stderr:?}"
                );
            }
            other => panic!("expected LoginFailed, got: {other:?}"),
        }
    }

    /// `classify_attic_login_failure` dispatches a post-`retry_command`
    /// `CommandAttemptFailure` to the typed [`AtticError`] variant
    /// whose structural shape matches. Sibling of
    /// [`test_classify_attic_push_failure_dispatches_on_spawn_vs_op`]
    /// on the login surface. A pure unit test of the dispatch helper
    /// — no subprocess, no shim, no retry-loop driving — so the
    /// typed mapping can evolve (e.g., adding
    /// `AtticError::LoginTimeout`) without subtle drift between
    /// this site and the canonical retry primitive.
    #[test]
    fn test_classify_attic_login_failure_dispatches_on_spawn_vs_op() {
        // Spawn-failure (attic not on PATH): must produce
        // `AtticError::ExecFailed` — never `LoginFailed` — because
        // the CLI never ran.
        let spawn = CommandAttemptFailure {
            operation: "login to Attic cache cache-x".to_string(),
            attempt: 1,
            exit_code: None,
            stderr: String::new(),
            stdout: "failed to spawn process: No such file or directory".to_string(),
        };
        match classify_attic_login_failure(spawn, "cache-x", "https://attic.example.com") {
            AtticError::ExecFailed { cache, message } => {
                assert_eq!(cache, "cache-x");
                assert!(
                    message.contains("No such file or directory"),
                    "spawn-error message must flow through stdout: {message}"
                );
            }
            other => panic!("expected ExecFailed, got: {other:?}"),
        }

        // Op-failure with terminal stderr (HTTP 401): must produce
        // `AtticError::LoginFailed` carrying (cache, server_url,
        // exit_code, stderr). The dispatch does NOT inspect
        // transient-vs-terminal (that classification happens INSIDE
        // `retry_command`); by the time the helper is called, the
        // retry loop has already exhausted or short-circuited.
        let op = CommandAttemptFailure {
            operation: "login to Attic cache cache-x".to_string(),
            attempt: 1,
            exit_code: Some(1),
            stderr: "401 Unauthorized: bad token".to_string(),
            stdout: String::new(),
        };
        match classify_attic_login_failure(op, "cache-x", "https://attic.example.com") {
            AtticError::LoginFailed {
                cache,
                server_url,
                exit_code,
                stderr,
            } => {
                assert_eq!(cache, "cache-x");
                assert_eq!(server_url, "https://attic.example.com");
                assert_eq!(exit_code, Some(1));
                assert!(stderr.contains("401"));
            }
            other => panic!("expected LoginFailed, got: {other:?}"),
        }
    }

    /// `login_optional` on the failure arm must swallow the typed
    /// [`AtticError::LoginFailed`] into `false` — the non-fatal contract
    /// `commands/build.rs::execute` relies on when attic login exits
    /// non-zero. Sibling of [`test_push_optional_returns_false_on_failure`]
    /// on the login surface. Uses a shim invoked by absolute path so the
    /// test is hermetic and parallel-safe (no env mutation).
    #[tokio::test]
    async fn test_login_optional_returns_false_on_failure() {
        let (_dir, shim) = make_attic_shim("#!/bin/sh\necho 'invalid token' 1>&2\nexit 5\n");
        let client = AtticClient::new("cache-login-opt-fail")
            .with_token("bad-tok")
            .with_attic_bin(&shim);
        let ok = client.login_optional("https://attic.example.com").await;
        assert!(!ok, "login_optional must return false on non-zero exit");
    }

    /// `login_optional` on the success arm must return `true` — pinning
    /// the affirmative half of the two-arm bool split so a future refactor
    /// that inverts the arms (or silently drops the `Ok(()) => true`
    /// case) breaks here rather than at the downstream `if !ok { ... }`
    /// reader. Sibling of [`test_push_optional_returns_true_on_success`]
    /// on the login surface.
    #[tokio::test]
    async fn test_login_optional_returns_true_on_success() {
        let (_dir, shim) = make_attic_shim("#!/bin/sh\nexit 0\n");
        let client = AtticClient::new("cache-login-opt-ok")
            .with_token("good-tok")
            .with_attic_bin(&shim);
        let ok = client.login_optional("https://attic.example.com").await;
        assert!(ok, "login_optional must return true on success");
    }

    /// `login_optional` with no token configured must return `false` —
    /// the pre-fire `TokenRequired` short-circuit at [`Self::login`]
    /// must ALSO swallow to the boolean, never panic or bubble.
    /// Pins the third arm of the three-error dispatch
    /// (`ExecFailed` / `LoginFailed` / `TokenRequired` → `false`) so a
    /// future refactor that adds a `.expect("token")` on the token
    /// look-up regresses here rather than at a call site that assumed
    /// bounded failure.
    #[tokio::test]
    async fn test_login_optional_returns_false_when_token_missing() {
        let client = AtticClient::new("cache-login-opt-notoken");
        let ok = client.login_optional("https://attic.example.com").await;
        assert!(
            !ok,
            "login_optional must return false when no token is configured"
        );
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

    /// `push_optional` on the success arm must return `true` — pinning
    /// the boolean split so a future refactor that inverts the arms (or
    /// silently drops the `Ok(()) => true` case) breaks here. Sibling of
    /// [`test_push_optional_returns_false_on_failure`] closing the
    /// affirmative half of the two-arm split.
    #[tokio::test]
    async fn test_push_optional_returns_true_on_success() {
        let (_dir, shim) = make_attic_shim("#!/bin/sh\nexit 0\n");
        let client = AtticClient::new("cache-opt-ok").with_attic_bin(&shim);
        let ok = client.push_optional("/nix/store/aaa-ok").await;
        assert!(ok, "push_optional must return true on success");
    }

    /// [`AtticClient::discover`] composed with
    /// [`AtticClient::push_optional`] is the exact call path
    /// `commands/push.rs::execute` routes its attic cache push through
    /// (via `AtticClient::discover(attic_cache).push_optional(&image_path)`).
    /// Pin the composition here so a future regression at either end
    /// — `discover` shape drift, `push_optional` boolean-arm inversion,
    /// or a re-fusion of the raw `Command::new("attic")` body at the
    /// push.rs call site — fails against the shared shape.
    ///
    /// `discover` reads `ATTIC_TOKEN` from process env (not set here, so
    /// the constructed client carries `token: None`), then falls through
    /// to `resolve_attic_bin` which honors `ATTIC_BIN` via
    /// [`get_tool_path`]. We chain `.with_attic_bin(shim)` (the test-
    /// only `#[cfg(test)]` builder) to inject a hermetic shim without
    /// mutating process env — same discipline every other
    /// binary-invocation test in this module carries. The shim exits
    /// non-zero, so `push_optional` returns `false` — pinning that the
    /// error path composes correctly through the discover-shaped client.
    #[tokio::test]
    async fn test_discover_composed_with_push_optional_returns_false_on_failure() {
        let (_dir, shim) = make_attic_shim("#!/bin/sh\nexit 3\n");
        let ok = AtticClient::discover("cache-discover-opt")
            .with_attic_bin(&shim)
            .push_optional("/nix/store/whatever-discover")
            .await;
        assert!(
            !ok,
            "discover().push_optional() must return false when attic exits non-zero"
        );
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

    /// When the `attic` binary cannot be spawned, `use_cache` must
    /// surface [`AtticError::ExecFailed`] carrying the cache name —
    /// never a stringly anyhow "Failed to configure attic cache".
    /// Sibling of `test_login_returns_exec_failed_when_attic_missing`
    /// on the cache-selection surface; pins the spawn-vs-op split at
    /// the type level so telemetry can distinguish "attic missing"
    /// from "attic said no" without parsing strings. Uses an absolute
    /// path that does not exist, injected via `with_attic_bin`, so
    /// the test is hermetic and parallel-safe (no env mutation).
    #[tokio::test]
    async fn test_use_cache_returns_exec_failed_when_attic_missing() {
        let client = AtticClient::new("cache-use-x")
            .with_attic_bin("/nonexistent/path/to/attic-binary-does-not-exist");
        let err = client
            .use_cache("default")
            .await
            .expect_err("missing attic must fail");
        match err {
            AtticError::ExecFailed { cache, .. } => assert_eq!(cache, "cache-use-x"),
            other => panic!("expected ExecFailed, got: {other:?}"),
        }
    }

    /// `use_cache` failures must produce [`AtticError::UseFailed`]
    /// carrying cache, server alias, exit code, and captured stderr —
    /// never a fused `bail!("Attic use failed")`. Mirror of
    /// `test_login_returns_login_failed_with_structured_fields` on the
    /// cache-selection surface; guarantees the structural-record tuple
    /// Phase 1 attestation records (THEORY §V.4) destructure.
    #[tokio::test]
    async fn test_use_cache_returns_use_failed_with_structured_fields() {
        let (_dir, shim) = make_attic_shim("#!/bin/sh\necho 'unknown cache' 1>&2\nexit 7\n");
        let client = AtticClient::new("cache-use-y").with_attic_bin(&shim);
        let err = client
            .use_cache("default")
            .await
            .expect_err("nonzero exit must fail");
        match err {
            AtticError::UseFailed {
                cache,
                server,
                exit_code,
                stderr,
            } => {
                assert_eq!(cache, "cache-use-y");
                assert_eq!(server, "default");
                assert_eq!(exit_code, Some(7));
                assert!(
                    stderr.contains("unknown cache"),
                    "stderr field must capture attic stderr verbatim, got: {stderr:?}"
                );
            }
            other => panic!("expected UseFailed, got: {other:?}"),
        }
    }

    /// On the success path, `use_cache` must complete without error —
    /// pins the affirmative floor `commands/build.rs::execute` relies
    /// on after a successful `attic login`. Sibling of
    /// `test_push_success_path` and `test_login_returns_login_failed_...`
    /// on the login/push surfaces.
    #[tokio::test]
    async fn test_use_cache_success_path() {
        let (_dir, shim) = make_attic_shim("#!/bin/sh\nexit 0\n");
        let client = AtticClient::new("cache-use-ok").with_attic_bin(&shim);
        client
            .use_cache("default")
            .await
            .expect("success path must succeed");
    }

    /// `use_cache` must pass `<server>:<cache_name>` as the CLI arg to
    /// `attic use` — a single joined ref rather than two separate
    /// tokens. Pre-migration the ref was joined at each call site via
    /// `format!("{server}:{cache}")`; post-migration the join lives in
    /// the primitive so a future change to the ref shape (e.g. an
    /// attic upgrade adding a shard qualifier) lands in one place. The
    /// shim echoes its argv to stderr and exits non-zero so the
    /// captured stderr in [`AtticError::UseFailed`] round-trips the
    /// observed arg — pinning the ref format structurally.
    #[tokio::test]
    async fn test_use_cache_passes_joined_server_and_cache_ref_to_attic() {
        let (_dir, shim) = make_attic_shim("#!/bin/sh\necho \"argv=$*\" 1>&2\nexit 11\n");
        let client = AtticClient::new("cache-ref-probe").with_attic_bin(&shim);
        let err = client
            .use_cache("srv-probe")
            .await
            .expect_err("nonzero exit must fail");
        match err {
            AtticError::UseFailed { stderr, .. } => {
                assert!(
                    stderr.contains("argv=use srv-probe:cache-ref-probe"),
                    "use_cache must invoke `attic use <server>:<cache>` verbatim; got stderr: {stderr:?}"
                );
            }
            other => panic!("expected UseFailed, got: {other:?}"),
        }
    }

    /// `use_cache` must NOT inject `ATTIC_TOKEN` into the spawned
    /// `attic` process — the `attic use` subcommand consumes no token
    /// (auth is seeded by the prior `attic login`). Sibling of
    /// `test_login_does_not_inject_attic_token_env` on the login
    /// surface; the two together pin the token-passing floor for both
    /// post-config attic subcommands. Guards against a future
    /// "harmonize all attic invocations to forward the token" refactor
    /// that would broaden the attack surface for `ps`-style
    /// observation on shared hosts by leaking the token into the env
    /// of a subcommand that never needed it.
    #[tokio::test]
    async fn test_use_cache_does_not_inject_attic_token_env() {
        let (_dir, shim) =
            make_attic_shim("#!/bin/sh\necho \"USE_SAW_TOKEN=$ATTIC_TOKEN\" 1>&2\nexit 13\n");
        let client = AtticClient::new("cache-use-tok")
            .with_token("must-not-leak-into-env")
            .with_attic_bin(&shim);
        let err = client
            .use_cache("default")
            .await
            .expect_err("nonzero exit must fail");
        match err {
            AtticError::UseFailed { stderr, .. } => {
                assert!(
                    stderr.contains("USE_SAW_TOKEN="),
                    "shim must observe the env var probe; got stderr: {stderr:?}"
                );
                assert!(
                    !stderr.contains("USE_SAW_TOKEN=must-not-leak-into-env"),
                    "use_cache MUST NOT forward token via ATTIC_TOKEN env; got stderr: {stderr:?}"
                );
            }
            other => panic!("expected UseFailed, got: {other:?}"),
        }
    }

    /// [`AtticClient::command`] MUST target the resolved `attic` binary
    /// (`self.resolve_attic_bin()`). Reads the returned `Command`'s
    /// program directly via [`std::process::Command::get_program`]
    /// (through `tokio::process::Command::as_std`) and asserts it
    /// equals the shim's absolute path when [`AtticClient::with_attic_bin`]
    /// binds it. A regression that swapped the helper body for a raw
    /// `Command::new("attic")` (silently bypassing `ATTIC_BIN`) would
    /// surface here as a mismatched program path — never as a silent-
    /// PATH-fallback bug at deploy time. Runs hermetically: no spawn,
    /// no process creation, no env-var mutation.
    ///
    /// Mirror of the sibling
    /// `infrastructure/git.rs::test_command_helper_program_equals_resolve_git_bin`
    /// (commit b388f85) on the attic client — same
    /// `Command::as_std().get_program()` inspection technique, applied
    /// to the attic-binary-resolution invariant here instead of the
    /// git-binary-resolution invariant there.
    #[test]
    fn test_command_helper_program_equals_resolve_attic_bin() {
        let shim = "/nonexistent/hermetic/shim/attic";
        let client = AtticClient::new("cache-probe").with_attic_bin(shim);
        let cmd = client.command();
        assert_eq!(
            cmd.as_std().get_program(),
            std::ffi::OsStr::new(shim),
            "AtticClient::command() must resolve the program through \
             `self.resolve_attic_bin()`, not hardcode `attic`. Got \
             program={:?}, expected {shim}",
            cmd.as_std().get_program()
        );
    }

    /// Whole-module shield: the `Command::new(self.resolve_attic_bin())`
    /// direct-expression spawn shape MUST appear at exactly one code
    /// line in this module — the [`AtticClient::command`] helper body.
    /// Every direct-`&self` consumer method
    /// ([`AtticClient::push_closure_via_stdin`], [`AtticClient::login`],
    /// [`AtticClient::use_cache`]) MUST route through `self.command()`
    /// instead of respelling the `let attic_bin = self.resolve_attic_bin();
    /// let mut cmd = Command::new(&attic_bin);` two-line preamble
    /// inline. Pre-lift the three consumer methods each carried the
    /// preamble verbatim; the lift collapses them onto the helper and
    /// this shield forbids re-fusion so the binary-resolution primitive
    /// stays authored at ONE body.
    ///
    /// The needle is `Command::new(self.resolve_attic_bin())` — the
    /// direct-expression form the post-lift helper body carries.
    /// Retry-driven consumers ([`AtticClient::push_with_retries`],
    /// [`AtticClient::login_with_retries`]) keep the local-capture
    /// shape (`let attic_bin = self.resolve_attic_bin();` outside the
    /// `retry_command` closure, `Command::new(&attic_bin)` inside the
    /// `async move`) — the closure's `'static` future cannot borrow
    /// `&self` across the boundary, so those two sites cannot compose
    /// through `self.command()`. Neither the outside-closure
    /// `self.resolve_attic_bin()` invocation (a bare method call, not
    /// a `Command::new` construction) nor the inside-closure
    /// `Command::new(&attic_bin)` (a local capture, not the `self.`
    /// direct expression) matches this shield's needle, so the two
    /// retry sites correctly do not count against the one-hit cap.
    /// The static [`AtticClient::is_available`] (which uses
    /// `Command::new(&attic_bin)` after a free-function `get_tool_path`
    /// resolve, also not the `self.` direct expression) is also
    /// exempted for the same reason.
    ///
    /// Routes through [`crate::test_support::code_line_hits`] so this
    /// shield's own docstring prose (which quotes the forbidden literal
    /// for narrative purposes) does not self-match. The needle is
    /// reconstructed via [`format!`] from its two lexical halves so the
    /// shield's own executable body does not false-fire against itself.
    ///
    /// Sibling shield to `infrastructure/git.rs`'s
    /// `test_command_new_resolve_git_bin_is_only_at_the_command_helper_body`
    /// (commit b388f85) — same one-hit-cap discipline, applied to the
    /// attic surface here.
    #[test]
    fn test_command_new_resolve_attic_bin_is_only_at_the_command_helper_body() {
        const SOURCE: &str = include_str!("attic.rs");

        let needle = format!("Command::new(self.{}())", "resolve_attic_bin");
        let hits = crate::test_support::code_line_hits(SOURCE, &needle);
        assert_eq!(
            hits.len(),
            1,
            "the attic-binary construction expression must appear at \
             exactly one code line in `cli/src/infrastructure/attic.rs` \
             — the `AtticClient::command` helper body. Every \
             direct-`&self` consumer method must route through \
             `self.command()` instead of respelling the two-line \
             `let attic_bin = self.resolve_attic_bin(); \
             let mut cmd = Command::new(&attic_bin);` preamble inline. \
             Found {} hit(s): {hits:#?}",
            hits.len()
        );
    }

    /// Whole-module shield: `fn attic_bin()` — the module-scoped
    /// sigil that resolves the `attic` binary via the canonical
    /// two-argument `get_tool_path("ATTIC_BIN", "attic")` call — MUST
    /// be defined at a code line in this module AND the two-argument
    /// resolve MUST appear at exactly ONE code line in the module
    /// body (only in the sigil definition).
    ///
    /// Pre-lift the module carried two respells of the two-argument
    /// resolve — one in [`AtticClient::resolve_attic_bin`]'s fallback
    /// branch (`self.attic_bin.clone().unwrap_or_else(|| get_tool_path(
    /// "ATTIC_BIN", "attic"))`), one in [`AtticClient::is_available`]'s
    /// inline probe (`let attic_bin = get_tool_path("ATTIC_BIN",
    /// "attic"); Command::new(&attic_bin).arg("--version")…`). The
    /// second respell silently bypassed the module's own
    /// single-point-of-truth for tool resolution: a future edit to
    /// the resolve contract at `resolve_attic_bin` would have left
    /// `is_available` stranded at the pre-edit form. Post-lift each
    /// consumer routes through `attic_bin()` and the resolve appears
    /// in exactly ONE place (the sigil body). The `resolve_count == 1`
    /// assertion fails-before at 2, passes-after at 1 — the canonical
    /// fail-before-pass-after arc matching the sibling `<tool>_bin()`
    /// shield discipline landed on
    /// `commands/comprehensive_release.rs::cargo_bin` (fceeecc),
    /// `cli/src/nix.rs::nix_bin` (6b2ea15),
    /// `commands/rust_service.rs::nix_bin` (63d4fe7),
    /// `commands/tool.rs::{cargo,crate2nix}_bin` (9f6046b / 7561329),
    /// and the broader `<tool>_bin()` sigil family. The mixed
    /// direct-`&self` / static-associated-fn shape asymmetry
    /// (`resolve_attic_bin` needs `&self` to honor the
    /// `with_attic_bin` test override; `is_available` is a static
    /// availability probe with no client instance) is exactly what
    /// motivates the free-function sigil: the shared resolve contract
    /// factors out of the `impl` block so both call shapes can route
    /// through it.
    ///
    /// The scan bounds on the whole-module boundary (from the file
    /// start to the FIRST `\n#[cfg(test)]\nmod tests {` marker in
    /// source order — the outer test module's opener at line ~680 in
    /// the current layout) so this shield's own docstring mentions of
    /// `get_tool_path("ATTIC_BIN", "attic")` — living inside the
    /// `#[cfg(test)]` block below that marker — stay out of scope
    /// AND every current or future attic-spawning helper landing
    /// anywhere in the top-level module body cannot silently ride
    /// along without going through `attic_bin()`.
    ///
    /// The two-argument-resolve needle is reconstructed via `format!`
    /// inside [`crate::test_support::get_tool_path_two_arg_call_needle`]
    /// and the sigil-definition needle via
    /// [`crate::test_support::sigil_bin_fn_definition_needle`], so
    /// this shield's own source never contains a concrete
    /// `get_tool_path("ATTIC_BIN", "attic")` or `fn attic_bin()`
    /// literal and cannot false-match itself on either assertion.
    /// Both positive assertions route through
    /// [`crate::test_support::code_line_hits`] to preserve the
    /// anti-docstring-self-match discipline.
    #[test]
    fn test_attic_routes_attic_bin_through_attic_bin_sigil_not_raw_resolve() {
        let body = crate::test_support::module_body_before_tests(
            include_str!("attic.rs"),
            "infrastructure/attic.rs",
        );

        let sigil_needle = crate::test_support::sigil_bin_fn_definition_needle("attic_bin");
        let sigil_hits = crate::test_support::code_line_hits(body, &sigil_needle);
        assert!(
            !sigil_hits.is_empty(),
            "infrastructure/attic.rs must define `attic_bin()` at a \
             code line in the module body — the sigil function that \
             resolves the tools-registry `ATTIC_BIN` override for \
             every `attic` binary lookup (both the `&self` \
             `resolve_attic_bin` fallback and the static \
             `is_available` probe). Mirrors the sibling `<tool>_bin()` \
             sigils across the CARGO surface (test_ci, prerelease, \
             developer_tools, tool, e2e, comprehensive_release), the \
             NIX_BIN surface (build, developer_tools, rust_service, \
             nix_builder, e2e, tool), and the broader sigil family."
        );

        let two_arg_needle =
            crate::test_support::get_tool_path_two_arg_call_needle("ATTIC_BIN", "attic");
        let resolve_hits = crate::test_support::code_line_hits(body, &two_arg_needle);
        assert_eq!(
            resolve_hits.len(),
            1,
            "the two-argument resolve `{two_arg_needle}` must appear \
             at exactly ONE code line in the module body (only in the \
             `attic_bin()` sigil), not {} — every consumer must route \
             through `attic_bin()`, not re-copy the resolve inline. \
             A future edit to the resolve contract (a substrate-path \
             validation step, a per-spawn env-injection hook, a \
             telemetry sigil on the resolved path) must land at the \
             sigil body once, not at each drifted call site. Found \
             {} code-line hit(s): {resolve_hits:#?}",
            resolve_hits.len(),
            resolve_hits.len()
        );
    }
}
