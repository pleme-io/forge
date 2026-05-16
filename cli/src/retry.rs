//! Retry primitives for forge external-CLI surfaces
//!
//! Frontier hermetic-build systems (Bazel BEP, Buck2, BuildKit) drive every
//! transient failure through a single retry primitive parameterized by:
//! a backoff schedule (initial, factor, max), an attempt cap, and a typed
//! transient/terminal classifier. forge has accreted three competing retry
//! loops — `infrastructure/registry.rs::push_with_retries`,
//! `commands/github_runner_ci.rs::attic_command_with_retry`, and
//! `commands/github_runner_ci.rs::push_with_retry` — each with a different
//! schedule and different rules for "what counts as retryable." This
//! module is the single primitive they collapse into.
//!
//! The classifier is closure-shaped (`Fn(&E) -> bool`) so callers carry
//! domain-specific transient/terminal logic without this module learning
//! about every external CLI's stderr dialect. Pre-existing typed errors
//! — `RegistryError`, `AtticError`, `GitError`, `NixBuildError` — already
//! carry the structured (op, exit_code, stderr) tuple a real classifier
//! needs (THEORY §V.4 Phase 1 attestation records).
//!
//! # Why exponential
//!
//! The pre-existing fixed `sleep(2s)` schedule in `push_with_retries` and
//! `push_with_retry` is the worst of both worlds: too long when the
//! transient is gone after 250ms, too short when it's a 30-second
//! upstream incident. Exponential backoff (Bazel-style: 250ms ×
//! factor=2 capped at 30s) covers both regimes by construction.

use std::future::Future;
use std::time::Duration;

/// Schedule + cap for retrying a fallible async operation.
///
/// `compute_delay` is a pure function of `attempt` — the loop body owns
/// the actual sleep — so callers and tests can reason about the schedule
/// without driving the clock.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Maximum number of attempts (inclusive). `1` means no retry.
    pub max_attempts: u32,
    /// Backoff before the first retry (between attempt 1 and attempt 2).
    pub initial_backoff: Duration,
    /// Multiplicative growth factor per retry. `1` produces fixed backoff.
    pub factor: u32,
    /// Cap on backoff. Backoff never exceeds this regardless of factor.
    pub max_backoff: Duration,
}

impl RetryPolicy {
    /// Zero retry — call once, return what you got. Useful where the caller
    /// already drove the schedule itself or where retry is unsafe (mutating
    /// non-idempotent endpoints).
    #[allow(dead_code)]
    pub const fn immediate() -> Self {
        Self {
            max_attempts: 1,
            initial_backoff: Duration::ZERO,
            factor: 1,
            max_backoff: Duration::ZERO,
        }
    }

    /// Reference policy for transient network failures against external
    /// CLIs (skopeo / regctl / attic / git). Five attempts, 250ms ×
    /// factor=2 starting backoff capped at 30s — matches the Bazel /
    /// Buck2 / SLSA frontier shape for transient build/upload events.
    pub const fn network() -> Self {
        Self {
            max_attempts: 5,
            initial_backoff: Duration::from_millis(250),
            factor: 2,
            max_backoff: Duration::from_secs(30),
        }
    }

    /// Custom policy. `max_attempts` is clamped to `>= 1` so a degenerate
    /// `0` cannot silently turn the loop into a no-op.
    pub fn new(
        max_attempts: u32,
        initial_backoff: Duration,
        factor: u32,
        max_backoff: Duration,
    ) -> Self {
        Self {
            max_attempts: max_attempts.max(1),
            initial_backoff,
            factor,
            max_backoff,
        }
    }

    /// Builder-style override of `max_attempts` on an existing policy.
    /// Clamps to `>= 1` (same discipline as [`Self::new`]) so a degenerate
    /// `0` from a caller-supplied `retries` parameter cannot silently turn
    /// the retry loop into a no-op. The schedule (`initial_backoff`,
    /// `factor`, `max_backoff`) is preserved verbatim.
    ///
    /// Lifts the verbatim eight-line pattern
    /// ```text
    /// let policy = {
    ///     let net = RetryPolicy::network();
    ///     RetryPolicy::new(
    ///         retries.max(1),
    ///         net.initial_backoff,
    ///         net.factor,
    ///         net.max_backoff,
    ///     )
    /// };
    /// ```
    /// that the two retry-driven typed-error producer sites in forge that
    /// override the canonical [`Self::network`] schedule's budget —
    /// `infrastructure/attic.rs::push_with_retries` and
    /// `infrastructure/registry.rs::push_with_retries` — carry verbatim.
    /// Two identically-shaped bodies past the duplication threshold the
    /// forge command-module surface enforces (≥2; PRIME DIRECTIVE) — this
    /// primitive is the law-redeeming consolidation for the
    /// "canonical-schedule + caller-budget" policy-build shape, sibling
    /// of [`Self::network`] (the canonical schedule) and
    /// [`Self::immediate`] (the no-retry shape).
    ///
    /// Composes with both factory constructors: `RetryPolicy::network()
    /// .with_max_attempts(retries)` gives the canonical exponential
    /// schedule with a caller-overridden budget; `RetryPolicy::immediate()
    /// .with_max_attempts(n)` is degenerate (immediate's
    /// `initial_backoff` is zero, so all delays are zero regardless of
    /// `n`) but composes cleanly without a special case.
    ///
    /// # The clamping invariant is load-bearing
    ///
    /// Without the clamp, a public-API caller passing `0` would produce a
    /// policy whose `max_attempts: 0` makes `run_with_policy`'s
    /// `attempt >= max` predicate true on the first call, returning the
    /// first error without ever consuming the retry budget — visible only
    /// as a regression in attempt-count telemetry, not in the typed-error
    /// surface. Pinning the clamp at this primitive means a future
    /// retry-driven site that takes a caller-supplied budget cannot
    /// silently produce a no-op loop.
    pub fn with_max_attempts(mut self, max_attempts: u32) -> Self {
        self.max_attempts = max_attempts.max(1);
        self
    }

    /// Backoff to wait *before* the given 1-indexed attempt.
    ///
    /// `compute_delay(1)` is `Duration::ZERO` (no wait before the first
    /// call). `compute_delay(n)` for `n >= 2` is `initial_backoff *
    /// factor^(n-2)`, capped at `max_backoff`. The cap is enforced even
    /// when `factor.pow(n-2)` overflows `u32`, so the schedule is safe
    /// for arbitrarily-large `n` without panic.
    pub fn compute_delay(&self, attempt: u32) -> Duration {
        if attempt <= 1 {
            return Duration::ZERO;
        }
        if self.initial_backoff.is_zero() {
            return Duration::ZERO;
        }
        let exp = attempt - 2;
        // Saturating exponentiation: any overflow collapses to the cap.
        let mult: u128 = match (self.factor as u128).checked_pow(exp) {
            Some(m) => m,
            None => return self.max_backoff,
        };
        let nanos: u128 = self.initial_backoff.as_nanos().saturating_mul(mult);
        let cap_nanos = self.max_backoff.as_nanos();
        let chosen = nanos.min(cap_nanos);
        // Clamp to u64 nanos; anything over u64::MAX nanos is far past
        // any reasonable cap.
        let chosen_u64 = u64::try_from(chosen).unwrap_or(u64::MAX);
        Duration::from_nanos(chosen_u64)
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self::network()
    }
}

/// Markers in captured stderr that signal a transient network/server
/// failure worth retrying. The list is canonical across the dialects
/// forge's external CLIs speak: skopeo (Go's `net/http`), regctl (Go),
/// attic (reqwest/hyper), git-over-HTTPS (curl), and the underlying
/// HTTP servers (GHCR, attic-server). Sourced from the substring set
/// the pre-existing `attic_command_with_retry` matched in production
/// (b0db1da's prior context) plus the Go-stdlib timeout/EOF idioms.
///
/// Markers are matched as plain substrings (case-sensitive on the
/// canonical capitalization the tools emit). Numeric codes ("500",
/// "502", "503", "504") match alongside their named forms because
/// different tools emit one or the other; matching both is harmless.
const TRANSIENT_NETWORK_STDERR_MARKERS: &[&str] = &[
    // HTTP 5xx — numeric forms first (skopeo / regctl emit numeric).
    "500",
    "502",
    "503",
    "504",
    // HTTP 5xx — named forms (attic / curl emit named).
    "Internal Server Error",
    "InternalServerError",
    "Bad Gateway",
    "Service Unavailable",
    "Gateway Timeout",
    // Connection-level failures — both Go-stdlib lowercase and curl mixed-case.
    "Connection refused",
    "connection refused",
    "Connection reset",
    "connection reset",
    "Connection aborted",
    // I/O timeouts (Go net/http and TLS handshake variants).
    "i/o timeout",
    "TLS handshake timeout",
    "timeout",
    // Mid-stream TCP drops (servers closing under load).
    "unexpected EOF",
    "EOF",
];

/// Heuristic classifier: does `stderr` indicate a transient network or
/// upstream-server failure that should be retried, vs a terminal failure
/// (auth, not-found, missing tool, manifest mismatch) that should fail
/// fast?
///
/// Returns `true` for HTTP 5xx (numeric or named), connection-level errors
/// (refused / reset / aborted), I/O and TLS-handshake timeouts, and EOF /
/// unexpected-EOF (typical TCP drop mid-stream). Returns `false` for
/// anything else — including empty stderr, so a typed `ExecFailed` /
/// `TokenRequired` / `LocalImageNotFound` whose record carries no stderr
/// short-circuits without burning retry budget.
///
/// This is the typed lift of the substring-classifier the pre-existing
/// `commands/github_runner_ci.rs::attic_command_with_retry` carried
/// inline. Centralizing it pre-empts the planned migrations of
/// `attic_command_with_retry` and `push_with_retry` (b0db1da's
/// follow-up) — both consume this primitive instead of carrying their
/// own substring lists.
pub fn is_transient_network_stderr(stderr: &str) -> bool {
    if stderr.is_empty() {
        return false;
    }
    TRANSIENT_NETWORK_STDERR_MARKERS
        .iter()
        .any(|m| stderr.contains(m))
}

/// Captured `(exit_code, stderr)` of a failed external-command attempt.
///
/// Typed primitive sitting between `std::process::Output` and the typed
/// `*Failed` variants every external-CLI surface in forge produces
/// (`GitError::OpFailed`, `GitError::RemoteOpFailed`,
/// `NixBuildError::BuildFailed`, `AtticError::PushFailed`,
/// `AtticError::LoginFailed`, `RegistryError::PushFailed`). Each of those
/// variants carries the same two fields — `exit_code: Option<i32>`,
/// `stderr: String` — and each producer site otherwise re-derives them
/// inline with the verbatim two-line incantation
/// `(output.status.code(), String::from_utf8_lossy(&output.stderr).trim().to_string())`.
/// Five typed-error producer sites in forge carry that incantation —
/// well past the three-times threshold (THEORY §VI.1) — so this commit
/// redeems the duplication: every typed-error producer that wraps an
/// external-CLI failure now extracts `(exit_code, stderr)` through one
/// typed conversion, not five drift-prone copies.
///
/// The UTF-8-lossy decode + trim discipline is load-bearing — the
/// canonical [`is_transient_network_stderr`] substring matcher would
/// otherwise miss a transient marker that a tool emitted with a trailing
/// newline (e.g. `"503 Service Unavailable\n"` would still match by
/// substring, but `"503 Service Unavailable\r\n"` against a
/// `.contains("Service Unavailable")` matcher passes only because the
/// marker happens to not include the trailing whitespace; pinning the
/// trim discipline at the typed primitive guarantees the classifier
/// always sees a normalized stderr regardless of which producer site
/// constructed the record). A future site that forgets `.trim()` —
/// silently leaking a trailing `\n` into the canonical classifier — is
/// structurally impossible: there is one place that does the decode and
/// every site goes through it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedFailure {
    /// Exit code from the child process. `None` when killed by signal.
    pub exit_code: Option<i32>,
    /// Captured stderr, UTF-8-lossy-decoded and trimmed of leading/
    /// trailing whitespace. Internal whitespace is preserved so multi-
    /// line tool diagnostics survive the round-trip into the typed
    /// `*Failed` variant.
    pub stderr: String,
}

impl CapturedFailure {
    /// Extract `(exit_code, stderr)` from any `Output` regardless of
    /// status. Use this from a code path that already knows the output
    /// represents a failure (e.g. inside the non-success arm of a `match
    /// output.status.success() { ... }`). Use [`Self::from_output_if_failed`]
    /// from a code path that needs to discriminate success vs. failure
    /// in one expression.
    pub fn from_output(output: &std::process::Output) -> Self {
        Self {
            exit_code: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        }
    }

    /// Extract `(exit_code, stderr)` from `Output` iff the status is
    /// non-success. Returns `None` when the process exited zero — the
    /// load-bearing invariant for callers that fold "did this command
    /// succeed?" into the typed-error path: `if let Some(cf) =
    /// CapturedFailure::from_output_if_failed(&out) { return Err(...) }`.
    /// A future regression that returned `Some` on success would
    /// silently turn every successful invocation into a typed `*Failed`
    /// variant — pinned out by `test_captured_failure_from_output_if_failed_none_on_success`.
    pub fn from_output_if_failed(output: &std::process::Output) -> Option<Self> {
        if output.status.success() {
            None
        } else {
            Some(Self::from_output(output))
        }
    }
}

/// Classify an external-CLI invocation's `io::Result<Output>` into one of
/// three structural shapes — success, spawn-failure, op-failure — and
/// route each non-success shape into a typed-error variant supplied by
/// the caller.
///
/// Lifts the verbatim two-step pattern
/// ```text
/// let output = cmd.output().await.map_err(|e| <Family>::ExecFailed {
///     <op_field>: ..., message: e.to_string(),
/// })?;
/// if let Some(cf) = CapturedFailure::from_output_if_failed(&output) {
///     return Err(<Family>::<OpFailed> {
///         <op_field>: ..., exit_code: cf.exit_code, stderr: cf.stderr,
///     });
/// }
/// ```
/// that four typed-error producer sites in forge carry verbatim modulo
/// per-site `<Family>` and per-site `<op_field>`:
/// `git.rs::git_capture`, `git.rs::git_capture_remote`,
/// `nix.rs::run_nix_build_typed`, and
/// `infrastructure/registry.rs::create_manifest_index`. Four
/// identically-shaped bodies past the three-times threshold
/// (THEORY §VI.1) — this primitive is the law-redeeming consolidation
/// for the typed-error producer surface, the same way `retry_command`
/// (commit 26ddcef) consolidated the typed-error retry-driver surface.
///
/// The caller supplies two closures, one per non-success shape:
/// - `on_spawn` receives the underlying `std::io::Error` and produces
///   the family-specific `*::ExecFailed` variant. Spawn-failure means
///   the CLI binary could not be invoked at all (not on PATH, fork
///   failed, permission denied) — the canonical discipline four typed-
///   error families already encode for their `ExecFailed` variants
///   (Registry, Nix, Attic, Git).
/// - `on_op` receives the canonical [`CapturedFailure`] (UTF-8-lossy-
///   trimmed stderr + extracted exit_code) and produces the family-
///   specific operation-failure variant (`*::OpFailed`,
///   `*::BuildFailed`, `*::ManifestFailed`, etc.). The `CapturedFailure`
///   typed primitive guarantees the `(exit_code, stderr)` extraction
///   never drifts on UTF-8 decode or trim discipline — the
///   load-bearing invariant the canonical
///   [`is_transient_network_stderr`] classifier relies on across every
///   typed-error consumer.
///
/// On success, the captured `Output` is returned verbatim so the caller
/// can extract `stdout` / inspect the status / etc. without re-running
/// the command.
///
/// The split between `on_spawn` (could not spawn) and `on_op` (CLI ran
/// and rejected) is the typed analog of
/// [`CommandAttemptFailure::is_spawn_failure`] (commit 34c1a35), which
/// performs the same discrimination one phase later (after the retry
/// loop) for retry-call-site consumers. Together the two predicates
/// cover both the non-retry direct-call-site shape (this helper) and
/// the retry-loop post-dispatch shape — every typed-error producer in
/// forge that drives a `tokio::process::Command` against an external
/// CLI now flows through one of the two canonical primitives, with the
/// same structural-record discipline at both surfaces.
pub fn classify_capture<E, FExec, FOp>(
    captured: std::io::Result<std::process::Output>,
    on_spawn: FExec,
    on_op: FOp,
) -> Result<std::process::Output, E>
where
    FExec: FnOnce(std::io::Error) -> E,
    FOp: FnOnce(CapturedFailure) -> E,
{
    match captured {
        Ok(out) if out.status.success() => Ok(out),
        Ok(out) => Err(on_op(CapturedFailure::from_output(&out))),
        Err(e) => Err(on_spawn(e)),
    }
}

/// Query-shaped dual of [`classify_capture`]: routes the same three
/// structural shapes (success / spawn-failure / op-failure) but returns
/// the trimmed UTF-8-lossy stdout on success instead of the raw `Output`.
///
/// Lifts the verbatim three-step pattern
/// ```text
/// let output = cmd.output().await.map_err(|e| <Family>::ExecFailed { ... })?;
/// if !output.status.success() {
///     // op-failure produces a domain-specific variant — sometimes carrying
///     // (exit_code, stderr), sometimes a precondition variant that ignores
///     // both because the structural meaning is "the queried thing isn't there"
///     return Err(<Family>::<QueryFailed> { ... });
/// }
/// let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
/// ```
/// that four typed-error producer sites in forge carry verbatim modulo per-
/// site `<Family>` and per-site op-failure shape:
/// `nix.rs::run_nix_build_typed` (already on `classify_capture`, still
/// re-derives the trim),
/// `infrastructure/git.rs::GitClient::rev_parse_short`,
/// `infrastructure/git.rs::GitClient::get_full_sha`,
/// `infrastructure/registry.rs::RegistryClient::verify_tag_exists`. Four
/// identically-shaped bodies past the three-times threshold (THEORY §VI.1)
/// — this primitive is the law-redeeming consolidation for the typed-error
/// query-shape surface, the dual of [`classify_capture`]'s consolidation
/// for the typed-error op-shape surface (commit b75a273).
///
/// The split between [`classify_capture`] and [`classify_capture_query`]
/// is structural, not stylistic: a producer site that consumes both stdout
/// AND stderr from a successful invocation (e.g. `regctl index create`,
/// where the manifest digest may surface on stderr depending on the
/// dialect) wants the raw `Output`. A producer site that only consumes
/// stdout (the canonical "query the registry / SCM / build-tool for a
/// single value" shape) wants the trimmed `String` directly. Pinning the
/// two shapes as separate primitives keeps the per-site signature minimal:
/// query-shaped sites no longer carry the trim incantation as a fifth
/// load-bearing line, and op-shape sites no longer return `Result<String,
/// E>` and force their callers to re-discriminate empty-vs-nonempty when
/// the structural meaning is "the CLI ran and produced bytes."
///
/// The op-failure closure receives the canonical [`CapturedFailure`]
/// (UTF-8-lossy-trimmed stderr + extracted exit_code) — same as
/// [`classify_capture`] — so a site that DOES want the structural-record
/// tuple in its op-failure variant (`GitError::ShaFailed` carrying the
/// stderr) destructures `cf.exit_code` and `cf.stderr` by name, and a
/// site that does NOT want them (`RegistryError::RemoteImageNotFound`
/// carrying only `(registry, tag)` because the precondition meaning is
/// "the queried tag isn't there") simply ignores `cf` with `|_cf| ...`.
/// Either choice keeps the typed-error producer surface uniform across
/// the four already-migrated families (Registry, Nix, Attic, Git) and
/// the canonical retry primitives.
pub fn classify_capture_query<E, FExec, FOp>(
    captured: std::io::Result<std::process::Output>,
    on_spawn: FExec,
    on_op: FOp,
) -> Result<String, E>
where
    FExec: FnOnce(std::io::Error) -> E,
    FOp: FnOnce(CapturedFailure) -> E,
{
    match captured {
        Ok(out) if out.status.success() => {
            Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
        }
        Ok(out) => Err(on_op(CapturedFailure::from_output(&out))),
        Err(e) => Err(on_spawn(e)),
    }
}

/// Captured output of a single failed external-command attempt.
///
/// Typed error shape for ad-hoc retry call sites (`commands/push.rs`,
/// `commands/github_runner_ci.rs`) whose public surface returns
/// `anyhow::Result<()>` and where a domain-specific error enum
/// (`RegistryError`, `AtticError`, `GitError`, `NixBuildError`) does not
/// yet exist. Carries the structural-record tuple THEORY §V.4 Phase 1
/// attestation records need: `(operation, attempt, exit_code, stderr,
/// stdout)`. The hand-rolled retry loops this type displaces all fused
/// these fields into free-form `anyhow::bail!("…: {}", stderr)` strings;
/// pinning them as separate fields means a future telemetry / replay /
/// attestation consumer can recover the exact failure tuple without log
/// scraping.
///
/// Transient/terminal classification is via [`Self::is_transient`], which
/// delegates to [`is_transient_network_stderr`] against the captured
/// stderr. Empty stderr (the spawn-failure path: `Command::output().await`
/// returned `Err`, or a tool was found but produced no stderr) is
/// unconditionally terminal so the retry loop never burns budget on a
/// "binary not on PATH" or "operating-system fork failed" precondition.
#[derive(Debug, Clone)]
pub struct CommandAttemptFailure {
    /// Caller-supplied label for the failed operation
    /// (e.g. `"login to Attic"`, `"push ghcr.io/o/p:tag"`).
    pub operation: String,
    /// 1-indexed attempt number on which the failure occurred.
    pub attempt: u32,
    /// Exit code from the child process, if it exited normally. `None`
    /// when the process could not be spawned (or was killed by signal).
    pub exit_code: Option<i32>,
    /// Captured stderr, trimmed. Empty when the process could not be
    /// spawned. Consumed by [`Self::is_transient`].
    pub stderr: String,
    /// Captured stdout, trimmed. Used as a Display fallback when stderr
    /// is empty.
    pub stdout: String,
}

impl CommandAttemptFailure {
    /// True iff the captured stderr matches a transient network/server
    /// failure marker (HTTP 5xx, connection-level, I/O timeout, EOF).
    /// Empty stderr is terminal by construction.
    pub fn is_transient(&self) -> bool {
        is_transient_network_stderr(&self.stderr)
    }

    /// True iff this record represents a process that could not be spawned
    /// (binary not on PATH, fork failed, permission denied), as opposed to
    /// a process that ran-but-exited-non-zero.
    ///
    /// The structural shape of a spawn-failure record is fixed by
    /// [`Self::from_capture`]: `exit_code: None` and an empty `stderr`
    /// (the spawn error is moved into `stdout` for Display fallback).
    /// A non-zero-exit op-failure always carries `Some(_)` exit code (or
    /// `None` only when killed by signal — but with non-empty stderr).
    /// The conjunction `exit_code.is_none() && stderr.is_empty()` is
    /// load-bearing: it lets typed-error producer sites that consume
    /// `retry_command`'s output discriminate `*::ExecFailed` (spawn could
    /// not run the CLI) from `*::PushFailed` / `*::OpFailed` /
    /// `*::BuildFailed` (CLI ran and rejected the request) without
    /// substring-parsing the failure message — same discipline the four
    /// pre-existing typed-error families established with their
    /// `ExecFailed` variants (Registry, Nix, Attic, Git).
    ///
    /// A retry-loop site that wants to short-circuit on spawn-failure
    /// already gets that for free via [`Self::is_transient`] (empty
    /// stderr is terminal). This predicate is the post-loop dispatch
    /// shape: once `retry_command` returns `Err(CommandAttemptFailure)`,
    /// the call site uses `is_spawn_failure()` to choose between the two
    /// typed-error variants (`ExecFailed` vs the operation-specific
    /// failure).
    pub fn is_spawn_failure(&self) -> bool {
        self.exit_code.is_none() && self.stderr.is_empty()
    }

    /// Convert a `Command::output()` result into a typed
    /// `CommandAttemptFailure` or success `Output`. Lifts the
    /// `match { Ok success | Ok non-success | Err spawn }` body every
    /// retry-loop in forge would otherwise duplicate
    /// (`commands/github_runner_ci.rs::{attic_command_with_retry,
    /// push_with_retry}`, `commands/push.rs::push_with_retry`). The
    /// returned `Err` is the structural-record shape `run_with_policy`
    /// consumes; success returns the captured `Output` so callers retain
    /// stdout/stderr access for logging.
    ///
    /// Three failure shapes collapse into one typed mapping:
    /// - `Ok(out)` with `out.status.success()` → success `Output` is
    ///   returned verbatim (callers may inspect stdout/stderr).
    /// - `Ok(out)` with non-zero status → typed record carrying
    ///   `(operation, attempt, exit_code, stderr, stdout)`. Both stderr
    ///   and stdout are decoded UTF-8-lossy and trimmed.
    /// - `Err(spawn_err)` (process could not be spawned) → typed record
    ///   with `exit_code: None`, empty `stderr`, and the spawn error in
    ///   `stdout`. Empty stderr is unconditionally terminal under
    ///   [`is_transient_network_stderr`], so the retry loop short-
    ///   circuits rather than burning budget on a "binary not on PATH"
    ///   or "fork failed" precondition. The operation name already
    ///   appears in the record's `operation` field, so the spawn-error
    ///   message format is uniform across call sites (no per-site
    ///   "Failed to execute X" / "X command failed" prefix variation).
    pub fn from_capture(
        captured: Result<std::process::Output, std::io::Error>,
        operation: impl Into<String>,
        attempt: u32,
    ) -> Result<std::process::Output, Self> {
        match captured {
            Ok(out) if out.status.success() => Ok(out),
            Ok(out) => Err(Self {
                operation: operation.into(),
                attempt,
                exit_code: out.status.code(),
                stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
                stdout: String::from_utf8_lossy(&out.stdout).trim().to_string(),
            }),
            Err(spawn_err) => Err(Self {
                operation: operation.into(),
                attempt,
                exit_code: None,
                stderr: String::new(),
                stdout: format!("failed to spawn process: {spawn_err}"),
            }),
        }
    }
}

impl std::fmt::Display for CommandAttemptFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let detail = if !self.stderr.is_empty() {
            self.stderr.as_str()
        } else if !self.stdout.is_empty() {
            self.stdout.as_str()
        } else {
            "(no captured output)"
        };
        write!(
            f,
            "Failed to {}: {} (exit {:?}, attempt {})",
            self.operation, detail, self.exit_code, self.attempt
        )
    }
}

impl std::error::Error for CommandAttemptFailure {}

/// Run `op` under `policy`, retrying transient errors per the schedule.
///
/// `op` receives the 1-indexed attempt number so callers can build error
/// records that surface the final attempt count (e.g.,
/// [`crate::error::RegistryError::PushFailed`]'s `attempts` field). The
/// classifier `is_transient` decides which errors are retried; a
/// `false` short-circuits and returns the error immediately, so a
/// "not-on-PATH" or "unauthorized" failure never burns retry budget.
///
/// On exhaustion, the *last* error is returned — the loop never invents
/// a synthetic "max retries reached" wrapper, so the typed shape pinned
/// in [`crate::error`] is preserved end-to-end. `op` is called at most
/// `policy.max_attempts` times.
pub async fn run_with_policy<T, E, Op, Fut, F>(
    policy: &RetryPolicy,
    is_transient: F,
    mut op: Op,
) -> Result<T, E>
where
    Op: FnMut(u32) -> Fut,
    Fut: Future<Output = Result<T, E>>,
    F: Fn(&E) -> bool,
{
    let max = policy.max_attempts.max(1);
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        match op(attempt).await {
            Ok(v) => return Ok(v),
            Err(e) => {
                if !is_transient(&e) || attempt >= max {
                    return Err(e);
                }
                let delay = policy.compute_delay(attempt + 1);
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }
}

/// Drive `spawn` under `policy`, mapping each attempt's
/// `std::io::Result<Output>` into the canonical [`CommandAttemptFailure`]
/// shape and routing transient failures through the canonical
/// [`is_transient_network_stderr`] classifier.
///
/// Lifts the verbatim triple
/// `run_with_policy(policy, |e| e.is_transient(), |attempt| async {
///   CommandAttemptFailure::from_capture(Command::new(..).output().await, op, attempt)
/// })`
/// that three sites in forge — `commands/push.rs::push_with_retry`,
/// `commands/github_runner_ci.rs::attic_command_with_retry`, and
/// `commands/github_runner_ci.rs::push_with_retry` — each carry verbatim
/// modulo per-site logging. Three identically-shaped bodies past the
/// three-times threshold (THEORY §VI.1) — this primitive is the
/// law-redeeming consolidation.
///
/// `spawn(attempt)` returns a future yielding `std::io::Result<Output>`
/// — the shape `tokio::process::Command::output().await` already
/// produces. On a zero-exit `Output`, the `Output` is returned. On a
/// non-zero exit, a [`CommandAttemptFailure`] is constructed via
/// [`CommandAttemptFailure::from_capture`] (the canonical
/// UTF-8-lossy-plus-trim mapping), and routed through
/// [`run_with_policy`] with the canonical classifier. Spawn failures
/// (`Err(io::Error)` — binary not on PATH, fork failed) become a
/// `CommandAttemptFailure` with empty stderr — terminal by
/// construction under the classifier — so the retry loop short-
/// circuits without burning budget on a structural precondition.
///
/// The helper does NOT log or warn on per-attempt failure. Callers that
/// want per-attempt visibility log on the returned `Err`, or wrap
/// `spawn` to tee stderr to `tracing::debug!`. Centralizing the warning
/// in the helper would conflate two separable concerns (retry policy vs.
/// observability dialect) and force every call site to share a single
/// log message shape.
pub async fn retry_command<F, Fut>(
    policy: &RetryPolicy,
    operation: impl Into<String>,
    mut spawn: F,
) -> Result<std::process::Output, CommandAttemptFailure>
where
    F: FnMut(u32) -> Fut,
    Fut: Future<Output = std::io::Result<std::process::Output>>,
{
    let operation = operation.into();
    run_with_policy(
        policy,
        |e: &CommandAttemptFailure| e.is_transient(),
        |attempt| {
            let op = operation.clone();
            let fut = spawn(attempt);
            async move {
                let captured = fut.await;
                CommandAttemptFailure::from_capture(captured, op, attempt)
            }
        },
    )
    .await
}

/// Log a "retry attempt failed" warning iff `outcome` represents a failure
/// AND another attempt remains in budget, then return the captured `outcome`
/// verbatim. The pass-through is the load-bearing invariant: callers chain
/// the helper into `retry_command`'s spawn closure as the final expression
/// so the typed retry primitive consumes the same `io::Result<Output>`
/// shape it would have received without the log.
///
/// Lifts the verbatim eight-line pattern
/// ```text
/// let outcome = cmd.output().await;
/// if outcome
///     .as_ref()
///     .map(|o| !o.status.success())
///     .unwrap_or(true)
///     && attempt < max_attempts
/// {
///     warn!("...attempt {}/{} failed, retrying...", attempt, max_attempts);
/// }
/// outcome
/// ```
/// that four retry-driven external-CLI sites in forge carry verbatim modulo
/// per-site warning format:
/// `infrastructure/registry.rs::push_with_retries`,
/// `infrastructure/attic.rs::push_with_retries`,
/// `commands/github_runner_ci.rs::attic_command_with_retry`,
/// `commands/github_runner_ci.rs::push_with_retry`. Four identically-shaped
/// bodies past the three-times threshold (THEORY §VI.1) — this primitive is
/// the law-redeeming consolidation for the per-attempt warn-on-failure
/// dispatch shape, sibling of the four canonical retry primitives in this
/// module ([`RetryPolicy`], [`run_with_policy`], [`retry_command`],
/// [`classify_capture`] / [`classify_capture_query`]).
///
/// The "failure" predicate matches the structural shape `retry_command`
/// itself uses to discriminate retryable outcomes: an `Ok(out)` with
/// `out.status.success() == false`, OR an `Err(io::Error)` (spawn-failure).
/// Both shapes are "this attempt did not succeed" from the retry-loop's
/// perspective; the caller does not need to discriminate spawn-vs-op here
/// (that is the job of the post-loop dispatch helpers
/// `classify_attic_push_failure` / `classify_push_failure` / et al.).
///
/// The "another attempt remains" predicate (`attempt < max_attempts`)
/// suppresses the warn on the LAST attempt — there is no retry after the
/// final attempt, so warning "...retrying..." would mis-describe what
/// happens next. The caller-supplied final-failure path (the post-loop
/// dispatch onto a typed `*::PushFailed` / `*::ExecFailed` variant) owns
/// the terminal-failure log surface; this primitive owns only the
/// per-attempt-with-budget-remaining surface.
///
/// Logs at `warn!` level via `tracing` — same level the four pre-migration
/// sites used. The message format `"{op} failed (attempt {n}/{max}):
/// retrying..."` standardizes on the most informative pre-migration shape
/// (`commands/github_runner_ci.rs::attic_command_with_retry`'s); the two
/// infrastructure/* sites previously emitted "Push attempt {n} failed,
/// retrying..." without the operation label, so post-migration their warns
/// gain the op label by construction.
pub fn log_retry_attempt(
    outcome: std::io::Result<std::process::Output>,
    operation: &str,
    attempt: u32,
    max_attempts: u32,
) -> std::io::Result<std::process::Output> {
    let failed = outcome
        .as_ref()
        .map(|o| !o.status.success())
        .unwrap_or(true);
    if failed && attempt < max_attempts {
        tracing::warn!(
            "{} failed (attempt {}/{}): retrying...",
            operation,
            attempt,
            max_attempts
        );
    }
    outcome
}

/// Format captured stdout/stderr of an external-command [`std::process::Output`]
/// as `<tool>`-prefixed debug-level messages, suitable for tee'ing into
/// `tracing::debug!`. Pure function — no I/O, no side effects, no tracing
/// subscriber assumed — so callers can assert the exact message format
/// directly instead of via a tracing-subscriber harness.
///
/// Empty (after trim) stdout / stderr streams produce no message. The
/// trim discipline — UTF-8-lossy decode + trim of leading/trailing
/// whitespace, internal whitespace preserved — matches
/// [`CapturedFailure::from_output`]'s so the debug surface aligns with
/// the typed-error surface across every retry-driven external-CLI
/// producer site in forge. A regression that drifted between the two
/// disciplines (e.g., a debug-tee that did not trim while the typed
/// `*::PushFailed.stderr` field did) would silently emit divergent
/// messages for the same captured failure across the warn / debug
/// surfaces.
///
/// # Output ordering invariant
///
/// `stdout` precedes `stderr` in the returned vector. The two pre-
/// migration call sites (`commands/github_runner_ci.rs::
/// attic_command_with_retry` and `::push_with_retry`) emit stdout-then-
/// stderr; pinning the order here keeps log replay deterministic across
/// the migration.
pub fn format_capture_streams(out: &std::process::Output, tool: &str) -> Vec<String> {
    let mut messages = Vec::new();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stdout_trimmed = stdout.trim();
    if !stdout_trimmed.is_empty() {
        messages.push(format!("{} stdout: {}", tool, stdout_trimmed));
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stderr_trimmed = stderr.trim();
    if !stderr_trimmed.is_empty() {
        messages.push(format!("{} stderr: {}", tool, stderr_trimmed));
    }
    messages
}

/// Tee captured stdout / stderr of an external-command
/// [`std::process::Output`] at `tracing::debug` level under a `<tool>`
/// prefix. Sibling of [`log_retry_attempt`] in the canonical retry
/// primitive set: `log_retry_attempt` owns the per-attempt warn-on-
/// failure dispatch (level=warn, suppressed on the final attempt); this
/// owns the per-attempt stream-tee debug surface (level=debug, on every
/// attempt — there is no "retry-shaped" suppression for observability).
///
/// Lifts the verbatim six-line pattern
/// ```text
/// let stdout = String::from_utf8_lossy(&out.stdout);
/// let stderr = String::from_utf8_lossy(&out.stderr);
/// if !stdout.trim().is_empty() {
///     debug!("<tool> stdout: {}", stdout.trim());
/// }
/// if !stderr.trim().is_empty() {
///     debug!("<tool> stderr: {}", stderr.trim());
/// }
/// ```
/// that two retry-driven external-CLI sites in forge carry verbatim modulo
/// per-site tool name: `commands/github_runner_ci.rs::
/// attic_command_with_retry` (tool = "attic") and `::push_with_retry`
/// (tool = "skopeo"). Two identically-shaped bodies past the duplication
/// threshold the forge command-module surface enforces (≥2; PRIME
/// DIRECTIVE) — this primitive is the law-redeeming consolidation for
/// the per-attempt debug-tee dispatch shape.
///
/// Routes through [`format_capture_streams`] so the message format
/// (`"<tool> stdout: <trimmed>"` / `"<tool> stderr: <trimmed>"`) is
/// pinned by a pure unit test on the formatter, not by an integration
/// test that has to spin up a tracing-test subscriber. Future regressions
/// on the format surface here first.
///
/// # When to call
///
/// On the non-success `Ok(out)` arm of an external-command outcome
/// inside a retry-loop spawn closure, AFTER the closure has consumed the
/// captured `Output` and BEFORE the closure returns the outcome to
/// [`retry_command`] / [`log_retry_attempt`]. Spawn-failures (`Err(io::
/// Error)` — binary not on PATH) are NOT routed through this primitive;
/// the spawn-error message is consumed by
/// [`CommandAttemptFailure::from_capture`]'s `stdout` field, which the
/// post-loop typed-error dispatch (`classify_attempt_failure`) routes to
/// the `*::ExecFailed.message` field.
pub fn debug_log_capture_streams(out: &std::process::Output, tool: &str) {
    for message in format_capture_streams(out, tool) {
        tracing::debug!("{}", message);
    }
}

/// Dispatch a post-[`retry_command`] [`CommandAttemptFailure`] to the typed
/// family-error variant whose structural shape matches the captured failure.
/// Routes through the canonical [`CommandAttemptFailure::is_spawn_failure`]
/// predicate: spawn failure (CLI not on PATH, fork failed, permission denied)
/// → `on_spawn`; non-zero exit (CLI ran and rejected the request) → `on_op`.
///
/// Lifts the verbatim two-arm `if failure.is_spawn_failure() { *::ExecFailed
/// {..} } else { *::PushFailed {..} }` match every typed-error producer site
/// that consumes `retry_command` carries inline:
/// `infrastructure/registry.rs::classify_push_failure` and
/// `infrastructure/attic.rs::classify_attic_push_failure`. Two
/// identically-shaped bodies past the duplication threshold the forge
/// command-module surface enforces (≥2; PRIME DIRECTIVE) — this primitive
/// is the law-redeeming consolidation for the post-`retry_command`
/// dispatch surface, the `CommandAttemptFailure`-shape dual of
/// [`classify_capture`]'s consolidation for the pre-retry
/// `io::Result<Output>`-shape surface (commit b75a273).
///
/// The closures consume the whole [`CommandAttemptFailure`] by value rather
/// than picking individual fields at the boundary, so per-family error
/// variants can read whichever subset they need by name (registry's
/// `ExecFailed` reads `failure.operation`; attic's reads only the spawn
/// message via `failure.stdout`; both `*::PushFailed` variants read
/// `failure.attempt` / `failure.exit_code` / `failure.stderr`). Passing
/// the whole record also future-proofs against per-family variants that
/// later want richer evidence — e.g., a `*::PushFailed` carrying both
/// stderr AND the trimmed stdout — without changing this primitive's
/// signature.
///
/// # The `is_spawn_failure` invariant is load-bearing
///
/// The discriminator delegates to [`CommandAttemptFailure::is_spawn_failure`]
/// — the same `exit_code.is_none() && stderr.is_empty()` shape pinned by
/// `test_classify_*_silent_op_failure_routes_to_push_failed` at both
/// migrated call sites. A future regression that broadened the predicate
/// (e.g., to `exit_code.is_none()` alone) would silently route a
/// signal-killed CLI op-failure into `*::ExecFailed`. Pinning the dispatch
/// at this primitive means a single regression test on
/// `classify_attempt_failure` covers every downstream typed-error family
/// that consumes it.
///
/// # Sibling primitives
///
/// - [`classify_capture`] / [`classify_capture_query`]: pre-retry shape
///   (raw `io::Result<Output>`). Dispatch happens BEFORE the retry loop;
///   used by direct-call-site producer sites (`git_capture`,
///   `run_nix_build_typed`, `verify_tag_exists`, `create_manifest_index`)
///   that don't drive a retry budget at all.
/// - `classify_attempt_failure` (this): post-retry shape
///   ([`CommandAttemptFailure`]). Dispatch happens AFTER the retry loop;
///   used by retry-driven typed-error producer sites
///   (`AtticClient::push_with_retries`, `RegistryClient::push_with_retries`).
///
/// Together the two primitives close the typed-error producer surface for
/// every external-CLI invocation in forge: every site routes through one
/// of the two structural shapes, and every site uses the same canonical
/// `(exit_code, stderr)` extraction discipline (UTF-8-lossy + trim) — no
/// site re-derives the match arms inline.
pub fn classify_attempt_failure<E, FSpawn, FOp>(
    failure: CommandAttemptFailure,
    on_spawn: FSpawn,
    on_op: FOp,
) -> E
where
    FSpawn: FnOnce(CommandAttemptFailure) -> E,
    FOp: FnOnce(CommandAttemptFailure) -> E,
{
    if failure.is_spawn_failure() {
        on_spawn(failure)
    } else {
        on_op(failure)
    }
}

/// Run a configured `tokio::process::Command` with stdout and stderr inherited
/// from the parent process, await its exit, and return `Ok(())` on success or
/// a structured `anyhow::Error` carrying the operation label and the
/// terminating shape (exit code, or "killed by signal" when `status.code()`
/// is `None`).
///
/// `op` is the human-readable label for the operation (e.g. `"cargo test"`,
/// `"crate2nix generate"`, `"docker-compose up"`). It feeds both the
/// spawn-context message (`"Failed to run {op}"`) and the failure message
/// (`"{op} failed ({detail})"`).
///
/// Lifts the verbatim eleven-line stanza
/// ```text
/// let status = Command::new(BIN)
///     .args(ARGS)
///     [.current_dir(DIR)]?
///     .stdout(Stdio::inherit())
///     .stderr(Stdio::inherit())
///     .status()
///     .await
///     .context(SPAWN_CTX)?;
/// if !status.success() {
///     bail!(FAIL_MSG);
/// }
/// ```
/// that more than a dozen command-module sites in forge carry verbatim modulo
/// per-site `BIN` / `ARGS` / `SPAWN_CTX` / `FAIL_MSG` — well past the
/// three-times threshold (THEORY §VI.1: "two occurrences is a coincidence;
/// three is a law"). The primitive owns the `Stdio::inherit()` wiring, the
/// `with_context` spawn-error envelope, and the structural failure message
/// (which now uniformly carries the exit code) so call sites compose down to
/// `let mut cmd = Command::new(...); cmd.args(...); run_inherited_status(cmd,
/// "...").await?;` — three lines, no inline boilerplate.
///
/// # Why a separate primitive
///
/// This is the status-only sibling of [`classify_capture`] / [`retry_command`]
/// in the canonical typed-CLI primitive set:
///
/// - [`classify_capture`] / [`classify_capture_query`]: captured-output
///   shape (`cmd.output().await`). Used by typed-error producer sites that
///   need the structured `(exit_code, stderr)` tuple in their error variants
///   (`GitError::OpFailed`, `NixBuildError::BuildFailed`, etc.).
/// - [`retry_command`]: retry-driven captured-output shape. Used by sites
///   that need the structured tuple AND drive a retry budget against a
///   transient classifier.
/// - `run_inherited_status` (this): status-only shape (`cmd.status().await`).
///   Used by sites where stdout / stderr are streamed live to the operator's
///   terminal — interactive build tools (`cargo test`, `cargo clippy`,
///   `cargo fmt`, `crate2nix generate`, `docker-compose up`) — and the
///   failure surface is just "did this thing exit zero?". Capturing
///   stdout / stderr would defeat the purpose by hiding live progress
///   from the operator.
///
/// Together the three primitives close the typed-CLI surface: every external-
/// command invocation in forge routes through one of them, with the same
/// canonical spawn-failure envelope (`Failed to run {op}`) at every site.
///
/// # The exit-code carry is load-bearing
///
/// Pre-migration the eleven-line stanza's failure messages were ad-hoc
/// (`"Tests failed"`, `"Linting failed"`, `"Formatting failed"`, etc.) — they
/// dropped the exit code that `status.code()` carries. Post-migration the
/// canonical format `"{op} failed (exit {code})"` (or
/// `"{op} failed (killed by signal)"` for `status.code() == None`) preserves
/// the exit code at the operator log surface for every migrated site by
/// construction. A future Phase 1 attestation-record consumer that wants the
/// terminating shape (THEORY §V.4) can pattern-match on the message format
/// produced by this primitive — one shape across every status-only site in
/// forge, no per-site dialect.
///
/// # Stdio override
///
/// The primitive sets `Stdio::inherit()` on the supplied `cmd` AFTER the
/// caller has had a chance to configure args, current-dir, env vars, etc.,
/// so any caller-supplied `.stdout(...)` / `.stderr(...)` is overwritten. A
/// caller that needs a different stdio shape should use `cmd.status().await`
/// directly — this primitive is the typed lift of the inherited-stdio shape
/// specifically.
pub async fn run_inherited_status(
    mut cmd: tokio::process::Command,
    op: &str,
) -> anyhow::Result<()> {
    use anyhow::Context;
    cmd.stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());
    let status = cmd
        .status()
        .await
        .with_context(|| format!("Failed to run {}", op))?;
    if !status.success() {
        let detail = match status.code() {
            Some(code) => format!("exit {}", code),
            None => "killed by signal".to_string(),
        };
        anyhow::bail!("{} failed ({})", op, detail);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    /// HTTP 5xx in numeric form must match — skopeo/regctl emit numeric.
    #[test]
    fn test_transient_classifier_matches_http_5xx_numeric() {
        assert!(is_transient_network_stderr(
            "manifest invalid: 500 Internal Server Error"
        ));
        assert!(is_transient_network_stderr(
            "received unexpected HTTP status: 502"
        ));
        assert!(is_transient_network_stderr(
            "registry returned 503 (retry-after: 5s)"
        ));
        assert!(is_transient_network_stderr("upstream said 504"));
    }

    /// HTTP 5xx in named form must match — attic/curl emit named.
    #[test]
    fn test_transient_classifier_matches_http_5xx_named() {
        assert!(is_transient_network_stderr("Bad Gateway from cdn"));
        assert!(is_transient_network_stderr(
            "Service Unavailable; please retry"
        ));
        assert!(is_transient_network_stderr("Internal Server Error"));
        assert!(is_transient_network_stderr(
            "InternalServerError: cache write failed"
        ));
        assert!(is_transient_network_stderr("Gateway Timeout"));
    }

    /// Connection-level failures must match in both Go-stdlib lowercase
    /// and curl mixed-case dialects.
    #[test]
    fn test_transient_classifier_matches_connection_failures() {
        assert!(is_transient_network_stderr(
            "dial tcp 1.2.3.4:443: connect: connection refused"
        ));
        assert!(is_transient_network_stderr(
            "curl: Connection refused on attempt"
        ));
        assert!(is_transient_network_stderr(
            "read tcp: connection reset by peer"
        ));
        assert!(is_transient_network_stderr("Connection reset"));
        assert!(is_transient_network_stderr(
            "Connection aborted by remote endpoint"
        ));
    }

    /// I/O timeouts and TLS handshake timeouts are transient.
    #[test]
    fn test_transient_classifier_matches_timeouts() {
        assert!(is_transient_network_stderr(
            "read tcp 10.0.0.1: i/o timeout"
        ));
        assert!(is_transient_network_stderr(
            "TLS handshake timeout after 30s"
        ));
        // Bare "timeout" — the substring catches the broader class.
        assert!(is_transient_network_stderr("operation timeout reached"));
    }

    /// Mid-stream EOF (TCP drop while a response is streaming) is transient.
    #[test]
    fn test_transient_classifier_matches_eof() {
        assert!(is_transient_network_stderr("post manifest: unexpected EOF"));
        assert!(is_transient_network_stderr("read body: EOF"));
    }

    /// Empty stderr must NOT be classified transient. A typed error whose
    /// record carries no stderr (ExecFailed, TokenRequired,
    /// LocalImageNotFound) must short-circuit, not retry.
    #[test]
    fn test_transient_classifier_empty_stderr_is_terminal() {
        assert!(!is_transient_network_stderr(""));
    }

    /// Terminal failures common to skopeo / regctl / attic / git must NOT
    /// match. Pinning these explicitly is the load-bearing test: if a
    /// future marker is added that swallows one of these, the regression
    /// shows up here, not in production via burned retry budget.
    #[test]
    fn test_transient_classifier_terminal_failures_do_not_match() {
        // skopeo / regctl
        assert!(!is_transient_network_stderr(
            "401 Unauthorized: bad credentials"
        ));
        assert!(!is_transient_network_stderr("403 Forbidden: denied"));
        assert!(!is_transient_network_stderr(
            "404 manifest unknown: ghcr.io/o/p"
        ));
        assert!(!is_transient_network_stderr(
            "manifest invalid: bad image config digest"
        ));
        // git
        assert!(!is_transient_network_stderr(
            "fatal: remote rejected: pre-receive hook declined"
        ));
        assert!(!is_transient_network_stderr(
            "non-fast-forward: tip of branch is behind remote"
        ));
        // attic
        assert!(!is_transient_network_stderr(
            "configuration error: cache 'foo' not found"
        ));
        // exec-missing
        assert!(!is_transient_network_stderr("skopeo: command not found"));
        assert!(!is_transient_network_stderr(
            "No such file or directory (os error 2)"
        ));
    }

    /// An HTTP 4xx error code embedded in a message must NOT match the
    /// 5xx markers. Specifically, "400 Bad Request" must not trip the
    /// "Bad Gateway" marker (different word) or any 5xx numeric.
    #[test]
    fn test_transient_classifier_4xx_does_not_match() {
        assert!(!is_transient_network_stderr("400 Bad Request"));
        assert!(!is_transient_network_stderr("429 Too Many Requests"));
    }

    /// `compute_delay` is a pure function of `attempt`. Pin the schedule
    /// directly so a future schedule change shows up as a test diff, not
    /// as a silent regression.
    #[test]
    fn test_compute_delay_first_attempt_is_zero() {
        let p = RetryPolicy::network();
        assert_eq!(p.compute_delay(0), Duration::ZERO);
        assert_eq!(p.compute_delay(1), Duration::ZERO);
    }

    #[test]
    fn test_compute_delay_exponential_growth() {
        let p = RetryPolicy {
            max_attempts: 10,
            initial_backoff: Duration::from_millis(100),
            factor: 2,
            max_backoff: Duration::from_secs(60),
        };
        assert_eq!(p.compute_delay(2), Duration::from_millis(100));
        assert_eq!(p.compute_delay(3), Duration::from_millis(200));
        assert_eq!(p.compute_delay(4), Duration::from_millis(400));
        assert_eq!(p.compute_delay(5), Duration::from_millis(800));
    }

    #[test]
    fn test_compute_delay_capped_at_max() {
        let p = RetryPolicy {
            max_attempts: 20,
            initial_backoff: Duration::from_millis(100),
            factor: 2,
            max_backoff: Duration::from_millis(500),
        };
        assert_eq!(p.compute_delay(2), Duration::from_millis(100));
        assert_eq!(p.compute_delay(3), Duration::from_millis(200));
        assert_eq!(p.compute_delay(4), Duration::from_millis(400));
        assert_eq!(p.compute_delay(5), Duration::from_millis(500), "capped");
        assert_eq!(
            p.compute_delay(50),
            Duration::from_millis(500),
            "still capped"
        );
    }

    /// Overflow of `factor.pow(exp)` must collapse to `max_backoff`, not
    /// panic. Pin against an absurd `attempt` value so the saturation path
    /// is exercised.
    #[test]
    fn test_compute_delay_does_not_panic_on_huge_attempt() {
        let p = RetryPolicy {
            max_attempts: u32::MAX,
            initial_backoff: Duration::from_secs(1),
            factor: 1_000_000,
            max_backoff: Duration::from_secs(30),
        };
        assert_eq!(p.compute_delay(u32::MAX), Duration::from_secs(30));
    }

    #[test]
    fn test_immediate_policy_never_sleeps() {
        let p = RetryPolicy::immediate();
        for n in 0..16 {
            assert_eq!(p.compute_delay(n), Duration::ZERO);
        }
    }

    #[test]
    fn test_network_policy_defaults_match_documented_shape() {
        let p = RetryPolicy::network();
        assert_eq!(p.max_attempts, 5);
        assert_eq!(p.initial_backoff, Duration::from_millis(250));
        assert_eq!(p.factor, 2);
        assert_eq!(p.max_backoff, Duration::from_secs(30));
    }

    #[test]
    fn test_new_clamps_zero_max_attempts() {
        let p = RetryPolicy::new(0, Duration::ZERO, 1, Duration::ZERO);
        assert_eq!(p.max_attempts, 1, "max_attempts must clamp up to 1");
    }

    /// `with_max_attempts` overrides the budget without touching the
    /// schedule. The two retry-driven typed-error producer sites that drive
    /// `RetryPolicy::network().with_max_attempts(retries)`
    /// (`AtticClient::push_with_retries`, `RegistryClient::push_with_retries`)
    /// rely on this — the canonical Bazel/Buck2/SLSA-shape exponential
    /// schedule (250ms × factor=2 capped at 30s) must survive the override
    /// verbatim. A future regression that perturbed the schedule fields
    /// (e.g., reset `max_backoff` to zero) would silently turn every
    /// retry-driven push into a fixed-zero-backoff loop, hammering the
    /// upstream cache/registry on every transient. Pinning every schedule
    /// field at the primitive boundary catches that here.
    #[test]
    fn test_with_max_attempts_preserves_network_schedule() {
        let net = RetryPolicy::network();
        let p = net.clone().with_max_attempts(7);
        assert_eq!(p.max_attempts, 7, "max_attempts must take the override");
        assert_eq!(
            p.initial_backoff, net.initial_backoff,
            "initial_backoff must survive the override verbatim"
        );
        assert_eq!(
            p.factor, net.factor,
            "factor must survive the override verbatim"
        );
        assert_eq!(
            p.max_backoff, net.max_backoff,
            "max_backoff must survive the override verbatim"
        );
    }

    /// `with_max_attempts(0)` clamps to `1` — same discipline as
    /// [`RetryPolicy::new`]. The clamp is load-bearing because the two
    /// public-API call sites
    /// (`AtticClient::push_with_retries(_, retries: u32)`,
    /// `RegistryClient::push_with_retries(_, _, _, retries: u32)`) accept a
    /// caller-supplied `retries` value; without the clamp, a `0` would
    /// produce a policy whose `max_attempts: 0` makes
    /// `run_with_policy`'s `attempt >= max` predicate true on the first
    /// call, returning the first error without ever consuming the retry
    /// budget — visible only in attempt-count telemetry, not in the
    /// typed-error surface. Pinning the clamp here (and not relying on
    /// `RetryPolicy::new`'s clamp, since `with_max_attempts` does not call
    /// `new`) closes that drift path by construction.
    #[test]
    fn test_with_max_attempts_clamps_zero_to_one() {
        let p = RetryPolicy::network().with_max_attempts(0);
        assert_eq!(p.max_attempts, 1, "with_max_attempts(0) must clamp up to 1");
        // Schedule still survives the clamp verbatim — the clamp targets
        // only `max_attempts`.
        let net = RetryPolicy::network();
        assert_eq!(p.initial_backoff, net.initial_backoff);
        assert_eq!(p.factor, net.factor);
        assert_eq!(p.max_backoff, net.max_backoff);
    }

    /// `with_max_attempts` composes with both factory constructors. The
    /// `immediate()` composition is structurally degenerate
    /// (`initial_backoff: ZERO` makes every `compute_delay` zero
    /// regardless of `max_attempts`), but must compose cleanly without a
    /// special case — a future caller that wants a "no-backoff but N
    /// attempts" shape can express it without reaching for
    /// `RetryPolicy::new` directly.
    #[test]
    fn test_with_max_attempts_composes_with_immediate() {
        let p = RetryPolicy::immediate().with_max_attempts(4);
        assert_eq!(p.max_attempts, 4);
        assert_eq!(p.initial_backoff, Duration::ZERO);
        assert_eq!(p.compute_delay(2), Duration::ZERO);
        assert_eq!(p.compute_delay(10), Duration::ZERO);
    }

    /// `with_max_attempts` is idempotent under repeat-application: the
    /// last call wins, the schedule still survives. Pins that the builder
    /// does not accumulate state across chained calls (a future
    /// regression that turned the override into an additive `+=` would
    /// silently double the budget on chained calls — invisible in
    /// production except as a longer worst-case retry storm).
    #[test]
    fn test_with_max_attempts_repeated_application_takes_last() {
        let p = RetryPolicy::network()
            .with_max_attempts(3)
            .with_max_attempts(9);
        assert_eq!(p.max_attempts, 9, "last call must win");
        let net = RetryPolicy::network();
        assert_eq!(p.initial_backoff, net.initial_backoff);
        assert_eq!(p.factor, net.factor);
        assert_eq!(p.max_backoff, net.max_backoff);
    }

    /// Success on the first call must not retry. `op` is invoked exactly
    /// once.
    #[tokio::test]
    async fn test_run_with_policy_first_success_calls_op_once() {
        let p = RetryPolicy::immediate();
        let calls = Arc::new(AtomicU32::new(0));
        let calls_clone = calls.clone();
        let result: Result<&'static str, &'static str> = run_with_policy(
            &p,
            |_| true,
            |_| {
                let calls = calls_clone.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, &'static str>("ok")
                }
            },
        )
        .await;
        assert_eq!(result.unwrap(), "ok");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// Always-transient failure must invoke `op` exactly `max_attempts`
    /// times and return the LAST error (no synthetic wrapper). Uses
    /// `Duration::ZERO` for the backoff so the test runs in nanoseconds.
    #[tokio::test]
    async fn test_run_with_policy_exhausts_attempts_and_returns_last_error() {
        let p = RetryPolicy::new(4, Duration::ZERO, 2, Duration::ZERO);
        let calls = Arc::new(AtomicU32::new(0));
        let calls_clone = calls.clone();
        let result: Result<(), u32> = run_with_policy(
            &p,
            |_| true,
            |attempt| {
                let calls = calls_clone.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Err::<(), u32>(attempt)
                }
            },
        )
        .await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            4,
            "must call op exactly 4 times"
        );
        assert_eq!(
            result.unwrap_err(),
            4,
            "returned error must be the LAST attempt's, not a synthetic wrapper"
        );
    }

    /// Terminal failure (classifier returns false) must short-circuit:
    /// `op` is invoked exactly once even when budget remains.
    #[tokio::test]
    async fn test_run_with_policy_terminal_short_circuits() {
        let p = RetryPolicy::new(10, Duration::ZERO, 2, Duration::ZERO);
        let calls = Arc::new(AtomicU32::new(0));
        let calls_clone = calls.clone();
        let result: Result<(), &'static str> = run_with_policy(
            &p,
            |_| false,
            |_| {
                let calls = calls_clone.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Err::<(), &'static str>("terminal")
                }
            },
        )
        .await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "terminal must short-circuit"
        );
        assert_eq!(result.unwrap_err(), "terminal");
    }

    /// Eventual success — fail twice, then succeed on the third call.
    /// Verifies the loop stops the moment Ok arrives.
    #[tokio::test]
    async fn test_run_with_policy_eventual_success() {
        let p = RetryPolicy::new(5, Duration::ZERO, 2, Duration::ZERO);
        let calls = Arc::new(AtomicU32::new(0));
        let calls_clone = calls.clone();
        let result: Result<u32, &'static str> = run_with_policy(
            &p,
            |_| true,
            |attempt| {
                let calls = calls_clone.clone();
                async move {
                    let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
                    if n < 3 {
                        Err::<u32, &'static str>("transient")
                    } else {
                        Ok(attempt)
                    }
                }
            },
        )
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert_eq!(result.unwrap(), 3, "succeeded on attempt 3");
    }

    /// `op` receives the 1-indexed attempt number on every call. This is
    /// the contract `RegistryError::PushFailed.attempts` and friends rely
    /// on to surface the correct attempt count without a separate counter.
    #[tokio::test]
    async fn test_run_with_policy_passes_attempt_index() {
        let p = RetryPolicy::new(3, Duration::ZERO, 2, Duration::ZERO);
        let seen = Arc::new(std::sync::Mutex::new(Vec::<u32>::new()));
        let seen_clone = seen.clone();
        let _: Result<(), u32> = run_with_policy(
            &p,
            |_| true,
            |attempt| {
                let seen = seen_clone.clone();
                async move {
                    seen.lock().unwrap().push(attempt);
                    Err::<(), u32>(attempt)
                }
            },
        )
        .await;
        assert_eq!(*seen.lock().unwrap(), vec![1, 2, 3]);
    }

    /// `CommandAttemptFailure::is_transient` must return true on stderr
    /// matching a canonical 5xx / connection / timeout / EOF marker. Pins
    /// the typed structural-record shape that ad-hoc retry sites consume
    /// instead of carrying their own substring lists.
    #[test]
    fn test_command_attempt_failure_is_transient_on_5xx() {
        let f = CommandAttemptFailure {
            operation: "push to Attic cache".to_string(),
            attempt: 2,
            exit_code: Some(1),
            stderr: "received unexpected HTTP status: 503".to_string(),
            stdout: String::new(),
        };
        assert!(f.is_transient());
    }

    /// Terminal failures (auth, not-found, manifest mismatch) must NOT
    /// be classified transient — they must short-circuit the retry loop
    /// instead of burning the full budget × backoff.
    #[test]
    fn test_command_attempt_failure_is_not_transient_on_terminal() {
        let f = CommandAttemptFailure {
            operation: "login to Attic".to_string(),
            attempt: 1,
            exit_code: Some(1),
            stderr: "401 Unauthorized: bad token".to_string(),
            stdout: String::new(),
        };
        assert!(!f.is_transient());
    }

    /// Empty stderr — the spawn-failure path (`Command::output()` failed,
    /// or the process exited with no stderr) — must be terminal. A
    /// "binary not on PATH" precondition must never burn retry budget.
    #[test]
    fn test_command_attempt_failure_empty_stderr_is_terminal() {
        let f = CommandAttemptFailure {
            operation: "push image".to_string(),
            attempt: 1,
            exit_code: None,
            stderr: String::new(),
            stdout: "skopeo: command not found".to_string(),
        };
        assert!(!f.is_transient());
    }

    /// Display surfaces operation, exit code, attempt — the structural
    /// tuple downstream telemetry / attestation expects on the failure
    /// record. Must NOT lose any field by fusing them into a single
    /// stringly anyhow::bail!() (which is what the hand-rolled loops did).
    #[test]
    fn test_command_attempt_failure_display_surfaces_fields() {
        let f = CommandAttemptFailure {
            operation: "push ghcr.io/o/p:abc1234".to_string(),
            attempt: 3,
            exit_code: Some(2),
            stderr: "manifest invalid: 503".to_string(),
            stdout: String::new(),
        };
        let s = f.to_string();
        assert!(s.contains("push ghcr.io/o/p:abc1234"));
        assert!(s.contains("manifest invalid: 503"));
        assert!(s.contains("exit Some(2)"));
        assert!(s.contains("attempt 3"));
    }

    /// Display falls back to stdout when stderr is empty. Pins the
    /// fallback chain stderr → stdout → "(no captured output)" so a
    /// future caller never produces a record with no human-readable
    /// detail.
    #[test]
    fn test_command_attempt_failure_display_falls_back_to_stdout() {
        let f = CommandAttemptFailure {
            operation: "use cache".to_string(),
            attempt: 1,
            exit_code: Some(1),
            stderr: String::new(),
            stdout: "configuration error: cache 'foo' not found".to_string(),
        };
        let s = f.to_string();
        assert!(s.contains("configuration error: cache 'foo' not found"));
    }

    /// Final fallback when both stderr and stdout are empty. The record
    /// still surfaces operation + exit_code + attempt so telemetry can
    /// pin the failing call site even when the tool produces no output.
    #[test]
    fn test_command_attempt_failure_display_no_output_fallback() {
        let f = CommandAttemptFailure {
            operation: "noisy op".to_string(),
            attempt: 5,
            exit_code: None,
            stderr: String::new(),
            stdout: String::new(),
        };
        let s = f.to_string();
        assert!(s.contains("(no captured output)"));
        assert!(s.contains("noisy op"));
        assert!(s.contains("attempt 5"));
    }

    /// Classifier closure shaped like the one inside the migrated retry
    /// helpers: drives `run_with_policy` so a transient
    /// `CommandAttemptFailure` retries while a terminal one
    /// short-circuits. Mirrors the discipline registry.rs adopted for
    /// `RegistryError::PushFailed` (ff89296), now applied to the
    /// structural-record shape ad-hoc helpers consume.
    #[tokio::test]
    async fn test_run_with_policy_consumes_command_attempt_failure() {
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;

        // Transient: classifier returns true on 503; loop retries until
        // exhaustion and returns the LAST error.
        let p = RetryPolicy::new(3, Duration::ZERO, 1, Duration::ZERO);
        let calls = Arc::new(AtomicU32::new(0));
        let calls_clone = calls.clone();
        let res: Result<(), CommandAttemptFailure> = run_with_policy(
            &p,
            |e: &CommandAttemptFailure| e.is_transient(),
            move |attempt| {
                let calls = calls_clone.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Err(CommandAttemptFailure {
                        operation: "test".to_string(),
                        attempt,
                        exit_code: Some(1),
                        stderr: "503 Service Unavailable".to_string(),
                        stdout: String::new(),
                    })
                }
            },
        )
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        let err = res.unwrap_err();
        assert_eq!(err.attempt, 3, "last error must carry final attempt count");

        // Terminal: classifier returns false on 401; loop short-circuits
        // after a single call.
        let calls = Arc::new(AtomicU32::new(0));
        let calls_clone = calls.clone();
        let res: Result<(), CommandAttemptFailure> = run_with_policy(
            &p,
            |e: &CommandAttemptFailure| e.is_transient(),
            move |attempt| {
                let calls = calls_clone.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Err(CommandAttemptFailure {
                        operation: "test".to_string(),
                        attempt,
                        exit_code: Some(1),
                        stderr: "401 Unauthorized".to_string(),
                        stdout: String::new(),
                    })
                }
            },
        )
        .await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "terminal must short-circuit on first attempt"
        );
        assert!(res.is_err());
    }

    /// `max_attempts = 1` is "no retry": a transient error returns
    /// immediately without consulting the classifier or sleeping.
    #[tokio::test]
    async fn test_run_with_policy_max_one_means_no_retry() {
        let p = RetryPolicy::immediate();
        let calls = Arc::new(AtomicU32::new(0));
        let calls_clone = calls.clone();
        let result: Result<(), &'static str> = run_with_policy(
            &p,
            |_| true,
            |_| {
                let calls = calls_clone.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Err::<(), &'static str>("once")
                }
            },
        )
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(result.unwrap_err(), "once");
    }

    /// Helper: synthesize a `std::process::Output` with the given exit
    /// status, stdout, and stderr. Lets the `from_capture` tests pin the
    /// typed conversion without driving a real subprocess.
    fn synth_output(success: bool, stdout: &[u8], stderr: &[u8]) -> std::process::Output {
        // ExitStatus has no public constructor; produce one by running a
        // trivial host binary whose exit code is deterministic. `true`
        // (exit 0) and `false` (exit 1) ship on every platform forge
        // targets and the OS-level fork is a few hundred microseconds.
        let bin = if success { "true" } else { "false" };
        let status = std::process::Command::new(bin)
            .status()
            .expect("host must provide /usr/bin/true and /usr/bin/false for the test runner");
        std::process::Output {
            status,
            stdout: stdout.to_vec(),
            stderr: stderr.to_vec(),
        }
    }

    /// Success case — `from_capture` returns the captured `Output` so
    /// callers can still read stdout/stderr (e.g., for debug-logging the
    /// happy path).
    #[test]
    fn test_from_capture_success_returns_output() {
        let out = synth_output(true, b"hello", b"");
        let result = CommandAttemptFailure::from_capture(Ok(out), "test op", 1);
        let captured = result.expect("success must return Output");
        assert!(captured.status.success());
        assert_eq!(captured.stdout, b"hello");
    }

    /// Non-zero exit — `from_capture` produces a typed record carrying
    /// `(operation, attempt, exit_code, stderr, stdout)` as separate
    /// destructurable fields. Pins the structural-record shape against a
    /// future "fuse them into a single message" regression.
    #[test]
    fn test_from_capture_non_zero_exit_carries_structured_fields() {
        let out = synth_output(false, b" raw stdout \n", b"  503 Service Unavailable\n");
        let err = CommandAttemptFailure::from_capture(Ok(out), "push ghcr.io/o/p:tag", 7)
            .expect_err("non-zero exit must produce a failure record");
        assert_eq!(err.operation, "push ghcr.io/o/p:tag");
        assert_eq!(err.attempt, 7);
        // `false` exits with code 1 on every Unix; pin only that the
        // exit_code is present and non-zero.
        assert!(err.exit_code.is_some());
        assert_ne!(err.exit_code, Some(0));
        // stderr / stdout trimmed of leading/trailing whitespace.
        assert_eq!(err.stderr, "503 Service Unavailable");
        assert_eq!(err.stdout, "raw stdout");
        // The transient classifier sees the trimmed stderr and matches.
        assert!(err.is_transient());
    }

    /// Spawn-failure path — `Err(io::Error)` produces a record with
    /// `exit_code: None`, EMPTY `stderr`, and the spawn error in
    /// `stdout`. Empty stderr is the load-bearing invariant: it makes
    /// the record terminal under [`is_transient_network_stderr`] so the
    /// retry loop never burns budget on a "binary not on PATH"
    /// precondition. This is the same discipline the prior typed-error
    /// `ExecFailed` variants (Registry, Nix, Attic, Git) adopted —
    /// every spawn-failure path on every external-CLI surface in forge
    /// short-circuits the retry loop by construction.
    #[test]
    fn test_from_capture_spawn_failure_is_terminal_by_construction() {
        let spawn_err = std::io::Error::new(std::io::ErrorKind::NotFound, "no such file");
        let captured: Result<std::process::Output, std::io::Error> = Err(spawn_err);
        let err = CommandAttemptFailure::from_capture(captured, "spawn missing tool", 3)
            .expect_err("spawn failure must produce a record");
        assert_eq!(err.operation, "spawn missing tool");
        assert_eq!(err.attempt, 3);
        assert_eq!(err.exit_code, None);
        assert!(
            err.stderr.is_empty(),
            "stderr MUST be empty so the classifier short-circuits"
        );
        assert!(
            !err.is_transient(),
            "spawn-failure record MUST be terminal — empty stderr → terminal by construction"
        );
        assert!(err.stdout.contains("failed to spawn process"));
        assert!(err.stdout.contains("no such file"));
    }

    /// `is_spawn_failure()` discriminates the two structural shapes
    /// `from_capture` produces: a spawn-failure (`Err(io::Error)` →
    /// `exit_code: None` + empty stderr) returns `true`; a non-zero exit
    /// (`Ok(out)` with stderr populated) returns `false`. This is the
    /// post-`retry_command` dispatch shape typed-error producer sites
    /// consume to choose between `*::ExecFailed` (spawn could not run
    /// the CLI) and `*::PushFailed` / `*::OpFailed` / `*::BuildFailed`
    /// (CLI ran and rejected the request), without substring-parsing
    /// the failure message.
    #[test]
    fn test_is_spawn_failure_discriminates_spawn_from_op() {
        // Spawn-failure: produced by the `Err(io::Error)` arm of
        // from_capture. exit_code: None + empty stderr.
        let spawn_err = std::io::Error::new(std::io::ErrorKind::NotFound, "no such file");
        let captured: Result<std::process::Output, std::io::Error> = Err(spawn_err);
        let f = CommandAttemptFailure::from_capture(captured, "exec missing", 1)
            .expect_err("spawn failure must produce a record");
        assert!(f.is_spawn_failure(), "spawn failure must discriminate true");

        // Op-failure: produced by the `Ok(out)` non-success arm of
        // from_capture. exit_code: Some(_) + non-empty stderr.
        let out = synth_output(false, b"", b"401 Unauthorized");
        let f = CommandAttemptFailure::from_capture(Ok(out), "auth op", 1)
            .expect_err("non-zero exit must produce a record");
        assert!(
            !f.is_spawn_failure(),
            "op failure (CLI ran with stderr) must NOT discriminate as spawn"
        );

        // Op-failure with transient stderr: also not a spawn failure.
        let out = synth_output(false, b"", b"503 Service Unavailable");
        let f = CommandAttemptFailure::from_capture(Ok(out), "transient op", 1)
            .expect_err("non-zero exit must produce a record");
        assert!(!f.is_spawn_failure());
        assert!(f.is_transient(), "transient op must remain transient");
    }

    /// `is_spawn_failure()` and `is_transient()` are independent
    /// predicates: every spawn-failure is terminal (because empty
    /// stderr cannot trip the transient classifier), but a terminal
    /// failure is NOT necessarily a spawn-failure (auth-fail / 404 /
    /// manifest-mismatch all have non-empty stderr but are terminal).
    /// Pinning this guards against a future regression that conflates
    /// the two predicates — typed-error producer sites depend on
    /// `is_spawn_failure()` discriminating the structural shape, NOT
    /// the classifier's transient/terminal verdict.
    #[test]
    fn test_is_spawn_failure_independent_of_is_transient() {
        // Terminal op (401) — not transient, not a spawn failure.
        let f = CommandAttemptFailure {
            operation: "x".to_string(),
            attempt: 1,
            exit_code: Some(1),
            stderr: "401 Unauthorized".to_string(),
            stdout: String::new(),
        };
        assert!(!f.is_transient());
        assert!(!f.is_spawn_failure());

        // Spawn failure — not transient, IS a spawn failure.
        let f = CommandAttemptFailure {
            operation: "x".to_string(),
            attempt: 1,
            exit_code: None,
            stderr: String::new(),
            stdout: "failed to spawn process: no such file".to_string(),
        };
        assert!(!f.is_transient());
        assert!(f.is_spawn_failure());
    }

    /// `from_capture` Display surfaces the same five-field tuple
    /// downstream telemetry / attestation expects, regardless of whether
    /// the failure came from a non-zero exit or a spawn error. The
    /// fallback chain stderr → stdout → "(no captured output)" remains
    /// intact across the typed mapping.
    #[test]
    fn test_from_capture_display_preserves_fallback_chain() {
        // Spawn-failure: stderr empty → Display falls back to stdout
        // (which carries the spawn-error message).
        let spawn_err = std::io::Error::other("permission denied");
        let captured: Result<std::process::Output, std::io::Error> = Err(spawn_err);
        let err = CommandAttemptFailure::from_capture(captured, "exec foo", 1)
            .expect_err("spawn failure must produce a record");
        let s = err.to_string();
        assert!(s.contains("exec foo"));
        assert!(s.contains("permission denied"));
        assert!(s.contains("attempt 1"));
    }

    /// `from_capture` drives `run_with_policy` end-to-end: a transient
    /// stderr (HTTP 503) retries to exhaustion; a spawn failure
    /// short-circuits on the first attempt. Pins that the typed mapping
    /// composes correctly with the canonical retry primitive — no
    /// inter-primitive glue is needed at the call site.
    #[tokio::test]
    async fn test_from_capture_composes_with_run_with_policy() {
        // Spawn failure: short-circuits on attempt 1.
        let p = RetryPolicy::new(5, Duration::ZERO, 1, Duration::ZERO);
        let calls = Arc::new(AtomicU32::new(0));
        let calls_clone = calls.clone();
        let result: Result<(), CommandAttemptFailure> = run_with_policy(
            &p,
            |e: &CommandAttemptFailure| e.is_transient(),
            move |attempt| {
                let calls = calls_clone.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    let captured: Result<std::process::Output, std::io::Error> =
                        Err(std::io::Error::new(std::io::ErrorKind::NotFound, "x"));
                    CommandAttemptFailure::from_capture(captured, "spawn x", attempt).map(|_| ())
                }
            },
        )
        .await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "spawn failure (empty stderr) must be terminal — single attempt only"
        );
        assert!(result.is_err());
    }

    /// `CapturedFailure::from_output` extracts `(exit_code, stderr)`
    /// from any `Output`. Pins the canonical extraction shape every
    /// typed-error producer site (`GitError::OpFailed`,
    /// `NixBuildError::BuildFailed`, `AtticError::PushFailed`,
    /// `RegistryError::PushFailed`) consumes. The canonical
    /// `(output.status.code(), String::from_utf8_lossy(&stderr).trim())`
    /// incantation lives in one place — drift across the five sites
    /// becomes structurally impossible.
    #[test]
    fn test_captured_failure_from_output_extracts_exit_code_and_stderr() {
        let out = synth_output(false, b"", b"403 Forbidden");
        let cf = CapturedFailure::from_output(&out);
        // `false` exits with code 1 on every Unix forge targets.
        assert!(cf.exit_code.is_some());
        assert_ne!(cf.exit_code, Some(0));
        assert_eq!(cf.stderr, "403 Forbidden");
    }

    /// Trim discipline is load-bearing: the canonical
    /// [`is_transient_network_stderr`] substring matcher operates on the
    /// `stderr` field directly, so a leading/trailing newline or space
    /// would otherwise change which substrings match. Pins the trim at
    /// the typed primitive so a future site can't drift on this
    /// (silently changing classifier behaviour for any tool whose
    /// stderr ends in `\n`, which is most of them).
    #[test]
    fn test_captured_failure_from_output_trims_leading_and_trailing_whitespace() {
        let out = synth_output(false, b"", b"  \n\tservice unavailable\n  ");
        let cf = CapturedFailure::from_output(&out);
        assert_eq!(cf.stderr, "service unavailable");
    }

    /// Internal whitespace MUST be preserved. A multi-line tool
    /// diagnostic must survive the round-trip into the typed `*Failed`
    /// variant unchanged in the middle — only the edges are stripped.
    /// Without this guard a future "normalize all whitespace" refactor
    /// would silently lose newlines that a downstream consumer (a log
    /// renderer, a test that asserts on a specific marker phrase across
    /// lines) depends on.
    #[test]
    fn test_captured_failure_from_output_preserves_internal_whitespace() {
        let out = synth_output(false, b"", b"line one\nline two\n\nline four\n");
        let cf = CapturedFailure::from_output(&out);
        assert_eq!(cf.stderr, "line one\nline two\n\nline four");
    }

    /// UTF-8-lossy decode MUST NOT panic on invalid UTF-8 in stderr.
    /// Build tools that pipe binary log fragments (Nix store paths
    /// rendered with embedded ANSI sequences, raw blob digests printed
    /// as-is) emit invalid UTF-8 by accident; the typed primitive
    /// guarantees the canonical decode never panics, so a transient
    /// build failure cannot manifest as a Rust panic in the producer
    /// site. Pinned by feeding 0xFF (an invalid lead byte) through.
    #[test]
    fn test_captured_failure_from_output_handles_invalid_utf8() {
        let out = synth_output(false, b"", &[0xFF, 0xFE, b' ', b'h', b'i']);
        let cf = CapturedFailure::from_output(&out);
        // The two invalid bytes get replaced with U+FFFD (3 bytes each
        // in UTF-8); the trim chops the leading space we put in the
        // input and leaves "hi" at the tail. Pin only that the decode
        // produced a valid string ending in "hi" without panicking.
        assert!(cf.stderr.ends_with("hi"));
        assert!(!cf.stderr.is_empty());
    }

    /// `from_output_if_failed` returns `Some(CapturedFailure)` on a
    /// non-zero exit. Pins the producer-site contract: any caller that
    /// folds "did this command succeed?" into one expression
    /// (`if let Some(cf) = ... { return Err(...) }`) must see the
    /// failure record only when the command failed.
    #[test]
    fn test_captured_failure_from_output_if_failed_some_on_nonzero() {
        let out = synth_output(false, b"", b"i/o timeout");
        let cf = CapturedFailure::from_output_if_failed(&out)
            .expect("non-zero exit must produce a CapturedFailure");
        assert!(cf.exit_code.is_some());
        assert_ne!(cf.exit_code, Some(0));
        assert_eq!(cf.stderr, "i/o timeout");
    }

    /// Load-bearing inverse: `from_output_if_failed` returns `None` on
    /// a zero exit. A future regression that returned `Some` on success
    /// would silently turn every successful invocation across the five
    /// migrated producer sites into a typed `*Failed` variant — the
    /// `if let Some(cf) = ...` arm at each site would fire and bail
    /// with a synthetic exit-0 record. Pin against that.
    #[test]
    fn test_captured_failure_from_output_if_failed_none_on_success() {
        let out = synth_output(true, b"hello", b"warnings emitted");
        assert!(
            CapturedFailure::from_output_if_failed(&out).is_none(),
            "from_output_if_failed MUST return None on a zero-exit Output \
             so success paths do not bail with a synthetic failure record"
        );
    }

    /// Pin the typed-record shape against renames. Every typed-error
    /// `*Failed` variant in `cli/src/error.rs` (RegistryError::PushFailed,
    /// GitError::OpFailed / RemoteOpFailed, NixBuildError::BuildFailed,
    /// AtticError::PushFailed / LoginFailed) accesses `cf.exit_code`
    /// and `cf.stderr` by name. Renaming either field on the typed
    /// primitive without updating the five producer sites would compile
    /// (because the field initializers in `*Failed` would silently
    /// inherit the new name via the local binding). This test wires
    /// `CapturedFailure` through a typed-record constructor that
    /// destructures by name, so a future rename forces the test (and
    /// thus every producer site) to update in lockstep.
    #[test]
    fn test_captured_failure_field_names_are_load_bearing() {
        let out = synth_output(false, b"", b"503 Service Unavailable");
        let CapturedFailure { exit_code, stderr } = CapturedFailure::from_output(&out);
        // Round-trip through the canonical classifier — proves the
        // typed primitive's stderr field is wired to the substring
        // matcher every typed-error variant's classifier closure
        // ultimately consumes.
        assert!(is_transient_network_stderr(&stderr));
        assert!(exit_code.is_some());
    }

    /// `retry_command` returns the captured `Output` verbatim on the
    /// first zero-exit attempt — `spawn` is invoked exactly once and
    /// the loop short-circuits without consulting the classifier.
    #[tokio::test]
    async fn test_retry_command_first_success_returns_output() {
        let p = RetryPolicy::immediate();
        let calls = Arc::new(AtomicU32::new(0));
        let calls_clone = calls.clone();
        let result = retry_command(&p, "echo hello", move |_attempt| {
            let calls = calls_clone.clone();
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(synth_output(true, b"hello\n", b""))
            }
        })
        .await;
        let output = result.expect("zero-exit must return Output");
        assert!(output.status.success());
        assert_eq!(output.stdout, b"hello\n");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// Always-transient failure (HTTP 503 in stderr) must invoke
    /// `spawn` exactly `max_attempts` times and return the LAST
    /// `CommandAttemptFailure` — no synthetic wrapper. Pins that
    /// `retry_command` composes the canonical classifier with the
    /// canonical `from_capture` mapping end-to-end, so callers never
    /// need to thread `|e: &CommandAttemptFailure| e.is_transient()`
    /// or `CommandAttemptFailure::from_capture(...)` through their
    /// retry call sites.
    #[tokio::test]
    async fn test_retry_command_exhausts_on_transient_stderr() {
        let p = RetryPolicy::new(4, Duration::ZERO, 1, Duration::ZERO);
        let calls = Arc::new(AtomicU32::new(0));
        let calls_clone = calls.clone();
        let result = retry_command(&p, "push transient", move |_attempt| {
            let calls = calls_clone.clone();
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(synth_output(
                    false,
                    b"",
                    b"received unexpected HTTP status: 503",
                ))
            }
        })
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 4, "must exhaust attempts");
        let err = result.expect_err("transient exhaustion must produce Err");
        assert_eq!(err.attempt, 4, "last error must carry final attempt");
        assert_eq!(err.operation, "push transient");
        assert!(err.is_transient());
        assert!(err.stderr.contains("503"));
    }

    /// Terminal stderr (HTTP 401) must short-circuit on the first
    /// attempt — the canonical classifier returns `false` and
    /// `run_with_policy` exits without consulting the schedule.
    /// Pinning this guards against a future regression where
    /// `retry_command` accidentally swaps in a permissive
    /// "always-transient" classifier (which would burn budget on
    /// terminal failures).
    #[tokio::test]
    async fn test_retry_command_short_circuits_on_terminal_stderr() {
        let p = RetryPolicy::new(10, Duration::ZERO, 1, Duration::ZERO);
        let calls = Arc::new(AtomicU32::new(0));
        let calls_clone = calls.clone();
        let result = retry_command(&p, "login terminal", move |_attempt| {
            let calls = calls_clone.clone();
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(synth_output(false, b"", b"401 Unauthorized: bad creds"))
            }
        })
        .await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "terminal must short-circuit"
        );
        let err = result.expect_err("terminal must produce Err");
        assert_eq!(err.attempt, 1);
        assert!(!err.is_transient());
    }

    /// Spawn failure (`Err(io::Error)` — binary not on PATH) MUST be
    /// terminal by construction. The lifted helper carries the same
    /// "empty stderr → terminal" invariant the four pre-existing
    /// `*::ExecFailed` typed-error variants encode, so a missing tool
    /// never burns retry budget. Pin this against a future regression
    /// where `retry_command` accidentally treats spawn errors as
    /// transient (which would amplify "skopeo not installed" into a
    /// 5-attempt × 30-second backoff, then fail anyway).
    #[tokio::test]
    async fn test_retry_command_spawn_failure_is_terminal() {
        let p = RetryPolicy::new(5, Duration::ZERO, 1, Duration::ZERO);
        let calls = Arc::new(AtomicU32::new(0));
        let calls_clone = calls.clone();
        let result = retry_command(&p, "spawn missing", move |_attempt| {
            let calls = calls_clone.clone();
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "no such file",
                ))
            }
        })
        .await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "spawn failure must short-circuit on attempt 1"
        );
        let err = result.expect_err("spawn failure must produce Err");
        assert_eq!(err.exit_code, None);
        assert!(
            err.stderr.is_empty(),
            "spawn failure must carry empty stderr"
        );
        assert!(err.stdout.contains("no such file"));
        assert!(!err.is_transient());
    }

    /// `spawn` receives the 1-indexed attempt number on every call.
    /// Pins the contract callers rely on when they want the per-
    /// attempt counter to flow into per-attempt log messages or
    /// per-attempt `--retry-times` parameters of the underlying tool.
    /// Same shape `run_with_policy` already pins for its inner
    /// closure, lifted up through the typed-Output mapping.
    #[tokio::test]
    async fn test_retry_command_passes_attempt_index() {
        let p = RetryPolicy::new(3, Duration::ZERO, 1, Duration::ZERO);
        let seen = Arc::new(std::sync::Mutex::new(Vec::<u32>::new()));
        let seen_clone = seen.clone();
        let _ = retry_command(&p, "track attempts", move |attempt| {
            let seen = seen_clone.clone();
            async move {
                seen.lock().unwrap().push(attempt);
                Ok(synth_output(false, b"", b"503"))
            }
        })
        .await;
        assert_eq!(*seen.lock().unwrap(), vec![1, 2, 3]);
    }

    /// Eventual success — fail twice transient, then succeed on the
    /// third attempt. Pins that `retry_command` stops the loop the
    /// moment a zero-exit `Output` arrives and returns it verbatim,
    /// regardless of how many transients preceded.
    #[tokio::test]
    async fn test_retry_command_eventual_success() {
        let p = RetryPolicy::new(5, Duration::ZERO, 1, Duration::ZERO);
        let calls = Arc::new(AtomicU32::new(0));
        let calls_clone = calls.clone();
        let result = retry_command(&p, "eventually ok", move |_attempt| {
            let calls = calls_clone.clone();
            async move {
                let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
                if n < 3 {
                    Ok(synth_output(false, b"", b"i/o timeout"))
                } else {
                    Ok(synth_output(true, b"done", b""))
                }
            }
        })
        .await;
        let output = result.expect("must succeed on attempt 3");
        assert!(output.status.success());
        assert_eq!(output.stdout, b"done");
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    /// Operation label must surface on the returned
    /// `CommandAttemptFailure` — the structural-record tuple Phase 1
    /// attestation records (THEORY §V.4) and per-attempt logs depend
    /// on. Pinning this guards against a future regression where the
    /// helper accidentally drops the caller-supplied operation label
    /// (e.g. by passing an empty string into `from_capture`).
    #[tokio::test]
    async fn test_retry_command_operation_label_surfaces_on_failure() {
        let p = RetryPolicy::new(1, Duration::ZERO, 1, Duration::ZERO);
        let result = retry_command(&p, "push ghcr.io/o/p:abc1234", |_attempt| async {
            Ok(synth_output(false, b"", b"401 Unauthorized"))
        })
        .await;
        let err = result.expect_err("must fail");
        assert_eq!(err.operation, "push ghcr.io/o/p:abc1234");
    }

    /// Synthetic typed-error family used to pin `classify_capture`'s
    /// dispatch contract without coupling the retry-module tests to any
    /// of the production error families in `cli/src/error.rs`. Mirrors
    /// the structural shape every production family already carries
    /// (the four already-migrated families — Registry, Nix, Attic, Git
    /// — each pair `ExecFailed` with a per-family op-failure variant
    /// carrying `(exit_code: Option<i32>, stderr: String)`).
    #[derive(Debug, PartialEq, Eq)]
    enum FakeError {
        ExecFailed {
            op: String,
            message: String,
        },
        OpFailed {
            op: String,
            exit_code: Option<i32>,
            stderr: String,
        },
    }
    impl std::fmt::Display for FakeError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self)
        }
    }
    impl std::error::Error for FakeError {}

    /// Success — `classify_capture` returns the captured `Output`
    /// verbatim so the caller can read `stdout` (or inspect status, or
    /// debug-log) without re-running the command. Pins the load-bearing
    /// invariant that `on_op` and `on_spawn` are NEVER invoked on a
    /// zero-exit `Output` — same discipline
    /// `CapturedFailure::from_output_if_failed` already encodes for its
    /// own surface.
    #[test]
    fn test_classify_capture_success_returns_output() {
        let out = synth_output(true, b"hello world\n", b"");
        let result: Result<std::process::Output, FakeError> = classify_capture(
            Ok(out),
            |_e| panic!("on_spawn must NOT fire on success"),
            |_cf| panic!("on_op must NOT fire on success"),
        );
        let captured = result.expect("zero-exit must return Output");
        assert!(captured.status.success());
        assert_eq!(captured.stdout, b"hello world\n");
    }

    /// Spawn-failure (`Err(io::Error)` — binary not on PATH, fork
    /// failed) routes to `on_spawn`. `on_op` MUST NOT fire — the CLI
    /// never ran, so there is no captured stderr to dispatch on. Pins
    /// the same discriminator the four already-migrated `ExecFailed`
    /// variants encode at their producer sites.
    #[test]
    fn test_classify_capture_spawn_failure_routes_to_on_spawn() {
        let captured: std::io::Result<std::process::Output> = Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no such file or directory",
        ));
        let result: Result<std::process::Output, FakeError> = classify_capture(
            captured,
            |e| FakeError::ExecFailed {
                op: "spawn missing tool".to_string(),
                message: e.to_string(),
            },
            |_cf| panic!("on_op MUST NOT fire on spawn-failure (CLI never ran)"),
        );
        match result.expect_err("spawn failure must produce Err") {
            FakeError::ExecFailed { op, message } => {
                assert_eq!(op, "spawn missing tool");
                assert!(
                    message.contains("no such file"),
                    "spawn-error message must flow through: {message}"
                );
            }
            other => panic!("expected ExecFailed, got: {other:?}"),
        }
    }

    /// Op-failure (`Ok(out)` with non-zero status) routes to `on_op`,
    /// which receives the canonical [`CapturedFailure`] carrying the
    /// extracted `(exit_code, stderr)` tuple — UTF-8-lossy-decoded and
    /// trimmed by [`CapturedFailure::from_output`]. `on_spawn` MUST NOT
    /// fire — the CLI ran. The structural-record tuple flows verbatim
    /// into the caller-supplied `OpFailed` variant by name; every
    /// production family's op-failure variant already destructures
    /// `cf.exit_code` and `cf.stderr` this way.
    #[test]
    fn test_classify_capture_op_failure_routes_to_on_op_with_captured_failure() {
        let out = synth_output(false, b"", b"  503 Service Unavailable\n  ");
        let result: Result<std::process::Output, FakeError> = classify_capture(
            Ok(out),
            |_e| panic!("on_spawn MUST NOT fire on op-failure (CLI ran)"),
            |cf| FakeError::OpFailed {
                op: "push transient".to_string(),
                exit_code: cf.exit_code,
                stderr: cf.stderr,
            },
        );
        match result.expect_err("non-zero exit must produce Err") {
            FakeError::OpFailed {
                op,
                exit_code,
                stderr,
            } => {
                assert_eq!(op, "push transient");
                assert!(exit_code.is_some());
                assert_ne!(exit_code, Some(0));
                // Trim discipline — leading/trailing whitespace stripped
                // by `CapturedFailure::from_output` — load-bearing for
                // the canonical classifier.
                assert_eq!(stderr, "503 Service Unavailable");
                // The trimmed stderr round-trips through the canonical
                // transient classifier — proves the dispatch preserves
                // the structural-record shape downstream consumers
                // (retry, telemetry, attestation) depend on.
                assert!(is_transient_network_stderr(&stderr));
            }
            other => panic!("expected OpFailed, got: {other:?}"),
        }
    }

    /// Discriminator pin: spawn-failure and op-failure are distinct
    /// arms — a single `classify_capture` call cannot route to both,
    /// and the load-bearing invariant is that `on_op` does not fire on
    /// `Err(io::Error)` (no captured stderr exists to extract) and
    /// `on_spawn` does not fire on `Ok(out)` non-success (the CLI ran).
    /// Pinning this guards against a future regression that conflates
    /// the two arms (e.g., synthesizing an empty `CapturedFailure` from
    /// a spawn error and routing through `on_op` — which would silently
    /// turn every "binary not on PATH" failure into an
    /// `OpFailed { exit_code: None, stderr: "" }` record, drift-prone
    /// against the canonical classifier and against the
    /// `is_spawn_failure` post-loop predicate).
    #[test]
    fn test_classify_capture_arms_are_disjoint() {
        use std::sync::atomic::{AtomicU32, Ordering};
        // Spawn-failure: only on_spawn fires.
        let spawn_fired = AtomicU32::new(0);
        let op_fired = AtomicU32::new(0);
        let captured: std::io::Result<std::process::Output> = Err(std::io::Error::other("x"));
        let _: Result<std::process::Output, FakeError> = classify_capture(
            captured,
            |_e| {
                spawn_fired.fetch_add(1, Ordering::SeqCst);
                FakeError::ExecFailed {
                    op: "x".to_string(),
                    message: "x".to_string(),
                }
            },
            |_cf| {
                op_fired.fetch_add(1, Ordering::SeqCst);
                FakeError::OpFailed {
                    op: "x".to_string(),
                    exit_code: None,
                    stderr: String::new(),
                }
            },
        );
        assert_eq!(spawn_fired.load(Ordering::SeqCst), 1);
        assert_eq!(op_fired.load(Ordering::SeqCst), 0);

        // Op-failure: only on_op fires.
        let spawn_fired = AtomicU32::new(0);
        let op_fired = AtomicU32::new(0);
        let out = synth_output(false, b"", b"401 Unauthorized");
        let _: Result<std::process::Output, FakeError> = classify_capture(
            Ok(out),
            |_e| {
                spawn_fired.fetch_add(1, Ordering::SeqCst);
                FakeError::ExecFailed {
                    op: "x".to_string(),
                    message: "x".to_string(),
                }
            },
            |_cf| {
                op_fired.fetch_add(1, Ordering::SeqCst);
                FakeError::OpFailed {
                    op: "x".to_string(),
                    exit_code: None,
                    stderr: String::new(),
                }
            },
        );
        assert_eq!(spawn_fired.load(Ordering::SeqCst), 0);
        assert_eq!(op_fired.load(Ordering::SeqCst), 1);

        // Success: neither fires.
        let spawn_fired = AtomicU32::new(0);
        let op_fired = AtomicU32::new(0);
        let out = synth_output(true, b"ok", b"");
        let _: Result<std::process::Output, FakeError> = classify_capture(
            Ok(out),
            |_e| {
                spawn_fired.fetch_add(1, Ordering::SeqCst);
                FakeError::ExecFailed {
                    op: "x".to_string(),
                    message: "x".to_string(),
                }
            },
            |_cf| {
                op_fired.fetch_add(1, Ordering::SeqCst);
                FakeError::OpFailed {
                    op: "x".to_string(),
                    exit_code: None,
                    stderr: String::new(),
                }
            },
        );
        assert_eq!(spawn_fired.load(Ordering::SeqCst), 0);
        assert_eq!(op_fired.load(Ordering::SeqCst), 0);
    }

    /// Success — `classify_capture_query` returns the trimmed UTF-8-lossy
    /// stdout as `String`. The trim discipline is load-bearing — query-
    /// shaped sites (`get_sha`, `verify_tag_exists`, build store-path
    /// resolution) feed the returned string directly into downstream
    /// equality checks, environment variables, or attestation records;
    /// a leaked trailing `\n` from a tool's printed output (every UNIX
    /// CLI's default convention) would silently break those consumers.
    /// Pinning the trim at the typed primitive guarantees no caller can
    /// drift onto a `from_utf8_lossy(&out.stdout).to_string()` shape that
    /// forgets the trim.
    #[test]
    fn test_classify_capture_query_success_returns_trimmed_stdout() {
        let out = synth_output(true, b"  abc1234\n  ", b"");
        let result: Result<String, FakeError> = classify_capture_query(
            Ok(out),
            |_e| panic!("on_spawn must NOT fire on success"),
            |_cf| panic!("on_op must NOT fire on success"),
        );
        let stdout = result.expect("zero-exit must return trimmed stdout");
        assert_eq!(
            stdout, "abc1234",
            "trim discipline must strip leading/trailing whitespace"
        );
    }

    /// Internal whitespace must survive the trim — only leading and
    /// trailing whitespace is stripped. Same discipline
    /// `CapturedFailure::from_output` already encodes for stderr, lifted
    /// to the success-stdout path. Without this guard a future regression
    /// that swapped `.trim()` for `.replace(char::is_whitespace, "")`
    /// (or a similar over-aggressive normalization) would silently corrupt
    /// query results that legitimately carry internal whitespace
    /// (multi-line build outputs, sha256 digests with line-wrapped surrounds).
    #[test]
    fn test_classify_capture_query_preserves_internal_whitespace() {
        let out = synth_output(true, b"\nline one\nline two\n", b"");
        let result: Result<String, FakeError> = classify_capture_query(
            Ok(out),
            |_e| panic!("on_spawn must NOT fire on success"),
            |_cf| panic!("on_op must NOT fire on success"),
        );
        let stdout = result.expect("zero-exit must return trimmed stdout");
        assert_eq!(stdout, "line one\nline two");
    }

    /// Empty stdout on success returns an empty `String` — the post-check
    /// `if digest.is_empty() { ... }` discipline that
    /// `verify_tag_exists` / `rev_parse_short` / `run_nix_build_typed`
    /// each carry stays at the producer site (it's a per-family
    /// precondition variant, not a structural classifier concern). Pinning
    /// this means the primitive does NOT silently turn empty-stdout into
    /// a typed-error variant — a future caller that wants the post-check
    /// keeps owning it.
    #[test]
    fn test_classify_capture_query_empty_stdout_returns_empty_string() {
        let out = synth_output(true, b"", b"");
        let result: Result<String, FakeError> = classify_capture_query(
            Ok(out),
            |_e| panic!("on_spawn must NOT fire on success"),
            |_cf| panic!("on_op must NOT fire on success"),
        );
        let stdout = result.expect("zero-exit must return Ok even on empty stdout");
        assert!(
            stdout.is_empty(),
            "empty stdout must return empty String, not Err"
        );
    }

    /// Spawn-failure (`Err(io::Error)` — git/skopeo/nix not on PATH)
    /// routes to `on_spawn`. Same discipline `classify_capture` encodes,
    /// lifted to the query-shape return type. `on_op` MUST NOT fire — the
    /// CLI never ran, no stdout exists.
    #[test]
    fn test_classify_capture_query_spawn_failure_routes_to_on_spawn() {
        let captured: std::io::Result<std::process::Output> = Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no such file or directory",
        ));
        let result: Result<String, FakeError> = classify_capture_query(
            captured,
            |e| FakeError::ExecFailed {
                op: "rev-parse".to_string(),
                message: e.to_string(),
            },
            |_cf| panic!("on_op MUST NOT fire on spawn-failure (CLI never ran)"),
        );
        match result.expect_err("spawn failure must produce Err") {
            FakeError::ExecFailed { op, message } => {
                assert_eq!(op, "rev-parse");
                assert!(
                    message.contains("no such file"),
                    "spawn-error message must flow through: {message}"
                );
            }
            other => panic!("expected ExecFailed, got: {other:?}"),
        }
    }

    /// Op-failure (`Ok(out)` with non-zero status) routes to `on_op`,
    /// which receives the canonical [`CapturedFailure`] carrying the
    /// extracted `(exit_code, stderr)` tuple — UTF-8-lossy-decoded and
    /// trimmed. A query-shape site that wants the structural tuple
    /// (e.g. `GitError::ShaFailed` carrying the stderr) destructures
    /// `cf.exit_code` and `cf.stderr` by name; a site that wants only
    /// the precondition meaning (e.g. `RegistryError::RemoteImageNotFound`
    /// carrying just the (registry, tag) tuple — "the queried thing
    /// isn't there") ignores `cf` with `|_cf| ...`. Both shapes are
    /// in-tree consumers of this primitive.
    #[test]
    fn test_classify_capture_query_op_failure_routes_to_on_op_with_captured_failure() {
        let out = synth_output(false, b"", b"  fatal: not a git repository  \n");
        let result: Result<String, FakeError> = classify_capture_query(
            Ok(out),
            |_e| panic!("on_spawn MUST NOT fire on op-failure (CLI ran)"),
            |cf| FakeError::OpFailed {
                op: "rev-parse".to_string(),
                exit_code: cf.exit_code,
                stderr: cf.stderr,
            },
        );
        match result.expect_err("non-zero exit must produce Err") {
            FakeError::OpFailed {
                op,
                exit_code,
                stderr,
            } => {
                assert_eq!(op, "rev-parse");
                assert!(exit_code.is_some());
                assert_ne!(exit_code, Some(0));
                assert_eq!(
                    stderr, "fatal: not a git repository",
                    "trim discipline must strip leading/trailing whitespace from stderr"
                );
            }
            other => panic!("expected OpFailed, got: {other:?}"),
        }
    }

    /// Discriminator pin: the three arms (success / op-failure /
    /// spawn-failure) are disjoint — exactly one closure fires per call.
    /// Same shape `test_classify_capture_arms_are_disjoint` pins for the
    /// op-shape primitive, lifted to the query-shape primitive. Without
    /// this guard a future regression that conflated op-failure with
    /// spawn-failure (e.g. synthesizing an empty `CapturedFailure` from
    /// an `Err(io::Error)` and routing through `on_op`) would silently
    /// turn every "git not on PATH" failure into a `ShaFailed("")`
    /// record, drift-prone against the canonical
    /// [`CommandAttemptFailure::is_spawn_failure`] post-loop predicate.
    #[test]
    fn test_classify_capture_query_arms_are_disjoint() {
        use std::sync::atomic::{AtomicU32, Ordering};

        // Spawn-failure: only on_spawn fires.
        let spawn_fired = AtomicU32::new(0);
        let op_fired = AtomicU32::new(0);
        let captured: std::io::Result<std::process::Output> = Err(std::io::Error::other("x"));
        let _: Result<String, FakeError> = classify_capture_query(
            captured,
            |_e| {
                spawn_fired.fetch_add(1, Ordering::SeqCst);
                FakeError::ExecFailed {
                    op: "x".to_string(),
                    message: "x".to_string(),
                }
            },
            |_cf| {
                op_fired.fetch_add(1, Ordering::SeqCst);
                FakeError::OpFailed {
                    op: "x".to_string(),
                    exit_code: None,
                    stderr: String::new(),
                }
            },
        );
        assert_eq!(spawn_fired.load(Ordering::SeqCst), 1);
        assert_eq!(op_fired.load(Ordering::SeqCst), 0);

        // Op-failure: only on_op fires.
        let spawn_fired = AtomicU32::new(0);
        let op_fired = AtomicU32::new(0);
        let out = synth_output(false, b"", b"401 Unauthorized");
        let _: Result<String, FakeError> = classify_capture_query(
            Ok(out),
            |_e| {
                spawn_fired.fetch_add(1, Ordering::SeqCst);
                FakeError::ExecFailed {
                    op: "x".to_string(),
                    message: "x".to_string(),
                }
            },
            |_cf| {
                op_fired.fetch_add(1, Ordering::SeqCst);
                FakeError::OpFailed {
                    op: "x".to_string(),
                    exit_code: None,
                    stderr: String::new(),
                }
            },
        );
        assert_eq!(spawn_fired.load(Ordering::SeqCst), 0);
        assert_eq!(op_fired.load(Ordering::SeqCst), 1);

        // Success: neither fires.
        let spawn_fired = AtomicU32::new(0);
        let op_fired = AtomicU32::new(0);
        let out = synth_output(true, b"abc1234", b"");
        let _: Result<String, FakeError> = classify_capture_query(
            Ok(out),
            |_e| {
                spawn_fired.fetch_add(1, Ordering::SeqCst);
                FakeError::ExecFailed {
                    op: "x".to_string(),
                    message: "x".to_string(),
                }
            },
            |_cf| {
                op_fired.fetch_add(1, Ordering::SeqCst);
                FakeError::OpFailed {
                    op: "x".to_string(),
                    exit_code: None,
                    stderr: String::new(),
                }
            },
        );
        assert_eq!(spawn_fired.load(Ordering::SeqCst), 0);
        assert_eq!(op_fired.load(Ordering::SeqCst), 0);
    }

    /// Success on a non-final attempt — `log_retry_attempt` returns the
    /// captured `Ok(Output)` verbatim. The pass-through is the load-bearing
    /// invariant: the helper sits inside `retry_command`'s spawn closure as
    /// the final expression, and the typed retry primitive consumes the
    /// returned value. A future regression that swallowed `Output.stdout`
    /// (e.g. by deconstructing and reconstructing the `Output` for logging)
    /// would silently corrupt every query-shaped `retry_command` call site.
    #[test]
    fn test_log_retry_attempt_success_returns_outcome_verbatim() {
        let out = synth_output(true, b"hello\n", b"");
        let result = log_retry_attempt(Ok(out), "push transient", 1, 5);
        let captured = result.expect("success outcome must pass through Ok");
        assert!(captured.status.success());
        assert_eq!(captured.stdout, b"hello\n");
    }

    /// Op-failure on a non-final attempt — `log_retry_attempt` returns the
    /// captured `Ok(Output)` verbatim and emits a warn-level retry log on
    /// the side. Pins the pass-through (the structural invariant) without
    /// asserting the warn (an observability concern; the `tracing` macro is
    /// a no-op when no subscriber is configured, which is the test default
    /// — a future test that pinned the warn would need a `tracing-test`-
    /// shaped harness, separately disposed). The body covers the same cell
    /// `infrastructure/registry.rs::push_with_retries`'s pre-migration body
    /// covered: failed status × retry budget remaining.
    #[test]
    fn test_log_retry_attempt_op_failure_with_budget_returns_outcome_verbatim() {
        let out = synth_output(false, b"", b"503 Service Unavailable\n");
        let result = log_retry_attempt(Ok(out), "push ghcr.io/o/p:tag", 2, 5);
        let captured = result.expect("op-failure must still pass Ok(Output) through");
        assert!(!captured.status.success());
        assert_eq!(captured.stderr, b"503 Service Unavailable\n");
    }

    /// Op-failure on the FINAL attempt — `log_retry_attempt` returns the
    /// outcome verbatim WITHOUT emitting the "retrying..." warn (because no
    /// retry follows). The "another attempt remains" predicate (`attempt <
    /// max_attempts`) is load-bearing: emitting "retrying..." on the final
    /// attempt would mis-describe what happens next (the post-loop dispatch
    /// onto the typed `*::PushFailed` / `*::ExecFailed` variant fires
    /// instead). Pins the suppressed-on-final-attempt invariant via the
    /// structural pass-through; the warn-side-effect-suppression is documented
    /// in the helper's contract.
    #[test]
    fn test_log_retry_attempt_op_failure_on_final_attempt_returns_outcome_verbatim() {
        let out = synth_output(false, b"", b"i/o timeout\n");
        // attempt == max_attempts: no retry follows.
        let result = log_retry_attempt(Ok(out), "push ghcr.io/o/p:tag", 5, 5);
        let captured = result.expect("op-failure on final attempt must still pass Ok(Output)");
        assert!(!captured.status.success());
        assert_eq!(captured.stderr, b"i/o timeout\n");
    }

    /// Op-failure with `Stdio::null()`-discarded stdout — `log_retry_attempt`
    /// must NOT depend on stdout being non-empty. `commands/push.rs::
    /// push_with_retry` (the fifth retry-driven call site that consumes this
    /// helper) routes skopeo with `stdout(Stdio::null())` so the captured
    /// `Output.stdout` is always `b""` regardless of what skopeo would have
    /// emitted; the failure-detection predicate (`!o.status.success()`)
    /// fires entirely off the exit code. A future "optimization" that
    /// started inspecting stdout to gate the warn (e.g., suppressing the
    /// retry log when stdout is empty) would silently break that site:
    /// every transient failure there would emit no warn, and the operator
    /// would lose mid-loop visibility on a five-attempt push storm.
    /// Pinning the stdout-independence property at the primitive level means
    /// the regression surfaces here first.
    #[test]
    fn test_log_retry_attempt_op_failure_with_empty_stdout_returns_outcome_verbatim() {
        // synth_output(success=false, stdout=b"" — the Stdio::null() shape —,
        // stderr=non-empty transient). The "another attempt remains" branch
        // must still fire (attempt < max_attempts), and the outcome must
        // pass through verbatim for the downstream retry-loop's classifier.
        let out = synth_output(false, b"", b"503 Service Unavailable\n");
        let result = log_retry_attempt(Ok(out), "push ghcr.io/o/p:tag", 1, 5);
        let captured = result.expect("op-failure with empty stdout must pass Ok(Output) through");
        assert!(
            !captured.status.success(),
            "non-success status must survive verbatim"
        );
        assert!(
            captured.stdout.is_empty(),
            "Stdio::null()-discarded stdout must remain empty post-passthrough"
        );
        assert_eq!(
            captured.stderr, b"503 Service Unavailable\n",
            "stderr must survive verbatim — the canonical transient classifier reads it"
        );
    }

    /// Spawn-failure on a non-final attempt — `log_retry_attempt` returns
    /// the captured `Err(io::Error)` verbatim. The error kind, message, and
    /// the underlying error chain MUST flow through unchanged so the
    /// downstream `retry_command` → `CommandAttemptFailure::from_capture`
    /// dispatch can route the spawn-failure to the typed
    /// `*::ExecFailed` variant via `is_spawn_failure()`. A future regression
    /// that synthesized a fake `Output` from the spawn error would silently
    /// turn every "binary not on PATH" precondition into a `*::PushFailed`
    /// record — invisible at the typed-error surface but visible in
    /// telemetry / replay / attestation as drift.
    #[test]
    fn test_log_retry_attempt_spawn_failure_returns_outcome_verbatim() {
        let captured: std::io::Result<std::process::Output> = Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no such file or directory",
        ));
        let result = log_retry_attempt(captured, "push ghcr.io/o/p:tag", 1, 5);
        let err = result.expect_err("spawn-failure must pass Err(io::Error) through");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        assert!(err.to_string().contains("no such file"));
    }

    /// Spawn-failure on the FINAL attempt — same pass-through invariant,
    /// no warn. The post-loop typed-error dispatch
    /// (`is_spawn_failure()` → `*::ExecFailed`) owns the terminal-failure
    /// log surface for spawn errors; this primitive does not duplicate it.
    #[test]
    fn test_log_retry_attempt_spawn_failure_on_final_attempt_returns_outcome_verbatim() {
        let captured: std::io::Result<std::process::Output> =
            Err(std::io::Error::other("permission denied"));
        let result = log_retry_attempt(captured, "push ghcr.io/o/p:tag", 5, 5);
        let err = result.expect_err("spawn-failure on final attempt must pass Err through");
        assert!(err.to_string().contains("permission denied"));
    }

    /// `log_retry_attempt` composes with `retry_command` end-to-end: the
    /// spawn closure invokes the helper as its final expression and
    /// `retry_command` consumes the returned `io::Result<Output>` exactly as
    /// it would have without the helper. Pins the integration shape every
    /// migrated call site uses — a future regression in either primitive
    /// that broke the closure-return contract (e.g. by changing the success
    /// type) would fail the build at every call site, but is also pinned
    /// here at the primitive level so the regression surfaces in
    /// `cli/src/retry.rs`'s test suite first. Drives an always-transient
    /// stderr (HTTP 503) through `retries=3` and asserts the final attempt
    /// count surfaces on the `CommandAttemptFailure`.
    #[tokio::test]
    async fn test_log_retry_attempt_composes_with_retry_command() {
        let p = RetryPolicy::new(3, Duration::ZERO, 1, Duration::ZERO);
        let calls = Arc::new(AtomicU32::new(0));
        let calls_clone = calls.clone();
        let max_attempts = p.max_attempts;
        let result = retry_command(&p, "push composed", move |attempt| {
            let calls = calls_clone.clone();
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                let outcome = Ok(synth_output(false, b"", b"503 Service Unavailable"));
                log_retry_attempt(outcome, "push composed", attempt, max_attempts)
            }
        })
        .await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "retry_command must drive every attempt; log_retry_attempt is pure pass-through"
        );
        let err = result.expect_err("transient exhaustion must produce Err");
        assert_eq!(err.attempt, 3);
        assert!(err.is_transient());
        assert!(err.stderr.contains("503"));
    }

    /// `classify_attempt_failure` routes a spawn-failure record (empty
    /// stderr + `exit_code: None`) through the `on_spawn` closure, NOT
    /// `on_op`. The structural shape of a spawn-failure is fixed by
    /// [`CommandAttemptFailure::from_capture`]: the spawn-error message
    /// flows through `stdout` and stderr is empty. Pinning the dispatch
    /// at the primitive level guards against a regression at any of the
    /// downstream call sites (`classify_push_failure` /
    /// `classify_attic_push_failure`) routing a missing-CLI failure to a
    /// `*::PushFailed` variant — which would silently set
    /// `attempts: 1, exit_code: None, stderr: ""` instead of routing the
    /// spawn-error message into the `*::ExecFailed.message` field.
    #[test]
    fn test_classify_attempt_failure_routes_spawn_to_on_spawn() {
        let spawn = CommandAttemptFailure {
            operation: "op".to_string(),
            attempt: 1,
            exit_code: None,
            stderr: String::new(),
            stdout: "failed to spawn process: No such file or directory".to_string(),
        };
        // `tag` is one of {"spawn", "op"} so the assertion pins which
        // closure ran without inspecting the failure record itself.
        let tag: &'static str = classify_attempt_failure(spawn, |_| "spawn", |_| "op");
        assert_eq!(tag, "spawn");
    }

    /// `classify_attempt_failure` routes a non-zero-exit op-failure
    /// record (CLI ran and rejected) through the `on_op` closure, NOT
    /// `on_spawn`. The structural shape of an op-failure is `exit_code:
    /// Some(_)` with stderr potentially populated.
    #[test]
    fn test_classify_attempt_failure_routes_op_to_on_op() {
        let op = CommandAttemptFailure {
            operation: "op".to_string(),
            attempt: 3,
            exit_code: Some(1),
            stderr: "received unexpected HTTP status: 503".to_string(),
            stdout: String::new(),
        };
        let tag: &'static str = classify_attempt_failure(op, |_| "spawn", |_| "op");
        assert_eq!(tag, "op");
    }

    /// Regression guard for the silent-op-failure shape: a CLI that ran,
    /// exited non-zero, and emitted nothing on stderr (`exit_code:
    /// Some(_)` AND empty stderr) is structurally distinct from a
    /// spawn-failure (`exit_code: None` AND empty stderr). The two share
    /// "empty stderr" but the typed dispatch must route them to different
    /// closures. Mirror of the silent-op-failure regression guards at the
    /// two migrated call sites
    /// (`test_classify_push_failure_silent_op_failure_routes_to_push_failed`
    /// in registry.rs / attic.rs); pinning at the primitive level means a
    /// future regression on the `is_spawn_failure` predicate is caught
    /// here first.
    #[test]
    fn test_classify_attempt_failure_silent_op_routes_to_on_op() {
        let silent_op = CommandAttemptFailure {
            operation: "op".to_string(),
            attempt: 2,
            exit_code: Some(125),
            stderr: String::new(),
            stdout: String::new(),
        };
        // Sanity: this is NOT a spawn failure (exit_code is Some).
        assert!(!silent_op.is_spawn_failure());
        let tag: &'static str = classify_attempt_failure(silent_op, |_| "spawn", |_| "op");
        assert_eq!(
            tag, "op",
            "silent op-failure must route to on_op even though stderr is empty"
        );
    }

    /// The closures receive the whole [`CommandAttemptFailure`] by value
    /// (not borrowed, not destructured at the boundary). Pinning the
    /// signature at the primitive level guards against a future
    /// "optimization" that takes only the fields each closure happens to
    /// read today — which would force every per-family classifier to
    /// destructure the record at the call site and re-derive the
    /// `(attempts, exit_code, stderr)` tuple instead of consuming the
    /// canonical record. Captures: `failure.operation`,
    /// `failure.attempt`, `failure.exit_code`, `failure.stderr`,
    /// `failure.stdout` must all flow into the closure unchanged.
    #[test]
    fn test_classify_attempt_failure_passes_whole_failure_to_closure() {
        let op = CommandAttemptFailure {
            operation: "verbatim-op-label".to_string(),
            attempt: 7,
            exit_code: Some(42),
            stderr: "verbatim-stderr".to_string(),
            stdout: "verbatim-stdout".to_string(),
        };
        let echoed: CommandAttemptFailure =
            classify_attempt_failure(op, |spawn| spawn, |op_failure| op_failure);
        assert_eq!(echoed.operation, "verbatim-op-label");
        assert_eq!(echoed.attempt, 7);
        assert_eq!(echoed.exit_code, Some(42));
        assert_eq!(echoed.stderr, "verbatim-stderr");
        assert_eq!(echoed.stdout, "verbatim-stdout");
    }

    /// `format_capture_streams` emits `<tool> stdout` then `<tool> stderr`
    /// (in that order) when both streams are non-empty after trim. The
    /// stdout-then-stderr order is the canonical pre-migration order; both
    /// retry-driven CI sites this primitive consolidates emit stdout first.
    /// Pinning the order keeps log replay deterministic across the
    /// migration.
    #[test]
    fn test_format_capture_streams_emits_stdout_then_stderr() {
        let out = synth_output(false, b"raw stdout line", b"raw stderr line");
        let messages = format_capture_streams(&out, "attic");
        assert_eq!(
            messages,
            vec![
                "attic stdout: raw stdout line".to_string(),
                "attic stderr: raw stderr line".to_string(),
            ],
        );
    }

    /// Empty (after trim) stdout / stderr produce no message — same
    /// suppression discipline the two pre-migration sites carried inline
    /// (`if !stdout.trim().is_empty() { debug!(...) }`). Pre-migration
    /// regression: a tool that emits only whitespace on stderr (e.g., a
    /// trailing newline from a successful no-op) would have produced an
    /// empty `debug!` line; pinning the suppression at the formatter
    /// boundary closes that drift.
    #[test]
    fn test_format_capture_streams_suppresses_empty_streams() {
        // Both empty → no messages.
        let out = synth_output(false, b"", b"");
        assert!(format_capture_streams(&out, "skopeo").is_empty());
        // Whitespace-only → still suppressed (trim discipline matches
        // CapturedFailure::from_output).
        let out = synth_output(false, b"  \n\t", b"\r\n   \n");
        assert!(format_capture_streams(&out, "skopeo").is_empty());
        // Only stdout populated → only stdout message.
        let out = synth_output(false, b"hello", b"");
        assert_eq!(
            format_capture_streams(&out, "skopeo"),
            vec!["skopeo stdout: hello".to_string()],
        );
        // Only stderr populated → only stderr message.
        let out = synth_output(false, b"", b"oops");
        assert_eq!(
            format_capture_streams(&out, "skopeo"),
            vec!["skopeo stderr: oops".to_string()],
        );
    }

    /// Leading and trailing whitespace are trimmed — internal whitespace
    /// is preserved so multi-line tool diagnostics survive the round-trip
    /// into the debug log. Same discipline `CapturedFailure::from_output`
    /// applies to the typed-error stderr field; pinning both surfaces on
    /// the same trim contract means a tool's captured failure looks
    /// structurally identical at the warn (typed-error) and debug
    /// (stream-tee) surfaces.
    #[test]
    fn test_format_capture_streams_trims_leading_trailing_whitespace() {
        let out = synth_output(
            false,
            b"  outer-leading\nline two\nline three\n  ",
            b"\n  503 Service Unavailable\n",
        );
        let messages = format_capture_streams(&out, "attic");
        assert_eq!(
            messages,
            vec![
                "attic stdout: outer-leading\nline two\nline three".to_string(),
                "attic stderr: 503 Service Unavailable".to_string(),
            ],
            "leading/trailing trim only; internal whitespace (\\n between lines) preserved verbatim",
        );
    }

    /// UTF-8-lossy decode survives invalid bytes — same discipline
    /// `CapturedFailure::from_output` applies. A future regression that
    /// switched to strict UTF-8 decode would silently drop the message
    /// on any invalid-byte stderr (e.g., a tool emitting a binary
    /// header). Pinning the lossy decode catches that here.
    #[test]
    fn test_format_capture_streams_lossy_decode_survives_invalid_bytes() {
        // Invalid UTF-8 prefix + valid bytes; trim should leave the
        // replacement-char prefix intact (it's not whitespace).
        let out = synth_output(false, b"", &[0xFF, 0xFE, b' ', b'h', b'i']);
        let messages = format_capture_streams(&out, "tool");
        assert_eq!(messages.len(), 1);
        assert!(
            messages[0].starts_with("tool stderr: "),
            "lossy decode preserves the message under the canonical prefix: {:?}",
            messages[0]
        );
        assert!(
            messages[0].contains("hi"),
            "valid bytes after the invalid prefix must survive: {:?}",
            messages[0]
        );
    }

    /// Tool name flows verbatim into the message prefix. The two pre-
    /// migration sites use distinct tool names (`"attic"` and
    /// `"skopeo"`); pinning that the formatter never normalizes or
    /// case-folds the tool string means a future site can use any
    /// idiomatic tool label (e.g., `"git remote"`, `"regctl"`,
    /// `"kubectl rollout"`) without the formatter mangling it.
    #[test]
    fn test_format_capture_streams_tool_name_is_verbatim() {
        let out = synth_output(false, b"x", b"y");
        for tool in ["attic", "skopeo", "git remote", "regctl", "kubectl rollout"] {
            let messages = format_capture_streams(&out, tool);
            assert_eq!(messages.len(), 2);
            assert_eq!(messages[0], format!("{} stdout: x", tool));
            assert_eq!(messages[1], format!("{} stderr: y", tool));
        }
    }

    /// `debug_log_capture_streams` is a side-effecting wrapper around
    /// `format_capture_streams`. The pure formatter pins the message
    /// format; this end-to-end probe pins that the wrapper does not
    /// panic on any of the structural shapes the formatter handles
    /// (both populated, both empty, only stdout, only stderr,
    /// invalid-UTF-8 stderr). A future regression that reshaped the
    /// wrapper (e.g., panicking on empty streams instead of suppressing)
    /// surfaces here, not in production via a CI run that suddenly
    /// crashes mid-retry.
    #[test]
    fn test_debug_log_capture_streams_does_not_panic_on_any_shape() {
        for stdout in [&b""[..], b"  \n\t", b"hello", b"line1\nline2"] {
            for stderr in [&b""[..], b"\r\n   ", b"oops", b"503 Service Unavailable\n"] {
                let out = synth_output(false, stdout, stderr);
                debug_log_capture_streams(&out, "tool");
            }
        }
        // Invalid UTF-8 in stderr — must not panic.
        let out = synth_output(false, b"", &[0xFF, 0xFE, b'x']);
        debug_log_capture_streams(&out, "tool");
    }

    /// On the success path (`status.success()` is true), `run_inherited_status`
    /// returns `Ok(())` verbatim — no message, no envelope, no transformation.
    /// Pinned with a hermetic shim that exits zero, invoked by absolute path
    /// so the test does not race on global PATH state (same hermetic
    /// discipline `git.rs`'s and `nix.rs`'s shim-driven tests rely on).
    #[tokio::test]
    async fn test_run_inherited_status_success_returns_ok() {
        let (_dir, shim) =
            crate::test_support::make_executable_shim("interactive-cli", "#!/bin/sh\nexit 0\n");
        let cmd = tokio::process::Command::new(&shim);
        let result = run_inherited_status(cmd, "interactive-cli").await;
        assert!(result.is_ok(), "exit 0 must surface as Ok(())");
    }

    /// On a non-zero exit, `run_inherited_status` returns an `anyhow::Error`
    /// whose Display form carries both the operation label AND the captured
    /// exit code. Pre-migration, the eleven-line stanza's failure messages
    /// dropped the exit code (`bail!("Tests failed")`); post-migration the
    /// canonical `"{op} failed (exit {N})"` shape preserves it for every
    /// migrated site by construction. A regression that dropped either the
    /// op label or the exit code from the message would surface here, not in
    /// production via a less-informative operator log line.
    #[tokio::test]
    async fn test_run_inherited_status_nonzero_exit_carries_op_and_code() {
        let (_dir, shim) =
            crate::test_support::make_executable_shim("interactive-cli", "#!/bin/sh\nexit 7\n");
        let cmd = tokio::process::Command::new(&shim);
        let err = run_inherited_status(cmd, "interactive-cli")
            .await
            .expect_err("nonzero exit must fail");
        let msg = format!("{:#}", err);
        assert!(
            msg.contains("interactive-cli"),
            "op label must appear in failure message, got: {msg}"
        );
        assert!(
            msg.contains("exit 7"),
            "exit code must appear in failure message, got: {msg}"
        );
    }

    /// On a spawn failure (binary not on PATH, fork failed, permission
    /// denied), `run_inherited_status` returns an `anyhow::Error` whose
    /// Display form carries the operation label. The spawn-error envelope
    /// is `"Failed to run {op}"` so a downstream operator log surface can
    /// distinguish "couldn't even invoke the tool" from "tool ran and
    /// rejected" — the same typed split the canonical
    /// [`classify_capture`] / [`CommandAttemptFailure::is_spawn_failure`]
    /// primitives encode for the captured-output sibling shapes.
    #[tokio::test]
    async fn test_run_inherited_status_spawn_failure_carries_op() {
        let cmd = tokio::process::Command::new(
            "/nonexistent/path/to/inherited-status-binary-that-does-not-exist",
        );
        let err = run_inherited_status(cmd, "missing-tool")
            .await
            .expect_err("missing binary must fail");
        let msg = format!("{:#}", err);
        assert!(
            msg.contains("missing-tool"),
            "op label must appear in spawn-failure message, got: {msg}"
        );
    }

    /// Signal-killed processes (where `status.code()` is `None`) must surface
    /// as a structural `"killed by signal"` detail, distinct from a normal
    /// non-zero exit. Pinning the discriminator means an operator who
    /// receives the message can immediately distinguish "tool exited 137 on
    /// OOM" from "tool was killed by SIGKILL mid-run" — same THEORY §V.4
    /// Phase 1 attestation-record discipline the
    /// [`CommandAttemptFailure::is_spawn_failure`] split encodes for the
    /// captured-output sibling shape (`exit_code: None` is the structural
    /// signal-killed marker on the captured-output surface as well).
    #[cfg(unix)]
    #[tokio::test]
    async fn test_run_inherited_status_signal_killed_reports_killed_by_signal() {
        let (_dir, shim) =
            crate::test_support::make_executable_shim("self-killer", "#!/bin/sh\nkill -9 $$\n");
        let cmd = tokio::process::Command::new(&shim);
        let err = run_inherited_status(cmd, "self-killer")
            .await
            .expect_err("signal-killed must fail");
        let msg = format!("{:#}", err);
        assert!(
            msg.contains("killed by signal"),
            "signal-killed detail must surface, got: {msg}"
        );
        assert!(
            msg.contains("self-killer"),
            "op label must appear in signal-killed message, got: {msg}"
        );
    }

    /// The primitive's contract is that it OVERWRITES any caller-supplied
    /// stdout / stderr stdio shape with `Stdio::inherit()`. Pinning this is
    /// load-bearing for the migrated call sites: a future regression that
    /// branched on a pre-existing stdio setting (e.g. "if the caller already
    /// configured stdout, leave it alone") would silently break the live-
    /// progress invariant the inherited-stdio shape exists for. Operators
    /// expect to see `cargo test` / `cargo clippy` / `crate2nix generate`
    /// output streamed live to their terminal; a quietly-piped variant
    /// would suppress all of it.
    ///
    /// Asserted indirectly: the test pre-pipes both streams and confirms the
    /// primitive still completes successfully (the override happens, the
    /// shim runs, and exit-zero surfaces as `Ok(())`). A regression that
    /// honored the pre-piped setting would change the pipe-buffer fill
    /// behaviour but not necessarily the return value, so this is a
    /// structural pin (the primitive does not error on conflicting
    /// caller-supplied stdio) rather than a behavioural one.
    #[tokio::test]
    async fn test_run_inherited_status_overrides_caller_supplied_stdio() {
        let (_dir, shim) = crate::test_support::make_executable_shim(
            "interactive-cli",
            "#!/bin/sh\necho hi\nexit 0\n",
        );
        let mut cmd = tokio::process::Command::new(&shim);
        cmd.stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let result = run_inherited_status(cmd, "interactive-cli").await;
        assert!(
            result.is_ok(),
            "primitive must overwrite caller-supplied piped stdio and complete normally"
        );
    }

    /// `run_inherited_status`'s `anyhow::Error` shape composes cleanly with a
    /// caller-supplied `.with_context(|| ...)` wrap so the operator sees BOTH
    /// the domain narrative AND the primitive's structural record (op label
    /// + exit code) at the same failure event. Pinning this is load-bearing
    /// for every migrated call site that carries domain context — the five
    /// `commands/federation.rs` git-add / git-commit / git-push sites
    /// (commit migrating five status-only sites) wrap the primitive with
    /// `.with_context(|| format!("Failed to stage federation files at:
    /// {path}"))` and rely on the primitive's `anyhow::bail!("{op} failed
    /// (exit {N})")` becoming the inner cause that anyhow's chain walks
    /// from. A future regression that returned a flat `String` (or
    /// swallowed the inner cause via `.map_err(|_| ...)` instead of
    /// passing through anyhow's chain) would silently break this surface:
    /// the operator log would carry the domain narrative but lose the
    /// exit code that distinguishes "git add exited 128 (no such repo)"
    /// from "git add exited 1 (path conflict)" — a regression that is
    /// invisible at the call site but load-bearing on the operator
    /// triage surface (THEORY §V.4 Phase 1 attestation-record discipline).
    #[tokio::test]
    async fn test_run_inherited_status_chains_with_caller_context_on_nonzero_exit() {
        use anyhow::Context;
        let (_dir, shim) =
            crate::test_support::make_executable_shim("interactive-cli", "#!/bin/sh\nexit 7\n");
        let cmd = tokio::process::Command::new(&shim);
        let err = run_inherited_status(cmd, "git add")
            .await
            .with_context(|| {
                "Failed to stage federation files at: products/foo/federation".to_string()
            })
            .expect_err("nonzero exit must fail");

        // The outer Display surface (default) carries the caller's domain
        // context — the human narrative the operator-log consumer reads first.
        let outer = format!("{}", err);
        assert!(
            outer.contains("Failed to stage federation files at: products/foo/federation"),
            "outer Display must carry caller-supplied with_context wrap, got: {outer}"
        );

        // The full chain (walked by `anyhow::Error::chain()`, the surface a
        // structured-log consumer parses) must carry BOTH layers: the outer
        // domain narrative AND the inner structural record (op + exit code).
        // The alternate-Display form (`{:#}`) flattens the chain into a
        // single string with `: ` separators — which is the canonical shape
        // the operator-monitoring consumer reads when an attestation record
        // is replayed.
        let chained = format!("{:#}", err);
        assert!(
            chained.contains("Failed to stage federation files at: products/foo/federation"),
            "chain must carry outer domain narrative, got: {chained}"
        );
        assert!(
            chained.contains("git add failed (exit 7)"),
            "chain must carry primitive's structural record (op + exit code), got: {chained}"
        );

        // The chain has at least two distinct layers: the outer with_context
        // wrap and the inner anyhow::bail! the primitive emits. Pinning the
        // count rules out a future regression that flattened the two layers
        // into one (e.g. by formatting the inner cause into the outer
        // string at construction time).
        let layers: Vec<String> = err.chain().map(|e| e.to_string()).collect();
        assert!(
            layers.len() >= 2,
            "anyhow chain must preserve at least the outer + primitive layers, got {} layer(s): {:?}",
            layers.len(),
            layers
        );
    }

    /// Symmetric sibling of the non-zero-exit chain test: a caller-supplied
    /// `.with_context(|| ...)` wrap composes cleanly with the primitive's
    /// SPAWN-failure branch as well. Pinning this is load-bearing for the
    /// migrated `commands/developer_tools.rs` sites — `rust_dev`'s
    /// `docker-compose up` carries `.context("Failed to start
    /// docker-compose")`, `rust_dev_down`'s `docker-compose down` carries
    /// `.context("Failed to stop docker-compose")`, and `rust_dev`'s
    /// `cargo run` carries `.context("Failed to start cargo run")`. On a
    /// development workstation that lacks `docker-compose` on PATH (a real
    /// failure mode — the binary is bundled by the dev-shell, not by
    /// substrate), the spawn-failure branch fires and the operator log
    /// must surface BOTH the domain narrative ("Failed to start
    /// docker-compose") AND the primitive's structural envelope ("Failed
    /// to run docker-compose up") so the operator can distinguish "the
    /// dev shell didn't include docker-compose" from "docker-compose
    /// rejected the compose file." Pre-migration, the inline
    /// `.context("Failed to start docker-compose")?` was the ONLY layer
    /// (the bail message was suppressed by the `?` on the upstream Err),
    /// so the structural envelope was absent; post-migration it gains by
    /// construction. A future regression that returned a flat `String` (or
    /// swallowed the inner spawn cause via `.map_err(|_| ...)` instead of
    /// passing through anyhow's chain) would silently break this — the
    /// operator log would carry the domain narrative but lose the
    /// "Failed to run {op}" structural marker that distinguishes the
    /// spawn-failure path from the non-zero-exit path on the operator
    /// triage surface (THEORY §V.4 Phase 1 attestation-record discipline).
    #[tokio::test]
    async fn test_run_inherited_status_chains_with_caller_context_on_spawn_failure() {
        use anyhow::Context;
        let cmd = tokio::process::Command::new(
            "/nonexistent/path/to/inherited-status-binary-that-does-not-exist",
        );
        let err = run_inherited_status(cmd, "docker-compose up")
            .await
            .with_context(|| "Failed to start docker-compose".to_string())
            .expect_err("missing binary must fail");

        let outer = format!("{}", err);
        assert!(
            outer.contains("Failed to start docker-compose"),
            "outer Display must carry caller-supplied with_context wrap, got: {outer}"
        );

        let chained = format!("{:#}", err);
        assert!(
            chained.contains("Failed to start docker-compose"),
            "chain must carry outer domain narrative, got: {chained}"
        );
        assert!(
            chained.contains("Failed to run docker-compose up"),
            "chain must carry primitive's spawn-failure envelope (op label), got: {chained}"
        );

        let layers: Vec<String> = err.chain().map(|e| e.to_string()).collect();
        assert!(
            layers.len() >= 2,
            "anyhow chain must preserve at least the outer + primitive layers on spawn-failure, got {} layer(s): {:?}",
            layers.len(),
            layers
        );
    }

    /// A caller-supplied `.current_dir(...)` on the `tokio::process::Command`
    /// is preserved through `run_inherited_status` — the primitive only
    /// rewrites stdout / stderr and must leave every other field
    /// (current_dir, env, args, kill_on_drop, ...) untouched. Pinning this
    /// is load-bearing for the `commands/web_service.rs` migration: all four
    /// migrated sites (`pleme-linker regen` rooted at `repo_root`, `crate2nix
    /// generate` and `cargo update` rooted at the Hanabi platform package
    /// dir) drive their working directory via `cmd.current_dir(&path)`
    /// directly on the per-cmd `Command` rather than `env::set_current_dir`
    /// (which would mutate the forge process's cwd for every concurrent
    /// task). A future regression that added `cmd.current_dir(".")` or
    /// `cmd.current_dir(std::env::current_dir().unwrap())` inside the
    /// primitive would silently route every migrated site's command into
    /// forge's cwd rather than the Hanabi dir — a Cargo.lock at the wrong
    /// workspace, a deps.nix at the wrong frontend, no compile error, no
    /// test failure on the existing chain pins. This test catches that
    /// regression by construction: the probe shell exits 0 IFF its cwd
    /// contains the unique marker file written into the caller-supplied
    /// dir, so a primitive that resets current_dir fails the probe with
    /// `test -f` exit 1.
    ///
    /// Pre-this-test, every call site that drove cwd via cmd.current_dir
    /// was relying on an unpinned implementation detail of the primitive.
    /// Post-this-test, current_dir survival is part of the primitive's
    /// public typed contract — same way the chain-with-caller-context tests
    /// pinned the anyhow-composition contract for the federation /
    /// developer_tools migrations.
    #[tokio::test]
    async fn test_run_inherited_status_preserves_caller_supplied_current_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Unique marker name keeps the test hermetic regardless of what
        // happens to live in the test runner's cwd. If the primitive
        // rewrote current_dir, /bin/sh would run in some other directory
        // and `test -f` would fail with exit 1 — Err, not Ok.
        let marker_name = "forge_current_dir_marker_a1b2c3d4e5f6";
        std::fs::write(dir.path().join(marker_name), b"").expect("write marker");

        let mut cmd = tokio::process::Command::new("/bin/sh");
        cmd.arg("-c")
            .arg(format!("test -f {}", marker_name))
            .current_dir(dir.path());
        let result = run_inherited_status(cmd, "current-dir-probe").await;
        assert!(
            result.is_ok(),
            "primitive must preserve caller-supplied current_dir on the Command; got: {:?}",
            result.err().map(|e| format!("{:#}", e))
        );
    }

    /// A caller-supplied `.env(KEY, VAL)` on the `tokio::process::Command`
    /// survives the primitive's stdio override — same contract as
    /// current_dir survival, but on the env-var slot. Pinning env survival
    /// is the third leg of the field-survival contract (alongside the
    /// stdio-override and current_dir-preservation tests). Several already-
    /// migrated and prospective-migration sites set env vars on the
    /// per-cmd Command rather than the process-wide environment:
    /// `commands/rust_service.rs` AMD64/ARM64 build sites set `GIT_SHA`,
    /// `ATTIC_TOKEN`, `ATTIC_CACHE`, `ATTIC_SERVER` via
    /// `cmd.env(...)` so each parallel build carries its own attestation
    /// input bindings (Bazel / BuildKit per-spawn env shape — env is a
    /// typed field on the spawn request, not a side-effect of
    /// process-wide setenv). A future regression that added
    /// `cmd.env_clear()` or `cmd.env_remove(...)` inside the primitive
    /// (plausibly as a "make spawn-failure messages more hermetic by
    /// stripping inherited env" change) would silently route every
    /// migrated build site into an env-less subprocess — the build
    /// would fail with a confusing "ATTIC_TOKEN not set" or run with the
    /// wrong GIT_SHA, with no compile error and no failure on the
    /// stdio/current_dir/chain pins. This test catches that regression
    /// by construction: the probe shell exits 0 IFF the caller-supplied
    /// env var is visible to it, so a primitive that cleared or
    /// rewrote env fails the probe with `test "$VAR" = ...` exit 1.
    ///
    /// Pre-this-test, every call site that drove env via cmd.env was
    /// relying on an unpinned implementation detail. Post-this-test,
    /// env survival is part of the primitive's public typed contract —
    /// same way the current_dir-preservation test pinned the per-cmd
    /// cwd-survival contract for the web_service.rs migration.
    #[tokio::test]
    async fn test_run_inherited_status_preserves_caller_supplied_env_var() {
        // Unique key keeps the test hermetic regardless of what the test
        // runner's own environment happens to carry; unique value avoids
        // any accidental coincidence with an inherited setting.
        let probe_key = "FORGE_RETRY_ENV_PROBE_K7M3";
        let probe_val = "expected-survival-marker-9z8y7x";

        let mut cmd = tokio::process::Command::new("/bin/sh");
        cmd.arg("-c")
            .arg(format!("test \"${}\" = \"{}\"", probe_key, probe_val))
            .env(probe_key, probe_val);
        let result = run_inherited_status(cmd, "env-survival-probe").await;
        assert!(
            result.is_ok(),
            "primitive must preserve caller-supplied env() bindings on the Command; got: {:?}",
            result.err().map(|e| format!("{:#}", e))
        );
    }

    /// A caller-supplied `.args(...)` sequence on the
    /// `tokio::process::Command` survives the primitive's stdio override
    /// unchanged — the primitive must neither prepend, append, reorder,
    /// drop, nor mutate any element of the argv list. Pinning args
    /// survival is the fourth leg of the field-survival contract trio,
    /// alongside the stdio-override
    /// (`test_run_inherited_status_overrides_caller_supplied_stdio`),
    /// current_dir-preservation
    /// (`test_run_inherited_status_preserves_caller_supplied_current_dir`),
    /// and env-preservation
    /// (`test_run_inherited_status_preserves_caller_supplied_env_var`)
    /// pins. Every migrated site drives the operation it represents
    /// through `cmd.args([...])` and trusts the primitive not to
    /// interpose: a future regression that inserted a "wrapper" subcommand
    /// (`["sandboxed", ...original_args]`), stripped a flag, or shifted
    /// argv[0] would silently change every migrated site's semantics with
    /// no compile error and no failure on the stdio / current_dir / env /
    /// chain pins. The `commands/rust_service.rs` single-repo deploy path
    /// makes the dependency literal — three sites
    /// (`git add <manifest>`, `git commit -m <msg>`, `git push origin
    /// <branch>`) drive entirely through `.args(...)` with no
    /// current_dir, no env, no kill_on_drop, so argv fidelity is the
    /// only survival contract those three rely on. A primitive that
    /// rewrote argv would push to the wrong branch (`git push origin
    /// HEAD~1`) or commit with the wrong message — silently incorrect
    /// deploys, not loud failures.
    ///
    /// The probe encodes a content-addressable argv shape: a uniquely-
    /// labelled marker arg (`forge-args-survival-probe-c4d7e9f1`) and a
    /// uniquely-labelled value arg (`expected-args-marker-q8w7e6r5`),
    /// passed positionally so the shell receives `$1` = marker and `$2`
    /// = value. The test passes IFF both reach the subprocess in the
    /// exact slots the caller set. A primitive that prepended an
    /// argument would shift the marker to `$2`, fail the equality check,
    /// and surface the regression here rather than silently in a
    /// production `git push` shifted onto the wrong branch.
    #[tokio::test]
    async fn test_run_inherited_status_preserves_caller_supplied_args() {
        // Unique marker + value strings keep the test hermetic — no
        // chance of accidental coincidence with anything else the test
        // runner might have set or with /bin/sh's builtins.
        let marker = "forge-args-survival-probe-c4d7e9f1";
        let value = "expected-args-marker-q8w7e6r5";

        let mut cmd = tokio::process::Command::new("/bin/sh");
        // -c <script> "$0" "$1" "$2" — /bin/sh -c uses the first positional
        // as $0, so we feed "probe" as a throwaway $0 and our marker/value
        // arrive at $1/$2 inside the script.
        cmd.args([
            "-c",
            "test \"$1\" = \"forge-args-survival-probe-c4d7e9f1\" && \
             test \"$2\" = \"expected-args-marker-q8w7e6r5\"",
            "probe",
            marker,
            value,
        ]);
        let result = run_inherited_status(cmd, "args-survival-probe").await;
        assert!(
            result.is_ok(),
            "primitive must preserve caller-supplied .args() argv on the Command; got: {:?}",
            result.err().map(|e| format!("{:#}", e))
        );
    }
}
