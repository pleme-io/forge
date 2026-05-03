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
}
