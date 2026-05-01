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
}
