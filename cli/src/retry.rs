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
