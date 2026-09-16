//! Poll-loop backoff advance primitive — the 2-line stanza
//!
//! ```ignore
//! <tokio::time::sleep|std::thread::sleep>(<X>_poll_delay(backoff_attempt))<.await>?;
//! backoff_attempt = backoff_attempt.saturating_add(1);
//! ```
//!
//! that closes every retry/wait poll iteration across the codebase.
//!
//! # Duplication being lifted
//!
//! 9 pre-lift sibling sites (8 async, 1 sync) each restated the same
//! 2-line "sleep for the schedule-computed delay, then bump the attempt
//! counter" stanza, varying only in the `<X>_poll_delay` schedule
//! function and in the sleep flavour (async vs. blocking):
//!
//! Async (`tokio::time::sleep`):
//!
//! - `commands/flux.rs::verify_deployment_image` (`flux_poll_delay`)
//! - `commands/flux.rs::wait_for_deployment` (`flux_poll_delay`)
//! - `commands/comprehensive_release.rs::execute` (`services_healthy_poll_delay`)
//! - `commands/federation_tests.rs::wait_for_job_completion` (`federation_job_poll_delay`)
//! - `commands/github_runner_ci.rs::rollout` (`github_runner_rollout_poll_delay`)
//! - `commands/integration_tests.rs::wait_for_readiness` (`post_deployment_readiness_poll_delay`)
//! - `commands/migrations.rs::wait_for_shinka_migration` (`shinka_migration_poll_delay`)
//! - `services/migration_service.rs::wait_for_completion` (`migration_job_poll_delay`)
//!
//! Synchronous (`std::thread::sleep`):
//!
//! - `commands/e2e.rs::verify_docker_running` (`docker_startup_poll_delay`)
//!
//! Nine occurrences past THEORY.md §VI.1's three-times threshold
//! ("two occurrences is a coincidence; three is a law"). The
//! sleep-then-bump shape lifts onto ONE typed body per sleep flavour.
//!
//! # Load-bearing invariants
//!
//! Two invariants the pre-lift 2-line stanza silently carried at every
//! site — either broken by an ordering or arithmetic slip would drift
//! the schedule mid-loop, with no compile error and no test failure at
//! any single call site:
//!
//! 1. **Delay reads the PRE-bump counter.** The next-iteration delay is
//!    computed against `backoff_attempt`'s value BEFORE the bump. A
//!    caller that reversed the order (bump first, then compute delay
//!    against the bumped counter) would skip iteration 0's delay and
//!    consume the schedule one step ahead of the intended cadence.
//! 2. **`saturating_add(1)` is load-bearing.** A regular `+= 1` panics
//!    on `u32::MAX` in debug mode and silently wraps to 0 in release
//!    mode; either outcome would reset the schedule mid-loop for a
//!    pathologically long wait. `saturating_add(1)` clamps at
//!    `u32::MAX` and pins the schedule at its cap for the loop's
//!    remainder.
//!
//! # Compounding
//!
//! A tenth poll loop (a new deploy verification wait, a chart-release
//! rollout probe, a supergraph propagation wait) idiomatically forwards
//! through the same primitive at ONE call rather than copy-pasting the
//! 2-line stanza. A future change — a `tracing::debug!("poll iteration
//! {}", backoff_attempt)` structured tick between the sleep and the
//! bump, a `poll_backoff_iteration` metric emitted per advance, a
//! synchronous `tokio::task::yield_now()` between the sleep and the
//! bump for cooperative scheduling — lands at ONE typed body rather
//! than nine copy-pasted lockstep edits.
//!
//! # Theory grounding
//!
//! THEORY.md §VI.1 (three-times rule): nine sibling occurrences past
//! the "two is a coincidence; three is a law" threshold — the
//! sleep-then-bump shape lifts onto one typed body per sleep flavour.
//! THEORY.md §V.1 (Types → Invariants → Proofs → Render Anywhere):
//! the pre-bump-delay-then-saturating-bump ordering invariant lives in
//! `#[test]` fail-before-pass proofs against a recording schedule
//! rather than as an unwritten convention each call site restates.

use std::time::Duration;

/// Delay-schedule function pointer: `attempt -> Duration`.
///
/// Every `<X>_poll_delay(attempt: u32) -> Duration` module-scoped
/// function across the codebase — `flux_poll_delay`,
/// `shinka_migration_poll_delay`, `github_runner_rollout_poll_delay`,
/// `federation_job_poll_delay`, `migration_job_poll_delay`,
/// `post_deployment_readiness_poll_delay`, `services_healthy_poll_delay`,
/// `docker_startup_poll_delay` — fits this exact signature and
/// forwards through the two primitives below.
pub type PollDelaySchedule = fn(u32) -> Duration;

/// Sleep for `schedule(*backoff_attempt)` via [`tokio::time::sleep`],
/// then advance `*backoff_attempt` by one via [`u32::saturating_add`].
///
/// # Contract
///
/// 1. `schedule` is called with `*backoff_attempt`'s value BEFORE the
///    bump — the next-iteration delay reads the PRE-bump counter.
/// 2. `*backoff_attempt` is bumped by exactly one via `saturating_add`,
///    clamping at `u32::MAX` rather than panicking (debug) or
///    wrapping to 0 (release).
///
/// The 8 async poll-iteration sites listed in the module docstring
/// forward through this primitive.
pub async fn advance_poll_backoff_tokio(backoff_attempt: &mut u32, schedule: PollDelaySchedule) {
    tokio::time::sleep(schedule(*backoff_attempt)).await;
    *backoff_attempt = backoff_attempt.saturating_add(1);
}

/// Sleep for `schedule(*backoff_attempt)` via [`std::thread::sleep`]
/// (blocking, no async runtime), then advance `*backoff_attempt` by
/// one via [`u32::saturating_add`].
///
/// # Contract
///
/// Same pre-bump-delay-then-saturating-bump ordering invariant as
/// [`advance_poll_backoff_tokio`]; differs only in the sleep flavour
/// (blocking vs. tokio-yielding).
///
/// The 1 synchronous poll-iteration site — `commands/e2e.rs`
/// docker-startup wait — forwards through this primitive; the async
/// variant [`advance_poll_backoff_tokio`] covers the other 8.
pub fn advance_poll_backoff_thread(backoff_attempt: &mut u32, schedule: PollDelaySchedule) {
    std::thread::sleep(schedule(*backoff_attempt));
    *backoff_attempt = backoff_attempt.saturating_add(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn zero_delay(_attempt: u32) -> Duration {
        Duration::ZERO
    }

    /// Recording schedule: pushes each `attempt` value it is called
    /// with into a static slot indexed by call-count, returning
    /// [`Duration::ZERO`] so the tests do not actually sleep.
    ///
    /// The sync- and async-primitive tests use isolated slots so a
    /// parallel test run does not cross-contaminate. `u32::MAX` marks
    /// an unwritten slot.
    static SYNC_SEEN: [AtomicU32; 3] = [
        AtomicU32::new(u32::MAX),
        AtomicU32::new(u32::MAX),
        AtomicU32::new(u32::MAX),
    ];
    static SYNC_IDX: AtomicU32 = AtomicU32::new(0);

    fn sync_recording_schedule(attempt: u32) -> Duration {
        let i = SYNC_IDX.fetch_add(1, Ordering::SeqCst) as usize;
        if i < SYNC_SEEN.len() {
            SYNC_SEEN[i].store(attempt, Ordering::SeqCst);
        }
        Duration::ZERO
    }

    static TOKIO_SEEN: [AtomicU32; 3] = [
        AtomicU32::new(u32::MAX),
        AtomicU32::new(u32::MAX),
        AtomicU32::new(u32::MAX),
    ];
    static TOKIO_IDX: AtomicU32 = AtomicU32::new(0);

    fn tokio_recording_schedule(attempt: u32) -> Duration {
        let i = TOKIO_IDX.fetch_add(1, Ordering::SeqCst) as usize;
        if i < TOKIO_SEEN.len() {
            TOKIO_SEEN[i].store(attempt, Ordering::SeqCst);
        }
        Duration::ZERO
    }

    /// Invariant 1 for the sync primitive: `schedule` is called with
    /// the PRE-bump attempt counter (0, 1, 2), and the counter
    /// advances by exactly one per call (0 → 1 → 2 → 3).
    ///
    /// A caller that reversed the order (bump first, then compute
    /// delay) would report [1, 2, 3] in the recording slot; a
    /// caller that bumped by 2 would leave `counter == 6` at the end.
    #[test]
    fn advance_poll_backoff_thread_computes_delay_with_pre_bump_counter() {
        SYNC_IDX.store(0, Ordering::SeqCst);
        for s in &SYNC_SEEN {
            s.store(u32::MAX, Ordering::SeqCst);
        }

        let mut counter: u32 = 0;
        advance_poll_backoff_thread(&mut counter, sync_recording_schedule);
        assert_eq!(counter, 1);
        advance_poll_backoff_thread(&mut counter, sync_recording_schedule);
        assert_eq!(counter, 2);
        advance_poll_backoff_thread(&mut counter, sync_recording_schedule);
        assert_eq!(counter, 3);

        assert_eq!(
            SYNC_SEEN[0].load(Ordering::SeqCst),
            0,
            "schedule call 1 must see attempt=0 (PRE-bump); a caller \
             that bumped first would report attempt=1 here"
        );
        assert_eq!(SYNC_SEEN[1].load(Ordering::SeqCst), 1);
        assert_eq!(SYNC_SEEN[2].load(Ordering::SeqCst), 2);
    }

    /// Invariant 2 for the sync primitive: at `u32::MAX` the counter
    /// clamps to `u32::MAX` rather than panicking or wrapping.
    /// `saturating_add(1)` is load-bearing: a regular `+= 1` would
    /// either panic (debug) or wrap to 0 (release), resetting the
    /// schedule mid-loop.
    #[test]
    fn advance_poll_backoff_thread_saturates_at_u32_max() {
        let mut counter = u32::MAX;
        advance_poll_backoff_thread(&mut counter, zero_delay);
        assert_eq!(
            counter,
            u32::MAX,
            "saturating_add(1) at u32::MAX must clamp to u32::MAX — \
             a regular `+= 1` would either panic (debug) or wrap to 0 \
             (release), resetting the schedule mid-loop for a \
             pathologically long wait"
        );
    }

    /// Invariant 1 for the async primitive: same pre-bump semantics
    /// as the sync sibling.
    #[tokio::test]
    async fn advance_poll_backoff_tokio_computes_delay_with_pre_bump_counter() {
        TOKIO_IDX.store(0, Ordering::SeqCst);
        for s in &TOKIO_SEEN {
            s.store(u32::MAX, Ordering::SeqCst);
        }

        let mut counter: u32 = 0;
        advance_poll_backoff_tokio(&mut counter, tokio_recording_schedule).await;
        assert_eq!(counter, 1);
        advance_poll_backoff_tokio(&mut counter, tokio_recording_schedule).await;
        assert_eq!(counter, 2);
        advance_poll_backoff_tokio(&mut counter, tokio_recording_schedule).await;
        assert_eq!(counter, 3);

        assert_eq!(TOKIO_SEEN[0].load(Ordering::SeqCst), 0);
        assert_eq!(TOKIO_SEEN[1].load(Ordering::SeqCst), 1);
        assert_eq!(TOKIO_SEEN[2].load(Ordering::SeqCst), 2);
    }

    /// Invariant 2 for the async primitive: same saturating semantics
    /// as the sync sibling.
    #[tokio::test]
    async fn advance_poll_backoff_tokio_saturates_at_u32_max() {
        let mut counter = u32::MAX;
        advance_poll_backoff_tokio(&mut counter, zero_delay).await;
        assert_eq!(counter, u32::MAX);
    }

    /// Positive delegation shield: the 9 pre-lift poll-iteration sites
    /// (8 async + 1 sync) MUST forward through the two primitives
    /// above — one delegation per file at minimum, 9 total minimum
    /// across the fleet. A future poll loop that dropped a forward
    /// would leave a paired negative-caller shield in each file (see
    /// `no_raw_backoff_saturating_add_in_command_modules` below)
    /// trivially satisfied by absence; this positive count catches
    /// that.
    #[test]
    fn call_sites_forward_through_advance_poll_backoff() {
        const SOURCES: &[(&str, &str)] = &[
            ("commands/flux.rs", include_str!("commands/flux.rs")),
            (
                "commands/comprehensive_release.rs",
                include_str!("commands/comprehensive_release.rs"),
            ),
            (
                "commands/federation_tests.rs",
                include_str!("commands/federation_tests.rs"),
            ),
            (
                "commands/github_runner_ci.rs",
                include_str!("commands/github_runner_ci.rs"),
            ),
            (
                "commands/integration_tests.rs",
                include_str!("commands/integration_tests.rs"),
            ),
            (
                "commands/migrations.rs",
                include_str!("commands/migrations.rs"),
            ),
            (
                "services/migration_service.rs",
                include_str!("services/migration_service.rs"),
            ),
            ("commands/e2e.rs", include_str!("commands/e2e.rs")),
        ];

        let tokio_needle = "crate::poll_backoff_advance::advance_poll_backoff_tokio(";
        let thread_needle = "crate::poll_backoff_advance::advance_poll_backoff_thread(";

        let mut total_forwards = 0usize;
        for (path, source) in SOURCES {
            let tokio_forwards = crate::test_support::code_line_hits(source, tokio_needle).len();
            let thread_forwards = crate::test_support::code_line_hits(source, thread_needle).len();
            let hits = tokio_forwards + thread_forwards;
            assert!(
                hits >= 1,
                "{path} must forward at least one poll-backoff advance \
                 through the typed primitive; found tokio={tokio_forwards} \
                 thread={thread_forwards}"
            );
            total_forwards += hits;
        }
        assert!(
            total_forwards >= 9,
            "the 9 pre-lift poll-iteration call sites (8 async + 1 sync) \
             must forward through the poll-backoff-advance primitives; \
             found {total_forwards} total"
        );
    }

    /// Negative caller shield: no raw
    /// `backoff_attempt = backoff_attempt.saturating_add(1);`
    /// line may live in the per-command modules outside the two
    /// forwards above. The primitive's own body carries the
    /// `*backoff_attempt = backoff_attempt.saturating_add(1);` shape
    /// (dereference on the left-hand side), which is a distinct
    /// spelling, so this shield's needle does not self-match here
    /// either.
    #[test]
    fn no_raw_backoff_saturating_add_in_command_modules() {
        const SOURCES: &[(&str, &str)] = &[
            ("commands/flux.rs", include_str!("commands/flux.rs")),
            (
                "commands/comprehensive_release.rs",
                include_str!("commands/comprehensive_release.rs"),
            ),
            (
                "commands/federation_tests.rs",
                include_str!("commands/federation_tests.rs"),
            ),
            (
                "commands/github_runner_ci.rs",
                include_str!("commands/github_runner_ci.rs"),
            ),
            (
                "commands/integration_tests.rs",
                include_str!("commands/integration_tests.rs"),
            ),
            (
                "commands/migrations.rs",
                include_str!("commands/migrations.rs"),
            ),
            (
                "services/migration_service.rs",
                include_str!("services/migration_service.rs"),
            ),
            ("commands/e2e.rs", include_str!("commands/e2e.rs")),
        ];

        // Assemble the needle at test time from two fragments so this
        // shield's own body does not self-match on any single line.
        let needle_a = "backoff_attempt = backoff_attempt";
        let needle_b = ".saturating_add(1)";
        let needle = format!("{}{}", needle_a, needle_b);

        for (path, source) in SOURCES {
            let hits = crate::test_support::code_line_hits(source, &needle);
            assert!(
                hits.is_empty(),
                "{path} must NOT restate the raw \
                 `backoff_attempt = backoff_attempt.saturating_add(1);` \
                 line — route through \
                 `crate::poll_backoff_advance::advance_poll_backoff_tokio` \
                 (async) or \
                 `crate::poll_backoff_advance::advance_poll_backoff_thread` \
                 (sync) instead. Found:\n{}",
                hits.join("\n"),
            );
        }
    }
}
