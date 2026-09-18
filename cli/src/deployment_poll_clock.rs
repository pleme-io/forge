//! Deployment-pod-polling loop clock — the 3-line preamble
//!
//! ```ignore
//! let start = std::time::Instant::now();
//! let mut backoff_attempt: u32 = 0;
//! let mut last_diag_at = 0u64;
//! ```
//!
//! that opens every deployment-pod-polling loop this crate spawns.
//!
//! # Duplication being lifted
//!
//! Two pre-lift sibling sites in `commands/flux.rs` each restated the
//! identical 3-line "wall-clock start, retry-attempt counter, last
//! diagnostic-burst tick" triple, varying not at all:
//!
//! - `commands/flux.rs::verify_deployment_image` (line 535-537)
//! - `commands/flux.rs::wait_for_deployment` (line 630-632)
//!
//! Both loops thread the three locals into the same two typed sinks:
//!
//! - `start.elapsed().as_secs()` — read as `elapsed` at loop top
//! - `&mut last_diag_at` — passed to
//!   [`crate::commands::flux::emit_periodic_deployment_diagnostics_burst`]
//!   (lifted at 665c405) at loop bottom
//! - `&mut backoff_attempt` — passed to
//!   [`crate::poll_backoff_advance::advance_poll_backoff_tokio`]
//!   (lifted at eefebf5) at loop bottom
//!
//! Grouping the three fields into a typed value closes three classes of
//! defect the three separate locals silently admitted:
//!
//! 1. **Zero-init omission.** A future third poll loop that seeded
//!    `last_diag_at` to some non-zero value (or forgot to declare it)
//!    would suppress the first periodic diagnostic burst until 120s
//!    past the seed, or emit a burst on iteration 0 respectively. The
//!    typed [`DeploymentPollClock::new`] constructor pins the seed once.
//! 2. **Type slip.** `backoff_attempt: u32` and `last_diag_at: u64` are
//!    two distinct numeric widths that both zero-init to the same
//!    literal (`0`). A copy-paste that reversed the two would compile
//!    (each field's `saturating_add` / `saturating_sub` accepts the
//!    same-typed argument) but silently mis-track the cadence.
//! 3. **Cross-loop hoist.** Three separate locals inside a `loop { }`
//!    body cannot escape it; a `DeploymentPollClock` bound above the
//!    loop can. A future refactor that wrapped the poll loop in an
//!    outer retry (e.g., "re-run the entire verification after a Flux
//!    force-reconcile") gets a single [`DeploymentPollClock::new`] call
//!    at the outer boundary rather than three re-declarations.
//!
//! # Load-bearing invariants
//!
//! Two invariants the pre-lift 3-line preamble silently carried:
//!
//! 1. **`start` binds via `Instant::now()`, not `Instant::now() -
//!    Duration::from_secs(X)`.** The elapsed clock reads zero at the
//!    first iteration, so the first `emit_periodic_deployment_diagnostics_burst`
//!    check (`elapsed.saturating_sub(*last_diag_at) >= 120`) evaluates
//!    to `0 - 0 >= 120 = false` and no burst fires. A caller that
//!    seeded `start` with a past instant (`Instant::now() -
//!    Duration::from_secs(200)`) would fire a burst on iteration 0.
//! 2. **`last_diag_at = 0u64`, not `elapsed`.** Seeding
//!    `last_diag_at = elapsed` at loop entry would make the first
//!    burst wait 120s past whatever the first-iteration `elapsed` was
//!    — cascading the operator-visible-cadence off by up to
//!    `elapsed`'s magnitude. The `0u64` seed makes the first burst
//!    fire at the first iteration where `elapsed >= 120`.
//!
//! # Compounding
//!
//! A third deployment-pod-polling loop (a chart-release rollout probe,
//! a supergraph propagation wait, a cluster-overlay reconcile poll)
//! idiomatically forwards through [`DeploymentPollClock::new`] at ONE
//! call rather than restating the 3-line preamble. A future change —
//! swapping `Instant::now()` for a monotonic tick source, adding a
//! third field (`total_bursts_emitted: u32` for observability), or
//! bumping the diagnostic-burst cadence — lands at ONE typed body
//! rather than N copy-pasted lockstep edits.
//!
//! # Theory grounding
//!
//! THEORY.md §II (constructive substrate): the poll-loop clock is a
//! typed value with a single constructor, not three separate locals a
//! caller re-derives from convention. THEORY.md §VI.1 (three-times
//! rule): two occurrences is the "coincidence" threshold; the third
//! poll loop the fleet adds — which the pattern's structural momentum
//! makes inevitable — forwards through this primitive at zero
//! duplication cost.

/// Wall-clock and cadence-cursor bundle for a deployment-pod-polling
/// loop.
///
/// Threads three fields the two consumer loops in `commands/flux.rs`
/// each already carry:
///
/// - `start`: the monotonic wall clock the loop's `elapsed` reads
///   against (`self.elapsed_secs()`).
/// - `backoff_attempt`: the 0-indexed retry counter
///   [`crate::poll_backoff_advance::advance_poll_backoff_tokio`]
///   advances at each iteration.
/// - `last_diag_at`: the "elapsed value at the last diagnostic-burst
///   emit" cursor
///   [`crate::commands::flux::emit_periodic_deployment_diagnostics_burst`]
///   reads and updates.
///
/// # Field visibility
///
/// Both cursor fields are `pub` so the existing typed primitives can
/// take `&mut` borrows via ordinary disjoint field access
/// (`&mut clock.backoff_attempt`, `&mut clock.last_diag_at`). `start`
/// is `pub` for symmetry, though the intended read path is
/// [`Self::elapsed_secs`].
pub struct DeploymentPollClock {
    /// Loop-entry wall-clock instant. Read via [`Self::elapsed_secs`].
    pub start: std::time::Instant,
    /// 0-indexed retry counter, seeded to 0 at loop entry, advanced
    /// by [`crate::poll_backoff_advance::advance_poll_backoff_tokio`].
    pub backoff_attempt: u32,
    /// "Elapsed value at the last diagnostic-burst emit" cursor,
    /// seeded to 0 at loop entry so the first burst fires at the
    /// first iteration where `elapsed >= 120`.
    pub last_diag_at: u64,
}

impl DeploymentPollClock {
    /// Seed all three fields at loop entry:
    /// `start = Instant::now()`, `backoff_attempt = 0`,
    /// `last_diag_at = 0`.
    ///
    /// The two seed literals are load-bearing; see the module
    /// docstring's "Load-bearing invariants" section for the two
    /// cadence defects a divergent seed would silently admit.
    pub fn new() -> Self {
        Self {
            start: std::time::Instant::now(),
            backoff_attempt: 0,
            last_diag_at: 0u64,
        }
    }

    /// The wall-clock elapsed seconds since [`Self::new`] — the
    /// `elapsed` value at loop top and the argument the periodic
    /// burst / progress lines read against.
    pub fn elapsed_secs(&self) -> u64 {
        self.start.elapsed().as_secs()
    }
}

impl Default for DeploymentPollClock {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Zero-init invariant: a fresh [`DeploymentPollClock`] carries
    /// `backoff_attempt = 0` and `last_diag_at = 0`. A regression
    /// that seeded either cursor to a non-zero value would suppress
    /// the first periodic diagnostic burst (or, for `backoff_attempt`,
    /// consume the schedule mid-loop).
    #[test]
    fn deployment_poll_clock_new_zeros_both_cursors() {
        let clock = DeploymentPollClock::new();
        assert_eq!(
            clock.backoff_attempt, 0,
            "backoff_attempt must seed to 0 so the first \
             `advance_poll_backoff_tokio` reads schedule(0), not \
             schedule(N) for some post-restart carry-over N"
        );
        assert_eq!(
            clock.last_diag_at, 0u64,
            "last_diag_at must seed to 0u64 so the first \
             `emit_periodic_deployment_diagnostics_burst` check fires \
             at the first iteration where `elapsed >= 120`, not at \
             `elapsed >= last_diag_at + 120` for some non-zero seed"
        );
    }

    /// `elapsed_secs()` reads a value strictly less than 1 second at
    /// the instant of construction (no test sleep). A regression that
    /// seeded `start` with a past instant would fail this bound.
    #[test]
    fn deployment_poll_clock_elapsed_secs_reads_zero_at_construction() {
        let clock = DeploymentPollClock::new();
        assert_eq!(
            clock.elapsed_secs(),
            0,
            "elapsed_secs() must return 0 at the instant of \
             construction — a caller that seeded `start` with a past \
             instant (e.g., `Instant::now() - Duration::from_secs(200)`) \
             would fail this and silently fire a burst on iteration 0"
        );
    }

    /// `elapsed_secs()` reads a monotone-nondecreasing value across
    /// two successive calls with no intervening advance-time
    /// operation. Pins that the reader does not itself mutate the
    /// clock (a future refactor that swapped `Instant::now()` for a
    /// stateful tick source that advanced on read would fail here).
    #[test]
    fn deployment_poll_clock_elapsed_secs_is_monotone_across_reads() {
        let clock = DeploymentPollClock::new();
        let first = clock.elapsed_secs();
        let second = clock.elapsed_secs();
        assert!(
            second >= first,
            "elapsed_secs() must be monotone across successive reads; \
             saw first={} second={}",
            first,
            second,
        );
    }

    /// Disjoint-field-borrow shield: the two cursor fields can be
    /// mutably borrowed independently in the same expression, so the
    /// existing consumer primitives
    /// (`advance_poll_backoff_tokio(&mut clock.backoff_attempt, …)`,
    /// `emit_periodic_deployment_diagnostics_burst(…, &mut
    /// clock.last_diag_at)`) drop-in-replace the pre-lift
    /// `&mut backoff_attempt` / `&mut last_diag_at` local borrows
    /// without a borrow-checker collision. A regression that hid the
    /// fields behind a getter/setter API would break the drop-in
    /// substitution.
    #[test]
    fn deployment_poll_clock_disjoint_field_borrows_compose() {
        let mut clock = DeploymentPollClock::new();
        let backoff_ref: &mut u32 = &mut clock.backoff_attempt;
        let diag_ref: &mut u64 = &mut clock.last_diag_at;
        *backoff_ref = backoff_ref.saturating_add(1);
        *diag_ref = 120u64;
        assert_eq!(clock.backoff_attempt, 1);
        assert_eq!(clock.last_diag_at, 120u64);
    }

    /// Positive delegation shield: `commands/flux.rs`'s non-test body
    /// consumes [`DeploymentPollClock::new`] at ≥ 2 code lines (the
    /// two consumer loops — `verify_deployment_image` and
    /// `wait_for_deployment` — plus any future third loop) — the
    /// pre-lift 3-line `let start … let mut backoff_attempt …
    /// let mut last_diag_at …` preamble must not reappear at either
    /// site.
    ///
    /// The negative shields on the two pre-lift line shapes (`let mut
    /// backoff_attempt: u32 = 0;`, `let mut last_diag_at = 0u64;`)
    /// live at
    /// [`crate::commands::flux::tests::test_flux_polling_loops_route_deployment_poll_clock_new`]
    /// where they can bound the scan to the module's non-test body
    /// (the shield here would false-positive on this module's own
    /// docstring, which cites the pre-lift shape as context).
    #[test]
    fn deployment_poll_clock_new_delegated_from_flux_polling_loops() {
        let flux_body = include_str!("commands/flux.rs");
        let delegation_hits = crate::test_support::code_line_hits(
            crate::test_support::module_body_before_tests(flux_body, "commands/flux.rs"),
            "DeploymentPollClock::new()",
        );
        assert!(
            delegation_hits.len() >= 2,
            "commands/flux.rs must consume `DeploymentPollClock::new()` \
             at both polling loops' preamble sites — post-lift the \
             constructor is invoked at 2 call sites \
             (`verify_deployment_image`, `wait_for_deployment`). \
             Found:\n{}",
            delegation_hits.join("\n"),
        );
    }
}
