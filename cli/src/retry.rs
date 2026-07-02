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
///
/// # Structural equality
///
/// `RetryPolicy` derives [`PartialEq`] and [`Eq`] through its four
/// `Eq`-bound struct fields (`u32`, [`Duration`], `u32`, [`Duration`]),
/// closing the structural-equality reading at the typed-primitive
/// surface. Equality is field-wise extensional: two policies are equal
/// iff their `max_attempts`, `initial_backoff`, `factor`, and
/// `max_backoff` match exactly. The derive makes a downstream
/// consumer's "this policy matches the canonical
/// [`Self::network`] / [`Self::immediate`] / [`Self::network_or_immediate`]
/// / [`Self::network_with_max_attempts`] / [`Self::with_max_attempts`]
/// shape" reading a one-line `assert_eq!` or `==` against the
/// reference factory at the consumer site, rather than a four-field
/// cascade against each struct field independently — exactly the
/// `THEORY §VI.1` one-oracle discipline lift the prior factory-
/// constructor commits (75d495e / 85ccff4) applied at the
/// construction surface, here applied at the comparison surface.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Where a 1-indexed `attempt` sits under a [`RetryPolicy`]'s per-attempt
/// axis — the typed sum consuming the closed per-attempt-axis BOOLEAN 3×2
/// grid at ONE reading.
///
/// The per-attempt-axis boolean surface pinned by
/// [`tests::test_retry_policy_floor_ceiling_boolean_split_universal_property`]
/// factors into two 3-way partitions (`is_before_first_attempt` /
/// `is_first_attempt` / `is_retry_attempt` at the FLOOR side, `is_over_budget`
/// / `is_final_attempt` / `is_interim_attempt` at the CEILING side).
/// `PerAttemptRegion` names the load-bearing 5-way projection through the
/// cross-product: every `(policy, attempt)` maps to exactly one variant,
/// and the mapping is a pure function of the boolean peers at that input.
///
/// # The 5-way partition
///
/// For a policy with `M = self.effective_max_attempts()` (clamped to ≥ 1),
/// the projection reads:
///
/// | Region        | Condition                                            |
/// | ------------- | ---------------------------------------------------- |
/// | `BeforeFirst` | `attempt < 1`                                        |
/// | `First`       | `attempt == 1` AND `attempt < M`                     |
/// | `Interim`     | `attempt > 1` AND `attempt < M`                      |
/// | `Final`       | `attempt == M` (may collide with `First` when M = 1) |
/// | `OverBudget`  | `attempt > M`                                        |
///
/// The collision at `attempt == 1 == M` (a single-attempt policy calling
/// `op(1)`) is resolved by the CEILING side: the region is [`Final`], not
/// [`First`]. This matches the load-bearing distinction the retry loop
/// itself reads — a single-attempt policy short-circuits at `is_final_attempt`
/// regardless of whether the attempt is also the first, so the projection
/// preserves the termination-relevant classification at the collision.
///
/// # Consumers
///
/// The projection lets a downstream telemetry emitter, structured-
/// attestation surface, or defensive pre-invocation guard read ONE typed
/// label instead of restating the FLOOR-then-CEILING boolean cascade:
///
/// * A per-attempt telemetry label that discriminates
///   `BeforeFirst` / `First` / `Interim` / `Final` / `OverBudget` reads
///   [`RetryPolicy::per_attempt_region`] once instead of six inline
///   boolean readings against the raw
///   [`RetryPolicy::is_before_first_attempt`] /
///   [`RetryPolicy::is_first_attempt`] / [`RetryPolicy::is_retry_attempt`] /
///   [`RetryPolicy::is_final_attempt`] /
///   [`RetryPolicy::is_interim_attempt`] / [`RetryPolicy::is_over_budget`]
///   ladder.
/// * A structured-attestation record classifying per-attempt events
///   against the SLSA chain reads the sum type directly, and a future
///   variant insertion (e.g., splitting `First` into `FirstAndOnly` for
///   single-attempt policies vs `FirstOfMany` for multi-attempt policies)
///   forces every consumer's exhaustive `match` to extend by construction.
/// * A defensive pre-invocation guard that skips `op(attempt)` on
///   out-of-band attempt indices reads `matches!(region, BeforeFirst
///   | OverBudget)` at ONE site instead of two independent boolean
///   readings.
///
/// # THEORY grounding
///
/// THEORY.md §II Language — typed primitives own boundary classification;
/// the per-attempt-axis 3×2 boolean grid closure is projected here as ONE
/// typed sum instead of read as six boolean peers at every downstream
/// consumer. THEORY.md §VI.1 one-oracle discipline — the FLOOR-then-CEILING
/// boolean cascade is named at ONE typed-primitive site
/// ([`RetryPolicy::per_attempt_region`]); downstream consumers of the
/// per-attempt classification read the sum instead of restating the
/// cascade.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PerAttemptRegion {
    /// STRICTLY before the FLOOR boundary — `attempt < 1` (equivalently,
    /// `attempt == 0`). The "pre-invocation counter reading" class: a
    /// telemetry replay of a state before any `op(attempt)` call has been
    /// made, or a caller-bug diagnostic for an out-of-band pre-invocation
    /// index. Grounds through [`RetryPolicy::is_before_first_attempt`].
    BeforeFirst,
    /// AT the FLOOR boundary and STRICTLY below the CEILING boundary —
    /// `attempt == 1` AND `attempt < self.effective_max_attempts()`. The
    /// first live `op(attempt)` call in a multi-attempt schedule. The
    /// FLOOR/CEILING collision at `attempt == 1 == M` (single-attempt
    /// policies) is absorbed by [`PerAttemptRegion::Final`], not by
    /// `First` — the CEILING side wins because it names the termination-
    /// relevant class the retry loop itself reads.
    First,
    /// STRICTLY between the FLOOR and CEILING boundaries — `attempt > 1`
    /// AND `attempt < self.effective_max_attempts()`. A mid-schedule
    /// retry attempt.
    Interim,
    /// AT the CEILING boundary — `attempt == self.effective_max_attempts()`.
    /// The final attempt in the schedule; the retry loop short-circuits
    /// after this call. Absorbs the FLOOR/CEILING collision at
    /// `attempt == 1 == M` — see [`PerAttemptRegion::First`].
    Final,
    /// STRICTLY past the CEILING boundary — `attempt >
    /// self.effective_max_attempts()`. A caller-bug or telemetry-replay
    /// diagnostic class distinct from [`Final`]: an attempt index the
    /// retry loop could never legally produce under this policy. Grounds
    /// through [`RetryPolicy::is_over_budget`].
    ///
    /// [`Final`]: PerAttemptRegion::Final
    OverBudget,
}

impl PerAttemptRegion {
    /// Every [`PerAttemptRegion`] variant, listed in per-attempt-axis
    /// order (`BeforeFirst < First < Interim < Final < OverBudget`) — the
    /// single-source enumeration of the typed sum. The named peer of the
    /// array-literal restatement pattern the sibling
    /// [`crate::probe_outcome::AdmissionTier::ALL`] and
    /// [`crate::version::BumpLevel::ALL`] enumerations closed at their
    /// surfaces (95e74ae / f891180): an exhaustive-cover property test,
    /// a telemetry-label enumeration, or a debug-print traversal reads
    /// this const instead of restating the variant list.
    ///
    /// The exhaustive `match` in
    /// [`tests::test_per_attempt_region_all_contains_every_variant`]
    /// refuses compilation until a future variant is added to `ALL`, so
    /// property tests iterating `PerAttemptRegion::ALL` automatically
    /// pick up new variants without per-site edits.
    #[allow(dead_code)]
    pub const ALL: [PerAttemptRegion; 5] = [
        PerAttemptRegion::BeforeFirst,
        PerAttemptRegion::First,
        PerAttemptRegion::Interim,
        PerAttemptRegion::Final,
        PerAttemptRegion::OverBudget,
    ];

    /// True iff `self` is one of [`PerAttemptRegion::Final`] or
    /// [`PerAttemptRegion::OverBudget`] — the load-bearing CEILING peer at
    /// the projected sum surface. Names the "retry loop short-circuits
    /// after (or without invoking) this attempt" reading at ONE typed
    /// method instead of restating the two-variant `matches!` disjunction
    /// at every downstream consumer.
    ///
    /// # Semantic role
    ///
    /// The retry loop's structural short-circuit condition — the schedule
    /// terminates rather than dispatching another `op(attempt + 1)` — is
    /// `attempt >= self.effective_max_attempts()`. That condition is the
    /// UNION of the two ladder-ceiling regions at the sum surface:
    /// [`PerAttemptRegion::Final`] (the last legal in-schedule attempt,
    /// `attempt == M`) AND [`PerAttemptRegion::OverBudget`] (attempts
    /// STRICTLY past the schedule, `attempt > M`, that a caller-bug or
    /// telemetry-replay could still surface). A downstream consumer that
    /// says "on this attempt, DO NOT dispatch a follow-up" — a retry-loop
    /// exit condition, a fail-terminal telemetry emitter, a
    /// budget-exhausted diagnostic classifier — reads
    /// `region.is_terminal()` at ONE site instead of writing
    /// `matches!(region, Final | OverBudget)` or the equivalent
    /// `p.is_final_attempt(attempt) || p.is_over_budget(attempt)` boolean
    /// disjunction at the boolean-peer ladder each site.
    ///
    /// # Why the two-variant disjunction (not just [`Final`])
    ///
    /// The retry-loop short-circuit MUST cover both variants: `Final`
    /// alone omits the caller-bug diagnostic class where a consumer
    /// legitimately holds an attempt index past the budget (a persisted
    /// index from a prior policy with a larger `M`, a telemetry-replay of
    /// an over-budget value, a manual invocation with a hand-written
    /// index) and would still want to skip dispatch. Naming the disjunction
    /// at the sum surface refuses the silent classification drift a
    /// downstream `matches!(region, Final)` predicate leaves open — every
    /// terminal reading grounds through this method, and a future variant
    /// insertion at the ceiling side (e.g., a hypothetical
    /// `PerAttemptRegion::CancelledByCaller` inserted between `Final` and
    /// `OverBudget`) forces the compilation error at ONE named site
    /// rather than at every consumer's inline `matches!` disjunction.
    ///
    /// # De Morgan complement
    ///
    /// The complement `!self.is_terminal()` names the "retry loop may
    /// dispatch a follow-up after this attempt" reading — the disjunction
    /// `BeforeFirst | First | Interim` at the sum surface. Future
    /// compounding: a named `is_pre_terminal(&self) -> bool` De Morgan peer
    /// closes the 2-way split at the projected surface — the same
    /// FLOOR/CEILING BOOLEAN COMPLEMENT idiom
    /// [`RetryPolicy::is_retry_attempt`] applies at the FLOOR side of the
    /// boolean-peer ladder (commit 3359c54).
    ///
    /// # Grounding through the boolean-peer ladder
    ///
    /// `region.is_terminal()` grounds through the CEILING-side
    /// boolean-peer disjunction at every `(policy, attempt)`:
    /// `self.per_attempt_region(attempt).is_terminal()` iff
    /// `self.is_final_attempt(attempt) || self.is_over_budget(attempt)`
    /// iff `attempt >= self.effective_max_attempts()`. Pinned by
    /// [`tests::test_retry_policy_per_attempt_region_is_terminal_iff_ge_effective_max`]
    /// across the canonical policy grid × attempt-index grid.
    ///
    /// # Idiom lineage
    ///
    /// Sibling of [`crate::probe_outcome::AdmissionTier::is_strict`]
    /// (commit 1775181) and [`crate::version::BumpLevel::is_major_only`]
    /// (commit 79e7dde) at their respective ladder-ceiling variant-
    /// identity peers — here at the projected sum surface, the CEILING
    /// reading spans TWO variants (`Final | OverBudget`) because the
    /// projection factors the CEILING half-open ray of the per-attempt
    /// axis into the ladder-ceiling variant (`Final`) and the
    /// STRICTLY-past-ceiling variant (`OverBudget`) at commit b3aeb92 /
    /// eb0d5d1 / 158c06a. The disjunction reading at this method's body
    /// closes the CEILING half-open ray at ONE named surface at the sum
    /// level.
    ///
    /// # THEORY grounding
    ///
    /// THEORY.md §II Language — typed primitives own boundary
    /// classification; the CEILING half-open ray at the projected sum
    /// surface is named at ONE typed method (`is_terminal`) rather than
    /// restated as the two-variant `matches!` disjunction or as the
    /// two-peer boolean-ladder disjunction at every downstream consumer.
    /// THEORY.md §VI.1 one-oracle — the "retry loop short-circuits after
    /// this attempt" semantic role is named at one site (this method's
    /// body), so a downstream retry-loop exit condition, a fail-terminal
    /// telemetry emitter, or a budget-exhausted diagnostic classifier
    /// reads `region.is_terminal()` once and is automatically extended
    /// across a future CEILING-side variant insertion when this method is
    /// updated.
    #[allow(dead_code)]
    pub const fn is_terminal(&self) -> bool {
        matches!(
            *self,
            PerAttemptRegion::Final | PerAttemptRegion::OverBudget
        )
    }

    /// True iff `self` is one of [`PerAttemptRegion::BeforeFirst`],
    /// [`PerAttemptRegion::First`], or [`PerAttemptRegion::Interim`] —
    /// the load-bearing FLOOR peer at the projected sum surface, the
    /// De Morgan complement of [`PerAttemptRegion::is_terminal`]. Names
    /// the "retry loop MAY dispatch a follow-up `op(attempt + 1)` after
    /// (or before) this attempt" reading at ONE typed method instead of
    /// restating either the three-variant `matches!` disjunction or the
    /// negated CEILING peer (`!region.is_terminal()`) at every downstream
    /// consumer.
    ///
    /// # Semantic role
    ///
    /// The retry loop's structural non-short-circuit condition — the
    /// schedule may still dispatch another attempt after (or has not yet
    /// invoked) `op(attempt)` — is `attempt < self.effective_max_attempts()`.
    /// That condition is the UNION of the three non-CEILING regions at the
    /// sum surface: [`PerAttemptRegion::BeforeFirst`] (the pre-invocation
    /// counter reading, `attempt < 1`), [`PerAttemptRegion::First`] (the
    /// first live `op(attempt)` call in a multi-attempt schedule), and
    /// [`PerAttemptRegion::Interim`] (a mid-schedule retry attempt). A
    /// downstream consumer that says "on this attempt, the retry loop is
    /// still live" — a pre-attempt guard, a "may-retry" telemetry
    /// discriminator, a structured-attestation surface recording "this
    /// attempt did NOT terminate the schedule" against the SLSA chain —
    /// reads `region.is_pre_terminal()` at ONE site instead of writing
    /// `matches!(region, BeforeFirst | First | Interim)`,
    /// `!region.is_terminal()`, or the equivalent
    /// `p.is_before_first_attempt(attempt) || p.is_first_attempt(attempt)
    /// || p.is_retry_attempt(attempt) && !p.is_final_attempt(attempt)`
    /// cascade at each site.
    ///
    /// # Idiom lineage
    ///
    /// Sibling of [`RetryPolicy::is_retry_attempt`] (commit 3359c54) at
    /// the FLOOR side of the boolean-peer ladder — the same FLOOR/CEILING
    /// BOOLEAN COMPLEMENT idiom the boolean-peer ladder established when
    /// closing the CEILING peer [`RetryPolicy::is_final_attempt`] (d55b12b)
    /// with its FLOOR complement [`RetryPolicy::is_retry_attempt`]. Here
    /// at the projected sum surface, the FLOOR reading spans THREE
    /// variants because the projection factors the FLOOR half-open ray
    /// of the per-attempt axis into the STRICTLY-below-floor variant
    /// (`BeforeFirst` — b3aeb92), the ladder-floor variant (`First` —
    /// 1123c2c), and the strictly-between-boundaries variant (`Interim` —
    /// 14c0de3) at commits 158c06a / 494c053.
    ///
    /// # Why the three-variant disjunction (not just the CEILING negation)
    ///
    /// A downstream `!region.is_terminal()` restatement carries the same
    /// truth-table but leaves the "retry loop may dispatch" reading
    /// implicit at the negation site — the reader must trace the CEILING
    /// peer's docstring to recover the "loop is still live" semantic
    /// role. Naming the disjunction at ONE typed method surfaces the
    /// affirmative reading (the retry loop is NOT short-circuited on
    /// this attempt) as the load-bearing typed-primitive surface, matching
    /// the same affirmative-vs-negated discipline
    /// [`RetryPolicy::is_retry_attempt`] surfaces at the boolean-peer
    /// ladder's FLOOR side (`attempt > 1` named at ONE method, not
    /// restated as `!p.is_first_attempt(attempt)` at every consumer). The
    /// pin at
    /// [`tests::test_per_attempt_region_is_pre_terminal_complements_is_terminal`]
    /// enforces the De Morgan complement law across every
    /// [`PerAttemptRegion::ALL`] variant so a future CEILING-side variant
    /// insertion desyncs at ONE named site rather than at every consumer's
    /// inline `matches!` disjunction.
    ///
    /// # Grounding through the boolean-peer ladder
    ///
    /// `region.is_pre_terminal()` grounds through the FLOOR-side numeric
    /// axis at every `(policy, attempt)`:
    /// `self.per_attempt_region(attempt).is_pre_terminal()` iff
    /// `attempt < self.effective_max_attempts()`. Pinned by
    /// [`tests::test_retry_policy_per_attempt_region_is_pre_terminal_iff_lt_effective_max`]
    /// across the canonical policy grid × attempt-index grid.
    ///
    /// # THEORY grounding
    ///
    /// THEORY.md §II Language — typed primitives own boundary
    /// classification; the FLOOR half-open ray at the projected sum
    /// surface is named at ONE typed method (`is_pre_terminal`) rather
    /// than restated as the three-variant `matches!` disjunction or as
    /// the negated CEILING peer at every downstream consumer.
    /// THEORY.md §VI.1 one-oracle — the "retry loop MAY dispatch a
    /// follow-up after this attempt" semantic role is named at one site
    /// (this method's body), so a downstream pre-attempt guard, a
    /// "may-retry" telemetry discriminator, or an in-schedule attestation
    /// classifier reads `region.is_pre_terminal()` once and is
    /// automatically extended across a future FLOOR-side variant insertion
    /// when this method is updated.
    #[allow(dead_code)]
    pub const fn is_pre_terminal(&self) -> bool {
        !self.is_terminal()
    }

    /// True iff `self` is one of [`PerAttemptRegion::BeforeFirst`] or
    /// [`PerAttemptRegion::OverBudget`] — the load-bearing OUT-OF-SCHEDULE
    /// peer at the projected sum surface. Names the "the retry loop would
    /// NEVER legally reach this attempt index under this policy — the
    /// index is either strictly before the first legal call (a
    /// pre-invocation counter reading) or strictly past the last legal
    /// call (a bug / telemetry-replay)" reading at ONE typed method
    /// instead of restating the two-variant `matches!` disjunction, the
    /// two-peer strict-boundary boolean disjunction
    /// (`p.is_before_first_attempt(a) || p.is_over_budget(a)`), or the
    /// range-complement `!(1..=M).contains(&attempt)` at every downstream
    /// consumer.
    ///
    /// # Semantic role
    ///
    /// The two variants this disjunction covers are the diagnostic
    /// classes at the STRICT boundaries of the per-attempt axis: the
    /// pre-invocation index (`attempt < 1`) and the past-budget index
    /// (`attempt > effective_max_attempts()`). Neither can be produced by
    /// the retry loop at [`run_with_policy`] — the loop's counter starts
    /// at `1` and short-circuits at [`PerAttemptRegion::Final`], so the
    /// live sequence the loop produces is
    /// `First -> (Interim -> ...) -> Final`, wholly inside the closed
    /// inclusive interval `[1, M]`. A downstream consumer receiving an
    /// out-of-band `attempt` index (a persisted counter reading from a
    /// prior policy with a different `M`, a telemetry-replay of a
    /// serialized attempt index, a deserialization or caller-bug source)
    /// that says "this index is a bug/replay diagnostic class distinct
    /// from any live in-schedule attempt" — a defensive pre-invocation
    /// guard, a structured-attestation surface recording an out-of-band
    /// provenance datum, a telemetry emitter distinguishing bug/replay
    /// classes from live-invocation classes against the SLSA chain —
    /// reads `region.is_out_of_schedule()` at ONE site instead of
    /// writing `matches!(region, BeforeFirst | OverBudget)` or the
    /// two-peer boolean disjunction at each site.
    ///
    /// # Orthogonal to the terminal axis
    ///
    /// The sum surface now names TWO orthogonal binary axes:
    ///
    /// |                | in-schedule (legal live attempt)  | out-of-schedule (bug/replay)  |
    /// | -------------- | --------------------------------- | ----------------------------- |
    /// | pre-terminal   | `First`, `Interim`                | `BeforeFirst`                 |
    /// | terminal       | `Final`                           | `OverBudget`                  |
    ///
    /// [`is_terminal`](Self::is_terminal) /
    /// [`is_pre_terminal`](Self::is_pre_terminal) names the "does the
    /// retry loop short-circuit after this attempt?" axis;
    /// `is_out_of_schedule` (and its complement, the affirmative
    /// in-schedule reading) names the "is this attempt index a live
    /// in-schedule invocation or a bug/replay diagnostic?" axis. The
    /// two axes cross-classify every variant, so a future consumer that
    /// needs the FULL 2×2 grid reads both peers independently rather
    /// than restating either axis at every emission site. Pinned by
    /// [`tests::test_per_attempt_region_out_of_schedule_orthogonal_to_terminal`].
    ///
    /// # Grounding through the strict-boundary boolean peers
    ///
    /// `region.is_out_of_schedule()` grounds through the STRICT-boundary
    /// disjunction on the numeric axis at every `(policy, attempt)`:
    /// `self.per_attempt_region(attempt).is_out_of_schedule()` iff
    /// `self.is_before_first_attempt(attempt) || self.is_over_budget(attempt)`
    /// iff `attempt < 1 || attempt > self.effective_max_attempts()`.
    /// Pinned by
    /// [`tests::test_retry_policy_per_attempt_region_is_out_of_schedule_iff_strict_boundary`]
    /// across the canonical policy grid × attempt-index grid.
    ///
    /// # De Morgan complement
    ///
    /// The complement `!self.is_out_of_schedule()` names the "the retry
    /// loop legally invokes `op(attempt)` at this attempt index" reading
    /// — the disjunction `First | Interim | Final` at the sum surface,
    /// equivalent to the closed inclusive range `1 <= attempt <= M`.
    /// Future compounding: a named `is_in_schedule(&self) -> bool` De
    /// Morgan peer closes the 2-way in-schedule/out-of-schedule split at
    /// the projected surface, the same FLOOR/CEILING BOOLEAN COMPLEMENT
    /// idiom [`is_terminal`](Self::is_terminal) /
    /// [`is_pre_terminal`](Self::is_pre_terminal) applies at the
    /// terminal axis.
    ///
    /// # Idiom lineage
    ///
    /// Sibling of [`is_terminal`](Self::is_terminal) at the sum surface
    /// — both are two-variant disjunctions naming a load-bearing binary
    /// axis. Where `is_terminal` names the CEILING half-open ray at the
    /// TERMINAL axis (`{Final, OverBudget}`, `attempt >= M`),
    /// `is_out_of_schedule` names the DIAGONAL disjunction at the
    /// SCHEDULE axis (`{BeforeFirst, OverBudget}`, `attempt < 1 || attempt > M`).
    /// The `OverBudget` variant sits at the intersection of both axes'
    /// affirmative readings — it is BOTH terminal AND out-of-schedule —
    /// while `Final` is terminal but IN-SCHEDULE and `BeforeFirst` is
    /// out-of-schedule but PRE-TERMINAL. The 2×2 grid pin refuses the
    /// silent axis-collapse a downstream consumer might infer from the
    /// shared `OverBudget` variant.
    ///
    /// # THEORY grounding
    ///
    /// THEORY.md §II Language — typed primitives own boundary
    /// classification; the STRICT-boundary disjunction at the projected
    /// sum surface is named at ONE typed method (`is_out_of_schedule`)
    /// rather than restated as the two-variant `matches!` disjunction or
    /// as the two-peer strict-boundary boolean disjunction at every
    /// downstream consumer. THEORY.md §VI.1 one-oracle — the "attempt
    /// index is a bug/replay diagnostic class distinct from any live
    /// in-schedule invocation" semantic role is named at one site (this
    /// method's body), so a downstream defensive pre-invocation guard, a
    /// structured-attestation surface recording out-of-band provenance,
    /// or a telemetry emitter distinguishing bug/replay from
    /// live-invocation classes reads `region.is_out_of_schedule()` once
    /// and is automatically extended across a future STRICT-boundary
    /// variant insertion when this method is updated.
    #[allow(dead_code)]
    pub const fn is_out_of_schedule(&self) -> bool {
        matches!(
            *self,
            PerAttemptRegion::BeforeFirst | PerAttemptRegion::OverBudget
        )
    }

    /// True iff `self` is one of [`PerAttemptRegion::First`],
    /// [`PerAttemptRegion::Interim`], or [`PerAttemptRegion::Final`] —
    /// the load-bearing IN-SCHEDULE peer at the projected sum surface,
    /// the De Morgan complement of
    /// [`PerAttemptRegion::is_out_of_schedule`]. Names the "the retry
    /// loop LEGALLY invokes `op(attempt)` at this attempt index under
    /// this policy" reading at ONE typed method instead of restating the
    /// three-variant `matches!` disjunction, the negated OUT-OF-SCHEDULE
    /// peer (`!region.is_out_of_schedule()`), the closed-inclusive
    /// range-membership `(1..=M).contains(&attempt)`, or the negated
    /// STRICT-boundary boolean disjunction
    /// (`!(p.is_before_first_attempt(a) || p.is_over_budget(a))`) at
    /// every downstream consumer.
    ///
    /// # Semantic role
    ///
    /// The three variants this disjunction covers are the LIVE
    /// in-schedule invocation classes the retry loop at
    /// [`run_with_policy`] actually produces — its counter starts at
    /// `1`, dispatches `op(attempt)` at [`PerAttemptRegion::First`] /
    /// [`PerAttemptRegion::Interim`] / [`PerAttemptRegion::Final`], and
    /// short-circuits at [`PerAttemptRegion::Final`]. A downstream
    /// consumer that says "this attempt index is a legal live
    /// invocation of the schedule" — a pre-invocation guard admitting
    /// the attempt to the retry loop, a "legal provenance" attestation
    /// classifier recording the attempt against the SLSA chain as an
    /// in-schedule datum distinct from a bug/replay class, a telemetry
    /// emitter tagging live-invocation counts distinct from bug/replay
    /// counts — reads `region.is_in_schedule()` at ONE site instead of
    /// writing `matches!(region, First | Interim | Final)`,
    /// `!region.is_out_of_schedule()`, or the closed-inclusive range
    /// membership at each site.
    ///
    /// # Orthogonal to the terminal axis
    ///
    /// The sum surface now names TWO orthogonal binary axes with BOTH
    /// halves affirmatively surfaced:
    ///
    /// |                | in-schedule (legal live attempt) | out-of-schedule (bug/replay) |
    /// | -------------- | -------------------------------- | ---------------------------- |
    /// | pre-terminal   | `First`, `Interim`               | `BeforeFirst`                |
    /// | terminal       | `Final`                          | `OverBudget`                 |
    ///
    /// [`is_terminal`](Self::is_terminal) /
    /// [`is_pre_terminal`](Self::is_pre_terminal) names the "does the
    /// retry loop short-circuit after this attempt?" axis with BOTH
    /// halves surfaced affirmatively; `is_out_of_schedule` /
    /// `is_in_schedule` now names the "is this attempt index a live
    /// in-schedule invocation or a bug/replay diagnostic?" axis with
    /// BOTH halves surfaced affirmatively too. A future consumer that
    /// needs either single axis reads the affirmative peer directly at
    /// ONE site; a consumer that needs the FULL 2×2 grid reads both
    /// peers independently rather than restating either axis at every
    /// emission site.
    ///
    /// # Grounding through the closed-inclusive range
    ///
    /// `region.is_in_schedule()` grounds through the closed-inclusive
    /// range-membership on the numeric axis at every `(policy, attempt)`:
    /// `self.per_attempt_region(attempt).is_in_schedule()` iff
    /// `!(self.is_before_first_attempt(attempt) || self.is_over_budget(attempt))`
    /// iff `1 <= attempt <= self.effective_max_attempts()`. Pinned by
    /// [`tests::test_retry_policy_per_attempt_region_is_in_schedule_iff_closed_inclusive_range`]
    /// across the canonical policy grid × attempt-index grid.
    ///
    /// # Idiom lineage
    ///
    /// Sibling of [`is_pre_terminal`](Self::is_pre_terminal) at the sum
    /// surface — both are affirmative De Morgan complements of a
    /// two-variant CEILING-style disjunction peer, naming the
    /// three-variant FLOOR-side reading through the negated body idiom
    /// (`!self.is_out_of_schedule()` here mirrors `!self.is_terminal()`
    /// at commit 1887f97). Together they close both axes at the
    /// projected sum surface with BOTH halves named at ONE affirmative
    /// typed method each — the same FLOOR/CEILING BOOLEAN COMPLEMENT
    /// discipline the boolean-peer ladder established
    /// ([`RetryPolicy::is_final_attempt`] d55b12b /
    /// [`RetryPolicy::is_retry_attempt`] 3359c54,
    /// [`RetryPolicy::is_over_budget`] eb0d5d1 /
    /// [`RetryPolicy::is_before_first_attempt`] b3aeb92).
    ///
    /// # THEORY grounding
    ///
    /// THEORY.md §II Language — typed primitives own boundary
    /// classification; the closed-inclusive-range disjunction at the
    /// projected sum surface is named at ONE typed method
    /// (`is_in_schedule`) rather than restated as the three-variant
    /// `matches!` disjunction, the negated OUT-OF-SCHEDULE peer, or the
    /// negated STRICT-boundary boolean disjunction at every downstream
    /// consumer. THEORY.md §VI.1 one-oracle — the "attempt index is a
    /// legal live in-schedule invocation of the retry loop" semantic
    /// role is named at ONE typed-primitive site (this method's body),
    /// so a downstream pre-invocation guard admitting live attempts, a
    /// legal-provenance attestation classifier, or a telemetry emitter
    /// tagging live-invocation counts reads `region.is_in_schedule()`
    /// once and is automatically extended across a future in-schedule
    /// variant insertion when this method is updated.
    #[allow(dead_code)]
    pub const fn is_in_schedule(&self) -> bool {
        !self.is_out_of_schedule()
    }

    /// The bounded-ladder BOTTOM (⊥) on the per-attempt-axis order —
    /// [`PerAttemptRegion::BeforeFirst`], the strictly-below-floor
    /// STRICT-boundary diagnostic class, the leftmost variant of
    /// [`PerAttemptRegion::ALL`] under the derived [`Ord`] chain
    /// (`BeforeFirst < First < Interim < Final < OverBudget`). Named
    /// typed-primitive peer of [`PerAttemptRegion::BeforeFirst`] at the
    /// bounded-ladder surface, distinct from the variant-name surface:
    /// where `PerAttemptRegion::BeforeFirst` reads the pre-invocation
    /// counter semantic role, [`PerAttemptRegion::BOTTOM`] reads the
    /// bounded-ladder anchor role — the global lower bound of the
    /// per-attempt-axis Ord chain, the leftmost variant of the
    /// [`PerAttemptRegion::ALL`] enumeration, the seed a downstream
    /// per-attempt-axis min-fold consumes at ONE named oracle.
    ///
    /// # The bounded-ladder axiom pair
    ///
    /// - `BOTTOM <= v` at every [`PerAttemptRegion::ALL`] variant — the
    ///   global-lower-bound law. Pinned by
    ///   [`tests::test_per_attempt_region_bottom_le_every_variant`].
    /// - `BOTTOM == *PerAttemptRegion::ALL.first().unwrap()` — the
    ///   routing pin that ties the bounded-ladder anchor to the
    ///   canonical-ladder-order enumeration surface. Pinned by
    ///   [`tests::test_per_attempt_region_bottom_equals_all_first`].
    ///
    /// # Grounding through the sum-surface axes
    ///
    /// [`BOTTOM`](Self::BOTTOM) sits at the FLOOR-strict corner of the
    /// 2×2 grid the schedule-axis / terminal-axis pair projects:
    /// `is_out_of_schedule()` is TRUE (the strictly-below-floor STRICT
    /// boundary is out-of-schedule) AND `is_pre_terminal()` is TRUE
    /// (the retry loop MAY dispatch a follow-up — the counter has not
    /// yet started). Pinned by
    /// [`tests::test_per_attempt_region_bottom_out_of_schedule_and_pre_terminal`].
    ///
    /// # Why a named const, not the variant
    ///
    /// The const reads `Self::BeforeFirst` and at the present five-variant
    /// enumeration the two coincide. The named [`BOTTOM`](Self::BOTTOM)
    /// const carries the bounded-ladder anchor semantic role distinct
    /// from the variant-name surface: a downstream consumer reading
    /// `PerAttemptRegion::BOTTOM` reads "the per-attempt-axis floor —
    /// the seed a per-attempt-axis min-fold consumes at, the leftmost
    /// class in the derived Ord chain" at the call site, where the same
    /// consumer reading `PerAttemptRegion::BeforeFirst` reads the
    /// pre-invocation counter semantic role (the strictly-below-floor
    /// STRICT boundary at the numeric axis, `attempt < 1`). The two
    /// surfaces overlap at the present ladder but diverge under
    /// refinement: a future variant inserted strictly below
    /// `BeforeFirst` (e.g., a hypothetical `NeverInvoked` variant
    /// distinct from `BeforeFirst`'s "counter at zero" reading) would
    /// shift the bounded-ladder floor — [`BOTTOM`](Self::BOTTOM) updates
    /// at this one site, every consumer of "the per-attempt-axis
    /// min-fold seed" automatically picks up the new floor. Same
    /// one-oracle discipline [`crate::version::BumpLevel::BOTTOM`]
    /// (commit 7f561de) and
    /// [`crate::probe_outcome::AdmissionTier::BOTTOM`] (commit fbf3ae5)
    /// established at their respective ladders, here applied to the
    /// per-attempt-axis projection surface.
    ///
    /// THEORY.md §II Language — typed primitives own boundary
    /// classification; the per-attempt-axis floor anchor is a
    /// typed-primitive surface on [`PerAttemptRegion`] itself (one
    /// named const), not the variant name re-aliased at every min-fold
    /// seed / lower-bound reader consumer site. THEORY.md §V.5
    /// total-order discipline — [`BOTTOM`](Self::BOTTOM) is the global
    /// lower bound of the derived [`Ord`] chain, the structural anchor
    /// a downstream `<= BOTTOM` / `>= BOTTOM` reader consumes through
    /// one named oracle. THEORY.md §VI.1 one-oracle — the per-attempt-
    /// axis floor semantic role is named at one site (this const), so
    /// a future ladder refinement that shifts the floor updates one
    /// site, not every min-fold seed / lower-bound reader consumer.
    #[allow(dead_code)]
    pub const BOTTOM: Self = Self::BeforeFirst;

    /// The bounded-ladder TOP (⊤) on the per-attempt-axis order —
    /// [`PerAttemptRegion::OverBudget`], the strictly-past-ceiling
    /// STRICT-boundary diagnostic class, the rightmost variant of
    /// [`PerAttemptRegion::ALL`] under the derived [`Ord`] chain
    /// (`BeforeFirst < First < Interim < Final < OverBudget`). Named
    /// typed-primitive peer of [`PerAttemptRegion::OverBudget`] at the
    /// bounded-ladder surface, distinct from the variant-name surface:
    /// where `PerAttemptRegion::OverBudget` reads the past-budget
    /// caller-bug / telemetry-replay semantic role,
    /// [`PerAttemptRegion::TOP`] reads the bounded-ladder anchor role
    /// — the global upper bound of the per-attempt-axis Ord chain, the
    /// rightmost variant of the [`PerAttemptRegion::ALL`] enumeration,
    /// the seed a downstream per-attempt-axis max-fold consumes at
    /// ONE named oracle. Mirror const of [`BOTTOM`](Self::BOTTOM),
    /// closing the bounded-ladder anchor pair at the typed-primitive
    /// surface.
    ///
    /// # The bounded-ladder axiom pair (top dual)
    ///
    /// - `v <= TOP` at every [`PerAttemptRegion::ALL`] variant — the
    ///   global-upper-bound law. Pinned by
    ///   [`tests::test_per_attempt_region_top_ge_every_variant`].
    /// - `TOP == *PerAttemptRegion::ALL.last().unwrap()` — the routing
    ///   pin that ties the bounded-ladder anchor to the canonical-
    ///   ladder-order enumeration surface. Pinned by
    ///   [`tests::test_per_attempt_region_top_equals_all_last`].
    ///
    /// # Grounding through the sum-surface axes
    ///
    /// [`TOP`](Self::TOP) sits at the CEILING-strict corner of the 2×2
    /// grid the schedule-axis / terminal-axis pair projects:
    /// `is_out_of_schedule()` is TRUE (the strictly-past-ceiling STRICT
    /// boundary is out-of-schedule) AND `is_terminal()` is TRUE (the
    /// retry loop MUST NOT dispatch a follow-up — the budget is
    /// exhausted). Pinned by
    /// [`tests::test_per_attempt_region_top_out_of_schedule_and_terminal`].
    /// The pair [`BOTTOM`](Self::BOTTOM) / [`TOP`](Self::TOP) is thus
    /// the two-anchor witness of the schedule-axis STRICT-boundary
    /// disjunction — [`is_out_of_schedule`](Self::is_out_of_schedule)
    /// reads `matches!(*self, BOTTOM | TOP)` at ONE named oracle pair
    /// (structurally, though the body still reads
    /// `BeforeFirst | OverBudget` for locality with the sum surface).
    ///
    /// # Together with [`BOTTOM`](Self::BOTTOM)
    ///
    /// The pair [`BOTTOM`](Self::BOTTOM) / [`TOP`](Self::TOP) names the
    /// closed per-attempt-axis interval `[BOTTOM, TOP]` that contains
    /// every variant — pinned by
    /// [`tests::test_per_attempt_region_bottom_lt_top`] (non-degeneracy)
    /// and the per-variant pins above (lower / upper bound). A
    /// downstream consumer that needs the global bounds of the
    /// per-attempt-axis reads
    /// `PerAttemptRegion::BOTTOM..=PerAttemptRegion::TOP` once at one
    /// named oracle pair, rather than restating the variant names at
    /// every consumer site.
    ///
    /// THEORY.md §II Language — typed primitives own boundary
    /// classification; the per-attempt-axis ceiling anchor is a
    /// typed-primitive surface on [`PerAttemptRegion`] itself (one
    /// named const). THEORY.md §V.5 total-order discipline —
    /// [`TOP`](Self::TOP) is the global upper bound of the derived
    /// [`Ord`] chain. THEORY.md §VI.1 one-oracle — the per-attempt-
    /// axis ceiling semantic role is named at one site (this const),
    /// so a future ladder refinement that shifts the ceiling updates
    /// one site, not every max-fold seed / upper-bound reader
    /// consumer.
    #[allow(dead_code)]
    pub const TOP: Self = Self::OverBudget;

    /// The canonical lowercase snake_case label for this
    /// [`PerAttemptRegion`] variant. Fixed-shape named oracle for
    /// telemetry / log / structured-attestation consumers that surface
    /// the per-attempt-axis classification as a string, closing the
    /// variant→label mapping at ONE named typed-primitive site instead
    /// of restating the match at every downstream consumer.
    ///
    /// # The label-axis one-oracle
    ///
    /// A downstream consumer that renders the per-attempt-axis
    /// classification as a string — a per-attempt telemetry counter
    /// labelled by region (`retry_attempts_total{region="interim"}`),
    /// a structured-attestation record carrying the region as a
    /// `provenance.retry.region` field on the SLSA chain, a debug/CLI
    /// pretty-print of the retry-loop state at a given attempt — reads
    /// `region.as_str()` at ONE named site. Without this method the
    /// consumer either restates the five-variant `match` at each site
    /// (drift class: a typo `"interim"` vs. `"Interim"` slipping in at
    /// one site out of many, silently re-classifying a downstream
    /// aggregator's histogram bucket), or falls back to the Debug
    /// impl's `"Interim"` / `"BeforeFirst"` UpperCamel form (drift
    /// class: a structured-attestation surface consuming the UpperCamel
    /// form breaks when the label-axis convention shifts to
    /// snake_case for consistency with the sibling
    /// [`crate::probe_outcome::AdmissionTier::as_str`] and
    /// [`crate::version::BumpLevel::as_str`] surfaces).
    ///
    /// # Idiom lineage
    ///
    /// Sibling of [`crate::version::BumpLevel::as_str`] (canonical
    /// `patch` / `minor` / `major` labels at the semver-magnitude
    /// ladder) and [`crate::probe_outcome::AdmissionTier::as_str`]
    /// (canonical `refused` / `staging_only` / `strict` labels at the
    /// admission-tier ladder) — both label-axis oracles at the sibling
    /// typed sums. This method completes the label-axis oracle at the
    /// per-attempt-region ladder under the same lowercase snake_case
    /// discipline, so a downstream telemetry / attestation / CLI
    /// surface that reads the label-axis of any of the three
    /// repo-internal ordered typed sums reads through one named
    /// oracle at each surface.
    ///
    /// # Canonical labels
    ///
    /// The five variants render as:
    /// * [`PerAttemptRegion::BeforeFirst`] → `"before_first"`
    /// * [`PerAttemptRegion::First`] → `"first"`
    /// * [`PerAttemptRegion::Interim`] → `"interim"`
    /// * [`PerAttemptRegion::Final`] → `"final"`
    /// * [`PerAttemptRegion::OverBudget`] → `"over_budget"`
    ///
    /// The labels track the variant names verbatim under the
    /// `UpperCamel → snake_case` transform: two-word variants
    /// (`BeforeFirst` → `"before_first"`, `OverBudget` → `"over_budget"`)
    /// gain the underscore separator; one-word variants (`First`,
    /// `Interim`, `Final`) lowercase in place. Pinned by
    /// [`tests::test_per_attempt_region_as_str_canonical_strings`] at
    /// the exact-shape surface and
    /// [`tests::test_per_attempt_region_as_str_lowercase_snake_case`]
    /// at the discipline surface (lowercase ASCII letters, digits, or
    /// underscores only — no hyphens, no whitespace, no uppercase),
    /// matching the same discipline
    /// [`crate::probe_outcome::AdmissionTier::as_str`] pins at its
    /// sibling surface. The mapping is injective across
    /// [`PerAttemptRegion::ALL`] (no two variants share a label),
    /// pinned by
    /// [`tests::test_per_attempt_region_as_str_distinct`] — the
    /// structural anchor that seals the bijection between the variant
    /// axis and the label axis so a future variant insertion that
    /// collided with an existing label (e.g., a `PostFinal` variant
    /// mistakenly labelled `"final"`) would silently re-classify every
    /// telemetry consumer that branched on the label; this test
    /// surfaces the collision at the one source-of-truth site.
    ///
    /// # Const-fn discipline
    ///
    /// Marked `const fn` for the same reason
    /// [`crate::probe_outcome::AdmissionTier::as_str`] and
    /// [`crate::version::BumpLevel::as_str`] are: the mapping is a
    /// pure function of the receiver, with no allocation and no trait
    /// dispatch. A const-context call shape (e.g., a `const
    /// FIRST_LABEL: &str = PerAttemptRegion::First.as_str();` table
    /// at a future telemetry-label site) is admissible.
    ///
    /// THEORY.md §II Language — typed primitives own boundary
    /// classification; the variant→label mapping is a typed-primitive
    /// surface on [`PerAttemptRegion`] itself (one named method), not
    /// the variant name re-aliased at every telemetry/log consumer
    /// site. THEORY.md §VI.1 one-oracle / generation-over-composition:
    /// the label-axis oracle is named at one site (this method's body),
    /// so a downstream telemetry / attestation / CLI consumer reads
    /// `region.as_str()` once and is automatically updated across a
    /// future ladder refinement that renames or inserts a variant.
    #[allow(dead_code)]
    pub const fn as_str(&self) -> &'static str {
        match self {
            PerAttemptRegion::BeforeFirst => "before_first",
            PerAttemptRegion::First => "first",
            PerAttemptRegion::Interim => "interim",
            PerAttemptRegion::Final => "final",
            PerAttemptRegion::OverBudget => "over_budget",
        }
    }

    /// The lattice join over the per-attempt-axis ladder — the
    /// [`PerAttemptRegion`] the most-advanced of `self` and `other` reads
    /// on the derived [`Ord`] chain
    /// (`BeforeFirst < First < Interim < Final < OverBudget`). Reads
    /// `self.max(other)` at one named site, returning the greater of the
    /// two variants. The named typed-method peer of the [`Ord::max`]
    /// reduction at the [`PerAttemptRegion`] surface, the structural
    /// mirror of [`crate::version::BumpLevel::join`] (commit ba37d27) at
    /// the version-bump magnitude ladder and
    /// [`crate::probe_outcome::AdmissionTier::join`] (commit ad62782) at
    /// the admission-tier ladder, here at the per-attempt-region ladder.
    /// Single one-line body routing through the derived [`Ord`] chain
    /// (commit 158c06a) so a future ladder refinement extends the
    /// most-advanced-region oracle at one site instead of retyping
    /// `.max()` at every consumer.
    ///
    /// # The most-advanced-region reading
    ///
    /// Given two [`PerAttemptRegion`] readings (e.g., a fold across two
    /// counters watching the same [`RetryPolicy`] — a per-op progress
    /// counter and a per-batch progress counter), [`join`](Self::join)
    /// names "the further-along region either counter reached." The
    /// load-bearing distinction from a bare
    /// [`Ord::max`] reduction is the reading, not the numeric answer:
    /// * A consumer reading `region_a.join(region_b)` reads "the
    ///   most-advanced region either input reached" at the call site,
    ///   where the same consumer reading `region_a.max(region_b)` reads
    ///   "the larger of the two variants" — the `max` form is a general
    ///   lattice op shared with arbitrary comparable types, the `join`
    ///   form names the most-advanced-region reading at the typed-
    ///   primitive surface. Same one-oracle discipline the
    ///   [`crate::version::BumpLevel::join`] lift established at the
    ///   release-aggregation surface and
    ///   [`crate::probe_outcome::AdmissionTier::join`] established at
    ///   the per-axis-OR-ceiling surface, here applied to the
    ///   most-advanced-region surface over the per-attempt-axis ladder.
    /// * A one-oracle anchor for a future ladder refinement. The
    ///   lattice join over a total order coincides with [`Ord::max`] by
    ///   definition, but a future ladder extension that introduces new
    ///   structural distinctions inside the per-attempt-axis (e.g., a
    ///   `PerAttemptRegion::CancelledByCaller` variant inserted between
    ///   `Final` and `OverBudget` — see the projection docstring)
    ///   extends this method body once, instead of retyping the
    ///   most-advanced-region oracle at every consumer's inline `.max()`
    ///   call.
    ///
    /// # Algebraic invariants
    ///
    /// The lattice join over a total order is idempotent, commutative,
    /// and associative, with the ladder floor
    /// ([`PerAttemptRegion::BOTTOM`]) as the identity element and the
    /// ladder ceiling ([`PerAttemptRegion::TOP`]) as the absorbing
    /// element — the load-bearing structural facts pinned by:
    /// * [`tests::test_per_attempt_region_join_is_idempotent_at_every_variant`]
    ///   — `a.join(a) == a` at every variant.
    /// * [`tests::test_per_attempt_region_join_is_commutative_at_every_pair`]
    ///   — `a.join(b) == b.join(a)` at every (a, b) over the 5×5 grid.
    /// * [`tests::test_per_attempt_region_join_is_associative_at_every_triple`]
    ///   — `a.join(b.join(c)) == a.join(b).join(c)` at every (a, b, c)
    ///   over the 5×5×5 grid.
    /// * [`tests::test_per_attempt_region_join_has_bottom_as_identity`]
    ///   — `BOTTOM.join(a) == a.join(BOTTOM) == a` at every variant.
    /// * [`tests::test_per_attempt_region_join_has_top_as_absorbing_element`]
    ///   — `TOP.join(a) == a.join(TOP) == TOP` at every variant.
    /// * [`tests::test_per_attempt_region_join_bounded_below_by_both_arguments`]
    ///   — `a.join(b) >= a && a.join(b) >= b` at every (a, b).
    /// * [`tests::test_per_attempt_region_join_returns_one_of_the_arguments`]
    ///   — `a.join(b) ∈ {a, b}` at every (a, b), the structural witness
    ///   that the lattice join over a total order is the identity-or-
    ///   other readback — distinct from a free-lattice join that could
    ///   return a third element.
    ///
    /// THEORY.md §V.5 total-order discipline: the most-advanced-region
    /// reading is a lattice operation (`max`) on the derived [`Ord`]
    /// ladder, named at the typed-primitive surface so a downstream
    /// consumer reads `region_a.join(region_b)` once and is automatically
    /// updated across a future ladder refinement. THEORY.md §VI.1
    /// one-oracle / generation-over-composition: the most-advanced-
    /// region idiom is named at one site (this method's body), not
    /// retyped at every consumer's inline `.max()` call.
    #[allow(dead_code)]
    pub fn join(self, other: Self) -> Self {
        self.max(other)
    }

    /// The lattice meet over the per-attempt-axis ladder — the
    /// [`PerAttemptRegion`] the least-advanced of `self` and `other`
    /// reads on the derived [`Ord`] chain
    /// (`BeforeFirst < First < Interim < Final < OverBudget`). Reads
    /// `self.min(other)` at one named site, returning the lesser of
    /// the two variants. The named typed-method peer of the
    /// [`Ord::min`] reduction at the [`PerAttemptRegion`] surface, the
    /// structural mirror of [`crate::version::BumpLevel::meet`] (commit
    /// f7436eb) at the version-bump magnitude ladder and
    /// [`crate::probe_outcome::AdmissionTier::meet`] (commit 0093064)
    /// at the admission-tier ladder, here at the per-attempt-region
    /// ladder. Dual of [`join`](Self::join) at the same ladder — the
    /// commit that closes the lattice-operation pair at the
    /// [`PerAttemptRegion`] surface. Single one-line body routing
    /// through the derived [`Ord`] chain (commit 158c06a) so a future
    /// ladder refinement extends the least-advanced-region oracle at
    /// one site instead of retyping `.min()` at every consumer.
    ///
    /// # The least-advanced-region reading
    ///
    /// Given two [`PerAttemptRegion`] readings (e.g., a fold across
    /// two counters watching the same [`RetryPolicy`] — a per-op
    /// progress counter and a per-batch progress counter),
    /// [`meet`](Self::meet) names "the less-advanced region either
    /// counter reached." The load-bearing distinction from a bare
    /// [`Ord::min`] reduction is the reading, not the numeric answer:
    /// * A consumer reading `region_a.meet(region_b)` reads "the
    ///   least-advanced region either input reached" at the call
    ///   site, where the same consumer reading `region_a.min(region_b)`
    ///   reads "the smaller of the two variants" — the `min` form is
    ///   a general lattice op shared with arbitrary comparable types,
    ///   the `meet` form names the least-advanced-region reading at
    ///   the typed-primitive surface. Same one-oracle discipline the
    ///   [`crate::version::BumpLevel::meet`] lift established at the
    ///   per-commit-floor surface and
    ///   [`crate::probe_outcome::AdmissionTier::meet`] established at
    ///   the per-axis-AND-floor surface, here applied to the least-
    ///   advanced-region surface over the per-attempt-axis ladder.
    /// * A one-oracle anchor for a future ladder refinement. The
    ///   lattice meet over a total order coincides with [`Ord::min`]
    ///   by definition, but a future ladder extension that introduces
    ///   new structural distinctions inside the per-attempt-axis
    ///   (e.g., a `PerAttemptRegion::CancelledByCaller` variant
    ///   inserted between `Final` and `OverBudget` — see the
    ///   projection docstring) extends this method body once, instead
    ///   of retyping the least-advanced-region oracle at every
    ///   consumer's inline `.min()` call.
    ///
    /// # Algebraic invariants
    ///
    /// The lattice meet over a total order is idempotent, commutative,
    /// and associative, with the ladder ceiling
    /// ([`PerAttemptRegion::TOP`]) as the identity element and the
    /// ladder floor ([`PerAttemptRegion::BOTTOM`]) as the absorbing
    /// element — the duals of the [`join`](Self::join) invariants on
    /// the same ladder. The lattice meet and join satisfy the
    /// absorption laws (`a.join(a.meet(b)) == a` and
    /// `a.meet(a.join(b)) == a`), pinned by
    /// [`tests::test_per_attempt_region_meet_join_absorption_at_every_pair`]
    /// — the structural anchor that the meet/join pair forms a
    /// lattice in the algebraic sense, not merely two independent
    /// reductions over the same [`Ord`] ladder. The meet is bounded
    /// above by both arguments and below by the join over the same
    /// pair, pinned by
    /// [`tests::test_per_attempt_region_meet_bounded_above_by_both_arguments`]
    /// and
    /// [`tests::test_per_attempt_region_meet_le_join_at_every_pair`]
    /// — the structural witness that the meet–join interval brackets
    /// the per-attempt-axis range of the input pair.
    ///
    /// * [`tests::test_per_attempt_region_meet_is_idempotent_at_every_variant`]
    ///   — `a.meet(a) == a` at every variant.
    /// * [`tests::test_per_attempt_region_meet_is_commutative_at_every_pair`]
    ///   — `a.meet(b) == b.meet(a)` at every (a, b) over the 5×5 grid.
    /// * [`tests::test_per_attempt_region_meet_is_associative_at_every_triple`]
    ///   — `a.meet(b.meet(c)) == a.meet(b).meet(c)` at every (a, b, c)
    ///   over the 5×5×5 grid.
    /// * [`tests::test_per_attempt_region_meet_has_top_as_identity`]
    ///   — `TOP.meet(a) == a.meet(TOP) == a` at every variant.
    /// * [`tests::test_per_attempt_region_meet_has_bottom_as_absorbing_element`]
    ///   — `BOTTOM.meet(a) == a.meet(BOTTOM) == BOTTOM` at every
    ///   variant.
    /// * [`tests::test_per_attempt_region_meet_returns_one_of_the_arguments`]
    ///   — `a.meet(b) ∈ {a, b}` at every (a, b), the structural
    ///   witness that the lattice meet over a total order is the
    ///   identity-or-other readback — distinct from a free-lattice
    ///   meet that could return a third element.
    ///
    /// THEORY.md §V.5 total-order discipline: the least-advanced-
    /// region reading is a lattice operation (`min`) on the derived
    /// [`Ord`] ladder, named at the typed-primitive surface so a
    /// downstream consumer reads `region_a.meet(region_b)` once and
    /// is automatically updated across a future ladder refinement.
    /// THEORY.md §VI.1 one-oracle / generation-over-composition: the
    /// least-advanced-region idiom is named at one site (this
    /// method's body), not retyped at every consumer's inline `.min()`
    /// call. Together with [`join`](Self::join), this closes the
    /// lattice-operation pair at the [`PerAttemptRegion`] surface —
    /// the structural mirror of the [`crate::version::BumpLevel`]
    /// meet/join pair at the version-bump magnitude surface and the
    /// [`crate::probe_outcome::AdmissionTier`] meet/join pair at the
    /// admission-tier surface.
    #[allow(dead_code)]
    pub fn meet(self, other: Self) -> Self {
        self.min(other)
    }
}

/// `Display` impl routes through [`PerAttemptRegion::as_str`] so the
/// variant→label mapping stays single-source: a future variant insertion
/// (a `CancelledByCaller` band strictly between [`PerAttemptRegion::Final`]
/// and [`PerAttemptRegion::OverBudget`], a `PostFinal` peer at the terminal
/// axis) updates the [`as_str`] match body alone and every `format!` /
/// `write!` consumer automatically inherits the new canonical label.
///
/// Sibling of [`crate::version::BumpLevel`]'s `Display` impl (which routes
/// through [`crate::version::BumpLevel::as_str`]) and
/// [`crate::probe_outcome::AdmissionTier`]'s `Display` impl (which routes
/// through [`crate::probe_outcome::AdmissionTier::as_str`]), here applied
/// to the per-attempt-region typed sum. Together with
/// [`PerAttemptRegion::as_str`] this closes the `to_string()` / `format!`
/// surface a downstream retry-loop telemetry / log-formatting consumer
/// reads the region through — no per-call-site `match` cascade that
/// drifts when a sixth variant is inserted and no leakage of the derived
/// `Debug` impl's UpperCamel labels (`BeforeFirst`, `OverBudget`) through
/// the formatter surface.
///
/// After this commit the trio (`BumpLevel` / `AdmissionTier` /
/// `PerAttemptRegion`) all carry `Display`-mirrors-`as_str` at their
/// label-axis surfaces, matching the closed lattice-op peer-set
/// (`join`/`meet`) and bounded-lattice-anchor peer-set (`BOTTOM`/`TOP`)
/// across the three repo-internal ordered typed sums. A downstream
/// consumer reading `format!("{region}")` at any of the three ladders
/// reads through one named oracle per surface with the label-axis
/// discipline (canonical labels + snake_case + injectivity) pinned at
/// each typed-primitive site.
///
/// THEORY.md §V.4 typed primitives: the per-variant string rendering is a
/// typed-primitive surface on [`PerAttemptRegion`] itself (one `Display`
/// impl routing through one `as_str` match body), not a per-call-site
/// cascade restated at every `format!("{:?}", region)` site that would
/// otherwise emit `BeforeFirst` / `OverBudget` UpperCamel labels via the
/// derived `Debug` rendering. THEORY.md §VI.1 one-oracle discipline: the
/// canonical label is named at one site ([`PerAttemptRegion::as_str`])
/// and every surface — `as_str`, `Display`, future `Serialize`,
/// future `FromStr` — reads through it.
impl std::fmt::Display for PerAttemptRegion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Parse the canonical lowercase / snake_case string (`"before_first"`,
/// `"first"`, `"interim"`, `"final"`, `"over_budget"`) into a
/// [`PerAttemptRegion`] variant. The named grammar-oracle inverse to
/// [`PerAttemptRegion::as_str`] — a downstream CLI-flag parser, telemetry-
/// label rehydrator, or YAML/JSON deserializer that recovers a
/// [`PerAttemptRegion`] from its canonical string label reads through
/// this one site instead of a per-consumer `match s { "first" | ... | _
/// }` cascade that would drift when a sixth variant is inserted.
///
/// Sibling of [`crate::version::BumpLevel`]'s [`std::str::FromStr`] impl
/// (which inverts [`crate::version::BumpLevel::as_str`]) and
/// [`crate::probe_outcome::AdmissionTier`]'s [`std::str::FromStr`] impl
/// (which inverts [`crate::probe_outcome::AdmissionTier::as_str`]), here
/// applied to the per-attempt-region typed sum. Together with
/// [`PerAttemptRegion::as_str`] and `Display for PerAttemptRegion` this
/// closes the `Display`↔`FromStr`↔`as_str` triangle at the per-attempt-
/// region ladder — the same closed round-trip surface
/// [`crate::probe_outcome::AdmissionTier`] and
/// [`crate::version::BumpLevel`] already carry at their ladders. The
/// round-trip identity `region.to_string().parse::<PerAttemptRegion>()
/// .unwrap() == region` at every variant is pinned by
/// [`tests::test_per_attempt_region_display_round_trips_through_from_str`].
///
/// The parser is strict: only the canonical labels emitted by
/// [`PerAttemptRegion::as_str`] parse. Empty input, UpperCamel rendering
/// (`"BeforeFirst"`, `"OverBudget"` — as the derived [`Debug`] impl
/// would emit), whitespace padding, uppercase (`"FIRST"`), and
/// snake_case labels with a dropped underscore (`"beforefirst"`,
/// `"overbudget"`) all reject. A downstream surface that wants alias
/// matrix or whitespace tolerance normalizes the string before routing
/// it through this canonical parser.
///
/// The error wording follows the sibling
/// [`crate::probe_outcome::AdmissionTier::from_str`] shape — names the
/// offending input inside single quotes and echoes the canonical
/// grammar — so a downstream operator reading the error text at the
/// retry-loop telemetry surface reads the same layout the admission-tier
/// and bump-level traps at the sibling ladders emit.
///
/// THEORY.md §V.4 typed primitives: the label-axis parser is a typed-
/// primitive surface on [`PerAttemptRegion`] itself (one match body over
/// the closed variant grammar) rather than a per-consumer inline
/// cascade. THEORY.md §VI.1 one-oracle / generation-over-composition:
/// the canonical-label grammar is named at one site
/// ([`PerAttemptRegion::as_str`]), the [`std::fmt::Display`] impl and
/// this [`std::str::FromStr`] impl are the two derived read/write
/// surfaces that route through it, and a future ladder refinement that
/// renames or inserts a variant is a one-site edit at [`as_str`] plus
/// the matching parser-arm addition here.
impl std::str::FromStr for PerAttemptRegion {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "before_first" => Ok(Self::BeforeFirst),
            "first" => Ok(Self::First),
            "interim" => Ok(Self::Interim),
            "final" => Ok(Self::Final),
            "over_budget" => Ok(Self::OverBudget),
            _ => Err(anyhow::anyhow!(
                "Invalid per-attempt region '{s}' — use before_first, first, interim, final, or over_budget",
            )),
        }
    }
}

/// [`serde::Serialize`] impl routes through [`PerAttemptRegion::as_str`] so
/// a downstream structured-attestation record, YAML config emit, or JSON
/// telemetry surface serialises the variant as its canonical snake_case
/// label (`"before_first"`, `"first"`, `"interim"`, `"final"`,
/// `"over_budget"`) rather than the UpperCamel variant identifier the
/// derived `serde::Serialize` (via `#[derive(Serialize)]`) would emit
/// (`"BeforeFirst"`, `"OverBudget"`) — the same label axis
/// [`std::fmt::Display`] and [`std::str::FromStr`] already inhabit, now
/// extended to the serde read/write surface at one typed-primitive site.
///
/// A future variant insertion (a `CancelledByCaller` band strictly between
/// [`PerAttemptRegion::Final`] and [`PerAttemptRegion::OverBudget`], a
/// `PostFinal` peer at the terminal axis) updates the [`as_str`] match
/// body alone and every serde emitter automatically inherits the new
/// canonical label — no manifest schema churn per consumer, no drift
/// between the [`Display`] rendering the operator reads at the retry-loop
/// telemetry surface and the serialised value the SLSA attestation record
/// stamps against the per-attempt-region label.
///
/// The round-trip `region -> serialize -> deserialize` identity at every
/// [`PerAttemptRegion::ALL`] variant is pinned by
/// [`tests::test_per_attempt_region_serde_round_trips_through_json_at_every_variant`],
/// closing the two-oracle discipline (canonical-label emission through
/// [`as_str`], canonical-label parsing through [`std::str::FromStr`])
/// across the full serde read/write surface.
///
/// THEORY.md §V.4 typed primitives: the serialisation surface is a
/// typed-primitive site on [`PerAttemptRegion`] itself (one `Serialize`
/// impl routing through the [`as_str`] canonical-label oracle), not a
/// per-consumer `#[derive(Serialize)]` + `#[serde(rename_all)]` retyping
/// that would fragment the label-axis definition across every downstream
/// consumer's struct. THEORY.md §VI.1 one-oracle: the canonical label is
/// named at one site ([`PerAttemptRegion::as_str`]) and every surface —
/// `as_str`, `Display`, this `Serialize`, `Deserialize`, `FromStr` —
/// reads through it.
impl serde::Serialize for PerAttemptRegion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

/// [`serde::Deserialize`] impl routes through [`std::str::FromStr`] so a
/// downstream YAML config load, JSON telemetry replay, or attestation-
/// record rehydration recovers the [`PerAttemptRegion`] variant from the
/// same canonical snake_case grammar [`PerAttemptRegion::as_str`] emits —
/// no per-consumer `#[serde(rename)]` matrix, no drift between the
/// serialised value the SLSA attestation record stamped and the
/// deserialised variant a replay consumer reads back at the retry-loop
/// telemetry surface.
///
/// The parser is strict for the same reason [`std::str::FromStr`] is: only
/// the canonical labels emitted by [`PerAttemptRegion::as_str`] parse.
/// Empty input, UpperCamel rendering (as the derived [`Debug`] impl would
/// emit — `"BeforeFirst"`, `"OverBudget"`), whitespace padding, uppercase
/// (`"FIRST"`), and snake_case labels with a dropped underscore
/// (`"beforefirst"`, `"overbudget"`) all reject. Non-string JSON/YAML
/// scalars (numbers, booleans, nulls, objects, arrays) reject at the
/// [`serde::Deserialize`] visitor layer with the standard "invalid type"
/// diagnostic — a downstream surface that wants alias matrix, whitespace
/// tolerance, or numeric-tag support normalises the input before routing
/// it through this canonical parser.
///
/// The round-trip `region -> serialize -> deserialize` identity at every
/// [`PerAttemptRegion::ALL`] variant is pinned by
/// [`tests::test_per_attempt_region_serde_round_trips_through_json_at_every_variant`].
/// The strict-parse behaviour on unknown labels is pinned by
/// [`tests::test_per_attempt_region_deserialize_rejects_unknown_string`].
///
/// THEORY.md §V.4 typed primitives: the deserialisation surface is a
/// typed-primitive site on [`PerAttemptRegion`] itself (one `Deserialize`
/// impl routing through the [`std::str::FromStr`] canonical-label parser),
/// not a per-consumer `#[derive(Deserialize)]` + `#[serde(rename_all)]`
/// retyping. THEORY.md §VI.1 one-oracle: canonical-label parsing lives at
/// one site ([`std::str::FromStr`] for [`PerAttemptRegion`]) and every
/// read surface — `FromStr`, this `Deserialize`, a future TOML config
/// loader, a future MessagePack telemetry replay — reads through it.
impl<'de> serde::Deserialize<'de> for PerAttemptRegion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <&str as serde::Deserialize>::deserialize(deserializer)?;
        s.parse::<Self>().map_err(serde::de::Error::custom)
    }
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

    /// The boolean-conditional retry-policy constructor: the canonical
    /// [`Self::network`] schedule when `retry_on_transient` is `true`,
    /// the no-retry [`Self::immediate`] shape when `false`.
    ///
    /// Lifts the verbatim five-line stanza
    /// ```text
    /// let policy = if safe_mode {
    ///     RetryPolicy::network()
    /// } else {
    ///     RetryPolicy::immediate()
    /// };
    /// ```
    /// that two retry-driven external-CLI sites in
    /// `commands/github_runner_ci.rs` — `attic_command_with_retry`
    /// and `push_with_retry` — carry verbatim modulo per-site comments.
    /// Two identically-shaped bodies past the duplication threshold the
    /// forge command-module surface enforces (≥2; PRIME DIRECTIVE) —
    /// this primitive is the law-redeeming consolidation for the
    /// safe-mode-conditional retry-policy shape, sibling of
    /// [`Self::network`] (the canonical exponential schedule),
    /// [`Self::immediate`] (the no-retry shape), and
    /// [`Self::with_max_attempts`] (the canonical-schedule + caller-
    /// budget builder).
    ///
    /// # Why the two-factory partition is load-bearing
    ///
    /// Under safe mode the retry-driven CI surface MUST retry transient
    /// network/server failures (HTTP 5xx, connection-level errors, I/O
    /// timeouts, EOF) so a registry/cache CDN hiccup does not fail a
    /// long-running CI job; under non-safe mode the operator wants a
    /// fail-fast loop (no retry budget burn against a deliberately
    /// short-circuited CI). The two factory constructors carry the two
    /// schedules; this constructor is the named dispatch between them
    /// at one site so a future safe-mode-only schedule refinement
    /// (e.g., a different cap, a different factor) gets named here, not
    /// retyped per consumer.
    ///
    /// The parameter is named `retry_on_transient` — not `safe_mode` —
    /// to keep the typed-primitive surface abstract from the call-site-
    /// specific safe-mode concept. The boolean's semantics is "should
    /// transient failures be retried under the canonical network
    /// schedule?", not "is the CI surface in safe mode?". A future
    /// retry-driven consumer that drives the partition off a different
    /// flag (e.g., `--allow-retry`, a config knob) consumes this
    /// primitive without retyping the conditional.
    ///
    /// THEORY.md §VI.1 one-oracle discipline: the safe-mode-conditional
    /// retry-policy partition is named at one site (here), not retyped
    /// as the inline five-line `if` stanza per consumer. THEORY.md §V.4
    /// honesty channel: the named constructor surfaces "this is the
    /// boolean-conditional dispatch between the canonical network
    /// schedule and the no-retry shape" as the load-bearing structural
    /// reading at the consumer site, making the choice between the two
    /// factory constructors explicit at the named-primitive surface
    /// rather than implicit at the inline `if` body.
    ///
    /// # Const-fn discipline
    ///
    /// Marked `const fn` for the same reason [`Self::network`] and
    /// [`Self::immediate`] are: the dispatch is a pure function of the
    /// boolean argument, and a const constructor admits the same
    /// `const`-context call shapes the two sibling factory constructors
    /// admit (e.g., a `const POLICY: RetryPolicy =
    /// RetryPolicy::network_or_immediate(SAFE_MODE_DEFAULT);` table at
    /// a future call site).
    pub const fn network_or_immediate(retry_on_transient: bool) -> Self {
        if retry_on_transient {
            Self::network()
        } else {
            Self::immediate()
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

    /// The canonical [`Self::network`] schedule with a caller-supplied
    /// budget cap. Equivalent to `Self::network().with_max_attempts(
    /// max_attempts)` and inherits the same clamping invariant (`>= 1`)
    /// from [`Self::with_max_attempts`].
    ///
    /// Lifts the verbatim two-line stanza
    /// ```text
    /// let policy = RetryPolicy::network().with_max_attempts(retries);
    /// ```
    /// that the two typed-error producer sites
    /// `infrastructure/attic.rs::push_with_retries` and
    /// `infrastructure/registry.rs::push_with_retries` carry verbatim —
    /// two identically-shaped bodies past the duplication threshold the
    /// forge command-module surface enforces (≥2; PRIME DIRECTIVE) — so
    /// the named composition is redeemed at one typed-primitive site,
    /// sibling of [`Self::network`] (the canonical schedule),
    /// [`Self::immediate`] (the no-retry shape),
    /// [`Self::network_or_immediate`] (the safe-mode-conditional
    /// dispatch), and [`Self::with_max_attempts`] (the budget-override
    /// builder).
    ///
    /// # Why the named composition is load-bearing
    ///
    /// The canonical network-schedule + caller-budget shape is the
    /// reference policy for the two typed-error push surfaces in
    /// forge's `infrastructure/` layer: both expose a `retries: u32`
    /// parameter that overrides only the attempt budget while
    /// preserving the canonical exponential schedule
    /// (`initial_backoff` 250ms, `factor` 2, `max_backoff` 30s). A
    /// future refinement to either the canonical schedule (e.g., a
    /// jittered backoff, a different cap) or the clamping discipline
    /// (e.g., an upper bound to prevent caller-supplied retry-storm
    /// budgets) gets named at this one typed-primitive site instead of
    /// retyped per consumer — exactly the structural seam
    /// THEORY §VI.1 one-oracle discipline forecloses.
    ///
    /// Not marked `const fn`: the `.max(1)` clamp via the `Ord` trait
    /// is not const-callable. Same discipline as the sibling
    /// [`Self::with_max_attempts`] and [`Self::new`] constructors —
    /// every factory that clamps the caller-supplied budget is
    /// non-const; every factory that takes only field literals
    /// ([`Self::immediate`], [`Self::network`],
    /// [`Self::network_or_immediate`]) is const.
    pub fn network_with_max_attempts(max_attempts: u32) -> Self {
        Self::network().with_max_attempts(max_attempts)
    }

    /// True iff this policy never retries — every invocation under
    /// [`run_with_policy`] / [`run_command_with_policy`] terminates after
    /// exactly one attempt, regardless of the classifier's transient/
    /// terminal verdict.
    ///
    /// Equivalent to `self.max_attempts <= 1`. The retry-loop body at
    /// [`run_with_policy`] (line `let max = policy.max_attempts.max(1);
    /// ... if !is_transient(&e) || attempt >= max { return Err(e); }`)
    /// short-circuits on the first error whenever `max_attempts <= 1`
    /// because the `attempt >= max` predicate fires at `attempt == 1`.
    /// The `<= 1` body (rather than `== 1`) handles the degenerate
    /// `max_attempts: 0` field-literal shape — every factory constructor
    /// in forge clamps via [`Self::with_max_attempts`] / [`Self::new`]
    /// so `0` cannot reach this surface through a sanctioned construction
    /// path, but a hand-built `RetryPolicy { max_attempts: 0, .. }`
    /// (e.g., the `test_compute_delay_exponential_growth` shape, the
    /// `test_partial_eq_reflexive_across_factory_constructors` `0` arm)
    /// is structurally a no-retry policy under the same retry-loop
    /// invariant.
    ///
    /// # Why a named typed-method predicate
    ///
    /// The "does this policy ever burn retry budget?" reading is the
    /// load-bearing structural-state partition at the typed-primitive
    /// surface — a future post-loop telemetry consumer histogramming
    /// no-retry-vs-retried invocations, a future structured-attestation
    /// surface distinguishing "ran-immediately" from "ran-under-retry"
    /// provenance classes, a future pre-loop fail-fast skip that wants
    /// to short-circuit before constructing the closure when retry is
    /// structurally impossible, a future config-validation surface that
    /// warns the operator when a `--retries 0` flag silently produced
    /// a no-retry policy (the clamp at [`Self::with_max_attempts`]
    /// promotes `0` to `1`, both of which are no-retry under this
    /// predicate) — previously all read the partition as
    /// `policy.max_attempts <= 1` or `policy == RetryPolicy::immediate()`
    /// at every consumer. The named typed-method peer hoists that reading
    /// to the typed-primitive surface, matching the named-predicate idiom
    /// the peer-pairs at the typed-failure surfaces established at the
    /// retry boundary (the [`CapturedFailure::is_transient`] /
    /// [`CapturedFailure::is_terminal`] retry-dispatch pair from commit
    /// 6069a25, the [`CommandAttemptFailure::is_spawn_failure`] /
    /// [`CommandAttemptFailure::is_op_failure`] structural pair from
    /// commit a4f4146, the
    /// [`CommandAttemptFailure::is_signal_killed`] /
    /// [`CommandAttemptFailure::is_exited_normally`] three-way
    /// partition closure at the call-site surface from commits cb0db50
    /// / 5e07cc2): every binary partition the typed primitives at the
    /// retry boundary surface exposes is now read through one named
    /// typed method, not through the raw field access / direct-
    /// equality cascade at every consumer.
    ///
    /// # Distinct from `== RetryPolicy::immediate()`
    ///
    /// Direct equality against [`Self::immediate`] discriminates on the
    /// full struct shape — `max_attempts: 1` AND `initial_backoff:
    /// ZERO` AND `factor: 1` AND `max_backoff: ZERO`. A policy that
    /// inherits the canonical [`Self::network`] schedule but with a
    /// caller-supplied `max_attempts: 1` (e.g.,
    /// `RetryPolicy::network_with_max_attempts(1)`) is structurally
    /// no-retry but NOT `== immediate()`, because its `initial_backoff`,
    /// `factor`, and `max_backoff` carry the canonical Bazel/Buck2/SLSA
    /// network schedule (250ms × factor=2 capped at 30s). The named
    /// predicate names the retry-budget axis directly so a consumer
    /// reading "does this policy ever retry?" is not silently coupled
    /// to the schedule axis the direct-equality reading also
    /// discriminates on.
    ///
    /// THEORY.md §VI.1 one-oracle discipline: the no-retry structural-
    /// state partition is named at one typed-primitive site instead of
    /// retyped as the inline `policy.max_attempts <= 1` cascade at
    /// every consumer site that branches on the structural state. Same
    /// generation-over-composition discipline the recent typed-method
    /// peers established at the [`CapturedFailure`] /
    /// [`CommandAttemptFailure`] surfaces of the retry boundary, here
    /// applied to the [`RetryPolicy`] typed primitive that drives the
    /// retry-loop budget.
    pub const fn is_no_retry(&self) -> bool {
        self.max_attempts <= 1
    }

    /// True iff this policy ever burns retry budget — under an
    /// always-transient classifier, [`run_with_policy`] /
    /// [`run_command_with_policy`] invokes `op` more than once.
    ///
    /// Defined as `!self.is_no_retry()` — the named-complement peer at
    /// the typed-primitive surface, closing the binary partition of
    /// the retry-budget axis. Equivalent to `self.max_attempts > 1`,
    /// but read through one named typed method so a future consumer
    /// branching on the "will-it-retry?" arm of the partition is not
    /// silently coupled to the raw-field-access reading.
    ///
    /// # Why the named-complement peer
    ///
    /// Every binary partition the typed primitives at the retry
    /// boundary surface previously exposed surfaces the named
    /// complement as a peer typed method: the
    /// [`CapturedFailure::is_transient`] /
    /// [`CapturedFailure::is_terminal`] retry-dispatch pair from commit
    /// 6069a25, the
    /// [`CommandAttemptFailure::is_spawn_failure`] /
    /// [`CommandAttemptFailure::is_op_failure`] structural pair from
    /// commit a4f4146, the
    /// [`CommandAttemptFailure::is_signal_killed`] /
    /// [`CommandAttemptFailure::is_exited_normally`] three-way
    /// partition closure at the call-site surface from commits cb0db50
    /// / 5e07cc2, and the
    /// [`AdmissionTier::admits_strict`] / [`AdmissionTier::refuses_strict`]
    /// admit/refuse peer-pair at the typed-coverage surface from
    /// commits 05f5071 / aec7d7c. The retry-budget axis at the
    /// retry-policy surface now joins that idiom: any future consumer
    /// reading the will-it-retry? arm (the natural retry-policy peer
    /// of a no-retry-vs-retried branch — a future post-loop telemetry
    /// histogram that buckets *retried* invocations against
    /// *immediate-only* invocations, a future structured-attestation
    /// surface that records the "ran-under-retry" provenance class
    /// against the SLSA chain, a future budget-validation surface that
    /// warns the operator when a CLI flag silently produced a
    /// will-retry policy where caller-intent was no-retry) reads one
    /// named typed method without re-typing the `max_attempts > 1` or
    /// `!policy.is_no_retry()` cascade per consumer.
    ///
    /// # Equivalent to `!self.is_no_retry()`
    ///
    /// The complement law `self.will_retry() == !self.is_no_retry()`
    /// holds for every [`RetryPolicy`] record — pinned by
    /// [`test_retry_policy_will_retry_complements_is_no_retry`]. A future
    /// regression that desynced the two predicates (e.g., one
    /// promoting its threshold off `<= 1` without the other; one
    /// reading a stale `initial_backoff.is_zero()` shortcut the other
    /// did not) lights up that test.
    ///
    /// THEORY.md §VI.1 one-oracle discipline: the will-retry
    /// structural-state partition is named at one typed-primitive site
    /// instead of retyped as the inline `policy.max_attempts > 1` /
    /// `!policy.is_no_retry()` cascade at every consumer site that
    /// branches on the structural state. Same generation-over-
    /// composition discipline the recent named-complement peers
    /// established at the [`CapturedFailure`] / [`CommandAttemptFailure`]
    /// surfaces of the retry boundary.
    pub const fn will_retry(&self) -> bool {
        !self.is_no_retry()
    }

    /// The clamped-to-≥1 attempt budget this policy actually drives — i.e.,
    /// `self.max_attempts.max(1)`, expressed through the same const-callable
    /// `if self.max_attempts > 1 { self.max_attempts } else { 1 }` shape the
    /// retry-loop body at [`run_with_policy`] and every per-attempt typed-
    /// method peer applies. The load-bearing numeric primitive at the
    /// policy-level retry-budget axis — the numeric reading that grounds
    /// every downstream typed-method peer at the axis.
    ///
    /// # The policy-level numeric primitive at the retry-budget axis
    ///
    /// The retry-budget axis exposes readings at two grains: the
    /// *policy-level* grain (does this policy retry at all? — no `attempt`
    /// argument) and the *per-attempt* grain (is THIS attempt the last one?
    /// — a 1-indexed `attempt` argument). At the policy-level grain, the
    /// boolean partition already appears as the
    /// [`is_no_retry`](Self::is_no_retry) / [`will_retry`](Self::will_retry)
    /// named-complement pair directly above ("does this policy ever burn
    /// retry budget?" / "will this policy ever invoke `op` more than
    /// once?"). `effective_max_attempts` names the *numeric* reading at the
    /// same policy-level grain: "what is the total attempt count under this
    /// policy's budget, after the clamp-to-≥1 discipline?" — the numeric
    /// peer of the boolean pair at the same axis, matching the numeric-vs-
    /// boolean peer idiom [`attempts_remaining`](Self::attempts_remaining)
    /// established at the per-attempt grain (numeric peer of the
    /// [`is_final_attempt`](Self::is_final_attempt) /
    /// [`is_interim_attempt`](Self::is_interim_attempt) per-attempt boolean
    /// partition).
    ///
    /// # The load-bearing primitive downstream typed peers ground through
    ///
    /// Every downstream typed-method peer at the retry-budget axis reads
    /// the clamped budget: [`is_final_attempt`](Self::is_final_attempt)
    /// fires on `attempt >= self.effective_max_attempts()`,
    /// [`is_interim_attempt`](Self::is_interim_attempt) is its De Morgan
    /// complement, and [`attempts_remaining`](Self::attempts_remaining)
    /// reads `self.effective_max_attempts().saturating_sub(attempt)`. The
    /// two policy-level boolean peers ground through the same primitive
    /// under the algebraic laws
    /// `policy.is_no_retry() == (policy.effective_max_attempts() == 1)`
    /// and `policy.will_retry() == (policy.effective_max_attempts() > 1)`
    /// — pinned by
    /// [`tests::test_retry_policy_effective_max_attempts_grounds_is_no_retry`]
    /// and
    /// [`tests::test_retry_policy_effective_max_attempts_grounds_will_retry`].
    /// Naming the numeric primitive means every future peer at the axis
    /// (a per-attempt telemetry gauge that emits the total budget as a
    /// gauge distinct from the budget-remaining count, a structured-
    /// attestation surface recording the clamped budget as a numeric
    /// provenance datum, an operator diagnostic that surfaces "policy
    /// clamped from 0 to 1" when the caller-supplied budget hit the
    /// degenerate shape) reads through one named typed method where today
    /// each would re-derive the `max_attempts.max(1)` cascade against the
    /// raw field.
    ///
    /// # Clamp-to-≥1 invariant
    ///
    /// The body reads `if self.max_attempts > 1 { self.max_attempts } else
    /// { 1 }`, matching the same clamp discipline
    /// [`is_final_attempt`](Self::is_final_attempt) and
    /// [`attempts_remaining`](Self::attempts_remaining) previously inlined
    /// verbatim. A hand-built `RetryPolicy { max_attempts: 0, .. }` (the
    /// degenerate field-literal shape every factory constructor's clamping
    /// discipline forecloses against, but which is structurally
    /// constructible) reads `effective_max_attempts() == 1` — the same
    /// clamped-≥1 reading the downstream per-attempt peers apply to that
    /// degenerate shape. Pinning the clamp at one typed-primitive site
    /// means a future per-attempt reading that grounds through this
    /// primitive inherits the clamp discipline without restatement.
    ///
    /// # Const-fn discipline
    ///
    /// Marked `const fn` for the same reason
    /// [`is_no_retry`](Self::is_no_retry),
    /// [`will_retry`](Self::will_retry),
    /// [`is_final_attempt`](Self::is_final_attempt),
    /// [`is_interim_attempt`](Self::is_interim_attempt), and
    /// [`attempts_remaining`](Self::attempts_remaining) are: the reading is
    /// a pure function of the receiver with no allocation and no trait
    /// dispatch — the `if` cascade uses only the const-stable `u32::>`
    /// comparator on the derived [`u32::Ord`] instance. A const-context
    /// call shape (e.g., a `const NETWORK_BUDGET: u32 =
    /// RetryPolicy::network().effective_max_attempts();` table at a future
    /// telemetry-label site) is admissible.
    ///
    /// THEORY.md §VI.1 one-oracle discipline: the clamped-budget numeric
    /// reading is named at one typed-primitive site instead of retyped as
    /// the inline `if self.max_attempts > 1 { self.max_attempts } else { 1
    /// }` cascade at every consumer site that reads the effective budget
    /// — previously inlined verbatim at two per-attempt peers
    /// ([`is_final_attempt`](Self::is_final_attempt),
    /// [`attempts_remaining`](Self::attempts_remaining)), now grounded
    /// through one named primitive. THEORY.md §V.4 typed primitives: the
    /// reading is a typed-primitive surface on `RetryPolicy` itself (one
    /// named const-fn method) rather than a raw-field-plus-clamp shape
    /// restated at every consumer.
    #[allow(dead_code)]
    pub const fn effective_max_attempts(&self) -> u32 {
        if self.max_attempts > 1 {
            self.max_attempts
        } else {
            1
        }
    }

    /// True iff the 1-indexed `attempt` is the LAST attempt allowed under
    /// this policy's budget — i.e., `attempt >= self.max_attempts.max(1)`
    /// under the same clamp-to-≥1 discipline the retry-loop body at
    /// [`run_with_policy`] applies. Named typed-method peer of the inline
    /// `attempt >= max` predicate the retry loop short-circuits on at
    /// [`run_with_policy`] (`if !is_transient(&e) || attempt >= max`) and
    /// of the structural complement `attempt < max_attempts` the
    /// warn-only-while-budget-remains dispatch at [`log_retry_attempt`]
    /// suppresses its warn on.
    ///
    /// # The per-attempt retry-budget axis
    ///
    /// Where [`is_no_retry`](Self::is_no_retry) names the *policy-level*
    /// retry-budget partition ("does this policy ever burn retry
    /// budget?") and [`will_retry`](Self::will_retry) names the
    /// *policy-level* complement ("will this policy ever invoke `op`
    /// more than once?"), `is_final_attempt` names the *per-attempt*
    /// reading at the same retry-budget axis ("is THIS specific attempt
    /// the last one under the policy's budget — and so the one the
    /// retry loop must short-circuit on, the one the warn-while-budget-
    /// remains dispatch must suppress its warn on, the one a future
    /// loud-fail telemetry surface must escalate its diagnostic class
    /// on?"). The two policy-level predicates are special cases of this
    /// per-attempt predicate at `attempt = 1`:
    /// `policy.is_no_retry() == policy.is_final_attempt(1)` and
    /// `policy.will_retry() == !policy.is_final_attempt(1)` — pinned by
    /// [`tests::test_retry_policy_is_no_retry_equals_is_final_attempt_at_one`]
    /// and
    /// [`tests::test_retry_policy_will_retry_complements_is_final_attempt_at_one`].
    ///
    /// # Why a named typed-method predicate
    ///
    /// The "is this attempt the last one under the budget?" reading is
    /// the load-bearing structural reading at the typed-primitive
    /// surface: a future per-attempt telemetry consumer that buckets
    /// final-attempt failures (a candidate for a loud-fail diagnostic
    /// class distinct from the budget-remaining-warn class
    /// [`log_retry_attempt`] already emits), a future structured-
    /// attestation surface distinguishing "final-attempt-exhausted"
    /// from "interim-attempt-failed" provenance classes against the
    /// SLSA chain, a future pre-attempt fail-fast escalation that wants
    /// to surface the final-attempt-imminent verdict before the next
    /// `op` invocation, a future per-attempt error-message enrichment
    /// that wants to inline the budget-exhausted verdict in the final
    /// attempt's error wrapper — all read the partition through one
    /// named typed method, where today they would each re-derive the
    /// `attempt >= self.max_attempts.max(1)` cascade against the raw
    /// fields. The named typed-method peer hoists that reading to the
    /// typed-primitive surface, matching the named-predicate idiom the
    /// peer-pairs at the typed-failure surfaces established at the
    /// retry boundary (the [`CapturedFailure::is_transient`] /
    /// [`CapturedFailure::is_terminal`] retry-dispatch pair, the
    /// [`CommandAttemptFailure::is_spawn_failure`] /
    /// [`CommandAttemptFailure::is_op_failure`] structural pair, the
    /// [`is_no_retry`](Self::is_no_retry) / [`will_retry`](Self::will_retry)
    /// policy-level retry-budget pair directly above).
    ///
    /// # Co-firing with the retry-loop short-circuit
    ///
    /// The named typed method is the structural witness for the retry-
    /// loop's short-circuit behavior at [`run_with_policy`]: under an
    /// always-transient classifier, the loop body short-circuits and
    /// returns the captured error iff `policy.is_final_attempt(attempt)`
    /// — pinned by
    /// [`tests::test_retry_policy_is_final_attempt_co_fires_with_run_with_policy_short_circuit`].
    /// A future regression that decoupled the predicate from the loop's
    /// short-circuit (e.g., a refactor that promoted the retry-loop's
    /// `max(1)` clamp to a `max(2)` floor without updating the
    /// predicate, a refactor that broadened the predicate to fire on
    /// `attempt > max` instead of `>=`) lights up that test.
    ///
    /// # Clamp-to-≥1 invariant
    ///
    /// The body reads `self.max_attempts.max(1)` rather than the raw
    /// `self.max_attempts` field, matching the retry-loop body at
    /// [`run_with_policy`] (`let max = policy.max_attempts.max(1);`)
    /// and the same clamp discipline [`is_no_retry`](Self::is_no_retry)
    /// applies through its `<= 1` comparator. A hand-built
    /// `RetryPolicy { max_attempts: 0, .. }` (the degenerate field-
    /// literal shape every factory constructor's clamping discipline
    /// forecloses against, but which is structurally constructible)
    /// is treated as a no-retry policy under this predicate — i.e.,
    /// `is_final_attempt(1)` returns `true` — so a future consumer
    /// reading the per-attempt predicate cannot silently slip into a
    /// no-op loop against the same degenerate shape
    /// [`is_no_retry`](Self::is_no_retry) classifies as no-retry.
    ///
    /// # Const-fn discipline
    ///
    /// Marked `const fn` for the same reason
    /// [`is_no_retry`](Self::is_no_retry) and
    /// [`will_retry`](Self::will_retry) are: the predicate is a pure
    /// function of the receiver and the attempt argument, with no
    /// allocation and no trait dispatch beyond the const-stable
    /// `u32::max` inherent comparison. A const-context call shape
    /// (e.g., a `const FIRST_IS_FINAL: bool =
    /// RetryPolicy::immediate().is_final_attempt(1);` table at a
    /// future telemetry-label site) is admissible.
    ///
    /// THEORY.md §VI.1 one-oracle discipline: the per-attempt retry-
    /// budget partition is named at one typed-primitive site instead
    /// of retyped as the inline `attempt >= self.max_attempts.max(1)`
    /// cascade at every consumer site that branches on the structural
    /// state — [`run_with_policy`]'s loop body, [`log_retry_attempt`]'s
    /// warn-while-budget-remains dispatch (the structural complement
    /// `attempt < max_attempts`), and any future per-attempt diagnostic
    /// /telemetry/attestation consumer at the retry boundary. THEORY.md
    /// §V.5 total-order discipline: the predicate reads the `>=`
    /// comparison on the derived [`u32::Ord`] instance, the same
    /// total-order surface the [`is_no_retry`](Self::is_no_retry) /
    /// [`will_retry`](Self::will_retry) policy-level pair reads its
    /// `<= 1` / `> 1` comparators on, here applied to the per-attempt
    /// axis with the clamp-to-≥1 invariant pinned at the typed-
    /// primitive surface.
    #[allow(dead_code)]
    pub const fn is_final_attempt(&self, attempt: u32) -> bool {
        attempt >= self.effective_max_attempts()
    }

    /// True iff the 1-indexed `attempt` is an INTERIM attempt under this
    /// policy's budget — i.e., another attempt remains after this one,
    /// equivalently `attempt < self.max_attempts.max(1)` under the same
    /// clamp-to-≥1 discipline the retry-loop body at [`run_with_policy`]
    /// applies. Named typed-method peer of the inline `attempt <
    /// max_attempts` predicate the warn-only-while-budget-remains
    /// dispatch at [`log_retry_attempt`] gates its `warn!` emission on.
    ///
    /// Defined as `!self.is_final_attempt(attempt)` — the named De Morgan
    /// complement peer at the per-attempt retry-budget axis, closing the
    /// binary partition the [`is_final_attempt`](Self::is_final_attempt)
    /// predicate exposes and mirroring the
    /// [`is_no_retry`](Self::is_no_retry) /
    /// [`will_retry`](Self::will_retry) named-complement pair at the
    /// policy-level retry-budget axis directly above. The two policy-
    /// level predicates are special cases of the per-attempt pair at
    /// `attempt = 1`: `policy.will_retry() == policy.is_interim_attempt(1)`
    /// — pinned by
    /// [`tests::test_retry_policy_will_retry_equals_is_interim_attempt_at_one`].
    ///
    /// # Why the named-complement peer
    ///
    /// Every binary partition the typed primitives at the retry
    /// boundary surface previously exposed surfaces the named
    /// complement as a peer typed method: the
    /// [`CapturedFailure::is_transient`] /
    /// [`CapturedFailure::is_terminal`] retry-dispatch pair, the
    /// [`CommandAttemptFailure::is_spawn_failure`] /
    /// [`CommandAttemptFailure::is_op_failure`] structural pair, the
    /// [`CommandAttemptFailure::is_signal_killed`] /
    /// [`CommandAttemptFailure::is_exited_normally`] three-way partition
    /// closure at the call-site surface, and the
    /// [`is_no_retry`](Self::is_no_retry) /
    /// [`will_retry`](Self::will_retry) policy-level retry-budget pair
    /// directly above. The per-attempt retry-budget axis at the retry-
    /// policy surface now joins that idiom: any future consumer reading
    /// the "budget-remaining" arm of the per-attempt partition (the
    /// natural retry-policy peer of a final-vs-interim branch — the
    /// warn-while-budget-remains dispatch at [`log_retry_attempt`], a
    /// future per-attempt telemetry surface that emits a distinct
    /// counter class for interim-attempt failures against final-
    /// attempt failures, a future structured-attestation surface
    /// recording "interim-attempt" provenance distinct from "final-
    /// attempt-exhausted" against the SLSA chain, a future per-attempt
    /// warn-message enrichment that inlines the "budget-remaining"
    /// verdict in the attempt's warn wrapper) reads one named typed
    /// method without re-typing the `attempt < policy.max_attempts.max(1)`
    /// or `!policy.is_final_attempt(attempt)` cascade per consumer.
    ///
    /// # Equivalent to `!self.is_final_attempt(attempt)`
    ///
    /// The complement law `self.is_interim_attempt(a) ==
    /// !self.is_final_attempt(a)` holds for every [`RetryPolicy`]
    /// record and every `attempt` — pinned by
    /// [`tests::test_retry_policy_is_interim_attempt_complements_is_final_attempt`].
    /// A future regression that desynced the two predicates (e.g., one
    /// promoting its threshold off `>=` without the other, one reading
    /// a stale `initial_backoff.is_zero()` shortcut the other did not)
    /// lights up that test.
    ///
    /// # Clamp-to-≥1 invariant
    ///
    /// The body reads through [`is_final_attempt`](Self::is_final_attempt)
    /// so the same clamp discipline the retry-loop body at
    /// [`run_with_policy`] applies (`let max =
    /// policy.max_attempts.max(1);`) is preserved without restatement. A
    /// hand-built `RetryPolicy { max_attempts: 0, .. }` (the degenerate
    /// field-literal shape every factory constructor's clamping
    /// discipline forecloses against) is treated as a no-retry policy
    /// under this predicate — `is_interim_attempt(1)` returns `false` —
    /// so a future consumer reading the per-attempt predicate cannot
    /// silently classify a degenerate no-op policy's first attempt as
    /// interim, matching the retry-loop body's short-circuit.
    ///
    /// # Const-fn discipline
    ///
    /// Marked `const fn` for the same reason
    /// [`is_final_attempt`](Self::is_final_attempt),
    /// [`is_no_retry`](Self::is_no_retry), and
    /// [`will_retry`](Self::will_retry) are: the predicate is a pure
    /// function of the receiver and the attempt argument, delegating to
    /// a const-fn peer. A const-context call shape (e.g., a `const
    /// FIRST_IS_INTERIM: bool =
    /// RetryPolicy::network().is_interim_attempt(1);` table at a future
    /// telemetry-label site) is admissible.
    ///
    /// THEORY.md §VI.1 one-oracle discipline: the per-attempt "budget-
    /// remaining" partition is named at one typed-primitive site
    /// instead of retyped as the inline `attempt < self.max_attempts`
    /// cascade at every consumer site that branches on the structural
    /// state — [`log_retry_attempt`]'s warn-while-budget-remains
    /// dispatch, and any future per-attempt diagnostic / telemetry /
    /// attestation consumer at the retry boundary. THEORY.md §V.5
    /// total-order discipline: the predicate reads the same `>=`
    /// comparison on the derived [`u32::Ord`] instance that
    /// [`is_final_attempt`](Self::is_final_attempt) reads, here
    /// complemented at the typed-primitive surface with the clamp-to-≥1
    /// invariant preserved by delegation.
    #[allow(dead_code)]
    pub const fn is_interim_attempt(&self, attempt: u32) -> bool {
        !self.is_final_attempt(attempt)
    }

    /// Number of attempts remaining under this policy's budget *after* the
    /// given 1-indexed `attempt` — the numeric peer of the boolean per-
    /// attempt [`is_final_attempt`](Self::is_final_attempt) /
    /// [`is_interim_attempt`](Self::is_interim_attempt) partition at the
    /// same per-attempt retry-budget axis. Defined as
    /// `self.max_attempts.max(1).saturating_sub(attempt)` under the same
    /// clamp-to-≥1 discipline the boolean pair applies.
    ///
    /// # The numeric-vs-boolean reading at the same axis
    ///
    /// Where [`is_final_attempt`](Self::is_final_attempt) and
    /// [`is_interim_attempt`](Self::is_interim_attempt) name the *boolean*
    /// partition at the per-attempt retry-budget axis (the two-way "is
    /// this the last one?" / "is another attempt in budget?" split),
    /// `attempts_remaining` names the *numeric* reading at the same axis:
    /// "how many attempts remain after this one?" The boolean partition is
    /// a special case of the numeric reading:
    /// `policy.is_final_attempt(a) == (policy.attempts_remaining(a) == 0)`
    /// and `policy.is_interim_attempt(a) == (policy.attempts_remaining(a) > 0)`
    /// — pinned by
    /// [`tests::test_retry_policy_attempts_remaining_zero_iff_is_final_attempt`]
    /// and
    /// [`tests::test_retry_policy_attempts_remaining_positive_iff_is_interim_attempt`].
    ///
    /// # Why a named numeric typed method
    ///
    /// The "how many more?" reading is the load-bearing structural reading
    /// distinct from the two-way boolean partition: a future warn-message
    /// enrichment at [`log_retry_attempt`] that wants to inline the
    /// budget-remaining count in the attempt's warn wrapper (`"...retrying
    /// (N attempts remaining)..."` — a strict shape refinement over the
    /// current `attempt/max_attempts` fraction), a future per-attempt
    /// telemetry consumer that emits a budget-remaining gauge distinct
    /// from the boolean interim/final class distinction, a future pre-
    /// attempt escalation that wants to gate its "getting close to
    /// exhaustion" verdict on `attempts_remaining(attempt) <= 1` rather
    /// than the coarser is-final boolean — all read the numeric partition
    /// through one named typed method, where today they would each re-
    /// derive the `max_attempts.max(1).saturating_sub(attempt)` cascade
    /// against the raw fields. The named typed-method peer hoists that
    /// reading to the typed-primitive surface, matching the numeric-peer
    /// idiom [`compute_delay`](Self::compute_delay) established at the
    /// backoff-schedule axis (numeric [`Duration`] peer of the boolean
    /// "is-there-a-next-attempt?" partition).
    ///
    /// # Saturation on out-of-budget attempts
    ///
    /// The body reads `saturating_sub`, so an `attempt` beyond the
    /// clamped budget (e.g., `policy.network().attempts_remaining(100)`)
    /// returns `0` rather than underflowing — matching the retry-loop
    /// body's short-circuit at [`run_with_policy`], which returns after
    /// the final attempt and cannot invoke the predicate at
    /// `attempt > max`. Pinning saturation at the typed-primitive surface
    /// forecloses a future consumer's silent underflow against an
    /// off-by-one call shape.
    ///
    /// # Clamp-to-≥1 invariant
    ///
    /// The body reads `self.max_attempts.max(1)` rather than the raw
    /// `self.max_attempts` field, matching the clamp discipline
    /// [`is_final_attempt`](Self::is_final_attempt) and
    /// [`is_interim_attempt`](Self::is_interim_attempt) apply through
    /// their peer delegation. A hand-built
    /// `RetryPolicy { max_attempts: 0, .. }` (the degenerate field-
    /// literal shape every factory constructor's clamping discipline
    /// forecloses against, but which is structurally constructible) is
    /// treated as a no-retry policy under this predicate — i.e.,
    /// `attempts_remaining(1) == 0` — so a future consumer reading the
    /// per-attempt numeric budget cannot silently classify a degenerate
    /// no-op policy's first attempt as "one attempt remaining", matching
    /// the boolean partition's degenerate-shape reading.
    ///
    /// # Const-fn discipline
    ///
    /// Marked `const fn` for the same reason
    /// [`is_final_attempt`](Self::is_final_attempt),
    /// [`is_interim_attempt`](Self::is_interim_attempt),
    /// [`is_no_retry`](Self::is_no_retry), and
    /// [`will_retry`](Self::will_retry) are: the reading is a pure
    /// function of the receiver and the attempt argument, with no
    /// allocation and no trait dispatch beyond the const-stable
    /// `u32::max` / `u32::saturating_sub` inherent operations. A
    /// const-context call shape (e.g., a `const NETWORK_INITIAL_BUDGET:
    /// u32 = RetryPolicy::network().attempts_remaining(1);` table at a
    /// future telemetry-label site) is admissible.
    ///
    /// THEORY.md §VI.1 one-oracle discipline: the per-attempt numeric
    /// budget-remaining reading is named at one typed-primitive site
    /// instead of retyped as the inline
    /// `policy.max_attempts.max(1).saturating_sub(attempt)` cascade at
    /// every consumer site that reads the numeric budget — any future
    /// per-attempt diagnostic / telemetry / warn-message-enrichment /
    /// pre-attempt-escalation consumer at the retry boundary. THEORY.md
    /// §V.4 typed primitives: the reading is a typed-primitive surface
    /// on `RetryPolicy` itself (one named const-fn method), not a raw-
    /// field-plus-clamp-plus-saturate shape restated at every consumer.
    #[allow(dead_code)]
    pub const fn attempts_remaining(&self, attempt: u32) -> u32 {
        self.effective_max_attempts().saturating_sub(attempt)
    }

    /// True iff the 1-indexed `attempt` is the FIRST attempt under this
    /// policy's budget — i.e., `attempt <= 1`, the exact predicate the
    /// [`compute_delay`](Self::compute_delay) body applies verbatim as its
    /// zero-delay early-return guard. The per-attempt-axis FLOOR peer of
    /// the CEILING reading the [`is_final_attempt`](Self::is_final_attempt)
    /// / [`is_interim_attempt`](Self::is_interim_attempt) named-complement
    /// pair anchors — the ladder-floor anchor at the per-attempt grain,
    /// matching the ladder-floor/ceiling anchor idiom
    /// [`BumpLevel::BOTTOM`](crate::version::BumpLevel::BOTTOM) /
    /// [`BumpLevel::TOP`](crate::version::BumpLevel::TOP) and
    /// [`AdmissionTier::BOTTOM`](crate::network_policy_admission::AdmissionTier::BOTTOM)
    /// /
    /// [`AdmissionTier::TOP`](crate::network_policy_admission::AdmissionTier::TOP)
    /// established at the magnitude and tier ladders in commits 7f561de /
    /// fbf3ae5.
    ///
    /// # The per-attempt-axis floor peer
    ///
    /// The per-attempt-axis previously named only the CEILING side of the
    /// attempt-index range through the boolean partition
    /// [`is_final_attempt`](Self::is_final_attempt) ("is `attempt >=
    /// max`?") / [`is_interim_attempt`](Self::is_interim_attempt) ("is
    /// there budget after `attempt`?"), plus the numeric
    /// [`attempts_remaining`](Self::attempts_remaining) reading ("how many
    /// remain after `attempt`?"). `is_first_attempt` names the FLOOR side:
    /// "is this the opening attempt, before any retry has been consumed?"
    /// — the peer that reads the other end of the attempt-index axis.
    ///
    /// Under the retry-loop `attempt` counter's 1-indexed convention (the
    /// [`run_with_policy`] body increments the counter from `0` to `1`
    /// before the first `op(attempt)` call), `is_first_attempt(1)` is
    /// always `true` (the first attempt is always the first), and
    /// `is_first_attempt(a)` for `a >= 2` is always `false` (any attempt
    /// past 1 is a retry). `is_first_attempt(0)` returns `true` — the
    /// pre-invocation counter reading — matching the same shape
    /// [`compute_delay`](Self::compute_delay) admits at its early-return
    /// guard.
    ///
    /// # The grounding call site
    ///
    /// [`compute_delay`](Self::compute_delay) reads `if attempt <= 1
    /// { return Duration::ZERO; }` as its zero-delay early-return guard —
    /// the verbatim shape this predicate names. The
    /// [`compute_delay`](Self::compute_delay) body is refactored to route
    /// that guard through `self.is_first_attempt(attempt)`, so the raw
    /// `attempt <= 1` predicate is named at one typed-primitive site
    /// rather than restated at the call site. Any future per-attempt
    /// telemetry consumer that emits a "first-attempt-vs-retry" class
    /// label distinct from the boolean is-final/is-interim class, a
    /// future warn-message enrichment at [`log_retry_attempt`] that
    /// wants to gate its "retrying attempt N" prefix on "this is not the
    /// first call", a future structured-attestation surface that
    /// records the "ran-under-retry" provenance class as the
    /// complement of the first-attempt reading, or a future pre-attempt
    /// diagnostic that wants to skip the "no retries needed" happy-path
    /// log on `is_first_attempt(attempt) && op.is_ok()` — all consume
    /// this named predicate rather than restating the `attempt <= 1`
    /// cascade against the raw counter.
    ///
    /// # The ladder-floor/ceiling anchor idiom at the per-attempt axis
    ///
    /// The typed-primitive surface at the retry boundary previously
    /// named the ladder-floor/ceiling anchors at the two other ordered
    /// axes forge's typed algebra tracks:
    /// [`BumpLevel::BOTTOM`](crate::version::BumpLevel::BOTTOM) /
    /// [`BumpLevel::TOP`](crate::version::BumpLevel::TOP) at the
    /// magnitude ladder (commit 7f561de) and
    /// [`AdmissionTier::BOTTOM`](crate::network_policy_admission::AdmissionTier::BOTTOM)
    /// /
    /// [`AdmissionTier::TOP`](crate::network_policy_admission::AdmissionTier::TOP)
    /// at the tier ladder (commit fbf3ae5). Both anchor the two ends of
    /// a bounded ordered surface at named typed-method peers so a
    /// consumer branching on "the floor" or "the ceiling" of the ladder
    /// reads one named surface rather than restating the specific
    /// variant. The per-attempt attempt-index axis at the retry-budget
    /// surface is the same shape — a bounded ordered range from 1 up to
    /// the clamped `effective_max_attempts()` budget — and the
    /// [`is_final_attempt`](Self::is_final_attempt) predicate previously
    /// named the ceiling side. `is_first_attempt` closes the floor side
    /// at the named typed-method peer, matching the anchor idiom.
    ///
    /// # The clamp-independence discipline
    ///
    /// Unlike [`is_final_attempt`](Self::is_final_attempt) and
    /// [`attempts_remaining`](Self::attempts_remaining), the first-
    /// attempt reading does not ground through
    /// [`effective_max_attempts`](Self::effective_max_attempts) — the
    /// floor of the attempt-index range is `1` regardless of the
    /// clamped budget's ceiling. The predicate reads `attempt <= 1`
    /// directly, matching the shape [`compute_delay`](Self::compute_delay)
    /// applies. This is the load-bearing structural asymmetry: the
    /// per-attempt-axis ceiling depends on the policy's budget; the
    /// per-attempt-axis floor does not. Naming the reading at one
    /// typed-primitive site pins that asymmetry as an explicit surface
    /// distinct from the clamp-grounded ceiling peers.
    ///
    /// # Const-fn discipline
    ///
    /// Marked `const fn` for the same reason
    /// [`is_final_attempt`](Self::is_final_attempt),
    /// [`is_interim_attempt`](Self::is_interim_attempt),
    /// [`attempts_remaining`](Self::attempts_remaining),
    /// [`effective_max_attempts`](Self::effective_max_attempts),
    /// [`is_no_retry`](Self::is_no_retry), and
    /// [`will_retry`](Self::will_retry) are: the predicate is a pure
    /// function of the attempt argument, with no allocation and no
    /// receiver-field access. A const-context call shape (e.g., a
    /// `const FIRST_CALL_HAS_NO_DELAY: bool =
    /// RetryPolicy::network().is_first_attempt(1);` table at a future
    /// telemetry-label site) is admissible.
    ///
    /// THEORY.md §VI.1 one-oracle discipline: the per-attempt-axis
    /// floor reading is named at one typed-primitive site instead of
    /// retyped as the inline `attempt <= 1` cascade at every consumer
    /// site — previously inlined verbatim at
    /// [`compute_delay`](Self::compute_delay)'s zero-delay early-return
    /// guard, now grounded through one named primitive. THEORY.md §V.4
    /// typed primitives: the reading is a typed-primitive surface on
    /// `RetryPolicy` itself (one named const-fn method), not a raw-
    /// counter-comparison shape restated at every consumer.
    #[allow(dead_code)]
    pub const fn is_first_attempt(&self, attempt: u32) -> bool {
        let _ = self;
        attempt <= 1
    }

    /// True iff the 1-indexed `attempt` is a RETRY under this policy's
    /// budget — i.e., `attempt > 1`, the exact predicate the
    /// [`log_retry_attempt`] surface, a future
    /// "retrying attempt N" warn-message prefix, or a future
    /// per-attempt telemetry consumer that emits a "retry-vs-first-call"
    /// class distinct from the boolean is-final/is-interim class reads
    /// when it needs to skip the first-call happy-path arm.
    ///
    /// Defined as `!self.is_first_attempt(attempt)` — the named De Morgan
    /// complement peer at the per-attempt-axis FLOOR grain, closing the
    /// binary partition the [`is_first_attempt`](Self::is_first_attempt)
    /// predicate exposes and mirroring the
    /// [`is_final_attempt`](Self::is_final_attempt) /
    /// [`is_interim_attempt`](Self::is_interim_attempt) named-complement
    /// pair at the per-attempt-axis CEILING grain directly above. Closes
    /// the per-attempt-axis BOOLEAN 2×2 quadrant grid at the same
    /// (FLOOR/CEILING × ANCHOR/COMPLEMENT) surface the numeric axis's
    /// FLOOR-EXCLUSIVE / FLOOR-INCLUSIVE / CEILING-EXCLUSIVE /
    /// CEILING-INCLUSIVE quadrant grid closes at
    /// [`attempts_completed_before`](Self::attempts_completed_before) /
    /// [`attempts_used_through`](Self::attempts_used_through) /
    /// [`attempts_remaining`](Self::attempts_remaining) /
    /// [`attempts_remaining_including`](Self::attempts_remaining_including).
    ///
    /// # The per-attempt-axis BOOLEAN 2×2 quadrant closure
    ///
    /// The per-attempt-axis boolean surface now spans:
    ///
    /// |         | ANCHOR                                | COMPLEMENT (De Morgan)                 |
    /// | ------- | ------------------------------------- | -------------------------------------- |
    /// | FLOOR   | [`is_first_attempt`] (`a <= 1`)       | `is_retry_attempt` (`a > 1`) ← new     |
    /// | CEILING | [`is_final_attempt`] (`a >= budget`)  | [`is_interim_attempt`] (`a < budget`)  |
    ///
    /// Every consumer that previously would have retyped the inline
    /// `!policy.is_first_attempt(attempt)` or `attempt > 1` or
    /// `attempt >= 2` cascade — a per-attempt telemetry gauge emitting
    /// a "retry-vs-first-call" class label distinct from the
    /// interim/final class distinction, a structured-attestation surface
    /// recording the "ran-under-retry" provenance datum against the SLSA
    /// chain, a warn-message enrichment at
    /// [`log_retry_attempt`](crate::retry::log_retry_attempt) that
    /// wants to gate its "retrying attempt N" prefix on "this is not
    /// the first call", a pre-attempt escalation that wants to
    /// short-circuit on the first-call happy-path arm — now reads one
    /// named typed method.
    ///
    /// # Equivalent to `!self.is_first_attempt(attempt)`
    ///
    /// The complement law `self.is_retry_attempt(a) ==
    /// !self.is_first_attempt(a)` holds for every [`RetryPolicy`] record
    /// and every `attempt` — pinned by
    /// [`tests::test_retry_policy_is_retry_attempt_complements_is_first_attempt`].
    /// A future regression that desynced the two predicates (e.g., one
    /// promoting its threshold off `<=` without the other, one starting
    /// to ground through
    /// [`effective_max_attempts`](Self::effective_max_attempts) as the
    /// ceiling peers do while the other stayed clamp-independent) lights
    /// up that test.
    ///
    /// # Clamp-independence discipline
    ///
    /// The body reads through [`is_first_attempt`](Self::is_first_attempt)
    /// so the same clamp-INDEPENDENT discipline the floor peer applies
    /// is preserved without restatement. Like the FLOOR anchor peer —
    /// and UNLIKE the CEILING pair
    /// [`is_final_attempt`](Self::is_final_attempt) /
    /// [`is_interim_attempt`](Self::is_interim_attempt) which ground
    /// through [`effective_max_attempts`](Self::effective_max_attempts)
    /// — `is_retry_attempt` does not depend on the policy's clamped
    /// budget: whether attempt `a` is a retry is determined entirely by
    /// `a > 1`, independent of `max_attempts`. This pins the load-bearing
    /// structural asymmetry that the per-attempt-axis FLOOR predicate
    /// pair is clamp-INDEPENDENT while the CEILING predicate pair is
    /// clamp-DEPENDENT as an explicit surface on both sides of the FLOOR
    /// partition, matching the same clamp-INDEPENDENT / clamp-DEPENDENT
    /// asymmetry the numeric quadrant grid pins between
    /// [`attempts_completed_before`](Self::attempts_completed_before)
    /// (clamp-INDEPENDENT) and
    /// [`attempts_used_through`](Self::attempts_used_through) /
    /// [`attempts_remaining`](Self::attempts_remaining) /
    /// [`attempts_remaining_including`](Self::attempts_remaining_including)
    /// (clamp-DEPENDENT).
    ///
    /// # Boolean-numeric correspondence at the FLOOR peer
    ///
    /// The boolean FLOOR-COMPLEMENT reading `is_retry_attempt(a)` is
    /// equivalent to the numeric FLOOR-EXCLUSIVE reading
    /// `attempts_completed_before(a) > 0`:
    ///
    /// ```text
    /// self.is_retry_attempt(a) == (self.attempts_completed_before(a) > 0)
    /// ```
    ///
    /// — pinned by
    /// [`tests::test_retry_policy_is_retry_attempt_iff_attempts_completed_before_positive`].
    /// The zero-vs-positive dichotomy at the numeric FLOOR-EXCLUSIVE
    /// reading names exactly the "first-vs-retry" dichotomy at the
    /// boolean FLOOR peer, mirroring the algebraic law
    /// `is_interim_attempt(a) == (attempts_remaining(a) > 0)` that ties
    /// the boolean CEILING-COMPLEMENT reading to the numeric
    /// CEILING-EXCLUSIVE reading at the ceiling peer.
    ///
    /// # Const-fn discipline
    ///
    /// Marked `const fn` for the same reason
    /// [`is_first_attempt`](Self::is_first_attempt),
    /// [`is_final_attempt`](Self::is_final_attempt),
    /// [`is_interim_attempt`](Self::is_interim_attempt),
    /// [`is_no_retry`](Self::is_no_retry), and
    /// [`will_retry`](Self::will_retry) are: the predicate is a pure
    /// function of the attempt argument, delegating to a const-fn peer.
    /// A const-context call shape (e.g., a `const
    /// FIRST_IS_NOT_RETRY: bool =
    /// !RetryPolicy::network().is_retry_attempt(1);` table at a future
    /// telemetry-label site) is admissible.
    ///
    /// THEORY.md §VI.1 one-oracle discipline: the per-attempt-axis
    /// "is-this-a-retry" partition is named at one typed-primitive site
    /// instead of retyped as the inline `attempt > 1` or `attempt >= 2`
    /// or `!policy.is_first_attempt(attempt)` cascade at every consumer
    /// — a future per-attempt telemetry surface emitting a
    /// "retry-vs-first-call" class label, a warn-message enrichment at
    /// [`log_retry_attempt`](crate::retry::log_retry_attempt) that
    /// gates its "retrying attempt N" prefix on
    /// `!is_first_attempt(attempt)`, a structured-attestation surface
    /// recording the "ran-under-retry" provenance class as the
    /// complement of the first-attempt reading, or a pre-attempt
    /// happy-path guard that skips the "no retries needed" log on
    /// `is_first_attempt(attempt) && op.is_ok()` — all read one named
    /// typed method rather than restating the raw-counter comparison.
    /// THEORY.md §V.4 typed primitives: the reading is a typed-primitive
    /// surface on `RetryPolicy` itself (one named const-fn method), not
    /// a raw-counter-comparison shape restated at every consumer.
    ///
    /// [`log_retry_attempt`]: crate::retry::log_retry_attempt
    /// [`is_first_attempt`]: Self::is_first_attempt
    /// [`is_final_attempt`]: Self::is_final_attempt
    /// [`is_interim_attempt`]: Self::is_interim_attempt
    #[allow(dead_code)]
    pub const fn is_retry_attempt(&self, attempt: u32) -> bool {
        !self.is_first_attempt(attempt)
    }

    /// The number of ATTEMPTS this policy has BURNED before the given
    /// 1-indexed `attempt` — i.e., `attempt.saturating_sub(1)`, the
    /// prior-attempts count read as a `u32` at every attempt-index in
    /// the retry-loop's 1-indexed convention. The per-attempt-axis
    /// FLOOR NUMERIC peer of the CEILING NUMERIC
    /// [`attempts_remaining`](Self::attempts_remaining) reading —
    /// closes the numeric-peer pair at the same per-attempt grain the
    /// boolean partition [`is_first_attempt`](Self::is_first_attempt) /
    /// [`is_final_attempt`](Self::is_final_attempt) /
    /// [`is_interim_attempt`](Self::is_interim_attempt) already spans.
    ///
    /// # The per-attempt-axis floor NUMERIC peer
    ///
    /// The per-attempt-axis previously named:
    ///
    /// - the CEILING BOOLEAN partition through
    ///   [`is_final_attempt`](Self::is_final_attempt) /
    ///   [`is_interim_attempt`](Self::is_interim_attempt) ("is
    ///   `attempt >= max`? — is another attempt in budget?");
    /// - the CEILING NUMERIC reading through
    ///   [`attempts_remaining`](Self::attempts_remaining) ("how many
    ///   attempts remain AFTER this one?");
    /// - the FLOOR BOOLEAN reading through
    ///   [`is_first_attempt`](Self::is_first_attempt) ("is this the
    ///   opening attempt, before any retry has been consumed?").
    ///
    /// `attempts_completed_before` closes the FLOOR NUMERIC side: "how
    /// many attempts have been consumed BEFORE this one?" — the
    /// numeric peer of the floor boolean at the same axis, matching
    /// the numeric/boolean peer idiom
    /// [`attempts_remaining`](Self::attempts_remaining) already
    /// established at the ceiling.
    ///
    /// # Zero iff first attempt
    ///
    /// `attempts_completed_before(attempt) == 0` exactly when
    /// [`is_first_attempt`](Self::is_first_attempt) fires — the
    /// algebraic law tying the numeric prior-count reading to the
    /// boolean per-attempt "is-this-the-first-one?" partition, pinned
    /// by
    /// [`tests::test_retry_policy_attempts_completed_before_zero_iff_is_first_attempt`].
    /// The floor-side peer of the
    /// `attempts_remaining(attempt) == 0 iff is_final_attempt(attempt)`
    /// law pinned at the ceiling.
    ///
    /// # Conservation-of-attempts identity
    ///
    /// For every `attempt ∈ [1, effective_max_attempts()]`:
    ///
    /// ```text
    /// attempts_completed_before(attempt)
    ///   + 1
    ///   + attempts_remaining(attempt)
    ///   == effective_max_attempts()
    /// ```
    ///
    /// — the prior + current + remaining decomposition of the clamped
    /// budget, pinned by
    /// [`tests::test_retry_policy_attempts_completed_before_conservation_in_budget`].
    /// A future regression that desynced any of the three primitives
    /// (an off-by-one in the numeric floor, an off-by-one in the
    /// numeric ceiling, a drift in the clamp discipline) lights up
    /// this test.
    ///
    /// # Clamp-independence discipline
    ///
    /// Unlike [`attempts_remaining`](Self::attempts_remaining),
    /// [`is_final_attempt`](Self::is_final_attempt), and
    /// [`is_interim_attempt`](Self::is_interim_attempt), this reading
    /// does NOT ground through
    /// [`effective_max_attempts`](Self::effective_max_attempts) — the
    /// prior-attempts count at any given `attempt` is `attempt - 1`
    /// regardless of the clamped budget's ceiling, mirroring the
    /// clamp-independence discipline
    /// [`is_first_attempt`](Self::is_first_attempt) applies at the
    /// floor BOOLEAN side. The load-bearing structural asymmetry: the
    /// per-attempt-axis ceiling depends on the policy's budget; the
    /// per-attempt-axis floor does not. Naming the reading at one
    /// typed-primitive site pins that asymmetry as an explicit surface
    /// distinct from the clamp-grounded ceiling peers.
    ///
    /// # Saturating-sub discipline
    ///
    /// The body reads `attempt.saturating_sub(1)` — a pre-invocation
    /// `attempt == 0` counter reading (matches the shape
    /// [`run_with_policy`]'s counter enters the loop body with, before
    /// the `attempt += 1` increment) reads `0`, matching the
    /// `is_first_attempt(0) == true` reading at the boolean peer. No
    /// underflow.
    ///
    /// # Const-fn discipline
    ///
    /// Marked `const fn` for the same reason
    /// [`is_first_attempt`](Self::is_first_attempt),
    /// [`is_final_attempt`](Self::is_final_attempt),
    /// [`is_interim_attempt`](Self::is_interim_attempt),
    /// [`attempts_remaining`](Self::attempts_remaining),
    /// [`effective_max_attempts`](Self::effective_max_attempts),
    /// [`is_no_retry`](Self::is_no_retry), and
    /// [`will_retry`](Self::will_retry) are: the reading is a pure
    /// function of the attempt argument, with no allocation and no
    /// receiver-field access beyond the const-stable
    /// `u32::saturating_sub`. A const-context call shape (e.g., a
    /// `const FIRST_HAS_NO_PRIOR: u32 =
    /// RetryPolicy::network().attempts_completed_before(1);` table at
    /// a future telemetry-label site) is admissible.
    ///
    /// THEORY.md §VI.1 one-oracle discipline: the prior-attempts count
    /// is named at one typed-primitive site instead of retyped as the
    /// inline `attempt.saturating_sub(1)` cascade at every consumer
    /// site — a future per-attempt telemetry counter emitting
    /// "attempts consumed so far", a structured-attestation surface
    /// recording the prior-attempt count as a numeric provenance
    /// datum, a warn-message enrichment at
    /// [`log_retry_attempt`](crate::retry::log_retry_attempt) that
    /// wants to surface the burned-so-far count distinct from the
    /// current 1-indexed attempt number — all read through one named
    /// typed method rather than restating the raw subtraction against
    /// the counter. THEORY.md §V.4 typed primitives: the reading is a
    /// typed-primitive surface on `RetryPolicy` itself (one named
    /// const-fn method), not a raw-counter-shape restated at every
    /// consumer.
    #[allow(dead_code)]
    pub const fn attempts_completed_before(&self, attempt: u32) -> u32 {
        let _ = self;
        attempt.saturating_sub(1)
    }

    /// The number of ATTEMPTS this policy has BURNED through the given
    /// 1-indexed `attempt` INCLUSIVE — i.e., `attempt.min(self.
    /// effective_max_attempts())`, the budget-clamped consumption count
    /// read as a `u32` at every attempt-index in the retry-loop's
    /// 1-indexed convention. The per-attempt-axis FLOOR NUMERIC
    /// INCLUSIVE peer of the FLOOR NUMERIC EXCLUSIVE
    /// [`attempts_completed_before`](Self::attempts_completed_before)
    /// reading — closes the inclusive/exclusive floor-numeric peer pair
    /// at the same per-attempt grain, and gives a universal 2-term
    /// partition of the clamped budget with
    /// [`attempts_remaining`](Self::attempts_remaining).
    ///
    /// # The per-attempt-axis floor NUMERIC INCLUSIVE peer
    ///
    /// The per-attempt-axis previously named:
    ///
    /// - the CEILING BOOLEAN partition through
    ///   [`is_final_attempt`](Self::is_final_attempt) /
    ///   [`is_interim_attempt`](Self::is_interim_attempt) ("is
    ///   `attempt >= max`? — is another attempt in budget?");
    /// - the CEILING NUMERIC reading through
    ///   [`attempts_remaining`](Self::attempts_remaining) ("how many
    ///   attempts remain AFTER this one?");
    /// - the FLOOR BOOLEAN reading through
    ///   [`is_first_attempt`](Self::is_first_attempt) ("is this the
    ///   opening attempt, before any retry has been consumed?");
    /// - the FLOOR NUMERIC EXCLUSIVE reading through
    ///   [`attempts_completed_before`](Self::attempts_completed_before)
    ///   ("how many attempts have been consumed BEFORE this one?").
    ///
    /// `attempts_used_through` closes the FLOOR NUMERIC INCLUSIVE side:
    /// "how many budget slots have been consumed THROUGH this one
    /// inclusive?" — the inclusive peer of the exclusive floor at the
    /// same axis, mirroring the numerator "k" of the canonical "attempt
    /// k of n" progress-message shape [`log_retry_attempt`] formats at
    /// the warn surface.
    ///
    /// # Universal 2-term conservation identity
    ///
    /// For EVERY `attempt: u32` (including `0`, in-budget, and
    /// out-of-budget):
    ///
    /// ```text
    /// attempts_used_through(attempt)
    ///   + attempts_remaining(attempt)
    ///   == effective_max_attempts()
    /// ```
    ///
    /// — the budget-slots-used + budget-slots-left decomposition of the
    /// clamped budget, pinned by
    /// [`tests::test_retry_policy_attempts_used_through_conservation_universal`].
    /// Stronger than the 3-term
    /// `attempts_completed_before + 1 + attempts_remaining ==
    /// effective_max_attempts` identity
    /// ([`tests::test_retry_policy_attempts_completed_before_conservation_in_budget`]),
    /// which requires `attempt ∈ [1, effective_max_attempts()]`: the
    /// 2-term identity holds universally because both terms saturate at
    /// the budget boundary (the FLOOR INCLUSIVE saturates at
    /// `effective_max_attempts()`, the CEILING EXCLUSIVE saturates at
    /// `0`). A future regression that desynced the pair (an off-by-one
    /// in either primitive, drift in the clamp discipline) lights up
    /// this test.
    ///
    /// # Relation to `attempts_completed_before`
    ///
    /// The floor pair is related by `+1` under the clamp — inside the
    /// budget:
    ///
    /// ```text
    /// attempts_used_through(attempt)
    ///   == attempts_completed_before(attempt) + 1
    ///   for attempt ∈ [1, effective_max_attempts()]
    /// ```
    ///
    /// — pinned by
    /// [`tests::test_retry_policy_attempts_used_through_is_completed_before_plus_one_in_budget`].
    /// Outside the budget the two diverge by the clamp discipline: at
    /// `attempt = 0` the pair reads `used_through(0) = 0` (nothing has
    /// been used yet) while `completed_before(0) = 0` (nothing has been
    /// completed either), so `used_through(0) != completed_before(0) +
    /// 1`; at `attempt > effective_max_attempts()` the inclusive floor
    /// saturates at `effective_max_attempts()` while the exclusive
    /// floor `completed_before` grows unboundedly (its
    /// clamp-independence discipline). The load-bearing structural
    /// asymmetry: the exclusive floor is clamp-INDEPENDENT (a pure
    /// counter of prior attempts), the inclusive floor is
    /// clamp-DEPENDENT (a bounded-consumption reading against the
    /// budget). Naming the two at distinct typed-primitive sites pins
    /// the asymmetry as an explicit surface.
    ///
    /// # Clamp-dependence discipline
    ///
    /// Like [`attempts_remaining`](Self::attempts_remaining),
    /// [`is_final_attempt`](Self::is_final_attempt), and
    /// [`is_interim_attempt`](Self::is_interim_attempt) — and UNLIKE
    /// [`attempts_completed_before`](Self::attempts_completed_before)
    /// and [`is_first_attempt`](Self::is_first_attempt) — this reading
    /// grounds through
    /// [`effective_max_attempts`](Self::effective_max_attempts): the
    /// count of budget slots used through any given `attempt` saturates
    /// at the clamped budget's ceiling, matching the clamp-grounded
    /// discipline the ceiling peers apply. The load-bearing structural
    /// symmetry with `attempts_remaining`: the two together decompose
    /// the clamped budget into "used" and "left" halves, both saturating
    /// at the same boundary.
    ///
    /// # `u32::min` discipline
    ///
    /// The body reads `attempt.min(self.effective_max_attempts())` — a
    /// pre-invocation `attempt == 0` counter reading (matches the shape
    /// [`run_with_policy`]'s counter enters the loop body with, before
    /// the `attempt += 1` increment) reads `0`, and an out-of-budget
    /// `attempt > effective_max_attempts()` reading saturates at
    /// `effective_max_attempts()` (matching the ceiling-clamp discipline
    /// [`attempts_remaining`] applies from the other direction). No
    /// overflow.
    ///
    /// # Const-fn discipline
    ///
    /// Marked `const fn` for the same reason
    /// [`is_first_attempt`](Self::is_first_attempt),
    /// [`is_final_attempt`](Self::is_final_attempt),
    /// [`is_interim_attempt`](Self::is_interim_attempt),
    /// [`attempts_remaining`](Self::attempts_remaining),
    /// [`attempts_completed_before`](Self::attempts_completed_before),
    /// [`effective_max_attempts`](Self::effective_max_attempts),
    /// [`is_no_retry`](Self::is_no_retry), and
    /// [`will_retry`](Self::will_retry) are: the reading is a pure
    /// function of the receiver and attempt argument, with no
    /// allocation and no trait dispatch beyond the const-stable
    /// `u32::min` on the derived [`u32::Ord`] instance and the
    /// const-callable
    /// [`effective_max_attempts`](Self::effective_max_attempts) it
    /// grounds through. A const-context call shape (e.g., a
    /// `const NETWORK_USED_AT_FIRST: u32 =
    /// RetryPolicy::network().attempts_used_through(1);` table at a
    /// future telemetry-label site) is admissible.
    ///
    /// THEORY.md §VI.1 one-oracle discipline: the budget-slots-used
    /// count is named at one typed-primitive site instead of retyped
    /// as the inline `attempt.min(self.effective_max_attempts())` or
    /// `(attempts_completed_before + 1).min(effective_max_attempts)`
    /// cascade at every consumer site — a future per-attempt telemetry
    /// gauge emitting "budget consumed so far" against the total
    /// budget, a structured-attestation surface recording the
    /// budget-consumption count as a numeric provenance datum against
    /// the SLSA chain, a warn-message enrichment at
    /// [`log_retry_attempt`](crate::retry::log_retry_attempt) that
    /// wants to surface the "k of n" progress numerator distinct from
    /// the raw 1-indexed attempt counter — all read through one named
    /// typed method rather than restating the clamped-min cascade
    /// against the counter and the budget. THEORY.md §V.4 typed
    /// primitives: the reading is a typed-primitive surface on
    /// `RetryPolicy` itself (one named const-fn method), not a
    /// raw-counter-plus-clamp shape restated at every consumer.
    #[allow(dead_code)]
    pub const fn attempts_used_through(&self, attempt: u32) -> u32 {
        let cap = self.effective_max_attempts();
        if attempt < cap {
            attempt
        } else {
            cap
        }
    }

    /// The number of BUDGET SLOTS this policy has REMAINING at the given
    /// 1-indexed `attempt` INCLUSIVE — i.e., the current attempt itself
    /// plus every attempt still to come under the clamped budget, read as
    /// a `u32` at every attempt-index in the retry-loop's 1-indexed
    /// convention. The per-attempt-axis CEILING NUMERIC INCLUSIVE peer of
    /// the CEILING NUMERIC EXCLUSIVE
    /// [`attempts_remaining`](Self::attempts_remaining) reading — closes
    /// the inclusive/exclusive ceiling-numeric peer pair at the same
    /// per-attempt grain, and closes the full 2×2 numeric quadrant grid
    /// (FLOOR/CEILING × EXCLUSIVE/INCLUSIVE) the numeric axis at the
    /// per-attempt surface exposes.
    ///
    /// # The per-attempt-axis 2×2 numeric quadrant closure
    ///
    /// The per-attempt-axis numeric surface now spans:
    ///
    /// - the FLOOR NUMERIC EXCLUSIVE reading through
    ///   [`attempts_completed_before`](Self::attempts_completed_before)
    ///   ("how many attempts have been consumed BEFORE this one?",
    ///   clamp-INDEPENDENT);
    /// - the FLOOR NUMERIC INCLUSIVE reading through
    ///   [`attempts_used_through`](Self::attempts_used_through) ("how
    ///   many budget slots have been consumed THROUGH this one
    ///   inclusive?", clamp-DEPENDENT);
    /// - the CEILING NUMERIC EXCLUSIVE reading through
    ///   [`attempts_remaining`](Self::attempts_remaining) ("how many
    ///   attempts remain AFTER this one?", clamp-DEPENDENT).
    ///
    /// `attempts_remaining_including` closes the CEILING NUMERIC
    /// INCLUSIVE side: "how many budget slots remain FROM this one
    /// forward, counting the current attempt itself?" — the numerator
    /// "n − k + 1" reading a per-attempt progress emitter that says
    /// "attempts remaining including this one" wants, distinct from the
    /// AFTER-current [`attempts_remaining`] reading.
    ///
    /// # Dual conservation identity
    ///
    /// For every `attempt: u32` with `attempt <= effective_max_attempts() + 1`:
    ///
    /// ```text
    /// attempts_completed_before(attempt)
    ///   + attempts_remaining_including(attempt)
    ///   == effective_max_attempts()
    /// ```
    ///
    /// — the completed-before + remaining-including-current decomposition
    /// of the clamped budget, the dual of the universal 2-term
    /// `attempts_used_through(attempt) + attempts_remaining(attempt) ==
    /// effective_max_attempts()` identity, pinned by
    /// [`tests::test_retry_policy_attempts_remaining_including_dual_conservation`].
    /// Unlike the FLOOR-INCLUSIVE + CEILING-EXCLUSIVE partition (which
    /// holds universally because both terms saturate at the budget
    /// boundary), the dual FLOOR-EXCLUSIVE + CEILING-INCLUSIVE partition
    /// holds only up to `effective_max_attempts() + 1`: beyond that, the
    /// clamp-INDEPENDENT floor exclusive `attempts_completed_before`
    /// grows unboundedly while the clamp-DEPENDENT ceiling inclusive
    /// saturates at `0`, so the sum overshoots the budget.
    ///
    /// # Relation to `attempts_remaining`
    ///
    /// The ceiling pair is related by `+1` under the clamp — for every
    /// `attempt ∈ [1, effective_max_attempts()]`:
    ///
    /// ```text
    /// attempts_remaining_including(attempt)
    ///   == attempts_remaining(attempt) + 1
    /// ```
    ///
    /// — pinned by
    /// [`tests::test_retry_policy_attempts_remaining_including_is_remaining_plus_one_in_budget`].
    /// The load-bearing bridge between the CEILING NUMERIC EXCLUSIVE and
    /// CEILING NUMERIC INCLUSIVE readings inside the budget, mirroring
    /// the FLOOR-side `+1` bridge
    /// `attempts_used_through(attempt) == attempts_completed_before(attempt) + 1`
    /// pinned by
    /// [`tests::test_retry_policy_attempts_used_through_is_completed_before_plus_one_in_budget`].
    /// Outside the budget the two ceiling readings diverge by the clamp
    /// discipline: both saturate at `0`, but from different attempt-index
    /// thresholds (`attempts_remaining` saturates one attempt earlier
    /// because it counts strictly AFTER the current attempt).
    ///
    /// # Clamp-dependence discipline
    ///
    /// Like [`attempts_remaining`](Self::attempts_remaining),
    /// [`attempts_used_through`](Self::attempts_used_through),
    /// [`is_final_attempt`](Self::is_final_attempt), and
    /// [`is_interim_attempt`](Self::is_interim_attempt) — and UNLIKE
    /// [`attempts_completed_before`](Self::attempts_completed_before)
    /// and [`is_first_attempt`](Self::is_first_attempt) — this reading
    /// grounds through
    /// [`effective_max_attempts`](Self::effective_max_attempts): the
    /// count of budget slots remaining including the current attempt
    /// saturates at `0` past the clamped budget's ceiling and at the
    /// full budget at attempt `0` or `1`, matching the clamp-grounded
    /// discipline the other ceiling peers apply.
    ///
    /// # Saturating-sub discipline
    ///
    /// The body reads
    /// `self.effective_max_attempts().saturating_sub(self.attempts_completed_before(attempt))`
    /// — grounding through both clamp-grounded primitives at once so any
    /// future drift in either the clamped-budget definition or the
    /// prior-attempts count propagates coherently. At `attempt == 0`
    /// (pre-invocation) and `attempt == 1` (first attempt), reads
    /// `effective_max_attempts()` (the full budget is still ahead
    /// counting the current slot). At `attempt == effective_max_attempts()`
    /// (last attempt), reads `1` (only the current slot remains). At
    /// `attempt > effective_max_attempts()` (out-of-budget), saturates
    /// at `0`. No underflow.
    ///
    /// # Const-fn discipline
    ///
    /// Marked `const fn` for the same reason
    /// [`attempts_used_through`](Self::attempts_used_through),
    /// [`attempts_completed_before`](Self::attempts_completed_before),
    /// [`attempts_remaining`](Self::attempts_remaining),
    /// [`effective_max_attempts`](Self::effective_max_attempts),
    /// [`is_first_attempt`](Self::is_first_attempt),
    /// [`is_final_attempt`](Self::is_final_attempt),
    /// [`is_interim_attempt`](Self::is_interim_attempt),
    /// [`is_no_retry`](Self::is_no_retry), and
    /// [`will_retry`](Self::will_retry) are: the reading is a pure
    /// function of the receiver and the attempt argument, with no
    /// allocation and no trait dispatch beyond the const-callable
    /// [`effective_max_attempts`](Self::effective_max_attempts) and
    /// [`attempts_completed_before`](Self::attempts_completed_before) it
    /// grounds through, plus the const-stable `u32::saturating_sub`. A
    /// const-context call shape (e.g., a
    /// `const NETWORK_REMAIN_INCL_AT_FIRST: u32 =
    /// RetryPolicy::network().attempts_remaining_including(1);` table at
    /// a future telemetry-label site) is admissible.
    ///
    /// THEORY.md §VI.1 one-oracle discipline: the "attempts left
    /// including current" count is named at one typed-primitive site
    /// instead of retyped as the inline
    /// `self.effective_max_attempts().saturating_sub(attempt.saturating_sub(1))`
    /// or `self.attempts_remaining(attempt).saturating_add(1)` cascade
    /// at every consumer site — a future per-attempt telemetry gauge
    /// emitting "attempts left INCLUDING this one" against the total
    /// budget (the numerator a user-visible "N attempts to go
    /// (including this one)" progress prefix wants), a structured-
    /// attestation surface recording the remaining-INCLUDING-current
    /// count as a numeric provenance datum against the SLSA chain, a
    /// warn-message enrichment at
    /// [`log_retry_attempt`](crate::retry::log_retry_attempt) that
    /// wants to surface the "N-attempts-left-including-this-one"
    /// progress denominator distinct from the strictly-AFTER
    /// [`attempts_remaining`](Self::attempts_remaining) reading — all
    /// read through one named typed method rather than restating the
    /// saturating-sub cascade against the budget. THEORY.md §V.4 typed
    /// primitives: the reading is a typed-primitive surface on
    /// `RetryPolicy` itself (one named const-fn method), not a
    /// raw-budget-minus-prior-count shape restated at every consumer.
    #[allow(dead_code)]
    pub const fn attempts_remaining_including(&self, attempt: u32) -> u32 {
        self.effective_max_attempts()
            .saturating_sub(self.attempts_completed_before(attempt))
    }

    /// True iff the 1-indexed `attempt` is STRICTLY PAST this policy's
    /// clamped budget — i.e., `attempt > self.effective_max_attempts()`,
    /// the "structurally-exhausted" per-attempt reading distinct from the
    /// "at-or-past" reading [`is_final_attempt`](Self::is_final_attempt)
    /// captures. Named strict CEILING peer of the non-strict CEILING
    /// anchor [`is_final_attempt`](Self::is_final_attempt): the two
    /// together decompose the CEILING side of the per-attempt-axis into
    /// the 3-way partition "before-boundary" / "at-boundary" /
    /// "past-boundary" that a per-attempt consumer receiving an
    /// out-of-band `attempt` (a telemetry replay, a deserialized retry
    /// record, a bug in caller code) can classify without restating the
    /// raw `attempt > self.max_attempts.max(1)` cascade.
    ///
    /// # 3-way CEILING partition
    ///
    /// The two CEILING predicates together classify every `attempt: u32`:
    ///
    /// |  Region         | Predicate reading                                     |
    /// | --------------- | ----------------------------------------------------- |
    /// | BEFORE boundary | `is_interim_attempt(a) == true`                       |
    /// | AT boundary     | `is_final_attempt(a) && !is_over_budget(a)`           |
    /// | PAST boundary   | `is_over_budget(a) == true` (⊂ `is_final_attempt(a)`) |
    ///
    /// [`is_final_attempt`](Self::is_final_attempt) fires on both AT and
    /// PAST regions (its non-strict `>=` reading), whereas `is_over_budget`
    /// fires only on the PAST region (its strict `>` reading). The
    /// distinction is load-bearing for a per-attempt consumer that wants
    /// to distinguish "this attempt is the last legal one in the budget"
    /// (a route to the loud-fail final-attempt telemetry class) from
    /// "this attempt index is structurally impossible under the policy"
    /// (a route to a caller-bug diagnostic class distinct from the
    /// exhausted-budget class).
    ///
    /// # Strict subset of `is_final_attempt`
    ///
    /// The implication `is_over_budget(a) ⇒ is_final_attempt(a)` holds
    /// for every [`RetryPolicy`] record and every `attempt` — pinned by
    /// [`tests::test_retry_policy_is_over_budget_implies_is_final_attempt`].
    /// A future regression that broadened `is_over_budget` to fire on
    /// `attempt >= max` (collapsing the 3-way partition back to the
    /// 2-way anchor/complement) or that narrowed `is_final_attempt` to
    /// fire only on `attempt == max` (breaking the loop-short-circuit
    /// discipline [`run_with_policy`] reads through it) lights up this
    /// test.
    ///
    /// # Boolean-numeric correspondence with `attempts_remaining_including`
    ///
    /// The strict CEILING boolean reading `is_over_budget(a)` is
    /// equivalent to the CEILING NUMERIC INCLUSIVE reading
    /// `attempts_remaining_including(a) == 0`:
    ///
    /// ```text
    /// self.is_over_budget(a) == (self.attempts_remaining_including(a) == 0)
    /// ```
    ///
    /// — pinned by
    /// [`tests::test_retry_policy_is_over_budget_iff_attempts_remaining_including_zero`].
    /// The zero-slot reading at the CEILING NUMERIC INCLUSIVE peer names
    /// exactly the "past-the-boundary" reading at the CEILING BOOLEAN
    /// strict peer — the "budget saturated with the current slot itself
    /// gone" dichotomy at both surfaces, mirroring the algebraic bridge
    /// `is_interim_attempt(a) == (attempts_remaining(a) > 0)` that ties
    /// the CEILING NON-STRICT boolean COMPLEMENT to the CEILING NUMERIC
    /// EXCLUSIVE positive reading at the boundary-adjacent peer.
    ///
    /// # Clamp-dependence discipline
    ///
    /// Like [`is_final_attempt`](Self::is_final_attempt),
    /// [`is_interim_attempt`](Self::is_interim_attempt),
    /// [`attempts_remaining`](Self::attempts_remaining),
    /// [`attempts_used_through`](Self::attempts_used_through), and
    /// [`attempts_remaining_including`](Self::attempts_remaining_including)
    /// — and UNLIKE the clamp-INDEPENDENT FLOOR peers
    /// [`is_first_attempt`](Self::is_first_attempt),
    /// [`is_retry_attempt`](Self::is_retry_attempt), and
    /// [`attempts_completed_before`](Self::attempts_completed_before) —
    /// this reading grounds through
    /// [`effective_max_attempts`](Self::effective_max_attempts): whether
    /// attempt `a` is past the budget is determined against the clamped
    /// budget, not the raw `self.max_attempts` field, so a hand-built
    /// `RetryPolicy { max_attempts: 0, .. }` (the degenerate shape every
    /// factory constructor's clamping discipline forecloses against) reads
    /// as-if `max_attempts == 1` under this predicate, matching the
    /// clamp-DEPENDENT discipline the other CEILING peers apply.
    ///
    /// # Const-fn discipline
    ///
    /// Marked `const fn` for the same reason
    /// [`is_final_attempt`](Self::is_final_attempt),
    /// [`is_interim_attempt`](Self::is_interim_attempt),
    /// [`effective_max_attempts`](Self::effective_max_attempts), and the
    /// other CEILING peers are: the reading is a pure function of the
    /// receiver and attempt argument, with no allocation and no trait
    /// dispatch beyond the const-callable
    /// [`effective_max_attempts`](Self::effective_max_attempts) and the
    /// const-stable `u32::gt` comparison on the derived [`u32::Ord`]
    /// instance. A const-context call shape (e.g., a
    /// `const NETWORK_OVER_AT_ONE: bool =
    /// RetryPolicy::network().is_over_budget(1);` table at a future
    /// telemetry-label site) is admissible.
    ///
    /// THEORY.md §VI.1 one-oracle discipline: the "past-the-clamped-
    /// budget" reading is named at one typed-primitive site instead of
    /// retyped as the inline `attempt > self.max_attempts.max(1)` or
    /// `attempt > self.effective_max_attempts()` or
    /// `self.attempts_remaining_including(attempt) == 0` cascade at every
    /// consumer — a future per-attempt telemetry surface emitting a
    /// caller-bug "impossible attempt index" class distinct from the
    /// budget-exhausted "final-attempt" class, a structured-attestation
    /// surface recording the "structurally-past-budget" provenance class
    /// distinct from the "at-final-slot" class, a defensive
    /// pre-invocation guard that skips the `op(attempt)` call on
    /// out-of-band attempt indices before they reach the retry loop —
    /// all read one named typed method. THEORY.md §V.5 total-order
    /// discipline: the predicate reads the strict `>` comparison on the
    /// derived [`u32::Ord`] instance, the strict-inequality peer of the
    /// non-strict `>=` comparison [`is_final_attempt`](Self::is_final_attempt)
    /// reads, applied to the same per-attempt axis with the clamp-to-≥1
    /// invariant preserved by delegation.
    #[allow(dead_code)]
    pub const fn is_over_budget(&self, attempt: u32) -> bool {
        attempt > self.effective_max_attempts()
    }

    /// True iff the 1-indexed `attempt` is STRICTLY BEFORE this policy's
    /// FLOOR boundary of `1` — i.e., `attempt < 1` (equivalently `attempt
    /// == 0`), the "not-yet-started" per-attempt reading distinct from the
    /// "at-or-not-yet-started" reading
    /// [`is_first_attempt`](Self::is_first_attempt) captures. Named strict
    /// FLOOR peer of the non-strict FLOOR anchor
    /// [`is_first_attempt`](Self::is_first_attempt): the two together
    /// decompose the FLOOR side of the per-attempt-axis into the 3-way
    /// partition "before-boundary" / "at-boundary" / "past-boundary" that
    /// a per-attempt consumer receiving an out-of-band `attempt` (a
    /// telemetry replay of a pre-invocation state, a deserialized
    /// counter reading, a bug in caller code) can classify without
    /// restating the raw `attempt < 1` or `attempt == 0` cascade.
    ///
    /// The FLOOR-side mirror of the strict CEILING peer
    /// [`is_over_budget`](Self::is_over_budget): both peers name the
    /// "strictly past the boundary" reading distinct from the "at-or-past
    /// the boundary" reading the non-strict anchor captures. Together they
    /// close the per-attempt-axis BOOLEAN 3×2 grid at (FLOOR/CEILING ×
    /// NON-STRICT/COMPLEMENT/STRICT), the full boundary-classification
    /// surface the per-attempt-axis exposes.
    ///
    /// # 3-way FLOOR partition
    ///
    /// The two FLOOR predicates together classify every `attempt: u32`:
    ///
    /// |  Region         | Predicate reading                                       |
    /// | --------------- | ------------------------------------------------------- |
    /// | PAST boundary   | [`is_retry_attempt`](Self::is_retry_attempt) == true    |
    /// | AT boundary     | `is_first_attempt(a) && !is_before_first_attempt(a)`    |
    /// | BEFORE boundary | `is_before_first_attempt(a) == true` (⊂ `is_first_attempt(a)`) |
    ///
    /// [`is_first_attempt`](Self::is_first_attempt) fires on both AT and
    /// BEFORE regions (its non-strict `<=` reading), whereas
    /// `is_before_first_attempt` fires only on the BEFORE region (its
    /// strict `<` reading). The distinction is load-bearing for a
    /// per-attempt consumer that wants to distinguish "this is the first
    /// legal call in the schedule" (a route to the first-call happy-path
    /// telemetry class) from "this attempt index is a pre-invocation
    /// counter reading, not a live call" (a route to a caller-bug or
    /// telemetry-replay diagnostic class distinct from the at-first-call
    /// class).
    ///
    /// # The per-attempt-axis BOOLEAN 3×2 grid closure
    ///
    /// The per-attempt-axis boolean surface now spans:
    ///
    /// |         | NON-STRICT (anchor)                     | COMPLEMENT (De Morgan)                | STRICT (⊂ anchor)                                    |
    /// | ------- | --------------------------------------- | ------------------------------------- | ---------------------------------------------------- |
    /// | FLOOR   | [`is_first_attempt`] (`a <= 1`)         | [`is_retry_attempt`] (`a > 1`)        | `is_before_first_attempt` (`a < 1`) ← new            |
    /// | CEILING | [`is_final_attempt`] (`a >= budget`)    | [`is_interim_attempt`] (`a < budget`) | [`is_over_budget`] (`a > budget`)                    |
    ///
    /// Every consumer that previously would have retyped the inline
    /// `attempt < 1` or `attempt == 0` cascade — a per-attempt telemetry
    /// class emitting a "pre-invocation counter reading" label distinct
    /// from the "at-first-call" label, a structured-attestation surface
    /// recording the "not-yet-started" provenance datum against the SLSA
    /// chain, a defensive pre-invocation guard that classifies out-of-band
    /// attempt indices before they reach the retry loop, a caller-bug
    /// diagnostic that discriminates the pre-invocation zero index from
    /// the first-call one index — now reads one named typed method.
    ///
    /// # Strict subset of `is_first_attempt`
    ///
    /// The implication `is_before_first_attempt(a) ⇒ is_first_attempt(a)`
    /// holds for every [`RetryPolicy`] record and every `attempt` —
    /// pinned by
    /// [`tests::test_retry_policy_is_before_first_attempt_implies_is_first_attempt`].
    /// The FLOOR-side mirror of the CEILING-side strict-subset law
    /// `is_over_budget(a) ⇒ is_final_attempt(a)`. A future regression
    /// that broadened `is_before_first_attempt` to fire on `attempt <= 1`
    /// (collapsing the 3-way FLOOR partition back to the 2-way
    /// anchor/complement) or narrowed `is_first_attempt` to fire only on
    /// `attempt == 1` (breaking the zero-delay short-circuit
    /// [`compute_delay`](Self::compute_delay) reads through it) lights up
    /// that test.
    ///
    /// # Boolean-numeric correspondence with `attempts_used_through`
    ///
    /// The strict FLOOR boolean reading `is_before_first_attempt(a)` is
    /// equivalent to the FLOOR NUMERIC INCLUSIVE reading
    /// `attempts_used_through(a) == 0`:
    ///
    /// ```text
    /// self.is_before_first_attempt(a) == (self.attempts_used_through(a) == 0)
    /// ```
    ///
    /// — pinned by
    /// [`tests::test_retry_policy_is_before_first_attempt_iff_attempts_used_through_zero`].
    /// The zero-slot reading at the FLOOR NUMERIC INCLUSIVE peer names
    /// exactly the "before-the-boundary" reading at the FLOOR BOOLEAN
    /// strict peer — the "no budget slot consumed even counting the
    /// current one" dichotomy at both surfaces, mirroring the algebraic
    /// bridge `is_over_budget(a) == (attempts_remaining_including(a) == 0)`
    /// that ties the CEILING STRICT boolean reading to the CEILING NUMERIC
    /// INCLUSIVE zero-slot reading. Both STRICT boolean peers correspond
    /// to zero at the INCLUSIVE numeric peer of their side, closing the
    /// strict-peer boolean-numeric correspondence at FLOOR and CEILING
    /// alike.
    ///
    /// # Clamp-independence discipline
    ///
    /// Like [`is_first_attempt`](Self::is_first_attempt) and
    /// [`is_retry_attempt`](Self::is_retry_attempt) — and UNLIKE the
    /// clamp-DEPENDENT CEILING peers
    /// [`is_final_attempt`](Self::is_final_attempt),
    /// [`is_interim_attempt`](Self::is_interim_attempt), and
    /// [`is_over_budget`](Self::is_over_budget) — this reading does not
    /// depend on the policy's clamped budget: whether attempt `a` is
    /// before the first attempt is determined entirely by `a < 1`,
    /// independent of `max_attempts`. This pins the load-bearing
    /// structural asymmetry that ALL THREE per-attempt-axis FLOOR boolean
    /// peers (NON-STRICT/COMPLEMENT/STRICT) are clamp-INDEPENDENT while
    /// ALL THREE per-attempt-axis CEILING boolean peers are
    /// clamp-DEPENDENT, matching the same clamp-INDEPENDENT /
    /// clamp-DEPENDENT asymmetry the numeric quadrant grid pins between
    /// [`attempts_completed_before`](Self::attempts_completed_before)
    /// (clamp-INDEPENDENT) and every other numeric peer (clamp-DEPENDENT).
    ///
    /// # Const-fn discipline
    ///
    /// Marked `const fn` for the same reason
    /// [`is_first_attempt`](Self::is_first_attempt),
    /// [`is_retry_attempt`](Self::is_retry_attempt),
    /// [`is_final_attempt`](Self::is_final_attempt),
    /// [`is_interim_attempt`](Self::is_interim_attempt), and
    /// [`is_over_budget`](Self::is_over_budget) are: the predicate is a
    /// pure function of the attempt argument, with no allocation and no
    /// trait dispatch beyond the const-stable `u32::lt` comparison on the
    /// derived [`u32::Ord`] instance. A const-context call shape (e.g., a
    /// `const NETWORK_BEFORE_AT_ZERO: bool =
    /// RetryPolicy::network().is_before_first_attempt(0);` table at a
    /// future telemetry-label site) is admissible.
    ///
    /// THEORY.md §VI.1 one-oracle discipline: the "strictly-before-first-
    /// attempt" reading is named at one typed-primitive site instead of
    /// retyped as the inline `attempt < 1` or `attempt == 0` or
    /// `self.attempts_used_through(attempt) == 0` cascade at every
    /// consumer — a future per-attempt telemetry surface emitting a
    /// "pre-invocation counter reading" class distinct from the
    /// "at-first-call" class, a structured-attestation surface recording
    /// the "not-yet-started" provenance class distinct from the "at-first-
    /// slot" class, a defensive pre-invocation guard that skips the
    /// `op(attempt)` call on out-of-band pre-invocation indices before
    /// they reach the retry loop — all read one named typed method.
    /// THEORY.md §V.5 total-order discipline: the predicate reads the
    /// strict `<` comparison on the derived [`u32::Ord`] instance, the
    /// strict-inequality peer of the non-strict `<=` comparison
    /// [`is_first_attempt`](Self::is_first_attempt) reads, applied to the
    /// same per-attempt axis with the clamp-INDEPENDENT discipline the
    /// FLOOR peers apply.
    ///
    /// [`is_first_attempt`]: Self::is_first_attempt
    /// [`is_retry_attempt`]: Self::is_retry_attempt
    /// [`is_final_attempt`]: Self::is_final_attempt
    /// [`is_interim_attempt`]: Self::is_interim_attempt
    /// [`is_over_budget`]: Self::is_over_budget
    #[allow(dead_code)]
    pub const fn is_before_first_attempt(&self, attempt: u32) -> bool {
        let _ = self;
        attempt < 1
    }

    /// Project the 1-indexed `attempt` under this policy's per-attempt
    /// axis onto the 5-way [`PerAttemptRegion`] sum — the typed reading
    /// that consumes the closed per-attempt-axis BOOLEAN 3×2 grid
    /// (`is_before_first_attempt` / `is_first_attempt` / `is_retry_attempt`
    /// at the FLOOR side, `is_over_budget` / `is_final_attempt` /
    /// `is_interim_attempt` at the CEILING side) at ONE named projection.
    ///
    /// The projection is a total, mutually-exclusive function on `u32`:
    /// every input maps to exactly one variant, and the classification is
    /// a pure function of `(attempt, self.effective_max_attempts())`.
    /// [`tests::test_retry_policy_per_attempt_region_is_total_and_mutually_exclusive`]
    /// pins totality-and-mutual-exclusion across the canonical
    /// `max_attempts × {ZERO, network}` policy grid × attempt-index grid,
    /// and
    /// [`tests::test_retry_policy_per_attempt_region_grounds_through_boolean_peers`]
    /// pins the FLOOR-then-CEILING boolean-cascade equivalence at every
    /// input.
    ///
    /// # 5-way partition
    ///
    /// For `M = self.effective_max_attempts()` (clamped to ≥ 1):
    ///
    /// | Region        | Predicate reading                                    |
    /// | ------------- | ---------------------------------------------------- |
    /// | `BeforeFirst` | `self.is_before_first_attempt(attempt)`              |
    /// | `First`       | `self.is_first_attempt(attempt) && !self.is_before_first_attempt(attempt) && !self.is_final_attempt(attempt)` |
    /// | `Interim`     | `self.is_retry_attempt(attempt) && !self.is_final_attempt(attempt)` |
    /// | `Final`       | `self.is_final_attempt(attempt) && !self.is_over_budget(attempt)` |
    /// | `OverBudget`  | `self.is_over_budget(attempt)`                       |
    ///
    /// The FLOOR/CEILING boundary collision at `attempt == 1 == M` (a
    /// single-attempt policy calling `op(1)`) is resolved by the CEILING
    /// side: the projection returns [`PerAttemptRegion::Final`], not
    /// [`PerAttemptRegion::First`]. The load-bearing collision-resolution
    /// discipline
    /// [`tests::test_retry_policy_per_attempt_region_absorbs_floor_ceiling_collision_at_no_retry`]
    /// pins.
    ///
    /// # Grounding through the boolean peers
    ///
    /// The body reads the CEILING-then-FLOOR strict cascade — [`is_over_budget`],
    /// [`is_final_attempt`], [`is_retry_attempt`], [`is_before_first_attempt`],
    /// with [`PerAttemptRegion::First`] as the residual case — so a future
    /// regression that broke ANY of the six per-attempt boolean peers'
    /// clamp-independence / clamp-dependence discipline propagates directly
    /// into a misprojection here. The projection does not restate any
    /// `attempt <op> 1` or `attempt <op> self.effective_max_attempts()`
    /// literal; every branch grounds through one named typed method.
    ///
    /// # Const-fn discipline
    ///
    /// Marked `const fn` for the same reason every per-attempt boolean
    /// peer is: the projection is a pure function of the receiver and
    /// attempt argument, with no allocation and no trait dispatch beyond
    /// the const-callable [`is_over_budget`] / [`is_final_attempt`] /
    /// [`is_retry_attempt`] / [`is_before_first_attempt`] ladder and the
    /// const-stable `u32::gt` / `u32::ge` / `u32::lt` comparisons on the
    /// derived [`u32::Ord`] instance. A const-context call shape (e.g., a
    /// `const NETWORK_AT_ONE: PerAttemptRegion =
    /// RetryPolicy::network().per_attempt_region(1);` table at a future
    /// telemetry-label site) is admissible.
    ///
    /// THEORY.md §II Language — typed primitives own boundary
    /// classification; the FLOOR-then-CEILING boolean cascade is projected
    /// here as ONE typed sum instead of restated at every downstream
    /// consumer. THEORY.md §VI.1 one-oracle discipline — the 5-way
    /// classification is named at ONE typed-primitive site (this method);
    /// downstream telemetry-label surfaces, structured-attestation records,
    /// and defensive pre-invocation guards read the sum instead of
    /// restating the six-peer boolean ladder.
    ///
    /// [`is_over_budget`]: Self::is_over_budget
    /// [`is_final_attempt`]: Self::is_final_attempt
    /// [`is_retry_attempt`]: Self::is_retry_attempt
    /// [`is_before_first_attempt`]: Self::is_before_first_attempt
    #[allow(dead_code)]
    pub const fn per_attempt_region(&self, attempt: u32) -> PerAttemptRegion {
        if self.is_over_budget(attempt) {
            PerAttemptRegion::OverBudget
        } else if self.is_final_attempt(attempt) {
            PerAttemptRegion::Final
        } else if self.is_retry_attempt(attempt) {
            PerAttemptRegion::Interim
        } else if self.is_before_first_attempt(attempt) {
            PerAttemptRegion::BeforeFirst
        } else {
            PerAttemptRegion::First
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
        if self.is_first_attempt(attempt) {
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

/// HTTP status codes that signal a transient/retryable failure when they
/// appear as a *standalone* status token in captured stderr.
///
/// These are matched token-wise (a maximal run of ASCII-alphanumeric
/// characters must equal the code exactly), **not** as bare substrings.
/// A bare-substring `"500"` matcher false-positives on every diagnostic
/// that merely happens to contain those three digits — a content digest
/// (`sha256:…ab500cd…`), a byte count (`pushed 50234 bytes`), a port
/// (`10.0.0.1:5000`), a duration (`504ms`), or a request id (`14290`) —
/// converting a terminal failure (auth-denied, manifest-invalid) into a
/// five-attempt retry storm against the registry/cache. In every dialect
/// forge's CLIs actually emit, the status code is a standalone token:
/// skopeo/regctl `"received unexpected HTTP status: 502"`, curl
/// `"The requested URL returned error: 429"`, `"500 Internal Server
/// Error"`. Token-matching keeps all of those while dropping the
/// digits-buried-in-a-larger-token false positives.
///
/// 5xx (500/502/503/504): upstream server faults the registry/cache CDN
/// recovers from. The two RFC-named safe-retry 4xx codes — 408 (Request
/// Timeout, RFC 7231 §6.5.7: "The client MAY repeat the request without
/// modifications at any later time") and 429 (Too Many Requests, RFC 6585
/// §4: the rate-limit backoff signal GHCR / Docker Hub / attic-fronted
/// CDNs return under load with an advisory `Retry-After`) — round out the
/// retryable set. The terminal 4xx family (400/401/403/404 — bad request,
/// auth, not-found) is absent by construction: retrying cannot help, so
/// failing fast preserves the budget.
const TRANSIENT_HTTP_STATUS_CODES: &[&str] = &["500", "502", "503", "504", "408", "429"];

/// Named/phrase markers in captured stderr that signal a transient
/// network/server failure worth retrying. The list is canonical across
/// the dialects forge's external CLIs speak: skopeo (Go's `net/http`),
/// regctl (Go), attic (reqwest/hyper), git-over-HTTPS (curl), and the
/// underlying HTTP servers (GHCR, attic-server). Sourced from the
/// substring set the pre-existing `attic_command_with_retry` matched in
/// production (b0db1da's prior context) plus the Go-stdlib timeout/EOF
/// idioms.
///
/// These are matched as plain substrings (case-sensitive on the
/// canonical capitalization the tools emit) because each is a
/// distinctive multi-word phrase or lowercase idiom with no
/// false-positive ambiguity — unlike the bare numeric status codes
/// (matched token-wise via [`TRANSIENT_HTTP_STATUS_CODES`]) and the
/// bare `EOF` acronym (matched token-wise via
/// [`TRANSIENT_NETWORK_STDERR_TOKEN_MARKERS`]).
const TRANSIENT_NETWORK_STDERR_MARKERS: &[&str] = &[
    // HTTP 5xx — named forms (attic / curl emit named).
    "Internal Server Error",
    "InternalServerError",
    "Bad Gateway",
    "Service Unavailable",
    "Gateway Timeout",
    // HTTP 429 rate limiting — named form (attic/reqwest, skopeo's
    // "received unexpected HTTP status: 429 Too Many Requests"). The
    // numeric "429" form is matched token-wise via the status-code set.
    "Too Many Requests",
    // HTTP 408 Request Timeout — named form. RFC 7231 §6.5.7 names the
    // contract verbatim: "The server would like to shut down this unused
    // connection. […] The client MAY repeat the request without
    // modifications at any later time." The one other RFC-explicit
    // safe-retry 4xx code beyond 429: the spec itself classifies 408 as
    // retryable at the protocol layer regardless of the request's own
    // idempotency, because the server is signalling it never began
    // processing the request body (it timed out the read before the body
    // arrived). Structurally distinct from 429 (`Too Many Requests`,
    // RFC 6585 §4 — rate-limit backoff signal: the server DID receive
    // the request but is asking the client to throttle): 408 says "I
    // never got your request, send it again"; 429 says "I got your
    // request but I'm rate-limiting you, back off then retry". Both
    // converge on the same retry verdict but at different ingress
    // semantics.
    //
    // forge's pipeline pushes against ingress-fronted upstreams every
    // run: GHCR (Microsoft Azure Front Door edge, `client_body_timeout`
    // tunable), attic-server (typically behind an nginx ingress with
    // `client_body_timeout 60s` default), git-over-HTTPS to github.com
    // (GitHub frontend's per-request body-receipt deadline), and
    // kube-apiserver behind a cluster ingress for the external-kubectl
    // shape. Production triggers: the per-blob upload exceeds the
    // ingress's `client_body_timeout` during a slow-start TCP window
    // (skopeo / regctl uploading a large multi-platform manifest blob
    // under burst load), the cluster ingress times out an inbound
    // request body during HPA-driven rolling reconciliation (the new
    // pod isn't ready to accept body bytes within the ingress's
    // upstream-read budget), or Cloudflare/Front-Door synthesizes a 408
    // when the upstream takes longer than the edge's request-body-read
    // budget. Every one is reconvergent within the existing retry-
    // policy budget; the fix here is recognizing the 408 named phrase
    // the prior `"Too Many Requests"` / `"Bad Gateway"` / `"Service
    // Unavailable"` / `"Gateway Timeout"` markers covered only the 5xx
    // and 429 axes, silently short-circuiting the one other RFC-named
    // safe-retry 4xx code at every consumer that reads the named-form
    // dialect (reqwest's `"HTTP status client error (Request Timeout)
    // for url"` carries no standalone `"408"` token for the numeric
    // matcher to catch).
    //
    // Across the dialects forge's external CLIs emit:
    // - Go net/http (skopeo, regctl, kubectl, helm-cli's HTTPS surface):
    //   `http.StatusText(408)` returns `"Request Timeout"` and the Go
    //   client formats `"received unexpected HTTP status: 408 Request
    //   Timeout"` (skopeo's response-error formatter, regctl's identical
    //   formatter, kubectl's `--request-timeout`-elapsed surface against
    //   an ingress that emitted 408 mid-upload);
    // - curl (git-over-HTTPS, container-registry probes, healthcheck
    //   shells): emits `"The requested URL returned error: 408 Request
    //   Timeout"` (curl's response-status formatter through
    //   `CURLE_HTTP_RETURNED_ERROR` when `--fail` is set) — note the
    //   numeric "408" token is captured by the status-code list, the
    //   named phrase is captured here for the dialects that drop the
    //   numeric form;
    // - reqwest / hyper (attic-client Rust surface): `reqwest::StatusCode::
    //   canonical_reason()` for 408 returns `"Request Timeout"` and
    //   reqwest's error formatter emits `"HTTP status client error (408
    //   Request Timeout) for url <url>"` — both forms covered;
    // - nginx ingress emitting 408 to the upstream client when
    //   `client_body_timeout` elapses: the response includes the named
    //   text `"408 Request Timeout"` in its body, surfaced through
    //   whatever client dialect parses the response.
    // One casing only — the named phrase follows the canonical HTTP
    // status text (RFC 7231 §6.5.7, IANA HTTP Status Code Registry
    // canonical: `Request Timeout` with title-case on both words).
    // Every emitter that produces the named form uses this exact
    // casing because they all source from the same canonical status-
    // text table (Go's `http.StatusText`, reqwest's `canonical_reason`,
    // libcurl's `Curl_strcase` lookup, nginx's `ngx_http_error_pages`
    // static table). The marker is distinct from the unrelated
    // diagnostic phrase `"request timeout"` (lowercase, hyphenated
    // form `--request-timeout` for kubectl/helm flag references) and
    // from the connection-level `"i/o timeout"` Go-net signal already
    // carried above (TCP-read-budget exhaustion on an established
    // socket, distinct from the HTTP-status-layer 408 signal here).
    "Request Timeout",
    // Connection-level failures — both Go-stdlib lowercase and curl mixed-case.
    "Connection refused",
    "connection refused",
    "Connection reset",
    "connection reset",
    "Connection aborted",
    // Routing-layer kernel transient — host-scope sibling
    // (`syscall.EHOSTUNREACH`). The kernel emits this signal at
    // `connect()` time when the local routing table has no route
    // matching the destination *host* prefix (and the upstream
    // router returned ICMP-host-unreachable, or the local stack
    // synthesized the equivalent verdict). Distinct from
    // `syscall.ECONNREFUSED` (covered by `connection refused` above
    // — SYN reached the destination, the destination actively
    // replied RST) and from `syscall.ETIMEDOUT` (covered by `timed
    // out` below — SYN was sent and the retransmit budget elapsed
    // without ACK): here the SYN never leaves the local kernel
    // because no route matches the destination prefix. The
    // structural transient forge's pipeline trips on during BGP
    // withdraw / route-flap / VPN-tunnel renegotiation /
    // cluster-network policy reload — the local route disappears
    // for seconds, then reconverges. The network-scope sibling
    // `syscall.ENETUNREACH` / `"network is unreachable"` is the
    // mirror entry directly below. Across the dialects forge's
    // external CLIs emit:
    // - Go net (skopeo / regctl / attic-client through its golang
    //   surface, kubectl): `syscall.EHOSTUNREACH.Error()` formats
    //   lowercase as `"no route to host"`
    //   (`"dial tcp 10.0.0.1:443: connect: no route to host"`);
    // - curl (git-over-HTTPS, container-registry probes,
    //   healthcheck shells): emits capitalized
    //   `"No route to host"` from `CURLE_COULDNT_CONNECT` /
    //   `CURLE_INTERFACE_FAILED` (`"curl: (7) Failed to connect to
    //   ghcr.io port 443: No route to host"`);
    // - Java jvm (helm-cli's JNI shells, jvm-backed kubectl
    //   plugins): `java.net.NoRouteToHostException: No route to
    //   host`;
    // - Python (`urllib3.exceptions.NewConnectionError` /
    //   `socket.error`): `"OSError: [Errno 113] No route to host"`;
    // - hyper / reqwest (attic-client Rust surface): `std::io::Error`
    //   wrapping `io::ErrorKind::HostUnreachable` formats
    //   `"No route to host (os error 113)"`.
    // Both casings carried because Go's lowercase form and curl's
    // capitalized form coexist in forge's stderr corpus — the same
    // dual-case discipline `"Connection refused"` / `"connection
    // refused"` and `"broken pipe"` / `"Broken pipe"` already carry.
    // One marker per casing rather than a single bare-lowercase
    // because, unlike `"timed out"` whose past-tense suffix is
    // uniformly lowercase across emitters and whose leading-word
    // variance carries the case, the `"no route to host"` phrase
    // itself carries the leading-word case: Go's whole emission is
    // lowercase, curl's whole emission capitalizes the leading `N`.
    "no route to host",
    "No route to host",
    // Routing-layer kernel transient — network-scope sibling
    // (`syscall.ENETUNREACH`). The kernel emits this signal at
    // `connect()` time when the local routing table has no route
    // matching the destination *network* prefix at all — distinct
    // from `EHOSTUNREACH` directly above, which fires when the
    // *host* within an otherwise-reachable network is unreachable.
    // The two signals are sibling routing-layer transients with
    // distinct phrases the kernel chooses based on which prefix-
    // match step failed (host-row vs network-row); both reconverge
    // on the same BGP-withdraw / route-flap / VPN-tunnel
    // renegotiation / interface-toggle / cluster-network policy
    // reload events. `ENETUNREACH` is the more commonly emitted of
    // the pair when the failure is the local default-route going
    // away (VPN tunnel down, primary interface flap, kubelet
    // network plugin reconciling) — forge's pipeline trips on this
    // form during cluster reconcile windows where the local pod's
    // routing table loses its default route for seconds. Across
    // the dialects forge's external CLIs emit:
    // - Go net (skopeo / regctl / attic-client through its golang
    //   surface, kubectl): `syscall.ENETUNREACH.Error()` formats
    //   lowercase as `"network is unreachable"`
    //   (`"dial tcp 10.0.0.1:443: connect: network is unreachable"`,
    //   `"dial tcp: lookup ghcr.io: connect: network is unreachable"`);
    // - curl (git-over-HTTPS, container-registry probes,
    //   healthcheck shells): emits capitalized
    //   `"Network is unreachable"` from `CURLE_COULDNT_CONNECT`
    //   (`"curl: (7) Failed to connect to ghcr.io port 443:
    //   Network is unreachable"`);
    // - Java jvm (helm-cli's JNI shells, jvm-backed kubectl
    //   plugins): `java.net.SocketException: Network is
    //   unreachable`;
    // - Python (`urllib3.exceptions.NewConnectionError` /
    //   `socket.error`): `"OSError: [Errno 101] Network is
    //   unreachable"`;
    // - hyper / reqwest (attic-client Rust surface): `std::io::Error`
    //   wrapping `io::ErrorKind::NetworkUnreachable` formats
    //   `"Network is unreachable (os error 101)"`.
    // Both casings carried for the same reason `"no route to host"`
    // / `"No route to host"` carries both: Go's whole emission is
    // lowercase, curl's whole emission capitalizes the leading
    // `N` — the casing variance is on the leading phrase-word,
    // not a uniformly-lowercase suffix like `"timed out"`.
    "network is unreachable",
    "Network is unreachable",
    // I/O timeouts (Go net/http and TLS handshake variants).
    "i/o timeout",
    "TLS handshake timeout",
    "timeout",
    // Connect-side TCP retransmit-budget exhaustion — the structural
    // mirror of `broken pipe` (mid-stream WRITE drop) at the connect
    // phase. `syscall.ETIMEDOUT` formats as `"connection timed out"`,
    // curl emits `"Connection timed out"` / `"Operation timed out"` /
    // `"connect() timed out"` from `CURLE_OPERATION_TIMEDOUT`, Python
    // `socket.timeout` / `urllib3.exceptions.ConnectTimeoutError` and
    // Java `SocketTimeoutException` emit `"connect timed out"` /
    // `"timed out"`, hyper / reqwest forwards a `std::io::Error` whose
    // Display impl includes `"timed out"`. The bare phrase `"timed out"`
    // is NOT a substring of `"timeout"` (the letters are `t-i-m-e-d`
    // then a space then `o-u-t`, not the contiguous `t-i-m-e-o-u-t` the
    // `"timeout"` marker requires), so every dialect that emits the
    // past-tense form silently short-circuited to terminal before this
    // entry. forge's pipeline opens connections against GHCR / attic-
    // server / git-over-HTTPS on every push, so SYN-without-ACK
    // (kernel-level TCP retransmit budget exhausted, common during BGP
    // convergence, registry rollover, or slow-start backpressure) is
    // the more commonly emitted connect-side transient than the
    // explicit `"i/o timeout"` form already carried above. One marker
    // covers both Go's lowercase form and curl's capitalized form
    // because the casing variance is on the leading word
    // (`Connection` / `connection` / `Operation` / `connect`) — the
    // `"timed out"` suffix is uniformly lowercase across emitters.
    "timed out",
    // Go-context-layer timeout — `context.DeadlineExceeded.Error()`
    // formats as the bare phrase `"context deadline exceeded"`
    // verbatim. Distinct layer from the kernel-TCP transients above
    // (`syscall.ETIMEDOUT` / `"timed out"` — SYN-retransmit budget
    // exhausted at the connect phase, or read budget exhausted on an
    // established socket) and from the net/http I/O budget
    // (`"i/o timeout"` — `http.Client.Timeout` fires inside the
    // request loop): here a higher-level Go `context.WithTimeout` /
    // `context.WithDeadline` budget elapses while a downstream
    // operation is in flight, and the context-cancellation propagates
    // up through every `select` on `ctx.Done()` as the same
    // `context.DeadlineExceeded` sentinel. The bare phrase is NOT a
    // substring of `"timeout"` (the contiguous letters
    // `t-i-m-e-o-u-t` do not appear in `"context deadline exceeded"`)
    // nor of `"timed out"` (different word, `exceeded` vs `out`), so
    // every dialect that emits the Go-context-deadline form silently
    // short-circuited to terminal before this entry.
    //
    // forge's pipeline invokes kubectl / helm / skopeo / regctl /
    // attic-client extensively, every one of which uses
    // `context.WithTimeout` on its outer API call — kubectl's
    // `--request-timeout` flag, helm's `--timeout` flag, skopeo's
    // `--command-timeout`, attic-client's per-request context budget.
    // The production trigger is the kube-apiserver / helm-release-
    // controller / container-registry being slow to respond within
    // the per-request budget — typically during a kube control-plane
    // election, helm release-history compaction, registry-side blob
    // lookup against a cold object-store backend, or attic-server
    // under upload pressure — every one of which reconverges within
    // the existing retry-policy budget. The fix here is recognizing
    // the Go-context-deadline phrase the prior `"timed out"` /
    // `"timeout"` markers silently short-circuited to terminal at
    // every Go-context-fronted CLI surface.
    //
    // Across the dialects forge's external CLIs emit:
    // - Go net / context (skopeo, regctl, attic-client through its
    //   golang surface, kubectl, helm-cli): the bare
    //   `context.DeadlineExceeded.Error()` phrase verbatim —
    //   `"Get \"https://10.0.0.1:6443/api/v1/namespaces/foo/pods\":
    //   context deadline exceeded"`,
    //   `"Error from server (Timeout): context deadline exceeded"`,
    //   `"trying to reuse connection: context deadline exceeded"`,
    //   `"Error: query: failed to query with labels: context
    //   deadline exceeded"` (helm), `"writing blob: context
    //   deadline exceeded"` (skopeo);
    // - gRPC-Go (controller-runtime clients wrapping kube-apiserver
    //   long-poll watches): the bare phrase forwards through the
    //   gRPC status formatter — `"rpc error: code = DeadlineExceeded
    //   desc = context deadline exceeded"`.
    // One casing only — every Go emitter passes through the
    // `context` package's exact lowercase formatting; the phrase is
    // not a cross-tool variant the way `Connection refused` /
    // `connection refused` is split. The marker is also distinct
    // from the closely-related `"context canceled"` phrase
    // (`context.Canceled.Error()`) which is deliberately NOT added:
    // a cancelled context can be the user's CTRL+C (terminal) or a
    // parent context's deadline-firing (transient at one layer up
    // but already covered by the deadline-exceeded propagation when
    // the parent's deadline fires); leaving the ambiguous-form
    // signal out of the marker set keeps the unambiguous-phrase-only
    // discipline `"Temporary failure in name resolution"` /
    // `"connection closed before message completed"` carry.
    "context deadline exceeded",
    // Mid-stream TCP drops — multi-word Go form. The bare `EOF` acronym
    // (`io.EOF`) is matched token-wise via
    // [`TRANSIENT_NETWORK_STDERR_TOKEN_MARKERS`].
    "unexpected EOF",
    // Mid-stream TCP drop on WRITE — structural mirror of `unexpected EOF`
    // (READ side). `syscall.EPIPE` formats as the bare phrase `broken pipe`
    // across the dialects forge's external CLIs emit: Go net (`"write tcp
    // 10.0.0.1:443: broken pipe"`, skopeo/regctl/attic-server), curl with
    // OpenSSL (`"OpenSSL SSL_write: Broken pipe, errno 32"`, `"Send
    // failure: Broken pipe"`, git-over-HTTPS), and hyper/reqwest
    // (`std::io::Error` formatting `"Broken pipe"`, attic-client).
    // forge's upload-heavy pipeline (image push to GHCR, store-path push
    // to attic-server) emits this form more often than `unexpected EOF` —
    // upstream closes the TCP connection mid-upload. Both casings carried
    // because Go syscall.EPIPE.Error() emits lowercase while curl/hyper
    // emit capitalized — same dual-case discipline `"Connection refused"`
    // / `"connection refused"` carries.
    "broken pipe",
    "Broken pipe",
    // Mid-stream HTTP-framing READ drop — hyper's
    // `hyper::Error::IncompleteMessage` `Display` impl emits the bare
    // phrase `"connection closed before message completed"` verbatim.
    // Structural sibling of `unexpected EOF` (Go's `io.ErrUnexpectedEOF`
    // — TCP-level EOF mid-stream, the READ-side mirror at the Go-net
    // dialect) and of `broken pipe` (`syscall.EPIPE` — WRITE-side EPIPE,
    // the cross-dialect mirror at the kernel-TCP layer). The HTTP-
    // framing-layer distinction matters: here the TCP connection
    // carried partial HTTP-response bytes before the upstream sent FIN
    // (graceful close) or RST (`syscall.ECONNRESET`) without completing
    // the chunked-transfer-encoding terminator / `Content-Length` byte
    // budget hyper's response decoder requires — distinct from
    // `unexpected EOF` (Go's TCP-level signal at the same shape,
    // emitted by skopeo / regctl / kubectl / helm-cli's Go-net surface)
    // and from `Connection reset` / `connection reset` (already carried
    // above — the kernel-layer `ECONNRESET` signal hyper's underlying
    // socket also surfaces directly when the upstream sends RST before
    // any HTTP-response bytes return).
    //
    // forge's attic-push hot path runs the attic-client Rust surface
    // (`reqwest` → `hyper`) against attic-server over the cluster LB.
    // Production triggers: attic-server restart (helm rollout, pod
    // eviction), upstream LB rolling reconciliation (cluster ingress
    // reload, service-mesh sidecar restart), HTTP/2 GOAWAY frame from
    // upstream before forge's PUT body fully drained, or upstream
    // idle-connection eviction (server-side `Keep-Alive` timeout
    // expiring mid-stream while forge's request-body uploader is mid-
    // chunk). Every one is reconvergent within the existing retry-
    // policy budget; the fix here is recognizing the hyper-specific
    // phrase the prior `unexpected EOF` marker (Go-only) silently
    // short-circuited to terminal at the Rust dialect.
    //
    // Across the dialects forge's external CLIs emit:
    // - hyper / reqwest (the attic-client Rust surface): emits the bare
    //   phrase `"connection closed before message completed"` verbatim
    //   from `hyper::Error::IncompleteMessage`'s `Display`
    //   (`std::error::Error::source` chain — `"error sending request
    //   for url (https://attic.…/_api/v1/cache/…): connection closed
    //   before message completed"`);
    // - Rust async-stream wrappers (`tokio-stream`, `axum`-fronted
    //   probes, attic-fronted CDN probes whose Rust-side fetch wraps
    //   the same hyper error): forward the same `Display` substring
    //   through whatever request-error wrapper they layer on top.
    //
    // One casing only — every emitter passes through hyper's exact
    // lowercase formatting; the phrase is hyper-specific, not a
    // cross-tool variant the way `Connection refused` / `connection
    // refused` is split. The libcurl sibling at the zero-bytes-
    // received shape — `"Empty reply from server"` (`CURLE_GOT_NOTHING`,
    // error 52) — is the marker entry directly below; it covers the
    // distinct case where libcurl established the TCP+TLS connection,
    // sent the request, and the upstream closed with zero response
    // bytes (no HTTP response started). Hyper's partial-response signal
    // here and libcurl's zero-bytes signal below are sibling shapes at
    // different runtimes, both reconvergent within the existing retry-
    // policy budget.
    "connection closed before message completed",
    // libcurl zero-response-bytes transient — `CURLE_GOT_NOTHING`
    // (error 52). libcurl declares this in `lib/strerror.c` as
    // `"Empty reply from server"`, surfaced through every libcurl-
    // fronted CLI's response-error formatter (curl's `--fail` path,
    // git-over-HTTPS's `remote-curl` helper, helm-cli's OCI surface,
    // nix-prefetch-url's fetcher, every healthcheck shell). The error
    // fires after the SYN+SYN-ACK+ACK completed, the TLS handshake
    // completed, libcurl sent the HTTP request, and the upstream
    // closed the connection without writing any HTTP response bytes —
    // distinct from `CURLE_RECV_ERROR` (56) which fires on a TCP
    // error during read after some bytes returned. libcurl's
    // `lib/transfer.c` recognizes the zero-bytes-received case at a
    // higher layer than the generic recv-error path and emits this
    // structurally distinct phrase.
    //
    // Distinct from the prior markers already carried:
    // - `"connection closed before message completed"` (hyper's
    //   `IncompleteMessage`) — partial response received then drop;
    // - `"unexpected EOF"` (Go's `io.ErrUnexpectedEOF`) — partial
    //   response received then EOF at the Go-net dialect;
    // - `"broken pipe"` / `"Broken pipe"` (`syscall.EPIPE`) —
    //   WRITE-side drop at the kernel-TCP layer;
    // - `"Connection reset"` (`syscall.ECONNRESET`) — kernel-level
    //   RST during read.
    // All four cover *partial*-response shapes; `CURLE_GOT_NOTHING`
    // is the *zero*-response mirror at the libcurl dialect — the
    // upstream accepted the TCP+TLS handshake then closed without
    // any HTTP response. The retry semantics are SAFER than the
    // partial-response class: with zero application bytes
    // exchanged, retrying cannot cause a duplicate side-effect at
    // the application layer (the request never reached an upstream
    // handler that could have begun processing). Same RFC-grounded
    // safe-retry guarantee `REFUSED_STREAM` carries at the HTTP/2
    // stream layer, translated to the libcurl-HTTP/1.x layer.
    //
    // forge's pipeline invokes libcurl-fronted CLIs on every run:
    // git-over-HTTPS (`git push` / `git fetch` / `git ls-remote`
    // through `git-remote-https`, which links against libcurl) for
    // tag/version probes during release-all and for the source-of-
    // truth fetch against github.com, helm-cli's OCI surface
    // (`helm pull oci://`, `helm registry login`, `helm push`
    // against an OCI registry — helm-cli uses libcurl for the
    // HTTPS transport under `oras-go`'s fallback path), healthcheck
    // shells (curl-based readiness probes against GHCR / attic-
    // server before push), and nix-prefetch-url's tarball fetcher.
    // Production triggers: github.com frontend rolling deploy (the
    // GitHub frontend backend pool rebalances mid-handshake-
    // completion — the SYN+TLS handshake reaches a backend that's
    // about to drain, the backend sends FIN immediately on receipt
    // of the HTTP request without writing any response), GHCR edge-
    // tier rolling deploy (Azure Front Door's edge pool reconciles
    // mid-handshake during Microsoft's tenant rebalance windows),
    // attic-server ingress reloading (the nginx ingress drops the
    // in-flight connection at the same shape during configmap
    // reload — accept-then-close before any response bytes),
    // cluster ingress active-active failover (the active node fails
    // over to the passive node mid-stream; the new node has no
    // session state and immediately closes). Every one is
    // reconvergent within the existing retry-policy budget; the fix
    // here is recognizing the libcurl zero-bytes phrase the prior
    // partial-response markers (`unexpected EOF` Go-dialect,
    // `connection closed before message completed` hyper-dialect)
    // silently short-circuited to terminal at the libcurl dialect.
    //
    // Across the dialects forge's external CLIs emit:
    // - libcurl (`curl` CLI, `git-remote-https`, helm-cli's OCI
    //   surface, nix-prefetch-url, healthcheck shells): emits the
    //   bare phrase verbatim through `curl_easy_strerror(CURLE_
    //   GOT_NOTHING)` — `"curl: (52) Empty reply from server"`
    //   (curl CLI through `--fail`), `"fatal: unable to access
    //   'https://github.com/org/repo.git/': Empty reply from
    //   server"` (git-remote-https through curl's response-error
    //   chain), `"Error: failed to do request: Empty reply from
    //   server"` (helm OCI through oras-go's libcurl-fronted
    //   transport);
    // - git-over-HTTPS surfaces forge invokes directly (`forge`'s
    //   git-fetch / git-ls-remote paths through the `git2-rs` C-
    //   binding, which links against the system libcurl on Linux):
    //   forwards the phrase through `git2::Error::Display` —
    //   `"failed to send request: Empty reply from server; class=
    //   Net (12)"`;
    // - Python urllib3 / requests (helm-cli's plugin-shell escape
    //   hatches, runtime probe shells): emits `"requests.exceptions.
    //   ConnectionError: ('Connection aborted.', RemoteDisconnected(
    //   'Remote end closed connection without response'))"` — NOT
    //   the libcurl phrase verbatim, but the closely-adjacent
    //   `"Connection aborted"` marker already carried above covers
    //   the urllib3 dialect.
    //
    // One casing only — every emitter passes through libcurl's
    // exact `strerror` formatting (`"Empty reply from server"` with
    // title-case `E` and lowercase rest, declared at one site in
    // libcurl's `lib/strerror.c` static table). Requiring the full
    // phrase keeps the signal while dropping the substring-buried
    // false positives a bare `"Empty"` or `"server"` substring
    // would catch (e.g. a logger message describing an empty
    // manifest, a server-name diagnostic). The marker is also
    // distinct from the closely-adjacent libcurl phrases whose
    // retry semantics are NOT safe: `"Could not resolve host"`
    // (`CURLE_COULDNT_RESOLVE_HOST` 6 — covered as transient via
    // the `"Temporary failure in name resolution"` named-form
    // marker only when the resolver returned `EAI_AGAIN`; bare
    // `"Could not resolve host"` without the `"Temporary"` prefix
    // is the permanent NXDOMAIN verdict and stays terminal),
    // `"SSL certificate problem"` (`CURLE_SSL_CACERT` 60 — terminal
    // TLS-config issue), `"The requested URL returned error: 404"`
    // (`CURLE_HTTP_RETURNED_ERROR` 22 on a permanent 4xx — terminal).
    "Empty reply from server",
    // Git-protocol mid-stream transport drop — `git` emits the bare
    // phrase `"the remote end hung up unexpectedly"` from
    // `pkt-line.c::packet_read` (the side-band-demultiplexing read
    // loop) when the remote closes the pack-protocol stream before
    // sending the expected pack-protocol terminator. Every git
    // transport forwards the same phrase — git-over-HTTPS through
    // `git-remote-https` (the TCP socket closes mid-pack-write before
    // libcurl can frame an HTTP-status error above), git-over-SSH
    // through `git-remote-ssh` (the SSH channel closes mid-pack-write),
    // git-over-git:// through `git-daemon` — because the upstream
    // caller is git's own `pkt-line.c`, not the transport.
    //
    // Distinct layer from the partial-response markers already carried:
    // - `"Empty reply from server"` (libcurl `CURLE_GOT_NOTHING` 52) —
    //   fires when libcurl established the TCP+TLS connection, sent
    //   the HTTP request, and the upstream closed WITHOUT writing any
    //   HTTP response bytes (HTTP-layer zero-bytes shape, the marker
    //   directly above); the git pkt-line drop fires AFTER the HTTP
    //   response started, mid-pack-stream — the pack bytes were
    //   arriving then the socket closed before the pack-protocol
    //   terminator;
    // - `"connection closed before message completed"` (hyper
    //   `IncompleteMessage`) — partial-HTTP-response drop at the Rust
    //   `hyper` layer; git doesn't use hyper, it uses libcurl + its
    //   own pack-protocol layer above HTTP, so the same shape
    //   surfaces here as the pkt-line phrase instead;
    // - `"unexpected EOF"` (Go's `io.ErrUnexpectedEOF`) — Go-net
    //   dialect partial-response drop; git is C, not Go;
    // - `"broken pipe"` / `"Broken pipe"` (`syscall.EPIPE`) — kernel-
    //   layer WRITE-side drop; the pkt-line phrase is the higher-
    //   layer git-protocol diagnostic that fires when the READ side
    //   of the pack-stream hangs up mid-frame.
    // All four cover non-git-protocol shapes; `"the remote end hung
    // up unexpectedly"` is the git-protocol-specific marker at the
    // pack-stream-receipt layer.
    //
    // forge's pipeline invokes git on every release-all and deploy
    // run — `git fetch` / `git push` / `git ls-remote` against
    // github.com for the source-of-truth pull and the GitOps-manifest
    // commit-push, plus the `git2-rs`-fronted operations forge runs
    // through its `git` module. Production triggers: the github.com
    // frontend backend pool rebalances mid-pack-write (the SYN+TLS
    // handshake reached a backend about to drain, the backend started
    // sending pack bytes then sent FIN before the pack-protocol
    // terminator), a cluster-internal Gitea / forgejo upstream
    // restarts mid-`git push` during helm rollout, the SSH connection's
    // TCP socket closes during BGP/routing reconvergence on the
    // GitHub edge, or a corporate proxy / firewall drops idle git-
    // over-HTTPS connections at its connection-pool timeout mid-pack-
    // receipt. Every one is reconvergent within the existing retry-
    // policy budget; the fix here is recognizing git's own pack-
    // protocol drop phrase the prior libcurl/hyper/Go-net partial-
    // response markers do not cover — git's pkt-line.c emits this
    // phrase at a layer ABOVE the transport, after the HTTP response
    // or SSH channel began sending pack bytes, and the transport-
    // layer markers above all fire on conditions distinct from the
    // pack-stream-mid-frame drop.
    //
    // Across the dialects forge's external CLIs emit:
    // - git-over-HTTPS (`git push` / `git fetch` / `git ls-remote`
    //   through `git-remote-https`): the bare phrase wrapped in
    //   git's typical multi-line error chain — `"error: RPC failed;
    //   HTTP 502 curl 22 The requested URL returned error: 502\n
    //   fatal: the remote end hung up unexpectedly"` (the HTTP-error
    //   variant where libcurl framed an HTTP-status error before the
    //   pack-stream drop) and `"fatal: the remote end hung up
    //   unexpectedly\nfatal: protocol error: bad pack header"` (the
    //   bare TCP-drop variant where no HTTP-status error preceded);
    // - git-over-SSH (`git push` / `git fetch` through `git-remote-
    //   ssh`): the bare phrase wrapped through git's pkt-line.c —
    //   `"Connection to ssh.github.com closed by remote host.\n
    //   fatal: the remote end hung up unexpectedly"`;
    // - git2-rs (forge's `git2`-fronted operations through the C-
    //   binding linking against the system libcurl on Linux): the
    //   phrase forwards through `git2::Error::Display`'s `class=Net`
    //   decoration — `"the remote end hung up unexpectedly;
    //   class=Net (12)"`;
    // - git's index-pack subprocess error chain: `"fatal: the
    //   remote end hung up unexpectedly\nfatal: index-pack failed"`
    //   (the bare-EOF early diagnostic when present is captured
    //   token-wise by the `"EOF"` token marker; the pkt-line phrase
    //   covers the cases where index-pack does not emit the bare-
    //   EOF line because the drop happened before any pack bytes
    //   arrived to index).
    //
    // One casing only — git's `pkt-line.c` emits the phrase with the
    // exact lowercase-articles casing (`"the remote end hung up
    // unexpectedly"`) and every transport forwards through the same
    // formatter, so no cross-dialect casing variance. Requiring the
    // multi-word phrase keeps the signal while dropping the substring-
    // buried false positives a bare `"hung up"` substring would catch
    // (the verb form is too generic — a TCP-state diagnostic, an SSH
    // disconnect message that is NOT the git-protocol drop, an
    // unrelated subsystem's metaphor in a log line). The marker is
    // also distinct from terminal git failures whose retry semantics
    // are NOT safe: `"fatal: Authentication failed"` (terminal auth
    // verdict — bad credential, not reconvergent), `"fatal: repository
    // '…' not found"` (terminal NXDOMAIN-equivalent at the git-
    // namespace layer), `"error: failed to push some refs"` followed
    // by `"non-fast-forward"` (terminal merge-conflict verdict — the
    // remote rejected the push for a reason retrying cannot resolve).
    // The pkt-line-drop phrase is the one git-protocol diagnostic the
    // protocol itself classifies as a transport-state signal rather
    // than a content-or-auth verdict, so it is the load-bearing
    // safe-retry marker at the git-protocol layer.
    "the remote end hung up unexpectedly",
    // DNS-resolver transient — `getaddrinfo(3)` `EAI_AGAIN` (glibc -3).
    // Distinct layer from the kernel-routing transients above
    // (`syscall.ENETUNREACH` / `EHOSTUNREACH`) and from the TCP-state
    // transients (`ECONNREFUSED` / `ECONNRESET` / `ETIMEDOUT`): here the
    // resolver upstream (typically cluster coredns / glibc's nss-dns
    // over the configured `/etc/resolv.conf` nameserver list) fails to
    // return a verdict within the resolver-side budget — distinct from
    // `EAI_NONAME` (NXDOMAIN: a permanent verdict from the resolver that
    // no record exists) and from `EAI_NODATA` (the name exists but no
    // matching record-type). `EAI_AGAIN`'s leading `"Temporary"` word
    // carries the transient verdict on its face; the production trigger
    // for forge's pipeline is cluster coredns reloading its corefile
    // (kubectl apply on the coredns configmap, node-local-dns
    // reconciliation, or upstream resolver flap) — the resolver returns
    // transient-fail within seconds, then reconverges. Across the
    // dialects forge's external CLIs emit:
    // - glibc strerror surface (every curl/skopeo/regctl/attic-client/
    //   kubectl/helm-cli/git on standard distros): emits the bare
    //   `gai_strerror(EAI_AGAIN)` phrase
    //   `"Temporary failure in name resolution"` verbatim;
    // - Go net (skopeo, regctl, attic-client through its golang
    //   surface, kubectl, helm-cli's discovery shells): the resolver
    //   wraps the strerror through the `net.DNSError` formatter — e.g.
    //   `"lookup ghcr.io on 169.254.169.254:53: Temporary failure in
    //   name resolution"`;
    // - curl (git-over-HTTPS, container-registry probes, healthcheck
    //   shells): forwards the strerror through `CURLE_COULDNT_RESOLVE_
    //   HOST` — `"curl: (6) Could not resolve host: ghcr.io: Temporary
    //   failure in name resolution"`;
    // - Python (`socket.gaierror` raised by `urllib3` / `requests` /
    //   `httpx` / the runtime probe shells): emits `"[Errno -3]
    //   Temporary failure in name resolution"`;
    // - hyper / reqwest (attic-client Rust surface): the resolver
    //   forwards a `std::io::Error` whose Display impl includes the
    //   same `"Temporary failure in name resolution"` substring.
    // One casing only — every emitter passes through glibc's strerror
    // verbatim, which capitalizes only the leading `T`. The marker set
    // deliberately does NOT include the `EAI_NONAME` phrase
    // `"Name or service not known"` (a permanent NXDOMAIN verdict from
    // the resolver) — retrying a deterministic-deny would burn budget
    // against a permanent resolver verdict; `EAI_AGAIN`'s `"Temporary"`
    // prefix is what makes this phrase unambiguously retryable.
    "Temporary failure in name resolution",
    // HTTP/2 graceful-shutdown transient — `golang.org/x/net/http2`
    // emits `"http2: server sent GOAWAY and closed the connection;
    // LastStreamID=…, ErrCode=NO_ERROR, debug=\"…\""` verbatim
    // (`http2/transport.go`'s `(*ClientConn).readLoop` propagating
    // `http2.GoAwayError` up through `Transport.RoundTrip`). Distinct
    // layer from the kernel-TCP transients (`syscall.ETIMEDOUT` /
    // `"timed out"`, `syscall.ECONNREFUSED` / `"connection refused"`),
    // from the HTTP/1-framing transient (hyper's
    // `"connection closed before message completed"` — the Rust-
    // dialect mirror at the HTTP/1.1 layer one phrase above), and from
    // the Go-context-layer transient (`context.DeadlineExceeded` /
    // `"context deadline exceeded"`): here the upstream HTTP/2 peer
    // signals graceful shutdown by sending a GOAWAY frame BEFORE
    // closing the TCP connection, per RFC 9113 §6.8 — the explicit
    // "you may safely retry on a new connection" signal in HTTP/2.
    // RFC 9113 §6.8 names the contract: a GOAWAY frame with
    // `ErrCode=NO_ERROR` is a SOFT signal that the upstream is
    // draining (rolling restart, scale-down, load-balancer
    // reconciliation) and the client SHOULD retry pending requests on
    // a fresh connection; an `ErrCode=PROTOCOL_ERROR` GOAWAY is a hard
    // signal that the client misbehaved (terminal), but the Go
    // formatter emits BOTH through the same `"http2: server sent
    // GOAWAY"` prefix and the dominant production class against
    // kube-apiserver / GHCR / attic-server upstreams is the
    // `NO_ERROR` rolling-shutdown shape — the hard-error case is
    // already covered by the per-error-code branch of the typed
    // retry-policy classifier above and is rare in forge's pipeline.
    //
    // forge's pipeline invokes the four Go-net/http2-fronted CLIs
    // — kubectl, helm-cli, skopeo, regctl — extensively against the
    // three HTTP/2-capable upstreams it depends on: the kube-apiserver
    // (HTTP/2-by-default since k8s 1.20), GHCR (HTTP/2 for OCI manifest
    // and blob endpoints), and attic-server (HTTP/2 when fronted by a
    // cluster ingress with HTTP/2 upstream). Production triggers: kube-
    // apiserver rolling restart (apiserver pod deletion during control-
    // plane upgrade, watch-cache compaction sending GOAWAY to drain
    // long-poll clients), GHCR backend rotation (Microsoft's GHCR
    // edge tier sends GOAWAY periodically to rebalance HTTP/2 streams
    // across backend pools), attic-server scale-up / helm-rollout
    // (HPA decisions during burst pressure trigger GOAWAY from the
    // pod being scaled down). Every one of these is reconvergent
    // within the existing retry-policy budget; the fix here is
    // recognizing the Go net/http2 GOAWAY phrase the prior `"timed
    // out"` / `"unexpected EOF"` / `"connection closed before message
    // completed"` markers silently short-circuited to terminal at the
    // Go-net/http2 dialect — Go's HTTP/2 client distinguishes GOAWAY
    // (a structured frame the server sent before closing) from the
    // raw TCP-EOF the prior markers cover, and forwards the GOAWAY
    // through its own typed error class with the distinctive phrase
    // above.
    //
    // Across the dialects forge's external CLIs emit:
    // - Go net/http2 (kubectl, helm-cli's HTTPS surface, skopeo,
    //   regctl, attic-client through its golang surface): `http2.
    //   GoAwayError.Error()` formats the prefix `"http2: server sent
    //   GOAWAY"` verbatim — `"http2: server sent GOAWAY and closed
    //   the connection; LastStreamID=137, ErrCode=NO_ERROR, debug=\"\""`,
    //   `"Get \"https://kube-apiserver/api/v1/pods\": http2: server
    //   sent GOAWAY and closed the connection; LastStreamID=33,
    //   ErrCode=NO_ERROR, debug=\"\""`, `"writing blob: http2: server
    //   sent GOAWAY and closed the connection; LastStreamID=5,
    //   ErrCode=NO_ERROR, debug=\"\""` (skopeo);
    // - gRPC-Go (controller-runtime watch clients wrapping kube-
    //   apiserver long-polls — surfaces transitively through helm-cli's
    //   release-status surface): forwards the GOAWAY through the gRPC
    //   status formatter — `"rpc error: code = Unavailable desc =
    //   transport is closing; http2: server sent GOAWAY and closed
    //   the connection; LastStreamID=…, ErrCode=NO_ERROR, debug=\"\""`.
    // The hyper / reqwest Rust dialect (attic-client Rust surface)
    // does NOT use this exact phrase — hyper's `h2`-backed transport
    // surfaces GOAWAY as either `"connection closed before message
    // completed"` (already carried above as the HTTP/1-framing mirror
    // marker — `hyper::Error::IncompleteMessage` covers the
    // mid-stream-drop shape regardless of frame type) or as a
    // GOAWAY-specific `"received unexpected GOAWAY"` whose
    // distinctive substring is left for a future marker if forge's
    // attic-client surface starts emitting it under the production
    // corpus.
    //
    // One casing only — every Go emitter passes through `http2.
    // GoAwayError`'s exact lowercase formatting (the `"http2:"`
    // package prefix is uniformly lowercase, the `"GOAWAY"` token is
    // the RFC-defined uppercase frame-name, the `"server"` /
    // `"sent"` middle words are uniformly lowercase). The marker is
    // distinct from the bare `"GOAWAY"` token a downstream proxy
    // configuration / k8s manifest comment might carry — requiring
    // the multi-word phrase `"http2: server sent GOAWAY"` keeps the
    // signal while dropping the substring-buried false positives an
    // unqualified `"GOAWAY"` substring would catch (the same
    // discipline `"unexpected EOF"` carries over the bare `"EOF"`
    // token — covered substring-wise here, token-wise via
    // [`TRANSIENT_NETWORK_STDERR_TOKEN_MARKERS`] for the bare form).
    // The marker is also distinct from a `PROTOCOL_ERROR` /
    // `INTERNAL_ERROR` GOAWAY whose `ErrCode` field signals a hard
    // failure rather than a graceful drain — those rare shapes
    // would benefit from a future per-ErrCode classifier; the
    // dominant `NO_ERROR` shape that drives forge's GOAWAY
    // production corpus is unambiguously transient and the
    // `"http2: server sent GOAWAY"` prefix is the load-bearing
    // substring across every `ErrCode` variant.
    "http2: server sent GOAWAY",
    // HTTP/2 client-side connection-lost transient — the client-
    // side mirror of the server-initiated `http2: server sent
    // GOAWAY` drain signal directly above. `golang.org/x/net/http2`
    // declares `errClientConnLost = errors.New("http2: client
    // connection lost")` in `transport.go`, propagated by
    // `(*ClientConn).RoundTrip` and `(*clientStream).awaitFlowControl`
    // when the underlying TCP transport detects the connection is
    // dead without the upstream having sent a structured GOAWAY
    // frame first — typical when an upstream pod is killed (SIGKILL
    // / OOM / node-eviction) or a cluster-network policy reconcile
    // tears down the established HTTP/2 connection before the
    // server's draining handler can run. Distinct from
    // `"http2: server sent GOAWAY"` (graceful server-initiated
    // shutdown via RFC 9113 §6.8 frame — the prior marker), from
    // `"connection closed before message completed"` (hyper's
    // HTTP/1-framing dialect — a different runtime), from
    // `"unexpected EOF"` (Go-net TCP-level EOF — the layer below
    // HTTP/2, fires when the read syscall returns 0 bytes without
    // any HTTP/2-layer signal), and from `"broken pipe"`
    // (`syscall.EPIPE` — kernel-level WRITE-side drop, the layer
    // below HTTP/2 for the upload direction).
    //
    // forge's pipeline invokes the four Go-net/http2-fronted CLIs
    // — kubectl, helm-cli, skopeo, regctl — extensively against the
    // three HTTP/2-capable upstreams it depends on: kube-apiserver
    // (HTTP/2-by-default since k8s 1.20), GHCR (HTTP/2 for OCI
    // manifest and blob endpoints), and attic-server (HTTP/2 when
    // fronted by a cluster ingress with HTTP/2 upstream).
    // Production triggers: kube-apiserver pod SIGKILL during
    // forced control-plane upgrade (the apiserver process dies
    // before its graceful-shutdown handler can send GOAWAY),
    // node-eviction of the GHCR / attic-server pod (kubelet sends
    // SIGTERM but the pod's graceful-stop hook misses the in-flight
    // HTTP/2 connection), cluster-network-policy reconcile dropping
    // an established HTTP/2 connection (calico / cilium iptables
    // rules updating mid-stream), or HTTP/2 keep-alive ping timeout
    // (the client's `ClientConn.healthCheck` fires when its
    // periodic PING frame goes unanswered past the read deadline).
    // Every one is reconvergent within the existing retry-policy
    // budget; the fix here is recognizing the client-side lost-
    // connection phrase the prior `"http2: server sent GOAWAY"`
    // marker (server-side initiated) does not cover — the GOAWAY
    // phrase requires the upstream to have sent a structured frame,
    // but the abrupt-pod-kill / network-policy-flap class drops
    // the connection without any HTTP/2 frame and surfaces through
    // Go's own typed `errClientConnLost` instead.
    //
    // Across the dialects forge's external CLIs emit:
    // - Go net/http2 (kubectl, helm-cli's HTTPS surface, skopeo,
    //   regctl, attic-client through its golang surface):
    //   `errClientConnLost.Error()` formats the bare phrase
    //   `"http2: client connection lost"` verbatim, wrapped through
    //   `Transport.RoundTrip`'s error chain — `"Get
    //   \"https://kube-apiserver/api/v1/pods\": http2: client
    //   connection lost"`, `"writing blob: http2: client connection
    //   lost"` (skopeo), `"Error: query: failed to query with
    //   labels: http2: client connection lost"` (helm-cli);
    // - gRPC-Go (controller-runtime watch clients): forwards the
    //   phrase through the gRPC status formatter — `"rpc error:
    //   code = Unavailable desc = transport is closing; http2:
    //   client connection lost"`.
    // The hyper / reqwest Rust dialect (attic-client Rust surface)
    // does NOT use this exact phrase — hyper's `h2`-backed transport
    // surfaces the same shape as `"connection closed before message
    // completed"` (already carried above as the HTTP/1-framing
    // mirror) or as the bare-EOF token via
    // [`TRANSIENT_NETWORK_STDERR_TOKEN_MARKERS`].
    //
    // One casing only — every Go emitter passes through the
    // `errClientConnLost` sentinel's exact lowercase formatting
    // (the `"http2:"` package prefix is uniformly lowercase, the
    // body `"client connection lost"` is uniformly lowercase).
    // The marker is also distinct from the bare phrase
    // `"connection lost"` an unrelated diagnostic might carry
    // (e.g. a VPN-client log, a kube event message) — requiring
    // the `"http2:"` package prefix keeps the signal while
    // dropping the substring-buried false positives a bare
    // `"connection lost"` substring would catch.
    "http2: client connection lost",
    // Go-net stdlib `net.ErrClosed` — local-side connection-close
    // race transient. The standard library declares
    // `var ErrClosed error = errClosed` (alias for the private
    // `errClosed = errors.New("use of closed network connection")`
    // in `src/net/net.go`) since Go 1.16, returned by `(*conn).Read`
    // / `(*conn).Write` / `(*TCPConn).CloseRead` / `(*Listener).
    // Accept` after `Close` has been called on the underlying
    // file descriptor.
    //
    // Distinct from the four remote-initiated Go-net connection-
    // loss markers already carried:
    // - `"http2: server sent GOAWAY"` — the remote peer sent
    //   the RFC 9113 §6.8 graceful-shutdown frame BEFORE
    //   closing;
    // - `"http2: client connection lost"` — the Go-net/http2
    //   client detected the underlying TCP transport is dead
    //   without an upstream GOAWAY frame (abrupt remote loss);
    // - `"Connection reset"` / `"connection refused"` —
    //   kernel-level remote-side RST / refusal at TCP layer;
    // - `"broken pipe"` / `"Broken pipe"` / `"unexpected EOF"`
    //   — kernel-level TCP drop mid-stream initiated by the
    //   remote (EPIPE on the WRITE side, EOF on the READ side).
    // All five cover *remote*-initiated connection-loss shapes;
    // `net.ErrClosed` is the LOCAL-initiated mirror: another
    // goroutine in THIS process (the parent's `context.WithCancel`
    // cleanup running on cancellation, a `defer transport.Close
    // IdleConnections()` in a graceful-stop handler, an HTTP/2
    // transport's `connsByKey` sweep evicting an idle connection,
    // a sibling worker's `(*Listener).Close` on shared accept-
    // loop teardown) closed the file descriptor before this
    // goroutine's read/write reached it. The retry semantics
    // are identical to the remote-loss class: the next attempt
    // allocates a fresh connection.
    //
    // forge's pipeline trips on this shape during context-
    // cancellation races against the same Go-net/http2-fronted
    // CLIs the prior client-loss / GOAWAY markers cover: kubectl's
    // `--request-timeout` budget fires, the typed retry loop
    // dispatches a fresh attempt, but a stale watch-goroutine
    // from the prior attempt hits `net.ErrClosed` as the parent
    // `context.WithTimeout`'s cleanup tore down the shared
    // transport mid-read. Same shape during concurrent blob-
    // upload in skopeo / regctl when a per-blob goroutine's
    // context is cancelled while the underlying HTTP/2 transport
    // is being reset by a sibling goroutine's connection-pool
    // sweep. Same shape during attic-client's parallel store-
    // path push against attic-server fronted by a cluster ingress
    // — the shared transport's idle-connection sweep closes the
    // connection mid-flight on a stale goroutine when the ingress
    // reconciles its HTTP/2 backend during a rolling restart.
    // Every one is reconvergent within the existing retry-policy
    // budget; the fix here is recognizing the local-close phrase
    // the prior remote-initiated markers do not cover — the
    // `errClosed` sentinel fires when local cleanup beat the
    // in-flight read/write to the file descriptor, not when the
    // remote sent a GOAWAY / RST / EOF, so the Go-net error
    // chain forwards a structurally distinct phrase.
    //
    // Across the dialects forge's external CLIs emit:
    // - Go net (skopeo, regctl, attic-client through its golang
    //   surface, kubectl, helm-cli's discovery shells):
    //   `net.ErrClosed.Error()` formats the bare phrase
    //   `"use of closed network connection"` verbatim, wrapped
    //   through `Transport.RoundTrip`'s error chain — `"Get
    //   \"https://10.0.0.1:6443/api/v1/watch/pods\": use of
    //   closed network connection"`, `"writing blob: use of
    //   closed network connection"` (skopeo), `"Error: query:
    //   failed to query with labels: use of closed network
    //   connection"` (helm-cli);
    // - gRPC-Go (controller-runtime watch clients wrapping
    //   kube-apiserver long-polls): forwards the phrase through
    //   the gRPC status formatter — `"rpc error: code =
    //   Unavailable desc = transport is closing; use of closed
    //   network connection"`.
    // The hyper / reqwest Rust dialect (attic-client Rust
    // surface) does NOT use this exact phrase — hyper surfaces
    // the local-close shape as `"connection closed before
    // message completed"` (already carried above as the HTTP/1-
    // framing mirror) or as Tokio's `io::ErrorKind::NotConnected`
    // / `io::ErrorKind::BrokenPipe` (already carried as
    // `"broken pipe"` / `"Broken pipe"` above for the kernel-
    // EPIPE shape).
    //
    // One casing only — every Go emitter passes through the
    // `errClosed` sentinel's exact lowercase formatting (the
    // entire phrase `"use of closed network connection"` is
    // uniformly lowercase). Requiring the leading `"use of "`
    // qualifier keeps the signal while dropping the substring-
    // buried false positives a bare `"closed network connection"`
    // or `"closed network"` substring would catch (e.g. a
    // CNI / VPN-tunnel reconciliation log line, a kube event
    // describing a closed-network-policy reconcile, an unrelated
    // subsystem's diagnostic).
    "use of closed network connection",
    // HTTP/2 stream-level explicit-retry signal — RFC 9113 §6.4
    // `REFUSED_STREAM` (ErrCode 0x7). The RFC names the contract
    // verbatim: "The REFUSED_STREAM error code can be included in
    // a RST_STREAM frame to indicate that the stream is being
    // closed prior to any processing having occurred. Any request
    // that was sent on the reset stream can be safely retried."
    // This is THE canonical safe-retry signal in HTTP/2 — the
    // upstream is explicitly telling the client "no application
    // processing happened, retry me on a new stream / new
    // connection". Distinct layer from the prior HTTP/2 markers
    // already carried:
    // - `"http2: server sent GOAWAY"` — CONNECTION-level signal:
    //   the upstream is draining the whole HTTP/2 connection;
    // - `"http2: client connection lost"` — TRANSPORT-level signal:
    //   Go-net/http2 detected the underlying TCP transport is dead
    //   without an upstream GOAWAY frame.
    // `REFUSED_STREAM` is the STREAM-level signal: the connection
    // is healthy, but THIS specific stream was refused (typically
    // because the upstream's per-connection concurrent-stream
    // budget — `SETTINGS_MAX_CONCURRENT_STREAMS`, RFC 9113 §6.5.2
    // — was hit, or because the upstream's worker pool was
    // exhausted at request-receipt time, or because a backend-
    // affinity hash routed the stream to a pod being scaled down
    // before any handler ran). The structural retry semantics are
    // strictly safer than the GOAWAY case: GOAWAY requires the
    // retry to allocate a fresh CONNECTION (the old one is
    // draining); REFUSED_STREAM only requires a fresh STREAM
    // (the existing connection is still healthy and the client's
    // HTTP/2 transport can immediately open a new stream against
    // the same multiplexed socket). The RFC's "safely retried"
    // language is the load-bearing pin: this is the one HTTP/2
    // ErrCode the spec itself classifies as unconditionally
    // idempotent at the protocol layer, regardless of the
    // request's own idempotency — because no application
    // processing happened, retrying cannot cause a duplicate
    // side-effect.
    //
    // forge's pipeline invokes the four Go-net/http2-fronted CLIs
    // — kubectl, helm-cli, skopeo, regctl — extensively against the
    // three HTTP/2-capable upstreams it depends on: kube-apiserver
    // (HTTP/2-by-default since k8s 1.20, with per-connection
    // `MaxConcurrentStreams` budget kube-apiserver advertises via
    // SETTINGS frame), GHCR (HTTP/2 for OCI manifest and blob
    // endpoints, with edge-tier per-connection stream budgets
    // Microsoft tunes for fair-share across tenants), and attic-
    // server (HTTP/2 when fronted by a cluster ingress that
    // multiplexes streams across an upstream h2 backend pool).
    // Production triggers: kube-apiserver under burst load during
    // mass-watch reconciliation (hundreds of controller-runtime
    // watches reconverging after a node-add reattaches CSI / CNI),
    // GHCR concurrent-blob-upload bursting past the per-connection
    // stream budget during a multi-platform image push (skopeo's
    // parallel-blob-upload writer opens N concurrent streams,
    // GHCR's edge tier RST_STREAMs the (N+1)th with REFUSED_STREAM),
    // attic-server ingress receiving REFUSED_STREAM from its
    // upstream h2 backend during HPA scale-down (the pod about to
    // be terminated refuses new streams to its draining handler
    // pool before the SIGTERM-driven GOAWAY drain completes).
    // Every one is reconvergent within the existing retry-policy
    // budget — the next attempt opens a fresh stream against the
    // healthy connection (or, if the connection is also draining,
    // against a fresh connection via the GOAWAY path) — and the
    // RFC explicitly guarantees the retry is safe at the protocol
    // layer.
    //
    // Across the dialects forge's external CLIs emit:
    // - Go net/http2 (kubectl, helm-cli's HTTPS surface, skopeo,
    //   regctl, attic-client through its golang surface):
    //   `http2.ErrCodeRefusedStream.String()` formats as
    //   `"REFUSED_STREAM"` verbatim, wrapped through
    //   `http2.StreamError.Error()` as `"stream error: stream ID
    //   %d; REFUSED_STREAM"` and forwarded through
    //   `Transport.RoundTrip`'s error chain — `"Get
    //   \"https://kube-apiserver/api/v1/pods\": stream error:
    //   stream ID 137; REFUSED_STREAM"`, `"writing blob: stream
    //   error: stream ID 5; REFUSED_STREAM"` (skopeo), `"Error:
    //   query: failed to query with labels: stream error: stream
    //   ID 33; REFUSED_STREAM"` (helm-cli);
    // - gRPC-Go (controller-runtime watch clients wrapping
    //   kube-apiserver long-polls — the dominant production
    //   surface for stream-pool exhaustion since each watch holds
    //   a stream for the watch's lifetime): forwards the phrase
    //   through the gRPC status formatter — `"rpc error: code =
    //   Unavailable desc = stream error: stream ID 25;
    //   REFUSED_STREAM"`;
    // - hyper / reqwest / h2 (attic-client Rust surface): h2's
    //   `h2::Error::reason()` returns `h2::Reason::REFUSED_STREAM`,
    //   which formats through the `Display` impl as
    //   `"REFUSED_STREAM"` verbatim, wrapped through reqwest's
    //   request-error chain — `"error sending request for url
    //   (https://attic.…/_api/v1/cache/…): connection error:
    //   REFUSED_STREAM"`.
    //
    // One casing only — the ErrCode name is RFC-defined uppercase
    // (`REFUSED_STREAM` per RFC 9113 §7) and every emitter passes
    // through the same uppercase formatting (Go's
    // `ErrCode.String()`, h2's `Reason::Display`, gRPC-Go's status-
    // formatter pass-through). The marker is the bare RFC token
    // because no unrelated diagnostic in forge's stderr corpus
    // spells `REFUSED_STREAM` — the underscore-separated
    // all-uppercase token is uniquely an HTTP/2 frame-error name,
    // distinct from every English-word diagnostic and from the
    // adjacent ErrCode names whose retry semantics are NOT safe
    // (`INTERNAL_ERROR` ErrCode 0x2 — could be an upstream bug
    // class, not RFC-classified as safe-retry; `PROTOCOL_ERROR`
    // ErrCode 0x1 — the client misbehaved, terminal; `CANCEL`
    // ErrCode 0x8 — request explicitly cancelled, terminal at
    // this surface). Deliberately matching ONLY `REFUSED_STREAM`,
    // not the broader `"stream error"` prefix, keeps the strict
    // RFC-9113-§6.4 contract: only the one ErrCode the spec
    // itself names as safe-retry is classified transient. Future
    // commits may extend per-ErrCode coverage if a less-strict
    // signal proves load-bearing under production telemetry, but
    // the conservative discipline here matches the GOAWAY-marker
    // commit's deferral of `INTERNAL_ERROR` / `PROTOCOL_ERROR`
    // GOAWAY shapes.
    "REFUSED_STREAM",
    // Go net/http `(*Client).Timeout` budget exhaustion — the bare
    // phrase `"Client.Timeout exceeded"` is emitted by `net/http/
    // client.go`'s deadline-firing path verbatim. The full Go error
    // chain forms as `"Get \"<url>\": net/http: request canceled
    // (Client.Timeout exceeded while awaiting headers)"` (the
    // dominant production case — timeout fires while the client is
    // waiting for the server's HEADERS frame) or `"…(Client.Timeout
    // exceeded while reading body)"` (timeout fires mid-body-read on
    // an established response stream). Distinct layer from every
    // prior timeout marker already carried:
    // - `"context deadline exceeded"` (`context.DeadlineExceeded` —
    //   Go-context-layer budget, fires on `ctx.WithTimeout` /
    //   `ctx.WithDeadline`, the higher-level cancellation propagates
    //   through every `select` on `ctx.Done()`);
    // - `"i/o timeout"` (Go-net `net.OpError`'s `net.Error.Timeout()`
    //   surface — socket-layer read/write budget exhaustion at the
    //   `(*conn).Read` / `(*conn).Write` boundary);
    // - `"TLS handshake timeout"` (Go-net `tls.Conn.Handshake`'s
    //   per-handshake budget — fires before any HTTP request bytes
    //   reach the wire);
    // - `"timeout"` (generic substring catch — but case-sensitive
    //   `.contains()` means `"Client.Timeout"` with capital `T` does
    //   NOT match the lowercase `"timeout"` substring; this is the
    //   silent-short-circuit shape the marker here closes);
    // - `"timed out"` (kernel `syscall.ETIMEDOUT` — SYN-retransmit
    //   budget at the connect phase);
    // - `"Request Timeout"` (HTTP 408 named form — server's response
    //   status, distinct from a client-side budget elapsing).
    // `Client.Timeout` is the `http.Client` struct field's named
    // budget — a higher-level deadline than `context.WithTimeout`
    // (which is a context-layer cancellation that the client honors
    // via `req.WithContext`) and structurally distinct from the
    // socket-layer `i/o timeout`. Go's `net/http` library formats
    // the budget-elapsed verdict through `client.go`'s `setReqCancel`
    // path with the literal `"Client.Timeout exceeded while …"`
    // suffix — uniformly across every Go-net/http-fronted CLI.
    //
    // forge's pipeline invokes the four Go-net/http-fronted CLIs —
    // kubectl, helm-cli, skopeo, regctl — extensively, every one
    // of which sets `http.Client.Timeout` on its outer client:
    // kubectl's `--request-timeout` flag (default `0` but commonly
    // set by CI scripts and forge's own wrappers), helm-cli's
    // `--timeout` flag (default `5m` for `helm install`/`upgrade`),
    // skopeo's `--command-timeout` (default `0` but commonly set
    // on registry-copy operations under burst load), regctl's
    // `--request-timeout` (defaults vary by subcommand), and
    // `helm registry login` / `helm push`'s per-request timeout
    // against an OCI registry. Production triggers: kube-apiserver
    // takes longer than `--request-timeout` to send response
    // HEADERS during a control-plane election (the elected apiserver
    // is rebuilding watch-cache, the per-request latency spikes
    // 5-30s during this window), GHCR's edge tier delays HEADERS on
    // a manifest GET during a backend rebalance (Azure Front Door
    // routes the GET to a backend draining its connection pool,
    // adding seconds to the first-byte latency), attic-server's
    // golang surface (when forge invokes attic via its CLI wrapper
    // rather than the Rust client) takes longer than the per-
    // request budget to send HEADERS during burst upload pressure,
    // or helm-release-controller's release-history compaction
    // blocks the discovery shell's `helm list` past helm-cli's
    // `--timeout`. Every one is reconvergent within the existing
    // retry-policy budget — the next attempt against a non-
    // congested upstream / freshly-elected apiserver / drained
    // backend completes within the budget; the fix here is
    // recognizing the Go-net/http Client.Timeout-elapsed phrase
    // the prior `"i/o timeout"` (socket-layer) and `"context
    // deadline exceeded"` (context-layer) markers do not cover.
    //
    // Across the dialects forge's external CLIs emit:
    // - Go net/http (kubectl, helm-cli's HTTPS surface, skopeo,
    //   regctl, attic-client through its golang surface): the
    //   bare phrase `"Client.Timeout exceeded while awaiting
    //   headers"` wrapped through `Transport.RoundTrip`'s error
    //   chain — `"Get \"https://10.0.0.1:6443/api/v1/namespaces/
    //   forge/pods\": net/http: request canceled (Client.Timeout
    //   exceeded while awaiting headers)"` (kubectl GET against
    //   slow apiserver), `"Get \"https://ghcr.io/v2/org/repo/
    //   manifests/sha256:…\": net/http: request canceled
    //   (Client.Timeout exceeded while awaiting headers)"`
    //   (skopeo/regctl manifest fetch against slow GHCR edge),
    //   `"Error: query: failed to query with labels: Get
    //   \"https://10.0.0.1:6443/api/v1/…\": net/http: request
    //   canceled (Client.Timeout exceeded while awaiting headers)"`
    //   (helm-cli release-status against slow apiserver);
    // - body-read variant — `"Get \"https://attic.…/_api/v1/
    //   cache/…\": net/http: request canceled (Client.Timeout
    //   exceeded while reading body)"` (attic-fetch where the
    //   server began streaming response bytes then stalled past
    //   the per-request budget — the `Client.Timeout exceeded`
    //   prefix is shared, the suffix names which phase the budget
    //   elapsed in);
    // - gRPC-Go (controller-runtime watch clients wrapping kube-
    //   apiserver long-polls): forwards the phrase through the
    //   gRPC status formatter — `"rpc error: code = DeadlineExceeded
    //   desc = Client.Timeout exceeded while awaiting headers"`.
    // The hyper / reqwest Rust dialect (attic-client Rust surface)
    // does NOT use this exact phrase — reqwest's per-request
    // timeout surfaces as `"operation timed out"` (covered via the
    // `"timed out"` marker above) or as `"error sending request
    // for url"` wrapping the underlying `hyper::Error::IncompleteMessage`
    // (covered via the `"connection closed before message completed"`
    // marker above).
    //
    // One casing only — every Go emitter passes through `net/http/
    // client.go`'s exact mixed-case formatting (the `Client.Timeout`
    // identifier follows Go's exported-field convention with capital
    // `C` and capital `T`, the `exceeded` verb is uniformly lowercase,
    // the `while awaiting headers` / `while reading body` suffix is
    // uniformly lowercase). The marker uses the prefix substring
    // `"Client.Timeout exceeded"` rather than either full suffix
    // variant — both `while awaiting headers` and `while reading
    // body` share the load-bearing `Client.Timeout exceeded` prefix,
    // and both are equally transient at the retry-policy oracle
    // (the budget elapsed against an upstream that was slow to
    // respond; the next attempt against a non-congested upstream
    // completes within the budget). Requiring the `Client.Timeout`
    // qualifier keeps the signal while dropping the substring-buried
    // false positives a bare `"Timeout exceeded"` substring would
    // catch (e.g. an unrelated subsystem's `"PodReady Timeout
    // exceeded"` kube-event message describing a permanent
    // readiness verdict, a `"RequestTimeout exceeded"` config-
    // parser diagnostic). The marker is also distinct from the
    // closely-related `"net/http: request canceled"` bare phrase
    // (deliberately NOT added: a cancelled request can be the
    // user's CTRL+C through a parent `context.WithCancel`
    // (terminal) or a parent context's deadline-firing (transient
    // at one layer up but already covered by the deadline-exceeded
    // propagation when the parent's deadline fires); leaving the
    // ambiguous-form signal out of the marker set keeps the
    // unambiguous-phrase-only discipline `"Temporary failure in
    // name resolution"` / `"connection closed before message
    // completed"` carry — the `Client.Timeout exceeded` phrase
    // unambiguously names a budget-elapsed verdict, not a parent-
    // cancel propagation).
    "Client.Timeout exceeded",
];

/// Named markers matched token-wise rather than as bare substrings.
///
/// Like the numeric status codes in [`TRANSIENT_HTTP_STATUS_CODES`], a
/// short acronym is dangerous as a bare substring: `stderr.contains("EOF")`
/// fires on any identifier with `E-O-F` adjacent — `GEOFFREY`,
/// `GEOFENCE`, `NEOFOLD`, `SOMEOFFICIAL`, an env var like `GEOFENCE_API`,
/// a hostname / service-name component, or a Brazilian-named build target
/// — converting a terminal failure (auth-denied, manifest-invalid) into a
/// five-attempt retry storm. The legitimate signal is Go's `io.EOF`
/// emitted as a standalone diagnostic word (`"read body: EOF"`,
/// `"connection terminated: EOF"`); requiring `EOF` to appear as a
/// maximal ASCII-alphanumeric token keeps the signal while dropping the
/// substring-buried false positives.
///
/// The multi-word Go form `"unexpected EOF"` (`io.ErrUnexpectedEOF`)
/// remains in [`TRANSIENT_NETWORK_STDERR_MARKERS`] as a distinctive
/// substring with no false-positive ambiguity.
const TRANSIENT_NETWORK_STDERR_TOKEN_MARKERS: &[&str] = &["EOF"];

/// Heuristic classifier: does `stderr` indicate a transient network or
/// upstream-server failure that should be retried, vs a terminal failure
/// (auth, not-found, missing tool, manifest mismatch) that should fail
/// fast?
///
/// Returns `true` for HTTP 5xx and 429 status codes (numeric forms
/// matched as standalone tokens via [`TRANSIENT_HTTP_STATUS_CODES`],
/// named forms — "Bad Gateway", "Too Many Requests" — via
/// [`TRANSIENT_NETWORK_STDERR_MARKERS`]), connection-level errors
/// (refused / reset / aborted), I/O and TLS-handshake timeouts, and EOF /
/// unexpected-EOF (typical TCP drop mid-stream). Returns `false` for
/// anything else — including the terminal 4xx family (400/401/403/404)
/// and empty stderr, so a typed `ExecFailed` / `TokenRequired` /
/// `LocalImageNotFound` whose record carries no stderr short-circuits
/// without burning retry budget.
///
/// Short ASCII markers match token-wise — a maximal ASCII-alphanumeric
/// run must equal the marker exactly — so a terminal failure whose
/// diagnostic merely *contains* the marker letters (a content digest, a
/// byte count, a port, a duration, an identifier like `GEOFENCE` or
/// `NEOFOLD` whose interior happens to spell `EOF`) is not misread as a
/// retryable signal. The numeric status codes
/// ([`TRANSIENT_HTTP_STATUS_CODES`]) and the bare `EOF` acronym
/// ([`TRANSIENT_NETWORK_STDERR_TOKEN_MARKERS`]) are matched this way.
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
    if TRANSIENT_NETWORK_STDERR_MARKERS
        .iter()
        .any(|m| stderr.contains(m))
    {
        return true;
    }
    // Short ASCII markers (numeric HTTP status codes, the bare `EOF`
    // acronym) match only as a maximal ASCII-alphanumeric token, never
    // as a bare substring — a "500" buried inside a digest or an "EOF"
    // buried inside an identifier (`GEOFENCE`, `NEOFOLD`) is not the
    // retryable signal.
    stderr
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|tok| {
            TRANSIENT_HTTP_STATUS_CODES.contains(&tok)
                || TRANSIENT_NETWORK_STDERR_TOKEN_MARKERS.contains(&tok)
        })
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

    /// True iff the captured stderr matches a transient network/server
    /// failure marker (HTTP 5xx, 429, connection-level, I/O timeout,
    /// EOF). Empty stderr is terminal by construction — same discipline
    /// the free [`is_transient_network_stderr`] classifier and the
    /// sibling peer [`CommandAttemptFailure::is_transient`] encode.
    ///
    /// Typed-method peer of [`CommandAttemptFailure::is_transient`].
    /// Both typed records at the retry surface carry a `stderr: String`
    /// field consumed by one canonical classifier; pinning that
    /// classifier at both typed-record surfaces means a consumer that
    /// holds a `CapturedFailure` (the typed-error producer surface:
    /// `GitError::OpFailed`, `NixBuildError::BuildFailed`,
    /// `AtticError::PushFailed`/`LoginFailed`,
    /// `RegistryError::PushFailed`) reads transient/terminal as
    /// `cf.is_transient()` — same call shape as a consumer that holds
    /// a `CommandAttemptFailure` (the retry-call-site surface) —
    /// instead of routing through the free function with the
    /// per-site `is_transient_network_stderr(&cf.stderr)` cascade.
    /// Closes the typed-method symmetry the
    /// `PartialEq`/`Eq` derive lift (commits 604884b/c6a47f2)
    /// established at the structural-equality surface, here applied
    /// at the transient/terminal predicate surface — every typed
    /// primitive at the retry boundary now speaks the same
    /// `is_transient()` language.
    ///
    /// THEORY.md §VI.1 one-oracle discipline: the
    /// transient/terminal classification rule is named at one site
    /// ([`is_transient_network_stderr`]) and surfaced through one
    /// typed-method per record carrying `stderr`. A future addition
    /// to the transient-marker list lights up at every typed-method
    /// peer in the same commit.
    pub fn is_transient(&self) -> bool {
        is_transient_network_stderr(&self.stderr)
    }

    /// True iff this captured failure represents a terminal (fail-fast)
    /// failure — a future retry-policy site holding a `CapturedFailure`
    /// should NOT burn budget on it.
    ///
    /// Named complement of [`Self::is_transient`]: the two predicates
    /// partition every [`CapturedFailure`] record into exactly two
    /// retry-dispatch shapes — `is_transient` (HTTP 5xx / 429,
    /// connection-level, I/O timeout, EOF) and `is_terminal` (every
    /// other shape: terminal 4xx auth/not-found/manifest-invalid,
    /// empty-stderr "silent failure", non-matching diagnostic). Never
    /// both and never neither.
    ///
    /// Typed-method peer of [`CommandAttemptFailure::is_terminal`]
    /// (commit 6fa921b). Both typed records at the retry surface carry
    /// a `stderr: String` field consumed by the one canonical
    /// classifier [`is_transient_network_stderr`]; pinning both arms
    /// of the partition at both typed-record surfaces means a consumer
    /// that holds a `CapturedFailure` (the typed-error producer
    /// surface: `GitError::OpFailed`, `NixBuildError::BuildFailed`,
    /// `AtticError::PushFailed`/`LoginFailed`,
    /// `RegistryError::PushFailed`) reads terminal/transient through
    /// one typed method per arm — `cf.is_terminal()` /
    /// `cf.is_transient()` — same call shape a consumer that holds a
    /// `CommandAttemptFailure` (the retry-call-site surface) already
    /// uses, instead of routing the terminal arm through
    /// `!cf.is_transient()` against the negated predicate.
    ///
    /// Closes the typed-method symmetry the recent
    /// [`CommandAttemptFailure::is_terminal`] peer (commit 6fa921b)
    /// established at the retry-call-site surface, here applied at
    /// the typed-error producer surface — every typed primitive at
    /// the retry boundary now speaks the same `is_terminal()` /
    /// `is_transient()` peer-pair language.
    ///
    /// THEORY.md §VI.1 one-oracle discipline: the transient/terminal
    /// retry-dispatch partition is named at one typed-primitive site
    /// with both arms exposed as typed methods, not as one method plus
    /// an implicit `!` at every consumer. Same parallel-axis
    /// named-complement peer idiom the
    /// [`CommandAttemptFailure::is_terminal`] /
    /// [`CommandAttemptFailure::is_transient`] pair established at
    /// the retry-call-site surface, here applied at the typed-error
    /// producer surface.
    pub fn is_terminal(&self) -> bool {
        !self.is_transient()
    }

    /// True iff this captured failure represents a child process that was
    /// killed by signal (no normal exit code) rather than a child process
    /// that ran-to-completion-then-exited-non-zero.
    ///
    /// Equivalent to `self.exit_code.is_none()`. The Rust standard library
    /// (`ExitStatus::code`) guarantees `None` exactly when the process was
    /// terminated by signal — the canonical Unix discriminator between
    /// "process exited via `exit(n)`" (`Some(n)`) and "process killed by
    /// SIGKILL / SIGTERM / SIGSEGV / SIGPIPE / SIGOOM-from-cgroups"
    /// (`None`). The typed primitive surfaces that discriminator as a
    /// named method so consumer sites read the structural-shape partition
    /// through `cf.is_signal_killed()` instead of through a raw
    /// `cf.exit_code.is_none()` field access against the wrong-abstraction
    /// level.
    ///
    /// Structural-shape peer of [`CommandAttemptFailure::is_spawn_failure`]
    /// (commit 34c1a35) — the analogous structural-shape predicate at the
    /// retry-call-site surface. The two predicates name *different*
    /// structural shapes because the two typed records cover different
    /// failure-mode universes:
    ///
    /// - [`CommandAttemptFailure`] is constructed from
    ///   `Result<Output, io::Error>` so it covers three shapes (success,
    ///   `Ok(non-success)` op-failure, `Err(spawn_err)` spawn-failure);
    ///   `is_spawn_failure` discriminates the third shape with the
    ///   conjunction `exit_code.is_none() && stderr.is_empty()` because at
    ///   that surface `exit_code: None` is ambiguous between spawn-failure
    ///   and signal-killed-with-stderr.
    /// - [`CapturedFailure`] is constructed from `&std::process::Output`
    ///   so it covers exactly one shape — the process DEFINITELY ran (we
    ///   hold an `Output`); a spawn failure produces no `Output` and never
    ///   reaches this typed primitive. So at the producer surface
    ///   `exit_code: None` is unambiguously signal-killed, and the
    ///   single-field predicate is the canonical discriminator with no
    ///   conjunction.
    ///
    /// # Orthogonal to the transient/terminal partition
    ///
    /// The retry-dispatch partition ([`Self::is_transient`] /
    /// [`Self::is_terminal`]) discriminates on `stderr` via the canonical
    /// [`is_transient_network_stderr`] classifier; this structural-shape
    /// partition discriminates on `exit_code`. The two axes are
    /// orthogonal — a signal-killed record (`exit_code: None`) with a
    /// transient stderr (`"i/o timeout"` flushed before the kill) is
    /// signal-killed AND transient; a signal-killed record with empty
    /// stderr (the SIGKILL / OOM-from-cgroups shape) is signal-killed AND
    /// terminal; a normal-exit record with terminal stderr (`"401
    /// Unauthorized"`) is NOT signal-killed AND terminal; a normal-exit
    /// record with transient stderr (`"503 Service Unavailable"`) is NOT
    /// signal-killed AND transient. Every quadrant of the 2×2 is
    /// populated by canonical structural shapes forge's external CLIs
    /// emit, so neither partition collapses into the other and both must
    /// be surfaced at this typed-record surface for any future
    /// post-classification consumer (telemetry histogramming OOM-kill
    /// vs auth-denial vs transient-5xx; structured-attestation surface
    /// distinguishing "killed by SIGTERM under deploy timeout" from
    /// "exited-normally-with-error"; future remediation-policy site that
    /// retries OOM-kills against a beefier builder while failing fast on
    /// auth denials).
    ///
    /// THEORY.md §VI.1 one-oracle discipline: the
    /// exited-normally/signal-killed structural partition is named at one
    /// typed-primitive site (here) instead of retyped as the inline
    /// `cf.exit_code.is_none()` cascade at every consumer site that
    /// branches on the structural shape. Same parallel-axis named
    /// structural-shape peer idiom the
    /// [`CommandAttemptFailure::is_spawn_failure`] /
    /// [`CommandAttemptFailure::is_op_failure`] peer-pair (commit
    /// a4f4146) established at the retry-call-site surface, here applied
    /// at the typed-error producer surface — the typed-method shape every
    /// `cf.exit_code` reader at the four producer sites
    /// (`GitError::OpFailed`, `NixBuildError::BuildFailed`,
    /// `AtticError::PushFailed` / `LoginFailed`,
    /// `RegistryError::PushFailed`) can adopt without re-deriving the
    /// `Option::is_none()` reading per call site.
    pub fn is_signal_killed(&self) -> bool {
        self.exit_code.is_none()
    }

    /// True iff this captured failure represents a child process that
    /// exited via `exit(n)` (any normal exit code, including the
    /// canonical 137 SIGKILL-from-shell exit code preserved by `bash`)
    /// rather than a child process killed by signal before reaching a
    /// normal exit.
    ///
    /// Equivalent to `self.exit_code.is_some()`. Named complement of
    /// [`Self::is_signal_killed`]: the two predicates partition every
    /// [`CapturedFailure`] record into exactly two structural shapes —
    /// the `exit_code: Some(_)` arm (the canonical `exit(n)` shape forge's
    /// external CLIs produce on a typed rejection: skopeo's `Some(1)` on
    /// manifest-invalid, attic's `Some(1)` on auth-denied, git's
    /// `Some(128)` on remote-rejected, nix-build's `Some(1)` on
    /// derivation-failed) and the `exit_code: None` arm (the
    /// signal-killed shape — SIGKILL / SIGTERM / SIGSEGV / SIGPIPE /
    /// cgroups OOM-kill). Never both and never neither, by the canonical
    /// Rust `ExitStatus::code` `None`/`Some` discriminator.
    ///
    /// # Why a named complement
    ///
    /// The recent [`Self::is_signal_killed`] peer (commit 5b49d2c) named
    /// the abnormal arm of the partition at this typed-error producer
    /// surface; the normal arm previously only surfaced as
    /// `!cf.is_signal_killed()` or as the raw field access
    /// `cf.exit_code.is_some()` at consumer sites that branch in that
    /// direction (a future post-classification surface routing
    /// "exited-normally-with-error" to one telemetry counter and
    /// "killed-by-signal" to another; a future remediation-policy site
    /// that retries OOM-kills against a beefier builder while reporting
    /// `exit(n)` failures verbatim; a future structured-attestation
    /// surface that records the structural shape of every failure in
    /// the SLSA provenance record). The named peer hoists that reading
    /// to a typed method, matching the structural-complement idiom the
    /// recent peer-pairs established:
    /// [`CommandAttemptFailure::is_op_failure`] /
    /// [`CommandAttemptFailure::is_spawn_failure`] (commit a4f4146) at
    /// the retry-call-site surface, [`CommandAttemptFailure::is_terminal`]
    /// / [`CommandAttemptFailure::is_transient`] (commit 6fa921b) at the
    /// retry-dispatch surface, [`Self::is_terminal`] /
    /// [`Self::is_transient`] (commit 6069a25) at this typed-error
    /// producer surface. Every binary partition the typed primitive
    /// surfaces now exposes both arms as typed methods, so consumer
    /// sites never read through a `!` against the wrong-direction
    /// predicate.
    ///
    /// # Orthogonal to the transient/terminal partition
    ///
    /// Same orthogonality the sibling [`Self::is_signal_killed`] holds:
    /// `is_exited_normally` discriminates on `exit_code`;
    /// [`Self::is_transient`] / [`Self::is_terminal`] discriminate on
    /// `stderr` via the canonical [`is_transient_network_stderr`]
    /// classifier. Every quadrant of the 2×2 — exited-normally ×
    /// transient (`Some(1)` + `"503"`, the canonical retry-budget arm),
    /// exited-normally × terminal (`Some(1)` + `"401"`, the canonical
    /// fail-fast arm), signal-killed × transient (`None` + `"i/o
    /// timeout"`, the deploy-timeout-on-network-op shape), signal-killed
    /// × terminal (`None` + `""`, the SIGKILL / OOM-kill shape) — is
    /// populated by a canonical structural shape forge's external CLIs
    /// emit. Neither partition collapses into the other.
    ///
    /// THEORY.md §VI.1 one-oracle discipline: the exited-normally /
    /// signal-killed structural partition is named at one typed-
    /// primitive site with both arms exposed as typed methods, not as
    /// one method plus an implicit `!` at every consumer. Same
    /// parallel-axis named structural-shape peer idiom the
    /// [`CommandAttemptFailure::is_op_failure`] /
    /// [`CommandAttemptFailure::is_spawn_failure`] peer-pair (commit
    /// a4f4146) established at the retry-call-site surface, here applied
    /// at the typed-error producer surface — the typed-method shape every
    /// `cf.exit_code` reader at the four producer sites
    /// (`GitError::OpFailed`, `NixBuildError::BuildFailed`,
    /// `AtticError::PushFailed` / `LoginFailed`,
    /// `RegistryError::PushFailed`) can adopt without re-deriving the
    /// `Option::is_some()` reading per call site.
    pub fn is_exited_normally(&self) -> bool {
        !self.is_signal_killed()
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
/// tuple in its op-failure variant (`GitError::OpFailed` carrying the
/// `(exit_code, stderr)` pair) destructures `cf.exit_code` and
/// `cf.stderr` by name, and a site that does NOT want them
/// (`RegistryError::RemoteImageNotFound` carrying only `(registry, tag)`
/// because the precondition meaning is "the queried tag isn't there")
/// simply ignores `cf` with `|_cf| ...`.
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

/// Anyhow-shaped sibling of [`classify_capture_query`]: routes the same
/// three structural shapes (success / spawn-failure / op-failure) into the
/// canonical anyhow envelope used by command-module helpers whose public
/// surface returns `anyhow::Result<T>` and where a domain-specific error
/// enum (`RegistryError`, `AtticError`, `GitError`, `NixBuildError`) does
/// not yet exist.
///
/// Lifts the verbatim seven-line mapper-pair body
/// ```text
/// let spawn_cmd = cmd.to_string();
/// let spawn_args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
/// let op_cmd = spawn_cmd.clone();
/// let op_args = spawn_args.clone();
/// classify_capture_query(
///     captured,
///     move |e| anyhow::anyhow!("Failed to spawn {} {:?}: {}", spawn_cmd, spawn_args, e),
///     move |cf| anyhow::anyhow!("{} {:?} failed (exit {:?}): {}", op_cmd, op_args, cf.exit_code, cf.stderr),
/// )
/// ```
/// that two command-module sites in forge carry verbatim modulo sync/async
/// at the spawn surface: `commands/seed.rs::run_command_output` (sync,
/// `std::process::Command` → `kubectl get pod` for CNPG primary discovery)
/// and `commands/attestation.rs::run_command_output` (async,
/// `tokio::process::Command` → `git remote get-url origin` / `git
/// symbolic-ref` / `git ls-tree` / `nix path-info` / `skopeo inspect` for
/// Phase 1 attestation source/build/image records). Two identically-shaped
/// bodies past the duplication threshold the forge command-module surface
/// enforces (≥2; PRIME DIRECTIVE) — this primitive is the law-redeeming
/// consolidation for the "anyhow envelope over a queried external CLI"
/// shape, sibling of [`classify_capture_query`] (the canonical typed-error
/// query-shape primitive) and [`classify_capture`] (the canonical
/// typed-error op-shape primitive).
///
/// # Sync/async-agnostic by construction
///
/// `std::io::Result<std::process::Output>` is the shape both
/// `std::process::Command::output()` and
/// `tokio::process::Command::output().await` produce — the classifier and
/// the mapper closures consume the post-spawn shape, not the spawn surface
/// itself. Sync callers (`commands/seed.rs`) and async callers
/// (`commands/attestation.rs`) flow through one canonical primitive with
/// identical message shapes by construction.
///
/// # Message format
///
/// - Spawn-failure: `"Failed to spawn {cmd} {args:?}: {io_error}"` —
///   carries the offending CLI binary path and the requested argv slice
///   in the `Debug` rendering. Pre-migration the spawn-failure path fused
///   into `with_context("Failed to execute {cmd}")` envelopes at both
///   sites that dropped the captured `io::Error::Display` and the args
///   entirely.
/// - Op-failure: `"{cmd} {args:?} failed (exit {exit_code:?}): {stderr}"`
///   — carries the structural-record tuple THEORY §V.4 Phase 1
///   attestation records pattern-match on (operation label, exit code,
///   trimmed UTF-8-lossy stderr). Pre-migration the op-failure path at
///   both sites fused the tuple into a single `bail!("kubectl failed:
///   {}", stderr)` / `bail!("{} {:?} failed: {}", cmd, args, stderr)`
///   string that dropped the exit code.
///
/// # The owned-copies pattern is load-bearing
///
/// `classify_capture_query` takes `FnOnce` on each arm so each closure
/// consumes its captures by move. The `to_string` + `Vec<String>` owned
/// copies decouple the closure lifetimes from the caller-supplied
/// `&str` / `&[&str]` borrows — pinning the discipline at this primitive
/// means every consumer that produces an anyhow error from a captured
/// external-CLI invocation routes through one ownership shape, not two
/// hand-rolled copies of it.
pub fn classify_capture_query_anyhow(
    captured: std::io::Result<std::process::Output>,
    cmd: &str,
    args: &[&str],
) -> anyhow::Result<String> {
    let spawn_cmd = cmd.to_string();
    let spawn_args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let op_cmd = spawn_cmd.clone();
    let op_args = spawn_args.clone();
    classify_capture_query(
        captured,
        move |e| anyhow::anyhow!("Failed to spawn {} {:?}: {}", spawn_cmd, spawn_args, e),
        move |cf| {
            anyhow::anyhow!(
                "{} {:?} failed (exit {:?}): {}",
                op_cmd,
                op_args,
                cf.exit_code,
                cf.stderr
            )
        },
    )
}

/// Run a sync external CLI and return its trimmed UTF-8-lossy stdout
/// under the canonical "anyhow envelope over a queried external CLI"
/// shape — sibling of [`classify_capture_query_anyhow`] that owns the
/// spawn surface (`std::process::Command::new(cmd).args(args).output()`)
/// in addition to the post-spawn classifier.
///
/// Lifts the verbatim three-line spawn-then-delegate body
/// ```text
/// classify_capture_query_anyhow(
///     std::process::Command::new(cmd).args(args).output(),
///     cmd,
///     args,
/// )
/// ```
/// that three command-module sites in forge carry verbatim modulo the
/// `cmd` argument: `commands/seed.rs::run_command_output` (parametric
/// `cmd`, single call site — `kubectl get pod` for CNPG primary
/// discovery), `commands/sessions.rs::kubectl` (`cmd` hardcoded to
/// `"kubectl"`, three call sites — secret-fetch / `valkey-cli keys` /
/// `valkey-cli DEL`), and `commands/local.rs::run_command_output`
/// (parametric `cmd`, two call sites — `docker stop` / `docker rm`).
/// Three identically-shaped bodies past THEORY §VI.1's three-is-a-law
/// threshold (PRIME DIRECTIVE: duplication budget is zero); this
/// primitive is the law-redeeming consolidation.
///
/// # Why a separate primitive, not "just call `classify_capture_query_anyhow`"
///
/// The post-spawn classifier ([`classify_capture_query_anyhow`])
/// consumes an `io::Result<std::process::Output>` and cannot own the
/// spawn step itself, because the spawn surface is intentionally split
/// between sync (`std::process::Command::output()`) and async
/// (`tokio::process::Command::output().await`) consumers. The three
/// sync consumers above each spelled the spawn-then-delegate body
/// verbatim — the wrapper had no per-site customization beyond the
/// `cmd` argument. Consolidating onto this primitive collapses the
/// three private `run_command_output` / `kubectl` shape-adapter
/// helpers (and their per-site test triples) onto one canonical
/// primitive with one test triple.
///
/// # Why sync-only, not also async
///
/// The async + cwd shape (`commands/attestation.rs::run_command_output`,
/// the only async consumer of `classify_capture_query_anyhow` in
/// forge) adds `.current_dir(cwd)` and runs through
/// `tokio::process::Command` — structurally distinct from the sync
/// no-cwd shape this primitive covers. One site is below the
/// three-times-rule threshold; when a second async + cwd site
/// appears, the `run_query_capture_async_in` sibling can join here.
/// Lifting it now would invent a second-rate primitive ahead of the
/// law.
///
/// # Message format
///
/// Inherited verbatim from [`classify_capture_query_anyhow`]:
/// spawn-failure surfaces `"Failed to spawn {cmd} {args:?}: {io_error}"`,
/// op-failure surfaces `"{cmd} {args:?} failed (exit {exit_code:?}):
/// {stderr}"`. The `(cmd, args, exit_code, stderr)` structural-record
/// tuple THEORY §V.4 Phase 1 attestation telemetry pattern-matches on
/// is preserved by construction.
pub fn run_query_capture_sync(cmd: &str, args: &[&str]) -> anyhow::Result<String> {
    classify_capture_query_anyhow(
        std::process::Command::new(cmd).args(args).output(),
        cmd,
        args,
    )
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
///
/// # Structural equality
///
/// Derives [`PartialEq`] and [`Eq`] field-wise. All five fields are
/// `Eq`-bound stdlib primitives (`String`, `u32`, `Option<i32>`,
/// `String`, `String`), so the derive is sound and reads extensional:
/// two records are equal iff their `(operation, attempt, exit_code,
/// stderr, stdout)` tuples match exactly. Closes the structural-
/// equality reading at the typed-record surface against the sibling
/// peer [`CapturedFailure`] (which already derived `PartialEq`/`Eq`)
/// and the canonical schedule peer [`RetryPolicy`] (commit 604884b),
/// so every typed primitive at the retry surface now speaks the same
/// `==` / `assert_eq!` language at consumer sites — including the
/// existing `test_command_attempt_failure_*` tests that previously
/// asserted each field independently and any future retry-telemetry
/// consumer comparing two records for structural agreement.
#[derive(Debug, Clone, PartialEq, Eq)]
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

    /// True iff this record represents a terminal (fail-fast) failure —
    /// the retry loop should NOT burn budget on it.
    ///
    /// Named complement of [`Self::is_transient`]: the two predicates
    /// partition every [`CommandAttemptFailure`] record into exactly two
    /// retry-dispatch shapes — `is_transient` (the canonical retry-
    /// budget-consuming arm: HTTP 5xx / 429, connection-level, I/O
    /// timeout, EOF) and `is_terminal` (every other shape: terminal 4xx
    /// auth/not-found/manifest-invalid, empty-stderr spawn-failure,
    /// non-matching diagnostic). Never both and never neither.
    ///
    /// # Why a named complement
    ///
    /// The canonical retry-loop dispatch site [`run_with_policy`] reads
    /// the partition as `if !is_transient(&e) || attempt >= max` — the
    /// negation against the transient predicate carries the "this error
    /// is terminal, short-circuit the loop" meaning implicitly at the
    /// load-bearing fail-fast arm. Consumer sites that branch in the
    /// other direction (testing for terminal-first, then falling back to
    /// a transient-retry path: e.g., a future post-retry telemetry
    /// surface histogramming terminal-vs-transient counts; a future
    /// fail-fast pre-loop skip for known-terminal records; a future
    /// structured-attestation surface distinguishing "transient retry
    /// exhausted" from "terminal classified at first attempt"
    /// previously had to write `!failure.is_transient()` against the
    /// negated transient predicate. The named peer hoists that reading
    /// to a typed method, matching the structural-complement idiom the
    /// recent spawn/op peer-pair ([`Self::is_spawn_failure`] /
    /// [`Self::is_op_failure`], commit a4f4146) and the
    /// [`crate::probe_outcome::AdmissionTier`] admit/refuse peer trio
    /// (commits 05f5071 / bb0110e / aec7d7c / 585ec00) established:
    /// every binary partition the typed primitive surfaces exposes both
    /// arms as typed methods, so consumer sites never read through a
    /// `!` against the wrong-direction predicate.
    ///
    /// # Spawn-failure is structurally terminal
    ///
    /// The spawn-failure shape ([`Self::is_spawn_failure`]: `exit_code:
    /// None` + empty `stderr`) is unconditionally terminal under the
    /// canonical [`is_transient_network_stderr`] classifier — empty
    /// stderr matches no transient marker by construction. So
    /// `is_spawn_failure()` implies `is_terminal()` at every record.
    /// The reverse does not hold: an op-failure record with terminal
    /// stderr (`Some(exit_code)` + `"401 Unauthorized"`) is terminal
    /// but not a spawn-failure. The two partitions
    /// (spawn-vs-op and transient-vs-terminal) are orthogonal —
    /// `is_spawn_failure` discriminates on the structural shape the
    /// record was constructed in; `is_terminal` discriminates on the
    /// retry-dispatch class. Both partitions surface their named
    /// complements at this typed-method surface for the canonical
    /// 2×2 reading at any future post-retry classifier.
    ///
    /// THEORY.md §VI.1 one-oracle discipline: the transient/terminal
    /// retry-dispatch partition is named at one typed-primitive site
    /// with both arms exposed as typed methods, not as one method plus
    /// an implicit `!` at every consumer. Same parallel-axis
    /// named-complement peer idiom the
    /// [`Self::is_spawn_failure`] / [`Self::is_op_failure`] pair
    /// recently established at the structural-shape surface, here
    /// applied at the retry-dispatch surface.
    pub fn is_terminal(&self) -> bool {
        !self.is_transient()
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

    /// True iff this record represents a process that ran-but-exited-
    /// non-zero (the CLI binary was found and invoked, but it rejected
    /// the request) — as opposed to a process that could not be spawned
    /// at all.
    ///
    /// Named complement of [`Self::is_spawn_failure`]: the two
    /// predicates together partition every [`CommandAttemptFailure`]
    /// record into exactly two structural shapes, never both and never
    /// neither. The `is_spawn_failure` half names the spawn-error shape
    /// (`exit_code: None` + empty stderr, with the spawn error in
    /// stdout) the `Err(io::Error)` arm of [`Self::from_capture`]
    /// produces; this half names the op-failure shape (`Some(_)` exit
    /// code or non-empty stderr) the `Ok(non-success)` arm produces.
    ///
    /// # Why a named complement
    ///
    /// The canonical post-`retry_command` dispatch site
    /// [`classify_attempt_failure`] reads the partition as
    /// `if failure.is_spawn_failure() { on_spawn } else { on_op }` — the
    /// `else` arm carries the op-failure meaning implicitly. Consumer
    /// sites that branch in the other direction (testing for op-failure
    /// first, then dispatching to a spawn-failure fallback) previously
    /// had to write `!failure.is_spawn_failure()` against the negated
    /// spawn predicate. The named peer hoists that reading to a typed
    /// method, matching the structural-complement idiom the recent
    /// peer-pairs at the typed-coverage surface
    /// ([`crate::probe_outcome::AdmissionTier::admits_relaxed`] /
    /// [`crate::probe_outcome::AdmissionTier::refuses_relaxed`],
    /// [`crate::probe_outcome::AdmissionTier::admits_strict`] /
    /// [`crate::probe_outcome::AdmissionTier::refuses_strict`])
    /// established: every predicate the typed primitive surfaces has
    /// its named complement at the same surface, so consumer sites
    /// never read through a `!` against the wrong-direction predicate.
    ///
    /// # The partition invariant is load-bearing
    ///
    /// `from_capture` constructs records in exactly two shapes — the
    /// `Ok(non-success)` arm always populates `(exit_code,
    /// stderr, stdout)` from the captured `Output`, and the
    /// `Err(io::Error)` arm always sets `exit_code: None`, empty
    /// `stderr`, spawn-error message in `stdout`. The
    /// `exit_code.is_none() && stderr.is_empty()` conjunction is
    /// the structural discriminator across the two shapes; its
    /// complement `exit_code.is_some() || !stderr.is_empty()` names
    /// the op-failure side directly. A future regression that
    /// constructed a record with `exit_code: None` AND non-empty
    /// stderr (e.g., a signal-killed process whose stderr was
    /// flushed before the signal) would correctly classify as
    /// op-failure here — same discipline `is_spawn_failure` already
    /// encodes for that edge case.
    ///
    /// THEORY.md §VI.1 one-oracle discipline: the spawn/op partition
    /// is named at one typed-primitive site with both arms exposed as
    /// typed methods, not as one method plus an implicit `else` at
    /// every consumer. The same generation-over-composition
    /// discipline the AdmissionTier admit/refuse peer trio
    /// established at the typed-coverage surface, here applied at the
    /// typed-attempt-failure surface.
    pub fn is_op_failure(&self) -> bool {
        !self.is_spawn_failure()
    }

    /// True iff this record represents a child process that ran but was
    /// killed by signal mid-op — `exit_code: None` AND non-empty
    /// `stderr` — as opposed to a process that could not be spawned at
    /// all (also `exit_code: None` but with empty `stderr`) or a process
    /// that ran-to-completion-then-exited-non-zero (`exit_code:
    /// Some(_)`).
    ///
    /// Equivalent to the conjunction
    /// `exit_code.is_none() && !stderr.is_empty()`. At the retry-call-
    /// site surface ([`CommandAttemptFailure`]) `exit_code: None` is
    /// ambiguous between two structural shapes that
    /// [`Self::from_capture`] produces: the `Err(io::Error)` spawn-
    /// failure arm (no `Output` ever existed, so `stderr` is empty by
    /// construction) and the `Ok(non-success)` signal-killed-mid-op arm
    /// (the child reached `exit()` only via signal — SIGKILL / SIGTERM
    /// / SIGSEGV / SIGPIPE / cgroups OOM-kill — after flushing some
    /// stderr). The conjunction discriminates between the two: empty
    /// stderr is the structural witness for spawn-failure
    /// ([`Self::is_spawn_failure`]); non-empty stderr with `exit_code:
    /// None` is the structural witness for signal-killed-mid-op.
    ///
    /// # Structural-shape peer at the retry-call-site surface
    ///
    /// Mirrors [`CapturedFailure::is_signal_killed`] (commit 5b49d2c) at
    /// the typed-error producer surface. The two predicates name the
    /// same structural shape (the child was terminated by signal before
    /// reaching a normal `exit(n)`) at two surfaces of the retry
    /// boundary; the load-bearing difference is the conjunction shape.
    /// The producer surface predicate has a single-field body
    /// (`exit_code.is_none()`) because at that surface the process
    /// definitely ran — [`CapturedFailure`] is constructed only from
    /// `&std::process::Output`, so a spawn failure produces no `Output`
    /// and never reaches the typed primitive. The call-site surface
    /// predicate adds the `!stderr.is_empty()` conjunction because at
    /// this surface the type is constructed from `Result<Output,
    /// io::Error>` — the `exit_code: None` half of the structural-
    /// shape universe is shared between the spawn-failure shape and
    /// the signal-killed-mid-op shape, and the canonical discriminator
    /// is the `stderr` field that [`Self::from_capture`] fixes empty
    /// only on the spawn-failure arm.
    ///
    /// # Three-way structural-shape partition within op-failure
    ///
    /// The existing [`Self::is_spawn_failure`] / [`Self::is_op_failure`]
    /// peer-pair (commit a4f4146) partitions every record into two
    /// shapes — spawn-failure vs op-failure — collapsing the signal-
    /// killed and exited-normally arms into one "op-failure" arm.
    /// That collapse is load-bearing at the canonical post-
    /// `retry_command` dispatch surface [`classify_attempt_failure`]
    /// which routes `*::ExecFailed` (spawn) vs `*::OpFailed`/
    /// `*::PushFailed`/`*::BuildFailed` (op). This finer-grained
    /// predicate names the signal-killed sub-arm of op-failure
    /// directly, so a future remediation-policy site that wants to
    /// retry OOM-kills against a beefier builder while failing fast
    /// on auth denials — or a future structured-attestation surface
    /// that records "killed by SIGTERM under deploy timeout" as a
    /// distinct provenance class from "exited normally with error" —
    /// reads the signal-killed structural shape through one typed
    /// method call instead of through the
    /// `exit_code.is_none() && !stderr.is_empty()` conjunction at
    /// every consumer.
    ///
    /// # Orthogonal to the retry-dispatch partition
    ///
    /// Same orthogonality the sibling [`CapturedFailure::is_signal_killed`]
    /// holds at the producer surface: the structural-shape partition
    /// discriminates on `exit_code` + the structural witness `stderr`;
    /// the retry-dispatch partition ([`Self::is_transient`] /
    /// [`Self::is_terminal`]) discriminates on `stderr` content via
    /// the canonical [`is_transient_network_stderr`] classifier. A
    /// signal-killed record with transient stderr (`"i/o timeout"`
    /// flushed before SIGTERM-on-deploy-timeout) is signal-killed AND
    /// transient; a signal-killed record with terminal stderr (`"fatal:
    /// aborted"` flushed before a SIGSEGV / SIGABRT) is signal-killed
    /// AND terminal. The two axes never collapse and the typed-method
    /// peer makes both quadrants directly readable.
    ///
    /// THEORY.md §VI.1 one-oracle discipline: the signal-killed
    /// structural shape is named at one typed-primitive site at each
    /// surface of the retry boundary, not retyped as the
    /// `exit_code.is_none() && !stderr.is_empty()` conjunction at
    /// every consumer site that branches on the structural shape.
    /// Same parallel-axis named structural-shape peer idiom commit
    /// 5b49d2c established at the typed-error producer surface, here
    /// applied at the retry-call-site surface where the conjunction
    /// shape is load-bearing.
    pub fn is_signal_killed(&self) -> bool {
        self.exit_code.is_none() && !self.stderr.is_empty()
    }

    /// True iff this record represents a child process that exited via
    /// `exit(n)` (any normal exit code, including the canonical 137
    /// SIGKILL-from-shell exit code preserved by `bash`) rather than a
    /// child process killed by signal before reaching a normal exit or
    /// a process that could not be spawned at all.
    ///
    /// Equivalent to `self.exit_code.is_some()`. Closes the three-way
    /// structural-shape partition at the retry-call-site surface:
    /// every [`CommandAttemptFailure`] record falls into exactly one of
    /// three disjoint structural shapes [`Self::from_capture`]
    /// constructs — spawn-failure ([`Self::is_spawn_failure`]:
    /// `exit_code: None` + empty `stderr`, from the `Err(io::Error)`
    /// arm), signal-killed-mid-op ([`Self::is_signal_killed`]:
    /// `exit_code: None` + non-empty `stderr`, from the
    /// `Ok(non-success)` arm whose child reached `exit()` only via
    /// signal — SIGKILL / SIGTERM / SIGSEGV / SIGPIPE / cgroups
    /// OOM-kill — after flushing some stderr), and exited-normally
    /// (this predicate: `exit_code: Some(_)` regardless of `stderr`,
    /// from the `Ok(non-success)` arm whose child ran to completion
    /// and exited with a non-success code). Never two and never none.
    ///
    /// # Single-field body at the call-site surface
    ///
    /// Mirrors [`CapturedFailure::is_exited_normally`] (commit 5c1cec1)
    /// at the typed-error producer surface. Both predicates have a
    /// single-field body (`exit_code.is_some()`) because `Some(_)` is
    /// unambiguously exited-normally at every surface of the retry
    /// boundary — the spawn-failure / signal-killed-mid-op
    /// disambiguation that the sibling [`Self::is_signal_killed`]
    /// conjunction body captures is structurally absent on the
    /// `exit_code: Some(_)` half of the universe. The
    /// `Err(io::Error)` spawn-failure arm of [`Self::from_capture`]
    /// always sets `exit_code: None`, so no spawn-failure record ever
    /// reaches `is_exited_normally`; this is what lets the call-site
    /// predicate be single-field clean.
    ///
    /// # Why a named peer
    ///
    /// The recent [`Self::is_signal_killed`] peer (commit cb0db50)
    /// named the signal-killed sub-arm of op-failure at this surface;
    /// the exited-normally sub-arm previously only surfaced as
    /// `!cf.is_signal_killed() && !cf.is_spawn_failure()` or as the
    /// raw field access `cf.exit_code.is_some()` at consumer sites that
    /// branch in that direction (a future remediation-policy site that
    /// retries OOM-kills against a beefier builder while reporting
    /// `exit(n)` failures verbatim; a future structured-attestation
    /// surface that records "exited normally with error" as a distinct
    /// provenance class from "killed by SIGTERM under deploy timeout";
    /// a future post-retry telemetry surface histogramming the three
    /// structural-shape sub-classes). The named peer hoists that
    /// reading to a typed method, matching the structural-complement
    /// idiom the recent peer-pairs established at both surfaces of the
    /// retry boundary:
    /// [`Self::is_spawn_failure`] / [`Self::is_op_failure`]
    /// (commit a4f4146) for the spawn/op partition at the call-site
    /// surface, [`Self::is_transient`] / [`Self::is_terminal`]
    /// (commit 6fa921b) for the retry-dispatch partition at the
    /// call-site surface, [`CapturedFailure::is_signal_killed`] /
    /// [`CapturedFailure::is_exited_normally`] (commits 5b49d2c /
    /// 5c1cec1) for the structural-shape partition at the producer
    /// surface. Every binary partition the typed primitives at the
    /// retry boundary surface now exposes both arms as typed methods,
    /// and the three-way structural-shape partition at the call-site
    /// surface is now closed at the same typed-method surface — every
    /// `cf.exit_code` reader at the post-`retry_command` consumer
    /// sites can adopt the typed-method shape without re-deriving the
    /// `Option::is_some()` reading per call site.
    ///
    /// # Orthogonal to the retry-dispatch partition
    ///
    /// Same orthogonality the sibling [`Self::is_signal_killed`] and
    /// [`CapturedFailure::is_exited_normally`] hold: this predicate
    /// discriminates on `exit_code`; [`Self::is_transient`] /
    /// [`Self::is_terminal`] discriminate on `stderr` via the
    /// canonical [`is_transient_network_stderr`] classifier. Every
    /// quadrant of the 2×2 — exited-normally × transient (`Some(1)` +
    /// `"503"`, the canonical retry-budget arm), exited-normally ×
    /// terminal (`Some(1)` + `"401"`, the canonical fail-fast arm),
    /// not-exited-normally × transient (`None` + `"i/o timeout"`, the
    /// deploy-timeout-on-network-op shape), not-exited-normally ×
    /// terminal (`None` + `""`, the spawn-failure / SIGKILL shape) —
    /// is populated by canonical structural shapes forge's external
    /// CLIs emit. Neither partition collapses into the other.
    ///
    /// THEORY.md §VI.1 one-oracle discipline: the exited-normally /
    /// (spawn-failure ∪ signal-killed) structural partition is named
    /// at one typed-primitive site with the exited-normally arm
    /// exposed as a typed method, not as `!cf.is_signal_killed() &&
    /// !cf.is_spawn_failure()` at every consumer. Same parallel-axis
    /// named structural-shape peer idiom commit 5c1cec1 established at
    /// the typed-error producer surface, here closing the three-way
    /// structural-shape symmetry at the retry-call-site surface.
    pub fn is_exited_normally(&self) -> bool {
        self.exit_code.is_some()
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
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        match op(attempt).await {
            Ok(v) => return Ok(v),
            Err(e) => {
                if !is_transient(&e) || policy.is_final_attempt(attempt) {
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
    /// and curl mixed-case dialects. The routing-layer kernel transient
    /// (`syscall.EHOSTUNREACH` / `no route to host`) is the structural
    /// mirror at the routing layer — the kernel emits
    /// destination-unreachable when no route matches the destination
    /// prefix at `connect()`, before any SYN leaves the host (covered
    /// by [`test_transient_classifier_matches_no_route_to_host`]).
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
    ///
    /// The structural mirror at the connect side is `timed out` — the
    /// past-tense form `syscall.ETIMEDOUT` / curl `CURLE_OPERATION_
    /// TIMEDOUT` / Python `socket.timeout` / Java `SocketTimeoutException`
    /// emit when the SYN-without-ACK kernel TCP retransmit budget is
    /// exhausted (covered by [`test_transient_classifier_matches_timed_out`]).
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

    /// Connect-side TCP retransmit-budget exhaustion (`syscall.ETIMEDOUT`)
    /// is transient — the structural mirror of `broken pipe`
    /// (mid-stream WRITE drop) at the connect phase. The bare phrase
    /// `"timed out"` is NOT covered by the `"timeout"` marker — the
    /// letters `t-i-m-e-d` then a space then `o-u-t` do not contain
    /// the contiguous `t-i-m-e-o-u-t` substring that `"timeout"`
    /// matches — so every dialect that emits the past-tense form
    /// silently short-circuited to terminal before this fix.
    ///
    /// Fail-before: the pre-fix marker set carried `"i/o timeout"` /
    /// `"TLS handshake timeout"` / `"timeout"` but not `"timed out"`,
    /// so every realistic skopeo / regctl / attic-client / curl /
    /// hyper-reqwest connect-side timeout that emitted the past-tense
    /// form short-circuited to terminal — the typed retry loop refused
    /// to back off, burning the connect attempt against a transient
    /// kernel-level event during BGP convergence / registry rollover /
    /// slow-start backpressure.
    /// Pass-after: every realistic dialect classifies transient and
    /// the shared `retry_command` / `run_with_policy` driver backs off
    /// and retries the connect.
    #[test]
    fn test_transient_classifier_matches_timed_out() {
        // Go net (skopeo, regctl, attic-server, attic-client through
        // its golang surface): `syscall.ETIMEDOUT.Error()` formats
        // lowercase `connection timed out`.
        assert!(is_transient_network_stderr(
            "dial tcp 10.0.0.1:443: connect: connection timed out"
        ));
        assert!(is_transient_network_stderr(
            "read tcp 10.0.0.1: connection timed out"
        ));
        // curl (git-over-HTTPS, container-registry probes, healthcheck
        // surfaces): `CURLE_OPERATION_TIMEDOUT` formats capitalized.
        assert!(is_transient_network_stderr(
            "curl: (7) Failed to connect to ghcr.io port 443: Connection timed out"
        ));
        assert!(is_transient_network_stderr(
            "curl: (28) Operation timed out after 30000 ms"
        ));
        assert!(is_transient_network_stderr(
            "curl: (28) Resolving timed out after 30000 ms"
        ));
        // hyper / reqwest (attic-client Rust surface) and Java /
        // jvm-style emitters that forge consumes through helm-cli,
        // kubectl, and the OpenSearch / OpenTelemetry probe shells:
        // the bare `timed out` phrase with varied leading word.
        assert!(is_transient_network_stderr(
            "error sending request for url: operation timed out"
        ));
        assert!(is_transient_network_stderr(
            "java.net.SocketTimeoutException: connect timed out"
        ));
        assert!(is_transient_network_stderr("read timed out"));
    }

    /// Go-context-layer timeout — `context.DeadlineExceeded.Error()` is
    /// retryable. Distinct layer from the kernel-TCP transients
    /// (`syscall.ETIMEDOUT` / `"timed out"`, pinned by
    /// [`test_transient_classifier_matches_timed_out`]) and from the
    /// net/http I/O budget (`"i/o timeout"` / `"TLS handshake timeout"`,
    /// pinned by [`test_transient_classifier_matches_timeouts`]): here a
    /// higher-level Go `context.WithTimeout` / `context.WithDeadline`
    /// budget elapses while a downstream operation is in flight, and the
    /// context-cancellation propagates up through every `select` on
    /// `ctx.Done()` as the same `context.DeadlineExceeded` sentinel.
    ///
    /// The dominant production transient class across forge's Go-context-
    /// fronted CLI surface: kubectl's `--request-timeout`, helm's
    /// `--timeout`, skopeo's `--command-timeout`, attic-client's
    /// per-request context budget. Production triggers: kube-apiserver
    /// election, helm release-history compaction, container-registry
    /// blob lookup against a cold object-store backend, attic-server
    /// under upload pressure — every one reconverges within the existing
    /// retry-policy budget.
    ///
    /// Fail-before: the pre-fix marker set carried `"timeout"` (substring
    /// `t-i-m-e-o-u-t` contiguous), `"timed out"` (the past-tense
    /// kernel-TCP form), `"i/o timeout"`, and `"TLS handshake timeout"`,
    /// but none of these is a substring of `"context deadline exceeded"`
    /// (the bare phrase contains neither the contiguous letters
    /// `t-i-m-e-o-u-t` nor the word `"out"` adjacent to `"timed"`). So
    /// every realistic kubectl / helm / skopeo / regctl / attic-client
    /// Go-context-timeout silently short-circuited to terminal — the
    /// typed retry loop refused to back off, burning the request against
    /// a reconvergent upstream-budget event the existing retry-policy
    /// budget covers. Pass-after: every realistic Go-context dialect
    /// classifies transient and the shared `retry_command` /
    /// `run_with_policy` driver backs off and retries.
    #[test]
    fn test_transient_classifier_matches_context_deadline_exceeded() {
        // Bare phrase — `context.DeadlineExceeded.Error()` emits this
        // verbatim across every Go binary.
        assert!(is_transient_network_stderr("context deadline exceeded"));
        // kubectl request-timeout surface — `--request-timeout` elapses
        // while waiting on the kube-apiserver response.
        assert!(is_transient_network_stderr(
            "Get \"https://10.0.0.1:6443/api/v1/namespaces/forge/pods\": context deadline exceeded"
        ));
        assert!(is_transient_network_stderr(
            "Error from server (Timeout): context deadline exceeded"
        ));
        // helm release surface — `--timeout` elapses on a slow release-
        // history compaction or chart-render path.
        assert!(is_transient_network_stderr(
            "Error: query: failed to query with labels: context deadline exceeded"
        ));
        // skopeo blob-copy surface — `--command-timeout` elapses while
        // writing a blob to a cold registry backend.
        assert!(is_transient_network_stderr(
            "writing blob: context deadline exceeded"
        ));
        // gRPC-Go status wrapper (controller-runtime watch clients) —
        // the bare phrase forwards through the gRPC status formatter.
        assert!(is_transient_network_stderr(
            "rpc error: code = DeadlineExceeded desc = context deadline exceeded"
        ));
        // attic-client through its golang surface (when invoked via the
        // golang CLI on legacy attic deployments) — the same phrase
        // forwards through an anyhow / contextual wrapper.
        assert!(is_transient_network_stderr(
            "Pushing store path /nix/store/abcd-foo: context deadline exceeded"
        ));
    }

    /// Routing-layer kernel transient — host-scope sibling
    /// (`syscall.EHOSTUNREACH`) is retryable. The kernel emits this
    /// signal at `connect()` time when no route in the local routing
    /// table matches the destination *host* prefix. Distinct from
    /// `ECONNREFUSED` (covered by `connection refused` —
    /// `test_transient_classifier_matches_connection_failures`) and
    /// from `ETIMEDOUT` (covered by `timed out` —
    /// `test_transient_classifier_matches_timed_out`): here the SYN
    /// never leaves the local kernel, where `ECONNREFUSED` requires
    /// the destination to actively reply RST and `ETIMEDOUT` requires
    /// the SYN-retransmit budget to elapse without ACK. The dominant
    /// production transient class during BGP withdraw / route-flap /
    /// VPN-tunnel renegotiation / cluster-network policy reload — the
    /// local route disappears for seconds, then reconverges; the
    /// kernel surfaces `EHOSTUNREACH` for the gap. The network-scope
    /// sibling `syscall.ENETUNREACH` / `"network is unreachable"` is
    /// pinned by [`test_transient_classifier_matches_network_is_unreachable`].
    ///
    /// Fail-before: the pre-fix marker set carried `connection
    /// refused` / `connection reset` / `connection aborted` (TCP
    /// destination-side states) and `timed out` (SYN-budget
    /// exhaustion) but no marker for `EHOSTUNREACH`. So every
    /// realistic skopeo / regctl / attic-client / curl / kubectl /
    /// helm-cli connect attempt during a route-flap silently
    /// short-circuited to terminal — the typed retry loop refused to
    /// back off, burning the connect attempt against a transient
    /// kernel-level routing event that would have reconverged within
    /// the existing retry-policy budget. Pass-after: every realistic
    /// dialect classifies transient and the shared `retry_command` /
    /// `run_with_policy` driver backs off and retries the connect.
    #[test]
    fn test_transient_classifier_matches_no_route_to_host() {
        // Go net (skopeo, regctl, attic-client through its golang
        // surface, kubectl): `syscall.EHOSTUNREACH.Error()` formats
        // lowercase as `no route to host`.
        assert!(is_transient_network_stderr(
            "dial tcp 10.0.0.1:443: connect: no route to host"
        ));
        assert!(is_transient_network_stderr("read tcp: no route to host"));
        // curl (git-over-HTTPS, container-registry probes,
        // healthcheck shells): `CURLE_COULDNT_CONNECT` formats
        // capitalized `No route to host`.
        assert!(is_transient_network_stderr(
            "curl: (7) Failed to connect to ghcr.io port 443: No route to host"
        ));
        // Java jvm (helm-cli JNI shells, jvm-backed kubectl
        // plugins): `java.net.NoRouteToHostException` carries
        // `No route to host` in its message.
        assert!(is_transient_network_stderr(
            "java.net.NoRouteToHostException: No route to host"
        ));
        // Python (`urllib3.exceptions.NewConnectionError` /
        // `socket.error`): emits `OSError: [Errno 113] No route to
        // host` through the runtime probe shells.
        assert!(is_transient_network_stderr(
            "OSError: [Errno 113] No route to host"
        ));
        // hyper / reqwest (attic-client Rust surface): `std::io::Error`
        // wrapping `io::ErrorKind::HostUnreachable` formats
        // `No route to host (os error 113)`.
        assert!(is_transient_network_stderr(
            "error sending request for url: No route to host (os error 113)"
        ));
    }

    /// Routing-layer kernel transient — network-scope sibling
    /// (`syscall.ENETUNREACH`) is retryable. The kernel emits this
    /// signal at `connect()` time when the local routing table has no
    /// route matching the destination *network* prefix at all — the
    /// mirror entry to `EHOSTUNREACH` / `"no route to host"`
    /// (pinned by [`test_transient_classifier_matches_no_route_to_host`])
    /// when the failure is at the network-row, not the host-row, of
    /// the local routing table. The dominant production trigger is
    /// the local default-route going away (VPN tunnel down, primary
    /// interface flap, kubelet network plugin reconciling) — during
    /// cluster reconcile windows the local pod's routing table loses
    /// its default route for seconds, then reconverges; the kernel
    /// surfaces `ENETUNREACH` for the gap.
    ///
    /// Fail-before: the pre-fix marker set carried `"no route to
    /// host"` / `"No route to host"` (host-scope `EHOSTUNREACH`) but
    /// no marker for the network-scope `ENETUNREACH`. So every
    /// realistic skopeo / regctl / attic-client / curl / kubectl /
    /// helm-cli connect attempt during a VPN-tunnel renegotiation
    /// or interface-toggle silently short-circuited to terminal —
    /// the typed retry loop refused to back off, burning the connect
    /// attempt against a transient kernel-level routing event that
    /// would have reconverged within the existing retry-policy
    /// budget. (The `"no route to host"` marker does not match the
    /// `"network is unreachable"` phrase — distinct phrases the
    /// kernel chooses based on which prefix-match step failed.)
    /// Pass-after: every realistic dialect classifies transient and
    /// the shared `retry_command` / `run_with_policy` driver backs
    /// off and retries the connect.
    #[test]
    fn test_transient_classifier_matches_network_is_unreachable() {
        // Go net (skopeo, regctl, attic-client through its golang
        // surface, kubectl): `syscall.ENETUNREACH.Error()` formats
        // lowercase as `network is unreachable`.
        assert!(is_transient_network_stderr(
            "dial tcp 10.0.0.1:443: connect: network is unreachable"
        ));
        assert!(is_transient_network_stderr(
            "dial tcp: lookup ghcr.io: connect: network is unreachable"
        ));
        // curl (git-over-HTTPS, container-registry probes,
        // healthcheck shells): `CURLE_COULDNT_CONNECT` formats
        // capitalized `Network is unreachable`.
        assert!(is_transient_network_stderr(
            "curl: (7) Failed to connect to ghcr.io port 443: Network is unreachable"
        ));
        // Java jvm (helm-cli JNI shells, jvm-backed kubectl
        // plugins): `java.net.SocketException` carries
        // `Network is unreachable` in its message.
        assert!(is_transient_network_stderr(
            "java.net.SocketException: Network is unreachable"
        ));
        // Python (`urllib3.exceptions.NewConnectionError` /
        // `socket.error`): emits `OSError: [Errno 101] Network is
        // unreachable` through the runtime probe shells.
        assert!(is_transient_network_stderr(
            "OSError: [Errno 101] Network is unreachable"
        ));
        // hyper / reqwest (attic-client Rust surface): `std::io::Error`
        // wrapping `io::ErrorKind::NetworkUnreachable` formats
        // `Network is unreachable (os error 101)`.
        assert!(is_transient_network_stderr(
            "error sending request for url: Network is unreachable (os error 101)"
        ));
    }

    /// Mid-stream EOF (TCP drop while a response is streaming) is transient.
    /// The bare `EOF` acronym is matched token-wise — a maximal ASCII-
    /// alphanumeric run must equal `EOF` exactly — so the legitimate
    /// Go-style `io.EOF` diagnostic still classifies in every realistic
    /// surrounding-punctuation dialect skopeo/regctl/attic/curl emit. The
    /// structural mirror on the WRITE side is `broken pipe` (covered by
    /// `test_transient_classifier_matches_broken_pipe`).
    #[test]
    fn test_transient_classifier_matches_eof() {
        // Multi-word Go form (`io.ErrUnexpectedEOF`) — substring marker.
        assert!(is_transient_network_stderr("post manifest: unexpected EOF"));
        // Bare `io.EOF` — token-wise marker, with the punctuation dialects
        // every retried CLI actually emits.
        assert!(is_transient_network_stderr("read body: EOF"));
        assert!(is_transient_network_stderr("connection terminated: EOF"));
        assert!(is_transient_network_stderr("upload aborted (EOF)"));
        assert!(is_transient_network_stderr("EOF mid-stream"));
        assert!(is_transient_network_stderr("error: EOF"));
    }

    /// Mid-stream TCP drop on WRITE (`syscall.EPIPE`) is transient — the
    /// structural mirror of `unexpected EOF` (mid-stream drop on READ).
    /// forge's pipeline is upload-heavy (image push to GHCR via skopeo /
    /// regctl, Nix store-path push to attic-server via attic-client, git
    /// push over HTTPS via curl), so this is the more commonly emitted
    /// form than `unexpected EOF`.
    ///
    /// Fail-before: the pre-fix marker set carried `unexpected EOF` but
    /// not `broken pipe`, so every realistic skopeo/regctl/attic-client/
    /// curl write-side drop short-circuited to terminal — the upload
    /// failed once and the typed retry loop refused to back off, burning
    /// the push-pipeline against a transient kernel-level TCP event.
    /// Pass-after: every realistic dialect classifies transient and the
    /// shared `retry_command` / `run_with_policy` driver backs off and
    /// retries the upload.
    #[test]
    fn test_transient_classifier_matches_broken_pipe() {
        // Go net/http (skopeo, regctl, attic-server): syscall.EPIPE
        // formats lowercase as `broken pipe`.
        assert!(is_transient_network_stderr(
            "write tcp 10.0.0.1:54321->1.2.3.4:443: broken pipe"
        ));
        assert!(is_transient_network_stderr("write: broken pipe"));
        assert!(is_transient_network_stderr(
            "Error pushing manifest: i/o error: broken pipe"
        ));
        // curl (git-over-HTTPS, container-registry probes): OpenSSL emits
        // capitalized `Broken pipe` via `SSL_write` / `Send failure`.
        assert!(is_transient_network_stderr(
            "curl: (55) OpenSSL SSL_write: Broken pipe, errno 32"
        ));
        assert!(is_transient_network_stderr("Send failure: Broken pipe"));
        // hyper / reqwest (attic-client): `std::io::Error` formats
        // capitalized `Broken pipe` through the Display impl.
        assert!(is_transient_network_stderr(
            "error sending request for url: Broken pipe (os error 32)"
        ));
    }

    /// Mid-stream HTTP-framing READ drop (hyper's
    /// `hyper::Error::IncompleteMessage`) is transient — the structural
    /// HTTP-framing-layer sibling of `unexpected EOF` (Go's TCP-level
    /// mirror, pinned by `test_transient_classifier_matches_eof`) and of
    /// `broken pipe` (the WRITE-side mirror, pinned by
    /// `test_transient_classifier_matches_broken_pipe`). Fires on the
    /// attic-client Rust surface (`reqwest` → `hyper`) when the upstream
    /// TCP connection carries partial HTTP-response bytes before sending
    /// FIN or RST without completing the `Content-Length` / chunked-
    /// transfer-encoding byte budget hyper's response decoder requires.
    ///
    /// Production triggers on forge's attic-push hot path: attic-server
    /// restart (helm rollout, pod eviction), upstream LB rolling
    /// reconciliation (cluster ingress reload, service-mesh sidecar
    /// restart), HTTP/2 GOAWAY frame from upstream before forge's PUT
    /// body drained, upstream `Keep-Alive` idle-connection eviction
    /// mid-stream. Every one is reconvergent within the existing
    /// retry-policy budget; the fail-before / pass-after seal is the
    /// hyper-specific phrase the prior Go-only `unexpected EOF` marker
    /// silently short-circuited to terminal at the Rust dialect.
    ///
    /// Fail-before: the pre-fix marker set carried `unexpected EOF`
    /// (Go's TCP-level mirror, used by skopeo / regctl / kubectl /
    /// helm-cli's Go-net surface) and `broken pipe` (WRITE-side EPIPE
    /// across dialects), but no marker for the hyper-specific HTTP-
    /// framing READ-side `IncompleteMessage` phrase. So every realistic
    /// attic-client push during an attic-server restart / upstream LB
    /// rolling reconcile / HTTP/2 GOAWAY / idle-conn eviction
    /// short-circuited to terminal — the typed retry loop refused to
    /// back off, burning the attic-push against a reconvergent upstream
    /// event the existing retry-policy budget covers. Pass-after: every
    /// realistic hyper-dialect surrounding-context wraps it and the
    /// shared `retry_command` / `run_with_policy` driver backs off and
    /// retries the push.
    #[test]
    fn test_transient_classifier_matches_connection_closed_before_message_completed() {
        // Bare hyper `Display` form — `hyper::Error::IncompleteMessage`
        // emits the lowercase phrase verbatim with no surrounding
        // context.
        assert!(is_transient_network_stderr(
            "connection closed before message completed"
        ));
        // reqwest request-error wrapping (the dominant attic-client
        // production surface) — `reqwest::Error::Request` forwards the
        // hyper source error's `Display` through its own format string.
        assert!(is_transient_network_stderr(
            "error sending request for url (https://attic.example.com/_api/v1/cache/forge/store): connection closed before message completed"
        ));
        // Surrounding-context anyhow chain (`forge`'s typed-error
        // surface formats `.context()`-wrapped errors as `outer: inner`)
        // — the hyper substring still classifies through whatever
        // outer wrapper layered on top.
        assert!(is_transient_network_stderr(
            "Pushing store path /nix/store/abcd-foo: connection closed before message completed"
        ));
        // tokio-stream / async-stream wrapper around a hyper-fronted
        // CDN probe — the same hyper substring carries through.
        assert!(is_transient_network_stderr(
            "stream error: connection closed before message completed"
        ));
    }

    /// libcurl zero-response-bytes transient — `CURLE_GOT_NOTHING`
    /// (error 52) emits the bare phrase `"Empty reply from server"`
    /// verbatim. The structural sibling at the libcurl dialect of the
    /// hyper `"connection closed before message completed"` marker
    /// (partial-response drop) and the Go-net `"unexpected EOF"`
    /// marker (also partial-response): here the upstream accepted the
    /// TCP+TLS handshake then closed without writing any HTTP
    /// response bytes. The retry semantics are strictly safer than
    /// the partial-response class — with zero application bytes
    /// exchanged, no upstream handler began processing — mirroring
    /// the RFC-9113-§6.4 `REFUSED_STREAM` safe-retry guarantee
    /// translated to the libcurl-HTTP/1.x layer.
    ///
    /// Fail-before: the pre-fix marker set carried hyper's partial-
    /// response phrase (`"connection closed before message
    /// completed"`) and Go's partial-response phrase (`"unexpected
    /// EOF"`) but no marker for the libcurl zero-bytes case at every
    /// libcurl-fronted CLI surface forge depends on (`git push` /
    /// `git fetch` / `git ls-remote` through `git-remote-https`,
    /// helm-cli's OCI surface, healthcheck shells, `git2-rs`
    /// bindings against the system libcurl). So every realistic
    /// dialect emitting `"curl: (52) Empty reply from server"` /
    /// `"fatal: unable to access 'https://github.com/...': Empty
    /// reply from server"` during a github.com / GHCR / attic-server
    /// frontend rolling-deploy window silently short-circuited to
    /// terminal — the retry loop refused to back off, burning the
    /// single attempt against a frontend reconciliation event that
    /// would have reconverged within the existing retry-policy
    /// budget. Pass-after: every realistic libcurl-fronted dialect
    /// classifies transient and the shared `retry_command` /
    /// `run_with_policy` driver backs off and retries the request.
    #[test]
    fn test_transient_classifier_matches_empty_reply_from_server() {
        // Bare curl CLI `--fail` form — `curl_easy_strerror(CURLE_GOT_NOTHING)`
        // verbatim through curl's response-error chain.
        assert!(is_transient_network_stderr(
            "curl: (52) Empty reply from server"
        ));
        // git-over-HTTPS through `git-remote-https` (the dominant
        // production surface during release-all tag/version probes
        // and source-of-truth fetches against github.com).
        assert!(is_transient_network_stderr(
            "fatal: unable to access 'https://github.com/pleme-io/forge.git/': Empty reply from server"
        ));
        // git2-rs C-binding wrapping the libcurl phrase through
        // `git2::Error::Display`'s `class=Net` decoration (forge's
        // direct git-fetch / git-ls-remote paths).
        assert!(is_transient_network_stderr(
            "failed to send request: Empty reply from server; class=Net (12)"
        ));
        // helm-cli OCI surface through oras-go's libcurl-fronted
        // transport — `helm pull oci://` / `helm push` during a
        // GHCR or attic-fronted-OCI edge reconciliation.
        assert!(is_transient_network_stderr(
            "Error: failed to do request: Empty reply from server"
        ));
        // Healthcheck shell wrapping the bare phrase with surrounding
        // shell-script context (probe shells against GHCR / attic-
        // server before the push step).
        assert!(is_transient_network_stderr(
            "readiness probe failed: Empty reply from server (curl exit 52)"
        ));
        // Bare phrase with no surrounding context — every emitter
        // that emits ONLY the strerror text classifies transient.
        assert!(is_transient_network_stderr("Empty reply from server"));
    }

    /// Git-protocol mid-stream transport drop — `git`'s `pkt-line.c::
    /// packet_read` emits the bare phrase `"the remote end hung up
    /// unexpectedly"` when the remote closes the pack-protocol stream
    /// before the pack-protocol terminator arrives. The git-protocol-
    /// specific marker at the pack-stream-receipt layer; structurally
    /// distinct from libcurl's HTTP-layer `"Empty reply from server"`
    /// (pinned by [`test_transient_classifier_matches_empty_reply_from_server`]),
    /// hyper's `"connection closed before message completed"` (pinned
    /// by [`test_transient_classifier_matches_connection_closed_before_message_completed`]),
    /// Go's `"unexpected EOF"` (pinned by
    /// [`test_transient_classifier_matches_eof`]), and the kernel-
    /// EPIPE `"broken pipe"` (pinned by
    /// [`test_transient_classifier_matches_broken_pipe`]) markers
    /// already carried.
    ///
    /// Fail-before: the pre-fix marker set carried HTTP-layer drops
    /// (libcurl zero-bytes, hyper partial-response) and kernel-layer
    /// drops (EPIPE / ECONNRESET / ECONNREFUSED) but no marker for
    /// git's own pack-protocol drop phrase. So every `git fetch` /
    /// `git push` / `git ls-remote` against github.com / the cluster-
    /// internal Gitea upstream / a corporate-proxy-fronted SSH
    /// endpoint that closed the pack-stream mid-write — without a
    /// libcurl/hyper/Go-net error having framed the drop first —
    /// silently short-circuited to terminal at the typed classifier.
    /// Pass-after: every realistic git-protocol dialect classifies
    /// transient and the shared `retry_command` / `run_with_policy`
    /// driver backs off and retries the git operation.
    #[test]
    fn test_transient_classifier_matches_remote_end_hung_up_unexpectedly() {
        // Bare git pkt-line.c phrase — emitters that forward ONLY
        // the pkt-line.c diagnostic classify transient.
        assert!(is_transient_network_stderr(
            "the remote end hung up unexpectedly"
        ));
        // git-over-HTTPS multi-line error chain with the leading
        // libcurl-HTTP-error line — the pkt-line.c phrase trails
        // after the RPC-failed banner (the HTTP-error variant where
        // libcurl framed an HTTP-status error before the pack-
        // stream drop).
        assert!(is_transient_network_stderr(
            "error: RPC failed; HTTP 502 curl 22 The requested URL returned error: 502\nfatal: the remote end hung up unexpectedly"
        ));
        // git-over-HTTPS bare TCP-drop variant — no preceding HTTP-
        // status error (the drop happened before any HTTP response
        // bytes returned, so git's pack-stream reader hits the pkt-
        // line EOF without a libcurl-status line above it).
        assert!(is_transient_network_stderr(
            "fatal: the remote end hung up unexpectedly\nfatal: protocol error: bad pack header"
        ));
        // git-over-SSH — the SSH channel closes mid-pack-write,
        // git's pkt-line.c emits the same phrase regardless of
        // transport.
        assert!(is_transient_network_stderr(
            "Connection to ssh.github.com closed by remote host.\nfatal: the remote end hung up unexpectedly"
        ));
        // git2-rs C-binding wrapping the pkt-line phrase through
        // `git2::Error::Display`'s `class=Net` decoration (forge's
        // direct `git2`-fronted operations against the system
        // libcurl).
        assert!(is_transient_network_stderr(
            "the remote end hung up unexpectedly; class=Net (12)"
        ));
        // index-pack subprocess wrapping the pkt-line.c phrase —
        // the bare-EOF early diagnostic when present would also
        // classify via the `"EOF"` token marker, but the load-
        // bearing signal here is the pkt-line.c phrase for the
        // cases where index-pack does not emit the bare-EOF line.
        assert!(is_transient_network_stderr(
            "fatal: the remote end hung up unexpectedly\nfatal: index-pack failed"
        ));
        // Surrounding-context anyhow chain (`forge`'s typed-error
        // surface formats `.context()`-wrapped errors as
        // `outer: inner`) — the git substring still classifies
        // through whatever outer wrapper layered on top.
        assert!(is_transient_network_stderr(
            "Pushing GitOps manifest to origin: the remote end hung up unexpectedly"
        ));
    }

    /// DNS-resolver transient — `getaddrinfo(3)` `EAI_AGAIN` (glibc -3)
    /// is retryable. Distinct layer from the kernel-routing transients
    /// (`syscall.ENETUNREACH` / `EHOSTUNREACH`, pinned by
    /// [`test_transient_classifier_matches_network_is_unreachable`] /
    /// [`test_transient_classifier_matches_no_route_to_host`]) and from
    /// the TCP-state transients (`ECONNREFUSED` / `ECONNRESET`, pinned
    /// by [`test_transient_classifier_matches_connection_failures`]):
    /// here the resolver upstream (typically cluster coredns / glibc's
    /// nss-dns over the configured `/etc/resolv.conf` nameserver list)
    /// fails to return a verdict within the resolver-side budget. The
    /// dominant production trigger is cluster coredns reloading its
    /// corefile (kubectl apply on the coredns configmap, node-local-dns
    /// reconciliation, or upstream resolver flap) — the resolver
    /// returns transient-fail within seconds; the next probe succeeds.
    ///
    /// Distinct from `EAI_NONAME` / `"Name or service not known"` (a
    /// permanent NXDOMAIN verdict from the resolver) and from
    /// `EAI_NODATA` (record-type miss) — `EAI_AGAIN`'s leading
    /// `"Temporary"` word carries the transient verdict on its face.
    /// The marker set deliberately does NOT include the NXDOMAIN
    /// phrase: retrying a deterministic-deny would burn budget against
    /// a permanent resolver verdict, the dual anti-pattern of the EOF
    /// false-positive `8952b9a` closed.
    ///
    /// Fail-before: the pre-fix marker set carried connection-layer
    /// (`refused` / `reset` / `aborted`), routing-layer (`no route to
    /// host` / `network is unreachable`), connect-timeout (`timed
    /// out`), and stream-drop (`unexpected EOF` / `broken pipe`)
    /// markers but no marker for the DNS-resolver transient at the
    /// layer above kernel routing. So every realistic skopeo / regctl
    /// / attic-client / curl / kubectl / helm-cli / git probe during a
    /// coredns reload or upstream-resolver flap silently
    /// short-circuited to terminal — the typed retry loop refused to
    /// back off, burning the connect attempt against a transient
    /// resolver-side event that would have reconverged within the
    /// existing retry-policy budget. Pass-after: every realistic
    /// dialect classifies transient and the shared `retry_command` /
    /// `run_with_policy` driver backs off and retries the lookup.
    #[test]
    fn test_transient_classifier_matches_temporary_dns_failure() {
        // glibc strerror surface (every curl/skopeo/regctl/attic-client/
        // kubectl/helm-cli/git on standard distros): emits the bare
        // `gai_strerror(EAI_AGAIN)` phrase verbatim.
        assert!(is_transient_network_stderr(
            "Temporary failure in name resolution"
        ));
        // Go net (skopeo, regctl, attic-client through its golang
        // surface, kubectl, helm-cli's discovery shells): the resolver
        // wraps the strerror through the `net.DNSError` formatter.
        assert!(is_transient_network_stderr(
            "lookup ghcr.io on 169.254.169.254:53: Temporary failure in name resolution"
        ));
        // curl (git-over-HTTPS, container-registry probes, healthcheck
        // surfaces): `CURLE_COULDNT_RESOLVE_HOST` forwards the strerror.
        assert!(is_transient_network_stderr(
            "curl: (6) Could not resolve host: ghcr.io: Temporary failure in name resolution"
        ));
        // Python (`socket.gaierror` raised by `urllib3` / `requests` /
        // `httpx` / the runtime probe shells): emits the bracketed-
        // errno form.
        assert!(is_transient_network_stderr(
            "socket.gaierror: [Errno -3] Temporary failure in name resolution"
        ));
        // hyper / reqwest (attic-client Rust surface): the resolver
        // forwards a `std::io::Error` whose Display impl includes the
        // same substring.
        assert!(is_transient_network_stderr(
            "error sending request for url: Temporary failure in name resolution"
        ));
    }

    /// `EAI_NONAME` / `"Name or service not known"` is a PERMANENT
    /// NXDOMAIN verdict from the resolver — not retryable. Pinning the
    /// fail-fast verdict explicitly is the load-bearing test: if a
    /// future marker is added that swallows the NXDOMAIN phrase, the
    /// regression shows up here, not in production via burned retry
    /// budget against a deterministic-deny resolver verdict. This is
    /// the dual anti-pattern of the EOF false-positive `8952b9a` closed
    /// — the marker `"Temporary failure in name resolution"` matches
    /// only the explicitly-transient `EAI_AGAIN` phrase, not the
    /// permanent `EAI_NONAME` phrase whose record genuinely does not
    /// exist.
    #[test]
    fn test_transient_classifier_nxdomain_is_terminal() {
        // glibc strerror (`gai_strerror(EAI_NONAME)`) — terminal.
        assert!(!is_transient_network_stderr("Name or service not known"));
        // Go net DNSError wrapping the strerror — terminal.
        assert!(!is_transient_network_stderr(
            "lookup typo-host.example.invalid on 169.254.169.254:53: no such host"
        ));
        // Python `socket.gaierror` — terminal.
        assert!(!is_transient_network_stderr(
            "socket.gaierror: [Errno -2] Name or service not known"
        ));
        // curl `CURLE_COULDNT_RESOLVE_HOST` carrying the strerror —
        // terminal. The leading `Could not resolve host` substring is
        // deliberately not a marker because curl uses it for both
        // permanent (NXDOMAIN) and transient (EAI_AGAIN) verdicts; only
        // the trailing strerror disambiguates, and only the
        // `Temporary failure` strerror is matched as transient.
        assert!(!is_transient_network_stderr(
            "curl: (6) Could not resolve host: typo.example.invalid"
        ));
    }

    /// HTTP/2 graceful-shutdown transient — Go net/http2's
    /// `http2.GoAwayError` is retryable. RFC 9113 §6.8 names the
    /// contract: a GOAWAY frame is the upstream's "draining; you may
    /// retry on a new connection" signal, and the dominant production
    /// shape (`ErrCode=NO_ERROR`) is unambiguously transient. Distinct
    /// layer from the kernel-TCP transients (`syscall.ETIMEDOUT` /
    /// `"timed out"`, pinned by
    /// [`test_transient_classifier_matches_timed_out`]), from the
    /// HTTP/1-framing-layer transient (hyper's
    /// `"connection closed before message completed"`, pinned by
    /// [`test_transient_classifier_matches_connection_closed_before_message_completed`]),
    /// and from the Go-context-layer transient (`context.Deadline
    /// Exceeded` / `"context deadline exceeded"`, pinned by
    /// [`test_transient_classifier_matches_context_deadline_exceeded`]):
    /// here the upstream HTTP/2 peer sends a structured GOAWAY frame
    /// before closing the TCP connection, distinct from the raw TCP-
    /// EOF the prior markers cover, and Go's HTTP/2 client forwards
    /// that signal through its own typed error class with the
    /// distinctive `"http2: server sent GOAWAY"` phrase.
    ///
    /// Fail-before: the pre-fix marker set carried connection-layer
    /// (`refused` / `reset` / `aborted`), routing-layer (`no route to
    /// host` / `network is unreachable`), connect-timeout (`timed
    /// out`), DNS (`Temporary failure in name resolution`),
    /// HTTP/1-framing (`unexpected EOF` / `broken pipe` /
    /// `connection closed before message completed`), and Go-context-
    /// layer (`context deadline exceeded`) markers but no marker for
    /// the HTTP/2 graceful-shutdown transient at the layer above kernel
    /// TCP. So every realistic kubectl / helm-cli / skopeo / regctl /
    /// attic-client probe during a kube-apiserver rolling restart,
    /// GHCR backend rotation, or attic-server scale event silently
    /// short-circuited to terminal — the typed retry loop refused to
    /// back off, burning the attempt against a transient HTTP/2
    /// graceful-shutdown event that would have reconverged within
    /// the existing retry-policy budget. Pass-after: every realistic
    /// Go-net/http2 dialect classifies transient and the shared
    /// `retry_command` / `run_with_policy` driver backs off and
    /// retries on a fresh connection.
    #[test]
    fn test_transient_classifier_matches_http2_server_sent_goaway() {
        // Bare `http2.GoAwayError.Error()` prefix — Go's HTTP/2 client
        // emits this verbatim across every Go-net/http2-fronted CLI.
        assert!(is_transient_network_stderr(
            "http2: server sent GOAWAY and closed the connection; LastStreamID=137, ErrCode=NO_ERROR, debug=\"\""
        ));
        // kubectl rolling-restart surface — kube-apiserver pod deletion
        // during control-plane upgrade or watch-cache compaction sends
        // GOAWAY to drain long-poll clients; the bare phrase forwards
        // through `Transport.RoundTrip`'s error wrap.
        assert!(is_transient_network_stderr(
            "Get \"https://10.0.0.1:6443/api/v1/namespaces/forge/pods\": http2: server sent GOAWAY and closed the connection; LastStreamID=33, ErrCode=NO_ERROR, debug=\"\""
        ));
        // skopeo blob-copy surface — GHCR backend rotation sends GOAWAY
        // mid-blob-upload; the Go-net/http2 client surfaces it through
        // the registry-write error wrap.
        assert!(is_transient_network_stderr(
            "writing blob: http2: server sent GOAWAY and closed the connection; LastStreamID=5, ErrCode=NO_ERROR, debug=\"\""
        ));
        // regctl manifest-fetch surface — same GHCR shape on the
        // read path.
        assert!(is_transient_network_stderr(
            "regctl: failed to fetch manifest: http2: server sent GOAWAY and closed the connection; LastStreamID=1, ErrCode=NO_ERROR, debug=\"\""
        ));
        // helm-cli release-status surface — kube-apiserver GOAWAY
        // forwards through the discovery-client wrap.
        assert!(is_transient_network_stderr(
            "Error: query: failed to query with labels: http2: server sent GOAWAY and closed the connection; LastStreamID=7, ErrCode=NO_ERROR, debug=\"\""
        ));
        // gRPC-Go status wrapper — controller-runtime long-poll
        // watch clients propagate the GOAWAY through the gRPC
        // status formatter.
        assert!(is_transient_network_stderr(
            "rpc error: code = Unavailable desc = transport is closing; http2: server sent GOAWAY and closed the connection; LastStreamID=11, ErrCode=NO_ERROR, debug=\"\""
        ));
        // GOAWAY with a non-empty `debug` field — production
        // upstreams sometimes attach a short reason string; the
        // marker substring is at the front so the trailing
        // `debug` payload is irrelevant to classification.
        assert!(is_transient_network_stderr(
            "http2: server sent GOAWAY and closed the connection; LastStreamID=1, ErrCode=NO_ERROR, debug=\"graceful shutdown\""
        ));
    }

    /// HTTP/2 client-side connection-lost transient — Go net/http2's
    /// `errClientConnLost` is retryable. The client-side mirror of
    /// the server-initiated GOAWAY drain signal: distinct from
    /// `"http2: server sent GOAWAY"` (server gracefully signals
    /// drain via RFC 9113 §6.8 frame, pinned by
    /// [`test_transient_classifier_matches_http2_server_sent_goaway`]),
    /// from the HTTP/1-framing transient (hyper's
    /// `"connection closed before message completed"`, pinned by
    /// [`test_transient_classifier_matches_connection_closed_before_message_completed`]),
    /// and from the TCP-EOF transient (`"unexpected EOF"`, pinned
    /// by [`test_transient_classifier_matches_eof`]): here the Go
    /// HTTP/2 client detects the underlying connection is dead
    /// without an upstream GOAWAY frame — typically an abrupt
    /// upstream-pod SIGKILL, a cluster-network-policy reconcile
    /// tearing down the established connection, or an HTTP/2
    /// keep-alive ping-timeout firing on a silently-dropped TCP
    /// link.
    ///
    /// Fail-before: the pre-fix marker set carried the server-
    /// initiated `"http2: server sent GOAWAY"` graceful-shutdown
    /// signal but no marker for the client-side abrupt-loss
    /// signal — every realistic kubectl / helm-cli / skopeo /
    /// regctl / attic-client probe against a kube-apiserver pod
    /// killed by node-eviction / OOM / forced control-plane
    /// upgrade, or a GHCR / attic-server pod that lost its
    /// HTTP/2 connection to a cluster-network-policy reconcile,
    /// silently short-circuited to terminal — the typed retry
    /// loop refused to back off, burning the attempt against a
    /// transient connection-loss event that would have
    /// reconverged on a fresh connection within the existing
    /// retry-policy budget. Pass-after: every realistic
    /// Go-net/http2 dialect classifies transient and the shared
    /// `retry_command` / `run_with_policy` driver backs off and
    /// retries on a fresh connection.
    #[test]
    fn test_transient_classifier_matches_http2_client_connection_lost() {
        // Bare `errClientConnLost.Error()` phrase — Go's HTTP/2
        // client emits this verbatim when its underlying
        // `(*ClientConn)` detects the TCP transport is dead without
        // a GOAWAY frame.
        assert!(is_transient_network_stderr("http2: client connection lost"));
        // kubectl surface against a kube-apiserver pod that was
        // SIGKILL'd mid-request (node-eviction, OOM, or forced
        // control-plane upgrade) — the typed-error wrap forwards
        // the bare phrase through `Transport.RoundTrip`'s chain.
        assert!(is_transient_network_stderr(
            "Get \"https://10.0.0.1:6443/api/v1/namespaces/forge/pods\": http2: client connection lost"
        ));
        // skopeo blob-copy surface — GHCR pod abrupt-loss
        // mid-blob-upload; the Go-net/http2 client surfaces it
        // through the registry-write error wrap.
        assert!(is_transient_network_stderr(
            "writing blob: http2: client connection lost"
        ));
        // regctl manifest-fetch surface — same GHCR shape on the
        // read path.
        assert!(is_transient_network_stderr(
            "regctl: failed to fetch manifest: http2: client connection lost"
        ));
        // helm-cli release-status surface — kube-apiserver
        // connection-loss forwards through the discovery-client
        // wrap.
        assert!(is_transient_network_stderr(
            "Error: query: failed to query with labels: http2: client connection lost"
        ));
        // gRPC-Go status wrapper — controller-runtime long-poll
        // watch clients propagate the connection-loss through the
        // gRPC status formatter.
        assert!(is_transient_network_stderr(
            "rpc error: code = Unavailable desc = transport is closing; http2: client connection lost"
        ));
        // attic-client golang surface against attic-server fronted
        // by a cluster ingress — the bare phrase forwards through
        // the anyhow chain.
        assert!(is_transient_network_stderr(
            "pushing store path: http2: client connection lost"
        ));
    }

    /// Go-net stdlib `net.ErrClosed` — local-side connection-close
    /// race transient is retryable. Distinct from the five remote-
    /// initiated Go-net connection-loss markers already pinned:
    /// `"http2: server sent GOAWAY"` (server-initiated graceful
    /// drain, pinned by
    /// [`test_transient_classifier_matches_http2_server_sent_goaway`]),
    /// `"http2: client connection lost"` (client-detected abrupt
    /// remote loss, pinned by
    /// [`test_transient_classifier_matches_http2_client_connection_lost`]),
    /// `"connection reset"` / `"connection refused"` (kernel-RST /
    /// refusal, pinned by
    /// [`test_transient_classifier_matches_connection_failures`]),
    /// and `"broken pipe"` / `"unexpected EOF"` (kernel-EPIPE /
    /// EOF, pinned by
    /// [`test_transient_classifier_matches_broken_pipe`] /
    /// [`test_transient_classifier_matches_eof`]): here LOCAL code
    /// (the parent `context.WithCancel`'s cleanup, a sibling
    /// goroutine's `Transport.CloseIdleConnections`, a shared
    /// HTTP/2 transport's idle-connection sweep) closed the file
    /// descriptor before this goroutine's read/write reached it.
    ///
    /// Fail-before: the pre-fix marker set carried every REMOTE-
    /// initiated Go-net connection-loss form (GOAWAY,
    /// `errClientConnLost`, ECONNRESET, EPIPE, EOF) but no marker
    /// for the local-close mirror (`net.ErrClosed`). So every
    /// realistic kubectl / helm-cli / skopeo / regctl / attic-
    /// client probe whose context-cancellation cleanup raced a
    /// stale goroutine on the shared HTTP/2 transport silently
    /// short-circuited to terminal — the typed retry loop refused
    /// to back off, burning the request against a local-cleanup
    /// race that would have reconverged on a fresh connection
    /// within the existing retry-policy budget. Pass-after:
    /// every realistic Go-net dialect classifies transient and
    /// the shared `retry_command` / `run_with_policy` driver
    /// backs off and retries on a fresh connection.
    #[test]
    fn test_transient_classifier_matches_use_of_closed_network_connection() {
        // Bare `net.ErrClosed.Error()` phrase — Go's stdlib emits
        // this verbatim across every binary.
        assert!(is_transient_network_stderr(
            "use of closed network connection"
        ));
        // kubectl long-poll watch surface — the parent
        // `context.WithTimeout`'s cleanup tore down the shared
        // HTTP/2 transport while a stale watch goroutine was
        // still reading.
        assert!(is_transient_network_stderr(
            "Get \"https://10.0.0.1:6443/api/v1/watch/namespaces/forge/pods\": use of closed network connection"
        ));
        // skopeo concurrent blob-upload surface — a sibling
        // goroutine's `Transport.CloseIdleConnections` closed
        // the shared transport mid-write.
        assert!(is_transient_network_stderr(
            "writing blob: use of closed network connection"
        ));
        // regctl manifest-fetch surface — same shape on the read
        // path against a GHCR connection torn down by a sibling.
        assert!(is_transient_network_stderr(
            "regctl: failed to fetch manifest: use of closed network connection"
        ));
        // helm-cli release-status surface — kube-apiserver
        // discovery shell's HTTP/2 transport reset during
        // context-cancellation cleanup.
        assert!(is_transient_network_stderr(
            "Error: query: failed to query with labels: use of closed network connection"
        ));
        // gRPC-Go controller-runtime watch clients — the bare
        // phrase forwards through the gRPC status formatter.
        assert!(is_transient_network_stderr(
            "rpc error: code = Unavailable desc = transport is closing; use of closed network connection"
        ));
        // attic-client golang surface against attic-server fronted
        // by a cluster ingress — parallel store-path push races a
        // shared-transport reset during ingress rolling restart.
        assert!(is_transient_network_stderr(
            "Pushing store path /nix/store/abcd-foo: use of closed network connection"
        ));
    }

    /// The bare phrase `"closed network connection"` (without the
    /// leading `"use of "` qualifier) is NOT a transient marker on
    /// its own — only the qualified `"use of closed network
    /// connection"` phrase is matched. Pinning the false-positive
    /// guard explicitly is the load-bearing test: if a future
    /// marker is added that swallows the bare `"closed network"` /
    /// `"closed network connection"` substring, the regression
    /// shows up here, not in production via burned retry budget
    /// against a CNI reconcile log line, a closed-network-policy
    /// kube event, or an unrelated subsystem's `"closed network"`
    /// diagnostic. Same dual anti-pattern the bare-`"connection
    /// lost"` and bare-`"GOAWAY"` false-positive guards close for
    /// the prior HTTP/2 markers, here applied to the bare
    /// `"closed network"` phrase.
    #[test]
    fn test_transient_classifier_bare_closed_network_is_not_a_marker() {
        // Bare `"closed network connection"` phrase without the
        // `"use of "` qualifier — could appear in a CNI
        // reconciliation log line, an ingress-controller
        // teardown notice, or an unrelated subsystem diagnostic.
        // Not a transient signal on its own at this oracle.
        assert!(!is_transient_network_stderr(
            "Event: cni reconcile: closed network connection slot for pod foo: 403 Forbidden"
        ));
        // A `"closed network"` substring buried inside a
        // network-policy kube event message that's otherwise
        // terminal — the unqualified substring would catch this,
        // the qualified phrase does not.
        assert!(!is_transient_network_stderr(
            "Event: NetworkPolicy reconcile: closed network egress to ghcr.io: 401 Unauthorized"
        ));
    }

    /// HTTP/2 stream-level explicit-retry signal — RFC 9113 §6.4
    /// `REFUSED_STREAM` (ErrCode 0x7) classifies transient. The RFC
    /// itself names the contract: "Any request that was sent on the
    /// reset stream can be safely retried." This is the one HTTP/2
    /// ErrCode the spec unconditionally classifies as safe-retry at
    /// the protocol layer, regardless of the request's own
    /// idempotency — because no application processing happened.
    /// Distinct from the prior HTTP/2 markers already pinned:
    /// `"http2: server sent GOAWAY"` (CONNECTION-level drain, pinned
    /// by [`test_transient_classifier_matches_http2_server_sent_goaway`])
    /// and `"http2: client connection lost"` (TRANSPORT-level abrupt
    /// loss, pinned by
    /// [`test_transient_classifier_matches_http2_client_connection_lost`]):
    /// here the connection is healthy but THIS specific stream was
    /// refused (per-connection `SETTINGS_MAX_CONCURRENT_STREAMS`
    /// budget hit, upstream worker-pool exhausted at receipt time,
    /// backend-affinity hash routed the stream to a draining pod).
    ///
    /// Fail-before: the pre-fix marker set carried both
    /// CONNECTION-level GOAWAY and TRANSPORT-level
    /// `errClientConnLost` HTTP/2 transients but no marker for the
    /// STREAM-level explicit-retry signal — every realistic kubectl /
    /// helm-cli / skopeo / regctl probe whose stream was refused by
    /// kube-apiserver / GHCR / attic-server under load silently
    /// short-circuited to terminal, the typed retry loop refused to
    /// back off, the request burned against the one HTTP/2 signal
    /// the RFC itself names as safely retryable. Pass-after: every
    /// realistic Go-net/http2 dialect classifies transient and the
    /// shared `retry_command` / `run_with_policy` driver backs off
    /// and opens a fresh stream against the healthy multiplexed
    /// connection.
    #[test]
    fn test_transient_classifier_matches_refused_stream() {
        // Bare `http2.ErrCodeRefusedStream.String()` token — the
        // RFC-defined uppercase ErrCode name forwards through every
        // emitter's status formatter verbatim.
        assert!(is_transient_network_stderr("REFUSED_STREAM"));
        // Go net/http2 `StreamError.Error()` formatted phrase —
        // wraps the bare ErrCode name with the stream-error
        // formatter prefix and stream ID.
        assert!(is_transient_network_stderr(
            "stream error: stream ID 137; REFUSED_STREAM"
        ));
        // kubectl surface against kube-apiserver under burst load
        // — per-connection `MaxConcurrentStreams` budget hit during
        // mass-watch reconciliation, the typed-error wrap forwards
        // the stream-error phrase through `Transport.RoundTrip`'s
        // chain.
        assert!(is_transient_network_stderr(
            "Get \"https://10.0.0.1:6443/api/v1/namespaces/forge/pods\": stream error: stream ID 137; REFUSED_STREAM"
        ));
        // skopeo concurrent blob-upload surface — GHCR's edge tier
        // RST_STREAMs the (N+1)th concurrent blob upload past the
        // per-connection stream budget; the registry-write error
        // wrap forwards the phrase.
        assert!(is_transient_network_stderr(
            "writing blob: stream error: stream ID 5; REFUSED_STREAM"
        ));
        // regctl manifest-fetch surface — same GHCR shape on the
        // read path against a connection whose stream budget was
        // exhausted by a parallel push goroutine.
        assert!(is_transient_network_stderr(
            "regctl: failed to fetch manifest: stream error: stream ID 9; REFUSED_STREAM"
        ));
        // helm-cli release-status surface — kube-apiserver
        // discovery shell's HTTP/2 stream pool exhausted during
        // controller-runtime watch storm.
        assert!(is_transient_network_stderr(
            "Error: query: failed to query with labels: stream error: stream ID 33; REFUSED_STREAM"
        ));
        // gRPC-Go controller-runtime watch clients — the bare token
        // forwards through the gRPC status formatter; this is the
        // dominant production surface since each watch holds a
        // stream for the watch's lifetime.
        assert!(is_transient_network_stderr(
            "rpc error: code = Unavailable desc = stream error: stream ID 25; REFUSED_STREAM"
        ));
        // attic-client Rust h2 surface — `h2::Reason::REFUSED_STREAM`
        // formats through the `Display` impl wrapped through
        // reqwest's request-error chain.
        assert!(is_transient_network_stderr(
            "error sending request for url (https://attic.forge.example.com/_api/v1/cache/forge): connection error: REFUSED_STREAM"
        ));
    }

    /// Go net/http `(*Client).Timeout` budget exhaustion — `net/http/
    /// client.go`'s deadline-firing path emits the bare phrase
    /// `"Client.Timeout exceeded while awaiting headers"` (HEADERS-
    /// phase budget elapsed; the dominant production form) or
    /// `"Client.Timeout exceeded while reading body"` (body-read-
    /// phase budget elapsed). Both forms share the load-bearing
    /// `"Client.Timeout exceeded"` prefix; both classify transient.
    /// Distinct layer from the four prior timeout markers already
    /// pinned: `"context deadline exceeded"` (Go-context-layer,
    /// pinned by
    /// [`test_transient_classifier_matches_context_deadline_exceeded`]),
    /// `"i/o timeout"` / `"TLS handshake timeout"` / `"timeout"`
    /// (Go-net socket-layer / TLS-handshake / generic, pinned by
    /// [`test_transient_classifier_matches_timeouts`]), and
    /// `"timed out"` (kernel-`syscall.ETIMEDOUT` connect-side, pinned
    /// by [`test_transient_classifier_matches_timed_out`]). The
    /// `Client.Timeout` budget is the `http.Client` struct field's
    /// named deadline — distinct from `context.WithTimeout` (context-
    /// layer cancellation propagating through `ctx.Done()`) and from
    /// the underlying socket I/O budget (`net.Error.Timeout()` at
    /// the `(*conn).Read` boundary).
    ///
    /// Fail-before: the pre-fix marker set carried context-layer,
    /// socket-layer, TLS-handshake-layer, and kernel-TCP-layer
    /// timeout markers but no marker for the Go-net/http Client-
    /// layer budget. The case-sensitive `.contains()` check meant
    /// the existing `"timeout"` substring marker did NOT catch
    /// `"Client.Timeout exceeded while awaiting headers"` (the
    /// capital-`T` `Timeout` identifier vs the lowercase `timeout`
    /// substring) — so every realistic kubectl `--request-timeout` /
    /// helm-cli `--timeout` / skopeo `--command-timeout` / regctl
    /// `--request-timeout` budget exhaustion against a slow kube-
    /// apiserver / slow GHCR edge / slow attic-server golang surface
    /// silently short-circuited to terminal. The typed retry loop
    /// refused to back off, burning the single attempt against a
    /// transient slow-HEADERS event that would have reconverged
    /// within the existing retry-policy budget. Pass-after: every
    /// realistic Go-net/http dialect classifies transient and the
    /// shared `retry_command` / `run_with_policy` driver backs off
    /// and retries on a fresh request against a non-congested
    /// upstream.
    #[test]
    fn test_transient_classifier_matches_client_timeout_exceeded() {
        // Bare `Client.Timeout exceeded while awaiting headers`
        // phrase — emitters that forward ONLY the net/http
        // client-error diagnostic classify transient.
        assert!(is_transient_network_stderr(
            "Client.Timeout exceeded while awaiting headers"
        ));
        // Bare `Client.Timeout exceeded while reading body` sibling
        // — body-read-phase budget elapsed, same `Client.Timeout
        // exceeded` prefix shared with the headers variant.
        assert!(is_transient_network_stderr(
            "Client.Timeout exceeded while reading body"
        ));
        // Go net/http full error chain — `(*Client).do` wraps the
        // Client.Timeout-elapsed verdict through the
        // `net/http: request canceled (…)` formatter against an
        // outer `Get "<url>":` prefix.
        assert!(is_transient_network_stderr(
            "Get \"https://10.0.0.1:6443/api/v1/namespaces/forge/pods\": net/http: request canceled (Client.Timeout exceeded while awaiting headers)"
        ));
        // kubectl `--request-timeout` exhaustion against slow kube-
        // apiserver during a control-plane election (the elected
        // apiserver is rebuilding watch-cache, per-request HEADERS
        // latency spikes past kubectl's budget).
        assert!(is_transient_network_stderr(
            "error: Get \"https://kube-apiserver/api/v1/pods\": net/http: request canceled (Client.Timeout exceeded while awaiting headers)"
        ));
        // skopeo concurrent blob-upload / manifest-fetch — GHCR's
        // edge tier delays HEADERS on a manifest GET during a
        // backend rebalance window past skopeo's `--command-timeout`.
        assert!(is_transient_network_stderr(
            "Get \"https://ghcr.io/v2/pleme-io/forge/manifests/sha256:abcd\": net/http: request canceled (Client.Timeout exceeded while awaiting headers)"
        ));
        // regctl manifest-fetch surface — same GHCR-slow-HEADERS
        // shape on the read path against regctl's per-request
        // budget.
        assert!(is_transient_network_stderr(
            "regctl: failed to fetch manifest: net/http: request canceled (Client.Timeout exceeded while awaiting headers)"
        ));
        // helm-cli release-status surface — `helm list` against
        // kube-apiserver where the release-history compaction
        // blocks the discovery shell past helm-cli's `--timeout`.
        assert!(is_transient_network_stderr(
            "Error: query: failed to query with labels: Get \"https://kube-apiserver/api/v1/namespaces/forge/secrets\": net/http: request canceled (Client.Timeout exceeded while awaiting headers)"
        ));
        // gRPC-Go status wrapper — controller-runtime watch clients
        // propagate the Client.Timeout-elapsed verdict through the
        // gRPC status formatter as `code = DeadlineExceeded`.
        assert!(is_transient_network_stderr(
            "rpc error: code = DeadlineExceeded desc = Client.Timeout exceeded while awaiting headers"
        ));
        // attic-client golang surface — when forge invokes attic
        // through its golang CLI wrapper rather than the Rust
        // client, the per-request budget exhaustion forwards
        // through the typed-error chain.
        assert!(is_transient_network_stderr(
            "Pushing store path /nix/store/abcd-foo: net/http: request canceled (Client.Timeout exceeded while awaiting headers)"
        ));
        // Body-read variant in production context — attic-fetch
        // where the server began streaming response bytes then
        // stalled past the per-request budget.
        assert!(is_transient_network_stderr(
            "Get \"https://attic.forge.example.com/_api/v1/cache/forge/abcd\": net/http: request canceled (Client.Timeout exceeded while reading body)"
        ));
    }

    /// The bare phrase `"Timeout exceeded"` (without the leading
    /// `"Client.Timeout"` qualifier) is NOT a transient marker on
    /// its own — only the qualified `"Client.Timeout exceeded"`
    /// phrase is matched. Pinning the false-positive guard
    /// explicitly is the load-bearing test: if a future marker is
    /// added that swallows the bare `"Timeout exceeded"` substring,
    /// the regression shows up here, not in production via burned
    /// retry budget against a kube-event message describing a
    /// permanent readiness verdict, an HPA scaling-decision log
    /// describing a permanent deadline verdict, or an unrelated
    /// subsystem's bare-`"Timeout exceeded"` diagnostic. Same dual
    /// anti-pattern the bare-`"connection lost"` / bare-`"closed
    /// network"` / bare-`"GOAWAY"` false-positive guards close for
    /// the prior HTTP/2 / Go-net markers, here applied to the bare
    /// `"Timeout exceeded"` phrase.
    #[test]
    fn test_transient_classifier_bare_timeout_exceeded_is_not_a_marker() {
        // Bare `"Timeout exceeded"` phrase without the
        // `"Client.Timeout"` qualifier — could appear in a kube-
        // event message describing a permanent PodReady verdict,
        // an HPA scaling-decision log line, or an unrelated
        // subsystem diagnostic. Not a transient signal on its
        // own at this oracle.
        assert!(!is_transient_network_stderr(
            "Event: PodReady Timeout exceeded for pod forge-runner: ImagePullBackOff"
        ));
        // A `"Timeout exceeded"` phrase buried inside an HPA
        // event message that's otherwise terminal — the
        // unqualified substring would catch this, the qualified
        // phrase does not.
        assert!(!is_transient_network_stderr(
            "Event: ScalingActiveTimeout: ScaleUp Timeout exceeded: 403 Forbidden quota exceeded"
        ));
    }

    /// Adjacent HTTP/2 ErrCode names whose retry semantics are NOT
    /// safe at the protocol layer are NOT matched — only
    /// `REFUSED_STREAM` (RFC 9113 §6.4: "can be safely retried")
    /// classifies transient. Pinning the per-ErrCode discipline
    /// explicitly is the load-bearing test: if a future marker is
    /// added that swallows the broader `"stream error:"` prefix, a
    /// `PROTOCOL_ERROR` (client misbehaved, terminal) or
    /// `CANCEL` (request explicitly cancelled, terminal at this
    /// surface) ErrCode would silently get retried, burning budget
    /// against a permanent verdict the RFC does NOT classify as
    /// safe-retry. The strict-RFC-§6.4-only discipline keeps the
    /// transient classification aligned with the one ErrCode the
    /// spec itself names as protocol-layer safe.
    #[test]
    fn test_transient_classifier_other_stream_errors_are_not_markers() {
        // `PROTOCOL_ERROR` (ErrCode 0x1) — RFC 9113 §7: "The
        // endpoint detected an unspecific protocol error." The
        // client misbehaved; retrying cannot help.
        assert!(!is_transient_network_stderr(
            "stream error: stream ID 3; PROTOCOL_ERROR"
        ));
        // `INTERNAL_ERROR` (ErrCode 0x2) — RFC 9113 §7: "The
        // endpoint encountered an unexpected internal error."
        // Could be an upstream bug class; the RFC does NOT
        // classify as safe-retry at the protocol layer. The
        // GOAWAY-marker commit deferred this ErrCode for the same
        // reason; the same discipline applies at the stream
        // surface.
        assert!(!is_transient_network_stderr(
            "stream error: stream ID 7; INTERNAL_ERROR"
        ));
        // `CANCEL` (ErrCode 0x8) — RFC 9113 §7: "Used by the
        // endpoint to indicate that the stream is no longer
        // needed." Request was explicitly cancelled (typically by
        // a parent `context.WithCancel`); retrying re-races the
        // same cancellation.
        assert!(!is_transient_network_stderr(
            "stream error: stream ID 11; CANCEL"
        ));
        // `ENHANCE_YOUR_CALM` (ErrCode 0xb) — RFC 9113 §7: "The
        // endpoint detected that its peer is exhibiting a behavior
        // that might be generating excessive load." This is a
        // rate-limit signal but at the HTTP/2-frame layer rather
        // than the HTTP-429 layer; the existing rate-limit retry
        // surface routes through the HTTP-429 status code, and
        // retrying immediately against an ENHANCE_YOUR_CALM frame
        // would worsen the upstream's pressure verdict. Not a
        // transient signal at this oracle (would belong on a
        // back-pressure-aware retry surface, not the substring
        // classifier).
        assert!(!is_transient_network_stderr(
            "stream error: stream ID 17; ENHANCE_YOUR_CALM"
        ));
    }

    /// The bare phrase `"connection lost"` is NOT a transient marker
    /// on its own — only the qualified `"http2: client connection
    /// lost"` phrase is matched. Pinning the false-positive guard
    /// explicitly is the load-bearing test: if a future marker is
    /// added that swallows the bare `"connection lost"` phrase, the
    /// regression shows up here, not in production via burned retry
    /// budget against a VPN-client log line, a kube-event message,
    /// or an unrelated subsystem's `"connection lost"` diagnostic.
    /// Same dual anti-pattern the bare-GOAWAY false-positive guard
    /// closes for the GOAWAY phrase, here applied to the bare
    /// `"connection lost"` phrase.
    #[test]
    fn test_transient_classifier_bare_connection_lost_is_not_a_marker() {
        // Bare `"connection lost"` phrase without the `"http2:"`
        // package prefix — could appear in a VPN-client log line,
        // a kube event, or an unrelated subsystem diagnostic. Not
        // a transient signal on its own at this oracle.
        assert!(!is_transient_network_stderr(
            "Error: vpn tunnel connection lost: peer authentication required"
        ));
        // A `"connection lost"` phrase buried inside a kube event
        // message that's otherwise terminal — the unqualified
        // substring would catch this, the qualified phrase does
        // not.
        assert!(!is_transient_network_stderr(
            "Event: BackOff: connection lost to image registry: 403 Forbidden"
        ));
    }

    /// The bare `GOAWAY` token is NOT a transient marker on its own —
    /// only the multi-word phrase `"http2: server sent GOAWAY"` is
    /// matched. Pinning the false-positive guard explicitly is the
    /// load-bearing test: if a future marker is added that swallows
    /// the bare `GOAWAY` token, the regression shows up here, not in
    /// production via burned retry budget against a config / manifest
    /// / comment buried `GOAWAY` substring. Same dual anti-pattern the
    /// EOF false-positive `8952b9a` closed at the bare `EOF` token,
    /// here applied to the bare `GOAWAY` token.
    #[test]
    fn test_transient_classifier_bare_goaway_token_is_not_a_marker() {
        // Bare `GOAWAY` token without the `"http2: server sent"`
        // prefix — could appear in a k8s manifest comment, an
        // ingress-controller config, or an unrelated error log line.
        // Not a transient signal on its own.
        assert!(!is_transient_network_stderr(
            "Error: invalid manifest: configmap GOAWAY-override missing"
        ));
        // A `GOAWAY` token buried inside a hostname / identifier —
        // the unqualified token would catch this, the qualified
        // phrase does not.
        assert!(!is_transient_network_stderr(
            "auth denied at https://GOAWAY-edge.example.com/v2/"
        ));
    }

    /// The bare `EOF` acronym matches token-wise, never as a bare
    /// substring buried inside a larger identifier. Without this
    /// discipline, `stderr.contains("EOF")` fires on every diagnostic
    /// whose interior happens to spell `E-O-F` adjacent —
    /// service / repo / env-var / branch identifiers like `GEOFENCE`,
    /// `GEOFFREY`, `NEOFOLD`, `SOMEOFFICIAL` — converting a terminal
    /// failure (auth-denied, manifest-invalid, 404) into a five-attempt
    /// retry storm against the registry/cache.
    ///
    /// Fail-before: the bare-substring matcher tripped on every one of
    /// these (`"GEOFENCE".contains("EOF") == true`, etc.), silently
    /// converting each terminal failure into a five-attempt retry storm.
    /// Pass-after: each diagnostic short-circuits via the typed-error
    /// fail-fast path.
    #[test]
    fn test_transient_classifier_eof_does_not_match_buried_substring() {
        // Service / repo identifiers carrying `EOF` interior — terminal.
        assert!(!is_transient_network_stderr(
            "service \"GEOFENCE-MAP\" not found: 404"
        ));
        assert!(!is_transient_network_stderr(
            "manifest unknown: ghcr.io/pleme-io/GEOFFREY-runner"
        ));
        // Env / config identifiers — terminal.
        assert!(!is_transient_network_stderr(
            "GEOFENCE_API_URL not configured: 401"
        ));
        assert!(!is_transient_network_stderr(
            "build target NEOFOLD failed: pre-receive hook declined"
        ));
        // Larger word containing `EOF` — terminal.
        assert!(!is_transient_network_stderr(
            "SOMEOFFICIAL deprecation warning: 403 Forbidden"
        ));
        // Token-adjacency edge cases — `EOFTOKEN` is one alphanumeric token,
        // not two. The whole token must equal `EOF` for the match to fire.
        assert!(!is_transient_network_stderr(
            "EOFTOKEN expired: bad credentials"
        ));
        assert!(!is_transient_network_stderr(
            "validation failed: TRAILEOF marker present"
        ));
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

    /// The terminal 4xx family must NOT match — retrying a bad request,
    /// an auth failure, a forbidden, or a not-found cannot help, so they
    /// must fail fast rather than burn retry budget. "400 Bad Request"
    /// must not trip the "Bad Gateway" marker (different word) or any
    /// 5xx numeric. 429 is deliberately EXCLUDED from this terminal set
    /// (see `test_transient_classifier_429_rate_limit_is_retryable`).
    #[test]
    fn test_transient_classifier_4xx_does_not_match() {
        assert!(!is_transient_network_stderr("400 Bad Request"));
        assert!(!is_transient_network_stderr("401 Unauthorized"));
        assert!(!is_transient_network_stderr("403 Forbidden"));
        assert!(!is_transient_network_stderr("404 Not Found"));
    }

    /// HTTP 429 (Too Many Requests) is the registry/cache rate-limit
    /// backoff signal (RFC 6585 §4) and MUST be classified transient so
    /// the shared `retry_command` / `run_with_policy` driver backs off
    /// and retries instead of failing the push/pull immediately. Covers
    /// the dialects forge's CLIs emit: skopeo/regctl numeric+named
    /// ("received unexpected HTTP status: 429 Too Many Requests"), curl
    /// numeric-only ("The requested URL returned error: 429"), and
    /// reqwest/attic named-only. This is the load-bearing pin: a
    /// regression that re-classified 429 as terminal (the pre-fix
    /// behavior) would silently restore fail-fast-on-rate-limit and burn
    /// the whole image-push pipeline under GHCR load — exactly the
    /// failure mode this marker closes.
    #[test]
    fn test_transient_classifier_429_rate_limit_is_retryable() {
        // skopeo / regctl: numeric + named in one line.
        assert!(is_transient_network_stderr(
            "Error: ... received unexpected HTTP status: 429 Too Many Requests"
        ));
        // curl (git-over-HTTPS): numeric only, no named text.
        assert!(is_transient_network_stderr(
            "The requested URL returned error: 429"
        ));
        // reqwest / attic: named only.
        assert!(is_transient_network_stderr(
            "HTTP status client error (Too Many Requests) for url"
        ));
        // With an advisory Retry-After still classifies transient.
        assert!(is_transient_network_stderr(
            "429 Too Many Requests (retry-after: 30)"
        ));
    }

    /// HTTP 408 (Request Timeout, RFC 7231 §6.5.7) is the second
    /// RFC-explicit safe-retry 4xx code beyond 429: the spec names the
    /// contract verbatim ("The client MAY repeat the request without
    /// modifications at any later time") so the shared `retry_command`
    /// / `run_with_policy` driver MUST classify it transient and back
    /// off instead of failing fast. Covers the dialects forge's CLIs
    /// emit against ingress-fronted upstreams (GHCR via Azure Front
    /// Door's `client_body_timeout`, attic-server behind nginx
    /// ingress, github.com's per-request body-receipt deadline,
    /// kube-apiserver behind cluster ingress under HPA reconcile):
    /// skopeo/regctl numeric+named (`"received unexpected HTTP
    /// status: 408 Request Timeout"`), curl numeric+named (`"The
    /// requested URL returned error: 408 Request Timeout"`), reqwest
    /// named-only-within-paren and numeric+named-within-paren
    /// (`"HTTP status client error (408 Request Timeout) for url"`),
    /// and nginx-passthrough body emit. This is the load-bearing
    /// pin: the pre-fix marker set carried 429 as the one retryable
    /// 4xx but silently short-circuited 408 to terminal at every
    /// consumer that reads the named-form dialect — reqwest's
    /// `"HTTP status client error (Request Timeout) for url"`
    /// carries no standalone `"408"` token for the numeric matcher
    /// (it sits inside the paren before the named text), and the
    /// pre-existing `"Gateway Timeout"` / `"i/o timeout"` /
    /// `"timed out"` markers cover the 504 / kernel-TCP / connect-
    /// side timeouts but never the HTTP-408 status-layer timeout
    /// the ingress emits when it gives up reading the request body.
    #[test]
    fn test_transient_classifier_matches_408_request_timeout() {
        // skopeo / regctl: numeric + named in one line via Go's
        // `http.StatusText(408)` formatter.
        assert!(is_transient_network_stderr(
            "Error: writing blob: received unexpected HTTP status: 408 Request Timeout"
        ));
        // curl (git-over-HTTPS, container-registry probes): numeric +
        // named via `CURLE_HTTP_RETURNED_ERROR` when `--fail` is set.
        assert!(is_transient_network_stderr(
            "curl: (22) The requested URL returned error: 408 Request Timeout"
        ));
        // curl numeric-only variant the matcher must catch via the
        // token-wise status code list (no named text after the number).
        assert!(is_transient_network_stderr(
            "The requested URL returned error: 408"
        ));
        // reqwest / attic: named form within paren — the numeric "408"
        // appears in the paren but the named phrase carries the signal.
        assert!(is_transient_network_stderr(
            "HTTP status client error (408 Request Timeout) for url"
        ));
        // reqwest variant emitting only the canonical_reason inside
        // the paren without the numeric prefix (older reqwest formats).
        assert!(is_transient_network_stderr(
            "HTTP status client error (Request Timeout) for url"
        ));
        // Go net/http client formatted error against an ingress that
        // returned 408 mid-upload (kubectl, helm-cli, skopeo): wraps
        // the upstream status text through the request-error chain.
        assert!(is_transient_network_stderr(
            "Put \"https://ghcr.io/v2/org/repo/blobs/upload\": 408 Request Timeout"
        ));
        // nginx ingress body passthrough — the default `408 Request
        // Timeout` response body when `client_body_timeout` elapses.
        assert!(is_transient_network_stderr(
            "<html><head><title>408 Request Timeout</title></head>"
        ));
        // With advisory metadata still classifies transient.
        assert!(is_transient_network_stderr(
            "408 Request Timeout (client_body_timeout=60s exceeded)"
        ));
    }

    /// Numeric HTTP status codes are transient ONLY as a standalone status
    /// token. A "500"/"502"/"503"/"504"/"429" buried inside a content
    /// digest, a byte count, a port, a duration, or a larger id is NOT an
    /// HTTP status and must NOT be classified transient — retrying a
    /// terminal failure (auth-denied, manifest-invalid) whose diagnostic
    /// merely happens to contain those digits burns the whole retry budget
    /// against the registry/cache for nothing.
    ///
    /// Fail-before: the pre-tokenization bare-substring matcher tripped on
    /// every one of these (`"ab500cd".contains("500")`, `"50234".contains(
    /// "502")`, `"5000".contains("500")`, `"504ms".contains("504")`,
    /// `"14290".contains("429")` all return true), silently converting each
    /// terminal failure into a five-attempt retry storm.
    #[test]
    fn test_transient_classifier_numeric_status_only_matches_standalone_token() {
        // Content digest carrying "500" between hex chars — terminal.
        assert!(!is_transient_network_stderr(
            "manifest blob unknown: sha256:ab500cd not present"
        ));
        // Byte count — "50234" is not status 502.
        assert!(!is_transient_network_stderr(
            "pushed 50234 bytes then denied: access forbidden"
        ));
        // Port — ":5000" is not status 500.
        assert!(!is_transient_network_stderr(
            "dial tcp 10.0.0.1:5000: requested access to the resource is denied"
        ));
        // Duration — "504ms" is not status 504.
        assert!(!is_transient_network_stderr(
            "auth check failed after 504ms: bad credentials"
        ));
        // Larger id containing "429" — "14290" is not status 429.
        assert!(!is_transient_network_stderr(
            "request id 14290 rejected: manifest unknown"
        ));
        // The standalone status token still matches in every real dialect.
        assert!(is_transient_network_stderr("HTTP/1.1 503 from upstream"));
        assert!(is_transient_network_stderr(
            "received unexpected HTTP status: 502"
        ));
        assert!(is_transient_network_stderr(
            "The requested URL returned error: 429"
        ));
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

    /// `network_or_immediate(true)` returns the canonical
    /// [`RetryPolicy::network`] shape verbatim — same schedule, same
    /// budget, same cap. The load-bearing pin: a regression that
    /// perturbed the `true` arm (e.g., dropped to a 1-attempt policy
    /// silently) would silently turn every safe-mode retry-driven CI
    /// surface into a fail-fast loop, invisible except as a regression
    /// in attempt-count telemetry. Pinning every schedule field at the
    /// primitive boundary catches that here.
    #[test]
    fn test_network_or_immediate_true_returns_network() {
        let p = RetryPolicy::network_or_immediate(true);
        let net = RetryPolicy::network();
        assert_eq!(
            p.max_attempts, net.max_attempts,
            "true arm must inherit network()'s max_attempts"
        );
        assert_eq!(
            p.initial_backoff, net.initial_backoff,
            "true arm must inherit network()'s initial_backoff"
        );
        assert_eq!(
            p.factor, net.factor,
            "true arm must inherit network()'s factor"
        );
        assert_eq!(
            p.max_backoff, net.max_backoff,
            "true arm must inherit network()'s max_backoff"
        );
    }

    /// `network_or_immediate(false)` returns the no-retry
    /// [`RetryPolicy::immediate`] shape verbatim. The load-bearing pin:
    /// a regression that perturbed the `false` arm (e.g., promoted it to
    /// `network()` so the partition collapsed to "always retry") would
    /// silently make every non-safe-mode CI surface a five-attempt
    /// retry loop against the registry/cache, exactly the failure mode
    /// the safe-mode partition exists to suppress. Pinning every
    /// schedule field at the primitive boundary catches that here.
    #[test]
    fn test_network_or_immediate_false_returns_immediate() {
        let p = RetryPolicy::network_or_immediate(false);
        let imm = RetryPolicy::immediate();
        assert_eq!(
            p.max_attempts, imm.max_attempts,
            "false arm must inherit immediate()'s max_attempts"
        );
        assert_eq!(
            p.initial_backoff, imm.initial_backoff,
            "false arm must inherit immediate()'s initial_backoff"
        );
        assert_eq!(
            p.factor, imm.factor,
            "false arm must inherit immediate()'s factor"
        );
        assert_eq!(
            p.max_backoff, imm.max_backoff,
            "false arm must inherit immediate()'s max_backoff"
        );
    }

    /// The two arms partition the two canonical factory constructors
    /// exactly — `true` arm equals `network()`, `false` arm equals
    /// `immediate()`, and the two factories are structurally distinct
    /// (different `max_attempts`, different `initial_backoff`,
    /// different `max_backoff`). The structural-witness pin a
    /// regression that fused both arms onto one factory would fail
    /// against: if both arms returned `network()`, the `false` arm
    /// would mis-match `immediate()`; if both arms returned
    /// `immediate()`, the `true` arm would mis-match `network()`. The
    /// derived `PartialEq` over [`RetryPolicy`] (via its struct field
    /// `PartialEq`s — `u32`, `Duration`, `u32`, `Duration`, all
    /// `Eq`-bound primitives) makes the partition pin a direct
    /// equality check rather than a per-field cascade.
    #[test]
    fn test_network_or_immediate_partitions_two_factories() {
        let true_arm = RetryPolicy::network_or_immediate(true);
        let false_arm = RetryPolicy::network_or_immediate(false);
        let net = RetryPolicy::network();
        let imm = RetryPolicy::immediate();
        assert_eq!(true_arm.max_attempts, net.max_attempts);
        assert_eq!(true_arm.initial_backoff, net.initial_backoff);
        assert_eq!(true_arm.factor, net.factor);
        assert_eq!(true_arm.max_backoff, net.max_backoff);
        assert_eq!(false_arm.max_attempts, imm.max_attempts);
        assert_eq!(false_arm.initial_backoff, imm.initial_backoff);
        assert_eq!(false_arm.factor, imm.factor);
        assert_eq!(false_arm.max_backoff, imm.max_backoff);
        // The two arms are structurally distinct — the partition is
        // non-degenerate.
        assert_ne!(
            true_arm.max_attempts, false_arm.max_attempts,
            "the partition must be non-degenerate: max_attempts differs"
        );
        assert_ne!(
            true_arm.initial_backoff, false_arm.initial_backoff,
            "the partition must be non-degenerate: initial_backoff differs"
        );
        assert_ne!(
            true_arm.max_backoff, false_arm.max_backoff,
            "the partition must be non-degenerate: max_backoff differs"
        );
    }

    /// `network_or_immediate` is callable in a `const` context — the
    /// same const-fn discipline [`RetryPolicy::network`] and
    /// [`RetryPolicy::immediate`] carry. Pins that a future regression
    /// that dropped the `const` qualifier (e.g., to add a non-const
    /// runtime branch) would surface here as a compile-error rather
    /// than as a silent loss of a `const POLICY: RetryPolicy = ...`
    /// table at a future call site.
    #[test]
    fn test_network_or_immediate_is_const_fn() {
        const TRUE_ARM: RetryPolicy = RetryPolicy::network_or_immediate(true);
        const FALSE_ARM: RetryPolicy = RetryPolicy::network_or_immediate(false);
        assert_eq!(TRUE_ARM.max_attempts, RetryPolicy::network().max_attempts);
        assert_eq!(
            FALSE_ARM.max_attempts,
            RetryPolicy::immediate().max_attempts
        );
    }

    /// `network_or_immediate` composes with [`RetryPolicy::with_max_attempts`]
    /// — both arms admit the canonical builder override without a
    /// special case. Pins the structural composition the post-migration
    /// safe-mode-conditional retry-driven consumers can reach for: a
    /// caller that wants the safe-mode-conditional dispatch AND a
    /// caller-supplied budget override reads
    /// `RetryPolicy::network_or_immediate(safe_mode).with_max_attempts(retries)`
    /// at one site rather than retyping the inline conditional. A
    /// regression that broke either constructor's composition with the
    /// builder would surface here.
    #[test]
    fn test_network_or_immediate_composes_with_with_max_attempts() {
        let true_arm = RetryPolicy::network_or_immediate(true).with_max_attempts(7);
        assert_eq!(true_arm.max_attempts, 7);
        // Schedule still comes from network() — only max_attempts is
        // overridden.
        let net = RetryPolicy::network();
        assert_eq!(true_arm.initial_backoff, net.initial_backoff);
        assert_eq!(true_arm.factor, net.factor);
        assert_eq!(true_arm.max_backoff, net.max_backoff);

        let false_arm = RetryPolicy::network_or_immediate(false).with_max_attempts(7);
        assert_eq!(false_arm.max_attempts, 7);
        // Schedule still comes from immediate() — every backoff is zero
        // regardless of max_attempts.
        let imm = RetryPolicy::immediate();
        assert_eq!(false_arm.initial_backoff, imm.initial_backoff);
        assert_eq!(false_arm.max_backoff, imm.max_backoff);
        assert_eq!(false_arm.compute_delay(2), Duration::ZERO);
    }

    /// `network_with_max_attempts(n)` inherits every schedule field of
    /// [`RetryPolicy::network`] verbatim and overrides only
    /// `max_attempts`. The load-bearing pin: a regression that
    /// perturbed any schedule field (`initial_backoff`, `factor`,
    /// `max_backoff`) would silently break the canonical
    /// exponential-backoff schedule the two `infrastructure/`
    /// push-with-retries surfaces (`attic::push_with_retries`,
    /// `registry::push_with_retries`) depend on for transient-network
    /// recovery — visible only as a degraded retry trajectory under
    /// load (e.g., fixed-200ms instead of 250ms × 2^n exponential),
    /// not in the typed-error surface. Pinning every schedule field
    /// at the primitive boundary catches that here.
    #[test]
    fn test_network_with_max_attempts_inherits_network_schedule() {
        let p = RetryPolicy::network_with_max_attempts(7);
        let net = RetryPolicy::network();
        assert_eq!(
            p.initial_backoff, net.initial_backoff,
            "schedule must inherit network()'s initial_backoff"
        );
        assert_eq!(
            p.factor, net.factor,
            "schedule must inherit network()'s factor"
        );
        assert_eq!(
            p.max_backoff, net.max_backoff,
            "schedule must inherit network()'s max_backoff"
        );
        assert_eq!(p.max_attempts, 7, "max_attempts must reflect caller arg");
    }

    /// The clamping discipline of [`RetryPolicy::with_max_attempts`]
    /// propagates verbatim: `network_with_max_attempts(0)` produces a
    /// `max_attempts: 1` policy, not a degenerate `0` that
    /// [`run_with_policy`]'s `attempt >= max` predicate would short-
    /// circuit on the first call. Without this pin, a public-API caller
    /// passing `0` to `RegistryClient::push_with_retries` or
    /// `AtticClient::push_with_retries` would silently produce a no-op
    /// retry loop that returned the first error without consuming any
    /// budget — a regression visible only in attempt-count telemetry.
    #[test]
    fn test_network_with_max_attempts_clamps_zero_to_one() {
        let p = RetryPolicy::network_with_max_attempts(0);
        assert_eq!(
            p.max_attempts, 1,
            "zero must clamp to 1 — inherited from with_max_attempts"
        );
        // Schedule still comes from network().
        let net = RetryPolicy::network();
        assert_eq!(p.initial_backoff, net.initial_backoff);
        assert_eq!(p.factor, net.factor);
        assert_eq!(p.max_backoff, net.max_backoff);
    }

    /// `network_with_max_attempts(n)` equals the inline composition
    /// `RetryPolicy::network().with_max_attempts(n)` at every `n` in a
    /// representative sweep, including the clamp boundary at `0`. The
    /// structural-witness pin against any regression that perturbed the
    /// named composition relative to the two-call inline form the two
    /// `infrastructure/` push-with-retries surfaces previously carried.
    /// [`RetryPolicy`] derives [`PartialEq`] via its four `Eq`-bound
    /// struct fields, so the equality is also asserted at the typed-
    /// primitive surface through one direct `assert_eq!(named, inline)`
    /// in addition to the field-wise cascade — the field-wise reading
    /// stays as the load-bearing per-field pin against any regression
    /// that perturbed exactly one field, and the direct-equality
    /// reading hoists the structural witness to the consumer-idiomatic
    /// `==` surface.
    #[test]
    fn test_network_with_max_attempts_equals_inline_composition() {
        for &n in &[0u32, 1, 2, 5, 7, 100, u32::MAX] {
            let named = RetryPolicy::network_with_max_attempts(n);
            let inline = RetryPolicy::network().with_max_attempts(n);
            // Direct-equality reading at the derived [`PartialEq`] surface
            // — the consumer-idiomatic `==` form `assert_eq!(named, inline)`
            // closed by the typed-primitive equality derive.
            assert_eq!(
                named, inline,
                "network_with_max_attempts({n}) must equal network().with_max_attempts({n}) at the typed-primitive surface"
            );
            // Field-wise cascade — the per-field structural witness
            // against any regression that perturbed exactly one field
            // (preserved alongside the direct-equality reading because
            // a four-field cross product silently agreeing modulo the
            // derive is still possible if the derive is removed).
            assert_eq!(
                named.max_attempts, inline.max_attempts,
                "max_attempts must match inline composition for n = {n}"
            );
            assert_eq!(
                named.initial_backoff, inline.initial_backoff,
                "initial_backoff must match inline composition for n = {n}"
            );
            assert_eq!(
                named.factor, inline.factor,
                "factor must match inline composition for n = {n}"
            );
            assert_eq!(
                named.max_backoff, inline.max_backoff,
                "max_backoff must match inline composition for n = {n}"
            );
        }
    }

    /// The canonical exponential backoff schedule survives the budget
    /// override: `compute_delay(2)` for any caller budget is still
    /// `network()`'s 250ms initial backoff (no premature cap, no
    /// schedule collapse). Pins that future regressions that fused
    /// `max_attempts` with `initial_backoff` (a typo in the field
    /// assignment) would surface here as a schedule mis-match rather
    /// than a silent retry-cadence regression.
    #[test]
    fn test_network_with_max_attempts_preserves_compute_delay_schedule() {
        let p = RetryPolicy::network_with_max_attempts(7);
        let net = RetryPolicy::network();
        // attempt 2: initial_backoff (250ms under network())
        assert_eq!(p.compute_delay(2), net.compute_delay(2));
        // attempt 3: initial_backoff * factor (500ms)
        assert_eq!(p.compute_delay(3), net.compute_delay(3));
        // attempt 4: initial_backoff * factor^2 (1s)
        assert_eq!(p.compute_delay(4), net.compute_delay(4));
        // attempt 1 is always ZERO regardless of schedule
        assert_eq!(p.compute_delay(1), Duration::ZERO);
    }

    /// `RetryPolicy` derives [`PartialEq`] reflexively at every factory
    /// constructor. The structural-witness pin against any regression
    /// that broke the derive (e.g., a future migration to a custom
    /// `PartialEq` impl that drifted from the field-wise extensional
    /// reading) would surface here at the reflexivity arm — the
    /// minimum-load-bearing [`PartialEq`] law `a == a`. Closed over a
    /// representative cross product of the five factory constructors
    /// the inherent-method matrix carries ([`Self::immediate`],
    /// [`Self::network`], [`Self::network_or_immediate`],
    /// [`Self::network_with_max_attempts`], [`Self::new`]) so a
    /// regression that broke the derive at one constructor's struct
    /// shape (e.g., a future field addition without an updated derive)
    /// would fail this pin against every reachable arm.
    #[test]
    fn test_partial_eq_reflexive_across_factory_constructors() {
        let policies = [
            RetryPolicy::immediate(),
            RetryPolicy::network(),
            RetryPolicy::network_or_immediate(true),
            RetryPolicy::network_or_immediate(false),
            RetryPolicy::network_with_max_attempts(7),
            RetryPolicy::network_with_max_attempts(0),
            RetryPolicy::new(3, Duration::from_millis(100), 2, Duration::from_secs(10)),
        ];
        for p in &policies {
            assert_eq!(
                *p,
                p.clone(),
                "PartialEq must be reflexive at every factory"
            );
        }
    }

    /// `PartialEq` separates the canonical factory constructors at the
    /// typed-primitive surface — [`Self::network`] and
    /// [`Self::immediate`] read structurally distinct under `==`
    /// without the field-wise cascade. The named pin a downstream
    /// consumer that branches on `policy == RetryPolicy::network()` or
    /// `policy == RetryPolicy::immediate()` relies on: the two factory
    /// constructors must NOT collapse to one structural value, or the
    /// safe-mode partition [`Self::network_or_immediate`] returns
    /// silently degenerates to a single-arm policy at every reachable
    /// call site. Pinned at the direct-equality surface so a regression
    /// that perturbed either factory's struct shape would surface here
    /// rather than at one downstream call site.
    #[test]
    fn test_partial_eq_separates_factory_constructors() {
        let net = RetryPolicy::network();
        let imm = RetryPolicy::immediate();
        assert_ne!(
            net, imm,
            "network() and immediate() must be structurally distinct under PartialEq"
        );
        // network_with_max_attempts(5) equals network() at the canonical
        // budget — the named composition preserves the structural equality
        // at the typed-primitive surface.
        assert_eq!(
            RetryPolicy::network_with_max_attempts(5),
            RetryPolicy::network(),
            "network_with_max_attempts(5) must equal network() at the canonical 5-attempt budget"
        );
        // network_with_max_attempts(7) does NOT equal network() — the
        // budget override surfaces at the direct-equality reading.
        assert_ne!(
            RetryPolicy::network_with_max_attempts(7),
            RetryPolicy::network(),
            "network_with_max_attempts(7) must differ from network() at the budget-override arm"
        );
    }

    /// [`Self::network_or_immediate`] composes with [`PartialEq`] at the
    /// two factory-constructor arms: the `true` arm equals
    /// [`Self::network`] under `==`, the `false` arm equals
    /// [`Self::immediate`] under `==`. The typed-primitive-equality
    /// reading of the safe-mode partition the downstream consumer
    /// previously had to assert field-wise at every call site (test
    /// `test_network_or_immediate_partitions_two_factories` enumerates
    /// `max_attempts` / `initial_backoff` / `factor` / `max_backoff`
    /// across both arms by hand) now reads at one direct `==` per arm.
    /// The structural-witness pin against any regression that broke the
    /// derive at either arm's struct shape — a future regression that
    /// flipped the `true` arm to [`Self::immediate`] or the `false` arm
    /// to [`Self::network`] would silently misroute every safe-mode-
    /// conditional retry consumer; the direct-equality surface catches
    /// it here.
    #[test]
    fn test_partial_eq_network_or_immediate_dispatches_to_factories() {
        assert_eq!(
            RetryPolicy::network_or_immediate(true),
            RetryPolicy::network(),
            "network_or_immediate(true) must equal network() at the typed-primitive surface"
        );
        assert_eq!(
            RetryPolicy::network_or_immediate(false),
            RetryPolicy::immediate(),
            "network_or_immediate(false) must equal immediate() at the typed-primitive surface"
        );
    }

    /// `PartialEq` is symmetric and transitive across the named factory
    /// constructors — the two remaining [`PartialEq`] laws `a == b =>
    /// b == a` (symmetry) and `a == b && b == c => a == c`
    /// (transitivity) closed at the consumer-facing arm where the
    /// safe-mode partition's `true` arm, the canonical
    /// [`Self::network`] factory, and the
    /// `network_with_max_attempts(5)` composition all read as one
    /// structural value at the typed-primitive surface. The
    /// minimum-load-bearing pin a future regression that hand-rolled a
    /// custom `PartialEq` impl could break — a custom impl that
    /// silently asymmetric-routed equality under one direction would
    /// fail symmetry here, and one that broke the transitive composition
    /// at the three-way `network_or_immediate(true) ==
    /// network_with_max_attempts(5) == network()` arm would fail
    /// transitivity here.
    #[test]
    fn test_partial_eq_symmetric_and_transitive_across_factory_constructors() {
        let a = RetryPolicy::network_or_immediate(true);
        let b = RetryPolicy::network_with_max_attempts(5);
        let c = RetryPolicy::network();
        // Symmetry: a == b iff b == a, b == c iff c == b, a == c iff c == a.
        assert_eq!(a == b, b == a);
        assert_eq!(b == c, c == b);
        assert_eq!(a == c, c == a);
        // Transitivity: a == b && b == c => a == c.
        assert_eq!(a, b);
        assert_eq!(b, c);
        assert_eq!(a, c);
    }

    /// [`RetryPolicy::is_no_retry`] discriminates the no-retry
    /// structural-state arm at the typed-primitive surface across the
    /// canonical factory constructors. [`Self::immediate`] is no-retry
    /// (`max_attempts: 1`); [`Self::network`] is retry
    /// (`max_attempts: 5`); the safe-mode partition routes via
    /// [`Self::network_or_immediate`] (`true` → retry, `false` →
    /// no-retry); [`Self::network_with_max_attempts(1)`] is no-retry
    /// despite carrying the canonical network schedule — the predicate
    /// names the retry-budget axis cleanly, NOT direct-equality
    /// against [`Self::immediate`].
    #[test]
    fn test_retry_policy_is_no_retry_discriminates_canonical_factories() {
        assert!(
            RetryPolicy::immediate().is_no_retry(),
            "immediate() is no-retry (max_attempts == 1)"
        );
        assert!(
            !RetryPolicy::network().is_no_retry(),
            "network() retries (max_attempts == 5)"
        );
        assert!(
            !RetryPolicy::network_or_immediate(true).is_no_retry(),
            "network_or_immediate(true) routes to network() — retries"
        );
        assert!(
            RetryPolicy::network_or_immediate(false).is_no_retry(),
            "network_or_immediate(false) routes to immediate() — no-retry"
        );
        assert!(
            RetryPolicy::network_with_max_attempts(1).is_no_retry(),
            "network_with_max_attempts(1) is no-retry despite the network schedule"
        );
        assert!(
            !RetryPolicy::network_with_max_attempts(2).is_no_retry(),
            "network_with_max_attempts(2) retries — budget exceeds 1"
        );
        // network_with_max_attempts(0) clamps to 1 — still no-retry.
        assert!(
            RetryPolicy::network_with_max_attempts(0).is_no_retry(),
            "network_with_max_attempts(0) clamps to 1 — no-retry"
        );
    }

    /// [`RetryPolicy::is_no_retry`] holds iff `max_attempts <= 1` —
    /// structural-definition pin against a regression that swapped the
    /// body for a synthetic discriminator (e.g., direct equality against
    /// [`Self::immediate`] which would mis-classify
    /// `network_with_max_attempts(1)` as retry; a strict `== 1`
    /// comparator which would mis-classify a hand-built
    /// `max_attempts: 0` field-literal record as retry; an `is_zero()`
    /// on `initial_backoff` which would mis-classify
    /// `immediate().with_max_attempts(4)` as no-retry). Covers the full
    /// `max_attempts` × {ZERO, non-ZERO `initial_backoff`} cross-product
    /// the retry-loop body discriminates.
    #[test]
    fn test_retry_policy_is_no_retry_equals_max_attempts_le_one() {
        let cases = [
            (0u32, true),
            (1, true),
            (2, false),
            (5, false),
            (100, false),
            (u32::MAX, false),
        ];
        for (max_attempts, expected) in cases {
            // Test against both schedule shapes (ZERO and non-ZERO
            // initial_backoff) — the predicate must NOT couple to the
            // schedule axis.
            let with_zero_schedule = RetryPolicy {
                max_attempts,
                initial_backoff: Duration::ZERO,
                factor: 1,
                max_backoff: Duration::ZERO,
            };
            let with_network_schedule = RetryPolicy {
                max_attempts,
                initial_backoff: Duration::from_millis(250),
                factor: 2,
                max_backoff: Duration::from_secs(30),
            };
            assert_eq!(
                with_zero_schedule.is_no_retry(),
                expected,
                "max_attempts = {max_attempts}, zero schedule"
            );
            assert_eq!(
                with_network_schedule.is_no_retry(),
                expected,
                "max_attempts = {max_attempts}, network schedule"
            );
        }
    }

    /// [`RetryPolicy::is_no_retry`] is the structural witness for the
    /// retry-loop short-circuit behavior at [`run_with_policy`]: under
    /// an always-transient classifier, a no-retry policy invokes `op`
    /// exactly once; a retry policy invokes `op` exactly
    /// `max_attempts` times. The load-bearing co-firing pin against
    /// any future regression that decoupled the predicate from the
    /// loop's `attempt >= max` short-circuit — e.g., a future
    /// refactor that promoted the retry-loop's `max(1)` clamp to a
    /// `max(2)` floor without updating the predicate, or a refactor
    /// that broadened the predicate to cover an `initial_backoff:
    /// ZERO` arm that the loop body did not treat as no-retry.
    #[tokio::test]
    async fn test_retry_policy_is_no_retry_co_fires_with_run_with_policy_short_circuit() {
        // No-retry policies invoke op exactly once even under an
        // always-transient classifier.
        for p in &[
            RetryPolicy::immediate(),
            RetryPolicy::network_with_max_attempts(1),
            RetryPolicy::network_or_immediate(false),
        ] {
            assert!(p.is_no_retry(), "precondition: {p:?} is no-retry");
            let calls = Arc::new(AtomicU32::new(0));
            let calls_clone = calls.clone();
            let result: Result<(), &'static str> = run_with_policy(
                p,
                |_| true,
                |_| {
                    let calls = calls_clone.clone();
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Err::<(), &'static str>("err")
                    }
                },
            )
            .await;
            assert!(result.is_err());
            assert_eq!(
                calls.load(Ordering::SeqCst),
                1,
                "no-retry policy must invoke op exactly once: {p:?}"
            );
        }
        // Retry policies invoke op exactly max_attempts times under an
        // always-transient classifier.
        let p = RetryPolicy::new(3, Duration::ZERO, 1, Duration::ZERO);
        assert!(!p.is_no_retry(), "precondition: {p:?} retries");
        let calls = Arc::new(AtomicU32::new(0));
        let calls_clone = calls.clone();
        let result: Result<(), &'static str> = run_with_policy(
            &p,
            |_| true,
            |_| {
                let calls = calls_clone.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Err::<(), &'static str>("err")
                }
            },
        )
        .await;
        assert!(result.is_err());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "retry policy must invoke op max_attempts times"
        );
    }

    /// [`RetryPolicy::will_retry`] discriminates the will-retry
    /// structural-state arm at the typed-primitive surface across the
    /// canonical factory constructors — the complement of the
    /// [`RetryPolicy::is_no_retry`] discrimination pinned above.
    /// [`Self::immediate`] is no-retry → `will_retry()` false;
    /// [`Self::network`] retries → `will_retry()` true;
    /// [`Self::network_or_immediate`] routes by safe-mode flag;
    /// [`Self::network_with_max_attempts(1)`] is no-retry despite the
    /// network schedule (the predicate names the retry-budget axis,
    /// NOT the schedule axis).
    #[test]
    fn test_retry_policy_will_retry_discriminates_canonical_factories() {
        assert!(
            !RetryPolicy::immediate().will_retry(),
            "immediate() does not retry (max_attempts == 1)"
        );
        assert!(
            RetryPolicy::network().will_retry(),
            "network() retries (max_attempts == 5)"
        );
        assert!(
            RetryPolicy::network_or_immediate(true).will_retry(),
            "network_or_immediate(true) routes to network() — retries"
        );
        assert!(
            !RetryPolicy::network_or_immediate(false).will_retry(),
            "network_or_immediate(false) routes to immediate() — does not retry"
        );
        assert!(
            !RetryPolicy::network_with_max_attempts(1).will_retry(),
            "network_with_max_attempts(1) does not retry despite the network schedule"
        );
        assert!(
            RetryPolicy::network_with_max_attempts(2).will_retry(),
            "network_with_max_attempts(2) retries — budget exceeds 1"
        );
        // network_with_max_attempts(0) clamps to 1 — still no-retry.
        assert!(
            !RetryPolicy::network_with_max_attempts(0).will_retry(),
            "network_with_max_attempts(0) clamps to 1 — does not retry"
        );
    }

    /// [`RetryPolicy::will_retry`] is the named complement of
    /// [`RetryPolicy::is_no_retry`]: `will_retry() == !is_no_retry()`
    /// holds for every [`RetryPolicy`] record. Structural-complement
    /// pin across the full `max_attempts` × `{ZERO, network}` schedule
    /// cross-product — a future regression that desynced the two
    /// predicates (e.g., one promoting its threshold off `<= 1`
    /// without the other, one reading a stale
    /// `initial_backoff.is_zero()` shortcut the other did not, a
    /// custom impl that drifted from the canonical definition) lights
    /// up this test.
    #[test]
    fn test_retry_policy_will_retry_complements_is_no_retry() {
        let cases = [0u32, 1, 2, 5, 100, u32::MAX];
        for max_attempts in cases {
            let with_zero_schedule = RetryPolicy {
                max_attempts,
                initial_backoff: Duration::ZERO,
                factor: 1,
                max_backoff: Duration::ZERO,
            };
            let with_network_schedule = RetryPolicy {
                max_attempts,
                initial_backoff: Duration::from_millis(250),
                factor: 2,
                max_backoff: Duration::from_secs(30),
            };
            assert_eq!(
                with_zero_schedule.will_retry(),
                !with_zero_schedule.is_no_retry(),
                "will_retry must complement is_no_retry: max_attempts = {max_attempts}, zero schedule"
            );
            assert_eq!(
                with_network_schedule.will_retry(),
                !with_network_schedule.is_no_retry(),
                "will_retry must complement is_no_retry: max_attempts = {max_attempts}, network schedule"
            );
        }
    }

    /// [`RetryPolicy::will_retry`] is the structural witness for the
    /// retry-loop's *multi-invocation* arm at [`run_with_policy`]:
    /// under an always-transient classifier, a `will_retry()` policy
    /// invokes `op` more than once (exactly `max_attempts` times); a
    /// `!will_retry()` policy invokes `op` exactly once. The
    /// load-bearing co-firing pin against any future regression that
    /// decoupled the predicate from the loop's `attempt >= max`
    /// short-circuit at [`run_with_policy`].
    #[tokio::test]
    async fn test_retry_policy_will_retry_co_fires_with_run_with_policy_multi_invocation() {
        // will_retry() policies invoke op more than once under an
        // always-transient classifier.
        let retry_policies = [
            RetryPolicy::network(),
            RetryPolicy::network_or_immediate(true),
            RetryPolicy::network_with_max_attempts(3),
            RetryPolicy::new(2, Duration::ZERO, 1, Duration::ZERO),
        ];
        for p in &retry_policies {
            assert!(p.will_retry(), "precondition: {p:?} will_retry");
            let calls = Arc::new(AtomicU32::new(0));
            let calls_clone = calls.clone();
            let result: Result<(), &'static str> = run_with_policy(
                p,
                |_| true,
                |_| {
                    let calls = calls_clone.clone();
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Err::<(), &'static str>("err")
                    }
                },
            )
            .await;
            assert!(result.is_err());
            let observed = calls.load(Ordering::SeqCst);
            assert!(
                observed > 1,
                "will_retry policy must invoke op more than once: {p:?} (observed {observed})"
            );
            assert_eq!(
                observed, p.max_attempts,
                "will_retry policy must invoke op exactly max_attempts times: {p:?}"
            );
        }
        // !will_retry() policies invoke op exactly once.
        let no_retry_policies = [
            RetryPolicy::immediate(),
            RetryPolicy::network_with_max_attempts(1),
            RetryPolicy::network_or_immediate(false),
        ];
        for p in &no_retry_policies {
            assert!(!p.will_retry(), "precondition: {p:?} does not retry");
            let calls = Arc::new(AtomicU32::new(0));
            let calls_clone = calls.clone();
            let result: Result<(), &'static str> = run_with_policy(
                p,
                |_| true,
                |_| {
                    let calls = calls_clone.clone();
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Err::<(), &'static str>("err")
                    }
                },
            )
            .await;
            assert!(result.is_err());
            assert_eq!(
                calls.load(Ordering::SeqCst),
                1,
                "!will_retry policy must invoke op exactly once: {p:?}"
            );
        }
    }

    /// [`RetryPolicy::is_final_attempt`] reads the per-attempt retry-
    /// budget partition across the canonical factory constructors. The
    /// canonical [`RetryPolicy::network`] policy with `max_attempts: 5`
    /// classifies attempts 1..=4 as non-final and 5..=u32::MAX as final;
    /// the no-retry shapes ([`RetryPolicy::immediate`],
    /// [`RetryPolicy::network_with_max_attempts(1)`],
    /// [`RetryPolicy::network_or_immediate(false)`]) classify attempt 1
    /// as final; the degenerate `max_attempts: 0` hand-built field-
    /// literal shape inherits the same clamp-to-≥1 discipline the loop
    /// body at [`run_with_policy`] applies, so attempt 1 is final.
    #[test]
    fn test_retry_policy_is_final_attempt_discriminates_canonical_factories() {
        // network() retries — attempts 1..=4 are non-final, 5..=∞ are final.
        let net = RetryPolicy::network();
        for attempt in 1..=4 {
            assert!(
                !net.is_final_attempt(attempt),
                "network() attempt {attempt} is not final (budget = 5)"
            );
        }
        for attempt in [5u32, 6, 100, u32::MAX] {
            assert!(
                net.is_final_attempt(attempt),
                "network() attempt {attempt} is final (>= budget = 5)"
            );
        }
        // immediate() is no-retry — attempt 1 is final.
        assert!(
            RetryPolicy::immediate().is_final_attempt(1),
            "immediate() attempt 1 is final (budget = 1)"
        );
        // network_with_max_attempts(1) is no-retry despite the network
        // schedule — attempt 1 is final.
        assert!(
            RetryPolicy::network_with_max_attempts(1).is_final_attempt(1),
            "network_with_max_attempts(1) attempt 1 is final"
        );
        // network_or_immediate(false) routes to immediate() — attempt 1 is final.
        assert!(
            RetryPolicy::network_or_immediate(false).is_final_attempt(1),
            "network_or_immediate(false) attempt 1 is final"
        );
        // network_or_immediate(true) routes to network() — attempt 1 is
        // NOT final under the network budget.
        assert!(
            !RetryPolicy::network_or_immediate(true).is_final_attempt(1),
            "network_or_immediate(true) attempt 1 is not final (network budget = 5)"
        );
        // Degenerate hand-built max_attempts: 0 — clamp-to-≥1 makes
        // attempt 1 the final attempt.
        let degenerate = RetryPolicy {
            max_attempts: 0,
            initial_backoff: Duration::ZERO,
            factor: 1,
            max_backoff: Duration::ZERO,
        };
        assert!(
            degenerate.is_final_attempt(1),
            "max_attempts: 0 attempt 1 is final under clamp-to-≥1"
        );
    }

    /// [`RetryPolicy::is_final_attempt`] reduces to the policy-level
    /// [`RetryPolicy::is_no_retry`] reading at `attempt = 1` — the per-
    /// attempt predicate's behavior at the first attempt names exactly
    /// the same retry-budget partition as the policy-level predicate.
    /// Structural-witness pin across the full `max_attempts` ×
    /// `{ZERO, network}` schedule cross-product: a future regression
    /// that desynced the per-attempt predicate at `attempt = 1` from the
    /// policy-level predicate (e.g., a future per-attempt predicate
    /// reading `attempt > max` instead of `>=`, a future policy-level
    /// predicate broadening to cover an `initial_backoff: ZERO` arm the
    /// per-attempt predicate did not) lights up this test.
    #[test]
    fn test_retry_policy_is_no_retry_equals_is_final_attempt_at_one() {
        let cases = [0u32, 1, 2, 5, 100, u32::MAX];
        for max_attempts in cases {
            for schedule in [
                (Duration::ZERO, 1, Duration::ZERO),
                (Duration::from_millis(250), 2, Duration::from_secs(30)),
            ] {
                let p = RetryPolicy {
                    max_attempts,
                    initial_backoff: schedule.0,
                    factor: schedule.1,
                    max_backoff: schedule.2,
                };
                assert_eq!(
                    p.is_no_retry(),
                    p.is_final_attempt(1),
                    "is_no_retry must equal is_final_attempt(1): max_attempts = {max_attempts}, schedule = {schedule:?}"
                );
            }
        }
    }

    /// [`RetryPolicy::is_final_attempt`] at `attempt = 1` is the De
    /// Morgan complement of [`RetryPolicy::will_retry`] —
    /// `will_retry() == !is_final_attempt(1)` holds for every
    /// [`RetryPolicy`] record. Structural-complement pin across the
    /// full `max_attempts` × `{ZERO, network}` schedule cross-product
    /// — the named-complement closure between the policy-level retry-
    /// budget pair ([`is_no_retry`] / [`will_retry`]) and the per-
    /// attempt retry-budget predicate at the first attempt, the same
    /// way [`is_no_retry`] / [`will_retry`] themselves form a named-
    /// complement pair at the policy level.
    #[test]
    fn test_retry_policy_will_retry_complements_is_final_attempt_at_one() {
        let cases = [0u32, 1, 2, 5, 100, u32::MAX];
        for max_attempts in cases {
            for schedule in [
                (Duration::ZERO, 1, Duration::ZERO),
                (Duration::from_millis(250), 2, Duration::from_secs(30)),
            ] {
                let p = RetryPolicy {
                    max_attempts,
                    initial_backoff: schedule.0,
                    factor: schedule.1,
                    max_backoff: schedule.2,
                };
                assert_eq!(
                    p.will_retry(),
                    !p.is_final_attempt(1),
                    "will_retry must complement is_final_attempt(1): max_attempts = {max_attempts}, schedule = {schedule:?}"
                );
            }
        }
    }

    /// [`RetryPolicy::is_final_attempt`] is the structural witness for
    /// the retry-loop short-circuit at [`run_with_policy`]: under an
    /// always-transient classifier, the loop body returns the captured
    /// error on attempt `n` iff `policy.is_final_attempt(n)` — the
    /// last invocation of `op` is at the smallest `n` for which the
    /// predicate fires. Load-bearing co-firing pin against any future
    /// regression that decoupled the predicate from the loop body's
    /// short-circuit (e.g., a refactor that promoted the retry-loop's
    /// `max(1)` clamp to a `max(2)` floor without updating the
    /// predicate, a refactor that broadened the predicate to fire on
    /// `attempt > max` instead of `>=`).
    #[tokio::test]
    async fn test_retry_policy_is_final_attempt_co_fires_with_run_with_policy_short_circuit() {
        let policies = [
            RetryPolicy::immediate(),
            RetryPolicy::network_with_max_attempts(1),
            RetryPolicy::new(2, Duration::ZERO, 1, Duration::ZERO),
            RetryPolicy::new(3, Duration::ZERO, 1, Duration::ZERO),
            RetryPolicy::new(5, Duration::ZERO, 1, Duration::ZERO),
        ];
        for p in &policies {
            let calls = Arc::new(AtomicU32::new(0));
            let last_seen = Arc::new(AtomicU32::new(0));
            let calls_clone = calls.clone();
            let last_seen_clone = last_seen.clone();
            let result: Result<(), &'static str> = run_with_policy(
                p,
                |_| true,
                |attempt| {
                    let calls = calls_clone.clone();
                    let last_seen = last_seen_clone.clone();
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        last_seen.store(attempt, Ordering::SeqCst);
                        Err::<(), &'static str>("err")
                    }
                },
            )
            .await;
            assert!(result.is_err());
            let observed = calls.load(Ordering::SeqCst);
            let last_attempt = last_seen.load(Ordering::SeqCst);
            // The last attempt the loop invoked must be the smallest n
            // for which is_final_attempt(n) is true — i.e., the loop
            // short-circuits exactly when the predicate fires.
            assert!(
                p.is_final_attempt(last_attempt),
                "{p:?}: predicate must fire on the last attempt invoked (attempt {last_attempt})"
            );
            if last_attempt > 1 {
                assert!(
                    !p.is_final_attempt(last_attempt - 1),
                    "{p:?}: predicate must NOT fire before the last attempt (attempt {})",
                    last_attempt - 1
                );
            }
            // Invocation count equals the last attempt (the loop ran
            // sequentially from 1 to the final attempt).
            assert_eq!(
                observed, last_attempt,
                "{p:?}: invocation count must equal the final attempt index"
            );
        }
    }

    /// [`RetryPolicy::is_interim_attempt`] is the named De Morgan
    /// complement of [`RetryPolicy::is_final_attempt`]:
    /// `is_interim_attempt(attempt) == !is_final_attempt(attempt)` holds
    /// for every [`RetryPolicy`] record and every 1-indexed attempt.
    /// Structural-complement pin across the full `max_attempts` ×
    /// `{ZERO, network}` schedule cross-product × attempt-count grid — a
    /// future regression that desynced the two predicates (e.g., one
    /// promoting its threshold off `>=` without the other, one reading
    /// a stale `initial_backoff.is_zero()` shortcut the other did not,
    /// a custom impl that drifted from the delegation) lights up this
    /// test.
    #[test]
    fn test_retry_policy_is_interim_attempt_complements_is_final_attempt() {
        let max_attempt_cases = [0u32, 1, 2, 5, 100, u32::MAX];
        let attempt_cases = [1u32, 2, 3, 4, 5, 6, 100, u32::MAX];
        for max_attempts in max_attempt_cases {
            for schedule in [
                (Duration::ZERO, 1, Duration::ZERO),
                (Duration::from_millis(250), 2, Duration::from_secs(30)),
            ] {
                let (initial_backoff, factor, max_backoff) = schedule;
                let p = RetryPolicy {
                    max_attempts,
                    initial_backoff,
                    factor,
                    max_backoff,
                };
                for attempt in attempt_cases {
                    assert_eq!(
                        p.is_interim_attempt(attempt),
                        !p.is_final_attempt(attempt),
                        "is_interim_attempt must complement is_final_attempt: \
                         max_attempts = {max_attempts}, attempt = {attempt}, schedule = {schedule:?}"
                    );
                }
            }
        }
    }

    /// [`RetryPolicy::is_interim_attempt`] discriminates the per-attempt
    /// "budget-remaining" partition across the canonical factory
    /// constructors. The canonical [`RetryPolicy::network`] policy with
    /// `max_attempts: 5` classifies attempts 1..=4 as interim and
    /// 5..=u32::MAX as non-interim (final); every no-retry shape
    /// ([`RetryPolicy::immediate`],
    /// [`RetryPolicy::network_with_max_attempts(1)`],
    /// [`RetryPolicy::network_or_immediate(false)`]) classifies attempt
    /// 1 as non-interim; the degenerate `max_attempts: 0` hand-built
    /// field-literal shape inherits the same clamp-to-≥1 discipline
    /// [`is_final_attempt`](RetryPolicy::is_final_attempt) applies, so
    /// attempt 1 is non-interim.
    #[test]
    fn test_retry_policy_is_interim_attempt_discriminates_canonical_factories() {
        // network() retries — attempts 1..=4 are interim, 5..=∞ are non-interim.
        let net = RetryPolicy::network();
        for attempt in 1..=4 {
            assert!(
                net.is_interim_attempt(attempt),
                "network() attempt {attempt} is interim (budget = 5)"
            );
        }
        for attempt in [5u32, 6, 100, u32::MAX] {
            assert!(
                !net.is_interim_attempt(attempt),
                "network() attempt {attempt} is not interim (>= budget = 5)"
            );
        }
        // immediate() is no-retry — attempt 1 is not interim.
        assert!(
            !RetryPolicy::immediate().is_interim_attempt(1),
            "immediate() attempt 1 is not interim (budget = 1)"
        );
        // network_with_max_attempts(1) is no-retry despite the network
        // schedule — attempt 1 is not interim.
        assert!(
            !RetryPolicy::network_with_max_attempts(1).is_interim_attempt(1),
            "network_with_max_attempts(1) attempt 1 is not interim"
        );
        // network_or_immediate(false) routes to immediate() — attempt 1 is not interim.
        assert!(
            !RetryPolicy::network_or_immediate(false).is_interim_attempt(1),
            "network_or_immediate(false) attempt 1 is not interim"
        );
        // network_or_immediate(true) routes to network() — attempt 1 IS interim.
        assert!(
            RetryPolicy::network_or_immediate(true).is_interim_attempt(1),
            "network_or_immediate(true) attempt 1 is interim (network budget = 5)"
        );
        // Degenerate hand-built max_attempts: 0 — clamp-to-≥1 makes
        // attempt 1 non-interim (matches is_final_attempt's degenerate arm).
        let degenerate = RetryPolicy {
            max_attempts: 0,
            initial_backoff: Duration::ZERO,
            factor: 1,
            max_backoff: Duration::ZERO,
        };
        assert!(
            !degenerate.is_interim_attempt(1),
            "max_attempts: 0 attempt 1 is not interim under clamp-to-≥1"
        );
    }

    /// [`RetryPolicy::is_interim_attempt`] reduces to the policy-level
    /// [`RetryPolicy::will_retry`] reading at `attempt = 1` — the per-
    /// attempt "budget-remaining" predicate's behavior at the first
    /// attempt names exactly the same retry-budget partition the
    /// policy-level "will-retry" predicate names. Closes the algebraic
    /// pair `is_final_attempt(1) == is_no_retry()` (pinned above) with
    /// its named-complement peer `is_interim_attempt(1) == will_retry()`
    /// across the full `max_attempts` × `{ZERO, network}` schedule
    /// cross-product.
    #[test]
    fn test_retry_policy_will_retry_equals_is_interim_attempt_at_one() {
        let cases = [0u32, 1, 2, 5, 100, u32::MAX];
        for max_attempts in cases {
            for schedule in [
                (Duration::ZERO, 1, Duration::ZERO),
                (Duration::from_millis(250), 2, Duration::from_secs(30)),
            ] {
                let (initial_backoff, factor, max_backoff) = schedule;
                let p = RetryPolicy {
                    max_attempts,
                    initial_backoff,
                    factor,
                    max_backoff,
                };
                assert_eq!(
                    p.is_interim_attempt(1),
                    p.will_retry(),
                    "is_interim_attempt(1) must equal will_retry(): \
                     max_attempts = {max_attempts}, schedule = {schedule:?}"
                );
            }
        }
    }

    /// [`RetryPolicy::is_interim_attempt`] is the structural witness for
    /// the warn-only-while-budget-remains dispatch at
    /// [`log_retry_attempt`]: the inline `attempt < max_attempts`
    /// predicate the warn is gated on is the raw-field spelling of the
    /// per-attempt "budget-remaining" partition the typed method names.
    /// For every canonical factory and every attempt in the reachable
    /// budget range, the typed-method reading and the
    /// `attempt < max_attempts` raw-field reading agree; the typed
    /// method additionally forecloses the degenerate `max_attempts: 0`
    /// arm through the clamp-to-≥1 discipline (a hand-built
    /// `max_attempts: 0` shape reads `attempt < 0 == false` at the raw-
    /// field spelling and `is_interim_attempt(attempt) == false` at the
    /// typed-method spelling — they agree on non-interim, but the
    /// typed-method reading names the invariant load-bearingly at the
    /// primitive surface). Pins the correspondence a future migration
    /// of [`log_retry_attempt`] to route through the typed predicate
    /// consumes.
    #[test]
    fn test_retry_policy_is_interim_attempt_matches_log_retry_attempt_predicate() {
        let policies = [
            RetryPolicy::immediate(),
            RetryPolicy::network(),
            RetryPolicy::network_with_max_attempts(1),
            RetryPolicy::network_with_max_attempts(3),
            RetryPolicy::network_or_immediate(true),
            RetryPolicy::network_or_immediate(false),
        ];
        for p in policies {
            let max = p.max_attempts;
            for attempt in [1u32, 2, 3, 4, 5, 6, 100] {
                // At canonical factories max_attempts is always >= 1
                // (clamped in the constructors), so the raw-field
                // reading and the typed-method reading agree exactly.
                assert_eq!(
                    p.is_interim_attempt(attempt),
                    attempt < max,
                    "log_retry_attempt's `attempt < max_attempts` predicate must \
                     equal is_interim_attempt(attempt) for canonical factories: \
                     policy = {p:?}, attempt = {attempt}"
                );
            }
        }
    }

    /// [`RetryPolicy::attempts_remaining`] returns `0` exactly when
    /// [`RetryPolicy::is_final_attempt`] fires — the algebraic law tying
    /// the numeric budget-remaining reading to the boolean per-attempt
    /// "is-this-the-last-one?" partition. Cross-product of the full
    /// `max_attempts × {ZERO, network}` schedule grid × attempt-count
    /// grid — 6 max_attempts × 2 schedules × 8 attempts = 96 pinned
    /// points. A future regression that desynced the numeric and boolean
    /// readings (e.g., off-by-one in `attempts_remaining`, or a change
    /// in the boolean predicate's threshold without a matching numeric
    /// change) lights up this test.
    #[test]
    fn test_retry_policy_attempts_remaining_zero_iff_is_final_attempt() {
        let schedules = [
            (std::time::Duration::ZERO, 1, std::time::Duration::ZERO),
            (
                std::time::Duration::from_millis(250),
                2,
                std::time::Duration::from_secs(30),
            ),
        ];
        for max_attempts in [0u32, 1, 2, 3, 5, 10] {
            for (initial_backoff, factor, max_backoff) in schedules {
                let p = RetryPolicy {
                    max_attempts,
                    initial_backoff,
                    factor,
                    max_backoff,
                };
                for attempt in [1u32, 2, 3, 4, 5, 6, 10, 100] {
                    assert_eq!(
                        p.attempts_remaining(attempt) == 0,
                        p.is_final_attempt(attempt),
                        "attempts_remaining(attempt) == 0 must equal is_final_attempt(attempt): \
                         max_attempts = {max_attempts}, attempt = {attempt}, schedule = {:?}",
                        (initial_backoff, factor, max_backoff)
                    );
                }
            }
        }
    }

    /// [`RetryPolicy::attempts_remaining`] returns a positive count
    /// exactly when [`RetryPolicy::is_interim_attempt`] fires — the
    /// algebraic law tying the numeric budget-remaining reading to the
    /// boolean per-attempt "is-another-attempt-in-budget?" partition
    /// (the complement of the `is_final_attempt` reading at the same
    /// axis). The peer-pair correspondence a future consumer relies on
    /// when it factors a boolean interim/final branch through the
    /// numeric budget-remaining threshold or vice versa.
    #[test]
    fn test_retry_policy_attempts_remaining_positive_iff_is_interim_attempt() {
        let schedules = [
            (std::time::Duration::ZERO, 1, std::time::Duration::ZERO),
            (
                std::time::Duration::from_millis(250),
                2,
                std::time::Duration::from_secs(30),
            ),
        ];
        for max_attempts in [0u32, 1, 2, 3, 5, 10] {
            for (initial_backoff, factor, max_backoff) in schedules {
                let p = RetryPolicy {
                    max_attempts,
                    initial_backoff,
                    factor,
                    max_backoff,
                };
                for attempt in [1u32, 2, 3, 4, 5, 6, 10, 100] {
                    assert_eq!(
                        p.attempts_remaining(attempt) > 0,
                        p.is_interim_attempt(attempt),
                        "attempts_remaining(attempt) > 0 must equal is_interim_attempt(attempt): \
                         max_attempts = {max_attempts}, attempt = {attempt}, schedule = {:?}",
                        (initial_backoff, factor, max_backoff)
                    );
                }
            }
        }
    }

    /// Per-attempt numeric budget-remaining discrimination across every
    /// canonical factory: `immediate()` (max=1) returns 0 at attempt 1
    /// and beyond; `network()` (max=5) counts down 4 → 3 → 2 → 1 → 0
    /// across attempts 1..=5, saturating at 0 for later attempts;
    /// `network_with_max_attempts(3)` (max=3) counts down 2 → 1 → 0;
    /// `network_or_immediate(true)` matches `network()` and
    /// `network_or_immediate(false)` matches `immediate()`. Pins the
    /// numeric budget accounting the canonical factories expose.
    #[test]
    fn test_retry_policy_attempts_remaining_discriminates_canonical_factories() {
        assert_eq!(RetryPolicy::immediate().attempts_remaining(1), 0);
        assert_eq!(RetryPolicy::immediate().attempts_remaining(2), 0);

        assert_eq!(RetryPolicy::network().attempts_remaining(1), 4);
        assert_eq!(RetryPolicy::network().attempts_remaining(2), 3);
        assert_eq!(RetryPolicy::network().attempts_remaining(3), 2);
        assert_eq!(RetryPolicy::network().attempts_remaining(4), 1);
        assert_eq!(RetryPolicy::network().attempts_remaining(5), 0);

        assert_eq!(
            RetryPolicy::network_with_max_attempts(3).attempts_remaining(1),
            2
        );
        assert_eq!(
            RetryPolicy::network_with_max_attempts(3).attempts_remaining(2),
            1
        );
        assert_eq!(
            RetryPolicy::network_with_max_attempts(3).attempts_remaining(3),
            0
        );

        assert_eq!(
            RetryPolicy::network_or_immediate(true).attempts_remaining(1),
            4
        );
        assert_eq!(
            RetryPolicy::network_or_immediate(false).attempts_remaining(1),
            0
        );
    }

    /// An out-of-budget `attempt` (past `max_attempts`) saturates to
    /// `0` rather than underflowing under the `saturating_sub`
    /// discipline. `network()` (max=5) reads `attempts_remaining(6)`,
    /// `attempts_remaining(100)`, `attempts_remaining(u32::MAX)` all as
    /// `0` — matching the retry-loop body's short-circuit at
    /// [`run_with_policy`], which returns after the final attempt and
    /// cannot invoke the reading at `attempt > max`. Pinning saturation
    /// at the typed-primitive surface forecloses a future consumer's
    /// silent underflow against an off-by-one call shape.
    #[test]
    fn test_retry_policy_attempts_remaining_saturates_out_of_budget() {
        let p = RetryPolicy::network();
        assert_eq!(p.attempts_remaining(6), 0);
        assert_eq!(p.attempts_remaining(100), 0);
        assert_eq!(p.attempts_remaining(u32::MAX), 0);

        let p3 = RetryPolicy::network_with_max_attempts(3);
        assert_eq!(p3.attempts_remaining(4), 0);
        assert_eq!(p3.attempts_remaining(u32::MAX), 0);
    }

    /// The degenerate hand-built `RetryPolicy { max_attempts: 0, .. }`
    /// shape (the field-literal shape every factory constructor's
    /// clamping discipline forecloses against) reads through the same
    /// clamp-to-≥1 discipline that [`is_final_attempt`] applies —
    /// `attempts_remaining(1) == 0` on the degenerate shape, matching
    /// `is_final_attempt(1) == true` and `is_interim_attempt(1) ==
    /// false`. Pins the clamp-invariant load-bearingly at the typed-
    /// primitive surface so a future consumer reading the numeric
    /// budget cannot silently classify a degenerate no-op policy's
    /// first attempt as "one attempt remaining".
    #[test]
    fn test_retry_policy_attempts_remaining_clamps_degenerate_max_attempts_zero() {
        let p = RetryPolicy {
            max_attempts: 0,
            initial_backoff: std::time::Duration::ZERO,
            factor: 1,
            max_backoff: std::time::Duration::ZERO,
        };
        assert_eq!(p.attempts_remaining(1), 0);
        assert_eq!(p.attempts_remaining(2), 0);
        assert_eq!(p.attempts_remaining(100), 0);
        assert!(p.is_final_attempt(1));
        assert!(!p.is_interim_attempt(1));
    }

    /// [`RetryPolicy::effective_max_attempts`] reads the same clamped budget
    /// as the inline `self.max_attempts.max(1)` cascade the retry-loop body
    /// and the constructors apply. Pinned across the full
    /// `max_attempts × {ZERO, network}` schedule cross-product: for every
    /// hand-built policy record the clamped-≥1 reading and the raw
    /// `max_attempts.max(1)` reading agree, foreclosing a future desync
    /// between the primitive and the constructor discipline.
    #[test]
    fn test_retry_policy_effective_max_attempts_equals_max_attempts_max_one() {
        let schedules = [
            (std::time::Duration::ZERO, 1, std::time::Duration::ZERO),
            (
                std::time::Duration::from_millis(250),
                2,
                std::time::Duration::from_secs(30),
            ),
        ];
        for max_attempts in [0u32, 1, 2, 3, 5, 10, u32::MAX] {
            for (initial_backoff, factor, max_backoff) in schedules {
                let p = RetryPolicy {
                    max_attempts,
                    initial_backoff,
                    factor,
                    max_backoff,
                };
                assert_eq!(
                    p.effective_max_attempts(),
                    max_attempts.max(1),
                    "effective_max_attempts must equal max_attempts.max(1): \
                     max_attempts = {max_attempts}, schedule = {:?}",
                    (initial_backoff, factor, max_backoff)
                );
                assert!(
                    p.effective_max_attempts() >= 1,
                    "effective_max_attempts must be >= 1: max_attempts = \
                     {max_attempts}, schedule = {:?}",
                    (initial_backoff, factor, max_backoff)
                );
            }
        }
    }

    /// Clamped-budget discrimination across every canonical factory:
    /// `immediate()` reads 1; `network()` reads 5; `network_with_max_attempts(n)`
    /// reads `n.max(1)` for `n ∈ {0, 1, 3, 7}`; `network_or_immediate(true)`
    /// matches `network()` and `network_or_immediate(false)` matches
    /// `immediate()`. Pins the numeric budget every canonical factory exposes.
    #[test]
    fn test_retry_policy_effective_max_attempts_discriminates_canonical_factories() {
        assert_eq!(RetryPolicy::immediate().effective_max_attempts(), 1);
        assert_eq!(RetryPolicy::network().effective_max_attempts(), 5);

        assert_eq!(
            RetryPolicy::network_with_max_attempts(0).effective_max_attempts(),
            1
        );
        assert_eq!(
            RetryPolicy::network_with_max_attempts(1).effective_max_attempts(),
            1
        );
        assert_eq!(
            RetryPolicy::network_with_max_attempts(3).effective_max_attempts(),
            3
        );
        assert_eq!(
            RetryPolicy::network_with_max_attempts(7).effective_max_attempts(),
            7
        );

        assert_eq!(
            RetryPolicy::network_or_immediate(true).effective_max_attempts(),
            5
        );
        assert_eq!(
            RetryPolicy::network_or_immediate(false).effective_max_attempts(),
            1
        );
    }

    /// The degenerate hand-built `RetryPolicy { max_attempts: 0, .. }` shape
    /// (the field-literal shape every factory constructor's clamping
    /// discipline forecloses against) reads through the clamp-to-≥1
    /// invariant: `effective_max_attempts() == 1`. Matches
    /// `is_final_attempt(1) == true`, `is_interim_attempt(1) == false`, and
    /// `attempts_remaining(1) == 0` on the same shape. Pins the load-bearing
    /// clamp invariant at the typed-primitive surface so a future consumer
    /// reading the clamped budget cannot silently classify the degenerate
    /// no-op policy as zero-budget.
    #[test]
    fn test_retry_policy_effective_max_attempts_clamps_degenerate_max_attempts_zero() {
        let p = RetryPolicy {
            max_attempts: 0,
            initial_backoff: std::time::Duration::ZERO,
            factor: 1,
            max_backoff: std::time::Duration::ZERO,
        };
        assert_eq!(p.effective_max_attempts(), 1);
        assert!(p.is_final_attempt(1));
        assert!(!p.is_interim_attempt(1));
        assert_eq!(p.attempts_remaining(1), 0);
    }

    /// [`RetryPolicy::is_final_attempt`] grounds through
    /// [`RetryPolicy::effective_max_attempts`] under the algebraic law
    /// `policy.is_final_attempt(a) == (a >= policy.effective_max_attempts())`
    /// — pinned across the full `max_attempts × {ZERO, network}` schedule
    /// cross-product × attempt-count grid. The structural anchor a future
    /// consumer relies on when it factors the per-attempt boolean partition
    /// through the clamped-budget numeric threshold or vice versa.
    #[test]
    fn test_retry_policy_effective_max_attempts_grounds_is_final_attempt() {
        let schedules = [
            (std::time::Duration::ZERO, 1, std::time::Duration::ZERO),
            (
                std::time::Duration::from_millis(250),
                2,
                std::time::Duration::from_secs(30),
            ),
        ];
        for max_attempts in [0u32, 1, 2, 3, 5, 10] {
            for (initial_backoff, factor, max_backoff) in schedules {
                let p = RetryPolicy {
                    max_attempts,
                    initial_backoff,
                    factor,
                    max_backoff,
                };
                for attempt in [1u32, 2, 3, 4, 5, 6, 10, 100] {
                    assert_eq!(
                        p.is_final_attempt(attempt),
                        attempt >= p.effective_max_attempts(),
                        "is_final_attempt must equal (attempt >= effective_max_attempts): \
                         max_attempts = {max_attempts}, attempt = {attempt}, schedule = {:?}",
                        (initial_backoff, factor, max_backoff)
                    );
                }
            }
        }
    }

    /// [`RetryPolicy::attempts_remaining`] grounds through
    /// [`RetryPolicy::effective_max_attempts`] under the algebraic law
    /// `policy.attempts_remaining(a) ==
    /// policy.effective_max_attempts().saturating_sub(a)` — pinned across
    /// the full `max_attempts × {ZERO, network}` schedule cross-product ×
    /// attempt-count grid, including out-of-budget attempts (u32::MAX)
    /// where the saturation invariant is load-bearing.
    #[test]
    fn test_retry_policy_effective_max_attempts_grounds_attempts_remaining() {
        let schedules = [
            (std::time::Duration::ZERO, 1, std::time::Duration::ZERO),
            (
                std::time::Duration::from_millis(250),
                2,
                std::time::Duration::from_secs(30),
            ),
        ];
        for max_attempts in [0u32, 1, 2, 3, 5, 10] {
            for (initial_backoff, factor, max_backoff) in schedules {
                let p = RetryPolicy {
                    max_attempts,
                    initial_backoff,
                    factor,
                    max_backoff,
                };
                for attempt in [1u32, 2, 3, 4, 5, 6, 10, 100, u32::MAX] {
                    assert_eq!(
                        p.attempts_remaining(attempt),
                        p.effective_max_attempts().saturating_sub(attempt),
                        "attempts_remaining must equal effective_max_attempts.saturating_sub(attempt): \
                         max_attempts = {max_attempts}, attempt = {attempt}, schedule = {:?}",
                        (initial_backoff, factor, max_backoff)
                    );
                }
            }
        }
    }

    /// [`RetryPolicy::is_no_retry`] grounds through
    /// [`RetryPolicy::effective_max_attempts`] under the algebraic law
    /// `policy.is_no_retry() == (policy.effective_max_attempts() == 1)` —
    /// pinned across every canonical factory and the degenerate hand-built
    /// `max_attempts: 0` shape. Closes the policy-level boolean-vs-numeric
    /// correspondence at the same retry-budget axis.
    #[test]
    fn test_retry_policy_effective_max_attempts_grounds_is_no_retry() {
        let cases = [
            RetryPolicy::immediate(),
            RetryPolicy::network(),
            RetryPolicy::network_with_max_attempts(1),
            RetryPolicy::network_with_max_attempts(3),
            RetryPolicy::network_with_max_attempts(7),
            RetryPolicy::network_or_immediate(true),
            RetryPolicy::network_or_immediate(false),
            RetryPolicy {
                max_attempts: 0,
                initial_backoff: std::time::Duration::ZERO,
                factor: 1,
                max_backoff: std::time::Duration::ZERO,
            },
        ];
        for p in cases {
            assert_eq!(
                p.is_no_retry(),
                p.effective_max_attempts() == 1,
                "is_no_retry must equal (effective_max_attempts == 1): policy = {p:?}"
            );
        }
    }

    /// [`RetryPolicy::will_retry`] grounds through
    /// [`RetryPolicy::effective_max_attempts`] under the algebraic law
    /// `policy.will_retry() == (policy.effective_max_attempts() > 1)` —
    /// pinned across every canonical factory and the degenerate hand-built
    /// `max_attempts: 0` shape. Closes the policy-level boolean-vs-numeric
    /// correspondence at the same retry-budget axis at the will-retry arm
    /// of the named-complement pair.
    #[test]
    fn test_retry_policy_effective_max_attempts_grounds_will_retry() {
        let cases = [
            RetryPolicy::immediate(),
            RetryPolicy::network(),
            RetryPolicy::network_with_max_attempts(1),
            RetryPolicy::network_with_max_attempts(3),
            RetryPolicy::network_with_max_attempts(7),
            RetryPolicy::network_or_immediate(true),
            RetryPolicy::network_or_immediate(false),
            RetryPolicy {
                max_attempts: 0,
                initial_backoff: std::time::Duration::ZERO,
                factor: 1,
                max_backoff: std::time::Duration::ZERO,
            },
        ];
        for p in cases {
            assert_eq!(
                p.will_retry(),
                p.effective_max_attempts() > 1,
                "will_retry must equal (effective_max_attempts > 1): policy = {p:?}"
            );
        }
    }

    /// [`RetryPolicy::is_first_attempt`] reads the raw `attempt <= 1`
    /// predicate — `true` at `attempt ∈ {0, 1}` (the pre-invocation
    /// counter reading and the first `op(attempt)` call), `false` at
    /// every `attempt >= 2` (any retry). Pinned across the full
    /// `max_attempts × {ZERO, network}` schedule cross-product ×
    /// attempt-count grid so a future regression that coupled the
    /// first-attempt reading to the clamped budget (e.g., misgrounded
    /// the predicate through
    /// [`RetryPolicy::effective_max_attempts`] as the ceiling peers do)
    /// lights up this test.
    #[test]
    fn test_retry_policy_is_first_attempt_reads_attempt_leq_one() {
        let schedules = [
            (Duration::ZERO, 1, Duration::ZERO),
            (Duration::from_millis(250), 2, Duration::from_secs(30)),
        ];
        for max_attempts in [0u32, 1, 2, 3, 5, 10, u32::MAX] {
            for (initial_backoff, factor, max_backoff) in schedules {
                let p = RetryPolicy {
                    max_attempts,
                    initial_backoff,
                    factor,
                    max_backoff,
                };
                for attempt in [0u32, 1, 2, 3, 4, 5, 10, 100, u32::MAX] {
                    assert_eq!(
                        p.is_first_attempt(attempt),
                        attempt <= 1,
                        "is_first_attempt must equal (attempt <= 1): \
                         max_attempts = {max_attempts}, attempt = {attempt}, \
                         schedule = {:?}",
                        (initial_backoff, factor, max_backoff)
                    );
                }
            }
        }
    }

    /// [`RetryPolicy::is_first_attempt`] is clamp-independent — the
    /// reading at any given `attempt` is identical across every
    /// canonical factory (`immediate()`, `network()`,
    /// `network_with_max_attempts(n)` for `n ∈ {0, 1, 3, 7}`,
    /// `network_or_immediate(true/false)`) and the degenerate hand-
    /// built `max_attempts: 0` shape. Load-bearing: pins the
    /// structural asymmetry that the per-attempt-axis floor does not
    /// depend on the clamped budget (unlike the ceiling peers). A
    /// future regression that coupled the floor to the budget lights
    /// up on the disagreement between any two policies.
    #[test]
    fn test_retry_policy_is_first_attempt_independent_of_policy() {
        let policies = [
            RetryPolicy::immediate(),
            RetryPolicy::network(),
            RetryPolicy::network_with_max_attempts(0),
            RetryPolicy::network_with_max_attempts(1),
            RetryPolicy::network_with_max_attempts(3),
            RetryPolicy::network_with_max_attempts(7),
            RetryPolicy::network_or_immediate(true),
            RetryPolicy::network_or_immediate(false),
            RetryPolicy {
                max_attempts: 0,
                initial_backoff: Duration::ZERO,
                factor: 1,
                max_backoff: Duration::ZERO,
            },
        ];
        for attempt in [0u32, 1, 2, 3, 4, 5, 10, 100, u32::MAX] {
            let readings: Vec<bool> = policies
                .iter()
                .map(|p| p.is_first_attempt(attempt))
                .collect();
            let first = readings[0];
            for (i, r) in readings.iter().enumerate() {
                assert_eq!(
                    *r, first,
                    "is_first_attempt must be clamp-independent: attempt = {attempt}, \
                     policies[0] reads {first}, policies[{i}] = {:?} reads {r}",
                    policies[i]
                );
            }
        }
    }

    /// [`RetryPolicy::is_retry_attempt`] complements
    /// [`RetryPolicy::is_first_attempt`] at every point in the
    /// `max_attempts × {ZERO, network} × attempt` cross-product grid —
    /// the load-bearing De Morgan complement law tying the FLOOR-anchor
    /// peer to the FLOOR-complement peer at the per-attempt-axis boolean
    /// surface. Mirrors the CEILING-side complement law
    /// [`test_retry_policy_is_interim_attempt_complements_is_final_attempt`]
    /// at the FLOOR side, closing the per-attempt-axis boolean 2×2
    /// quadrant grid at both ends.
    #[test]
    fn test_retry_policy_is_retry_attempt_complements_is_first_attempt() {
        let max_attempt_cases = [0u32, 1, 2, 5, 100, u32::MAX];
        let attempt_cases = [0u32, 1, 2, 3, 4, 5, 6, 100, u32::MAX];
        for max_attempts in max_attempt_cases {
            for schedule in [
                (Duration::ZERO, 1, Duration::ZERO),
                (Duration::from_millis(250), 2, Duration::from_secs(30)),
            ] {
                let (initial_backoff, factor, max_backoff) = schedule;
                let p = RetryPolicy {
                    max_attempts,
                    initial_backoff,
                    factor,
                    max_backoff,
                };
                for attempt in attempt_cases {
                    assert_eq!(
                        p.is_retry_attempt(attempt),
                        !p.is_first_attempt(attempt),
                        "is_retry_attempt must complement is_first_attempt: \
                         max_attempts = {max_attempts}, attempt = {attempt}, \
                         schedule = {schedule:?}"
                    );
                }
            }
        }
    }

    /// [`RetryPolicy::is_retry_attempt`] reads the raw `attempt > 1`
    /// predicate — `false` at `attempt ∈ {0, 1}` (the pre-invocation
    /// counter reading and the first `op(attempt)` call), `true` at
    /// every `attempt >= 2` (any retry). Pinned across the full
    /// `max_attempts × {ZERO, network}` schedule cross-product ×
    /// attempt-count grid so a future regression that coupled the
    /// retry-attempt reading to the clamped budget (e.g., misgrounded
    /// the predicate through
    /// [`RetryPolicy::effective_max_attempts`] as the ceiling peers do)
    /// lights up this test.
    #[test]
    fn test_retry_policy_is_retry_attempt_reads_attempt_gt_one() {
        let schedules = [
            (Duration::ZERO, 1, Duration::ZERO),
            (Duration::from_millis(250), 2, Duration::from_secs(30)),
        ];
        for max_attempts in [0u32, 1, 2, 3, 5, 10, u32::MAX] {
            for (initial_backoff, factor, max_backoff) in schedules {
                let p = RetryPolicy {
                    max_attempts,
                    initial_backoff,
                    factor,
                    max_backoff,
                };
                for attempt in [0u32, 1, 2, 3, 4, 5, 10, 100, u32::MAX] {
                    assert_eq!(
                        p.is_retry_attempt(attempt),
                        attempt > 1,
                        "is_retry_attempt must equal (attempt > 1): \
                         max_attempts = {max_attempts}, attempt = {attempt}, \
                         schedule = {:?}",
                        (initial_backoff, factor, max_backoff)
                    );
                }
            }
        }
    }

    /// [`RetryPolicy::is_retry_attempt`] is clamp-independent — the
    /// reading at any given `attempt` is identical across every
    /// canonical factory and the degenerate hand-built
    /// `max_attempts: 0` shape. Load-bearing peer of
    /// [`test_retry_policy_is_first_attempt_independent_of_policy`]:
    /// pins the structural asymmetry that BOTH sides of the
    /// per-attempt-axis FLOOR boolean partition are clamp-INDEPENDENT
    /// (unlike the CEILING pair, whose two sides both ground through
    /// [`RetryPolicy::effective_max_attempts`]). A future regression
    /// that coupled the FLOOR-COMPLEMENT peer to the budget lights up
    /// on the disagreement between any two policies.
    #[test]
    fn test_retry_policy_is_retry_attempt_independent_of_policy() {
        let policies = [
            RetryPolicy::immediate(),
            RetryPolicy::network(),
            RetryPolicy::network_with_max_attempts(0),
            RetryPolicy::network_with_max_attempts(1),
            RetryPolicy::network_with_max_attempts(3),
            RetryPolicy::network_with_max_attempts(7),
            RetryPolicy::network_or_immediate(true),
            RetryPolicy::network_or_immediate(false),
            RetryPolicy {
                max_attempts: 0,
                initial_backoff: Duration::ZERO,
                factor: 1,
                max_backoff: Duration::ZERO,
            },
        ];
        for attempt in [0u32, 1, 2, 3, 4, 5, 10, 100, u32::MAX] {
            let readings: Vec<bool> = policies
                .iter()
                .map(|p| p.is_retry_attempt(attempt))
                .collect();
            let first = readings[0];
            for (i, r) in readings.iter().enumerate() {
                assert_eq!(
                    *r, first,
                    "is_retry_attempt must be clamp-independent: attempt = {attempt}, \
                     policies[0] reads {first}, policies[{i}] = {:?} reads {r}",
                    policies[i]
                );
            }
        }
    }

    /// [`RetryPolicy::is_retry_attempt`] fires exactly when
    /// [`RetryPolicy::attempts_completed_before`] is positive — the
    /// algebraic law tying the boolean FLOOR-COMPLEMENT reading to the
    /// numeric FLOOR-EXCLUSIVE reading at the per-attempt-axis floor
    /// peer. Cross-product of the full `max_attempts × {ZERO, network}`
    /// schedule grid × attempt-count grid — a future regression that
    /// desynced the boolean and numeric floor peers (e.g., off-by-one
    /// in either, or a change in the boolean predicate's threshold
    /// without a matching numeric change) lights up this test. Mirrors
    /// the CEILING-side boolean-numeric correspondence law
    /// [`test_retry_policy_attempts_remaining_positive_iff_is_interim_attempt`]
    /// at the FLOOR side, closing the boolean-numeric correspondence at
    /// both ends of the per-attempt-axis.
    #[test]
    fn test_retry_policy_is_retry_attempt_iff_attempts_completed_before_positive() {
        let schedules = [
            (Duration::ZERO, 1, Duration::ZERO),
            (Duration::from_millis(250), 2, Duration::from_secs(30)),
        ];
        for max_attempts in [0u32, 1, 2, 3, 5, 10, u32::MAX] {
            for (initial_backoff, factor, max_backoff) in schedules {
                let p = RetryPolicy {
                    max_attempts,
                    initial_backoff,
                    factor,
                    max_backoff,
                };
                for attempt in [0u32, 1, 2, 3, 4, 5, 10, 100, u32::MAX] {
                    assert_eq!(
                        p.is_retry_attempt(attempt),
                        p.attempts_completed_before(attempt) > 0,
                        "is_retry_attempt must equal (attempts_completed_before > 0): \
                         max_attempts = {max_attempts}, attempt = {attempt}, \
                         schedule = {:?}",
                        (initial_backoff, factor, max_backoff)
                    );
                }
            }
        }
    }

    /// [`RetryPolicy::is_retry_attempt`] discriminates the per-attempt
    /// "first-vs-retry" partition across the canonical factory
    /// constructors identically to `!is_first_attempt` — the clamp-
    /// INDEPENDENT reading means every canonical factory classifies
    /// attempts `{0, 1}` as non-retry and every attempt `>= 2` as
    /// retry, independent of the clamped budget. The load-bearing
    /// witness that the FLOOR-COMPLEMENT peer preserves the
    /// clamp-independence of the FLOOR-ANCHOR peer across every factory
    /// shape.
    #[test]
    fn test_retry_policy_is_retry_attempt_discriminates_canonical_factories() {
        let policies = [
            RetryPolicy::immediate(),
            RetryPolicy::network(),
            RetryPolicy::network_with_max_attempts(1),
            RetryPolicy::network_with_max_attempts(3),
            RetryPolicy::network_with_max_attempts(7),
            RetryPolicy::network_or_immediate(true),
            RetryPolicy::network_or_immediate(false),
        ];
        for p in policies {
            assert!(
                !p.is_retry_attempt(0),
                "attempt 0 (pre-invocation) is not a retry: policy = {p:?}"
            );
            assert!(
                !p.is_retry_attempt(1),
                "attempt 1 (first call) is not a retry: policy = {p:?}"
            );
            for attempt in [2u32, 3, 4, 5, 10, 100, u32::MAX] {
                assert!(
                    p.is_retry_attempt(attempt),
                    "attempt {attempt} (>= 2) is a retry: policy = {p:?}"
                );
            }
        }
        // Degenerate hand-built max_attempts: 0 shape — the FLOOR-
        // COMPLEMENT peer is clamp-INDEPENDENT, so it agrees with every
        // canonical factory on the retry-attempt reading regardless of
        // the degenerate budget.
        let degenerate = RetryPolicy {
            max_attempts: 0,
            initial_backoff: Duration::ZERO,
            factor: 1,
            max_backoff: Duration::ZERO,
        };
        assert!(
            !degenerate.is_retry_attempt(0),
            "degenerate max_attempts: 0 attempt 0 is not a retry"
        );
        assert!(
            !degenerate.is_retry_attempt(1),
            "degenerate max_attempts: 0 attempt 1 is not a retry"
        );
        assert!(
            degenerate.is_retry_attempt(2),
            "degenerate max_attempts: 0 attempt 2 is a retry \
             (clamp-INDEPENDENT reading)"
        );
    }

    /// [`RetryPolicy::is_over_budget`] reads the raw `attempt >
    /// effective_max_attempts()` predicate — `true` at every `attempt >
    /// budget.max(1)`, `false` at every `attempt ∈ [0,
    /// effective_max_attempts()]`. Pinned across the full `max_attempts ×
    /// {ZERO, network}` schedule cross-product × attempt-count grid so a
    /// future regression that broadened the reading to fire on `>=`
    /// (collapsing the 3-way CEILING partition back to the anchor peer
    /// [`RetryPolicy::is_final_attempt`]) or dropped the clamp-to-≥1
    /// discipline (misgrounding through the raw `self.max_attempts`
    /// field) lights up this test.
    #[test]
    fn test_retry_policy_is_over_budget_reads_attempt_gt_effective_max() {
        let schedules = [
            (Duration::ZERO, 1, Duration::ZERO),
            (Duration::from_millis(250), 2, Duration::from_secs(30)),
        ];
        for max_attempts in [0u32, 1, 2, 3, 5, 10, u32::MAX] {
            for (initial_backoff, factor, max_backoff) in schedules {
                let p = RetryPolicy {
                    max_attempts,
                    initial_backoff,
                    factor,
                    max_backoff,
                };
                let cap = p.effective_max_attempts();
                for attempt in [0u32, 1, 2, 3, 4, 5, 6, 10, 100, u32::MAX] {
                    assert_eq!(
                        p.is_over_budget(attempt),
                        attempt > cap,
                        "is_over_budget must equal (attempt > effective_max_attempts()): \
                         max_attempts = {max_attempts}, effective = {cap}, attempt = {attempt}, \
                         schedule = {:?}",
                        (initial_backoff, factor, max_backoff)
                    );
                }
            }
        }
    }

    /// [`RetryPolicy::is_over_budget`] is a STRICT subset of
    /// [`RetryPolicy::is_final_attempt`] — every attempt classified as
    /// over-budget is also classified as final, but the converse fails at
    /// exactly one attempt-index: `attempt == effective_max_attempts()`
    /// (the AT-boundary case that distinguishes the strict `>` peer from
    /// the non-strict `>=` anchor). Cross-product of the full
    /// `max_attempts × {ZERO, network}` schedule grid × attempt-count
    /// grid, with an explicit AT-boundary assertion that the two
    /// predicates disagree at `attempt == cap`. A future regression that
    /// collapsed the 3-way CEILING partition back to the 2-way
    /// anchor/complement grid — e.g., a refactor that promoted the
    /// strict-past reading to a non-strict at-or-past reading — lights up
    /// this test.
    #[test]
    fn test_retry_policy_is_over_budget_implies_is_final_attempt() {
        let schedules = [
            (Duration::ZERO, 1, Duration::ZERO),
            (Duration::from_millis(250), 2, Duration::from_secs(30)),
        ];
        for max_attempts in [0u32, 1, 2, 3, 5, 10, u32::MAX] {
            for (initial_backoff, factor, max_backoff) in schedules {
                let p = RetryPolicy {
                    max_attempts,
                    initial_backoff,
                    factor,
                    max_backoff,
                };
                let cap = p.effective_max_attempts();
                for attempt in [0u32, 1, 2, 3, 4, 5, 6, 10, 100, u32::MAX] {
                    if p.is_over_budget(attempt) {
                        assert!(
                            p.is_final_attempt(attempt),
                            "is_over_budget must imply is_final_attempt: \
                             max_attempts = {max_attempts}, effective = {cap}, \
                             attempt = {attempt}, schedule = {:?}",
                            (initial_backoff, factor, max_backoff)
                        );
                    }
                }
                assert!(
                    p.is_final_attempt(cap),
                    "AT-boundary attempt {cap} must be final: max_attempts = {max_attempts}"
                );
                assert!(
                    !p.is_over_budget(cap),
                    "AT-boundary attempt {cap} must NOT be over-budget \
                     (the strict `>` reading distinguishes AT from PAST): \
                     max_attempts = {max_attempts}"
                );
                if let Some(past) = cap.checked_add(1) {
                    assert!(
                        p.is_over_budget(past),
                        "PAST-boundary attempt {past} must be over-budget: \
                         max_attempts = {max_attempts}"
                    );
                    assert!(
                        p.is_final_attempt(past),
                        "PAST-boundary attempt {past} must also be final \
                         (the non-strict `>=` reading fires on both AT and PAST): \
                         max_attempts = {max_attempts}"
                    );
                }
            }
        }
    }

    /// [`RetryPolicy::is_over_budget`] fires exactly when
    /// [`RetryPolicy::attempts_remaining_including`] reads zero — the
    /// algebraic law tying the CEILING BOOLEAN STRICT reading to the
    /// CEILING NUMERIC INCLUSIVE zero-slot reading. Cross-product of the
    /// full `max_attempts × {ZERO, network}` schedule grid × attempt-count
    /// grid — a future regression that desynced the boolean and numeric
    /// CEILING-strict peers (e.g., off-by-one in either primitive, drift
    /// in the clamp discipline between the two) lights up this test.
    /// Mirrors the CEILING-NON-STRICT boolean-numeric correspondence law
    /// [`test_retry_policy_attempts_remaining_positive_iff_is_interim_attempt`]
    /// at the strict peer, closing the boolean-numeric correspondence at
    /// both non-strict AND strict CEILING peers.
    #[test]
    fn test_retry_policy_is_over_budget_iff_attempts_remaining_including_zero() {
        let schedules = [
            (Duration::ZERO, 1, Duration::ZERO),
            (Duration::from_millis(250), 2, Duration::from_secs(30)),
        ];
        for max_attempts in [0u32, 1, 2, 3, 5, 10, u32::MAX] {
            for (initial_backoff, factor, max_backoff) in schedules {
                let p = RetryPolicy {
                    max_attempts,
                    initial_backoff,
                    factor,
                    max_backoff,
                };
                for attempt in [0u32, 1, 2, 3, 4, 5, 6, 10, 100, u32::MAX] {
                    assert_eq!(
                        p.is_over_budget(attempt),
                        p.attempts_remaining_including(attempt) == 0,
                        "is_over_budget must equal (attempts_remaining_including == 0): \
                         max_attempts = {max_attempts}, attempt = {attempt}, \
                         schedule = {:?}",
                        (initial_backoff, factor, max_backoff)
                    );
                }
            }
        }
    }

    /// [`RetryPolicy::is_over_budget`] discriminates the per-attempt
    /// "past-the-budget" partition across the canonical factory
    /// constructors. Because the reading is clamp-DEPENDENT (grounds
    /// through [`RetryPolicy::effective_max_attempts`]), the boundary
    /// varies by factory: [`RetryPolicy::immediate`] and
    /// [`RetryPolicy::network_or_immediate(false)`] read
    /// `effective_max_attempts() == 1` (so attempts ≥ 2 are past-budget),
    /// [`RetryPolicy::network`] reads `effective_max_attempts() == 5`
    /// (attempts ≥ 6 past-budget), and the degenerate hand-built
    /// `max_attempts: 0` shape reads `effective_max_attempts() == 1`
    /// under the clamp — matching the clamp-DEPENDENT CEILING discipline
    /// the other ceiling peers apply. Load-bearing witness that the
    /// STRICT CEILING peer preserves the clamp-DEPENDENCE of the
    /// NON-STRICT CEILING anchor across every factory shape.
    #[test]
    fn test_retry_policy_is_over_budget_discriminates_canonical_factories() {
        let cases: &[(RetryPolicy, u32)] = &[
            (RetryPolicy::immediate(), 1),
            (RetryPolicy::network(), 5),
            (RetryPolicy::network_with_max_attempts(1), 1),
            (RetryPolicy::network_with_max_attempts(3), 3),
            (RetryPolicy::network_with_max_attempts(7), 7),
            (RetryPolicy::network_or_immediate(true), 5),
            (RetryPolicy::network_or_immediate(false), 1),
        ];
        for (p, expected_cap) in cases {
            assert_eq!(
                p.effective_max_attempts(),
                *expected_cap,
                "canonical factory {p:?} must report effective_max_attempts = {expected_cap}"
            );
            for attempt in 0..=*expected_cap {
                assert!(
                    !p.is_over_budget(attempt),
                    "attempt {attempt} ≤ cap {expected_cap} is not over-budget: policy = {p:?}"
                );
            }
            for attempt in [
                expected_cap.saturating_add(1),
                expected_cap.saturating_add(2),
                expected_cap.saturating_add(10),
                u32::MAX,
            ] {
                assert!(
                    p.is_over_budget(attempt),
                    "attempt {attempt} > cap {expected_cap} is over-budget: policy = {p:?}"
                );
            }
        }
        // Degenerate hand-built max_attempts: 0 shape — the STRICT
        // CEILING peer is clamp-DEPENDENT, so it grounds through
        // effective_max_attempts() (which clamps to ≥ 1) and reads
        // as-if max_attempts == 1: attempts ≥ 2 are past-budget.
        let degenerate = RetryPolicy {
            max_attempts: 0,
            initial_backoff: Duration::ZERO,
            factor: 1,
            max_backoff: Duration::ZERO,
        };
        assert_eq!(
            degenerate.effective_max_attempts(),
            1,
            "degenerate max_attempts: 0 clamps to effective_max_attempts == 1"
        );
        assert!(
            !degenerate.is_over_budget(0),
            "degenerate max_attempts: 0 attempt 0 is not over-budget"
        );
        assert!(
            !degenerate.is_over_budget(1),
            "degenerate max_attempts: 0 attempt 1 is not over-budget (== cap)"
        );
        for attempt in [2u32, 3, 5, 10, 100, u32::MAX] {
            assert!(
                degenerate.is_over_budget(attempt),
                "degenerate max_attempts: 0 attempt {attempt} is over-budget \
                 (clamp-DEPENDENT reading grounds through the clamped cap of 1)"
            );
        }
    }

    /// [`RetryPolicy::is_over_budget`] partitions the per-attempt-axis
    /// CEILING into three regions in cooperation with
    /// [`RetryPolicy::is_final_attempt`] and
    /// [`RetryPolicy::is_interim_attempt`]: every attempt is in EXACTLY
    /// one of `BEFORE`, `AT`, or `PAST` boundary. The three regions are
    /// mutually exclusive and jointly exhaustive at every `attempt: u32`
    /// under every policy shape. A future regression that either
    /// admitted overlap (e.g., `is_over_budget` firing on `>=` so AT and
    /// PAST both fire together) or admitted a gap (e.g., `is_final_attempt`
    /// narrowed to fire only on `==` so AT falls through neither predicate
    /// class) lights up this test — the load-bearing structural witness
    /// that the strict CEILING peer closes the 3-way partition cleanly.
    #[test]
    fn test_retry_policy_is_over_budget_partitions_ceiling_three_ways() {
        let policies = [
            RetryPolicy::immediate(),
            RetryPolicy::network(),
            RetryPolicy::network_with_max_attempts(0),
            RetryPolicy::network_with_max_attempts(1),
            RetryPolicy::network_with_max_attempts(3),
            RetryPolicy::network_with_max_attempts(7),
            RetryPolicy::network_or_immediate(true),
            RetryPolicy::network_or_immediate(false),
            RetryPolicy {
                max_attempts: 0,
                initial_backoff: Duration::ZERO,
                factor: 1,
                max_backoff: Duration::ZERO,
            },
        ];
        for p in policies {
            for attempt in [0u32, 1, 2, 3, 4, 5, 6, 10, 100, u32::MAX] {
                let before = p.is_interim_attempt(attempt);
                let at = p.is_final_attempt(attempt) && !p.is_over_budget(attempt);
                let past = p.is_over_budget(attempt);
                let region_count = usize::from(before) + usize::from(at) + usize::from(past);
                assert_eq!(
                    region_count, 1,
                    "3-way CEILING partition must be mutually exclusive and jointly \
                     exhaustive: policy = {p:?}, attempt = {attempt}, \
                     BEFORE = {before}, AT = {at}, PAST = {past}"
                );
            }
        }
    }

    /// [`RetryPolicy::is_before_first_attempt`] reads the raw `attempt <
    /// 1` predicate — `true` at every `attempt == 0` (the pre-invocation
    /// counter reading), `false` at every `attempt >= 1`. Pinned across
    /// the full `max_attempts × {ZERO, network}` schedule cross-product ×
    /// attempt-count grid so a future regression that broadened the
    /// reading to fire on `<=` (collapsing the 3-way FLOOR partition back
    /// to the anchor peer
    /// [`RetryPolicy::is_first_attempt`]) or coupled the predicate to the
    /// clamped budget (misgrounding through
    /// [`RetryPolicy::effective_max_attempts`] as the ceiling peers do)
    /// lights up this test.
    #[test]
    fn test_retry_policy_is_before_first_attempt_reads_attempt_lt_one() {
        let schedules = [
            (Duration::ZERO, 1, Duration::ZERO),
            (Duration::from_millis(250), 2, Duration::from_secs(30)),
        ];
        for max_attempts in [0u32, 1, 2, 3, 5, 10, u32::MAX] {
            for (initial_backoff, factor, max_backoff) in schedules {
                let p = RetryPolicy {
                    max_attempts,
                    initial_backoff,
                    factor,
                    max_backoff,
                };
                for attempt in [0u32, 1, 2, 3, 4, 5, 10, 100, u32::MAX] {
                    assert_eq!(
                        p.is_before_first_attempt(attempt),
                        attempt < 1,
                        "is_before_first_attempt must equal (attempt < 1): \
                         max_attempts = {max_attempts}, attempt = {attempt}, \
                         schedule = {:?}",
                        (initial_backoff, factor, max_backoff)
                    );
                }
            }
        }
    }

    /// [`RetryPolicy::is_before_first_attempt`] is a STRICT subset of
    /// [`RetryPolicy::is_first_attempt`] — every attempt classified as
    /// before-first is also classified as first, but the converse fails
    /// at exactly one attempt-index: `attempt == 1` (the AT-boundary case
    /// that distinguishes the strict `<` peer from the non-strict `<=`
    /// anchor). Cross-product of the full `max_attempts × {ZERO,
    /// network}` schedule grid × attempt-count grid, with an explicit
    /// AT-boundary assertion that the two predicates disagree at
    /// `attempt == 1`. The FLOOR-side mirror of the CEILING-side
    /// strict-subset test
    /// [`test_retry_policy_is_over_budget_implies_is_final_attempt`]. A
    /// future regression that collapsed the 3-way FLOOR partition back to
    /// the 2-way anchor/complement grid — e.g., a refactor that promoted
    /// the strict-before reading to a non-strict at-or-before reading —
    /// lights up this test.
    #[test]
    fn test_retry_policy_is_before_first_attempt_implies_is_first_attempt() {
        let schedules = [
            (Duration::ZERO, 1, Duration::ZERO),
            (Duration::from_millis(250), 2, Duration::from_secs(30)),
        ];
        for max_attempts in [0u32, 1, 2, 3, 5, 10, u32::MAX] {
            for (initial_backoff, factor, max_backoff) in schedules {
                let p = RetryPolicy {
                    max_attempts,
                    initial_backoff,
                    factor,
                    max_backoff,
                };
                for attempt in [0u32, 1, 2, 3, 4, 5, 10, 100, u32::MAX] {
                    if p.is_before_first_attempt(attempt) {
                        assert!(
                            p.is_first_attempt(attempt),
                            "is_before_first_attempt must imply is_first_attempt: \
                             max_attempts = {max_attempts}, attempt = {attempt}, \
                             schedule = {:?}",
                            (initial_backoff, factor, max_backoff)
                        );
                    }
                }
                assert!(
                    p.is_first_attempt(1),
                    "AT-boundary attempt 1 must be first: max_attempts = {max_attempts}"
                );
                assert!(
                    !p.is_before_first_attempt(1),
                    "AT-boundary attempt 1 must NOT be before-first \
                     (the strict `<` reading distinguishes AT from BEFORE): \
                     max_attempts = {max_attempts}"
                );
                assert!(
                    p.is_before_first_attempt(0),
                    "BEFORE-boundary attempt 0 must be before-first: \
                     max_attempts = {max_attempts}"
                );
                assert!(
                    p.is_first_attempt(0),
                    "BEFORE-boundary attempt 0 must also be first \
                     (the non-strict `<=` reading fires on both AT and BEFORE): \
                     max_attempts = {max_attempts}"
                );
            }
        }
    }

    /// [`RetryPolicy::is_before_first_attempt`] fires exactly when
    /// [`RetryPolicy::attempts_used_through`] reads zero — the algebraic
    /// law tying the FLOOR BOOLEAN STRICT reading to the FLOOR NUMERIC
    /// INCLUSIVE zero-slot reading. Cross-product of the full
    /// `max_attempts × {ZERO, network}` schedule grid × attempt-count
    /// grid — a future regression that desynced the boolean and numeric
    /// FLOOR-strict peers (e.g., off-by-one in either primitive, or a
    /// change to the clamped-budget saturation shape of `attempts_used_through`)
    /// lights up this test. The FLOOR-side mirror of the CEILING-side
    /// boolean-numeric correspondence law
    /// [`test_retry_policy_is_over_budget_iff_attempts_remaining_including_zero`]
    /// at the strict peer, closing the boolean-numeric correspondence at
    /// both non-strict AND strict FLOOR peers.
    #[test]
    fn test_retry_policy_is_before_first_attempt_iff_attempts_used_through_zero() {
        let schedules = [
            (Duration::ZERO, 1, Duration::ZERO),
            (Duration::from_millis(250), 2, Duration::from_secs(30)),
        ];
        for max_attempts in [0u32, 1, 2, 3, 5, 10, u32::MAX] {
            for (initial_backoff, factor, max_backoff) in schedules {
                let p = RetryPolicy {
                    max_attempts,
                    initial_backoff,
                    factor,
                    max_backoff,
                };
                for attempt in [0u32, 1, 2, 3, 4, 5, 6, 10, 100, u32::MAX] {
                    assert_eq!(
                        p.is_before_first_attempt(attempt),
                        p.attempts_used_through(attempt) == 0,
                        "is_before_first_attempt must equal (attempts_used_through == 0): \
                         max_attempts = {max_attempts}, attempt = {attempt}, \
                         schedule = {:?}",
                        (initial_backoff, factor, max_backoff)
                    );
                }
            }
        }
    }

    /// [`RetryPolicy::is_before_first_attempt`] is clamp-independent —
    /// the reading at any given `attempt` is identical across every
    /// canonical factory (`immediate()`, `network()`,
    /// `network_with_max_attempts(n)` for `n ∈ {0, 1, 3, 7}`,
    /// `network_or_immediate(true/false)`) and the degenerate hand-built
    /// `max_attempts: 0` shape. Load-bearing peer of
    /// [`test_retry_policy_is_first_attempt_independent_of_policy`] and
    /// [`test_retry_policy_is_retry_attempt_independent_of_policy`]: pins
    /// the structural asymmetry that ALL THREE per-attempt-axis FLOOR
    /// boolean peers (NON-STRICT/COMPLEMENT/STRICT) are clamp-INDEPENDENT
    /// while ALL THREE per-attempt-axis CEILING boolean peers are
    /// clamp-DEPENDENT. A future regression that coupled the FLOOR STRICT
    /// peer to the budget lights up on the disagreement between any two
    /// policies.
    #[test]
    fn test_retry_policy_is_before_first_attempt_independent_of_policy() {
        let policies = [
            RetryPolicy::immediate(),
            RetryPolicy::network(),
            RetryPolicy::network_with_max_attempts(0),
            RetryPolicy::network_with_max_attempts(1),
            RetryPolicy::network_with_max_attempts(3),
            RetryPolicy::network_with_max_attempts(7),
            RetryPolicy::network_or_immediate(true),
            RetryPolicy::network_or_immediate(false),
            RetryPolicy {
                max_attempts: 0,
                initial_backoff: Duration::ZERO,
                factor: 1,
                max_backoff: Duration::ZERO,
            },
        ];
        for attempt in [0u32, 1, 2, 3, 4, 5, 10, 100, u32::MAX] {
            let readings: Vec<bool> = policies
                .iter()
                .map(|p| p.is_before_first_attempt(attempt))
                .collect();
            let first = readings[0];
            for (i, r) in readings.iter().enumerate() {
                assert_eq!(
                    *r, first,
                    "is_before_first_attempt must be clamp-independent: attempt = {attempt}, \
                     policies[0] reads {first}, policies[{i}] = {:?} reads {r}",
                    policies[i]
                );
            }
        }
    }

    /// [`RetryPolicy::is_before_first_attempt`] partitions the
    /// per-attempt-axis FLOOR into three regions in cooperation with
    /// [`RetryPolicy::is_first_attempt`] and
    /// [`RetryPolicy::is_retry_attempt`]: every attempt is in EXACTLY
    /// one of `BEFORE`, `AT`, or `PAST` boundary. The three regions are
    /// mutually exclusive and jointly exhaustive at every `attempt: u32`
    /// under every policy shape. The FLOOR-side mirror of
    /// [`test_retry_policy_is_over_budget_partitions_ceiling_three_ways`].
    /// A future regression that either admitted overlap (e.g.,
    /// `is_before_first_attempt` firing on `<=` so AT and BEFORE both fire
    /// together) or admitted a gap (e.g., `is_first_attempt` narrowed to
    /// fire only on `==` so BEFORE falls through neither predicate class)
    /// lights up this test — the load-bearing structural witness that the
    /// strict FLOOR peer closes the 3-way partition cleanly.
    #[test]
    fn test_retry_policy_is_before_first_attempt_partitions_floor_three_ways() {
        let policies = [
            RetryPolicy::immediate(),
            RetryPolicy::network(),
            RetryPolicy::network_with_max_attempts(0),
            RetryPolicy::network_with_max_attempts(1),
            RetryPolicy::network_with_max_attempts(3),
            RetryPolicy::network_with_max_attempts(7),
            RetryPolicy::network_or_immediate(true),
            RetryPolicy::network_or_immediate(false),
            RetryPolicy {
                max_attempts: 0,
                initial_backoff: Duration::ZERO,
                factor: 1,
                max_backoff: Duration::ZERO,
            },
        ];
        for p in policies {
            for attempt in [0u32, 1, 2, 3, 4, 5, 6, 10, 100, u32::MAX] {
                let before = p.is_before_first_attempt(attempt);
                let at = p.is_first_attempt(attempt) && !p.is_before_first_attempt(attempt);
                let past = p.is_retry_attempt(attempt);
                let region_count = usize::from(before) + usize::from(at) + usize::from(past);
                assert_eq!(
                    region_count, 1,
                    "3-way FLOOR partition must be mutually exclusive and jointly \
                     exhaustive: policy = {p:?}, attempt = {attempt}, \
                     BEFORE = {before}, AT = {at}, PAST = {past}"
                );
            }
        }
    }

    /// The per-attempt-axis BOOLEAN 3×2 grid at (FLOOR/CEILING ×
    /// NON-STRICT/COMPLEMENT/STRICT) splits by ONE universal property:
    /// every FLOOR boolean peer is a function of `attempt` alone
    /// (clamp-INDEPENDENT — the reading agrees across every policy at
    /// the same attempt); every CEILING boolean peer is a function of
    /// `(attempt, effective_max_attempts)` alone (clamp-DEPENDENT — the
    /// reading is determined by the clamped budget the CEILING peers
    /// ground through). This test pins that split as ONE structural
    /// property distinct from the per-side witness pair the per-
    /// predicate `_independent_of_policy` / `_discriminates_canonical_
    /// factories` tests already establish.
    ///
    /// # The FLOOR/CEILING clamp asymmetry
    ///
    /// The 3×2 grid of per-attempt-axis boolean peers closes at:
    ///
    /// ```text
    /// |         | NON-STRICT               | COMPLEMENT             | STRICT (⊂ anchor)         |
    /// | ------- | ------------------------ | ---------------------- | ------------------------- |
    /// | FLOOR   | is_first_attempt (<= 1)  | is_retry_attempt (> 1) | is_before_first_attempt (< 1) |
    /// | CEILING | is_final_attempt (>= m)  | is_interim_attempt (< m) | is_over_budget (> m)        |
    /// ```
    ///
    /// where `m = self.effective_max_attempts()` — the clamped budget
    /// [`RetryPolicy::effective_max_attempts`] names as the CEILING
    /// axis's grounded primitive. The FLOOR peers compare `attempt`
    /// against the fixed literal `1` (the retry-loop's 1-indexed first
    /// attempt), whose reading does not depend on `max_attempts` at all;
    /// the CEILING peers compare `attempt` against the clamped `m`,
    /// whose reading is determined by `max_attempts` (through the clamp
    /// to `>= 1`). The load-bearing structural asymmetry: the FLOOR
    /// half of the grid ignores the receiver; the CEILING half grounds
    /// through it.
    ///
    /// # Why the universal property is load-bearing
    ///
    /// The per-side clamp-independence-vs-dependence discipline was
    /// pinned per predicate (`test_retry_policy_is_first_attempt_
    /// independent_of_policy`, `test_retry_policy_is_retry_attempt_
    /// independent_of_policy`, `test_retry_policy_is_before_first_
    /// attempt_independent_of_policy` at the FLOOR side; `test_retry_
    /// policy_is_final_attempt_discriminates_canonical_factories`,
    /// `test_retry_policy_is_interim_attempt_discriminates_canonical_
    /// factories`, `test_retry_policy_is_over_budget_discriminates_
    /// canonical_factories` at the CEILING side). Each of those pins
    /// the property at one witness — one predicate's reading. A future
    /// regression that broke the FLOOR/CEILING split at a different
    /// axis than any single witness catches (e.g., a refactor that
    /// promoted every FLOOR peer to ground through
    /// `effective_max_attempts` without updating any single witness's
    /// clamp-independence test, or that promoted every CEILING peer to
    /// read against the fixed literal without updating any single
    /// witness's canonical-factory discrimination) would slip past every
    /// per-side witness. This universal property test pins the split at
    /// the level of the split itself, not at the level of any single
    /// witness — the load-bearing regression barrier the per-witness
    /// pairs cannot close alone.
    ///
    /// The universal property also names the FLOOR/CEILING split as
    /// ONE typed reading a future consumer (a `PerAttemptRegion` enum
    /// discriminated by both FLOOR and CEILING peers, a telemetry
    /// emitter that reads the 3-way partition as one label, a
    /// structured-attestation surface that classifies per-attempt
    /// events by both axes) can rely on: the FLOOR half determines
    /// the per-attempt phase without receiver context, the CEILING
    /// half grounds through the clamped budget. Both halves are
    /// necessary; the split is the load-bearing structural property.
    ///
    /// THEORY.md §II Language — typed primitives own boundary
    /// classification; the split between "boundary against the fixed
    /// first-attempt literal" and "boundary against the clamped budget"
    /// is a named structural property on the `RetryPolicy` typed-
    /// primitive surface, not a per-predicate coincidence to be
    /// rediscovered at every downstream consumer. THEORY.md §VI.1
    /// one-oracle discipline — the FLOOR/CEILING split is pinned at one
    /// structural test rather than as a per-predicate coincidence
    /// distributed across six independent witnesses.
    #[test]
    fn test_retry_policy_floor_ceiling_boolean_split_universal_property() {
        let policies = [
            RetryPolicy::immediate(),
            RetryPolicy::network(),
            RetryPolicy::network_with_max_attempts(0),
            RetryPolicy::network_with_max_attempts(1),
            RetryPolicy::network_with_max_attempts(3),
            RetryPolicy::network_with_max_attempts(7),
            RetryPolicy::network_or_immediate(true),
            RetryPolicy::network_or_immediate(false),
            RetryPolicy {
                max_attempts: 0,
                initial_backoff: Duration::ZERO,
                factor: 1,
                max_backoff: Duration::ZERO,
            },
        ];
        let attempts = [0u32, 1, 2, 3, 4, 5, 6, 10, 100, u32::MAX];
        for attempt in attempts {
            // FLOOR half: every peer reads (attempt <op> 1) against the
            // fixed first-attempt literal, so the reading is a pure
            // function of `attempt` — every policy agrees.
            let expected_first = attempt <= 1;
            let expected_retry = attempt > 1;
            let expected_before = attempt < 1;
            for p in &policies {
                assert_eq!(
                    p.is_first_attempt(attempt),
                    expected_first,
                    "FLOOR NON-STRICT is_first_attempt must be clamp-INDEPENDENT: \
                     attempt = {attempt}, policy = {p:?}, expected = {expected_first}"
                );
                assert_eq!(
                    p.is_retry_attempt(attempt),
                    expected_retry,
                    "FLOOR COMPLEMENT is_retry_attempt must be clamp-INDEPENDENT: \
                     attempt = {attempt}, policy = {p:?}, expected = {expected_retry}"
                );
                assert_eq!(
                    p.is_before_first_attempt(attempt),
                    expected_before,
                    "FLOOR STRICT is_before_first_attempt must be clamp-INDEPENDENT: \
                     attempt = {attempt}, policy = {p:?}, expected = {expected_before}"
                );
            }
            // CEILING half: every peer grounds through
            // `effective_max_attempts()`, so the reading is a pure
            // function of `(attempt, effective_max_attempts)`. Two
            // policies with the same clamped budget agree; two with
            // different clamped budgets can differ.
            for p in &policies {
                let eff = p.effective_max_attempts();
                assert_eq!(
                    p.is_final_attempt(attempt),
                    attempt >= eff,
                    "CEILING NON-STRICT is_final_attempt must ground through \
                     effective_max_attempts (clamp-DEPENDENT): attempt = {attempt}, \
                     policy = {p:?}, effective_max_attempts = {eff}"
                );
                assert_eq!(
                    p.is_interim_attempt(attempt),
                    attempt < eff,
                    "CEILING COMPLEMENT is_interim_attempt must ground through \
                     effective_max_attempts (clamp-DEPENDENT): attempt = {attempt}, \
                     policy = {p:?}, effective_max_attempts = {eff}"
                );
                assert_eq!(
                    p.is_over_budget(attempt),
                    attempt > eff,
                    "CEILING STRICT is_over_budget must ground through \
                     effective_max_attempts (clamp-DEPENDENT): attempt = {attempt}, \
                     policy = {p:?}, effective_max_attempts = {eff}"
                );
            }
        }
        // Cross-policy CEILING equivalence: any two policies that share
        // an `effective_max_attempts` produce identical CEILING readings
        // at every attempt. The load-bearing witness that the CEILING
        // reading is a function of the clamped-budget equivalence class,
        // not of the raw `max_attempts` field.
        for attempt in attempts {
            for p1 in &policies {
                for p2 in &policies {
                    if p1.effective_max_attempts() == p2.effective_max_attempts() {
                        assert_eq!(
                            p1.is_final_attempt(attempt),
                            p2.is_final_attempt(attempt),
                            "CEILING peers must agree on same effective_max_attempts: \
                             attempt = {attempt}, p1 = {p1:?}, p2 = {p2:?}"
                        );
                        assert_eq!(
                            p1.is_interim_attempt(attempt),
                            p2.is_interim_attempt(attempt),
                            "CEILING peers must agree on same effective_max_attempts: \
                             attempt = {attempt}, p1 = {p1:?}, p2 = {p2:?}"
                        );
                        assert_eq!(
                            p1.is_over_budget(attempt),
                            p2.is_over_budget(attempt),
                            "CEILING peers must agree on same effective_max_attempts: \
                             attempt = {attempt}, p1 = {p1:?}, p2 = {p2:?}"
                        );
                    }
                }
            }
        }
    }

    /// [`PerAttemptRegion::ALL`] contains every [`PerAttemptRegion`]
    /// variant. Uses an exhaustive `match` against the variant axis to
    /// refuse compilation until a future variant is added to `ALL` — the
    /// same single-source-enumeration discipline the sibling
    /// [`crate::probe_outcome::AdmissionTier::ALL`] and
    /// [`crate::version::BumpLevel::ALL`] tests pin at their surfaces
    /// (95e74ae / f891180). Every downstream property test iterating
    /// `PerAttemptRegion::ALL` picks up new variants automatically once
    /// this test is extended.
    #[test]
    fn test_per_attempt_region_all_contains_every_variant() {
        for region in PerAttemptRegion::ALL {
            let matched = match region {
                PerAttemptRegion::BeforeFirst
                | PerAttemptRegion::First
                | PerAttemptRegion::Interim
                | PerAttemptRegion::Final
                | PerAttemptRegion::OverBudget => true,
            };
            assert!(matched, "PerAttemptRegion::ALL must list every variant");
        }
        assert_eq!(
            PerAttemptRegion::ALL.len(),
            5,
            "PerAttemptRegion::ALL length must match variant count"
        );
    }

    /// [`RetryPolicy::per_attempt_region`] is a TOTAL, MUTUALLY-EXCLUSIVE
    /// function on `u32`: every `(policy, attempt)` pair in the canonical
    /// cross-product produces exactly one [`PerAttemptRegion`] variant.
    /// The load-bearing structural pin that the 5-way projection is a
    /// well-formed partition of the per-attempt-axis, not a merely-
    /// heuristic classifier: no attempt index at any policy falls into
    /// zero regions (totality) or two regions simultaneously (mutual
    /// exclusion). Cross-product of the full canonical-factory set ×
    /// attempt-index grid.
    #[test]
    fn test_retry_policy_per_attempt_region_is_total_and_mutually_exclusive() {
        let policies = [
            RetryPolicy::immediate(),
            RetryPolicy::network(),
            RetryPolicy::network_with_max_attempts(0),
            RetryPolicy::network_with_max_attempts(1),
            RetryPolicy::network_with_max_attempts(3),
            RetryPolicy::network_with_max_attempts(7),
            RetryPolicy::network_or_immediate(true),
            RetryPolicy::network_or_immediate(false),
            RetryPolicy {
                max_attempts: 0,
                initial_backoff: Duration::ZERO,
                factor: 1,
                max_backoff: Duration::ZERO,
            },
        ];
        let attempts = [0u32, 1, 2, 3, 4, 5, 6, 10, 100, u32::MAX];
        for p in &policies {
            for attempt in attempts {
                let region = p.per_attempt_region(attempt);
                // Totality: the exhaustive match reduces to `true`
                // exactly when the projection returns SOME variant. The
                // match itself refuses compilation if a future variant
                // is added without extending the projection body.
                let covered = match region {
                    PerAttemptRegion::BeforeFirst
                    | PerAttemptRegion::First
                    | PerAttemptRegion::Interim
                    | PerAttemptRegion::Final
                    | PerAttemptRegion::OverBudget => true,
                };
                assert!(
                    covered,
                    "per_attempt_region must be total: policy = {p:?}, attempt = {attempt}"
                );
                // Mutual exclusion: exactly one of the five candidate
                // classifications fires. Reading each region against the
                // projection's output as a boolean and summing counts
                // pins that no two regions co-fire.
                let hits = [
                    region == PerAttemptRegion::BeforeFirst,
                    region == PerAttemptRegion::First,
                    region == PerAttemptRegion::Interim,
                    region == PerAttemptRegion::Final,
                    region == PerAttemptRegion::OverBudget,
                ];
                let count = hits.iter().filter(|h| **h).count();
                assert_eq!(
                    count, 1,
                    "per_attempt_region must be mutually exclusive: \
                     policy = {p:?}, attempt = {attempt}, region = {region:?}"
                );
            }
        }
    }

    /// [`RetryPolicy::per_attempt_region`] grounds through the closed
    /// per-attempt-axis BOOLEAN 3×2 grid at every input — the load-
    /// bearing bridge from the six-peer boolean cascade to the 5-way
    /// typed sum. For every `(policy, attempt)`:
    ///
    /// * `OverBudget` iff `is_over_budget(attempt)`;
    /// * `Final` iff `is_final_attempt(attempt) && !is_over_budget(attempt)`;
    /// * `Interim` iff `is_retry_attempt(attempt) && !is_final_attempt(attempt)`;
    /// * `First` iff `is_first_attempt(attempt) && !is_before_first_attempt(attempt) && !is_final_attempt(attempt)`;
    /// * `BeforeFirst` iff `is_before_first_attempt(attempt)`.
    ///
    /// A future regression that broke the projection's boolean-peer
    /// cascade (e.g., swapped the FLOOR/CEILING resolution order at the
    /// `attempt == 1 == M` collision, or misgrounded any single branch)
    /// lights up this test at the first collision-relevant
    /// `(policy, attempt)`. Cross-product of the canonical-factory set ×
    /// attempt-index grid.
    #[test]
    fn test_retry_policy_per_attempt_region_grounds_through_boolean_peers() {
        let policies = [
            RetryPolicy::immediate(),
            RetryPolicy::network(),
            RetryPolicy::network_with_max_attempts(0),
            RetryPolicy::network_with_max_attempts(1),
            RetryPolicy::network_with_max_attempts(3),
            RetryPolicy::network_with_max_attempts(7),
            RetryPolicy::network_or_immediate(true),
            RetryPolicy::network_or_immediate(false),
            RetryPolicy {
                max_attempts: 0,
                initial_backoff: Duration::ZERO,
                factor: 1,
                max_backoff: Duration::ZERO,
            },
        ];
        let attempts = [0u32, 1, 2, 3, 4, 5, 6, 10, 100, u32::MAX];
        for p in &policies {
            for attempt in attempts {
                let region = p.per_attempt_region(attempt);
                let expected = if p.is_over_budget(attempt) {
                    PerAttemptRegion::OverBudget
                } else if p.is_final_attempt(attempt) {
                    PerAttemptRegion::Final
                } else if p.is_retry_attempt(attempt) {
                    PerAttemptRegion::Interim
                } else if p.is_before_first_attempt(attempt) {
                    PerAttemptRegion::BeforeFirst
                } else {
                    PerAttemptRegion::First
                };
                assert_eq!(
                    region,
                    expected,
                    "per_attempt_region must ground through the FLOOR/CEILING boolean \
                     cascade with CEILING winning at the boundary collision: \
                     policy = {p:?}, attempt = {attempt}, \
                     effective_max_attempts = {}",
                    p.effective_max_attempts()
                );
            }
        }
    }

    /// [`RetryPolicy::per_attempt_region`] at `attempt == 1` returns
    /// [`PerAttemptRegion::Final`] iff the policy is
    /// [`RetryPolicy::is_no_retry`], and [`PerAttemptRegion::First`]
    /// otherwise. The load-bearing FLOOR/CEILING collision-resolution
    /// pin: at the single-attempt case where `is_first_attempt(1) &&
    /// is_final_attempt(1)` both fire (the no-retry singleton
    /// [`tests::test_retry_policy_is_first_attempt_and_is_final_attempt_at_one_iff_no_retry`]
    /// pins), the projection collapses the collision by choosing the
    /// CEILING-side variant `Final` — the termination-relevant
    /// classification the retry loop itself reads. A future regression
    /// that inverted the tie-break to FLOOR-wins (returning `First` at
    /// the collision) or broadened it to a hypothetical `FirstAndOnly`
    /// variant without updating this test lights up here.
    #[test]
    fn test_retry_policy_per_attempt_region_absorbs_floor_ceiling_collision_at_no_retry() {
        let policies = [
            RetryPolicy::immediate(),
            RetryPolicy::network(),
            RetryPolicy::network_with_max_attempts(0),
            RetryPolicy::network_with_max_attempts(1),
            RetryPolicy::network_with_max_attempts(3),
            RetryPolicy::network_with_max_attempts(7),
            RetryPolicy::network_or_immediate(true),
            RetryPolicy::network_or_immediate(false),
            RetryPolicy {
                max_attempts: 0,
                initial_backoff: Duration::ZERO,
                factor: 1,
                max_backoff: Duration::ZERO,
            },
        ];
        for p in &policies {
            let region_at_one = p.per_attempt_region(1);
            let expected = if p.is_no_retry() {
                PerAttemptRegion::Final
            } else {
                PerAttemptRegion::First
            };
            assert_eq!(
                region_at_one,
                expected,
                "per_attempt_region(1) must absorb FLOOR/CEILING collision by CEILING: \
                 policy = {p:?}, is_no_retry = {}, effective_max_attempts = {}",
                p.is_no_retry(),
                p.effective_max_attempts()
            );
        }
    }

    /// [`RetryPolicy::per_attempt_region`] reads the expected variant at
    /// the anchor cases of the 5-way partition on a fixed multi-attempt
    /// policy (`network_with_max_attempts(3)`, `M = 3`). Fixed-witness
    /// pin distinct from the boolean-cascade grounding test: reads the
    /// projection at concrete `(attempt, region)` pairs so a future
    /// regression that broke the partition at ONE anchor without breaking
    /// the boolean cascade at that same anchor still lights up here.
    #[test]
    fn test_retry_policy_per_attempt_region_reads_five_way_partition_at_anchors() {
        let p = RetryPolicy::network_with_max_attempts(3);
        assert_eq!(p.effective_max_attempts(), 3);
        assert_eq!(
            p.per_attempt_region(0),
            PerAttemptRegion::BeforeFirst,
            "attempt < 1 must map to BeforeFirst"
        );
        assert_eq!(
            p.per_attempt_region(1),
            PerAttemptRegion::First,
            "attempt == 1 AND attempt < M must map to First"
        );
        assert_eq!(
            p.per_attempt_region(2),
            PerAttemptRegion::Interim,
            "1 < attempt < M must map to Interim"
        );
        assert_eq!(
            p.per_attempt_region(3),
            PerAttemptRegion::Final,
            "attempt == M must map to Final"
        );
        assert_eq!(
            p.per_attempt_region(4),
            PerAttemptRegion::OverBudget,
            "attempt > M must map to OverBudget"
        );
        assert_eq!(
            p.per_attempt_region(u32::MAX),
            PerAttemptRegion::OverBudget,
            "attempt >> M must map to OverBudget"
        );
    }

    /// [`PerAttemptRegion::is_terminal`] fires exactly at
    /// [`PerAttemptRegion::Final`] and [`PerAttemptRegion::OverBudget`]
    /// — the two CEILING-side variants at the projected sum surface — and
    /// nowhere else. The load-bearing variant-anchor pin at the ladder-
    /// ceiling reading: a regression that swept a third variant into the
    /// terminal disjunction (e.g., silently classifying `Interim` as
    /// terminal after a body edit) or dropped one of the two CEILING
    /// variants (e.g., an over-narrow `matches!(*self, Final)` body)
    /// lights up here.
    #[test]
    fn test_per_attempt_region_is_terminal_at_final_and_over_budget() {
        assert!(
            PerAttemptRegion::Final.is_terminal(),
            "Final is the ladder-ceiling variant — retry loop short-circuits here"
        );
        assert!(
            PerAttemptRegion::OverBudget.is_terminal(),
            "OverBudget is strictly past the ceiling — retry loop cannot dispatch further"
        );
        assert!(
            !PerAttemptRegion::BeforeFirst.is_terminal(),
            "BeforeFirst is a pre-invocation index — not a terminal region"
        );
        assert!(
            !PerAttemptRegion::First.is_terminal(),
            "First is a live in-schedule attempt — not a terminal region"
        );
        assert!(
            !PerAttemptRegion::Interim.is_terminal(),
            "Interim is a mid-schedule retry — not a terminal region"
        );
    }

    /// [`PerAttemptRegion::is_terminal`] agrees with the two-variant
    /// `matches!(*region, Final | OverBudget)` disjunction at every
    /// [`PerAttemptRegion::ALL`] variant — the structural pin that makes
    /// the derived `PartialEq`/`Eq` impl on the sum surface the load-
    /// bearing oracle for the CEILING-side ray reading. A regression that
    /// drifted the body to a different disjunction (e.g., `Final |
    /// Interim`, `Final` alone, or the whole-sum `matches!(*self, _)`)
    /// still passes
    /// [`test_per_attempt_region_is_terminal_at_final_and_over_budget`]
    /// only when the drift happens to land back on the same variant set;
    /// this pin refuses any variant-set desync against the canonical
    /// `Final | OverBudget` disjunction across every variant iteration.
    /// Iterates via [`PerAttemptRegion::ALL`] so a future variant addition
    /// automatically extends the coverage once `ALL` is extended.
    #[test]
    fn test_per_attempt_region_is_terminal_agrees_with_matches_final_or_over_budget() {
        for region in PerAttemptRegion::ALL {
            assert_eq!(
                region.is_terminal(),
                matches!(
                    region,
                    PerAttemptRegion::Final | PerAttemptRegion::OverBudget
                ),
                "is_terminal() must read the (Final | OverBudget) disjunction at {region:?}"
            );
        }
    }

    /// [`RetryPolicy::per_attempt_region`] projected through
    /// [`PerAttemptRegion::is_terminal`] reads `true` exactly when
    /// `attempt >= self.effective_max_attempts()` — the retry loop's
    /// structural short-circuit condition. The load-bearing grounding pin
    /// that bridges the sum-surface CEILING peer to the numeric
    /// per-attempt-axis reading: `region.is_terminal()` iff the retry loop
    /// would NOT dispatch a follow-up `op(attempt + 1)` after this
    /// attempt. A future regression that broke the projection's CEILING-
    /// side classification (e.g., misgrounded `Final` to a strictly-
    /// smaller attempt index) OR broke `is_terminal` at the sum surface
    /// (e.g., dropped `OverBudget` from the disjunction) lights up here at
    /// the first CEILING-side attempt-index. Cross-product of the
    /// canonical-factory set × attempt-index grid.
    ///
    /// The equivalence also grounds through the CEILING-side boolean-peer
    /// disjunction: `region.is_terminal()` iff
    /// `p.is_final_attempt(attempt) || p.is_over_budget(attempt)` — the
    /// two-peer boolean disjunction the projection factors into
    /// [`PerAttemptRegion::Final`] and [`PerAttemptRegion::OverBudget`]
    /// (commits eb0d5d1 / d55b12b). Pinning both equivalences at ONE
    /// test seals the sum-surface CEILING reading against desync with
    /// either the numeric axis or the boolean-peer ladder.
    #[test]
    fn test_retry_policy_per_attempt_region_is_terminal_iff_ge_effective_max() {
        let policies = [
            RetryPolicy::immediate(),
            RetryPolicy::network(),
            RetryPolicy::network_with_max_attempts(0),
            RetryPolicy::network_with_max_attempts(1),
            RetryPolicy::network_with_max_attempts(3),
            RetryPolicy::network_with_max_attempts(7),
            RetryPolicy::network_or_immediate(true),
            RetryPolicy::network_or_immediate(false),
            RetryPolicy {
                max_attempts: 0,
                initial_backoff: Duration::ZERO,
                factor: 1,
                max_backoff: Duration::ZERO,
            },
        ];
        let attempts = [0u32, 1, 2, 3, 4, 5, 6, 10, 100, u32::MAX];
        for p in &policies {
            let m = p.effective_max_attempts();
            for attempt in attempts {
                let terminal = p.per_attempt_region(attempt).is_terminal();
                assert_eq!(
                    terminal,
                    attempt >= m,
                    "is_terminal() at the sum surface must match the retry loop's \
                     short-circuit condition (attempt >= effective_max_attempts): \
                     policy = {p:?}, attempt = {attempt}, effective_max_attempts = {m}"
                );
                assert_eq!(
                    terminal,
                    p.is_final_attempt(attempt) || p.is_over_budget(attempt),
                    "is_terminal() at the sum surface must ground through the CEILING-side \
                     boolean-peer disjunction (is_final_attempt || is_over_budget): \
                     policy = {p:?}, attempt = {attempt}, effective_max_attempts = {m}"
                );
            }
        }
    }

    /// [`PerAttemptRegion::is_pre_terminal`] fires exactly at the three
    /// FLOOR-side variants ([`PerAttemptRegion::BeforeFirst`],
    /// [`PerAttemptRegion::First`], [`PerAttemptRegion::Interim`]) — the
    /// non-CEILING variants at the projected sum surface — and nowhere
    /// else. The load-bearing variant-anchor pin at the FLOOR-side
    /// reading: a regression that swept a CEILING-side variant into the
    /// pre-terminal disjunction (e.g., silently classifying `Final` as
    /// pre-terminal after a body edit) or dropped one of the three FLOOR
    /// variants (e.g., an over-narrow `matches!(*self, First | Interim)`
    /// body) lights up here.
    #[test]
    fn test_per_attempt_region_is_pre_terminal_at_before_first_first_interim() {
        assert!(
            PerAttemptRegion::BeforeFirst.is_pre_terminal(),
            "BeforeFirst is a pre-invocation index — retry loop has not short-circuited"
        );
        assert!(
            PerAttemptRegion::First.is_pre_terminal(),
            "First is a live in-schedule attempt — retry loop may dispatch a follow-up"
        );
        assert!(
            PerAttemptRegion::Interim.is_pre_terminal(),
            "Interim is a mid-schedule retry — retry loop may dispatch a follow-up"
        );
        assert!(
            !PerAttemptRegion::Final.is_pre_terminal(),
            "Final is the ladder-ceiling variant — retry loop short-circuits here"
        );
        assert!(
            !PerAttemptRegion::OverBudget.is_pre_terminal(),
            "OverBudget is strictly past the ceiling — retry loop cannot dispatch further"
        );
    }

    /// [`PerAttemptRegion::is_pre_terminal`] is the De Morgan complement
    /// of [`PerAttemptRegion::is_terminal`] at every
    /// [`PerAttemptRegion::ALL`] variant — the structural pin that ties
    /// the FLOOR-side sum-surface reading to the CEILING-side sum-surface
    /// reading at ONE named law. A regression that desynced the two
    /// predicates (e.g., one drifted onto a different variant set without
    /// the other) lights up here at the first offending variant. Iterates
    /// via [`PerAttemptRegion::ALL`] so a future variant addition
    /// automatically extends the coverage once `ALL` is extended.
    #[test]
    fn test_per_attempt_region_is_pre_terminal_complements_is_terminal() {
        for region in PerAttemptRegion::ALL {
            assert_eq!(
                region.is_pre_terminal(),
                !region.is_terminal(),
                "is_pre_terminal() must equal !is_terminal() at {region:?}"
            );
        }
    }

    /// [`PerAttemptRegion::is_pre_terminal`] agrees with the three-variant
    /// `matches!(*region, BeforeFirst | First | Interim)` disjunction at
    /// every [`PerAttemptRegion::ALL`] variant — the structural pin that
    /// makes the derived `PartialEq`/`Eq` impl on the sum surface the
    /// load-bearing oracle for the FLOOR-side ray reading. A regression
    /// that drifted the body to a different disjunction (e.g., `First |
    /// Interim`, `BeforeFirst | First`, or the whole-sum `matches!(*self,
    /// _)`) still passes
    /// [`test_per_attempt_region_is_pre_terminal_at_before_first_first_interim`]
    /// only when the drift happens to land back on the same variant set;
    /// this pin refuses any variant-set desync against the canonical
    /// `BeforeFirst | First | Interim` disjunction across every variant
    /// iteration.
    #[test]
    fn test_per_attempt_region_is_pre_terminal_agrees_with_matches_before_first_first_interim() {
        for region in PerAttemptRegion::ALL {
            assert_eq!(
                region.is_pre_terminal(),
                matches!(
                    region,
                    PerAttemptRegion::BeforeFirst
                        | PerAttemptRegion::First
                        | PerAttemptRegion::Interim
                ),
                "is_pre_terminal() must read the (BeforeFirst | First | Interim) disjunction at {region:?}"
            );
        }
    }

    /// [`RetryPolicy::per_attempt_region`] projected through
    /// [`PerAttemptRegion::is_pre_terminal`] reads `true` exactly when
    /// `attempt < self.effective_max_attempts()` — the retry loop's
    /// structural non-short-circuit condition. The load-bearing grounding
    /// pin that bridges the sum-surface FLOOR peer to the numeric
    /// per-attempt-axis reading: `region.is_pre_terminal()` iff the retry
    /// loop's `attempt < M` guard admits `op(attempt)` for another
    /// dispatch (or has not yet dispatched). A future regression that
    /// broke the projection's FLOOR-side classification OR broke
    /// `is_pre_terminal` at the sum surface (e.g., dropped a variant from
    /// the disjunction) lights up here at the first offending
    /// attempt-index. Cross-product of the canonical-factory set ×
    /// attempt-index grid.
    #[test]
    fn test_retry_policy_per_attempt_region_is_pre_terminal_iff_lt_effective_max() {
        let policies = [
            RetryPolicy::immediate(),
            RetryPolicy::network(),
            RetryPolicy::network_with_max_attempts(0),
            RetryPolicy::network_with_max_attempts(1),
            RetryPolicy::network_with_max_attempts(3),
            RetryPolicy::network_with_max_attempts(7),
            RetryPolicy::network_or_immediate(true),
            RetryPolicy::network_or_immediate(false),
            RetryPolicy {
                max_attempts: 0,
                initial_backoff: Duration::ZERO,
                factor: 1,
                max_backoff: Duration::ZERO,
            },
        ];
        let attempts = [0u32, 1, 2, 3, 4, 5, 6, 10, 100, u32::MAX];
        for p in &policies {
            let m = p.effective_max_attempts();
            for attempt in attempts {
                let pre_terminal = p.per_attempt_region(attempt).is_pre_terminal();
                assert_eq!(
                    pre_terminal,
                    attempt < m,
                    "is_pre_terminal() at the sum surface must match the retry loop's \
                     non-short-circuit condition (attempt < effective_max_attempts): \
                     policy = {p:?}, attempt = {attempt}, effective_max_attempts = {m}"
                );
                assert_eq!(
                    pre_terminal,
                    !p.per_attempt_region(attempt).is_terminal(),
                    "is_pre_terminal() must be the De Morgan complement of is_terminal at the \
                     sum-surface projection: policy = {p:?}, attempt = {attempt}, \
                     effective_max_attempts = {m}"
                );
            }
        }
    }

    /// [`PerAttemptRegion::is_out_of_schedule`] fires on
    /// [`PerAttemptRegion::BeforeFirst`] and [`PerAttemptRegion::OverBudget`]
    /// — the two STRICT-boundary diagnostic classes — and NOT on
    /// [`PerAttemptRegion::First`], [`PerAttemptRegion::Interim`], or
    /// [`PerAttemptRegion::Final`] — the three legal in-schedule
    /// invocation classes the retry loop at [`run_with_policy`] produces.
    /// Variant-anchor pin: a future regression that broadened the body
    /// to also fire on `Final` (silently reclassifying the final
    /// in-schedule attempt as a bug/replay class) or narrowed it to fire
    /// only on `OverBudget` (dropping the FLOOR-strict pre-invocation
    /// diagnostic) lights up here.
    #[test]
    fn test_per_attempt_region_is_out_of_schedule_at_before_first_and_over_budget() {
        assert!(PerAttemptRegion::BeforeFirst.is_out_of_schedule());
        assert!(PerAttemptRegion::OverBudget.is_out_of_schedule());
        assert!(!PerAttemptRegion::First.is_out_of_schedule());
        assert!(!PerAttemptRegion::Interim.is_out_of_schedule());
        assert!(!PerAttemptRegion::Final.is_out_of_schedule());
    }

    /// [`PerAttemptRegion::is_out_of_schedule`] agrees with the two-
    /// variant `matches!(*region, BeforeFirst | OverBudget)` disjunction
    /// at every [`PerAttemptRegion::ALL`] variant. Structural-shape pin
    /// that refuses a body drift onto a different variant set — a
    /// regression that promoted the body to `Final | OverBudget` (the
    /// CEILING terminal reading), `BeforeFirst | First` (the FLOOR
    /// closed-inclusive-below-first reading), or the whole-sum
    /// `matches!(*self, _)` still passes the variant-anchor test only
    /// when the drift happens to land back on the same variant set;
    /// this pin refuses any variant-set desync across every variant
    /// iteration.
    #[test]
    fn test_per_attempt_region_is_out_of_schedule_agrees_with_matches_before_first_or_over_budget()
    {
        for region in PerAttemptRegion::ALL {
            assert_eq!(
                region.is_out_of_schedule(),
                matches!(
                    region,
                    PerAttemptRegion::BeforeFirst | PerAttemptRegion::OverBudget
                ),
                "is_out_of_schedule() must read the (BeforeFirst | OverBudget) disjunction at {region:?}"
            );
        }
    }

    /// [`RetryPolicy::per_attempt_region`] projected through
    /// [`PerAttemptRegion::is_out_of_schedule`] reads `true` exactly when
    /// the two STRICT-boundary boolean peers fire —
    /// `p.is_before_first_attempt(a) || p.is_over_budget(a)` — the
    /// disjunction of the FLOOR-STRICT and CEILING-STRICT peers on the
    /// numeric axis. Grounding pin that bridges the sum-surface
    /// out-of-schedule reading to the STRICT-boundary boolean peers:
    /// `region.is_out_of_schedule()` iff the retry loop's counter
    /// leaves the closed inclusive `[1, effective_max_attempts()]`
    /// interval. A future regression that broke the projection's
    /// STRICT-boundary classification OR broke `is_out_of_schedule` at
    /// the sum surface lights up here at the first offending attempt-
    /// index. Cross-product of the canonical-factory set × attempt-
    /// index grid, including the degenerate `max_attempts: 0` hand-
    /// built field-literal shape.
    #[test]
    fn test_retry_policy_per_attempt_region_is_out_of_schedule_iff_strict_boundary() {
        let policies = [
            RetryPolicy::immediate(),
            RetryPolicy::network(),
            RetryPolicy::network_with_max_attempts(0),
            RetryPolicy::network_with_max_attempts(1),
            RetryPolicy::network_with_max_attempts(3),
            RetryPolicy::network_with_max_attempts(7),
            RetryPolicy::network_or_immediate(true),
            RetryPolicy::network_or_immediate(false),
            RetryPolicy {
                max_attempts: 0,
                initial_backoff: Duration::ZERO,
                factor: 1,
                max_backoff: Duration::ZERO,
            },
        ];
        let attempts = [0u32, 1, 2, 3, 4, 5, 6, 10, 100, u32::MAX];
        for p in &policies {
            let m = p.effective_max_attempts();
            for attempt in attempts {
                let out_of_schedule = p.per_attempt_region(attempt).is_out_of_schedule();
                let strict_boundary =
                    p.is_before_first_attempt(attempt) || p.is_over_budget(attempt);
                assert_eq!(
                    out_of_schedule, strict_boundary,
                    "is_out_of_schedule() at the sum surface must match the STRICT-boundary \
                     boolean disjunction (is_before_first_attempt || is_over_budget): \
                     policy = {p:?}, attempt = {attempt}, effective_max_attempts = {m}"
                );
                assert_eq!(
                    out_of_schedule,
                    attempt < 1 || attempt > m,
                    "is_out_of_schedule() must match the numeric out-of-schedule condition \
                     (attempt < 1 || attempt > effective_max_attempts): \
                     policy = {p:?}, attempt = {attempt}, effective_max_attempts = {m}"
                );
            }
        }
    }

    /// [`PerAttemptRegion::is_out_of_schedule`] and
    /// [`PerAttemptRegion::is_terminal`] name two ORTHOGONAL axes at the
    /// sum surface — the 2×2 cross-classification of every variant is
    /// pinned here. `OverBudget` sits at the intersection of the two
    /// affirmative readings (both terminal AND out-of-schedule);
    /// `Final` is terminal but IN-SCHEDULE; `BeforeFirst` is
    /// out-of-schedule but PRE-TERMINAL; `First` and `Interim` are
    /// neither. Refuses the silent axis-collapse a downstream consumer
    /// might infer from the shared `OverBudget` variant — the two
    /// predicates read distinct semantic axes even though they overlap
    /// on that one variant. A future regression that collapsed either
    /// axis onto the other (e.g., broadened `is_out_of_schedule` to
    /// match `Final` or narrowed `is_terminal` to exclude `OverBudget`)
    /// lights up here.
    #[test]
    fn test_per_attempt_region_out_of_schedule_orthogonal_to_terminal() {
        assert!(
            PerAttemptRegion::OverBudget.is_out_of_schedule()
                && PerAttemptRegion::OverBudget.is_terminal(),
            "OverBudget must be BOTH terminal AND out-of-schedule"
        );
        assert!(
            !PerAttemptRegion::Final.is_out_of_schedule() && PerAttemptRegion::Final.is_terminal(),
            "Final must be terminal but IN-SCHEDULE"
        );
        assert!(
            PerAttemptRegion::BeforeFirst.is_out_of_schedule()
                && !PerAttemptRegion::BeforeFirst.is_terminal(),
            "BeforeFirst must be out-of-schedule but PRE-TERMINAL"
        );
        for region in [PerAttemptRegion::First, PerAttemptRegion::Interim] {
            assert!(
                !region.is_out_of_schedule() && !region.is_terminal(),
                "{region:?} must be neither out-of-schedule nor terminal"
            );
        }
    }

    /// [`PerAttemptRegion::is_in_schedule`] fires exactly at the three
    /// LIVE in-schedule invocation variants ([`PerAttemptRegion::First`],
    /// [`PerAttemptRegion::Interim`], [`PerAttemptRegion::Final`]) — the
    /// three variants the retry loop at [`run_with_policy`] actually
    /// produces — and NOT at [`PerAttemptRegion::BeforeFirst`] or
    /// [`PerAttemptRegion::OverBudget`] — the two STRICT-boundary
    /// diagnostic classes. Variant-anchor pin: a future regression that
    /// swept `BeforeFirst` into the in-schedule reading (silently
    /// classifying a pre-invocation counter reading as a live
    /// invocation), swept `OverBudget` into the in-schedule reading
    /// (silently classifying a past-budget bug/replay index as a live
    /// invocation), or dropped one of the three in-schedule variants
    /// (e.g., an over-narrow `matches!(*self, First | Interim)` body that
    /// silently excluded the ladder-ceiling live attempt) lights up here.
    #[test]
    fn test_per_attempt_region_is_in_schedule_at_first_interim_final() {
        assert!(
            PerAttemptRegion::First.is_in_schedule(),
            "First is the first live in-schedule attempt — retry loop dispatches op(1)"
        );
        assert!(
            PerAttemptRegion::Interim.is_in_schedule(),
            "Interim is a mid-schedule live attempt — retry loop dispatches op(attempt)"
        );
        assert!(
            PerAttemptRegion::Final.is_in_schedule(),
            "Final is the last legal live attempt — retry loop dispatches op(M)"
        );
        assert!(
            !PerAttemptRegion::BeforeFirst.is_in_schedule(),
            "BeforeFirst is a pre-invocation counter reading — retry loop never reaches it"
        );
        assert!(
            !PerAttemptRegion::OverBudget.is_in_schedule(),
            "OverBudget is strictly past the budget — retry loop never reaches it"
        );
    }

    /// [`PerAttemptRegion::is_in_schedule`] is the De Morgan complement
    /// of [`PerAttemptRegion::is_out_of_schedule`] at every
    /// [`PerAttemptRegion::ALL`] variant — the structural pin that ties
    /// the affirmative in-schedule reading to the affirmative
    /// out-of-schedule reading at ONE named law at the sum surface. A
    /// regression that desynced the two predicates (e.g., one drifted
    /// onto a different variant set without the other) lights up here at
    /// the first offending variant. Iterates via
    /// [`PerAttemptRegion::ALL`] so a future variant addition
    /// automatically extends the pin's coverage.
    #[test]
    fn test_per_attempt_region_is_in_schedule_complements_is_out_of_schedule() {
        for region in PerAttemptRegion::ALL {
            assert_eq!(
                region.is_in_schedule(),
                !region.is_out_of_schedule(),
                "is_in_schedule() must be the De Morgan complement of is_out_of_schedule() at {region:?}"
            );
        }
    }

    /// [`PerAttemptRegion::is_in_schedule`] agrees with the three-variant
    /// `matches!(*region, First | Interim | Final)` disjunction at every
    /// [`PerAttemptRegion::ALL`] variant — the structural-shape pin that
    /// refuses a body drift onto a different variant set. A regression
    /// that promoted the body to `First | Interim | Final | OverBudget`
    /// (silently sweeping the past-budget bug/replay into the live
    /// class), narrowed it to `First | Final` (dropping the mid-schedule
    /// live retry), or reshaped it to any other variant set still passes
    /// the variant-anchor test only when the drift happens to land back
    /// on the same variant set; this pin refuses any variant-set desync
    /// across every variant iteration.
    #[test]
    fn test_per_attempt_region_is_in_schedule_agrees_with_matches_first_or_interim_or_final() {
        for region in PerAttemptRegion::ALL {
            assert_eq!(
                region.is_in_schedule(),
                matches!(
                    region,
                    PerAttemptRegion::First | PerAttemptRegion::Interim | PerAttemptRegion::Final
                ),
                "is_in_schedule() must read the (First | Interim | Final) disjunction at {region:?}"
            );
        }
    }

    /// [`RetryPolicy::per_attempt_region`] projected through
    /// [`PerAttemptRegion::is_in_schedule`] reads `true` exactly when
    /// the attempt index lies inside the closed inclusive range
    /// `[1, effective_max_attempts()]` — the range the retry loop's
    /// counter actually traverses. Grounding pin that bridges the
    /// sum-surface in-schedule reading to the closed-inclusive range on
    /// the numeric axis AND to the negated STRICT-boundary boolean
    /// disjunction (`!(is_before_first_attempt || is_over_budget)`) at
    /// every `(policy, attempt)`. A future regression that broke the
    /// projection's live-attempt classification OR broke `is_in_schedule`
    /// at the sum surface lights up here at the first offending
    /// attempt-index. Cross-product of the canonical-factory set ×
    /// attempt-index grid, including the degenerate `max_attempts: 0`
    /// hand-built field-literal shape.
    #[test]
    fn test_retry_policy_per_attempt_region_is_in_schedule_iff_closed_inclusive_range() {
        let policies = [
            RetryPolicy::immediate(),
            RetryPolicy::network(),
            RetryPolicy::network_with_max_attempts(0),
            RetryPolicy::network_with_max_attempts(1),
            RetryPolicy::network_with_max_attempts(3),
            RetryPolicy::network_with_max_attempts(7),
            RetryPolicy::network_or_immediate(true),
            RetryPolicy::network_or_immediate(false),
            RetryPolicy {
                max_attempts: 0,
                initial_backoff: Duration::ZERO,
                factor: 1,
                max_backoff: Duration::ZERO,
            },
        ];
        let attempts = [0u32, 1, 2, 3, 4, 5, 6, 10, 100, u32::MAX];
        for p in &policies {
            let m = p.effective_max_attempts();
            for attempt in attempts {
                let in_schedule = p.per_attempt_region(attempt).is_in_schedule();
                let negated_strict_boundary =
                    !(p.is_before_first_attempt(attempt) || p.is_over_budget(attempt));
                assert_eq!(
                    in_schedule, negated_strict_boundary,
                    "is_in_schedule() at the sum surface must match the negated STRICT-boundary \
                     boolean disjunction (!(is_before_first_attempt || is_over_budget)): \
                     policy = {p:?}, attempt = {attempt}, effective_max_attempts = {m}"
                );
                assert_eq!(
                    in_schedule,
                    (1..=m).contains(&attempt),
                    "is_in_schedule() must match the closed-inclusive range membership \
                     (1 <= attempt <= effective_max_attempts): \
                     policy = {p:?}, attempt = {attempt}, effective_max_attempts = {m}"
                );
            }
        }
    }

    /// [`PerAttemptRegion::BOTTOM`] names the bounded-ladder floor at
    /// [`PerAttemptRegion::BeforeFirst`] — the strictly-below-floor
    /// STRICT-boundary diagnostic class, the leftmost variant of the
    /// per-attempt-axis Ord chain. Exact-shape pin that forces a future
    /// variant insertion strictly below `BeforeFirst` (e.g., a
    /// hypothetical `NeverInvoked` distinct from the "counter at zero"
    /// reading) to shift the bounded-ladder anchor at this one site.
    #[test]
    fn test_per_attempt_region_bottom_named_at_ladder_floor() {
        assert_eq!(
            PerAttemptRegion::BOTTOM,
            PerAttemptRegion::BeforeFirst,
            "PerAttemptRegion::BOTTOM must name the ladder floor variant"
        );
    }

    /// [`PerAttemptRegion::TOP`] names the bounded-ladder ceiling at
    /// [`PerAttemptRegion::OverBudget`] — the strictly-past-ceiling
    /// STRICT-boundary diagnostic class, the rightmost variant of the
    /// per-attempt-axis Ord chain. Exact-shape pin — the dual of
    /// [`test_per_attempt_region_bottom_named_at_ladder_floor`] at the
    /// ceiling.
    #[test]
    fn test_per_attempt_region_top_named_at_ladder_ceiling() {
        assert_eq!(
            PerAttemptRegion::TOP,
            PerAttemptRegion::OverBudget,
            "PerAttemptRegion::TOP must name the ladder ceiling variant"
        );
    }

    /// [`PerAttemptRegion::BOTTOM`] equals the first element of
    /// [`PerAttemptRegion::ALL`] — the routing pin that ties the
    /// bounded-ladder anchor to the canonical-ladder-order enumeration
    /// surface. A refactor that reordered `ALL` but forgot to shift
    /// `BOTTOM` accordingly lights up here.
    #[test]
    fn test_per_attempt_region_bottom_equals_all_first() {
        assert_eq!(
            PerAttemptRegion::BOTTOM,
            *PerAttemptRegion::ALL.first().unwrap(),
            "PerAttemptRegion::BOTTOM must equal PerAttemptRegion::ALL.first()"
        );
    }

    /// [`PerAttemptRegion::TOP`] equals the last element of
    /// [`PerAttemptRegion::ALL`] — the routing pin that ties the
    /// bounded-ladder anchor to the canonical-ladder-order enumeration
    /// surface. Dual of
    /// [`test_per_attempt_region_bottom_equals_all_first`] at the
    /// ceiling.
    #[test]
    fn test_per_attempt_region_top_equals_all_last() {
        assert_eq!(
            PerAttemptRegion::TOP,
            *PerAttemptRegion::ALL.last().unwrap(),
            "PerAttemptRegion::TOP must equal PerAttemptRegion::ALL.last()"
        );
    }

    /// [`PerAttemptRegion::BOTTOM`] is the global lower bound of the
    /// derived [`Ord`] chain: `BOTTOM <= v` at every
    /// [`PerAttemptRegion::ALL`] variant. The structural anchor of
    /// "BOTTOM is the per-attempt-axis global lower bound." Iterates
    /// through `ALL` so a future variant addition automatically extends
    /// the pin's coverage.
    #[test]
    fn test_per_attempt_region_bottom_le_every_variant() {
        for region in PerAttemptRegion::ALL {
            assert!(
                PerAttemptRegion::BOTTOM <= region,
                "PerAttemptRegion::BOTTOM must be <= every variant, failed at {region:?}"
            );
        }
    }

    /// [`PerAttemptRegion::TOP`] is the global upper bound of the
    /// derived [`Ord`] chain: `v <= TOP` at every
    /// [`PerAttemptRegion::ALL`] variant. Dual of
    /// [`test_per_attempt_region_bottom_le_every_variant`] at the
    /// ceiling.
    #[test]
    fn test_per_attempt_region_top_ge_every_variant() {
        for region in PerAttemptRegion::ALL {
            assert!(
                region <= PerAttemptRegion::TOP,
                "PerAttemptRegion::TOP must be >= every variant, failed at {region:?}"
            );
        }
    }

    /// [`PerAttemptRegion::BOTTOM`] is strictly below
    /// [`PerAttemptRegion::TOP`] — the non-degeneracy pin that refuses
    /// a future collapse of the per-attempt-axis to a single-variant
    /// degenerate ladder. The structural witness that the bounded-
    /// ladder interval `[BOTTOM, TOP]` is non-empty / non-inverted.
    #[test]
    fn test_per_attempt_region_bottom_lt_top() {
        assert!(
            PerAttemptRegion::BOTTOM < PerAttemptRegion::TOP,
            "PerAttemptRegion::BOTTOM must be strictly less than PerAttemptRegion::TOP"
        );
    }

    /// Each [`PerAttemptRegion`] variant renders to its canonical
    /// lowercase snake_case string under [`PerAttemptRegion::as_str`].
    /// Fixed-shape pin at the label-axis oracle: a regression that
    /// drifted any variant's label (a typo `"pre_first"` substituting
    /// `"before_first"`, an UpperCamel `"BeforeFirst"` slipping in, or
    /// the two-word variants losing their underscore separator to
    /// `"beforefirst"` / `"overbudget"`) lights up here at exactly
    /// one site, preventing the drift from leaking to every consumer
    /// that surfaces the region as a string. Mirrors the discipline
    /// [`crate::probe_outcome::AdmissionTier::as_str`] and
    /// [`crate::version::BumpLevel::as_str`] pin at their sibling
    /// typed sums.
    #[test]
    fn test_per_attempt_region_as_str_canonical_strings() {
        assert_eq!(PerAttemptRegion::BeforeFirst.as_str(), "before_first");
        assert_eq!(PerAttemptRegion::First.as_str(), "first");
        assert_eq!(PerAttemptRegion::Interim.as_str(), "interim");
        assert_eq!(PerAttemptRegion::Final.as_str(), "final");
        assert_eq!(PerAttemptRegion::OverBudget.as_str(), "over_budget");
    }

    /// Every [`PerAttemptRegion`] variant's
    /// [`as_str`](PerAttemptRegion::as_str) rendering is lowercase +
    /// snake_case (lowercase ASCII letters, digits, or underscores
    /// only — no hyphens, no whitespace, no uppercase). Matches the
    /// discipline [`crate::version::BumpLevel::as_str`] and
    /// [`crate::probe_outcome::AdmissionTier::as_str`] established at
    /// the sibling typed sums, and the `serde(rename_all =
    /// "snake_case")` convention the deploy orchestrator's typed-enum
    /// YAML surfaces route through. Iterates
    /// [`PerAttemptRegion::ALL`] so a future variant insertion
    /// automatically inherits the discipline pin — a new variant
    /// labelled `"final-plus-one"` (kebab-case) or `"FinalPlusOne"`
    /// (UpperCamel) would light up here.
    #[test]
    fn test_per_attempt_region_as_str_lowercase_snake_case() {
        for region in PerAttemptRegion::ALL {
            let s = region.as_str();
            assert!(!s.is_empty(), "as_str must not be empty at {region:?}");
            assert!(
                s.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "as_str must be lowercase snake_case at {region:?} (got {s:?})",
            );
        }
    }

    /// Every [`PerAttemptRegion`] variant's
    /// [`as_str`](PerAttemptRegion::as_str) rendering is distinct from
    /// every other variant's — the variant→label mapping is injective
    /// across [`PerAttemptRegion::ALL`]. Pairs with
    /// [`test_per_attempt_region_as_str_canonical_strings`] (which pins
    /// the canonical labels) to seal the bijection between the variant
    /// axis and the label axis: a future variant insertion that
    /// collided with an existing label (e.g., a `PostFinal` variant
    /// mistakenly labelled `"final"`) would silently re-classify every
    /// telemetry consumer that branched on the label — this test
    /// surfaces the collision at the one source-of-truth site.
    /// Mirrors [`test_admission_tier_as_str_distinct`] at the sibling
    /// typed sum.
    #[test]
    fn test_per_attempt_region_as_str_distinct() {
        let mut labels: Vec<&'static str> = PerAttemptRegion::ALL
            .iter()
            .map(PerAttemptRegion::as_str)
            .collect();
        let n = labels.len();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(
            labels.len(),
            n,
            "as_str must be injective across ALL — no two variants share a label",
        );
    }

    /// [`PerAttemptRegion`]'s `Display` impl renders each variant as its
    /// canonical lowercase / snake_case string — the same label
    /// [`PerAttemptRegion::as_str`] returns. Fixed-shape pin at the
    /// `Display` surface: a regression that drifted the `Display` impl off
    /// [`as_str`] (e.g., a hand-written `match self { BeforeFirst =>
    /// write!(f, "BeforeFirst") }` cascade slipping in and re-introducing
    /// UpperCamel labels through `to_string()`, or a `Display` impl that
    /// forgot the underscore separator on `BeforeFirst` / `OverBudget`)
    /// lights up here at one site, preventing the drift from leaking to
    /// every `format!("{region}")` / `to_string()` consumer that surfaces
    /// the region as a string. Mirrors
    /// [`crate::probe_outcome::tests::test_admission_tier_display_canonical_strings`]
    /// at the sibling typed sum.
    #[test]
    fn test_per_attempt_region_display_canonical_strings() {
        assert_eq!(PerAttemptRegion::BeforeFirst.to_string(), "before_first");
        assert_eq!(PerAttemptRegion::First.to_string(), "first");
        assert_eq!(PerAttemptRegion::Interim.to_string(), "interim");
        assert_eq!(PerAttemptRegion::Final.to_string(), "final");
        assert_eq!(PerAttemptRegion::OverBudget.to_string(), "over_budget");
    }

    /// At every [`PerAttemptRegion`] variant, the `Display` rendering
    /// agrees byte-for-byte with [`PerAttemptRegion::as_str`]. The
    /// structural pin that ties the `Display` impl to the single-source
    /// `as_str` match body, so a future variant insertion automatically
    /// inherits both surfaces from the one site. Iterates
    /// [`PerAttemptRegion::ALL`] so the discipline extends to any future
    /// variant without an edit at the pin site. Mirrors the discipline
    /// [`crate::probe_outcome::tests::test_admission_tier_display_agrees_with_as_str`]
    /// established at the sibling typed sum: `Display` must agree with
    /// `as_str` at every variant the `ALL` const enumerates.
    #[test]
    fn test_per_attempt_region_display_agrees_with_as_str() {
        for region in PerAttemptRegion::ALL {
            assert_eq!(
                region.to_string(),
                region.as_str(),
                "Display and as_str must agree at {region:?}",
            );
        }
    }

    /// The five canonical lowercase / snake_case strings parse to the
    /// five [`PerAttemptRegion`] variants exactly — the grammar oracle
    /// inverse to [`PerAttemptRegion::as_str`] that every prior
    /// `match s { "before_first" | "first" | "interim" | "final" |
    /// "over_budget" | _ }` cascade at a downstream CLI / config /
    /// telemetry rehydration consumer now routes through. Mirrors the
    /// discipline
    /// [`crate::probe_outcome::tests::test_admission_tier_from_str_canonical_strings`]
    /// established at the sibling typed sum and
    /// [`crate::version::tests::test_bump_level_from_str_canonical_strings`]
    /// established at the sibling magnitude ladder.
    #[test]
    fn test_per_attempt_region_from_str_canonical_strings() {
        assert_eq!(
            "before_first".parse::<PerAttemptRegion>().unwrap(),
            PerAttemptRegion::BeforeFirst,
        );
        assert_eq!(
            "first".parse::<PerAttemptRegion>().unwrap(),
            PerAttemptRegion::First,
        );
        assert_eq!(
            "interim".parse::<PerAttemptRegion>().unwrap(),
            PerAttemptRegion::Interim,
        );
        assert_eq!(
            "final".parse::<PerAttemptRegion>().unwrap(),
            PerAttemptRegion::Final,
        );
        assert_eq!(
            "over_budget".parse::<PerAttemptRegion>().unwrap(),
            PerAttemptRegion::OverBudget,
        );
    }

    /// Any other string errors with wording that names the offending
    /// input and echoes the canonical grammar — same shape the
    /// [`crate::probe_outcome::AdmissionTier::from_str`] and
    /// [`crate::version::BumpLevel::from_str`] traps emit at the sibling
    /// typed sums. The parser is strict: empty input, UpperCamel
    /// rendering (as the derived [`Debug`] impl would emit), whitespace
    /// padding, uppercase, and snake_case labels with a dropped
    /// underscore all reject. A downstream surface that wants alias
    /// matrix or whitespace tolerance handles those concerns before
    /// routing the normalised string through this canonical parser.
    #[test]
    fn test_per_attempt_region_from_str_rejects_unknown() {
        let err = "invalid"
            .parse::<PerAttemptRegion>()
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("Invalid per-attempt region 'invalid'"),
            "error must name the offending input: {err}",
        );
        assert!(
            err.contains("use before_first, first, interim, final, or over_budget"),
            "error must echo the canonical grammar: {err}",
        );
        assert!(
            "".parse::<PerAttemptRegion>().is_err(),
            "empty string is rejected",
        );
        assert!(
            "BeforeFirst".parse::<PerAttemptRegion>().is_err(),
            "UpperCamel is rejected — only canonical lowercase parses",
        );
        assert!(
            "OverBudget".parse::<PerAttemptRegion>().is_err(),
            "UpperCamel is rejected — only canonical lowercase parses",
        );
        assert!(
            "FIRST".parse::<PerAttemptRegion>().is_err(),
            "uppercase is rejected — only canonical lowercase parses",
        );
        assert!(
            "  first ".parse::<PerAttemptRegion>().is_err(),
            "whitespace is not trimmed at this surface — caller's responsibility",
        );
        assert!(
            "beforefirst".parse::<PerAttemptRegion>().is_err(),
            "snake_case is load-bearing — `beforefirst` without the underscore is rejected",
        );
        assert!(
            "overbudget".parse::<PerAttemptRegion>().is_err(),
            "snake_case is load-bearing — `overbudget` without the underscore is rejected",
        );
    }

    /// At every [`PerAttemptRegion`] variant enumerated by
    /// [`PerAttemptRegion::ALL`], the round-trip `region -> Display ->
    /// FromStr` is the identity — `region.to_string()
    /// .parse::<PerAttemptRegion>().unwrap() == region`. The load-
    /// bearing structural pin that ties the canonical-label oracle
    /// ([`PerAttemptRegion::as_str`]) to its inverse
    /// ([`std::str::FromStr`]) via the [`std::fmt::Display`] impl that
    /// routes through [`as_str`]: a regression that drifted either side
    /// (e.g., a future variant insertion that extended [`as_str`]
    /// without a matching parser arm, or a parser-only alias extension
    /// that bypassed the [`as_str`] canonical label) desynchronises this
    /// pin at one site instead of leaking to every downstream telemetry
    /// / attestation consumer that reads a rehydrated
    /// [`PerAttemptRegion`] back from its serialized label. Mirrors the
    /// discipline
    /// [`crate::probe_outcome::tests::test_admission_tier_display_round_trips_through_from_str`]
    /// established at the sibling typed sum and
    /// [`crate::version::tests::test_bump_level_display_round_trips_through_from_str`]
    /// established at the sibling magnitude ladder.
    #[test]
    fn test_per_attempt_region_display_round_trips_through_from_str() {
        for region in PerAttemptRegion::ALL {
            let s = region.to_string();
            assert_eq!(
                s.parse::<PerAttemptRegion>().unwrap(),
                region,
                "Display→FromStr must round-trip at {region:?} (got {s:?})",
            );
            assert_eq!(
                s.as_str(),
                region.as_str(),
                "Display and as_str must agree at {region:?}",
            );
        }
    }

    /// Every [`PerAttemptRegion`] variant serialises to its canonical
    /// snake_case label — the same string [`PerAttemptRegion::as_str`]
    /// emits — through the `serde::Serialize` impl. The load-bearing
    /// structural pin that ties the canonical-label oracle to the serde
    /// write surface: a regression that swapped the `Serialize` impl to
    /// the derived UpperCamel labels (`"BeforeFirst"`, `"OverBudget"`)
    /// or diverged the label from [`as_str`] fails here at ONE named site
    /// instead of leaking to every downstream attestation record / YAML
    /// config emit / JSON telemetry consumer.
    #[test]
    fn test_per_attempt_region_serialize_emits_canonical_string_labels() {
        for region in PerAttemptRegion::ALL {
            let json = serde_json::to_string(&region).unwrap();
            let expected = format!("\"{}\"", region.as_str());
            assert_eq!(
                json, expected,
                "Serialize must emit canonical snake_case label at {region:?}",
            );
        }
    }

    /// Every canonical snake_case label deserialises back to its
    /// corresponding [`PerAttemptRegion`] variant through the
    /// `serde::Deserialize` impl. The load-bearing structural pin that
    /// ties the canonical-label parser ([`std::str::FromStr`]) to the
    /// serde read surface: a regression that swapped the `Deserialize`
    /// impl to accept the UpperCamel variant identifiers or diverged the
    /// accepted grammar from [`std::str::FromStr`] fails here at ONE
    /// named site instead of leaking to every downstream YAML config
    /// load / JSON telemetry replay / attestation-record rehydration
    /// consumer.
    #[test]
    fn test_per_attempt_region_deserialize_accepts_canonical_string_labels() {
        for region in PerAttemptRegion::ALL {
            let json = format!("\"{}\"", region.as_str());
            let parsed: PerAttemptRegion = serde_json::from_str(&json).unwrap();
            assert_eq!(
                parsed, region,
                "Deserialize must accept canonical label at {region:?} (input {json:?})",
            );
        }
    }

    /// The `serde::Deserialize` impl for [`PerAttemptRegion`] rejects any
    /// string outside the canonical snake_case grammar — the same strict-
    /// parse behaviour [`std::str::FromStr`] enforces, propagated to the
    /// serde read surface through
    /// [`serde::de::Error::custom`]. UpperCamel rendering (as the derived
    /// [`Debug`] impl would emit), uppercase, whitespace padding, and
    /// snake_case labels with a dropped underscore all reject. Non-string
    /// JSON scalars (numbers, booleans, nulls) reject at the visitor
    /// layer with the standard "invalid type" diagnostic. Sibling of
    /// [`test_per_attempt_region_from_str_rejects_unknown`] at the serde
    /// read surface — the strict-parse discipline is pinned at BOTH
    /// canonical-label parse sites.
    #[test]
    fn test_per_attempt_region_deserialize_rejects_unknown_string() {
        assert!(
            serde_json::from_str::<PerAttemptRegion>("\"invalid\"").is_err(),
            "unknown label rejects",
        );
        assert!(
            serde_json::from_str::<PerAttemptRegion>("\"\"").is_err(),
            "empty string rejects",
        );
        assert!(
            serde_json::from_str::<PerAttemptRegion>("\"BeforeFirst\"").is_err(),
            "UpperCamel rejects — only canonical lowercase parses",
        );
        assert!(
            serde_json::from_str::<PerAttemptRegion>("\"OverBudget\"").is_err(),
            "UpperCamel rejects — only canonical lowercase parses",
        );
        assert!(
            serde_json::from_str::<PerAttemptRegion>("\"FIRST\"").is_err(),
            "uppercase rejects — only canonical lowercase parses",
        );
        assert!(
            serde_json::from_str::<PerAttemptRegion>("\"  first \"").is_err(),
            "whitespace not trimmed — caller's responsibility",
        );
        assert!(
            serde_json::from_str::<PerAttemptRegion>("\"beforefirst\"").is_err(),
            "snake_case is load-bearing — `beforefirst` without the underscore rejects",
        );
        assert!(
            serde_json::from_str::<PerAttemptRegion>("\"overbudget\"").is_err(),
            "snake_case is load-bearing — `overbudget` without the underscore rejects",
        );
        assert!(
            serde_json::from_str::<PerAttemptRegion>("0").is_err(),
            "numeric scalar rejects at the visitor layer",
        );
        assert!(
            serde_json::from_str::<PerAttemptRegion>("true").is_err(),
            "boolean scalar rejects at the visitor layer",
        );
        assert!(
            serde_json::from_str::<PerAttemptRegion>("null").is_err(),
            "null scalar rejects at the visitor layer",
        );
    }

    /// At every [`PerAttemptRegion`] variant enumerated by
    /// [`PerAttemptRegion::ALL`], the round-trip `region -> Serialize ->
    /// Deserialize` through JSON is the identity — `serde_json::from_str
    /// (&serde_json::to_string(&region).unwrap()).unwrap() == region`.
    /// The load-bearing structural pin that ties the canonical-label
    /// oracle ([`PerAttemptRegion::as_str`]) to its serde-round-trip
    /// inverse via the `Serialize` impl that routes through [`as_str`]
    /// and the `Deserialize` impl that routes through [`std::str::FromStr`]:
    /// a regression that drifted either side (a `Serialize` change
    /// bypassing [`as_str`], a `Deserialize` change bypassing
    /// [`std::str::FromStr`], or a variant insertion without matching
    /// arms in both) desynchronises this pin at one site instead of
    /// leaking to every downstream YAML config / JSON telemetry /
    /// attestation-record consumer that reads a rehydrated
    /// [`PerAttemptRegion`] back from its serialised form. Sibling of
    /// [`test_per_attempt_region_display_round_trips_through_from_str`]
    /// at the string-scalar round-trip surface — the two round-trip
    /// pins together close the label-axis identity across both the
    /// `Display`/`FromStr` surface and the `Serialize`/`Deserialize`
    /// surface.
    #[test]
    fn test_per_attempt_region_serde_round_trips_through_json_at_every_variant() {
        for region in PerAttemptRegion::ALL {
            let json = serde_json::to_string(&region).unwrap();
            let parsed: PerAttemptRegion = serde_json::from_str(&json).unwrap();
            assert_eq!(
                parsed, region,
                "Serialize→Deserialize must round-trip through JSON at {region:?} (via {json:?})",
            );
        }
    }

    /// [`PerAttemptRegion::BOTTOM`] sits at the FLOOR-strict corner of
    /// the schedule-axis / terminal-axis 2×2 grid — it is
    /// out-of-schedule (the strictly-below-floor STRICT boundary) AND
    /// pre-terminal (the retry loop has not yet started, may still
    /// dispatch a follow-up). Grounds the bounded-ladder floor anchor
    /// through both sum-surface axes at ONE named pin.
    #[test]
    fn test_per_attempt_region_bottom_out_of_schedule_and_pre_terminal() {
        assert!(
            PerAttemptRegion::BOTTOM.is_out_of_schedule(),
            "PerAttemptRegion::BOTTOM must be out-of-schedule (strictly-below-floor STRICT boundary)"
        );
        assert!(
            PerAttemptRegion::BOTTOM.is_pre_terminal(),
            "PerAttemptRegion::BOTTOM must be pre-terminal (retry loop has not yet started)"
        );
    }

    /// [`PerAttemptRegion::TOP`] sits at the CEILING-strict corner of
    /// the schedule-axis / terminal-axis 2×2 grid — it is
    /// out-of-schedule (the strictly-past-ceiling STRICT boundary) AND
    /// terminal (the retry loop MUST NOT dispatch a follow-up, budget
    /// is exhausted). Grounds the bounded-ladder ceiling anchor
    /// through both sum-surface axes at ONE named pin. Together with
    /// [`test_per_attempt_region_bottom_out_of_schedule_and_pre_terminal`]
    /// pins BOTH strict-boundary anchors of the schedule axis at the
    /// bounded-ladder endpoints of the per-attempt-axis, and pins the
    /// off-diagonal split on the terminal axis at those two anchors
    /// (BOTTOM pre-terminal, TOP terminal).
    #[test]
    fn test_per_attempt_region_top_out_of_schedule_and_terminal() {
        assert!(
            PerAttemptRegion::TOP.is_out_of_schedule(),
            "PerAttemptRegion::TOP must be out-of-schedule (strictly-past-ceiling STRICT boundary)"
        );
        assert!(
            PerAttemptRegion::TOP.is_terminal(),
            "PerAttemptRegion::TOP must be terminal (retry loop must not dispatch a follow-up)"
        );
    }

    /// Exact-shape per-(a,b) pin over the 5×5 grid of
    /// [`PerAttemptRegion::ALL`] variants. Floor-sibling at the lattice-
    /// join surface, structural mirror of the corresponding
    /// [`crate::version::BumpLevel::join`] and
    /// [`crate::probe_outcome::AdmissionTier::join`] pins on the smaller
    /// ladders. Pins the exact answer at every corner of the closed
    /// per-attempt-axis 5×5 grid so a future variant insertion / ladder
    /// refinement lights up here rather than drifting silently.
    #[test]
    fn test_per_attempt_region_join_named_at_most_advanced_region_surface() {
        use PerAttemptRegion::*;
        let cases: &[(PerAttemptRegion, PerAttemptRegion, PerAttemptRegion)] = &[
            (BeforeFirst, BeforeFirst, BeforeFirst),
            (BeforeFirst, First, First),
            (BeforeFirst, Interim, Interim),
            (BeforeFirst, Final, Final),
            (BeforeFirst, OverBudget, OverBudget),
            (First, BeforeFirst, First),
            (First, First, First),
            (First, Interim, Interim),
            (First, Final, Final),
            (First, OverBudget, OverBudget),
            (Interim, BeforeFirst, Interim),
            (Interim, First, Interim),
            (Interim, Interim, Interim),
            (Interim, Final, Final),
            (Interim, OverBudget, OverBudget),
            (Final, BeforeFirst, Final),
            (Final, First, Final),
            (Final, Interim, Final),
            (Final, Final, Final),
            (Final, OverBudget, OverBudget),
            (OverBudget, BeforeFirst, OverBudget),
            (OverBudget, First, OverBudget),
            (OverBudget, Interim, OverBudget),
            (OverBudget, Final, OverBudget),
            (OverBudget, OverBudget, OverBudget),
        ];
        for (a, b, expected) in cases {
            assert_eq!(
                a.join(*b),
                *expected,
                "PerAttemptRegion::{a:?}.join({b:?}) must equal {expected:?}"
            );
        }
    }

    /// Structural-equivalence pin against [`Ord::max`] at every (a, b)
    /// over the 5×5 grid. Makes the `max` form the load-bearing oracle,
    /// so a future variant insertion that desynced the method body from
    /// the derived [`Ord`] chain lights up at the lattice-join surface
    /// rather than drifting silently.
    #[test]
    fn test_per_attempt_region_join_agrees_with_max_at_every_pair() {
        for a in PerAttemptRegion::ALL {
            for b in PerAttemptRegion::ALL {
                assert_eq!(
                    a.join(b),
                    a.max(b),
                    "PerAttemptRegion::{a:?}.join({b:?}) must equal {a:?}.max({b:?})"
                );
            }
        }
    }

    /// `a.join(a) == a` at every [`PerAttemptRegion::ALL`] variant. The
    /// idempotence axiom of the lattice-join surface, sibling of the
    /// reflexive-ordering pin at the derived-[`Ord`] surface.
    #[test]
    fn test_per_attempt_region_join_is_idempotent_at_every_variant() {
        for a in PerAttemptRegion::ALL {
            assert_eq!(
                a.join(a),
                a,
                "PerAttemptRegion::{a:?}.join({a:?}) must equal {a:?}"
            );
        }
    }

    /// `a.join(b) == b.join(a)` at every (a, b) over the 5×5 grid. The
    /// commutativity axiom of the lattice-join surface — the load-
    /// bearing fact a downstream most-advanced-region fold relies on to
    /// be insensitive to per-counter ORDER.
    #[test]
    fn test_per_attempt_region_join_is_commutative_at_every_pair() {
        for a in PerAttemptRegion::ALL {
            for b in PerAttemptRegion::ALL {
                assert_eq!(
                    a.join(b),
                    b.join(a),
                    "PerAttemptRegion::{a:?}.join({b:?}) must equal {b:?}.join({a:?})"
                );
            }
        }
    }

    /// `a.join(b.join(c)) == a.join(b).join(c)` at every (a, b, c) over
    /// the 5×5×5 grid. The associativity axiom of the lattice-join
    /// surface — the structural anchor a downstream most-advanced-region
    /// fold relies on to be insensitive to per-counter GROUPING.
    #[test]
    fn test_per_attempt_region_join_is_associative_at_every_triple() {
        for a in PerAttemptRegion::ALL {
            for b in PerAttemptRegion::ALL {
                for c in PerAttemptRegion::ALL {
                    assert_eq!(
                        a.join(b.join(c)),
                        a.join(b).join(c),
                        "PerAttemptRegion::{a:?}.join({b:?}.join({c:?})) must equal \
                         {a:?}.join({b:?}).join({c:?})"
                    );
                }
            }
        }
    }

    /// `BOTTOM.join(a) == a.join(BOTTOM) == a` at every variant. The
    /// load-bearing fact a downstream most-advanced-region fold seeds
    /// at [`PerAttemptRegion::BOTTOM`] with — a fold seeded at BOTTOM
    /// over a sequence returns the max of the sequence, or BOTTOM on an
    /// empty sequence (the no-progress reading).
    #[test]
    fn test_per_attempt_region_join_has_bottom_as_identity() {
        for a in PerAttemptRegion::ALL {
            assert_eq!(
                PerAttemptRegion::BOTTOM.join(a),
                a,
                "PerAttemptRegion::BOTTOM.join({a:?}) must equal {a:?}"
            );
            assert_eq!(
                a.join(PerAttemptRegion::BOTTOM),
                a,
                "PerAttemptRegion::{a:?}.join(BOTTOM) must equal {a:?}"
            );
        }
    }

    /// `TOP.join(a) == a.join(TOP) == TOP` at every variant. The load-
    /// bearing fact a downstream most-advanced-region fold can early-
    /// exit on: once any per-counter region reads
    /// [`PerAttemptRegion::TOP`], the aggregated most-advanced-region
    /// collapses to TOP regardless of the remaining counters.
    #[test]
    fn test_per_attempt_region_join_has_top_as_absorbing_element() {
        for a in PerAttemptRegion::ALL {
            assert_eq!(
                PerAttemptRegion::TOP.join(a),
                PerAttemptRegion::TOP,
                "PerAttemptRegion::TOP.join({a:?}) must equal TOP"
            );
            assert_eq!(
                a.join(PerAttemptRegion::TOP),
                PerAttemptRegion::TOP,
                "PerAttemptRegion::{a:?}.join(TOP) must equal TOP"
            );
        }
    }

    /// `a.join(b) >= a && a.join(b) >= b` at every (a, b) over the 5×5
    /// grid. The bounded-below-by-both-arguments law of the lattice-
    /// join surface — the structural anchor a downstream telemetry
    /// aggregator consumes ("the most-advanced-region reading subsumes
    /// every per-counter region") through one named site.
    #[test]
    fn test_per_attempt_region_join_bounded_below_by_both_arguments() {
        for a in PerAttemptRegion::ALL {
            for b in PerAttemptRegion::ALL {
                let j = a.join(b);
                assert!(
                    j >= a,
                    "PerAttemptRegion::{a:?}.join({b:?}) = {j:?} must be >= {a:?}"
                );
                assert!(
                    j >= b,
                    "PerAttemptRegion::{a:?}.join({b:?}) = {j:?} must be >= {b:?}"
                );
            }
        }
    }

    /// `a.join(b) ∈ {a, b}` at every (a, b) over the 5×5 grid. The
    /// structural witness that the lattice join over a TOTAL order is
    /// the identity-or-other readback — distinct from a free-lattice
    /// join that could return a third element outside `{a, b}`.
    #[test]
    fn test_per_attempt_region_join_returns_one_of_the_arguments() {
        for a in PerAttemptRegion::ALL {
            for b in PerAttemptRegion::ALL {
                let j = a.join(b);
                assert!(
                    j == a || j == b,
                    "PerAttemptRegion::{a:?}.join({b:?}) = {j:?} must be one of {{{a:?}, {b:?}}}"
                );
            }
        }
    }

    /// Exact-shape per-(a,b) pin over the 5×5 grid of
    /// [`PerAttemptRegion::ALL`] variants at the lattice-meet surface.
    /// Ceiling-sibling of
    /// [`test_per_attempt_region_join_named_at_most_advanced_region_surface`]
    /// at the lattice-join surface, structural mirror of the
    /// corresponding [`crate::version::BumpLevel::meet`] and
    /// [`crate::probe_outcome::AdmissionTier::meet`] pins on the
    /// smaller ladders. Pins the exact answer at every corner of the
    /// closed per-attempt-axis 5×5 grid so a future variant insertion
    /// / ladder refinement lights up at the least-advanced-region
    /// surface rather than drifting silently.
    #[test]
    fn test_per_attempt_region_meet_named_at_least_advanced_region_surface() {
        use PerAttemptRegion::*;
        let cases: &[(PerAttemptRegion, PerAttemptRegion, PerAttemptRegion)] = &[
            (BeforeFirst, BeforeFirst, BeforeFirst),
            (BeforeFirst, First, BeforeFirst),
            (BeforeFirst, Interim, BeforeFirst),
            (BeforeFirst, Final, BeforeFirst),
            (BeforeFirst, OverBudget, BeforeFirst),
            (First, BeforeFirst, BeforeFirst),
            (First, First, First),
            (First, Interim, First),
            (First, Final, First),
            (First, OverBudget, First),
            (Interim, BeforeFirst, BeforeFirst),
            (Interim, First, First),
            (Interim, Interim, Interim),
            (Interim, Final, Interim),
            (Interim, OverBudget, Interim),
            (Final, BeforeFirst, BeforeFirst),
            (Final, First, First),
            (Final, Interim, Interim),
            (Final, Final, Final),
            (Final, OverBudget, Final),
            (OverBudget, BeforeFirst, BeforeFirst),
            (OverBudget, First, First),
            (OverBudget, Interim, Interim),
            (OverBudget, Final, Final),
            (OverBudget, OverBudget, OverBudget),
        ];
        for (a, b, expected) in cases {
            assert_eq!(
                a.meet(*b),
                *expected,
                "PerAttemptRegion::{a:?}.meet({b:?}) must equal {expected:?}"
            );
        }
    }

    /// Structural-equivalence pin against [`Ord::min`] at every (a, b)
    /// over the 5×5 grid. Makes the `min` form the load-bearing oracle
    /// at the lattice-meet surface, so a future variant insertion that
    /// desynced the method body from the derived [`Ord`] chain lights
    /// up at the lattice-meet surface rather than drifting silently.
    /// Dual of
    /// [`test_per_attempt_region_join_agrees_with_max_at_every_pair`]
    /// at the lattice-join surface.
    #[test]
    fn test_per_attempt_region_meet_agrees_with_min_at_every_pair() {
        for a in PerAttemptRegion::ALL {
            for b in PerAttemptRegion::ALL {
                assert_eq!(
                    a.meet(b),
                    a.min(b),
                    "PerAttemptRegion::{a:?}.meet({b:?}) must equal {a:?}.min({b:?})"
                );
            }
        }
    }

    /// `a.meet(a) == a` at every [`PerAttemptRegion::ALL`] variant.
    /// The idempotence axiom of the lattice-meet surface, sibling of
    /// the reflexive-ordering pin at the derived-[`Ord`] surface. Dual
    /// of
    /// [`test_per_attempt_region_join_is_idempotent_at_every_variant`].
    #[test]
    fn test_per_attempt_region_meet_is_idempotent_at_every_variant() {
        for a in PerAttemptRegion::ALL {
            assert_eq!(
                a.meet(a),
                a,
                "PerAttemptRegion::{a:?}.meet({a:?}) must equal {a:?}"
            );
        }
    }

    /// `a.meet(b) == b.meet(a)` at every (a, b) over the 5×5 grid.
    /// The commutativity axiom of the lattice-meet surface — the
    /// load-bearing fact a downstream least-advanced-region fold
    /// relies on to be insensitive to per-counter ORDER. Dual of
    /// [`test_per_attempt_region_join_is_commutative_at_every_pair`].
    #[test]
    fn test_per_attempt_region_meet_is_commutative_at_every_pair() {
        for a in PerAttemptRegion::ALL {
            for b in PerAttemptRegion::ALL {
                assert_eq!(
                    a.meet(b),
                    b.meet(a),
                    "PerAttemptRegion::{a:?}.meet({b:?}) must equal {b:?}.meet({a:?})"
                );
            }
        }
    }

    /// `a.meet(b.meet(c)) == a.meet(b).meet(c)` at every (a, b, c)
    /// over the 5×5×5 grid. The associativity axiom of the lattice-
    /// meet surface — the structural anchor a downstream least-
    /// advanced-region fold relies on to be insensitive to per-
    /// counter GROUPING. Dual of
    /// [`test_per_attempt_region_join_is_associative_at_every_triple`].
    #[test]
    fn test_per_attempt_region_meet_is_associative_at_every_triple() {
        for a in PerAttemptRegion::ALL {
            for b in PerAttemptRegion::ALL {
                for c in PerAttemptRegion::ALL {
                    assert_eq!(
                        a.meet(b.meet(c)),
                        a.meet(b).meet(c),
                        "PerAttemptRegion::{a:?}.meet({b:?}.meet({c:?})) must equal \
                         {a:?}.meet({b:?}).meet({c:?})"
                    );
                }
            }
        }
    }

    /// `TOP.meet(a) == a.meet(TOP) == a` at every variant. The load-
    /// bearing fact a downstream least-advanced-region fold seeds at
    /// [`PerAttemptRegion::TOP`] with — a fold seeded at TOP over a
    /// sequence returns the min of the sequence, or TOP on an empty
    /// sequence (the no-input reading, dual to the empty-fold BOTTOM
    /// reading at the join surface). Dual of
    /// [`test_per_attempt_region_join_has_bottom_as_identity`].
    #[test]
    fn test_per_attempt_region_meet_has_top_as_identity() {
        for a in PerAttemptRegion::ALL {
            assert_eq!(
                PerAttemptRegion::TOP.meet(a),
                a,
                "PerAttemptRegion::TOP.meet({a:?}) must equal {a:?}"
            );
            assert_eq!(
                a.meet(PerAttemptRegion::TOP),
                a,
                "PerAttemptRegion::{a:?}.meet(TOP) must equal {a:?}"
            );
        }
    }

    /// `BOTTOM.meet(a) == a.meet(BOTTOM) == BOTTOM` at every variant.
    /// The load-bearing fact a downstream least-advanced-region fold
    /// can early-exit on: once any per-counter region reads
    /// [`PerAttemptRegion::BOTTOM`], the aggregated least-advanced-
    /// region collapses to BOTTOM regardless of the remaining
    /// counters. Dual of
    /// [`test_per_attempt_region_join_has_top_as_absorbing_element`].
    #[test]
    fn test_per_attempt_region_meet_has_bottom_as_absorbing_element() {
        for a in PerAttemptRegion::ALL {
            assert_eq!(
                PerAttemptRegion::BOTTOM.meet(a),
                PerAttemptRegion::BOTTOM,
                "PerAttemptRegion::BOTTOM.meet({a:?}) must equal BOTTOM"
            );
            assert_eq!(
                a.meet(PerAttemptRegion::BOTTOM),
                PerAttemptRegion::BOTTOM,
                "PerAttemptRegion::{a:?}.meet(BOTTOM) must equal BOTTOM"
            );
        }
    }

    /// `a.meet(b) <= a && a.meet(b) <= b` at every (a, b) over the 5×5
    /// grid. The bounded-above-by-both-arguments law of the lattice-
    /// meet surface — the structural anchor a downstream telemetry
    /// aggregator consumes ("the least-advanced-region reading is at
    /// or below every per-counter region") through one named site.
    /// Dual of
    /// [`test_per_attempt_region_join_bounded_below_by_both_arguments`].
    #[test]
    fn test_per_attempt_region_meet_bounded_above_by_both_arguments() {
        for a in PerAttemptRegion::ALL {
            for b in PerAttemptRegion::ALL {
                let m = a.meet(b);
                assert!(
                    m <= a,
                    "PerAttemptRegion::{a:?}.meet({b:?}) = {m:?} must be <= {a:?}"
                );
                assert!(
                    m <= b,
                    "PerAttemptRegion::{a:?}.meet({b:?}) = {m:?} must be <= {b:?}"
                );
            }
        }
    }

    /// `a.meet(b) ∈ {a, b}` at every (a, b) over the 5×5 grid. The
    /// structural witness that the lattice meet over a TOTAL order is
    /// the identity-or-other readback — distinct from a free-lattice
    /// meet that could return a third element outside `{a, b}`. Dual
    /// of
    /// [`test_per_attempt_region_join_returns_one_of_the_arguments`].
    #[test]
    fn test_per_attempt_region_meet_returns_one_of_the_arguments() {
        for a in PerAttemptRegion::ALL {
            for b in PerAttemptRegion::ALL {
                let m = a.meet(b);
                assert!(
                    m == a || m == b,
                    "PerAttemptRegion::{a:?}.meet({b:?}) = {m:?} must be one of {{{a:?}, {b:?}}}"
                );
            }
        }
    }

    /// Cross-surface order pin: `a.meet(b) <= a.join(b)` at every (a,
    /// b) over the 5×5 grid. The structural witness that the meet-
    /// join interval brackets the per-attempt-axis range of the
    /// input pair — the direct mirror of
    /// [`crate::version::BumpLevel`] `test_bump_level_meet_le_join_at_every_pair`
    /// at the version-bump magnitude ladder, here at the per-attempt-
    /// axis ladder. Equality holds when the inputs coincide
    /// (`a.meet(a) == a == a.join(a)`); strict inequality holds at
    /// every asymmetric pair (the meet and join return the two
    /// distinct arguments respectively).
    #[test]
    fn test_per_attempt_region_meet_le_join_at_every_pair() {
        for a in PerAttemptRegion::ALL {
            for b in PerAttemptRegion::ALL {
                let m = a.meet(b);
                let j = a.join(b);
                assert!(
                    m <= j,
                    "PerAttemptRegion::{a:?}.meet({b:?}) = {m:?} must be <= \
                     {a:?}.join({b:?}) = {j:?}"
                );
            }
        }
    }

    /// Absorption laws: `a.join(a.meet(b)) == a` and
    /// `a.meet(a.join(b)) == a` at every (a, b) over the 5×5 grid.
    /// The structural anchor that the meet/join pair forms a LATTICE
    /// in the algebraic sense — two reductions over the same [`Ord`]
    /// ladder, related by the absorption laws so that "join with
    /// one's own meet collapses" and "meet with one's own join
    /// collapses." A future ladder refinement that broke the
    /// absorption laws (e.g., a meet-irreducible variant inserted
    /// where `a.meet(b)` returned a strict lower bound of both
    /// arguments) would light up here, surfacing the structural
    /// distinction at the lattice-pair site rather than at every
    /// consumer. The load-bearing fact a downstream lattice-walk
    /// relies on to round-trip through the meet/join pair without
    /// unbounded drift. Direct mirror of
    /// `test_bump_level_meet_join_absorption_at_every_pair` at the
    /// version-bump magnitude ladder.
    #[test]
    fn test_per_attempt_region_meet_join_absorption_at_every_pair() {
        for a in PerAttemptRegion::ALL {
            for b in PerAttemptRegion::ALL {
                assert_eq!(
                    a.join(a.meet(b)),
                    a,
                    "join-meet absorption must hold: \
                     PerAttemptRegion::{a:?}.join({a:?}.meet({b:?})) must equal {a:?}"
                );
                assert_eq!(
                    a.meet(a.join(b)),
                    a,
                    "meet-join absorption must hold: \
                     PerAttemptRegion::{a:?}.meet({a:?}.join({b:?})) must equal {a:?}"
                );
            }
        }
    }

    /// Meet distributes over join:
    /// `a.meet(b.join(c)) == a.meet(b).join(a.meet(c))` at every
    /// `(a, b, c)` over the 5×5×5 grid (125 triples). The structural
    /// anchor that the meet/join pair forms a DISTRIBUTIVE lattice in
    /// the algebraic sense — every chain (totally-ordered lattice) is
    /// distributive, and the [`PerAttemptRegion`] ladder (`BeforeFirst
    /// < First < Interim < Final < OverBudget`) inherits the
    /// distributive property from its derived [`Ord`] chain. The next
    /// algebraic-law pin beyond absorption
    /// ([`test_per_attempt_region_meet_join_absorption_at_every_pair`]):
    /// absorption + distributivity together carry the full
    /// "distributive lattice" axioms a downstream lattice-walk relies
    /// on when reducing a meet/join expression to a normal form
    /// without retyping the distributive identity at every reduction
    /// site. A future ladder refinement that broke distributivity
    /// (e.g., inserting two incomparable variants in the same band —
    /// turning the chain into a non-distributive lattice like the
    /// diamond `M3` or the pentagon `N5`) would light up here,
    /// surfacing the structural distinction at the lattice-pair site
    /// rather than at every downstream consumer that silently relied
    /// on the distributive identity. Direct mirror of
    /// `test_bump_level_meet_distributes_over_join_at_every_triple` at
    /// the version-bump magnitude ladder and
    /// `test_admission_tier_meet_distributes_over_join_at_every_triple`
    /// at the admission-tier ladder, here at the per-attempt-axis
    /// ladder. THEORY.md §V.5: distributivity is the load-bearing
    /// axiom that distinguishes a chain-derived lattice from a general
    /// bounded lattice, and the structural witness the meet/join pair
    /// carries beyond mere absorption.
    #[test]
    fn test_per_attempt_region_meet_distributes_over_join_at_every_triple() {
        for a in PerAttemptRegion::ALL {
            for b in PerAttemptRegion::ALL {
                for c in PerAttemptRegion::ALL {
                    let lhs = a.meet(b.join(c));
                    let rhs = a.meet(b).join(a.meet(c));
                    assert_eq!(
                        lhs, rhs,
                        "meet distributes over join must hold: \
                         PerAttemptRegion::{a:?}.meet({b:?}.join({c:?})) = {lhs:?} \
                         must equal {a:?}.meet({b:?}).join({a:?}.meet({c:?})) = {rhs:?}"
                    );
                }
            }
        }
    }

    /// Join distributes over meet:
    /// `a.join(b.meet(c)) == a.join(b).meet(a.join(c))` at every
    /// `(a, b, c)` over the 5×5×5 grid (125 triples). The lattice-dual
    /// of
    /// [`test_per_attempt_region_meet_distributes_over_join_at_every_triple`]
    /// at the same per-attempt-axis ladder — in a distributive lattice
    /// the two distributive identities are equivalent, and pinning
    /// both closes the structural witness against a refactor that
    /// broke one but not the other (the structurally-asymmetric
    /// refactor a single-identity pin would miss). Together with the
    /// absorption-law pin
    /// ([`test_per_attempt_region_meet_join_absorption_at_every_pair`])
    /// and the lattice-bracket pin
    /// ([`test_per_attempt_region_meet_le_join_at_every_pair`]), this
    /// closes the distributive-lattice axiom surface on the
    /// [`PerAttemptRegion`] ladder at the typed-primitive site —
    /// mirroring what [`BumpLevel`](crate::version::BumpLevel) closed
    /// at the version-bump magnitude ladder (commit 46d2754) and
    /// [`AdmissionTier`](crate::probe_outcome::AdmissionTier) closed
    /// at the admission-tier ladder over the same 3×3×3 grid, here
    /// applied to the 5-variant per-attempt-axis ladder.
    #[test]
    fn test_per_attempt_region_join_distributes_over_meet_at_every_triple() {
        for a in PerAttemptRegion::ALL {
            for b in PerAttemptRegion::ALL {
                for c in PerAttemptRegion::ALL {
                    let lhs = a.join(b.meet(c));
                    let rhs = a.join(b).meet(a.join(c));
                    assert_eq!(
                        lhs, rhs,
                        "join distributes over meet must hold: \
                         PerAttemptRegion::{a:?}.join({b:?}.meet({c:?})) = {lhs:?} \
                         must equal {a:?}.join({b:?}).meet({a:?}.join({c:?})) = {rhs:?}"
                    );
                }
            }
        }
    }

    /// [`RetryPolicy::compute_delay`] returns `Duration::ZERO` exactly
    /// when either
    /// [`RetryPolicy::is_first_attempt`] fires *or* the policy's
    /// `initial_backoff` is zero — the algebraic law tying the backoff-
    /// schedule zero reading to the per-attempt-axis floor reading. The
    /// grounding-through-typed-primitive law a future consumer relies
    /// on when it factors the compute_delay early-return through the
    /// named floor peer or vice versa. Cross-product of the full
    /// `max_attempts × {ZERO, network}` schedule grid × attempt-count
    /// grid.
    #[test]
    fn test_retry_policy_compute_delay_zero_iff_first_attempt_or_zero_backoff() {
        let schedules = [
            (Duration::ZERO, 1, Duration::ZERO),
            (Duration::from_millis(250), 2, Duration::from_secs(30)),
        ];
        for max_attempts in [1u32, 2, 3, 5, 10] {
            for (initial_backoff, factor, max_backoff) in schedules {
                let p = RetryPolicy {
                    max_attempts,
                    initial_backoff,
                    factor,
                    max_backoff,
                };
                for attempt in [0u32, 1, 2, 3, 4, 5, 6, 10] {
                    let delay_is_zero = p.compute_delay(attempt).is_zero();
                    let expected_zero = p.is_first_attempt(attempt) || p.initial_backoff.is_zero();
                    assert_eq!(
                        delay_is_zero,
                        expected_zero,
                        "compute_delay(attempt).is_zero() must equal \
                         (is_first_attempt(attempt) || initial_backoff.is_zero()): \
                         max_attempts = {max_attempts}, attempt = {attempt}, \
                         schedule = {:?}",
                        (initial_backoff, factor, max_backoff)
                    );
                }
            }
        }
    }

    /// [`RetryPolicy::is_first_attempt(1)`] AND
    /// [`RetryPolicy::is_final_attempt(1)`] both fire iff the policy is
    /// no-retry — pinned by
    /// `(is_first_attempt(1) && is_final_attempt(1)) == is_no_retry()`
    /// across every canonical factory and the degenerate hand-built
    /// `max_attempts: 0` shape. The load-bearing structural law that
    /// closes the per-attempt-axis floor and ceiling peers at the
    /// no-retry singleton case: a one-shot policy is the unique shape
    /// where the first attempt is also the final attempt.
    #[test]
    fn test_retry_policy_is_first_attempt_and_is_final_attempt_at_one_iff_no_retry() {
        let cases = [
            RetryPolicy::immediate(),
            RetryPolicy::network(),
            RetryPolicy::network_with_max_attempts(1),
            RetryPolicy::network_with_max_attempts(3),
            RetryPolicy::network_with_max_attempts(7),
            RetryPolicy::network_or_immediate(true),
            RetryPolicy::network_or_immediate(false),
            RetryPolicy {
                max_attempts: 0,
                initial_backoff: Duration::ZERO,
                factor: 1,
                max_backoff: Duration::ZERO,
            },
        ];
        for p in cases {
            assert_eq!(
                p.is_first_attempt(1) && p.is_final_attempt(1),
                p.is_no_retry(),
                "(is_first_attempt(1) && is_final_attempt(1)) must equal is_no_retry(): \
                 policy = {p:?}"
            );
        }
    }

    /// [`RetryPolicy::attempts_completed_before`] reads the raw
    /// `attempt.saturating_sub(1)` predicate — `0` at `attempt ∈ {0, 1}`
    /// (the pre-invocation counter reading and the first `op(attempt)`
    /// call), `attempt - 1` at every `attempt >= 2`. Pinned across the
    /// full `max_attempts × {ZERO, network}` schedule cross-product ×
    /// attempt-count grid so a future regression that coupled the
    /// prior-attempts count to the clamped budget (e.g., misgrounded
    /// the reading through
    /// [`RetryPolicy::effective_max_attempts`] as the ceiling numeric
    /// peer does) lights up this test.
    #[test]
    fn test_retry_policy_attempts_completed_before_reads_attempt_saturating_sub_one() {
        let schedules = [
            (Duration::ZERO, 1, Duration::ZERO),
            (Duration::from_millis(250), 2, Duration::from_secs(30)),
        ];
        for max_attempts in [0u32, 1, 2, 3, 5, 10, u32::MAX] {
            for (initial_backoff, factor, max_backoff) in schedules {
                let p = RetryPolicy {
                    max_attempts,
                    initial_backoff,
                    factor,
                    max_backoff,
                };
                for attempt in [0u32, 1, 2, 3, 4, 5, 10, 100, u32::MAX] {
                    assert_eq!(
                        p.attempts_completed_before(attempt),
                        attempt.saturating_sub(1),
                        "attempts_completed_before must equal attempt.saturating_sub(1): \
                         max_attempts = {max_attempts}, attempt = {attempt}, \
                         schedule = {:?}",
                        (initial_backoff, factor, max_backoff)
                    );
                }
            }
        }
    }

    /// [`RetryPolicy::attempts_completed_before`] is clamp-independent
    /// — the reading at any given `attempt` is identical across every
    /// canonical factory (`immediate()`, `network()`,
    /// `network_with_max_attempts(n)` for `n ∈ {0, 1, 3, 7}`,
    /// `network_or_immediate(true/false)`) and the degenerate hand-
    /// built `max_attempts: 0` shape. Load-bearing: pins the
    /// structural asymmetry that the per-attempt-axis floor NUMERIC
    /// does not depend on the clamped budget, mirroring the
    /// clamp-independence discipline
    /// [`RetryPolicy::is_first_attempt`] applies at the floor BOOLEAN
    /// side and inverting the clamp-grounded discipline
    /// [`RetryPolicy::attempts_remaining`] applies at the ceiling
    /// NUMERIC side. A future regression that coupled the floor
    /// NUMERIC to the budget lights up on the disagreement between
    /// any two policies.
    #[test]
    fn test_retry_policy_attempts_completed_before_independent_of_policy() {
        let policies = [
            RetryPolicy::immediate(),
            RetryPolicy::network(),
            RetryPolicy::network_with_max_attempts(0),
            RetryPolicy::network_with_max_attempts(1),
            RetryPolicy::network_with_max_attempts(3),
            RetryPolicy::network_with_max_attempts(7),
            RetryPolicy::network_or_immediate(true),
            RetryPolicy::network_or_immediate(false),
            RetryPolicy {
                max_attempts: 0,
                initial_backoff: Duration::ZERO,
                factor: 1,
                max_backoff: Duration::ZERO,
            },
        ];
        for attempt in [0u32, 1, 2, 3, 4, 5, 10, 100, u32::MAX] {
            let readings: Vec<u32> = policies
                .iter()
                .map(|p| p.attempts_completed_before(attempt))
                .collect();
            let first = readings[0];
            for (i, r) in readings.iter().enumerate() {
                assert_eq!(
                    *r, first,
                    "attempts_completed_before must be clamp-independent: attempt = {attempt}, \
                     policies[0] reads {first}, policies[{i}] = {:?} reads {r}",
                    policies[i]
                );
            }
        }
    }

    /// [`RetryPolicy::attempts_completed_before`] returns `0` exactly
    /// when [`RetryPolicy::is_first_attempt`] fires — the algebraic
    /// law tying the numeric prior-count reading at the FLOOR to the
    /// boolean per-attempt "is-this-the-first-one?" partition. The
    /// floor-side peer of the
    /// `attempts_remaining(attempt) == 0 iff is_final_attempt(attempt)`
    /// law pinned at the ceiling. Cross-product of the full
    /// `max_attempts × {ZERO, network}` schedule grid × attempt-count
    /// grid — a future regression that desynced the numeric-floor
    /// reading and the boolean-floor predicate (off-by-one, drift in
    /// clamp discipline) lights up this test.
    #[test]
    fn test_retry_policy_attempts_completed_before_zero_iff_is_first_attempt() {
        let schedules = [
            (Duration::ZERO, 1, Duration::ZERO),
            (Duration::from_millis(250), 2, Duration::from_secs(30)),
        ];
        for max_attempts in [0u32, 1, 2, 3, 5, 10] {
            for (initial_backoff, factor, max_backoff) in schedules {
                let p = RetryPolicy {
                    max_attempts,
                    initial_backoff,
                    factor,
                    max_backoff,
                };
                for attempt in [0u32, 1, 2, 3, 4, 5, 6, 10, 100, u32::MAX] {
                    assert_eq!(
                        p.attempts_completed_before(attempt) == 0,
                        p.is_first_attempt(attempt),
                        "attempts_completed_before(attempt) == 0 must equal \
                         is_first_attempt(attempt): max_attempts = {max_attempts}, \
                         attempt = {attempt}, schedule = {:?}",
                        (initial_backoff, factor, max_backoff)
                    );
                }
            }
        }
    }

    /// Conservation-of-attempts identity for every
    /// `attempt ∈ [1, effective_max_attempts()]`:
    ///
    /// `attempts_completed_before(attempt) + 1 + attempts_remaining(attempt)
    ///  == effective_max_attempts()`
    ///
    /// — the prior + current + remaining decomposition of the clamped
    /// budget. Pinned across the full `max_attempts × {ZERO, network}`
    /// schedule cross-product, iterating `attempt` over the in-budget
    /// range `[1, effective_max_attempts()]` on each policy. A future
    /// regression that desynced any of the three primitives (off-by-
    /// one in the numeric floor, off-by-one in the numeric ceiling,
    /// drift in the clamp discipline) lights up this test.
    #[test]
    fn test_retry_policy_attempts_completed_before_conservation_in_budget() {
        let schedules = [
            (Duration::ZERO, 1, Duration::ZERO),
            (Duration::from_millis(250), 2, Duration::from_secs(30)),
        ];
        for max_attempts in [0u32, 1, 2, 3, 5, 10] {
            for (initial_backoff, factor, max_backoff) in schedules {
                let p = RetryPolicy {
                    max_attempts,
                    initial_backoff,
                    factor,
                    max_backoff,
                };
                let budget = p.effective_max_attempts();
                for attempt in 1..=budget {
                    assert_eq!(
                        p.attempts_completed_before(attempt) + 1 + p.attempts_remaining(attempt),
                        budget,
                        "attempts_completed_before + 1 + attempts_remaining must equal \
                         effective_max_attempts: max_attempts = {max_attempts}, \
                         attempt = {attempt}, schedule = {:?}",
                        (initial_backoff, factor, max_backoff)
                    );
                }
            }
        }
    }

    /// Per-attempt numeric prior-count discrimination across every
    /// canonical factory: `immediate()` reads 0 → 1 across attempts
    /// 1..=2; `network()` (max=5) counts up 0 → 1 → 2 → 3 → 4 across
    /// attempts 1..=5; `network_with_max_attempts(3)` counts up 0 → 1
    /// → 2; `network_or_immediate(true)` matches `network()` and
    /// `network_or_immediate(false)` matches `immediate()`. Pins the
    /// numeric prior-count accounting the canonical factories expose,
    /// mirroring the
    /// [`test_retry_policy_attempts_remaining_discriminates_canonical_factories`]
    /// pin at the ceiling numeric peer.
    #[test]
    fn test_retry_policy_attempts_completed_before_discriminates_canonical_factories() {
        assert_eq!(RetryPolicy::immediate().attempts_completed_before(1), 0);
        assert_eq!(RetryPolicy::immediate().attempts_completed_before(2), 1);

        assert_eq!(RetryPolicy::network().attempts_completed_before(1), 0);
        assert_eq!(RetryPolicy::network().attempts_completed_before(2), 1);
        assert_eq!(RetryPolicy::network().attempts_completed_before(3), 2);
        assert_eq!(RetryPolicy::network().attempts_completed_before(4), 3);
        assert_eq!(RetryPolicy::network().attempts_completed_before(5), 4);

        assert_eq!(
            RetryPolicy::network_with_max_attempts(3).attempts_completed_before(1),
            0
        );
        assert_eq!(
            RetryPolicy::network_with_max_attempts(3).attempts_completed_before(2),
            1
        );
        assert_eq!(
            RetryPolicy::network_with_max_attempts(3).attempts_completed_before(3),
            2
        );

        assert_eq!(
            RetryPolicy::network_or_immediate(true).attempts_completed_before(1),
            0
        );
        assert_eq!(
            RetryPolicy::network_or_immediate(false).attempts_completed_before(2),
            1
        );
    }

    /// [`RetryPolicy::attempts_used_through`] reads the raw
    /// `attempt.min(self.effective_max_attempts())` predicate — `0` at
    /// `attempt == 0` (the pre-invocation counter reading), the raw
    /// `attempt` at every `attempt ∈ [1, effective_max_attempts()]`,
    /// and saturated at `effective_max_attempts()` for any `attempt >
    /// effective_max_attempts()`. Pinned across the full `max_attempts
    /// × {ZERO, network}` schedule cross-product × attempt-count grid
    /// so a future regression that decoupled the FLOOR NUMERIC
    /// INCLUSIVE reading from the min-with-budget shape (e.g., dropped
    /// the clamp, coupled the reading to the raw `max_attempts` field
    /// rather than the clamped `effective_max_attempts()`) lights up
    /// this test.
    #[test]
    fn test_retry_policy_attempts_used_through_reads_min_of_attempt_and_effective_max() {
        let schedules = [
            (Duration::ZERO, 1, Duration::ZERO),
            (Duration::from_millis(250), 2, Duration::from_secs(30)),
        ];
        for max_attempts in [0u32, 1, 2, 3, 5, 10, u32::MAX] {
            for (initial_backoff, factor, max_backoff) in schedules {
                let p = RetryPolicy {
                    max_attempts,
                    initial_backoff,
                    factor,
                    max_backoff,
                };
                let cap = p.effective_max_attempts();
                for attempt in [0u32, 1, 2, 3, 4, 5, 10, 100, u32::MAX] {
                    let expected = if attempt < cap { attempt } else { cap };
                    assert_eq!(
                        p.attempts_used_through(attempt),
                        expected,
                        "attempts_used_through must equal attempt.min(effective_max_attempts()): \
                         max_attempts = {max_attempts}, attempt = {attempt}, cap = {cap}, \
                         schedule = {:?}",
                        (initial_backoff, factor, max_backoff)
                    );
                }
            }
        }
    }

    /// Universal 2-term conservation-of-attempts identity for every
    /// `attempt: u32` — including `attempt == 0` (pre-invocation),
    /// `attempt ∈ [1, effective_max_attempts()]` (in-budget), and
    /// `attempt > effective_max_attempts()` (out-of-budget, the
    /// [`run_with_policy`] loop cannot produce this but a hand-built
    /// consumer can):
    ///
    /// `attempts_used_through(attempt) + attempts_remaining(attempt)
    ///  == effective_max_attempts()`
    ///
    /// — the budget-slots-used + budget-slots-left decomposition of
    /// the clamped budget. Stronger than the 3-term
    /// `attempts_completed_before + 1 + attempts_remaining ==
    /// effective_max_attempts` identity pinned by
    /// [`test_retry_policy_attempts_completed_before_conservation_in_budget`],
    /// which requires `attempt ∈ [1, effective_max_attempts()]`: the
    /// 2-term identity holds universally because both terms saturate
    /// at the budget boundary. A future regression that desynced any
    /// of the three primitives (an off-by-one in the FLOOR INCLUSIVE,
    /// an off-by-one in the CEILING EXCLUSIVE, a drift in the clamp
    /// discipline) lights up this test.
    #[test]
    fn test_retry_policy_attempts_used_through_conservation_universal() {
        let schedules = [
            (Duration::ZERO, 1, Duration::ZERO),
            (Duration::from_millis(250), 2, Duration::from_secs(30)),
        ];
        for max_attempts in [0u32, 1, 2, 3, 5, 10] {
            for (initial_backoff, factor, max_backoff) in schedules {
                let p = RetryPolicy {
                    max_attempts,
                    initial_backoff,
                    factor,
                    max_backoff,
                };
                let budget = p.effective_max_attempts();
                for attempt in [0u32, 1, 2, 3, 4, 5, 6, 10, 100, u32::MAX] {
                    assert_eq!(
                        p.attempts_used_through(attempt) + p.attempts_remaining(attempt),
                        budget,
                        "attempts_used_through + attempts_remaining must equal \
                         effective_max_attempts: max_attempts = {max_attempts}, \
                         attempt = {attempt}, schedule = {:?}",
                        (initial_backoff, factor, max_backoff)
                    );
                }
            }
        }
    }

    /// The floor pair is related by `+1` under the clamp — for every
    /// `attempt ∈ [1, effective_max_attempts()]`:
    ///
    /// `attempts_used_through(attempt)
    ///   == attempts_completed_before(attempt) + 1`
    ///
    /// — the load-bearing bridge between the FLOOR NUMERIC EXCLUSIVE
    /// and FLOOR NUMERIC INCLUSIVE readings inside the budget. Outside
    /// the budget the two diverge by the clamp discipline (the
    /// exclusive floor is clamp-INDEPENDENT and grows unboundedly; the
    /// inclusive floor is clamp-DEPENDENT and saturates at
    /// `effective_max_attempts()`) — pinned above by
    /// [`test_retry_policy_attempts_used_through_reads_min_of_attempt_and_effective_max`]
    /// and
    /// [`test_retry_policy_attempts_completed_before_reads_attempt_saturating_sub_one`].
    /// A future regression that desynced the two floor readings inside
    /// the budget (e.g., dropped the `+ 1` inclusion, silently
    /// promoted the exclusive floor to include the current attempt)
    /// lights up this test.
    #[test]
    fn test_retry_policy_attempts_used_through_is_completed_before_plus_one_in_budget() {
        let schedules = [
            (Duration::ZERO, 1, Duration::ZERO),
            (Duration::from_millis(250), 2, Duration::from_secs(30)),
        ];
        for max_attempts in [0u32, 1, 2, 3, 5, 10] {
            for (initial_backoff, factor, max_backoff) in schedules {
                let p = RetryPolicy {
                    max_attempts,
                    initial_backoff,
                    factor,
                    max_backoff,
                };
                let budget = p.effective_max_attempts();
                for attempt in 1..=budget {
                    assert_eq!(
                        p.attempts_used_through(attempt),
                        p.attempts_completed_before(attempt) + 1,
                        "attempts_used_through(attempt) must equal \
                         attempts_completed_before(attempt) + 1 in-budget: \
                         max_attempts = {max_attempts}, attempt = {attempt}, \
                         schedule = {:?}",
                        (initial_backoff, factor, max_backoff)
                    );
                }
            }
        }
    }

    /// [`RetryPolicy::attempts_used_through`] saturates at
    /// [`RetryPolicy::effective_max_attempts`] for any
    /// `attempt > effective_max_attempts()`. Pins the clamp discipline
    /// at the boundary: the [`run_with_policy`] loop cannot produce an
    /// out-of-budget `attempt` (it short-circuits on
    /// [`RetryPolicy::is_final_attempt`]), but a hand-built consumer
    /// (a telemetry gauge fed a raw counter, a diagnostic that reads
    /// an already-exhausted policy's projected consumption at some
    /// hypothetical future attempt) can, and the reading must remain
    /// bounded at `effective_max_attempts()` rather than growing
    /// unboundedly. Mirrors the ceiling-side
    /// [`test_retry_policy_attempts_remaining_saturates_out_of_budget`]
    /// pin (which pins the CEILING EXCLUSIVE saturating at `0`).
    #[test]
    fn test_retry_policy_attempts_used_through_saturates_out_of_budget() {
        for max_attempts in [1u32, 2, 3, 5, 10] {
            let p = RetryPolicy::network_with_max_attempts(max_attempts);
            let cap = p.effective_max_attempts();
            for over in [1u32, 2, 5, 100, u32::MAX - cap] {
                let attempt = cap.saturating_add(over);
                assert_eq!(
                    p.attempts_used_through(attempt),
                    cap,
                    "attempts_used_through must saturate at effective_max_attempts \
                     for attempt > effective_max_attempts: max_attempts = {max_attempts}, \
                     attempt = {attempt}, cap = {cap}"
                );
            }
        }
    }

    /// Per-attempt INCLUSIVE budget-consumption discrimination across
    /// every canonical factory: `immediate()` (cap=1) reads 0 → 1 → 1
    /// across attempts 0 → 1 → 2 (saturating at the cap for
    /// out-of-budget); `network()` (cap=5) counts up 1 → 2 → 3 → 4 →
    /// 5 across attempts 1..=5 and saturates at 5 past the cap;
    /// `network_with_max_attempts(3)` counts up 1 → 2 → 3;
    /// `network_or_immediate(true)` matches `network()` and
    /// `network_or_immediate(false)` matches `immediate()`. Pins the
    /// per-factory numeric budget-consumption accounting, mirroring the
    /// [`test_retry_policy_attempts_completed_before_discriminates_canonical_factories`]
    /// pin at the FLOOR EXCLUSIVE and the
    /// [`test_retry_policy_attempts_remaining_discriminates_canonical_factories`]
    /// pin at the CEILING EXCLUSIVE.
    #[test]
    fn test_retry_policy_attempts_used_through_discriminates_canonical_factories() {
        assert_eq!(RetryPolicy::immediate().attempts_used_through(0), 0);
        assert_eq!(RetryPolicy::immediate().attempts_used_through(1), 1);
        assert_eq!(RetryPolicy::immediate().attempts_used_through(2), 1);

        assert_eq!(RetryPolicy::network().attempts_used_through(1), 1);
        assert_eq!(RetryPolicy::network().attempts_used_through(2), 2);
        assert_eq!(RetryPolicy::network().attempts_used_through(3), 3);
        assert_eq!(RetryPolicy::network().attempts_used_through(4), 4);
        assert_eq!(RetryPolicy::network().attempts_used_through(5), 5);
        assert_eq!(RetryPolicy::network().attempts_used_through(6), 5);

        assert_eq!(
            RetryPolicy::network_with_max_attempts(3).attempts_used_through(1),
            1
        );
        assert_eq!(
            RetryPolicy::network_with_max_attempts(3).attempts_used_through(2),
            2
        );
        assert_eq!(
            RetryPolicy::network_with_max_attempts(3).attempts_used_through(3),
            3
        );
        assert_eq!(
            RetryPolicy::network_with_max_attempts(3).attempts_used_through(4),
            3
        );

        assert_eq!(
            RetryPolicy::network_or_immediate(true).attempts_used_through(3),
            3
        );
        assert_eq!(
            RetryPolicy::network_or_immediate(false).attempts_used_through(3),
            1
        );
    }

    /// [`RetryPolicy::attempts_remaining_including`] reads
    /// `effective_max_attempts().saturating_sub(attempts_completed_before(attempt))`
    /// verbatim across every `attempt: u32` and every canonical schedule
    /// / `max_attempts` shape — the raw-formula grid pin that lights up
    /// any drift between the primitive's body and its documented
    /// definition (an off-by-one in the ceiling INCLUSIVE side, a
    /// promotion of the exclusive floor reading it grounds through, a
    /// stale delegation to a different saturating operator).
    #[test]
    fn test_retry_policy_attempts_remaining_including_reads_budget_minus_completed_before() {
        let schedules = [
            (Duration::ZERO, 1, Duration::ZERO),
            (Duration::from_millis(250), 2, Duration::from_secs(30)),
        ];
        for max_attempts in [0u32, 1, 2, 3, 5, 10, u32::MAX] {
            for (initial_backoff, factor, max_backoff) in schedules {
                let p = RetryPolicy {
                    max_attempts,
                    initial_backoff,
                    factor,
                    max_backoff,
                };
                let cap = p.effective_max_attempts();
                for attempt in [0u32, 1, 2, 3, 4, 5, 10, 100, u32::MAX] {
                    let expected = cap.saturating_sub(attempt.saturating_sub(1));
                    assert_eq!(
                        p.attempts_remaining_including(attempt),
                        expected,
                        "attempts_remaining_including must equal \
                         effective_max_attempts.saturating_sub(attempt.saturating_sub(1)): \
                         max_attempts = {max_attempts}, attempt = {attempt}, cap = {cap}, \
                         schedule = {:?}",
                        (initial_backoff, factor, max_backoff)
                    );
                }
            }
        }
    }

    /// Dual conservation-of-attempts identity for every
    /// `attempt ∈ [0, effective_max_attempts() + 1]`:
    ///
    /// `attempts_completed_before(attempt) + attempts_remaining_including(attempt)
    ///  == effective_max_attempts()`
    ///
    /// — the completed-before + remaining-including-current
    /// decomposition of the clamped budget, the dual of the universal
    /// 2-term
    /// `attempts_used_through(attempt) + attempts_remaining(attempt) ==
    /// effective_max_attempts()` identity pinned at
    /// [`test_retry_policy_attempts_used_through_conservation_universal`].
    /// Unlike the FLOOR-INCLUSIVE + CEILING-EXCLUSIVE partition (which
    /// holds universally because both terms saturate at the budget
    /// boundary), the dual FLOOR-EXCLUSIVE + CEILING-INCLUSIVE partition
    /// holds only up to `effective_max_attempts() + 1`: beyond that, the
    /// clamp-INDEPENDENT floor exclusive `attempts_completed_before`
    /// grows unboundedly while the clamp-DEPENDENT ceiling inclusive
    /// saturates at `0`, so the sum overshoots the budget. Pinning the
    /// boundary explicitly locks the dual partition's exact domain-of-
    /// validity against any future drift.
    #[test]
    fn test_retry_policy_attempts_remaining_including_dual_conservation() {
        let schedules = [
            (Duration::ZERO, 1, Duration::ZERO),
            (Duration::from_millis(250), 2, Duration::from_secs(30)),
        ];
        for max_attempts in [0u32, 1, 2, 3, 5, 10] {
            for (initial_backoff, factor, max_backoff) in schedules {
                let p = RetryPolicy {
                    max_attempts,
                    initial_backoff,
                    factor,
                    max_backoff,
                };
                let budget = p.effective_max_attempts();
                for attempt in 0..=(budget + 1) {
                    assert_eq!(
                        p.attempts_completed_before(attempt)
                            + p.attempts_remaining_including(attempt),
                        budget,
                        "attempts_completed_before + attempts_remaining_including must equal \
                         effective_max_attempts on [0, effective_max_attempts() + 1]: \
                         max_attempts = {max_attempts}, attempt = {attempt}, \
                         schedule = {:?}",
                        (initial_backoff, factor, max_backoff)
                    );
                }
            }
        }
    }

    /// The ceiling pair is related by `+1` under the clamp — for every
    /// `attempt ∈ [1, effective_max_attempts()]`:
    ///
    /// `attempts_remaining_including(attempt)
    ///   == attempts_remaining(attempt) + 1`
    ///
    /// — the load-bearing bridge between the CEILING NUMERIC EXCLUSIVE
    /// and CEILING NUMERIC INCLUSIVE readings inside the budget,
    /// mirroring the FLOOR-side `+1` bridge
    /// `attempts_used_through(attempt) == attempts_completed_before(attempt) + 1`
    /// pinned by
    /// [`test_retry_policy_attempts_used_through_is_completed_before_plus_one_in_budget`].
    /// Outside the budget the two ceiling readings diverge by the clamp
    /// discipline: both saturate at `0`, but from different attempt-
    /// index thresholds. A future regression that desynced the two
    /// ceiling readings inside the budget (e.g., dropped the `+ 1`
    /// inclusion, silently demoted the inclusive ceiling to exclude the
    /// current attempt) lights up this test.
    #[test]
    fn test_retry_policy_attempts_remaining_including_is_remaining_plus_one_in_budget() {
        let schedules = [
            (Duration::ZERO, 1, Duration::ZERO),
            (Duration::from_millis(250), 2, Duration::from_secs(30)),
        ];
        for max_attempts in [0u32, 1, 2, 3, 5, 10] {
            for (initial_backoff, factor, max_backoff) in schedules {
                let p = RetryPolicy {
                    max_attempts,
                    initial_backoff,
                    factor,
                    max_backoff,
                };
                let budget = p.effective_max_attempts();
                for attempt in 1..=budget {
                    assert_eq!(
                        p.attempts_remaining_including(attempt),
                        p.attempts_remaining(attempt) + 1,
                        "attempts_remaining_including(attempt) must equal \
                         attempts_remaining(attempt) + 1 in-budget: \
                         max_attempts = {max_attempts}, attempt = {attempt}, \
                         schedule = {:?}",
                        (initial_backoff, factor, max_backoff)
                    );
                }
            }
        }
    }

    /// [`RetryPolicy::attempts_remaining_including`] saturates at `0`
    /// for any `attempt > effective_max_attempts()`. Pins the clamp
    /// discipline at the boundary: the [`run_with_policy`] loop cannot
    /// produce an out-of-budget `attempt` (it short-circuits on
    /// [`RetryPolicy::is_final_attempt`]), but a hand-built consumer (a
    /// telemetry gauge fed a raw counter, a diagnostic that reads an
    /// already-exhausted policy's projected slots-left at some
    /// hypothetical future attempt) can, and the reading must remain
    /// bounded at `0` rather than underflowing. Mirrors the ceiling-
    /// exclusive [`test_retry_policy_attempts_remaining_saturates_out_of_budget`]
    /// pin (which pins the CEILING EXCLUSIVE saturating at `0` at the
    /// same threshold — but a distinct saturating operator: the
    /// exclusive ceiling reads `cap.saturating_sub(attempt)` while the
    /// inclusive ceiling reads
    /// `cap.saturating_sub(attempt.saturating_sub(1))`, so drift in
    /// either would break exactly one of the two pins).
    #[test]
    fn test_retry_policy_attempts_remaining_including_saturates_out_of_budget() {
        for max_attempts in [1u32, 2, 3, 5, 10] {
            let p = RetryPolicy::network_with_max_attempts(max_attempts);
            let cap = p.effective_max_attempts();
            for over in [2u32, 3, 5, 100, u32::MAX - cap] {
                let attempt = cap.saturating_add(over);
                assert_eq!(
                    p.attempts_remaining_including(attempt),
                    0,
                    "attempts_remaining_including must saturate at 0 for \
                     attempt > effective_max_attempts() + 1: max_attempts = {max_attempts}, \
                     attempt = {attempt}, cap = {cap}"
                );
            }
        }
    }

    /// Per-attempt CEILING INCLUSIVE budget-remaining discrimination
    /// across every canonical factory: `immediate()` (cap=1) reads 1 →
    /// 1 → 0 across attempts 0 → 1 → 2 (the current attempt slot at
    /// attempt=1 saturating at 0 past the cap); `network()` (cap=5)
    /// counts down 5 → 5 → 4 → 3 → 2 → 1 across attempts 0..=5 and
    /// saturates at 0 past the cap; `network_with_max_attempts(3)`
    /// counts down 3 → 3 → 2 → 1; `network_or_immediate(true)` matches
    /// `network()` and `network_or_immediate(false)` matches
    /// `immediate()`. Pins the per-factory numeric slots-left-including-
    /// current accounting, mirroring the
    /// [`test_retry_policy_attempts_used_through_discriminates_canonical_factories`]
    /// pin at the FLOOR INCLUSIVE and the
    /// [`test_retry_policy_attempts_remaining_discriminates_canonical_factories`]
    /// pin at the CEILING EXCLUSIVE.
    #[test]
    fn test_retry_policy_attempts_remaining_including_discriminates_canonical_factories() {
        assert_eq!(RetryPolicy::immediate().attempts_remaining_including(0), 1);
        assert_eq!(RetryPolicy::immediate().attempts_remaining_including(1), 1);
        assert_eq!(RetryPolicy::immediate().attempts_remaining_including(2), 0);

        assert_eq!(RetryPolicy::network().attempts_remaining_including(0), 5);
        assert_eq!(RetryPolicy::network().attempts_remaining_including(1), 5);
        assert_eq!(RetryPolicy::network().attempts_remaining_including(2), 4);
        assert_eq!(RetryPolicy::network().attempts_remaining_including(3), 3);
        assert_eq!(RetryPolicy::network().attempts_remaining_including(4), 2);
        assert_eq!(RetryPolicy::network().attempts_remaining_including(5), 1);
        assert_eq!(RetryPolicy::network().attempts_remaining_including(6), 0);

        assert_eq!(
            RetryPolicy::network_with_max_attempts(3).attempts_remaining_including(1),
            3
        );
        assert_eq!(
            RetryPolicy::network_with_max_attempts(3).attempts_remaining_including(2),
            2
        );
        assert_eq!(
            RetryPolicy::network_with_max_attempts(3).attempts_remaining_including(3),
            1
        );
        assert_eq!(
            RetryPolicy::network_with_max_attempts(3).attempts_remaining_including(4),
            0
        );

        assert_eq!(
            RetryPolicy::network_or_immediate(true).attempts_remaining_including(3),
            3
        );
        assert_eq!(
            RetryPolicy::network_or_immediate(false).attempts_remaining_including(3),
            0
        );
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

    /// Field-wise extensional reflexivity at the typed-record surface:
    /// `f == f.clone()` for a representative cross product of the
    /// structural shapes `CommandAttemptFailure` admits (transient op,
    /// terminal op, spawn failure). Pins the minimum-load-bearing
    /// `PartialEq` law against any future regression that hand-rolled
    /// a custom impl breaking reflexivity.
    #[test]
    fn test_command_attempt_failure_partial_eq_reflexive() {
        let cases = [
            CommandAttemptFailure {
                operation: "push to Attic".to_string(),
                attempt: 2,
                exit_code: Some(1),
                stderr: "503 Service Unavailable".to_string(),
                stdout: String::new(),
            },
            CommandAttemptFailure {
                operation: "login to Attic".to_string(),
                attempt: 1,
                exit_code: Some(1),
                stderr: "401 Unauthorized".to_string(),
                stdout: String::new(),
            },
            CommandAttemptFailure {
                operation: "spawn skopeo".to_string(),
                attempt: 1,
                exit_code: None,
                stderr: String::new(),
                stdout: "failed to spawn process: no such file".to_string(),
            },
        ];
        for f in &cases {
            assert_eq!(*f, f.clone());
        }
    }

    /// `PartialEq` separates records that disagree on any single field.
    /// One reference record + five perturbed neighbors (one per field):
    /// each neighbor must NOT equal the reference. The pin against a
    /// future regression that silently dropped a field from the derive
    /// (e.g. by hand-rolling a `PartialEq` impl that only compared
    /// `(operation, exit_code, stderr)`), which would let two records
    /// disagreeing on `attempt` or `stdout` read as structurally equal
    /// at a downstream telemetry / replay / attestation consumer.
    #[test]
    fn test_command_attempt_failure_partial_eq_separates_per_field() {
        let base = CommandAttemptFailure {
            operation: "push image".to_string(),
            attempt: 2,
            exit_code: Some(1),
            stderr: "503 Service Unavailable".to_string(),
            stdout: "noise".to_string(),
        };
        let neighbors = [
            CommandAttemptFailure {
                operation: "different op".to_string(),
                ..base.clone()
            },
            CommandAttemptFailure {
                attempt: 3,
                ..base.clone()
            },
            CommandAttemptFailure {
                exit_code: Some(2),
                ..base.clone()
            },
            CommandAttemptFailure {
                stderr: "504 Gateway Timeout".to_string(),
                ..base.clone()
            },
            CommandAttemptFailure {
                stdout: "different noise".to_string(),
                ..base.clone()
            },
        ];
        for n in &neighbors {
            assert_ne!(base, *n);
        }
    }

    /// `from_capture` constructs the same structural record from
    /// equivalent inputs — `assert_eq!` against a hand-built reference
    /// reads the construction discipline as one expression at the
    /// typed-primitive surface rather than five field-wise asserts.
    /// Pins the structural-equality reading at the construction site,
    /// not just at hand-written record literals.
    #[test]
    fn test_command_attempt_failure_from_capture_structural_equality() {
        let out = synth_output(false, b"stdout bytes", b"503 Service Unavailable");
        let from = CommandAttemptFailure::from_capture(Ok(out), "push image", 2)
            .expect_err("non-zero exit must produce a record");
        let reference = CommandAttemptFailure {
            operation: "push image".to_string(),
            attempt: 2,
            exit_code: from.exit_code,
            stderr: "503 Service Unavailable".to_string(),
            stdout: "stdout bytes".to_string(),
        };
        assert_eq!(from, reference);
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

    /// `is_op_failure()` discriminates the op-failure structural shape
    /// (`Ok(non-success)` arm of `from_capture`): a non-zero exit with a
    /// populated stderr returns `true`; a spawn-failure record
    /// (`Err(io::Error)` arm: `exit_code: None` + empty stderr) returns
    /// `false`. The named complement of [`is_spawn_failure`]: the same
    /// records the spawn-failure predicate discriminates as `true` are
    /// the records this predicate discriminates as `false`, and vice
    /// versa. Pins the structural-shape reading at every variant
    /// `from_capture` constructs.
    #[test]
    fn test_is_op_failure_discriminates_op_from_spawn() {
        // Op-failure: produced by the `Ok(non-success)` arm — non-empty
        // stderr + Some(_) exit code.
        let out = synth_output(false, b"", b"401 Unauthorized");
        let f = CommandAttemptFailure::from_capture(Ok(out), "auth op", 1)
            .expect_err("non-zero exit must produce a record");
        assert!(f.is_op_failure(), "op failure must discriminate true");

        // Op-failure with transient stderr: still op-failure.
        let out = synth_output(false, b"", b"503 Service Unavailable");
        let f = CommandAttemptFailure::from_capture(Ok(out), "transient op", 1)
            .expect_err("non-zero exit must produce a record");
        assert!(f.is_op_failure());
        assert!(f.is_transient(), "transient op must remain transient");

        // Spawn-failure: produced by the `Err(io::Error)` arm —
        // exit_code: None + empty stderr.
        let spawn_err = std::io::Error::new(std::io::ErrorKind::NotFound, "no such file");
        let captured: Result<std::process::Output, std::io::Error> = Err(spawn_err);
        let f = CommandAttemptFailure::from_capture(captured, "exec missing", 1)
            .expect_err("spawn failure must produce a record");
        assert!(
            !f.is_op_failure(),
            "spawn failure (empty stderr + no exit code) must NOT discriminate as op"
        );
    }

    /// De Morgan partition invariant: `is_op_failure()` and
    /// `is_spawn_failure()` are exact structural complements over every
    /// shape `from_capture` constructs and every hand-built record an
    /// upstream consumer might synthesize. `is_op_failure() ==
    /// !is_spawn_failure()` at every variant. The pin against a future
    /// regression that perturbed one predicate's body without lifting
    /// the change to the other (e.g., broadened `is_spawn_failure` to
    /// `exit_code.is_none()` alone without re-tightening
    /// `is_op_failure`'s body), which would silently break the
    /// `classify_attempt_failure` dispatch surface and downstream
    /// consumers that branch on either predicate.
    #[test]
    fn test_is_op_failure_equals_negation_of_is_spawn_failure() {
        // Op-failure shape: non-zero exit + populated stderr.
        let f = CommandAttemptFailure {
            operation: "x".to_string(),
            attempt: 1,
            exit_code: Some(1),
            stderr: "401 Unauthorized".to_string(),
            stdout: String::new(),
        };
        assert_eq!(f.is_op_failure(), !f.is_spawn_failure());

        // Spawn-failure shape: no exit code + empty stderr.
        let f = CommandAttemptFailure {
            operation: "x".to_string(),
            attempt: 1,
            exit_code: None,
            stderr: String::new(),
            stdout: "failed to spawn process: no such file".to_string(),
        };
        assert_eq!(f.is_op_failure(), !f.is_spawn_failure());

        // Edge: signal-killed with stderr — `exit_code: None` but
        // non-empty stderr. By the conjunction discipline this is an
        // op-failure (not a spawn-failure), and the De Morgan
        // equivalence must hold.
        let f = CommandAttemptFailure {
            operation: "x".to_string(),
            attempt: 1,
            exit_code: None,
            stderr: "fatal: process aborted".to_string(),
            stdout: String::new(),
        };
        assert_eq!(f.is_op_failure(), !f.is_spawn_failure());
        assert!(f.is_op_failure());

        // Edge: zero stderr but populated exit code — also op-failure
        // (signal-killed Output where stderr was already flushed
        // upstream, but the captured exit code is preserved).
        let f = CommandAttemptFailure {
            operation: "x".to_string(),
            attempt: 1,
            exit_code: Some(137),
            stderr: String::new(),
            stdout: String::new(),
        };
        assert_eq!(f.is_op_failure(), !f.is_spawn_failure());
        assert!(f.is_op_failure());
    }

    /// Disjoint-and-covering partition: `is_op_failure() XOR
    /// is_spawn_failure() == true` at every record. No record satisfies
    /// both predicates (the two structural shapes are mutually
    /// exclusive by construction); no record satisfies neither (the
    /// conjunction `exit_code.is_none() && stderr.is_empty()` is the
    /// canonical discriminator with no third arm). The peer-pair
    /// structural pin against any future regression that introduced an
    /// intermediate structural shape — e.g., a `Pending` variant or a
    /// signal-aware third arm — without re-partitioning the predicate
    /// pair at this typed-method surface. Same lattice-covering
    /// discipline the `AdmissionTier::admits_X` / `refuses_X` peer
    /// trio established at the tier-ladder surface.
    #[test]
    fn test_is_op_failure_xor_is_spawn_failure_partitions_records() {
        let records = [
            // Op-failure: non-zero exit, populated stderr.
            CommandAttemptFailure {
                operation: "auth".to_string(),
                attempt: 1,
                exit_code: Some(1),
                stderr: "401 Unauthorized".to_string(),
                stdout: String::new(),
            },
            // Op-failure: transient stderr.
            CommandAttemptFailure {
                operation: "push".to_string(),
                attempt: 2,
                exit_code: Some(2),
                stderr: "503 Service Unavailable".to_string(),
                stdout: String::new(),
            },
            // Spawn-failure: empty stderr, no exit code.
            CommandAttemptFailure {
                operation: "exec".to_string(),
                attempt: 1,
                exit_code: None,
                stderr: String::new(),
                stdout: "failed to spawn process: no such file".to_string(),
            },
            // Op-failure: signal-killed with stderr (`exit_code: None`
            // but stderr present).
            CommandAttemptFailure {
                operation: "killed".to_string(),
                attempt: 1,
                exit_code: None,
                stderr: "fatal: aborted".to_string(),
                stdout: String::new(),
            },
            // Op-failure: signal-killed without stderr but with
            // populated exit code.
            CommandAttemptFailure {
                operation: "sigkill".to_string(),
                attempt: 1,
                exit_code: Some(137),
                stderr: String::new(),
                stdout: String::new(),
            },
        ];
        for f in &records {
            assert!(
                f.is_op_failure() ^ f.is_spawn_failure(),
                "exactly one of is_op_failure / is_spawn_failure must hold for record {f:?}"
            );
        }
    }

    /// `is_signal_killed()` discriminates the signal-killed-mid-op
    /// structural shape (`exit_code: None` + non-empty `stderr`) from
    /// both sibling shapes `from_capture` constructs: the spawn-failure
    /// arm (`exit_code: None` + empty `stderr`) and the exited-normally
    /// op-failure arm (`exit_code: Some(_)`). The conjunction body is
    /// load-bearing — the predicate MUST short-circuit to `false` on
    /// spawn-failure even though both shapes share `exit_code: None`,
    /// because at this surface (call-site, constructed from
    /// `Result<Output, io::Error>`) `None` is ambiguous between the
    /// two structural shapes and the canonical discriminator is the
    /// `stderr` field that `from_capture` fixes empty only on the
    /// spawn-failure arm.
    #[test]
    fn test_is_signal_killed_discriminates_three_way_structural_shape() {
        // Spawn-failure: produced by the `Err(io::Error)` arm —
        // exit_code: None + empty stderr. MUST NOT discriminate as
        // signal-killed (the spawn-failure shape is structurally
        // distinct — no child process ever ran).
        let spawn_err = std::io::Error::new(std::io::ErrorKind::NotFound, "no such file");
        let captured: Result<std::process::Output, std::io::Error> = Err(spawn_err);
        let f = CommandAttemptFailure::from_capture(captured, "exec missing", 1)
            .expect_err("spawn failure must produce a record");
        assert!(
            !f.is_signal_killed(),
            "spawn-failure (None + empty stderr) MUST NOT discriminate as signal-killed"
        );
        assert!(
            f.is_spawn_failure(),
            "spawn-failure must still be discriminated by its own peer"
        );

        // Signal-killed-mid-op: `exit_code: None` + non-empty stderr
        // (the SIGTERM-on-deploy-timeout / SIGSEGV-after-flushing-
        // diagnostic shape — child caught the signal and flushed a
        // final diagnostic before exiting). MUST discriminate as
        // signal-killed.
        let f = CommandAttemptFailure {
            operation: "deploy".to_string(),
            attempt: 1,
            exit_code: None,
            stderr: "fatal: aborted".to_string(),
            stdout: String::new(),
        };
        assert!(
            f.is_signal_killed(),
            "None + non-empty stderr must discriminate as signal-killed"
        );
        assert!(
            !f.is_spawn_failure(),
            "signal-killed-mid-op MUST NOT collide with spawn-failure"
        );

        // Exited-normally op-failure: `exit_code: Some(_)` regardless
        // of stderr. MUST NOT discriminate as signal-killed.
        let out = synth_output(false, b"", b"401 Unauthorized");
        let f = CommandAttemptFailure::from_capture(Ok(out), "auth op", 1)
            .expect_err("non-zero exit must produce a record");
        assert!(
            !f.is_signal_killed(),
            "exit_code: Some(_) MUST NOT discriminate as signal-killed"
        );

        // Exited-normally with shell-preserved 137 (canonical
        // SIGKILL-from-shell code 128+9): at the OS surface it's a
        // normal exit. MUST NOT discriminate as signal-killed —
        // the predicate reads through `Option::is_none`, not through
        // a magic-code threshold.
        let f = CommandAttemptFailure {
            operation: "killed".to_string(),
            attempt: 1,
            exit_code: Some(137),
            stderr: String::new(),
            stdout: String::new(),
        };
        assert!(
            !f.is_signal_killed(),
            "exit_code: Some(137) MUST NOT discriminate as signal-killed regardless of code value"
        );
    }

    /// `is_signal_killed()` and `is_spawn_failure()` are mutually
    /// exclusive at every canonical record — never both hold, because
    /// the conjunction shapes share `exit_code.is_none()` but
    /// disagree on `stderr.is_empty()`. The pin against a future
    /// regression that broadened `is_signal_killed` to
    /// `exit_code.is_none()` alone (collapsing the conjunction) which
    /// would silently make every spawn-failure also classify as
    /// signal-killed, breaking the canonical three-way structural-
    /// shape partition forge's typed-error producer surfaces consume.
    #[test]
    fn test_is_signal_killed_mutually_exclusive_with_is_spawn_failure() {
        let records = [
            // Spawn-failure shape: None + empty stderr.
            CommandAttemptFailure {
                operation: "exec".to_string(),
                attempt: 1,
                exit_code: None,
                stderr: String::new(),
                stdout: "failed to spawn process: no such file".to_string(),
            },
            // Signal-killed-mid-op: None + non-empty stderr.
            CommandAttemptFailure {
                operation: "killed".to_string(),
                attempt: 1,
                exit_code: None,
                stderr: "fatal: aborted".to_string(),
                stdout: String::new(),
            },
            // Signal-killed-mid-op with transient stderr (i/o timeout
            // flushed before SIGTERM): still mutually exclusive
            // with spawn-failure.
            CommandAttemptFailure {
                operation: "deploy".to_string(),
                attempt: 1,
                exit_code: None,
                stderr: "i/o timeout".to_string(),
                stdout: String::new(),
            },
            // Exited-normally op-failure: Some + stderr.
            CommandAttemptFailure {
                operation: "auth".to_string(),
                attempt: 1,
                exit_code: Some(1),
                stderr: "401 Unauthorized".to_string(),
                stdout: String::new(),
            },
            // Exited-normally with empty stderr: Some + empty.
            CommandAttemptFailure {
                operation: "sigkill".to_string(),
                attempt: 1,
                exit_code: Some(137),
                stderr: String::new(),
                stdout: String::new(),
            },
        ];
        for f in &records {
            assert!(
                !(f.is_signal_killed() && f.is_spawn_failure()),
                "is_signal_killed and is_spawn_failure must be mutually exclusive at record {f:?}"
            );
        }
    }

    /// `is_signal_killed()` is orthogonal to the retry-dispatch
    /// partition (`is_transient` / `is_terminal`). Both quadrants
    /// reachable under the conjunction body — signal-killed AND
    /// transient (deploy-timeout-on-network-op with i/o timeout in
    /// stderr) and signal-killed AND terminal (SIGSEGV / SIGABRT with
    /// a fatal diagnostic) — are populated by canonical structural
    /// shapes forge's external CLIs emit. The pin against a future
    /// regression that fused the two axes (e.g., redefined
    /// `is_signal_killed` to additionally inspect the classifier's
    /// transient verdict, or redefined `is_transient` to inspect
    /// `exit_code` shape), which would collapse the 2×2 into a 1D
    /// partition and silently break the post-retry classification
    /// surface every downstream consumer depends on. Mirrors
    /// `test_captured_failure_is_signal_killed_orthogonal_to_transient`
    /// (commit 5b49d2c) at the producer surface; the only difference
    /// is that the spawn-failure quadrant is structurally absent at
    /// the call-site surface (spawn-failure does not satisfy
    /// `is_signal_killed` here).
    #[test]
    fn test_is_signal_killed_orthogonal_to_is_transient() {
        // Q1: signal-killed AND transient (deploy timeout while
        // retrying — `i/o timeout` in stderr, then SIGTERM).
        let f = CommandAttemptFailure {
            operation: "deploy".to_string(),
            attempt: 1,
            exit_code: None,
            stderr: "i/o timeout".to_string(),
            stdout: String::new(),
        };
        assert!(f.is_signal_killed());
        assert!(f.is_transient());

        // Q2: signal-killed AND terminal (SIGSEGV / SIGABRT with a
        // fatal diagnostic flushed before the signal).
        let f = CommandAttemptFailure {
            operation: "build".to_string(),
            attempt: 1,
            exit_code: None,
            stderr: "fatal: aborted".to_string(),
            stdout: String::new(),
        };
        assert!(f.is_signal_killed());
        assert!(f.is_terminal());

        // Q3: NOT signal-killed AND transient (the canonical retry-
        // budget-consuming arm — Some(1) exit with 503 in stderr).
        let f = CommandAttemptFailure {
            operation: "push".to_string(),
            attempt: 1,
            exit_code: Some(1),
            stderr: "503 Service Unavailable".to_string(),
            stdout: String::new(),
        };
        assert!(!f.is_signal_killed());
        assert!(f.is_transient());

        // Q4: NOT signal-killed AND terminal (the canonical fail-fast
        // arm — Some(1) exit with 401 in stderr).
        let f = CommandAttemptFailure {
            operation: "auth".to_string(),
            attempt: 1,
            exit_code: Some(1),
            stderr: "401 Unauthorized".to_string(),
            stdout: String::new(),
        };
        assert!(!f.is_signal_killed());
        assert!(f.is_terminal());
    }

    /// Pin the structural definition: `is_signal_killed()` is exactly
    /// `exit_code.is_none() && !stderr.is_empty()` at every record.
    /// A future refactor that shifted the predicate body to a
    /// synthetic discriminator (substring-match on stderr for "signal"
    /// / "killed" / "SIG*", a separate `killed_by_signal: bool` field,
    /// a magic exit-code threshold like `code >= 128`) without
    /// preserving the conjunction equivalence would silently break the
    /// canonical three-way structural-shape partition at this surface.
    /// Mirrors `test_captured_failure_is_signal_killed_equals_exit_code_is_none`
    /// (commit 5b49d2c) at the producer surface; the call-site
    /// equivalence here additionally pins the `!stderr.is_empty()`
    /// conjunction so the spawn-failure / signal-killed-mid-op
    /// disambiguation is captured in the structural-definition test.
    #[test]
    fn test_is_signal_killed_equals_conjunction() {
        let records = [
            // None + empty: spawn-failure.
            CommandAttemptFailure {
                operation: "x".to_string(),
                attempt: 1,
                exit_code: None,
                stderr: String::new(),
                stdout: "failed to spawn process: no such file".to_string(),
            },
            // None + transient stderr: signal-killed-mid-op.
            CommandAttemptFailure {
                operation: "x".to_string(),
                attempt: 1,
                exit_code: None,
                stderr: "i/o timeout".to_string(),
                stdout: String::new(),
            },
            // None + terminal stderr: signal-killed-mid-op.
            CommandAttemptFailure {
                operation: "x".to_string(),
                attempt: 1,
                exit_code: None,
                stderr: "fatal: aborted".to_string(),
                stdout: String::new(),
            },
            // Some + empty: exited-normally (the shell-preserved 137
            // shape — at OS surface a normal exit).
            CommandAttemptFailure {
                operation: "x".to_string(),
                attempt: 1,
                exit_code: Some(137),
                stderr: String::new(),
                stdout: String::new(),
            },
            // Some + terminal stderr: exited-normally.
            CommandAttemptFailure {
                operation: "x".to_string(),
                attempt: 1,
                exit_code: Some(1),
                stderr: "401 Unauthorized".to_string(),
                stdout: String::new(),
            },
            // Some + transient stderr: exited-normally.
            CommandAttemptFailure {
                operation: "x".to_string(),
                attempt: 1,
                exit_code: Some(1),
                stderr: "503 Service Unavailable".to_string(),
                stdout: String::new(),
            },
            // Some(0) + empty: degenerate-but-structurally-exited-
            // normally (would not occur in practice — from_capture
            // routes Ok(success) to Ok(Output) not Err — but the
            // structural equivalence must hold for hand-built records).
            CommandAttemptFailure {
                operation: "x".to_string(),
                attempt: 1,
                exit_code: Some(0),
                stderr: String::new(),
                stdout: String::new(),
            },
        ];
        for (i, f) in records.iter().enumerate() {
            assert_eq!(
                f.is_signal_killed(),
                f.exit_code.is_none() && !f.stderr.is_empty(),
                "record {i} must satisfy is_signal_killed() == (exit_code.is_none() && !stderr.is_empty()): {f:?}"
            );
        }
    }

    /// `is_exited_normally()` discriminates the three-way structural-shape
    /// partition at the retry-call-site surface: the canonical exit(n)
    /// op-failure shape (`Some(_)` exit code regardless of stderr — auth
    /// rejection, manifest invalid, 5xx-then-exit) discriminates as
    /// exited-normally; both the spawn-failure shape (`None` + empty
    /// stderr, `Err(io::Error)` arm) and the signal-killed-mid-op shape
    /// (`None` + non-empty stderr, child reached `exit()` only via
    /// signal) discriminate as NOT exited-normally. Pins the load-
    /// bearing structural-shape reading at the call-site surface against
    /// any future regression that perturbed the predicate body — notably
    /// pins that `Some(137)` (the canonical shell-preserved SIGKILL
    /// code, 128 + 9) discriminates as exited-normally (a normal OS-
    /// level exit at the [`std::process::ExitStatus::code`] surface),
    /// not as a magic-code threshold reading.
    #[test]
    fn test_is_exited_normally_discriminates_three_way_structural_shape() {
        // Exited-normally: typical non-zero exit op-failure (the
        // canonical Some(1) shape forge's external CLIs emit on a
        // typed rejection — skopeo manifest-invalid, attic auth-
        // denied, git remote-rejected, nix-build derivation-failed).
        let out = synth_output(false, b"", b"401 Unauthorized");
        let f = CommandAttemptFailure::from_capture(Ok(out), "auth op", 1)
            .expect_err("non-zero exit must produce a record");
        assert!(
            f.is_exited_normally(),
            "exit_code: Some(_) with op-failure stderr must discriminate as exited-normally"
        );

        // Exited-normally with shell-preserved 137 (canonical SIGKILL-
        // from-shell code 128 + 9): at the OS surface it's a normal
        // exit. MUST discriminate as exited-normally — the predicate
        // reads through `Option::is_some`, not through a magic-code
        // threshold.
        let f = CommandAttemptFailure {
            operation: "killed".to_string(),
            attempt: 1,
            exit_code: Some(137),
            stderr: String::new(),
            stdout: String::new(),
        };
        assert!(
            f.is_exited_normally(),
            "exit_code: Some(137) MUST discriminate as exited-normally regardless of code value"
        );

        // NOT exited-normally: spawn-failure (`Err(io::Error)` arm:
        // None + empty stderr). The child never reached `exit()`
        // because the process could not be spawned at all.
        let spawn_err = std::io::Error::new(std::io::ErrorKind::NotFound, "no such file");
        let captured: Result<std::process::Output, std::io::Error> = Err(spawn_err);
        let f = CommandAttemptFailure::from_capture(captured, "exec missing", 1)
            .expect_err("spawn failure must produce a record");
        assert!(
            !f.is_exited_normally(),
            "spawn-failure (None + empty stderr) MUST NOT discriminate as exited-normally"
        );
        assert!(
            f.is_spawn_failure(),
            "spawn-failure must still be discriminated by its own peer"
        );

        // NOT exited-normally: signal-killed-mid-op (`Ok(non-success)`
        // arm whose child reached `exit()` only via signal: None +
        // non-empty stderr, the SIGTERM-on-deploy-timeout / SIGSEGV-
        // after-flushing-diagnostic shape).
        let f = CommandAttemptFailure {
            operation: "deploy".to_string(),
            attempt: 1,
            exit_code: None,
            stderr: "fatal: aborted".to_string(),
            stdout: String::new(),
        };
        assert!(
            !f.is_exited_normally(),
            "signal-killed-mid-op (None + non-empty stderr) MUST NOT discriminate as exited-normally"
        );
        assert!(
            f.is_signal_killed(),
            "signal-killed-mid-op must still be discriminated by its own peer"
        );
    }

    /// Three-way disjoint-and-covering partition at the retry-call-site
    /// surface: exactly one of `is_exited_normally`, `is_signal_killed`,
    /// `is_spawn_failure` holds at every record, across the full
    /// spectrum of canonical structural shapes [`CommandAttemptFailure::
    /// from_capture`] constructs. No record satisfies two arms (the
    /// three shapes are partitioned by `(exit_code, stderr.is_empty())`
    /// projections — Some + any / None + non-empty / None + empty — and
    /// the three projections are pairwise disjoint by construction);
    /// no record satisfies none (every `Option<i32>` × `bool` cross-
    /// product is in exactly one arm). The peer-pair lattice-covering
    /// pin against any future regression that introduced an
    /// intermediate structural shape (e.g., a synthetic "abandoned" /
    /// "in-flight" arm) without re-partitioning at this surface, or
    /// that broadened any of the three predicates so that two arms
    /// could co-fire on the same record. Mirrors the sibling
    /// `test_captured_failure_is_exited_normally_xor_is_signal_killed_partitions_records`
    /// pin at the producer surface (commit 5c1cec1) — at the call-site
    /// surface the partition is three-way rather than two-way because
    /// the `Err(io::Error)` spawn-failure arm of `from_capture` carves
    /// a third structural shape out of the `exit_code: None` half of
    /// the universe.
    #[test]
    fn test_is_exited_normally_xor_signal_killed_xor_spawn_failure_partitions_records() {
        let records = [
            // Exited-normally: 4xx auth (the canonical exit(1) op-failure).
            CommandAttemptFailure {
                operation: "auth".to_string(),
                attempt: 1,
                exit_code: Some(1),
                stderr: "401 Unauthorized".to_string(),
                stdout: String::new(),
            },
            // Exited-normally: 5xx (transient stderr but still normal exit).
            CommandAttemptFailure {
                operation: "push".to_string(),
                attempt: 1,
                exit_code: Some(1),
                stderr: "503 Service Unavailable".to_string(),
                stdout: String::new(),
            },
            // Exited-normally: shell-preserved 137 (not a signal-kill at OS surface).
            CommandAttemptFailure {
                operation: "killed".to_string(),
                attempt: 1,
                exit_code: Some(137),
                stderr: String::new(),
                stdout: String::new(),
            },
            // Exited-normally: zero exit (degenerate but structurally exited-normally).
            CommandAttemptFailure {
                operation: "zero".to_string(),
                attempt: 1,
                exit_code: Some(0),
                stderr: String::new(),
                stdout: String::new(),
            },
            // Signal-killed-mid-op: None + transient stderr (i/o timeout flushed before SIGTERM).
            CommandAttemptFailure {
                operation: "deploy".to_string(),
                attempt: 1,
                exit_code: None,
                stderr: "i/o timeout".to_string(),
                stdout: String::new(),
            },
            // Signal-killed-mid-op: None + terminal stderr (fatal aborted before SIGSEGV).
            CommandAttemptFailure {
                operation: "build".to_string(),
                attempt: 1,
                exit_code: None,
                stderr: "fatal: aborted".to_string(),
                stdout: String::new(),
            },
            // Spawn-failure: None + empty stderr (Err(io::Error) arm).
            CommandAttemptFailure {
                operation: "exec".to_string(),
                attempt: 1,
                exit_code: None,
                stderr: String::new(),
                stdout: "failed to spawn process: no such file".to_string(),
            },
        ];
        for (i, f) in records.iter().enumerate() {
            let arms = [
                f.is_exited_normally(),
                f.is_signal_killed(),
                f.is_spawn_failure(),
            ];
            let true_count = arms.iter().filter(|b| **b).count();
            assert_eq!(
                true_count, 1,
                "record {i} must satisfy exactly one of (is_exited_normally, is_signal_killed, is_spawn_failure); got {arms:?}: {f:?}"
            );
        }
    }

    /// Pin the structural definition: `is_exited_normally()` is exactly
    /// `exit_code.is_some()` at every record. A future refactor that
    /// shifted the predicate body to a synthetic discriminator (e.g.,
    /// `stderr.is_empty()`, a separate `exited_normally: bool` field,
    /// a magic exit-code threshold like `code < 128`, or the inverse
    /// `!is_signal_killed() && !is_spawn_failure()` conjunction) without
    /// preserving the `exit_code.is_some()` equivalence would silently
    /// break every downstream consumer that branches on
    /// `is_exited_normally` against the canonical Rust
    /// [`std::process::ExitStatus::code`] semantics. Pinned across hand-
    /// built records covering both the `None` and `Some(_)` arms with
    /// the full spectrum of stderr shapes (empty, transient, terminal)
    /// so the equivalence holds independently of the retry-dispatch
    /// partition and independently of the spawn-failure / signal-killed
    /// disambiguation that shares the `exit_code: None` half of the
    /// universe. Mirrors `test_captured_failure_is_exited_normally_equals_exit_code_is_some`
    /// (commit 5c1cec1) at the producer surface.
    #[test]
    fn test_is_exited_normally_equals_exit_code_is_some() {
        let records = [
            // None + empty: spawn-failure.
            CommandAttemptFailure {
                operation: "x".to_string(),
                attempt: 1,
                exit_code: None,
                stderr: String::new(),
                stdout: "failed to spawn process: no such file".to_string(),
            },
            // None + transient stderr: signal-killed-mid-op.
            CommandAttemptFailure {
                operation: "x".to_string(),
                attempt: 1,
                exit_code: None,
                stderr: "i/o timeout".to_string(),
                stdout: String::new(),
            },
            // None + terminal stderr: signal-killed-mid-op.
            CommandAttemptFailure {
                operation: "x".to_string(),
                attempt: 1,
                exit_code: None,
                stderr: "fatal: aborted".to_string(),
                stdout: String::new(),
            },
            // Some(0) + empty: degenerate exited-normally.
            CommandAttemptFailure {
                operation: "x".to_string(),
                attempt: 1,
                exit_code: Some(0),
                stderr: String::new(),
                stdout: String::new(),
            },
            // Some(1) + terminal stderr: exited-normally.
            CommandAttemptFailure {
                operation: "x".to_string(),
                attempt: 1,
                exit_code: Some(1),
                stderr: "401 Unauthorized".to_string(),
                stdout: String::new(),
            },
            // Some(1) + transient stderr: exited-normally.
            CommandAttemptFailure {
                operation: "x".to_string(),
                attempt: 1,
                exit_code: Some(1),
                stderr: "503 Service Unavailable".to_string(),
                stdout: String::new(),
            },
            // Some(137) + empty stderr: shell-preserved SIGKILL code,
            // structurally exited-normally at the OS surface.
            CommandAttemptFailure {
                operation: "x".to_string(),
                attempt: 1,
                exit_code: Some(137),
                stderr: String::new(),
                stdout: String::new(),
            },
            // Some(255) + transient stderr: exited-normally.
            CommandAttemptFailure {
                operation: "x".to_string(),
                attempt: 1,
                exit_code: Some(255),
                stderr: "i/o timeout".to_string(),
                stdout: String::new(),
            },
        ];
        for (i, f) in records.iter().enumerate() {
            assert_eq!(
                f.is_exited_normally(),
                f.exit_code.is_some(),
                "record {i} must satisfy is_exited_normally() == exit_code.is_some(): {f:?}"
            );
        }
    }

    /// `is_terminal()` discriminates the retry-dispatch arms at every
    /// canonical structural shape `from_capture` constructs. Terminal
    /// stderr (auth 401), empty-stderr spawn-failure (`exit_code:
    /// None` + empty `stderr`), and the non-matching diagnostic
    /// (a free-form error message with no 5xx/timeout/EOF marker) all
    /// discriminate as terminal; the 5xx / connection-refused /
    /// timeout / EOF arms discriminate as NOT terminal. Pins the
    /// load-bearing structural-shape reading at the retry-dispatch
    /// surface against any future regression that perturbed the
    /// predicate body.
    #[test]
    fn test_is_terminal_discriminates_terminal_from_transient() {
        // Terminal: 4xx auth — must short-circuit retry.
        let out = synth_output(false, b"", b"401 Unauthorized: bad token");
        let f = CommandAttemptFailure::from_capture(Ok(out), "auth op", 1)
            .expect_err("non-zero exit must produce a record");
        assert!(f.is_terminal(), "401 auth must discriminate as terminal");

        // Terminal: spawn-failure (empty stderr, no exit code).
        let spawn_err = std::io::Error::new(std::io::ErrorKind::NotFound, "no such file");
        let captured: Result<std::process::Output, std::io::Error> = Err(spawn_err);
        let f = CommandAttemptFailure::from_capture(captured, "exec missing", 1)
            .expect_err("spawn failure must produce a record");
        assert!(
            f.is_terminal(),
            "spawn failure (empty stderr) must discriminate as terminal — empty stderr matches no transient marker"
        );

        // Terminal: non-matching diagnostic (manifest-invalid).
        let out = synth_output(false, b"", b"manifest invalid: bad digest");
        let f = CommandAttemptFailure::from_capture(Ok(out), "manifest op", 1)
            .expect_err("non-zero exit must produce a record");
        assert!(
            f.is_terminal(),
            "non-matching diagnostic must discriminate as terminal"
        );

        // NOT terminal: 5xx transient.
        let out = synth_output(false, b"", b"received unexpected HTTP status: 503");
        let f = CommandAttemptFailure::from_capture(Ok(out), "push op", 1)
            .expect_err("non-zero exit must produce a record");
        assert!(
            !f.is_terminal(),
            "5xx transient must NOT discriminate as terminal"
        );

        // NOT terminal: connection-refused transient.
        let out = synth_output(false, b"", b"dial tcp 10.0.0.1:5000: connection refused");
        let f = CommandAttemptFailure::from_capture(Ok(out), "connect op", 1)
            .expect_err("non-zero exit must produce a record");
        assert!(
            !f.is_terminal(),
            "connection-refused transient must NOT discriminate as terminal"
        );

        // NOT terminal: bare EOF token transient.
        let out = synth_output(false, b"", b"read body: EOF");
        let f = CommandAttemptFailure::from_capture(Ok(out), "read op", 1)
            .expect_err("non-zero exit must produce a record");
        assert!(
            !f.is_terminal(),
            "bare EOF token transient must NOT discriminate as terminal"
        );
    }

    /// De Morgan partition invariant: `is_terminal()` and
    /// `is_transient()` are exact structural complements at every
    /// record `from_capture` constructs and at every hand-built record
    /// an upstream consumer might synthesize. `is_terminal() ==
    /// !is_transient()` at every shape including the spawn-failure
    /// edge (empty stderr → terminal under both readings) and the
    /// signal-killed-with-stderr edge (`exit_code: None` + transient
    /// stderr → terminal-via-transient-classifier reads through). The
    /// pin against a future regression that perturbed one predicate's
    /// body without lifting the change to the other — e.g., broadened
    /// the transient-marker list without re-tightening the terminal
    /// body — which would silently break the canonical retry-loop
    /// dispatch in [`run_with_policy`] and every downstream consumer
    /// that branches on either predicate.
    #[test]
    fn test_is_terminal_equals_negation_of_is_transient() {
        // Transient: 5xx.
        let f = CommandAttemptFailure {
            operation: "x".to_string(),
            attempt: 1,
            exit_code: Some(1),
            stderr: "503 Service Unavailable".to_string(),
            stdout: String::new(),
        };
        assert_eq!(f.is_terminal(), !f.is_transient());
        assert!(!f.is_terminal());

        // Terminal: 4xx auth.
        let f = CommandAttemptFailure {
            operation: "x".to_string(),
            attempt: 1,
            exit_code: Some(1),
            stderr: "401 Unauthorized".to_string(),
            stdout: String::new(),
        };
        assert_eq!(f.is_terminal(), !f.is_transient());
        assert!(f.is_terminal());

        // Spawn-failure: empty stderr, no exit code — terminal by
        // construction (empty stderr matches no transient marker).
        let f = CommandAttemptFailure {
            operation: "x".to_string(),
            attempt: 1,
            exit_code: None,
            stderr: String::new(),
            stdout: "failed to spawn process: no such file".to_string(),
        };
        assert_eq!(f.is_terminal(), !f.is_transient());
        assert!(f.is_terminal());

        // Edge: signal-killed with transient stderr — `exit_code:
        // None` but stderr carries a transient marker. The transient
        // classifier reads through the stderr regardless of the exit
        // code, so this record is transient (and NOT terminal). The
        // De Morgan equivalence must hold.
        let f = CommandAttemptFailure {
            operation: "x".to_string(),
            attempt: 1,
            exit_code: None,
            stderr: "i/o timeout".to_string(),
            stdout: String::new(),
        };
        assert_eq!(f.is_terminal(), !f.is_transient());
        assert!(!f.is_terminal());

        // Edge: populated exit code with empty stderr (signal-killed
        // with stderr already flushed) — terminal (empty stderr
        // matches no transient marker).
        let f = CommandAttemptFailure {
            operation: "x".to_string(),
            attempt: 1,
            exit_code: Some(137),
            stderr: String::new(),
            stdout: String::new(),
        };
        assert_eq!(f.is_terminal(), !f.is_transient());
        assert!(f.is_terminal());
    }

    /// Disjoint-and-covering partition: `is_terminal() XOR
    /// is_transient() == true` at every record across the canonical
    /// structural shapes. No record satisfies both predicates (a
    /// transient stderr cannot simultaneously be terminal) and no
    /// record satisfies neither (every record's stderr classifies
    /// transient-or-not under [`is_transient_network_stderr`], and the
    /// `is_terminal` body is the literal negation of that
    /// classification with no third arm). The peer-pair lattice-
    /// covering pin against any future regression that introduced an
    /// intermediate retry-dispatch class — e.g., a "deferred-retry"
    /// or "rate-limited-with-Retry-After" third arm — without
    /// re-partitioning the predicate pair at this typed-method
    /// surface. Same disjoint-and-covering discipline the recent
    /// `is_op_failure` XOR `is_spawn_failure` peer-pair pin
    /// (commit a4f4146) established at the structural-shape surface,
    /// here applied at the retry-dispatch surface.
    #[test]
    fn test_is_terminal_xor_is_transient_partitions_records() {
        let records = [
            // Terminal: 4xx auth.
            CommandAttemptFailure {
                operation: "auth".to_string(),
                attempt: 1,
                exit_code: Some(1),
                stderr: "401 Unauthorized".to_string(),
                stdout: String::new(),
            },
            // Transient: 5xx.
            CommandAttemptFailure {
                operation: "push".to_string(),
                attempt: 2,
                exit_code: Some(2),
                stderr: "503 Service Unavailable".to_string(),
                stdout: String::new(),
            },
            // Terminal: spawn-failure (empty stderr, no exit code).
            CommandAttemptFailure {
                operation: "exec".to_string(),
                attempt: 1,
                exit_code: None,
                stderr: String::new(),
                stdout: "failed to spawn process: no such file".to_string(),
            },
            // Transient: connection-refused.
            CommandAttemptFailure {
                operation: "dial".to_string(),
                attempt: 1,
                exit_code: Some(1),
                stderr: "dial tcp: connection refused".to_string(),
                stdout: String::new(),
            },
            // Terminal: non-matching diagnostic (manifest-invalid).
            CommandAttemptFailure {
                operation: "manifest".to_string(),
                attempt: 1,
                exit_code: Some(1),
                stderr: "manifest invalid: bad digest".to_string(),
                stdout: String::new(),
            },
            // Transient: i/o timeout.
            CommandAttemptFailure {
                operation: "fetch".to_string(),
                attempt: 1,
                exit_code: Some(1),
                stderr: "i/o timeout".to_string(),
                stdout: String::new(),
            },
            // Transient: bare EOF token.
            CommandAttemptFailure {
                operation: "read".to_string(),
                attempt: 1,
                exit_code: Some(1),
                stderr: "read body: EOF".to_string(),
                stdout: String::new(),
            },
            // Terminal: signal-killed without stderr, populated exit
            // code (137 / SIGKILL).
            CommandAttemptFailure {
                operation: "sigkill".to_string(),
                attempt: 1,
                exit_code: Some(137),
                stderr: String::new(),
                stdout: String::new(),
            },
        ];
        for f in &records {
            assert!(
                f.is_terminal() ^ f.is_transient(),
                "exactly one of is_terminal / is_transient must hold for record {f:?}"
            );
        }
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

    /// `CapturedFailure::is_transient` must return `true` on stderr
    /// matching a canonical 5xx / 429 / connection / timeout / EOF
    /// marker — the typed-method peer of
    /// `CommandAttemptFailure::is_transient`. Pins the typed-record
    /// surface that every typed-error producer (`GitError::OpFailed`,
    /// `NixBuildError::BuildFailed`, `AtticError::PushFailed`,
    /// `RegistryError::PushFailed`) consumes when it wants to
    /// classify the captured failure without re-routing through the
    /// free `is_transient_network_stderr` function.
    #[test]
    fn test_captured_failure_is_transient_on_5xx() {
        let out = synth_output(false, b"", b"received unexpected HTTP status: 503");
        let cf = CapturedFailure::from_output(&out);
        assert!(cf.is_transient());
    }

    /// Terminal failures (auth, not-found, manifest mismatch) must
    /// NOT be classified transient — same discipline the sibling peer
    /// `CommandAttemptFailure::is_transient` encodes for the retry-
    /// call-site surface. A typed-error producer that wraps a
    /// terminal CLI failure (e.g. `AtticError::LoginFailed` from a
    /// 401) consumes `cf.is_transient()` to short-circuit any future
    /// retry-policy dispatch site without re-routing through the
    /// free classifier.
    #[test]
    fn test_captured_failure_is_not_transient_on_terminal() {
        let out = synth_output(false, b"", b"401 Unauthorized: bad token");
        let cf = CapturedFailure::from_output(&out);
        assert!(!cf.is_transient());
    }

    /// Empty stderr must be terminal under
    /// `CapturedFailure::is_transient` — same construction the sibling
    /// peer `CommandAttemptFailure::is_transient` encodes (empty stderr
    /// short-circuits the classifier at the very first guard, so a
    /// "no captured diagnostics" failure never burns retry budget).
    /// Although `CapturedFailure::from_output` is only ever called on
    /// a real `Output` (so the spawn-failure path that produces an
    /// empty-stderr `CommandAttemptFailure` cannot arise here), a
    /// CLI can still emit zero stderr on a non-zero exit — pinning
    /// the empty-stderr case to terminal keeps the typed-method
    /// peer behaviorally aligned with the sibling.
    #[test]
    fn test_captured_failure_is_not_transient_on_empty_stderr() {
        let out = synth_output(false, b"silent failure on stdout", b"");
        let cf = CapturedFailure::from_output(&out);
        assert!(cf.stderr.is_empty());
        assert!(!cf.is_transient());
    }

    /// `CapturedFailure::is_terminal` must discriminate every terminal
    /// shape (4xx auth, empty-stderr silent failure, non-matching
    /// diagnostic) as `true` and every canonical 5xx / 429 / connection
    /// / timeout / EOF transient arm as `false`. The typed-method peer
    /// of `CommandAttemptFailure::is_terminal` (commit 6fa921b) at the
    /// typed-error producer surface. Pins the load-bearing
    /// structural-shape reading at this surface against any future
    /// regression that perturbed the predicate body.
    #[test]
    fn test_captured_failure_is_terminal_discriminates_terminal_from_transient() {
        // Terminal: 4xx auth.
        let out = synth_output(false, b"", b"401 Unauthorized: bad token");
        let cf = CapturedFailure::from_output(&out);
        assert!(cf.is_terminal(), "401 auth must discriminate as terminal");

        // Terminal: empty stderr (silent CLI failure on stdout only).
        let out = synth_output(false, b"silent failure on stdout", b"");
        let cf = CapturedFailure::from_output(&out);
        assert!(
            cf.is_terminal(),
            "empty stderr must discriminate as terminal — matches no transient marker"
        );

        // Terminal: non-matching diagnostic.
        let out = synth_output(false, b"", b"manifest invalid: bad digest");
        let cf = CapturedFailure::from_output(&out);
        assert!(
            cf.is_terminal(),
            "non-matching diagnostic must discriminate as terminal"
        );

        // NOT terminal: 5xx transient.
        let out = synth_output(false, b"", b"received unexpected HTTP status: 503");
        let cf = CapturedFailure::from_output(&out);
        assert!(
            !cf.is_terminal(),
            "5xx transient must NOT discriminate as terminal"
        );

        // NOT terminal: connection-refused transient.
        let out = synth_output(false, b"", b"dial tcp 10.0.0.1:5000: connection refused");
        let cf = CapturedFailure::from_output(&out);
        assert!(
            !cf.is_terminal(),
            "connection-refused transient must NOT discriminate as terminal"
        );

        // NOT terminal: bare EOF token transient.
        let out = synth_output(false, b"", b"read body: EOF");
        let cf = CapturedFailure::from_output(&out);
        assert!(
            !cf.is_terminal(),
            "bare EOF token transient must NOT discriminate as terminal"
        );
    }

    /// De Morgan partition invariant at the typed-error producer
    /// surface: `cf.is_terminal() == !cf.is_transient()` at every
    /// record `from_output` constructs and at every hand-built record
    /// an upstream consumer might synthesize. Mirrors the sibling pin
    /// `test_is_terminal_equals_negation_of_is_transient` at the
    /// retry-call-site surface (commit 6fa921b). The pin against a
    /// future regression that perturbed one predicate's body without
    /// lifting the change to the other — e.g., broadened the
    /// transient-marker list at the free classifier without
    /// re-tightening the terminal body — which would silently break
    /// every downstream consumer that branches on either predicate.
    #[test]
    fn test_captured_failure_is_terminal_equals_negation_of_is_transient() {
        // Transient: 5xx.
        let cf = CapturedFailure {
            exit_code: Some(1),
            stderr: "503 Service Unavailable".to_string(),
        };
        assert_eq!(cf.is_terminal(), !cf.is_transient());
        assert!(!cf.is_terminal());

        // Terminal: 4xx auth.
        let cf = CapturedFailure {
            exit_code: Some(1),
            stderr: "401 Unauthorized".to_string(),
        };
        assert_eq!(cf.is_terminal(), !cf.is_transient());
        assert!(cf.is_terminal());

        // Terminal: empty stderr — matches no transient marker.
        let cf = CapturedFailure {
            exit_code: Some(1),
            stderr: String::new(),
        };
        assert_eq!(cf.is_terminal(), !cf.is_transient());
        assert!(cf.is_terminal());

        // Edge: signal-killed (`exit_code: None`) with transient stderr.
        // The classifier reads through stderr regardless of exit code, so
        // this record is transient (NOT terminal). The De Morgan
        // equivalence must hold.
        let cf = CapturedFailure {
            exit_code: None,
            stderr: "i/o timeout".to_string(),
        };
        assert_eq!(cf.is_terminal(), !cf.is_transient());
        assert!(!cf.is_terminal());

        // Edge: populated exit code with terminal stderr (manifest body).
        let cf = CapturedFailure {
            exit_code: Some(137),
            stderr: "manifest invalid: bad digest".to_string(),
        };
        assert_eq!(cf.is_terminal(), !cf.is_transient());
        assert!(cf.is_terminal());
    }

    /// Disjoint-and-covering partition at the typed-error producer
    /// surface: `cf.is_terminal() XOR cf.is_transient() == true` at
    /// every record across the canonical structural shapes. No record
    /// satisfies both (a transient stderr cannot simultaneously be
    /// terminal) and no record satisfies neither (every record's stderr
    /// classifies transient-or-not under
    /// [`is_transient_network_stderr`], and the `is_terminal` body is
    /// the literal negation of that classification with no third arm).
    /// The peer-pair lattice-covering pin against any future regression
    /// that introduced an intermediate retry-dispatch class — e.g., a
    /// "deferred-retry" or "rate-limited-with-Retry-After" third arm —
    /// without re-partitioning the predicate pair at this typed-method
    /// surface. Mirrors the sibling
    /// `test_is_terminal_xor_is_transient_partitions_records` pin at
    /// the retry-call-site surface (commit 6fa921b).
    #[test]
    fn test_captured_failure_is_terminal_xor_is_transient_partitions_records() {
        let records = [
            // Terminal: 4xx auth.
            CapturedFailure {
                exit_code: Some(1),
                stderr: "401 Unauthorized".to_string(),
            },
            // Transient: 5xx.
            CapturedFailure {
                exit_code: Some(2),
                stderr: "503 Service Unavailable".to_string(),
            },
            // Terminal: empty stderr (silent failure on stdout only).
            CapturedFailure {
                exit_code: Some(1),
                stderr: String::new(),
            },
            // Transient: connection-refused.
            CapturedFailure {
                exit_code: Some(1),
                stderr: "dial tcp: connection refused".to_string(),
            },
            // Terminal: non-matching diagnostic (manifest-invalid).
            CapturedFailure {
                exit_code: Some(1),
                stderr: "manifest invalid: bad digest".to_string(),
            },
            // Transient: i/o timeout (signal-killed with transient stderr).
            CapturedFailure {
                exit_code: None,
                stderr: "i/o timeout".to_string(),
            },
            // Transient: bare EOF token.
            CapturedFailure {
                exit_code: Some(1),
                stderr: "read body: EOF".to_string(),
            },
            // Terminal: signal-killed (`Some(137)`) with empty stderr.
            CapturedFailure {
                exit_code: Some(137),
                stderr: String::new(),
            },
        ];
        for (i, cf) in records.iter().enumerate() {
            assert!(
                cf.is_terminal() ^ cf.is_transient(),
                "record {i} must satisfy exactly one of (is_terminal, is_transient): {cf:?}"
            );
        }
    }

    /// `is_signal_killed()` discriminates the structural-shape partition
    /// at every canonical record `from_output` constructs and at every
    /// hand-built shape an upstream consumer might synthesize.
    /// `exit_code: None` (the canonical `ExitStatus::code` "killed by
    /// signal" semantics — SIGKILL, SIGTERM, SIGSEGV, SIGPIPE, cgroups
    /// OOM-kill) discriminates as signal-killed; `exit_code: Some(_)`
    /// (any normal exit code, including the canonical 137 SIGKILL-from-
    /// shell exit code preserved by `bash`) discriminates as NOT
    /// signal-killed. Pins the load-bearing structural-shape reading
    /// at the typed-error producer surface against any future regression
    /// that perturbed the predicate body (e.g., a refactor that broadened
    /// "signal-killed" to "exit code >= 128 OR None" without re-tightening
    /// the typed-method body to match).
    #[test]
    fn test_captured_failure_is_signal_killed_discriminates_structural_shape() {
        // Signal-killed: empty stderr (the canonical SIGKILL / OOM-kill
        // shape — child process terminated before flushing diagnostics).
        let cf = CapturedFailure {
            exit_code: None,
            stderr: String::new(),
        };
        assert!(
            cf.is_signal_killed(),
            "exit_code: None must discriminate as signal-killed"
        );

        // Signal-killed: populated stderr (the SIGTERM-graceful-shutdown
        // shape — child caught the signal and flushed a final
        // diagnostic before exiting).
        let cf = CapturedFailure {
            exit_code: None,
            stderr: "i/o timeout".to_string(),
        };
        assert!(
            cf.is_signal_killed(),
            "exit_code: None with stderr must still discriminate as signal-killed"
        );

        // NOT signal-killed: populated exit code with empty stderr.
        // 137 is the canonical shell-preserved SIGKILL code (128 + 9),
        // but at the OS surface it's a normal exit — the Output struct
        // distinguishes "killed by signal" from "exited with code 137"
        // strictly through `ExitStatus::code`'s None/Some discriminator,
        // not through the value of the code. Pins that the predicate
        // reads through `Option::is_none`, not through a magic-code
        // threshold.
        let cf = CapturedFailure {
            exit_code: Some(137),
            stderr: String::new(),
        };
        assert!(
            !cf.is_signal_killed(),
            "exit_code: Some(_) MUST NOT discriminate as signal-killed regardless of code value"
        );

        // NOT signal-killed: typical non-zero-exit op-failure.
        let cf = CapturedFailure {
            exit_code: Some(1),
            stderr: "401 Unauthorized".to_string(),
        };
        assert!(
            !cf.is_signal_killed(),
            "exit_code: Some(1) with op-failure stderr MUST NOT discriminate as signal-killed"
        );
    }

    /// Structural-shape predicate is orthogonal to the retry-dispatch
    /// partition (`is_transient` / `is_terminal`). Every quadrant of the
    /// 2×2 (signal-killed × transient, signal-killed × terminal,
    /// normal-exit × transient, normal-exit × terminal) is populated by a
    /// canonical structural shape forge's external CLIs emit, so neither
    /// partition collapses into the other. The pin against a future
    /// regression that fused the two axes — e.g., redefined `is_transient`
    /// to additionally inspect `exit_code` (breaking the stderr-only
    /// classifier discipline) or redefined `is_signal_killed` to
    /// additionally inspect `stderr` (breaking the structural-shape
    /// discipline) — which would collapse the 2×2 into a 1D partition
    /// and silently break the downstream classification surface every
    /// post-failure consumer site relies on.
    #[test]
    fn test_captured_failure_is_signal_killed_orthogonal_to_transient() {
        // Q1: signal-killed AND transient (SIGTERM-graceful with `"i/o
        // timeout"` in stderr — the deploy-timeout-on-network-op shape).
        let cf = CapturedFailure {
            exit_code: None,
            stderr: "i/o timeout".to_string(),
        };
        assert!(cf.is_signal_killed());
        assert!(cf.is_transient());

        // Q2: signal-killed AND terminal (SIGKILL / OOM-kill — empty
        // stderr means the canonical classifier short-circuits to
        // terminal regardless of structural shape).
        let cf = CapturedFailure {
            exit_code: None,
            stderr: String::new(),
        };
        assert!(cf.is_signal_killed());
        assert!(cf.is_terminal());

        // Q3: normal-exit AND transient (the canonical retry-budget-
        // consuming arm — `Some(1)` exit with 503 in stderr).
        let cf = CapturedFailure {
            exit_code: Some(1),
            stderr: "503 Service Unavailable".to_string(),
        };
        assert!(!cf.is_signal_killed());
        assert!(cf.is_transient());

        // Q4: normal-exit AND terminal (the canonical fail-fast arm —
        // `Some(1)` exit with 401 in stderr).
        let cf = CapturedFailure {
            exit_code: Some(1),
            stderr: "401 Unauthorized".to_string(),
        };
        assert!(!cf.is_signal_killed());
        assert!(cf.is_terminal());
    }

    /// Pin the structural definition: `is_signal_killed()` is exactly
    /// `exit_code.is_none()` at every record. A future refactor that
    /// shifted the predicate body to a synthetic discriminator (e.g.,
    /// `stderr.contains("signal")`, a separate `killed_by_signal: bool`
    /// field, a magic exit-code threshold) without preserving the
    /// `exit_code.is_none()` equivalence would silently break every
    /// downstream consumer that branches on `is_signal_killed` against
    /// the canonical Rust `ExitStatus::code` semantics. Pinned across
    /// hand-built records covering both the `None` and `Some(_)` arms
    /// with the full spectrum of stderr shapes (empty, transient,
    /// terminal) so the equivalence holds independently of the
    /// retry-dispatch partition.
    #[test]
    fn test_captured_failure_is_signal_killed_equals_exit_code_is_none() {
        let records = [
            CapturedFailure {
                exit_code: None,
                stderr: String::new(),
            },
            CapturedFailure {
                exit_code: None,
                stderr: "i/o timeout".to_string(),
            },
            CapturedFailure {
                exit_code: None,
                stderr: "fatal: aborted".to_string(),
            },
            CapturedFailure {
                exit_code: Some(0),
                stderr: String::new(),
            },
            CapturedFailure {
                exit_code: Some(1),
                stderr: "401 Unauthorized".to_string(),
            },
            CapturedFailure {
                exit_code: Some(137),
                stderr: String::new(),
            },
            CapturedFailure {
                exit_code: Some(255),
                stderr: "503 Service Unavailable".to_string(),
            },
        ];
        for (i, cf) in records.iter().enumerate() {
            assert_eq!(
                cf.is_signal_killed(),
                cf.exit_code.is_none(),
                "record {i} must satisfy is_signal_killed() == exit_code.is_none(): {cf:?}"
            );
        }
    }

    /// `is_exited_normally()` discriminates the normal-exit arm of the
    /// structural-shape partition at every canonical record `from_output`
    /// constructs and at every hand-built shape an upstream consumer
    /// might synthesize. `exit_code: Some(_)` (any normal exit code,
    /// including the canonical 137 SIGKILL-from-shell exit code preserved
    /// by `bash` — at the OS surface a normal exit, not a signal-kill)
    /// discriminates as exited-normally; `exit_code: None` (the canonical
    /// `ExitStatus::code` "killed by signal" semantics) discriminates as
    /// NOT exited-normally. Mirrors
    /// `test_captured_failure_is_signal_killed_discriminates_structural_shape`
    /// from the other arm — the two predicates discriminate the same
    /// partition through opposite-direction reads.
    #[test]
    fn test_captured_failure_is_exited_normally_discriminates_structural_shape() {
        // Exited-normally: typical non-zero-exit op-failure (the
        // canonical exit(1)-on-rejected-request shape every external
        // CLI in forge emits on a typed rejection: skopeo manifest-
        // invalid, attic auth-denied, git remote-rejected, nix-build
        // derivation-failed).
        let cf = CapturedFailure {
            exit_code: Some(1),
            stderr: "401 Unauthorized".to_string(),
        };
        assert!(
            cf.is_exited_normally(),
            "exit_code: Some(1) with op-failure stderr must discriminate as exited-normally"
        );

        // Exited-normally: populated exit code with empty stderr.
        // 137 is the canonical shell-preserved SIGKILL code (128 + 9),
        // but at the OS surface it's a normal exit — the Output struct
        // distinguishes "killed by signal" from "exited with code 137"
        // strictly through `ExitStatus::code`'s None/Some discriminator,
        // not through the value of the code. Pins that the predicate
        // reads through `Option::is_some`, not through a magic-code
        // threshold.
        let cf = CapturedFailure {
            exit_code: Some(137),
            stderr: String::new(),
        };
        assert!(
            cf.is_exited_normally(),
            "exit_code: Some(137) MUST discriminate as exited-normally regardless of code value"
        );

        // NOT exited-normally: signal-killed with empty stderr (the
        // canonical SIGKILL / OOM-kill shape — child process terminated
        // before flushing diagnostics).
        let cf = CapturedFailure {
            exit_code: None,
            stderr: String::new(),
        };
        assert!(
            !cf.is_exited_normally(),
            "exit_code: None MUST NOT discriminate as exited-normally"
        );

        // NOT exited-normally: signal-killed with populated stderr
        // (the SIGTERM-graceful-shutdown shape — child caught the
        // signal and flushed a final diagnostic before exiting).
        let cf = CapturedFailure {
            exit_code: None,
            stderr: "i/o timeout".to_string(),
        };
        assert!(
            !cf.is_exited_normally(),
            "exit_code: None with stderr MUST NOT discriminate as exited-normally"
        );
    }

    /// Disjoint-and-covering partition at the typed-error producer
    /// surface: `cf.is_exited_normally() XOR cf.is_signal_killed() == true`
    /// at every record across the canonical structural shapes. No record
    /// satisfies both (`exit_code` is canonically either `Some(_)` or
    /// `None`, never both) and no record satisfies neither (every
    /// `Option<i32>` is in exactly one of the two arms). The peer-pair
    /// lattice-covering pin against any future regression that introduced
    /// a third structural-shape class — e.g., a synthetic "abandoned"
    /// or "in-flight" intermediate — without re-partitioning the
    /// predicate pair at this typed-method surface. Mirrors the sibling
    /// `test_is_op_failure_xor_is_spawn_failure_partitions_records` pin
    /// at the retry-call-site surface (commit a4f4146) and the
    /// `test_captured_failure_is_terminal_xor_is_transient_partitions_records`
    /// pin for the retry-dispatch partition (commit 6069a25).
    #[test]
    fn test_captured_failure_is_exited_normally_xor_is_signal_killed_partitions_records() {
        let records = [
            // Exited-normally: 4xx auth (the canonical exit(1) op-failure).
            CapturedFailure {
                exit_code: Some(1),
                stderr: "401 Unauthorized".to_string(),
            },
            // Exited-normally: 5xx (transient stderr but still normal exit).
            CapturedFailure {
                exit_code: Some(1),
                stderr: "503 Service Unavailable".to_string(),
            },
            // Exited-normally: shell-preserved 137 (not a signal-kill at OS surface).
            CapturedFailure {
                exit_code: Some(137),
                stderr: String::new(),
            },
            // Exited-normally: zero exit (degenerate but structurally exited-normally).
            CapturedFailure {
                exit_code: Some(0),
                stderr: String::new(),
            },
            // Signal-killed: empty stderr (SIGKILL / OOM-kill shape).
            CapturedFailure {
                exit_code: None,
                stderr: String::new(),
            },
            // Signal-killed: transient stderr (i/o timeout flushed before kill).
            CapturedFailure {
                exit_code: None,
                stderr: "i/o timeout".to_string(),
            },
            // Signal-killed: terminal stderr (fatal aborted before kill).
            CapturedFailure {
                exit_code: None,
                stderr: "fatal: aborted".to_string(),
            },
        ];
        for (i, cf) in records.iter().enumerate() {
            assert!(
                cf.is_exited_normally() ^ cf.is_signal_killed(),
                "record {i} must satisfy exactly one of (is_exited_normally, is_signal_killed): {cf:?}"
            );
        }
    }

    /// Pin the structural definition: `is_exited_normally()` is exactly
    /// `exit_code.is_some()` at every record. A future refactor that
    /// shifted the predicate body to a synthetic discriminator (e.g.,
    /// `stderr.is_empty()`, a separate `exited_normally: bool` field,
    /// a magic exit-code threshold like `code < 128`) without preserving
    /// the `exit_code.is_some()` equivalence would silently break every
    /// downstream consumer that branches on `is_exited_normally` against
    /// the canonical Rust `ExitStatus::code` semantics. Pinned across
    /// hand-built records covering both the `None` and `Some(_)` arms
    /// with the full spectrum of stderr shapes (empty, transient,
    /// terminal) so the equivalence holds independently of the
    /// retry-dispatch partition. Mirrors
    /// `test_captured_failure_is_signal_killed_equals_exit_code_is_none`
    /// from the sibling arm.
    #[test]
    fn test_captured_failure_is_exited_normally_equals_exit_code_is_some() {
        let records = [
            CapturedFailure {
                exit_code: None,
                stderr: String::new(),
            },
            CapturedFailure {
                exit_code: None,
                stderr: "i/o timeout".to_string(),
            },
            CapturedFailure {
                exit_code: None,
                stderr: "fatal: aborted".to_string(),
            },
            CapturedFailure {
                exit_code: Some(0),
                stderr: String::new(),
            },
            CapturedFailure {
                exit_code: Some(1),
                stderr: "401 Unauthorized".to_string(),
            },
            CapturedFailure {
                exit_code: Some(137),
                stderr: String::new(),
            },
            CapturedFailure {
                exit_code: Some(255),
                stderr: "503 Service Unavailable".to_string(),
            },
        ];
        for (i, cf) in records.iter().enumerate() {
            assert_eq!(
                cf.is_exited_normally(),
                cf.exit_code.is_some(),
                "record {i} must satisfy is_exited_normally() == exit_code.is_some(): {cf:?}"
            );
        }
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
    /// (e.g. `GitError::OpFailed` carrying the `(exit_code, stderr)`
    /// pair) destructures `cf.exit_code` and `cf.stderr` by name; a site
    /// that wants only the precondition meaning (e.g.
    /// `RegistryError::RemoteImageNotFound` carrying just the (registry,
    /// tag) tuple — "the queried thing isn't there") ignores `cf` with
    /// `|_cf| ...`. Both shapes are in-tree consumers of this primitive.
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
    /// turn every "git not on PATH" failure into an `OpFailed` record
    /// with empty stderr, drift-prone against the canonical
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

    /// `classify_capture_query_anyhow` on a successful spawn returns the
    /// trimmed UTF-8-lossy stdout — same trim discipline
    /// `classify_capture_query` already pins. Both anyhow consumers
    /// (`commands/seed.rs::run_command_output` and
    /// `commands/attestation.rs::run_command_output`) feed the returned
    /// string into downstream pod-discovery and attestation-record paths
    /// where a leaked trailing `\n` surfaces as a confusing "pod not
    /// found" / "git ref invalid" diagnostic; pinning the trim at this
    /// primitive guarantees neither consumer can drift onto a
    /// `from_utf8_lossy(&out.stdout).to_string()` shape.
    #[test]
    fn test_classify_capture_query_anyhow_success_returns_trimmed_stdout() {
        let out = synth_output(true, b"  primary-pod-0  ", b"");
        let result = classify_capture_query_anyhow(Ok(out), "kubectl", &["get", "pod"]);
        let stdout = result.expect("zero-exit must return Ok(trimmed)");
        assert_eq!(
            stdout, "primary-pod-0",
            "trim must strip both leading/trailing ws"
        );
    }

    /// `classify_capture_query_anyhow` on a non-zero exit surfaces the
    /// canonical `"{cmd} {args:?} failed (exit {code:?}): {stderr}"`
    /// envelope. Pins the structural-record tuple (operation label, exit
    /// code, trimmed stderr) at the primitive — both the seed and the
    /// attestation consumers' tests assert the same shape against the
    /// primitive's output, so a future regression at the primitive would
    /// fail this test BEFORE the consumer-side asserts surface it.
    #[test]
    fn test_classify_capture_query_anyhow_op_failure_carries_structural_tuple() {
        let out = synth_output(false, b"", b"  fatal: bad ref  \n");
        let err = classify_capture_query_anyhow(Ok(out), "git", &["log", "-1"])
            .expect_err("non-zero exit must produce Err");
        let msg = format!("{err}");
        assert!(
            msg.contains("git"),
            "msg must carry the cmd label, got: {msg}"
        );
        assert!(
            msg.contains("\"log\"") && msg.contains("\"-1\""),
            "msg must carry args :? rendering, got: {msg}"
        );
        // `false` exits with code 1 on every Unix the test runner ships on;
        // pin only that the exit code surfaces in `(exit Some(_))` form.
        assert!(
            msg.contains("(exit Some("),
            "msg must carry the exit code in the canonical shape, got: {msg}"
        );
        assert!(
            msg.contains("fatal: bad ref"),
            "msg must carry trimmed stderr, got: {msg}"
        );
        // The trim discipline at the primitive must NOT leak the
        // leading/trailing whitespace from the synthesized stderr — pin
        // both directions explicitly so a future regression that swapped
        // `.trim()` for `.trim_end()` (or dropped the trim entirely) fails
        // here.
        assert!(
            !msg.contains("  fatal:"),
            "leading whitespace must be stripped from stderr, got: {msg}"
        );
    }

    /// `classify_capture_query_anyhow` on a spawn failure (binary not on
    /// PATH / fork failed) surfaces the canonical
    /// `"Failed to spawn {cmd} {args:?}: {io_error}"` envelope. Pins the
    /// spawn-vs-op discriminator that both anyhow consumers rely on at the
    /// canonical primitive — pre-migration the spawn arm fused into a
    /// `with_context("Failed to execute kubectl")` envelope that dropped
    /// the captured `io::Error::Display` and the args entirely. A future
    /// regression that re-fused the spawn arm into the op arm would fail
    /// this test rather than silently collapse the
    /// `classify_capture` (b75a273) spawn-vs-op invariant.
    #[test]
    fn test_classify_capture_query_anyhow_spawn_failure_carries_op_label() {
        let captured: std::io::Result<std::process::Output> = Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no such file or directory",
        ));
        let err = classify_capture_query_anyhow(captured, "kubectl", &["get", "pod"])
            .expect_err("spawn failure must produce Err");
        let msg = format!("{err}");
        assert!(
            msg.starts_with("Failed to spawn"),
            "spawn-arm envelope must lead the message, got: {msg}"
        );
        assert!(
            msg.contains("kubectl"),
            "msg must carry the cmd label, got: {msg}"
        );
        assert!(
            msg.contains("\"get\"") && msg.contains("\"pod\""),
            "msg must carry args :? rendering, got: {msg}"
        );
        assert!(
            msg.contains("no such file"),
            "msg must carry io::Error::Display, got: {msg}"
        );
    }

    /// Empty args slice — `args:?` renders as `[]` and the primitive must
    /// not panic / corrupt the message format. Pins the boundary against a
    /// future regression that special-cased empty args (e.g., dropped them
    /// from the message entirely, breaking the `{cmd} {args:?}` shape both
    /// consumers' `find_primary_pod` / `compute_*_attestation` callers
    /// rely on).
    #[test]
    fn test_classify_capture_query_anyhow_empty_args_round_trips() {
        let out = synth_output(false, b"", b"oops");
        let err = classify_capture_query_anyhow(Ok(out), "true", &[])
            .expect_err("non-zero exit must produce Err");
        let msg = format!("{err}");
        assert!(
            msg.contains("true []"),
            "empty args must render as `[]` in the canonical shape, got: {msg}"
        );
    }

    // -----------------------------------------------------------------
    // run_query_capture_sync — the canonical
    // `Command::new(cmd).args(args).output()` + `classify_capture_query_anyhow`
    // consolidation. Drives the full spawn-then-classify pipeline against
    // hermetic `make_executable_shim` binaries so a future regression at
    // either the spawn surface or the classifier shape fails here rather
    // than silently degrading the three consumer sites that pre-this-commit
    // each carried a private wrapper:
    // `commands/seed.rs::run_command_output`,
    // `commands/sessions.rs::kubectl`,
    // `commands/local.rs::run_command_output`.
    // -----------------------------------------------------------------

    /// `run_query_capture_sync` end-to-end via a hermetic shim: the
    /// successful spawn returns the trimmed UTF-8-lossy stdout. Mirrors
    /// the three per-site `..._success_returns_trimmed_stdout` tests
    /// this primitive consolidates (`commands/seed.rs`,
    /// `commands/local.rs`). The trim discipline is load-bearing
    /// downstream — `find_primary_pod`'s returned pod name feeds into a
    /// `kubectl exec -n NS POD` invocation where a trailing `\n` on
    /// the pod name surfaces as a confusing "pod not found" diagnostic.
    #[cfg(unix)]
    #[test]
    fn test_run_query_capture_sync_success_returns_trimmed_stdout() {
        let (_dir, shim) = crate::test_support::make_executable_shim(
            "echo-shim",
            "#!/bin/sh\necho '  primary-pod-0  '\n",
        );
        let out = run_query_capture_sync(&shim, &[]).expect("shim must succeed");
        assert_eq!(
            out, "primary-pod-0",
            "trim must strip both leading/trailing ws"
        );
    }

    /// `run_query_capture_sync` on a non-zero shim exit surfaces the
    /// structural-record tuple in the anyhow error message: the cmd
    /// label, the `args:?` Debug rendering, the exit code, and the
    /// trimmed stderr. Mirror of the three per-site
    /// `..._op_failure_carries_structural_tuple` tests this primitive
    /// consolidates. A future regression that re-dropped the exit code
    /// or the args from the message envelope would fail this test
    /// rather than silently degrade the THEORY §V.4 Phase 1 attestation
    /// record shape downstream telemetry pattern-matches on.
    #[cfg(unix)]
    #[test]
    fn test_run_query_capture_sync_op_failure_carries_structural_tuple() {
        let (_dir, shim) = crate::test_support::make_executable_shim(
            "fail-shim",
            "#!/bin/sh\necho 'no matching pod' 1>&2\nexit 11\n",
        );
        let err =
            run_query_capture_sync(&shim, &["get", "pod"]).expect_err("nonzero exit must fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("(exit Some(11))"),
            "msg must carry exit code, got: {msg}"
        );
        assert!(
            msg.contains("no matching pod"),
            "msg must carry trimmed stderr, got: {msg}"
        );
        assert!(
            msg.contains("\"get\"") && msg.contains("\"pod\""),
            "msg must carry args debug rendering, got: {msg}"
        );
    }

    /// `run_query_capture_sync` on a spawn failure (binary not on PATH
    /// / nonexistent absolute path) surfaces the canonical
    /// `Failed to spawn {cmd} {args:?}: {io_error}` envelope. Mirror
    /// of the three per-site `..._spawn_failure_carries_op_label`
    /// tests this primitive consolidates. Pins the spawn-vs-op
    /// discriminator: a future regression that re-fused the spawn arm
    /// into the op arm would fail this test rather than silently
    /// collapse the typed-error structural shape every consumer of
    /// the primitive (seed / sessions / local) relies on.
    #[test]
    fn test_run_query_capture_sync_spawn_failure_carries_op_label() {
        let missing = "/nonexistent/forge-test-shim-must-not-exist-run-query";
        let err = run_query_capture_sync(missing, &["arg-a"])
            .expect_err("spawn against nonexistent path must fail");
        let msg = format!("{err}");
        assert!(
            msg.starts_with("Failed to spawn"),
            "msg must carry spawn-arm envelope, got: {msg}"
        );
        assert!(
            msg.contains(missing),
            "msg must carry the offending cmd path, got: {msg}"
        );
        assert!(
            msg.contains("\"arg-a\""),
            "msg must carry args debug rendering, got: {msg}"
        );
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
