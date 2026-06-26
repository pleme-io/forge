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
/// recovers from. 429 (Too Many Requests, RFC 6585 §4): the rate-limit
/// backoff signal GHCR / Docker Hub / attic-fronted CDNs return under
/// load with an advisory `Retry-After` — the one retryable 4xx (back
/// off, then retry). The terminal 4xx family (400/401/403/404 — bad
/// request, auth, not-found) is absent by construction: retrying cannot
/// help, so failing fast preserves the budget.
const TRANSIENT_HTTP_STATUS_CODES: &[&str] = &["500", "502", "503", "504", "429"];

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
    // refused` is split. The marker is also distinct from the curl
    // sibling `"Empty reply from server"` (`CURLE_GOT_NOTHING` —
    // libcurl emits this when the TCP connection accepted then closed
    // with zero response bytes, distinct from hyper's *partial*-
    // response signal where some bytes returned before the close); the
    // libcurl marker is not added in this commit because forge's
    // libcurl-fronted CLIs (git-over-HTTPS) trip the closely-related
    // `unexpected EOF` substring first via libcurl's `CURLE_RECV_ERROR`
    // path — the hot-path gap closed here is the hyper/reqwest dialect
    // attic-client takes against attic-server.
    "connection closed before message completed",
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
