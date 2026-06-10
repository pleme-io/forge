//! Common contract for forge's typed probe outcomes.
//!
//! Sixteen sibling modules — [`crate::chart_dependencies`],
//! [`crate::cis_k8s_pass_rate`], [`crate::cosign`],
//! [`crate::deployment_manifest`], [`crate::flux_source_verification`],
//! [`crate::git_signature`], [`crate::helm_lint`],
//! [`crate::helm_provenance`], [`crate::helm_release_signature`],
//! [`crate::kensa_policy`], [`crate::network_policy_admission`],
//! [`crate::nix_reproducibility`], [`crate::oci_architecture`],
//! [`crate::pod_health`], [`crate::pod_listing`], and
//! [`crate::security_scan`] (which carries two distinct typed probe
//! outcomes, `SbomProbeOutcome` and `VulnScanProbeOutcome`) — each carry
//! a typed `*Outcome` enum with at least one variant that names the "no
//! probe ran / no evidence collected" world. The variant name is
//! `ProbeAbsent` in most modules and `Absent` in three (`SbomProbe`,
//! `VulnScanProbe`, `OciArchitecture`); the surface name varies because
//! the shape was discovered seventeen commits at a time, but the
//! load-bearing structural invariant is identical at every site:
//!
//! 1. The absent variant identifies as absent under `is_probe_absent()`.
//! 2. Every other variant identifies as not-absent.
//!
//! The bare `bool` returned by `is_probe_absent` carries the structural
//! discriminator the prior bare-literal attestation-call-site code
//! erased — every `vec![]` / `false` / `0` / `0.0` /
//! `Blake3Hash::digest(b"pending-…")` literal that the typed-primitive
//! family closed over commits b98eb5a → 5c0d121 collapsed three or four
//! operational worlds into a single surface value, where this trait now
//! lets a downstream verifier recover the kind-of-claim "did a probe run
//! at all?" from any implementor in one line of generic code.
//!
//! ## What this module does NOT do
//!
//! It does not introduce a generic `Claim` associated type or a generic
//! claim-collapse method. The seventeen probe outcomes surface
//! heterogeneous claim types — `bool` (10 of 17), `usize` (1), `f64` (1),
//! [`tameshi::Blake3Hash`](https://docs.rs/tameshi) (3, but only when the
//! `attestation` feature is on), `Vec<DependencyHash>` (1), `String` (1),
//! `(Blake3Hash, usize, usize)` (1), `Option<&str>` (1, alongside its
//! sibling `bool`) — and a single associated type would either force
//! every consumer through expensive cloning (for the `Vec` and `String`
//! cases), require a lifetime parameter (for the `Option<&str>` case),
//! or push the consumer back to a per-implementor match. The bare-bool
//! `is_probe_absent()` predicate is the largest common shape every
//! implementor admits cheaply, and is sufficient to drive the load-
//! bearing downstream consumer this trait enables — the probe-coverage
//! telemetry summary a follow-up commit will land at the
//! `compose_product_certification` call site.
//!
//! ## What this trait enables
//!
//! The first downstream consumer this trait names structurally is the
//! probe-coverage telemetry signal: given a slice of `&dyn ProbeOutcome`
//! references collected at the attestation composition site, a generic
//! helper can count `(probes_ran, probes_absent)` and emit a
//! `tracing::info!` (or a structural field on the
//! [`ProductCertification`](tameshi)) recording exactly how much of the
//! attestation pipeline produced evidence vs. how much surfaced default
//! claims. The `&dyn ProbeOutcome` object-safety requirement is the
//! reason this trait is intentionally minimal: a single `&self -> bool`
//! method admits the trait-object form without any boxing of a
//! heterogeneous `Claim` type. A future commit that lands the helper
//! will compose against this trait without needing to re-derive the
//! shape per-implementor.
//!
//! ## The macro
//!
//! Every implementor's body is identical:
//! `matches!(self, Self::<absent-variant>)`. The `impl_probe_outcome!`
//! macro factors the boilerplate so each module adds exactly one
//! invocation line:
//!
//! ```ignore
//! crate::impl_probe_outcome!(CosignVerifyOutcome, ProbeAbsent);
//! crate::impl_probe_outcome!(SbomProbeOutcome, Absent);
//! ```
//!
//! The macro takes the type and the absent variant's bare identifier;
//! both `ProbeAbsent` and `Absent` are supported by the shared pattern.
//! A future regression that swapped the match arms inside an implementor
//! is structurally foreclosed: there is one match expression in the
//! macro body, and the absent variant name is the only piece supplied
//! by the caller.

/// Common contract every typed probe outcome in forge's attestation
/// pipeline implements. The single `is_probe_absent` method names the
/// load-bearing structural discriminator the typed-primitive family
/// preserves over the pre-typed bare-literal attestation-call-site
/// code: did a probe actually run, or did the certification function
/// surface a default claim because no evidence was collected?
///
/// Object-safe by construction (one `&self` method returning a `bool`,
/// no generics, no associated types) so a slice of `&dyn ProbeOutcome`
/// references can be collected at the attestation composition site and
/// walked by a generic probe-coverage helper.
#[allow(dead_code)]
pub trait ProbeOutcome {
    /// True iff this outcome represents the "no probe ran / no evidence
    /// collected" world — the structural discriminator the typed
    /// primitive preserves over the pre-typed bare literal.
    ///
    /// Every implementor's body is `matches!(self, Self::<absent>)`;
    /// the [`impl_probe_outcome!`](crate::impl_probe_outcome) macro
    /// generates the impl from the type + absent variant name.
    fn is_probe_absent(&self) -> bool;
}

/// Emit the [`ProbeOutcome`] impl for `$ty` whose absent variant is
/// `$absent_variant` (bare ident — typically `ProbeAbsent` or `Absent`).
///
/// ```ignore
/// crate::impl_probe_outcome!(CosignVerifyOutcome, ProbeAbsent);
/// crate::impl_probe_outcome!(SbomProbeOutcome, Absent);
/// ```
///
/// The macro is the load-bearing carrier of the invariant the trait
/// pins: every implementor's `is_probe_absent` body is identical
/// (`matches!(self, Self::<absent>)`), so a future regression that
/// hand-rolled a divergent impl (e.g. swapped match arms, or returned a
/// hardcoded `false` because the implementor "doesn't have probes") is
/// structurally foreclosed at the call site — there is one expression
/// in the macro body, and the caller supplies only the absent variant
/// name.
#[macro_export]
macro_rules! impl_probe_outcome {
    ($ty:ty, $absent_variant:ident) => {
        impl $crate::probe_outcome::ProbeOutcome for $ty {
            fn is_probe_absent(&self) -> bool {
                matches!(self, Self::$absent_variant)
            }
        }
    };
}

/// Probe-coverage summary: count of probes that ran vs. probes that
/// surfaced an absent default. The Phase 1 / Phase 2 honesty channel a
/// future telemetry consumer at the
/// `commands::attestation::compose_product_certification` call site can
/// emit alongside the composed `ProductCertification` to report exactly
/// how much of the attestation pipeline produced evidence vs. how much
/// flowed through the absent-default path.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeCoverage {
    /// Number of probes whose `is_probe_absent()` returned `false` — the
    /// probe ran and produced evidence.
    pub ran: usize,
    /// Number of probes whose `is_probe_absent()` returned `true` — the
    /// probe was absent, the implementor surfaced its honest default
    /// claim (the load-bearing collapse every typed primitive preserves
    /// over the pre-typed bare literal).
    pub absent: usize,
}

#[allow(dead_code)]
impl ProbeCoverage {
    /// Total number of probes counted. The invariant `ran + absent ==
    /// total` holds by construction; downstream telemetry consumers
    /// derive the evidence-coverage ratio via [`coverage_ratio`].
    ///
    /// Arithmetic is `usize::saturating_add` rather than the panicking
    /// `+` — the load-bearing carrier of the monoid totality claim the
    /// [`Add`](std::ops::Add) impl below names. The post-saturation
    /// state `ProbeCoverage { ran: usize::MAX, absent: usize::MAX }`
    /// (reachable in finite steps via repeated `Add` from any starting
    /// point under a pathological fleet-wide aggregate) returns
    /// `usize::MAX` here rather than panicking in debug or wrapping
    /// silently in release — both arms the unchecked `self.ran +
    /// self.absent` would surface. The three load-bearing telemetry
    /// emission sites
    /// (`commands::attestation::compute_build_attestation`,
    /// `commands::attestation::compute_chart_attestation`, and
    /// `commands::attestation::compose_product_certification`) read
    /// `total()` directly into a `tracing::info!` field, so a panic
    /// here would propagate through the attestation composition site;
    /// the saturating ceiling keeps the telemetry channel alive under
    /// every reachable `ProbeCoverage` value. THEORY §VI.1: the monoid
    /// totality is upheld at every method, not just at `Add` — a
    /// downstream verifier reading `total()` cannot drive a panic the
    /// `Add`-side saturation foreclosed one impl up.
    ///
    /// [`coverage_ratio`]: ProbeCoverage::coverage_ratio
    pub fn total(&self) -> usize {
        self.ran.saturating_add(self.absent)
    }

    /// Fraction of counted probes that produced evidence — `ran as f64 /
    /// total as f64` when `total > 0`, and `0.0` when `total == 0` (the
    /// empty-slice boundary case [`probe_coverage`] returns
    /// `ProbeCoverage { ran: 0, absent: 0 }` for). The structural
    /// distinction between "no probes counted" and "every probe ran but
    /// surfaced an absent default" is preserved at the [`total`] field,
    /// not flattened into the ratio: a consumer that wants to
    /// disambiguate "no probes ran because the slice was empty" from
    /// "no probes ran because every probe surfaced an absent default"
    /// reads `total() == 0` vs. `total() > 0 && coverage_ratio() == 0.0`.
    ///
    /// The bare-f64 surface is the largest common shape the three
    /// load-bearing telemetry emission sites
    /// (`commands::attestation::compose_product_certification`,
    /// `commands::attestation::compute_chart_attestation`, and
    /// `commands::attestation::compute_build_attestation`) cheaply admit
    /// — `tracing`'s `Visit` API records `f64` directly without the
    /// per-emission `unwrap_or` an `Option<f64>` surface would force at
    /// every call site (and without the structurally-divergent sentinel
    /// — `f64::NAN`, `-1.0`, `Empty` — each call site would otherwise
    /// pick). The empty-slice 0.0 collapse documented above is the load-
    /// bearing decision the test suite pins; the structural
    /// disambiguator stays at `total()`.
    ///
    /// Lifts the derivation `ran as f64 / total as f64` from the
    /// downstream verifier the prior docstring gestured at to the
    /// composition site, so the three telemetry events forge emits
    /// surface a uniform `*_probes_coverage_ratio` field a `sekiban`
    /// admission verifier (THEORY §V.4 / §VII.1 honesty channel) /
    /// Prometheus alert rule reads with one field-name pattern across
    /// build / chart / deployment attestation records. THEORY §VI.1:
    /// one oracle — the ratio is derived at one site, not
    /// per-emission-call inlined at each telemetry consumer.
    pub fn coverage_ratio(&self) -> f64 {
        let total = self.total();
        if total == 0 {
            0.0
        } else {
            self.ran as f64 / total as f64
        }
    }

    /// True iff every counted probe ran and produced evidence — `ran > 0
    /// && absent == 0`. The typed discriminator for the strict-production
    /// `sekiban` admission verifier gate (THEORY §VII.1: attestation-
    /// gated deployments are structural, not policy overlays): a downstream
    /// reconciliation that fails-closed unless every probe substantiated
    /// its claim reads one bool here rather than re-deriving
    /// `coverage.ran > 0 && coverage.absent == 0` per call site.
    ///
    /// The four reachable arms of [`ProbeCoverage`] resolve as:
    ///
    /// | `ran` | `absent` | `is_empty()` | `is_fully_covered()` | `coverage_ratio()` |
    /// |-------|----------|--------------|----------------------|--------------------|
    /// | `0`   | `0`      | `true`       | `false`              | `0.0`              |
    /// | `0`   | `N`      | `false`      | `false`              | `0.0`              |
    /// | `M`   | `N`      | `false`      | `false`              | `M/(M+N)`          |
    /// | `M`   | `0`      | `false`      | `true`               | `1.0`              |
    ///
    /// The two-boolean discriminator pair `(is_empty, is_fully_covered)`
    /// is mutually exclusive and structurally disambiguates the
    /// empty-slice boundary (no probes counted) from the all-ran ceiling
    /// (every counted probe produced evidence) — both of which sit at the
    /// edge of `coverage_ratio()`'s range but carry distinct operational
    /// meaning. A downstream verifier that conditioned only on
    /// `coverage_ratio() == 1.0` would silently accept the empty-slice
    /// case (`0.0` is the documented collapse, not `1.0`, but the symmetry
    /// pin matters); conditioning on `is_fully_covered()` instead forces
    /// the verifier through the typed discriminator the empty case cannot
    /// satisfy.
    ///
    /// The four-arm matrix is orthogonal to [`is_saturated`]: every
    /// reachable `ProbeCoverage` value sits at exactly one of the four
    /// arms above, but every arm can independently be saturated
    /// (`ran == usize::MAX || absent == usize::MAX`) or unsaturated
    /// against the saturating monoid arithmetic the `Add` impl below
    /// admits. The saturation flag is the load-bearing trustworthiness
    /// signal a downstream consumer reads alongside `coverage_ratio()`
    /// — at the saturated state `{ran: MAX, absent: MAX}` (reachable
    /// asymptotically via fleet-wide aggregation), the true 0.5 ratio
    /// reads as 1.0 through the f64 division, so a verifier that gated
    /// only on `coverage_ratio() >= 0.9` would silently accept the
    /// post-saturation drift; conditioning on `!is_saturated() &&
    /// coverage_ratio() >= 0.9` instead forecloses that arm at the
    /// typed-primitive surface.
    ///
    /// [`is_saturated`]: ProbeCoverage::is_saturated
    ///
    /// THEORY §VI.1 one-oracle discipline: the predicate is derived at
    /// one site (here), not re-inlined as `coverage.ran > 0 &&
    /// coverage.absent == 0` per consumer. THEORY §V.4 / §VII.1 honesty
    /// channel: the discriminator names "every probe produced evidence,"
    /// the load-bearing precondition the Phase 1 / Phase 2 strict
    /// admission gate fails-closed on.
    pub fn is_fully_covered(&self) -> bool {
        self.ran > 0 && self.absent == 0
    }

    /// True iff zero probes were counted — `total() == 0`. The structural
    /// boundary case [`probe_coverage`] over an empty iterator produces
    /// (the only [`ProbeCoverage`] value with `total() == 0`, since `ran`
    /// and `absent` are both `usize` and non-negative). Distinguishes
    /// "no probes counted" from "every counted probe absent" — both
    /// collapse to `coverage_ratio() == 0.0`, but a downstream verifier
    /// that wants to disambiguate (e.g., to treat the empty-slice case as
    /// a no-op while gating against the all-absent case) reads
    /// [`is_empty`] directly rather than `coverage.total() == 0` at each
    /// call site.
    ///
    /// The structural complement of [`is_fully_covered`]'s edge case: the
    /// two predicates partition the `coverage_ratio == 0.0` /
    /// `coverage_ratio == 1.0` boundary into the four mutually-exclusive
    /// arms tabulated on [`is_fully_covered`]. Mirrors the standard-
    /// collection [`Vec::is_empty`] / [`HashMap::is_empty`] idiom every
    /// pleme-io consumer already reaches for.
    ///
    /// [`is_empty`]: ProbeCoverage::is_empty
    /// [`is_fully_covered`]: ProbeCoverage::is_fully_covered
    /// [`Vec::is_empty`]: std::vec::Vec::is_empty
    /// [`HashMap::is_empty`]: std::collections::HashMap::is_empty
    pub fn is_empty(&self) -> bool {
        self.total() == 0
    }

    /// True iff every counted probe surfaced an absent default — `ran == 0
    /// && absent > 0`. The structural mirror of [`is_fully_covered`]
    /// (`ran > 0 && absent == 0`): both predicates name an extreme arm of
    /// the four-arm matrix the docstring on [`is_fully_covered`]
    /// tabulates, bracketing the empty arm `(ran: 0, absent: 0)` where
    /// neither holds. Names the third arm of the matrix — today's
    /// [`compose_product_certification`] / [`compute_chart_attestation`]
    /// / [`compute_build_attestation`] call-site state (every typed
    /// outcome bound at its `ProbeAbsent` / `Absent` arm, so every
    /// counted probe surfaced the honest default claim the typed
    /// primitive preserves over the pre-typed bare literal).
    ///
    /// The compounding shape: before this predicate, a downstream
    /// `sekiban` admission verifier wanting to reject "every counted
    /// probe absent" (the operational state forge's call sites sit at
    /// today — the strict-production gate fails closed on it) had to
    /// compose `!coverage.is_empty() && coverage.coverage_ratio() == 0.0`
    /// at the consumer surface, mixing the float-form ratio's
    /// IEEE-754-imprecise equality comparison with the boundary-case
    /// predicate. After this predicate, the verifier reads one bool —
    /// `coverage.is_all_absent()` — and the integer-arithmetic body
    /// `ran == 0 && absent > 0` forecloses the float-comparison drift
    /// class the consumer-side composition would inherit.
    ///
    /// The four reachable arms of the matrix resolve cleanly under the
    /// three named predicates: `is_empty()` flags the empty arm,
    /// `is_all_absent()` flags the all-absent arm, `is_fully_covered()`
    /// flags the fully-covered arm, and the mixed arm is the negation of
    /// all three (`!is_empty() && !is_all_absent() && !is_fully_covered()`).
    /// The four predicates are mutually exclusive and jointly exhaustive
    /// (`is_empty + is_all_absent + is_fully_covered + mixed == 1` for
    /// every reachable [`ProbeCoverage`] value).
    ///
    /// Orthogonal to [`is_saturated`]: the all-absent arm at `(ran: 0,
    /// absent: usize::MAX)` is both `is_all_absent() == true` AND
    /// `is_saturated() == true`. The predicate stays saturation-robust
    /// (the load-bearing tests are `ran == 0` and `absent > 0`, not
    /// arithmetic on the sum) so a downstream verifier reading
    /// `is_all_absent()` against the saturated state cannot drift the
    /// way `coverage_ratio() == 0.0` would (which reads as `1.0` at
    /// `{ran: MAX, absent: MAX}` against the true 0.5 ratio).
    ///
    /// [`compose_product_certification`]: crate::commands::attestation::compose_product_certification
    /// [`compute_build_attestation`]: crate::commands::attestation::compute_build_attestation
    /// [`compute_chart_attestation`]: crate::commands::attestation::compute_chart_attestation
    /// [`is_fully_covered`]: ProbeCoverage::is_fully_covered
    /// [`is_saturated`]: ProbeCoverage::is_saturated
    ///
    /// THEORY §VI.1 one-oracle discipline: the predicate is derived at
    /// one site (here), not re-inlined as `!coverage.is_empty() &&
    /// coverage.coverage_ratio() == 0.0` per consumer (which would
    /// inherit the IEEE-754 imprecision the float-equality comparison
    /// admits at the saturated state). THEORY §V.4 / §VII.1 honesty
    /// channel: the discriminator names "every counted probe surfaced
    /// the honest default claim," the load-bearing precondition the
    /// Phase 1 / Phase 2 strict admission gate fails-closed on at
    /// today's call-site state.
    pub fn is_all_absent(&self) -> bool {
        self.ran == 0 && self.absent > 0
    }

    /// True iff at least one component has reached the saturating-add
    /// ceiling — `ran == usize::MAX || absent == usize::MAX`. The
    /// orthogonal boundary discriminator the saturating monoid arithmetic
    /// the [`Add`](std::ops::Add) impl below admits produces under a
    /// pathological fleet-wide aggregate: the `Add` clamp the `ran.
    /// saturating_add(rhs.ran)` / `absent.saturating_add(rhs.absent)`
    /// surfaces drops every increment past `usize::MAX`, so a component
    /// at the ceiling no longer carries the true count it once stood
    /// for. Downstream [`total`] and [`coverage_ratio`] derive from the
    /// post-clamp components, so the float-division `ran as f64 / total
    /// as f64` at the saturated state collapses against the true ratio
    /// — the regression `test_coverage_ratio_does_not_panic_at_
    /// saturated_state` already pins (the `{ran: MAX, absent: MAX}`
    /// true-ratio 0.5 reads as 1.0 through the saturated `f64` divison).
    /// `is_saturated` is the typed-primitive flag a downstream `sekiban`
    /// admission verifier reads to know the derived ratio is unreliable
    /// — when `true`, the verifier falls back on the saturation-robust
    /// [`is_fully_covered`] (`absent == 0` is the load-bearing test, not
    /// arithmetic on the sum) and [`is_empty`] (`total() == 0` is the
    /// load-bearing test, false at every saturated state since both
    /// components are non-negative and at least one is `usize::MAX`)
    /// discriminators.
    ///
    /// Orthogonal to the four-arm matrix the docstring on
    /// [`is_fully_covered`] tabulates: every reachable `ProbeCoverage`
    /// value sits at exactly one arm of `(is_empty, is_fully_covered,
    /// mixed, all_absent)`, but every arm can independently be
    /// saturated or unsaturated. The empty arm `{ran: 0, absent: 0}` is
    /// the only arm that is structurally unsaturated (both components
    /// are 0, neither at `usize::MAX`); the three non-empty arms each
    /// admit both a saturated and an unsaturated representative. The
    /// telemetry contract (`*_probes_saturated` field a future
    /// `emit_probe_coverage!` extension emits) reflects this
    /// orthogonality: the field is `false` for every realistically-sized
    /// fleet aggregate (the saturating ceiling is `1 << 64` records on a
    /// 64-bit target — unreachable in practice but structurally
    /// foreclosed by the saturating arithmetic the monoid uses).
    ///
    /// THEORY.md §VI.1 one-oracle discipline: the saturation predicate
    /// is derived at one site (here), not re-inlined as `coverage.ran
    /// == usize::MAX || coverage.absent == usize::MAX` per downstream
    /// telemetry consumer. THEORY.md §V.4 / §VII.1: the honesty channel
    /// surfaces both the coverage ratio AND its trustworthiness — a
    /// downstream verifier that gated only on `coverage_ratio() >= 0.9`
    /// would silently accept the `{MAX, MAX}` post-saturation state
    /// (true 0.5 ratio reading as 1.0); gating on `!is_saturated() &&
    /// coverage_ratio() >= 0.9` instead forecloses that drift class at
    /// the typed-primitive surface.
    ///
    /// [`coverage_ratio`]: ProbeCoverage::coverage_ratio
    /// [`is_empty`]: ProbeCoverage::is_empty
    /// [`is_fully_covered`]: ProbeCoverage::is_fully_covered
    /// [`total`]: ProbeCoverage::total
    pub fn is_saturated(&self) -> bool {
        self.ran == usize::MAX || self.absent == usize::MAX
    }

    /// Coverage fraction as an integer percent in `0..=100`. Returns `0`
    /// for the empty-slice boundary case (`total() == 0`), and
    /// `(ran * 100) / total()` (Euclidean floor) for every reachable
    /// non-empty value. The companion of [`coverage_ratio`]: the float
    /// surface is the largest common shape every `tracing::Visit::record_
    /// f64` consumer admits cheaply, the integer surface is the largest
    /// common shape every Prometheus `*_probe_coverage_ratio_pct > 90`
    /// alert rule / typed-policy threshold gate admits cheaply (integer
    /// arithmetic against an integer threshold, no IEEE-754 epsilon
    /// drift at the decision boundary `>= 0.9` floats imprecisely
    /// surface — `0.9_f64` is `0.8999...` under the binary fraction, so
    /// a fleet-wide aggregator summing per-record ratios across N records
    /// reads N`*0.9_f64` against an `N*0.9_f64 + epsilon` threshold and
    /// may admit or reject the same evidence depending on N).
    ///
    /// Routes through `u128` arithmetic to foreclose overflow at the
    /// `ran * 100` multiplication — `usize::MAX * 100` overflows `u128`
    /// only at `u128::MAX / 100 ≈ 3.4e36 / 100 ≈ 3.4e34`, well above
    /// the `usize::MAX ≈ 1.8e19` (64-bit) reach of the saturating
    /// monoid `Add`, so the integer arithmetic is total over every
    /// reachable `ProbeCoverage` value. The post-saturation state
    /// `{ran: MAX, absent: MAX}` reads `100` here (the true 0.5 ratio
    /// is dropped past the saturating clamp, same drift as
    /// [`coverage_ratio`]'s float reading of 1.0); the orthogonal
    /// [`is_saturated`] flag is the load-bearing trustworthiness
    /// signal a downstream verifier reads alongside this field to
    /// gate on `!is_saturated() && coverage_ratio_pct() >= 90` against
    /// the post-saturation drift.
    ///
    /// The cast to `u8` is structurally lossless: the quotient
    /// `(ran * 100) / total <= 100` by construction (`ran <= total`
    /// since `total = ran + absent` componentwise), so the result
    /// always fits in `u8`. A regression that hand-rolled the body with
    /// `* 100` BEFORE the division (the post-overflow form
    /// `(self.ran * 100) / self.total()` in `usize` arithmetic) would
    /// panic at any `ran > usize::MAX / 100` in debug and silently
    /// wrap in release — both arms closed at the `u128` cast.
    ///
    /// THEORY §VI.1 one-oracle discipline: the percent form is derived
    /// at one site (here), not re-inlined as
    /// `(coverage.ran as f64 / coverage.total() as f64 * 100.0) as
    /// u8` per consumer (which would inherit the float-imprecision
    /// drift at the `0.9_f64` boundary). THEORY §V.4 / §VII.1: the
    /// honesty channel surfaces both the float and the integer ratio
    /// forms — a downstream verifier reads whichever shape its
    /// admission gate's threshold representation aligns with, without
    /// re-deriving the conversion at the consumer surface.
    ///
    /// [`coverage_ratio`]: ProbeCoverage::coverage_ratio
    /// [`is_saturated`]: ProbeCoverage::is_saturated
    pub fn coverage_ratio_pct(&self) -> u8 {
        let total = self.total();
        if total == 0 {
            return 0;
        }
        let ran = self.ran as u128;
        let total = total as u128;
        ((ran * 100) / total) as u8
    }
}

/// Identity element of the [`Add`](std::ops::Add) impl below: the empty-
/// slice [`probe_coverage`] result, the zero value every [`Sum`] fold
/// starts from. Pins `ProbeCoverage::default() == ProbeCoverage { ran: 0,
/// absent: 0 }` structurally so a downstream verifier reading a
/// fleet-wide aggregate via `.iter().sum::<ProbeCoverage>()` cannot drift
/// against the empty-slice boundary case [`probe_coverage`] already
/// returns for the same shape.
impl Default for ProbeCoverage {
    fn default() -> Self {
        Self { ran: 0, absent: 0 }
    }
}

/// Componentwise `usize::saturating_add` over [`ProbeCoverage`] —
/// `(a.ran + b.ran, a.absent + b.absent)`. The structural monoid
/// `(ProbeCoverage, +, default())` lifts the per-phase coverage every
/// `*_probe_coverage` helper at `commands::attestation` produces (the
/// Phase 1 build / Phase 1 chart / Phase 2 deployment shape) to a single
/// product-level signal a future emission site can compose with
/// `[build, chart, deployment].iter().copied().sum::<ProbeCoverage>()`
/// — one site, not per-field-summed at every downstream verifier (THEORY
/// §VI.1 one-oracle discipline).
///
/// `saturating_add` rather than the panicking `+` is the load-bearing
/// arithmetic: a fleet-wide aggregator summing the per-record coverage
/// across every Phase 1 / Phase 2 attestation forge composes
/// (multi-product, multi-cluster, multi-environment) cannot panic on
/// overflow at `usize::MAX` — the saturating ceiling preserves the
/// monoid's totality (every pair of `ProbeCoverage` values has a defined
/// sum) where the unchecked addition would surface a panic on the
/// pathological aggregate (1 << 64 probe records on a 64-bit target,
/// realistically unreachable but structurally foreclosed here).
impl std::ops::Add for ProbeCoverage {
    type Output = ProbeCoverage;

    fn add(self, rhs: Self) -> Self::Output {
        ProbeCoverage {
            ran: self.ran.saturating_add(rhs.ran),
            absent: self.absent.saturating_add(rhs.absent),
        }
    }
}

/// In-place sibling of [`Add`](std::ops::Add) above. The `*self = *self +
/// rhs` body reuses the `Copy` derive on [`ProbeCoverage`] (the type is
/// two `usize`s — trivially copyable) so the assign form is a one-line
/// delegation that cannot drift from the `Add` semantics.
impl std::ops::AddAssign for ProbeCoverage {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

/// Owned-iterator [`Sum`] impl: `iter.fold(default(), Add::add)`. Lifts
/// a `Vec<ProbeCoverage>` / `[ProbeCoverage; N]` / `impl Iterator<Item =
/// ProbeCoverage>` to a single aggregate value the downstream telemetry
/// emission site can hand to `tracing::info!` alongside the per-phase
/// fields. The empty-iterator case returns [`ProbeCoverage::default`] (0
/// ran, 0 absent) — the same empty-slice boundary `probe_coverage`
/// returns, so the two surfaces compose without a structural seam.
impl std::iter::Sum for ProbeCoverage {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::default(), std::ops::Add::add)
    }
}

/// Borrowed-iterator [`Sum`] impl: lets a `&[ProbeCoverage]` borrow
/// reach `.iter().sum::<ProbeCoverage>()` without an explicit `.copied()`
/// at the call site — the idiomatic shape every other numeric `Sum` in
/// `std` already admits (`<i64 as Sum<&'a i64>>` etc.). The delegation
/// through `.copied()` reuses the `Copy` derive on [`ProbeCoverage`] so
/// the borrowed form cannot drift from the owned `Sum` semantics one
/// impl up.
impl<'a> std::iter::Sum<&'a ProbeCoverage> for ProbeCoverage {
    fn sum<I: Iterator<Item = &'a ProbeCoverage>>(iter: I) -> Self {
        iter.copied().sum()
    }
}

/// Walk a slice of `&dyn ProbeOutcome` references and compute the
/// probe-coverage summary — the count of probes that ran vs. the count
/// of probes that surfaced an absent default. Linear in the slice
/// length, no allocation.
///
/// Intended as the first generic consumer of the [`ProbeOutcome`] trait:
/// a future commit at the attestation composition site can collect the
/// seventeen typed-outcome bindings into a `&[&dyn ProbeOutcome]` array
/// and emit the resulting `ProbeCoverage` as a telemetry signal alongside
/// the composed `ProductCertification`, surfacing the Phase 1 / Phase 2
/// evidence-vs-default ratio every prior typed-primitive commit's
/// "Lift-to-pleme-actions candidate" note gestures at.
#[allow(dead_code)]
pub fn probe_coverage<'a, I>(outcomes: I) -> ProbeCoverage
where
    I: IntoIterator<Item = &'a dyn ProbeOutcome>,
{
    let mut ran = 0usize;
    let mut absent = 0usize;
    for outcome in outcomes {
        if outcome.is_probe_absent() {
            absent += 1;
        } else {
            ran += 1;
        }
    }
    ProbeCoverage { ran, absent }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A dummy typed probe outcome used as the test fixture for the
    /// trait + macro. Mirrors the two-arm `Probed` / `ProbeAbsent` shape
    /// the [`crate::pod_listing::PodListingOutcome`] /
    /// [`crate::cis_k8s_pass_rate::CisK8sPassRateOutcome`] family carries,
    /// without depending on the (feature-gated) attestation modules.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum DummyOutcome {
        Probed,
        ProbeAbsent,
    }
    crate::impl_probe_outcome!(DummyOutcome, ProbeAbsent);

    /// A second dummy with the `Absent` (not `ProbeAbsent`) variant name
    /// — exercises the macro against the alternative naming used by the
    /// [`crate::security_scan`] and [`crate::oci_architecture`] modules.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum DummyAbsentOutcome {
        Collected,
        Absent,
    }
    crate::impl_probe_outcome!(DummyAbsentOutcome, Absent);

    /// Pin the load-bearing trait invariant: the absent variant
    /// identifies as absent, and every other variant identifies as
    /// not-absent. This is THE structural discriminator the typed
    /// primitive family exists to preserve — a future regression that
    /// hand-rolled an `is_probe_absent` returning a hardcoded `false`
    /// (because some implementor "doesn't have probes") would fail this
    /// pin against any sibling implementor.
    #[test]
    fn test_is_probe_absent_pins_absent_variant() {
        assert!(DummyOutcome::ProbeAbsent.is_probe_absent());
        assert!(!DummyOutcome::Probed.is_probe_absent());
    }

    /// The macro supports the alternative `Absent` variant name —
    /// exercises the `security_scan` / `oci_architecture` naming
    /// convention. A future regression that hard-coded `ProbeAbsent` in
    /// the macro body would fail this pin.
    #[test]
    fn test_macro_accepts_absent_variant_name() {
        assert!(DummyAbsentOutcome::Absent.is_probe_absent());
        assert!(!DummyAbsentOutcome::Collected.is_probe_absent());
    }

    /// `probe_coverage` over an empty slice returns `ProbeCoverage { ran:
    /// 0, absent: 0 }`. The boundary case the helper must handle without
    /// a panic or a `1`-off — the attestation composition site may
    /// surface zero probes during integration-test paths.
    #[test]
    fn test_probe_coverage_empty_slice() {
        let outcomes: [&dyn ProbeOutcome; 0] = [];
        let coverage = probe_coverage(outcomes.iter().copied());
        assert_eq!(coverage, ProbeCoverage { ran: 0, absent: 0 });
        assert_eq!(coverage.total(), 0);
    }

    /// `probe_coverage` counts the ran vs. absent split correctly across
    /// a heterogeneous slice that mixes both dummy outcomes through the
    /// `&dyn ProbeOutcome` trait-object form — pins that the trait is
    /// object-safe AND that the helper walks the trait-object surface
    /// without depending on the concrete implementor type.
    #[test]
    fn test_probe_coverage_mixed_slice() {
        let probed = DummyOutcome::Probed;
        let probe_absent = DummyOutcome::ProbeAbsent;
        let collected = DummyAbsentOutcome::Collected;
        let absent = DummyAbsentOutcome::Absent;
        let outcomes: [&dyn ProbeOutcome; 4] = [&probed, &probe_absent, &collected, &absent];
        let coverage = probe_coverage(outcomes.iter().copied());
        assert_eq!(coverage, ProbeCoverage { ran: 2, absent: 2 });
        assert_eq!(coverage.total(), 4);
    }

    /// `probe_coverage` counts `ProbeCoverage { ran: N, absent: 0 }` when
    /// every outcome surfaces evidence — the all-probes-ran ceiling
    /// every Phase 1 / Phase 2 telemetry consumer can compare against
    /// the ideal of 100% probe coverage.
    #[test]
    fn test_probe_coverage_all_ran() {
        let a = DummyOutcome::Probed;
        let b = DummyOutcome::Probed;
        let c = DummyAbsentOutcome::Collected;
        let outcomes: [&dyn ProbeOutcome; 3] = [&a, &b, &c];
        let coverage = probe_coverage(outcomes.iter().copied());
        assert_eq!(coverage, ProbeCoverage { ran: 3, absent: 0 });
    }

    /// `probe_coverage` counts `ProbeCoverage { ran: 0, absent: N }`
    /// when every outcome surfaces an absent default — the all-probes-
    /// absent floor the integration-test paths exercise (no probes
    /// spawned, every typed primitive constructed in its `Absent` /
    /// `ProbeAbsent` form). The current
    /// `compose_product_certification` call site sits at exactly this
    /// floor for the seventeen typed outcomes the prior commits closed.
    #[test]
    fn test_probe_coverage_all_absent() {
        let a = DummyOutcome::ProbeAbsent;
        let b = DummyOutcome::ProbeAbsent;
        let c = DummyAbsentOutcome::Absent;
        let outcomes: [&dyn ProbeOutcome; 3] = [&a, &b, &c];
        let coverage = probe_coverage(outcomes.iter().copied());
        assert_eq!(coverage, ProbeCoverage { ran: 0, absent: 3 });
    }

    /// `coverage_ratio` returns `0.0` for the empty-slice boundary case
    /// `probe_coverage` over an empty iterator produces. The structural
    /// distinction between "no probes counted" and "every probe absent"
    /// is preserved at `total()` (which returns `0` here vs. `N` for the
    /// all-absent floor), not flattened into the ratio. A future
    /// regression that hand-rolled the division without guarding the
    /// `total == 0` denominator would emit `f64::NAN` and fail this pin,
    /// surfacing the boundary case at the typed-primitive site rather
    /// than at the tracing-field emission downstream.
    #[test]
    fn test_coverage_ratio_empty_returns_zero() {
        let coverage = ProbeCoverage { ran: 0, absent: 0 };
        assert_eq!(coverage.total(), 0);
        assert_eq!(coverage.coverage_ratio(), 0.0);
    }

    /// `coverage_ratio` returns `1.0` when every counted probe ran —
    /// the all-probes-ran ceiling the
    /// `*_probe_coverage_all_ran_ceiling` siblings at
    /// `commands::attestation` pin against the typed-primitive floors.
    /// Pinned across the three load-bearing total counts (3 for build,
    /// 4 for chart, 7 for deployment) so a future regression that
    /// hardcoded the denominator to one specific total would fail
    /// against the other two.
    #[test]
    fn test_coverage_ratio_all_ran_is_one() {
        assert_eq!(ProbeCoverage { ran: 3, absent: 0 }.coverage_ratio(), 1.0);
        assert_eq!(ProbeCoverage { ran: 4, absent: 0 }.coverage_ratio(), 1.0);
        assert_eq!(ProbeCoverage { ran: 7, absent: 0 }.coverage_ratio(), 1.0);
    }

    /// `coverage_ratio` returns `0.0` when every counted probe surfaced
    /// an absent default — the all-probes-absent floor today's
    /// `compose_product_certification` / `compute_chart_attestation` /
    /// `compute_build_attestation` call-site state sits at. The
    /// structural disambiguator from the empty-slice case is `total() >
    /// 0` here vs. `total() == 0` for the empty boundary; both produce
    /// `coverage_ratio() == 0.0` but a consumer can recover the kind-
    /// of-claim from the `total` field.
    #[test]
    fn test_coverage_ratio_all_absent_is_zero() {
        let coverage = ProbeCoverage { ran: 0, absent: 7 };
        assert_eq!(coverage.total(), 7);
        assert_eq!(coverage.coverage_ratio(), 0.0);
    }

    /// `coverage_ratio` returns the arithmetic fraction for the mixed
    /// arm-split — the realistic Phase 2 deployment-attestation
    /// three-of-seven shape `test_deployment_probe_coverage_mixed_arms_
    /// arithmetic` exercises one layer over, plus the half-and-half
    /// (1, 1) corner case the rational `0.5` pins exactly under IEEE-754
    /// (no floating-point rounding to chase). A regression that swapped
    /// `ran` and `absent` in the numerator would flip `3/7` to `4/7`
    /// and fail this pin.
    #[test]
    fn test_coverage_ratio_mixed_split_arithmetic() {
        assert_eq!(ProbeCoverage { ran: 1, absent: 1 }.coverage_ratio(), 0.5);
        assert_eq!(
            ProbeCoverage { ran: 3, absent: 4 }.coverage_ratio(),
            3.0 / 7.0
        );
        assert_eq!(
            ProbeCoverage { ran: 2, absent: 1 }.coverage_ratio(),
            2.0 / 3.0
        );
    }

    /// `coverage_ratio` is deterministic — repeated calls on the same
    /// `ProbeCoverage` value return bit-identical `f64`s. Pins that the
    /// method is a pure function of `ran` / `absent` with no hidden
    /// state (e.g. a stray `rand` or a cached interior-mutable field),
    /// the load-bearing invariant a downstream `sekiban` admission
    /// verifier reconciliation depends on when comparing two telemetry
    /// emissions of the same `ProbeCoverage` for equality.
    #[test]
    fn test_coverage_ratio_is_deterministic() {
        let coverage = ProbeCoverage { ran: 3, absent: 4 };
        let first = coverage.coverage_ratio();
        let second = coverage.coverage_ratio();
        assert_eq!(first.to_bits(), second.to_bits());
    }

    /// `ProbeCoverage::default()` returns the empty-slice
    /// `probe_coverage` shape — `ran: 0, absent: 0` — so the two
    /// surfaces compose without a structural seam. The
    /// `Sum::sum`-over-empty-iterator case below depends on this
    /// identity; a future regression that hand-rolled a default with a
    /// non-zero `absent` field would silently inflate every Phase 1 /
    /// Phase 2 fleet-wide aggregate by that constant.
    #[test]
    fn test_default_is_empty_probe_coverage() {
        assert_eq!(
            ProbeCoverage::default(),
            ProbeCoverage { ran: 0, absent: 0 }
        );
        let empty: [&dyn ProbeOutcome; 0] = [];
        assert_eq!(
            probe_coverage(empty.iter().copied()),
            ProbeCoverage::default()
        );
    }

    /// `Add` composes componentwise — `(a.ran + b.ran, a.absent +
    /// b.absent)` — and `total()` adds the same way (5 = 3 + 2; 3 = 1 +
    /// 2). The realistic Phase-1-build / Phase-1-chart / Phase-2-
    /// deployment fold a future product-level signal will run at the
    /// `compose_product_certification` call site: three per-record
    /// coverages summed into one product-record aggregate. A future
    /// regression that swapped `ran` / `absent` in the impl body would
    /// flip a high-evidence product record into a fully-absent one;
    /// this pin closes that arm.
    #[test]
    fn test_add_composes_componentwise() {
        let build = ProbeCoverage { ran: 3, absent: 0 };
        let chart = ProbeCoverage { ran: 1, absent: 3 };
        let deployment = ProbeCoverage { ran: 0, absent: 7 };
        let product = build + chart + deployment;
        assert_eq!(product, ProbeCoverage { ran: 4, absent: 10 });
        assert_eq!(product.total(), 14);
    }

    /// `Default` is the identity of `Add` — `c + default() == c` and
    /// `default() + c == c` for every `c`. The monoid law THEORY §VI.1
    /// one-oracle discipline depends on: a downstream verifier reading
    /// `product = phases.iter().sum::<ProbeCoverage>()` cannot drift
    /// from `product = phases[0] + phases[1] + ...` because the empty-
    /// fold seed is `default()` and `default()` is structurally the
    /// identity. A future regression that returned a non-zero default
    /// (e.g., `{ran: 1, absent: 0}` as a "probably ran" stub) would
    /// fail this pin at both arms.
    #[test]
    fn test_add_default_is_identity() {
        let c = ProbeCoverage { ran: 3, absent: 4 };
        assert_eq!(c + ProbeCoverage::default(), c);
        assert_eq!(ProbeCoverage::default() + c, c);
    }

    /// `Add` is commutative and associative — the structural monoid
    /// laws that make `[a, b, c].iter().sum::<ProbeCoverage>()`
    /// independent of iteration order. A fleet-wide aggregator that
    /// folds across an unordered set of per-record coverages (a
    /// `HashMap<ProductId, ProbeCoverage>::values()` walk, for
    /// example) reads the same aggregate regardless of hash-map
    /// iteration order; this pin closes the "Add silently depends on
    /// argument order" regression arm.
    #[test]
    fn test_add_is_commutative_and_associative() {
        let a = ProbeCoverage { ran: 3, absent: 0 };
        let b = ProbeCoverage { ran: 1, absent: 3 };
        let c = ProbeCoverage { ran: 0, absent: 7 };
        assert_eq!(a + b, b + a);
        assert_eq!((a + b) + c, a + (b + c));
    }

    /// `Add` saturates at `usize::MAX` rather than panicking on
    /// overflow — the load-bearing arithmetic the docstring above
    /// names. A fleet-wide aggregator summing across pathologically
    /// many per-record coverages (1 << 64 probe records on a 64-bit
    /// target, unreachable in practice but structurally foreclosed
    /// here) cannot drive a panic the unchecked `+` would surface;
    /// the monoid stays total over the full `usize` range.
    #[test]
    fn test_add_saturates_at_usize_max() {
        let max = ProbeCoverage {
            ran: usize::MAX,
            absent: usize::MAX,
        };
        let plus_one = ProbeCoverage { ran: 1, absent: 1 };
        assert_eq!(
            max + plus_one,
            ProbeCoverage {
                ran: usize::MAX,
                absent: usize::MAX,
            }
        );
    }

    /// `AddAssign` is the in-place sibling of `Add` and produces the
    /// same value. A future regression that decoupled the two impls
    /// (e.g., reimplemented `add_assign` directly with a different
    /// arithmetic) would fail this pin. The `*self = *self + rhs`
    /// delegation in the impl body relies on the `Copy` derive on
    /// `ProbeCoverage`; this test exercises the round-trip.
    #[test]
    fn test_add_assign_matches_add() {
        let mut acc = ProbeCoverage { ran: 3, absent: 0 };
        acc += ProbeCoverage { ran: 1, absent: 3 };
        acc += ProbeCoverage { ran: 0, absent: 7 };
        assert_eq!(acc, ProbeCoverage { ran: 4, absent: 10 });
    }

    /// `Sum` over an owned iterator folds with `Add` from `default()`.
    /// The realistic call-site shape a future product-level emission
    /// will use: collect per-phase coverages into a `Vec` (or an
    /// inline array), call `.into_iter().sum::<ProbeCoverage>()`, emit
    /// the aggregate as `product_probes_coverage_ratio`. Equivalent
    /// to the explicit `a + b + c` fold one assertion up — this pin
    /// closes the "Sum drifts from Add" regression arm.
    #[test]
    fn test_sum_owned_iterator_folds_with_add() {
        let phases = vec![
            ProbeCoverage { ran: 3, absent: 0 },
            ProbeCoverage { ran: 1, absent: 3 },
            ProbeCoverage { ran: 0, absent: 7 },
        ];
        let product: ProbeCoverage = phases.into_iter().sum();
        assert_eq!(product, ProbeCoverage { ran: 4, absent: 10 });
        assert_eq!(product.total(), 14);
    }

    /// `Sum` over a borrowed iterator (`.iter().sum::<ProbeCoverage>()`
    /// — no `.copied()` at the call site) returns the same aggregate as
    /// the owned form. The borrowed `Sum<&'a Self>` impl exists so
    /// `&[ProbeCoverage]` reaches the idiomatic numeric-`Sum` shape
    /// every `<i64 as Sum<&'a i64>>`-style impl in `std` already
    /// admits; a future regression that diverged the two surfaces
    /// would fail this pin.
    #[test]
    fn test_sum_borrowed_iterator_matches_owned() {
        let phases = [
            ProbeCoverage { ran: 3, absent: 0 },
            ProbeCoverage { ran: 1, absent: 3 },
            ProbeCoverage { ran: 0, absent: 7 },
        ];
        let borrowed: ProbeCoverage = phases.iter().sum();
        let owned: ProbeCoverage = phases.into_iter().sum();
        assert_eq!(borrowed, owned);
        assert_eq!(borrowed, ProbeCoverage { ran: 4, absent: 10 });
    }

    /// `Sum` over an empty iterator returns `default()` — the identity
    /// of the monoid. Symmetric to `test_probe_coverage_empty_slice`
    /// one layer over: the empty-slice trait-object walk and the
    /// empty-`Vec`-of-coverages fold produce the same `ProbeCoverage
    /// { ran: 0, absent: 0 }` value, so the two surfaces compose
    /// without a structural seam at the empty-input boundary.
    #[test]
    fn test_sum_empty_iterator_is_default() {
        let empty: Vec<ProbeCoverage> = Vec::new();
        let aggregate: ProbeCoverage = empty.into_iter().sum();
        assert_eq!(aggregate, ProbeCoverage::default());
        assert_eq!(aggregate.total(), 0);
    }

    /// `total()` saturates at `usize::MAX` rather than panicking on
    /// overflow — the load-bearing arithmetic the docstring on
    /// [`ProbeCoverage::total`] names. The post-saturation state
    /// `{ran: usize::MAX, absent: usize::MAX}` is reachable in finite
    /// steps via the monoid `Add` (the sibling
    /// `test_add_saturates_at_usize_max` pin proves it), so a `total()`
    /// implementation routed through the unchecked `self.ran +
    /// self.absent` would panic in debug (and silently wrap in release)
    /// at exactly this value — defeating the totality claim the
    /// `Add`-side saturation upholds one impl up. The three load-
    /// bearing telemetry emission sites (`compute_build_attestation`,
    /// `compute_chart_attestation`, `compose_product_certification`)
    /// emit `total()` directly into a `tracing::info!` field, so a
    /// panic here would propagate through the attestation composition
    /// site; this pin closes that arm at the typed-primitive surface.
    #[test]
    fn test_total_saturates_at_usize_max() {
        let saturated = ProbeCoverage {
            ran: usize::MAX,
            absent: usize::MAX,
        };
        assert_eq!(saturated.total(), usize::MAX);
    }

    /// `is_fully_covered()` returns `true` iff every counted probe ran
    /// and produced evidence — `ran > 0 && absent == 0`. Pinned across
    /// the three load-bearing total counts (3 for build, 4 for chart, 7
    /// for deployment) so a future regression that hardcoded the absent-
    /// count check to one specific N would fail against the other two.
    /// The typed discriminator a downstream `sekiban` strict-production
    /// admission verifier reads — the empty-slice boundary (`ran: 0,
    /// absent: 0`) does NOT satisfy this predicate even though
    /// `coverage_ratio() == 0.0`, structurally separating the two arms
    /// `coverage_ratio` alone collapses (the test_is_fully_covered_
    /// empty_returns_false sibling pin closes that arm).
    #[test]
    fn test_is_fully_covered_all_ran_is_true() {
        assert!(ProbeCoverage { ran: 3, absent: 0 }.is_fully_covered());
        assert!(ProbeCoverage { ran: 4, absent: 0 }.is_fully_covered());
        assert!(ProbeCoverage { ran: 7, absent: 0 }.is_fully_covered());
    }

    /// `is_fully_covered()` returns `false` for the empty-slice boundary
    /// case `probe_coverage` over an empty iterator produces (`ran: 0,
    /// absent: 0`). The structural discriminator from the all-ran ceiling
    /// arm one pin up: both produce `coverage_ratio() == 0.0` (the empty
    /// case via the `total == 0` guard, the all-absent case via the `0/N`
    /// arm — see test_coverage_ratio_all_absent_is_zero), but the empty
    /// case must not satisfy `is_fully_covered`. A future regression that
    /// relaxed the predicate to `absent == 0` alone (dropping the `ran >
    /// 0` conjunct) would silently flip the empty case to `true` and pass
    /// the strict-production gate vacuously; this pin closes that arm.
    #[test]
    fn test_is_fully_covered_empty_returns_false() {
        let empty = ProbeCoverage { ran: 0, absent: 0 };
        assert!(!empty.is_fully_covered());
        assert_eq!(empty.coverage_ratio(), 0.0);
    }

    /// `is_fully_covered()` returns `false` when any counted probe
    /// surfaced an absent default — the all-probes-absent floor today's
    /// `compose_product_certification` / `compute_chart_attestation` /
    /// `compute_build_attestation` call-site state sits at (every typed
    /// outcome bound at the `ProbeAbsent` arm), and the mixed-arm
    /// intermediate state a follow-up that wires a real probe at one of
    /// the seven Phase 2 sites will produce. Pinned across the all-absent
    /// floor and three realistic mixed-split shapes (1-of-2, 3-of-7,
    /// 2-of-3) so a future regression that hardcoded the predicate to one
    /// specific `absent` value would fail across the others.
    #[test]
    fn test_is_fully_covered_any_absent_is_false() {
        assert!(!ProbeCoverage { ran: 0, absent: 7 }.is_fully_covered());
        assert!(!ProbeCoverage { ran: 1, absent: 1 }.is_fully_covered());
        assert!(!ProbeCoverage { ran: 3, absent: 4 }.is_fully_covered());
        assert!(!ProbeCoverage { ran: 2, absent: 1 }.is_fully_covered());
    }

    /// `is_fully_covered()` composes with the monoid `Add` shape exactly
    /// the way a downstream fleet-wide aggregator depends on: summing a
    /// fully-covered Phase 1 build coverage with an any-absent Phase 1
    /// chart coverage produces an any-absent aggregate (one absent
    /// probe in any phase poisons the strict-production gate). Mirrors
    /// the structural intuition: a product certification is fully covered
    /// only when every phase is fully covered.
    #[test]
    fn test_is_fully_covered_sums_under_monoid_add() {
        let build = ProbeCoverage { ran: 3, absent: 0 };
        let chart = ProbeCoverage { ran: 1, absent: 3 };
        let deployment_fully_covered = ProbeCoverage { ran: 7, absent: 0 };
        assert!(build.is_fully_covered());
        assert!(!chart.is_fully_covered());
        assert!(deployment_fully_covered.is_fully_covered());
        assert!(!(build + chart).is_fully_covered());
        assert!((build + deployment_fully_covered).is_fully_covered());
        assert!(!(build + chart + deployment_fully_covered).is_fully_covered());
    }

    /// `is_empty()` returns `true` for the empty-slice boundary case
    /// `probe_coverage` over an empty iterator produces (`ran: 0, absent:
    /// 0`), and `false` for every reachable non-empty `ProbeCoverage`
    /// value. The structural disambiguator a downstream verifier reads to
    /// separate "no probes counted" from "every probe absent" — both
    /// collapse to `coverage_ratio() == 0.0` but only the former satisfies
    /// `is_empty()`. Pinned across the all-absent floor (`ran: 0, absent:
    /// N`) and three mixed splits to close the "regression that hardcoded
    /// `is_empty` to `ran == 0`" arm (which would silently satisfy the
    /// all-absent case).
    #[test]
    fn test_is_empty_pins_empty_boundary() {
        assert!(ProbeCoverage::default().is_empty());
        assert!(ProbeCoverage { ran: 0, absent: 0 }.is_empty());
        assert!(!ProbeCoverage { ran: 0, absent: 7 }.is_empty());
        assert!(!ProbeCoverage { ran: 3, absent: 4 }.is_empty());
        assert!(!ProbeCoverage { ran: 3, absent: 0 }.is_empty());
    }

    /// `is_empty()` and `is_fully_covered()` are mutually exclusive — no
    /// reachable `ProbeCoverage` value satisfies both. The empty case
    /// fails `is_fully_covered` (the `ran > 0` conjunct excludes it), and
    /// the fully-covered case fails `is_empty` (`ran > 0 && absent == 0`
    /// implies `total() > 0`). Pinned across the four-arm decision matrix
    /// the docstring on [`ProbeCoverage::is_fully_covered`] tabulates so
    /// a regression that decoupled the two predicates would fail the
    /// mutual-exclusion invariant here.
    #[test]
    fn test_is_empty_and_is_fully_covered_are_mutually_exclusive() {
        let empty = ProbeCoverage { ran: 0, absent: 0 };
        let all_absent = ProbeCoverage { ran: 0, absent: 7 };
        let mixed = ProbeCoverage { ran: 3, absent: 4 };
        let fully_covered = ProbeCoverage { ran: 3, absent: 0 };
        for c in [empty, all_absent, mixed, fully_covered] {
            assert!(
                !(c.is_empty() && c.is_fully_covered()),
                "is_empty and is_fully_covered must be mutually exclusive at {c:?}",
            );
        }
    }

    /// `is_all_absent()` returns `true` iff every counted probe surfaced
    /// an absent default — `ran == 0 && absent > 0`. Pinned across the
    /// three load-bearing total counts (3 for build, 4 for chart, 7 for
    /// deployment) so a future regression that hardcoded the `absent >
    /// 0` check to one specific N would fail against the other two. The
    /// typed discriminator a downstream `sekiban` admission verifier
    /// reads to fail closed on today's call-site state — every typed
    /// outcome bound at its `ProbeAbsent` / `Absent` arm, no probe ran.
    #[test]
    fn test_is_all_absent_when_no_probe_ran_is_true() {
        assert!(ProbeCoverage { ran: 0, absent: 3 }.is_all_absent());
        assert!(ProbeCoverage { ran: 0, absent: 4 }.is_all_absent());
        assert!(ProbeCoverage { ran: 0, absent: 7 }.is_all_absent());
    }

    /// `is_all_absent()` returns `false` for the empty-slice boundary
    /// case `probe_coverage` over an empty iterator produces (`ran: 0,
    /// absent: 0`). The structural disambiguator from the all-absent
    /// arm: both have `ran == 0` but only the all-absent arm has
    /// `absent > 0`. A future regression that relaxed the predicate to
    /// `ran == 0` alone (dropping the `absent > 0` conjunct) would
    /// silently flip the empty case to `true` and conflate the
    /// boundary; this pin closes that arm. Symmetric to
    /// `test_is_fully_covered_empty_returns_false` one layer over.
    #[test]
    fn test_is_all_absent_empty_returns_false() {
        let empty = ProbeCoverage { ran: 0, absent: 0 };
        assert!(!empty.is_all_absent());
        assert!(empty.is_empty());
    }

    /// `is_all_absent()` returns `false` when any counted probe ran —
    /// the fully-covered ceiling AND the mixed-split intermediate
    /// states. Pinned across the all-ran ceiling (3, 4, 7) plus three
    /// mixed-split shapes (1-of-2, 3-of-7, 2-of-3) so a future
    /// regression that hardcoded the predicate to one specific
    /// `ran` value would fail across the others. Symmetric to
    /// `test_is_fully_covered_any_absent_is_false` one layer over.
    #[test]
    fn test_is_all_absent_any_ran_is_false() {
        assert!(!ProbeCoverage { ran: 3, absent: 0 }.is_all_absent());
        assert!(!ProbeCoverage { ran: 4, absent: 0 }.is_all_absent());
        assert!(!ProbeCoverage { ran: 7, absent: 0 }.is_all_absent());
        assert!(!ProbeCoverage { ran: 1, absent: 1 }.is_all_absent());
        assert!(!ProbeCoverage { ran: 3, absent: 4 }.is_all_absent());
        assert!(!ProbeCoverage { ran: 2, absent: 1 }.is_all_absent());
    }

    /// The three named arm-predicates (`is_empty`, `is_all_absent`,
    /// `is_fully_covered`) are mutually exclusive AND, with the mixed
    /// arm `!is_empty && !is_all_absent && !is_fully_covered`, jointly
    /// exhaustive — exactly one of the four conditions holds for every
    /// reachable `ProbeCoverage` value. The structural pin closes the
    /// four-arm matrix the docstring on [`ProbeCoverage::is_fully_covered`]
    /// tabulates: a regression that decoupled the three predicates
    /// (e.g., made `is_all_absent` also return `true` at the empty arm)
    /// would fail this pin at the offending arm.
    #[test]
    fn test_arm_predicates_partition_the_matrix() {
        let empty = ProbeCoverage { ran: 0, absent: 0 };
        let all_absent = ProbeCoverage { ran: 0, absent: 7 };
        let mixed = ProbeCoverage { ran: 3, absent: 4 };
        let fully_covered = ProbeCoverage { ran: 3, absent: 0 };
        for c in [empty, all_absent, mixed, fully_covered] {
            let e = c.is_empty();
            let a = c.is_all_absent();
            let f = c.is_fully_covered();
            let m = !e && !a && !f;
            let arm_count = u32::from(e) + u32::from(a) + u32::from(f) + u32::from(m);
            assert_eq!(
                arm_count, 1,
                "exactly one of (empty, all_absent, fully_covered, mixed) \
                 must hold at {c:?} — got {arm_count} (empty={e}, \
                 all_absent={a}, fully_covered={f}, mixed={m})",
            );
        }
        assert!(empty.is_empty());
        assert!(all_absent.is_all_absent());
        assert!(fully_covered.is_fully_covered());
        assert!(!mixed.is_empty() && !mixed.is_all_absent() && !mixed.is_fully_covered());
    }

    /// `is_all_absent()` composes with the monoid `Add` shape the way a
    /// downstream fleet-wide aggregator depends on: summing two
    /// all-absent per-phase coverages stays all-absent (no phase added
    /// evidence), but summing an all-absent phase with any phase that
    /// has `ran > 0` produces a non-all-absent aggregate (any phase
    /// that ran lifts the aggregate off the all-absent floor). Mirrors
    /// the structural intuition: a product certification rests on the
    /// all-absent floor only when every phase rested there too.
    #[test]
    fn test_is_all_absent_sums_under_monoid_add() {
        let build_absent = ProbeCoverage { ran: 0, absent: 3 };
        let chart_absent = ProbeCoverage { ran: 0, absent: 4 };
        let deployment_absent = ProbeCoverage { ran: 0, absent: 7 };
        let chart_ran = ProbeCoverage { ran: 1, absent: 3 };
        assert!(build_absent.is_all_absent());
        assert!(chart_absent.is_all_absent());
        assert!(deployment_absent.is_all_absent());
        assert!(!chart_ran.is_all_absent());
        assert!((build_absent + chart_absent).is_all_absent());
        assert!((build_absent + chart_absent + deployment_absent).is_all_absent());
        assert!(!(build_absent + chart_ran).is_all_absent());
        assert!(!(build_absent + chart_ran + deployment_absent).is_all_absent());
    }

    /// `is_all_absent()` stays saturation-robust at the
    /// `(ran: 0, absent: usize::MAX)` arm — both `is_all_absent` AND
    /// `is_saturated` are `true`, the discriminator does not silently
    /// flip the way `coverage_ratio() == 0.0` would at that state
    /// (which reads as `0.0` correctly here — the saturated `absent`
    /// component does not poison the numerator — but a verifier using
    /// the symmetric `{ran: usize::MAX, absent: 0}` shape against
    /// `coverage_ratio() == 1.0` would not be able to disambiguate
    /// "every counted probe ran" from "the saturating clamp dropped
    /// equal evidence at the ceiling"). The integer-arithmetic body
    /// `ran == 0 && absent > 0` forecloses both drift directions
    /// through equality / inequality tests on the components themselves.
    #[test]
    fn test_is_all_absent_stays_robust_at_saturated_absent() {
        let saturated_absent = ProbeCoverage {
            ran: 0,
            absent: usize::MAX,
        };
        assert!(saturated_absent.is_all_absent());
        assert!(saturated_absent.is_saturated());
        assert!(!saturated_absent.is_empty());
        assert!(!saturated_absent.is_fully_covered());
        assert_eq!(saturated_absent.coverage_ratio(), 0.0);
        assert_eq!(saturated_absent.coverage_ratio_pct(), 0);

        let saturated_both = ProbeCoverage {
            ran: usize::MAX,
            absent: usize::MAX,
        };
        assert!(!saturated_both.is_all_absent());
    }

    /// `coverage_ratio()` does not panic at the post-saturation state
    /// `{ran: usize::MAX, absent: usize::MAX}` — it routes through
    /// `total()`, which now saturates at `usize::MAX` rather than
    /// overflowing on `ran + absent`. The float arithmetic `usize::MAX
    /// as f64 / usize::MAX as f64` is `1.0` in IEEE-754 (both numerator
    /// and denominator round identically to the same `f64`), which the
    /// pin asserts directly. A future regression that reverted `total()`
    /// to the unchecked `+` would panic at this call site in debug and
    /// produce a nonsensical wrapped ratio in release — both arms
    /// closed here. Symmetric to `test_add_saturates_at_usize_max` one
    /// impl up: the monoid totality is now upheld at every method the
    /// telemetry emission sites read, not just at `Add`.
    #[test]
    fn test_coverage_ratio_does_not_panic_at_saturated_state() {
        let saturated = ProbeCoverage {
            ran: usize::MAX,
            absent: usize::MAX,
        };
        assert_eq!(saturated.coverage_ratio(), 1.0);
    }

    /// `is_saturated()` returns `true` iff at least one component has
    /// hit the saturating-add ceiling `usize::MAX`. Pinned across the
    /// three reachable saturated arms — `ran` only saturated, `absent`
    /// only saturated, and the post-saturation state where both
    /// components are at the ceiling — so a future regression that
    /// hardcoded the predicate to one component would fail against the
    /// others. The typed-primitive flag a downstream verifier reads
    /// alongside `coverage_ratio()` to know the derived ratio is
    /// unreliable: at every state this predicate returns `true`, the
    /// float division `ran as f64 / total() as f64` has dropped at
    /// least one true increment past the saturating clamp.
    #[test]
    fn test_is_saturated_at_any_component_max_is_true() {
        assert!(ProbeCoverage {
            ran: usize::MAX,
            absent: 0,
        }
        .is_saturated());
        assert!(ProbeCoverage {
            ran: 0,
            absent: usize::MAX,
        }
        .is_saturated());
        assert!(ProbeCoverage {
            ran: usize::MAX,
            absent: usize::MAX,
        }
        .is_saturated());
        assert!(ProbeCoverage {
            ran: usize::MAX,
            absent: 42,
        }
        .is_saturated());
        assert!(ProbeCoverage {
            ran: 42,
            absent: usize::MAX,
        }
        .is_saturated());
    }

    /// `is_saturated()` returns `false` for every realistically-sized
    /// `ProbeCoverage` value. Pinned across the four arms of the matrix
    /// the docstring on [`ProbeCoverage::is_fully_covered`] tabulates
    /// (empty, all-absent, mixed, fully-covered) so a future regression
    /// that flipped the predicate to a vacuous `true` would fail every
    /// arm here. Symmetric to the saturated-true pin one test up: the
    /// two pins together pin the boundary between the saturated and
    /// unsaturated regions of `ProbeCoverage` exactly at the
    /// component-MAX inflection.
    #[test]
    fn test_is_saturated_below_ceiling_is_false() {
        assert!(!ProbeCoverage { ran: 0, absent: 0 }.is_saturated());
        assert!(!ProbeCoverage { ran: 0, absent: 7 }.is_saturated());
        assert!(!ProbeCoverage { ran: 3, absent: 4 }.is_saturated());
        assert!(!ProbeCoverage { ran: 3, absent: 0 }.is_saturated());
        assert!(!ProbeCoverage {
            ran: usize::MAX - 1,
            absent: usize::MAX - 1,
        }
        .is_saturated());
    }

    /// `is_saturated()` is the load-bearing trustworthiness flag at the
    /// `{ran: MAX, absent: MAX}` post-saturation state where the true
    /// ratio is 0.5 (every saturated component dropped equal evidence
    /// past the ceiling), but `coverage_ratio()` reads as `1.0` — the
    /// f64 division `MAX as f64 / MAX as f64` rounds identically against
    /// the IEEE-754 representation. A downstream verifier that gates
    /// only on `coverage_ratio() >= 0.5` would silently accept this
    /// state as fully covered; the typed `is_saturated()` flag forces
    /// the verifier through the trustworthiness predicate the f64
    /// division alone cannot surface. This pin is the structural witness
    /// for the docstring's "honest-signal drift" claim — `is_saturated`
    /// is `true` exactly at the state where `coverage_ratio` is
    /// untrustworthy.
    #[test]
    fn test_is_saturated_flags_coverage_ratio_drift_at_saturated_state() {
        let saturated = ProbeCoverage {
            ran: usize::MAX,
            absent: usize::MAX,
        };
        assert!(saturated.is_saturated());
        assert_eq!(saturated.coverage_ratio(), 1.0);
        assert!(!saturated.is_fully_covered());
        assert!(!saturated.is_empty());
    }

    /// `is_saturated()` is reachable in finite steps from any
    /// unsaturated starting point via the monoid `Add` — the
    /// saturating-add clamp at the component level forecloses
    /// `usize::MAX` as an asymptotic limit of repeated addition. Mirrors
    /// the `test_add_saturates_at_usize_max` pin one layer over: the
    /// pin there proves the saturating clamp at the `Add` impl, this
    /// pin proves the typed-primitive flag surfaces the resulting state.
    /// Together they close the round-trip: a fleet-wide aggregator
    /// summing per-record coverages via `.iter().sum::<ProbeCoverage>()`
    /// reaches the saturated state in finite steps, and the resulting
    /// telemetry record flags itself as saturated through the typed
    /// predicate here.
    #[test]
    fn test_is_saturated_reached_through_monoid_add() {
        let high = ProbeCoverage {
            ran: usize::MAX - 3,
            absent: 0,
        };
        let increment = ProbeCoverage { ran: 7, absent: 0 };
        let aggregate = high + increment;
        assert_eq!(aggregate.ran, usize::MAX);
        assert!(aggregate.is_saturated());
        assert!(!high.is_saturated());
    }

    /// `is_saturated()` composes with the monoid `Add` shape exactly
    /// the way a downstream fleet-wide aggregator depends on: summing a
    /// saturated Phase 1 build coverage with an unsaturated Phase 1
    /// chart coverage produces a saturated aggregate (one saturated
    /// component in any phase poisons the trustworthiness signal).
    /// Mirrors the [`is_fully_covered_sums_under_monoid_add`] pin one
    /// layer over: a product certification's `coverage_ratio()` is
    /// trustworthy only when every phase is unsaturated.
    #[test]
    fn test_is_saturated_propagates_under_monoid_add() {
        let build_saturated = ProbeCoverage {
            ran: usize::MAX,
            absent: 0,
        };
        let chart_normal = ProbeCoverage { ran: 1, absent: 3 };
        let deployment_normal = ProbeCoverage { ran: 0, absent: 7 };
        assert!(build_saturated.is_saturated());
        assert!(!chart_normal.is_saturated());
        assert!(!deployment_normal.is_saturated());
        assert!((build_saturated + chart_normal).is_saturated());
        assert!((chart_normal + deployment_normal + build_saturated).is_saturated());
        assert!(!(chart_normal + deployment_normal).is_saturated());
    }

    /// `coverage_ratio_pct()` returns `0` for the empty-slice boundary
    /// case (`probe_coverage` over an empty iterator produces
    /// `ProbeCoverage { ran: 0, absent: 0 }`). The structural
    /// disambiguator from the all-absent floor remains at `total()`:
    /// both produce `coverage_ratio_pct() == 0` but a downstream verifier
    /// reads `total() == 0` (empty) vs. `total() > 0 && coverage_ratio_pct
    /// == 0` (every counted probe absent). Symmetric to
    /// `test_coverage_ratio_empty_returns_zero` for the float surface.
    #[test]
    fn test_coverage_ratio_pct_empty_returns_zero() {
        let empty = ProbeCoverage { ran: 0, absent: 0 };
        assert_eq!(empty.total(), 0);
        assert_eq!(empty.coverage_ratio_pct(), 0);
    }

    /// `coverage_ratio_pct()` returns `100` for the all-probes-ran
    /// ceiling. Pinned across the three load-bearing total counts (3 for
    /// build, 4 for chart, 7 for deployment) so a future regression that
    /// hardcoded the denominator to one specific total would fail
    /// against the other two. The integer-form ceiling the typed
    /// admission gate `*_probe_coverage_ratio_pct >= 100` reads against
    /// (the strict-production threshold a `sekiban` admission verifier
    /// gates on, dual of the float-form `coverage_ratio() == 1.0`
    /// ceiling).
    #[test]
    fn test_coverage_ratio_pct_all_ran_is_hundred() {
        assert_eq!(
            ProbeCoverage { ran: 3, absent: 0 }.coverage_ratio_pct(),
            100
        );
        assert_eq!(
            ProbeCoverage { ran: 4, absent: 0 }.coverage_ratio_pct(),
            100
        );
        assert_eq!(
            ProbeCoverage { ran: 7, absent: 0 }.coverage_ratio_pct(),
            100
        );
    }

    /// `coverage_ratio_pct()` returns `0` when every counted probe
    /// surfaced an absent default — the all-probes-absent floor today's
    /// `compose_product_certification` / `compute_chart_attestation` /
    /// `compute_build_attestation` call-site state sits at. The
    /// structural disambiguator from the empty-slice case stays at
    /// `total()` (`total() > 0` here vs. `total() == 0` for the empty
    /// boundary). Symmetric to `test_coverage_ratio_all_absent_is_zero`
    /// for the float surface.
    #[test]
    fn test_coverage_ratio_pct_all_absent_is_zero() {
        let all_absent = ProbeCoverage { ran: 0, absent: 7 };
        assert_eq!(all_absent.total(), 7);
        assert_eq!(all_absent.coverage_ratio_pct(), 0);
    }

    /// `coverage_ratio_pct()` floors `(ran * 100) / total` to the
    /// nearest integer percent (Euclidean division, no rounding). Pinned
    /// across the realistic Phase 2 deployment-attestation
    /// three-of-seven shape and the half-and-half (1, 1) corner case so
    /// a future regression that swapped `ran` and `absent` in the
    /// numerator would flip `3/7 = 42` to `4/7 = 57` and fail this pin.
    /// The floor discipline is load-bearing for the admission threshold:
    /// a verifier gating `>= 90` against `(ran: 89, absent: 11)` reads
    /// `coverage_ratio_pct() == 89` (the floor of `89.0/100 = 89%`,
    /// dropping the 0.0 fractional), correctly refusing the just-below
    /// state, where a round-half-up form would round `(ran: 895, absent:
    /// 105)` to `90` and silently admit the just-below-90% state.
    #[test]
    fn test_coverage_ratio_pct_mixed_split_arithmetic() {
        assert_eq!(ProbeCoverage { ran: 1, absent: 1 }.coverage_ratio_pct(), 50);
        assert_eq!(ProbeCoverage { ran: 3, absent: 4 }.coverage_ratio_pct(), 42);
        assert_eq!(ProbeCoverage { ran: 2, absent: 1 }.coverage_ratio_pct(), 66);
        assert_eq!(
            ProbeCoverage {
                ran: 89,
                absent: 11
            }
            .coverage_ratio_pct(),
            89,
            "the just-below-90% state floors to 89 — the strict \
             admission threshold `>= 90` correctly refuses this state"
        );
    }

    /// `coverage_ratio_pct()` does not panic at the post-saturation
    /// state `{ran: usize::MAX, absent: usize::MAX}` — the `u128` cast
    /// at the multiplication forecloses the `ran * 100` overflow
    /// `usize::MAX * 100` would surface in the unchecked `usize`
    /// arithmetic. The `MAX * 100 / MAX` reading is `100` (every
    /// saturated component dropped equal evidence past the ceiling),
    /// the same drift `coverage_ratio()`'s float reading of `1.0`
    /// against the true `0.5` surfaces — the orthogonal
    /// [`ProbeCoverage::is_saturated`] flag is the trustworthiness
    /// signal a downstream verifier reads alongside this field to
    /// foreclose the drift class at the wire level. Symmetric to
    /// `test_coverage_ratio_does_not_panic_at_saturated_state` one
    /// impl up: the monoid totality is upheld at the integer-percent
    /// surface as well.
    #[test]
    fn test_coverage_ratio_pct_does_not_panic_at_saturated_state() {
        let saturated = ProbeCoverage {
            ran: usize::MAX,
            absent: usize::MAX,
        };
        assert_eq!(saturated.coverage_ratio_pct(), 100);
        assert!(saturated.is_saturated());
    }

    /// `coverage_ratio_pct()` is in `0..=100` for every reachable
    /// `ProbeCoverage` value — the invariant the `u8` return type
    /// surfaces structurally. The cast `((ran * 100) / total) as u8`
    /// is structurally lossless because `ran <= total` (componentwise)
    /// implies `(ran * 100) / total <= 100`. Pinned across the four
    /// arms of the matrix the docstring on [`ProbeCoverage::
    /// is_fully_covered`] tabulates (empty, all-absent, mixed,
    /// fully-covered) AND the saturated boundary so a future
    /// regression that decoupled the `<= 100` bound (e.g.,
    /// hand-rolled `ran * 200 / total` for a "double-resolution
    /// percent" form) would fail this pin at one of the arms it
    /// over-shot.
    #[test]
    fn test_coverage_ratio_pct_is_in_range_0_to_100() {
        let cases = [
            ProbeCoverage { ran: 0, absent: 0 },
            ProbeCoverage { ran: 0, absent: 7 },
            ProbeCoverage { ran: 3, absent: 4 },
            ProbeCoverage { ran: 3, absent: 0 },
            ProbeCoverage {
                ran: usize::MAX,
                absent: 0,
            },
            ProbeCoverage {
                ran: usize::MAX,
                absent: usize::MAX,
            },
        ];
        for c in cases {
            let pct = c.coverage_ratio_pct();
            assert!(
                pct <= 100,
                "coverage_ratio_pct must be in 0..=100 at {c:?} — got {pct}",
            );
        }
    }

    /// `coverage_ratio_pct()` floors to the same integer the
    /// f64-multiplied `coverage_ratio() * 100.0` form reads at every
    /// non-saturated value. Pinned across the four arms of the matrix
    /// plus a near-boundary just-below-threshold case so a regression
    /// that drifted between the float and integer surfaces (e.g.,
    /// hand-rolled the integer body via the f64 round-trip
    /// `(self.coverage_ratio() * 100.0) as u8`, which would inherit
    /// the IEEE-754 imprecision the docstring names) would fail this
    /// pin at the just-below state where the float form rounds
    /// differently than the integer floor.
    #[test]
    fn test_coverage_ratio_pct_matches_floor_of_float_ratio_times_hundred() {
        let cases = [
            ProbeCoverage { ran: 0, absent: 0 },
            ProbeCoverage { ran: 0, absent: 7 },
            ProbeCoverage { ran: 3, absent: 4 },
            ProbeCoverage { ran: 3, absent: 0 },
            ProbeCoverage { ran: 1, absent: 1 },
            ProbeCoverage {
                ran: 89,
                absent: 11,
            },
        ];
        for c in cases {
            let pct = c.coverage_ratio_pct();
            let expected = (c.coverage_ratio() * 100.0).floor() as u8;
            assert_eq!(
                pct, expected,
                "integer floor must match floor(f64_ratio * 100) at {c:?}",
            );
        }
    }
}
