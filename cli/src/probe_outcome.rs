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

/// Common contract for typed probe outcomes that carry a `Verified` arm
/// — the structural discriminator naming "the probe ran AND substantiated
/// a positive verification verdict." Five sibling modules carry a typed
/// `*Outcome` enum whose `is_verified` inherent method has structurally
/// identical bodies (`matches!(self, Self::Verified)` for unit-variant
/// form, `matches!(self, Self::Verified { .. })` for struct-variant
/// form):
///
/// * [`crate::flux_source_verification::FluxSourceVerificationOutcome`]
///   — `Verified` (unit) / `VerifyFailed` / `ProbeAbsent`.
/// * [`crate::helm_release_signature::HelmReleaseSignatureOutcome`]
///   — `Verified` (unit) / `VerifyFailed` / `ProbeAbsent`.
/// * [`crate::network_policy_admission::NetworkPolicyAdmissionOutcome`]
///   — `Verified` (unit) / `VerifyFailed` / `ProbeAbsent`.
/// * [`crate::helm_provenance::HelmProvenanceOutcome`]
///   — `Verified { signed_chart_hash }` (struct) / `Unverified` /
///   `VerifyFailed` / `ProbeAbsent`.
/// * [`crate::cosign::CosignVerifyOutcome`]
///   — `Verified { signer_identity, .. }` (struct) / `VerifyFailed` /
///   `Unsigned` / `ProbeAbsent`.
///
/// Object-safe by construction (one `&self` method returning a `bool`,
/// no generics, no associated types) so a slice of `&dyn VerifiedOutcome`
/// references can be collected at the attestation composition site and
/// walked by a future `verification_coverage` helper parallel to the
/// existing [`probe_coverage`] free function — the typed-primitive
/// surface for the verification-trustworthiness dimension orthogonal to
/// the no-evidence dimension [`ProbeOutcome::is_probe_absent`] already
/// discriminates.
///
/// The two dimensions decompose any `Verified`-bearing outcome into a
/// `(is_probe_absent, is_verified)` two-bool pair that names three of
/// the four matrix cells: `(false, true)` is the verified arm,
/// `(false, false)` is any negative-evidence arm (`VerifyFailed`,
/// `Unverified`, `Unsigned`), and `(true, false)` is the absent-probe
/// arm. The fourth corner `(true, true)` — a probe that did not run yet
/// substantiated a positive verdict — is structurally unreachable on
/// every implementor: the probe-absent variant is distinct from the
/// verified variant in every enum's match shape, so the two
/// discriminators are mutually exclusive at the positive end. THEORY
/// §V.4 / §VII.1: the verification-trustworthiness signal is the
/// honesty channel a downstream `sekiban` strict-production admission
/// verifier reads alongside the probe-coverage signal — a record whose
/// every probe ran (`is_probe_absent` false uniformly) but whose
/// verification-bearing subset rejected (`is_verified` false on the
/// verified-bearing arms) fails closed on a different gate than a
/// record whose probes did not run at all. THEORY §VI.1: the
/// verification discriminator is derived at one site (the typed enum's
/// `Verified` arm match), not re-inlined per call site as bool fields
/// on the downstream attestation struct.
#[allow(dead_code)]
pub trait VerifiedOutcome {
    /// True iff this outcome represents the "probe ran AND substantiated
    /// a positive verification verdict" world — the structural
    /// discriminator the `Verified`-bearing outcome family preserves
    /// over the pre-typed bare bool that flattened the verified /
    /// negatively-verified / no-probe-ran trio into a single value.
    ///
    /// Every implementor's inherent `is_verified` body is one of
    /// `matches!(self, Self::Verified)` (unit form) or
    /// `matches!(self, Self::Verified { .. })` (struct form); the
    /// [`impl_verified_outcome!`](crate::impl_verified_outcome) macro
    /// delegates the trait body through the inherent method so both
    /// variant shapes are admitted uniformly without the macro taking a
    /// position on the match pattern.
    fn is_verified(&self) -> bool;
}

/// Emit the [`VerifiedOutcome`] impl for `$ty`, delegating the trait
/// body through `<$ty>::is_verified(self)` — the inherent method the
/// implementor already defines. Admits both the unit-form `Verified`
/// and the struct-form `Verified { .. }` variants without branching at
/// the macro surface: the inherent method already chose the right
/// `matches!` shape, the macro just lifts that choice to the trait
/// surface.
///
/// ```ignore
/// crate::impl_verified_outcome!(FluxSourceVerificationOutcome);
/// crate::impl_verified_outcome!(HelmProvenanceOutcome);
/// ```
///
/// The macro is the load-bearing carrier of the trait invariant: every
/// implementor's trait body is `<$ty>::is_verified(self)`, so a future
/// regression that hand-rolled a divergent trait impl (e.g. returned a
/// hardcoded `false` because the implementor "doesn't have a Verified
/// arm at the trait surface") is structurally foreclosed — there is one
/// expression in the macro body, and the caller supplies only the type
/// name.
#[macro_export]
macro_rules! impl_verified_outcome {
    ($ty:ty) => {
        impl $crate::probe_outcome::VerifiedOutcome for $ty {
            fn is_verified(&self) -> bool {
                <$ty>::is_verified(self)
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

    /// True iff the counted probes split — some ran, some surfaced an
    /// absent default — `ran > 0 && absent > 0`. The fourth and final
    /// named arm of the four-arm matrix the docstring on
    /// [`is_fully_covered`] tabulates, the structural complement to the
    /// three extreme-arm predicates ([`is_empty`] at `(0, 0)`,
    /// [`is_all_absent`] at `(0, N)`, [`is_fully_covered`] at `(M, 0)`).
    /// Before this predicate, the mixed arm was only reachable by
    /// negation (`!is_empty && !is_all_absent && !is_fully_covered`);
    /// after this predicate, every arm of the matrix carries a typed
    /// name, and the partition pin
    /// `test_arm_predicates_partition_the_matrix` reads four explicit
    /// predicates rather than three explicit predicates plus one
    /// derived condition.
    ///
    /// Names the realistic Phase 2 deployment-attestation intermediate
    /// state — a fleet rollout where some typed probes have wired their
    /// real evidence (`Probed` arm) and others still surface the typed
    /// default (`ProbeAbsent` / `Absent` arm). A downstream `sekiban`
    /// admission verifier wanting to gate "some progress but not full
    /// coverage yet" (the relaxed-staging-policy `coverage_ratio >= 0.5
    /// && !is_fully_covered` threshold) reads one bool here rather than
    /// composing the three-predicate negation at the consumer surface.
    ///
    /// The two-condition body `ran > 0 && absent > 0` is the structural
    /// witness of "the counted probes are heterogeneous": neither
    /// component is at the zero boundary, so the slice mixes both
    /// surfaces of the [`ProbeOutcome::is_probe_absent`] predicate.
    /// Symmetric to [`is_fully_covered`] (which pins `absent == 0` at
    /// the upper edge) and [`is_all_absent`] (which pins `ran == 0` at
    /// the lower edge): the three extreme-arm predicates each pin one
    /// of the matrix's edges, and `is_mixed` pins the interior.
    ///
    /// Orthogonal to [`is_saturated`]: the mixed arm at
    /// `(ran: usize::MAX, absent: usize::MAX)` is both `is_mixed() ==
    /// true` AND `is_saturated() == true`. The predicate stays
    /// saturation-robust (the load-bearing tests are `ran > 0` and
    /// `absent > 0`, not arithmetic on the sum), so a downstream
    /// verifier reading `is_mixed()` against the saturated state cannot
    /// drift the way `coverage_ratio() == 0.5` would (which reads as
    /// `1.0` at `{ran: MAX, absent: MAX}` against the true 0.5 ratio).
    ///
    /// [`is_all_absent`]: ProbeCoverage::is_all_absent
    /// [`is_empty`]: ProbeCoverage::is_empty
    /// [`is_fully_covered`]: ProbeCoverage::is_fully_covered
    /// [`is_saturated`]: ProbeCoverage::is_saturated
    ///
    /// THEORY §VI.1 one-oracle discipline: the predicate is derived at
    /// one site (here), not re-inlined as `!coverage.is_empty() &&
    /// !coverage.is_all_absent() && !coverage.is_fully_covered()` per
    /// consumer (a three-call composition the typed name forecloses).
    /// THEORY §V.4 / §VII.1 honesty channel: the discriminator names
    /// "some counted probes ran, some surfaced absent defaults," the
    /// load-bearing precondition the relaxed-staging admission gate
    /// reads to admit partial-coverage progress without admitting the
    /// all-absent floor.
    pub fn is_mixed(&self) -> bool {
        self.ran > 0 && self.absent > 0
    }

    /// True iff at least one counted probe ran and produced evidence —
    /// `ran > 0`. The typed primitive for the relaxed-staging admission
    /// gate the docstrings on [`is_mixed`] and on the
    /// [`emit_probe_coverage!`](crate::commands) macro reference as
    /// `is_mixed() || is_fully_covered()` — the structural disjunction of
    /// the two `ran > 0` arms of the four-arm matrix the docstring on
    /// [`is_fully_covered`] tabulates. Before this predicate, a downstream
    /// `sekiban` admission verifier wanting to admit "any progress was
    /// made" (the relaxed-staging gate that admits both the mixed and
    /// fully-covered arms while rejecting the empty and all-absent floors)
    /// had to compose `coverage.is_mixed() || coverage.is_fully_covered()`
    /// at the consumer surface; after this predicate, the verifier reads
    /// one bool — `coverage.has_evidence()` — and the integer-arithmetic
    /// body `self.ran > 0` collapses the two-arm disjunction at the typed-
    /// primitive surface.
    ///
    /// The structural complement of `!has_evidence()` is "no counted probe
    /// ran" — the disjunction of the two `ran == 0` arms ([`is_empty`] at
    /// `(0, 0)` and [`is_all_absent`] at `(0, N)`), the operational floor
    /// today's [`compose_product_certification`] / [`compute_chart_attestation`]
    /// / [`compute_build_attestation`] call sites sit at (every typed
    /// outcome bound at its `ProbeAbsent` / `Absent` arm, so `ran == 0`
    /// uniformly). The relaxed-staging policy fails closed at
    /// `!has_evidence()` and admits everything above; the strict-production
    /// policy gates the additional ratio-and-trustworthiness composition
    /// `!is_saturated() && is_fully_covered()` one layer up.
    ///
    /// The single-conjunct body `self.ran > 0` is strictly cheaper than the
    /// two-call disjunction it replaces: `is_mixed() || is_fully_covered()`
    /// reads `ran > 0` twice and `absent` once (`(ran > 0 && absent > 0) ||
    /// (ran > 0 && absent == 0)`), where `has_evidence()` reads `ran` once.
    /// The cost matters at fleet-wide-aggregate scales the monoid `Sum`
    /// fold reaches (one read per phase per record across an N-record
    /// fleet aggregate); at one read per record the structural shape
    /// matters more than the cycle count, but the named primitive is
    /// cheaper at both surfaces.
    ///
    /// Symmetric to [`is_saturated`] in the orthogonality dimension: every
    /// reachable `ProbeCoverage` value carries an `(has_evidence,
    /// is_saturated)` two-bool pair the strict-production admission gate
    /// reads as `(true, false)` to admit, where the relaxed-staging gate
    /// reads only `has_evidence == true`. Saturation-robust by construction:
    /// the body is integer arithmetic against `ran` alone, so the post-
    /// saturation state `{ran: usize::MAX, absent: 0}` correctly reads
    /// `has_evidence() == true` (every counted probe — even the dropped
    /// past-ceiling increments — ran), and the post-saturation state `{ran:
    /// 0, absent: usize::MAX}` correctly reads `has_evidence() == false`
    /// (no counted probe ran). The two-arm disjunction `is_mixed() ||
    /// is_fully_covered()` is also saturation-robust (both predicates read
    /// against the components themselves), so the two surfaces compose
    /// without a structural seam at the saturated state.
    ///
    /// [`compose_product_certification`]: crate::commands::attestation::compose_product_certification
    /// [`compute_build_attestation`]: crate::commands::attestation::compute_build_attestation
    /// [`compute_chart_attestation`]: crate::commands::attestation::compute_chart_attestation
    /// [`is_all_absent`]: ProbeCoverage::is_all_absent
    /// [`is_empty`]: ProbeCoverage::is_empty
    /// [`is_fully_covered`]: ProbeCoverage::is_fully_covered
    /// [`is_mixed`]: ProbeCoverage::is_mixed
    /// [`is_saturated`]: ProbeCoverage::is_saturated
    ///
    /// THEORY §VI.1 one-oracle discipline: the predicate is derived at one
    /// site (here), not re-inlined as `coverage.is_mixed() ||
    /// coverage.is_fully_covered()` per consumer (which the typed
    /// primitive surface forecloses at the call-site form). THEORY §V.4 /
    /// §VII.1 honesty channel: the discriminator names "at least one
    /// counted probe ran," the load-bearing precondition the relaxed-
    /// staging admission gate admits and the all-absent-floor /
    /// empty-boundary failure case rejects.
    pub fn has_evidence(&self) -> bool {
        self.ran > 0
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

    /// True iff every counted probe ran AND the coverage signal is
    /// trustworthy — the typed primitive for the strict-production
    /// admission gate the [`is_saturated`] / [`is_fully_covered`]
    /// docstrings have named since the saturation flag landed: a
    /// downstream `sekiban` admission verifier wanting to admit only
    /// records whose evidence channel both fully fired AND whose
    /// derived ratio surfaces are reliable composes `!is_saturated() &&
    /// is_fully_covered()` at the consumer surface. Before this
    /// predicate, every strict-production gate had to retype that
    /// two-bool conjunction. After this predicate, the gate reads one
    /// bool — `coverage.is_admission_eligible_strict()` — and the
    /// integer-arithmetic body collapses the two-bool composition at
    /// the typed-primitive surface.
    ///
    /// Symmetric to [`has_evidence`] one layer over: where
    /// `has_evidence` lifts the relaxed-staging gate's two-bool
    /// disjunction `is_mixed() || is_fully_covered()` to one typed
    /// primitive (`ran > 0`), this lifts the strict-production gate's
    /// two-bool conjunction `!is_saturated() && is_fully_covered()` to
    /// one typed primitive. Every reachable `ProbeCoverage` value
    /// carries an `(has_evidence, is_admission_eligible_strict)`
    /// two-bool pair the two admission gates read uniformly — the
    /// relaxed-staging gate reads `has_evidence == true` (some
    /// evidence), the strict-production gate reads
    /// `is_admission_eligible_strict == true` (complete AND
    /// trustworthy evidence), and the strict gate strictly implies the
    /// relaxed gate (`is_fully_covered() => has_evidence()` since
    /// `is_fully_covered()` requires `ran > 0`).
    ///
    /// Saturation-robust by construction: `is_fully_covered()` reads
    /// `absent == 0 && ran > 0` against the components themselves
    /// (never against derived arithmetic), so the post-saturation
    /// state `{ran: usize::MAX, absent: 0}` is structurally
    /// `is_fully_covered() == true` BUT `is_saturated() == true`, so
    /// the conjunction correctly rejects (`true && !true == false`) —
    /// the saturated state cannot pass the strict gate even though
    /// every counted probe (up to the ceiling) ran. This is the
    /// load-bearing trustworthiness clamp: the float-form
    /// [`coverage_ratio`] and the integer-form [`coverage_ratio_pct`]
    /// both round to `1.0` / `100` at `{ran: MAX, absent: 0}` and
    /// against the true ratio at `{ran: MAX, absent: MAX}` — the
    /// strict gate forecloses both drift classes uniformly through the
    /// `!is_saturated()` factor.
    ///
    /// At every reachable `(ran, absent)` value, the predicate equals
    /// the documented consumer composition exactly — the structural
    /// equivalence
    /// `is_admission_eligible_strict() == (!is_saturated() &&
    /// is_fully_covered())`
    /// is pinned across the empty / all-absent / mixed / fully-covered
    /// arms AND each of the three saturated representatives by
    /// [`test_is_admission_eligible_strict_equals_documented_composition`].
    ///
    /// [`coverage_ratio`]: ProbeCoverage::coverage_ratio
    /// [`coverage_ratio_pct`]: ProbeCoverage::coverage_ratio_pct
    /// [`has_evidence`]: ProbeCoverage::has_evidence
    /// [`is_fully_covered`]: ProbeCoverage::is_fully_covered
    /// [`is_saturated`]: ProbeCoverage::is_saturated
    ///
    /// THEORY.md §VI.1 one-oracle discipline: the strict-production
    /// admission predicate is derived at one site (here), not
    /// re-inlined as `!coverage.is_saturated() &&
    /// coverage.is_fully_covered()` per downstream consumer. THEORY.md
    /// §V.4 / §VII.1 honesty channel: the strict gate names "complete
    /// AND trustworthy evidence," the load-bearing precondition the
    /// strict-production admission gate admits and every other arm
    /// (empty, all-absent, mixed, fully-covered-but-saturated) rejects.
    pub fn is_admission_eligible_strict(&self) -> bool {
        !self.is_saturated() && self.is_fully_covered()
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

/// Verification-coverage summary: count of verification-bearing probe
/// outcomes that substantiated a positive verification verdict
/// ([`VerifiedOutcome::is_verified`] returned `true`) vs. count that did
/// not. The orthogonal-axis peer of [`ProbeCoverage`]: where
/// `ProbeCoverage` summarizes the no-evidence dimension over the full
/// seventeen-outcome attestation pipeline (every typed outcome
/// implements [`ProbeOutcome`]), `VerificationCoverage` summarizes the
/// verification-trustworthiness dimension over the five-outcome
/// `Verified`-bearing subset (only the [`VerifiedOutcome`] implementors:
/// `FluxSourceVerificationOutcome`, `HelmReleaseSignatureOutcome`,
/// `NetworkPolicyAdmissionOutcome`, `HelmProvenanceOutcome`,
/// `CosignVerifyOutcome`).
///
/// The `unverified` field counts every non-verified arm uniformly — the
/// negative-verdict arms (`VerifyFailed`, `Unverified`, `Unsigned`) and
/// the absent-probe arm (`ProbeAbsent`) collapse together at this
/// surface, because the only signal a `&dyn VerifiedOutcome` exposes is
/// the bare `is_verified()` bool. A future commit that wants to recover
/// the (negative-verdict / absent-probe) split walks the same slice
/// through the `&dyn ProbeOutcome` peer trait and joins on the
/// `(is_probe_absent, is_verified)` two-bool decomposition the
/// orthogonality test [`tests::test_probe_absent_and_verified_decompose_
/// orthogonally`] pins.
///
/// THEORY.md §VI.1 one-oracle discipline: the verification-coverage
/// summary is derived at one site (here), not re-inlined as a per-
/// implementor `match` at every consumer of the verification-bearing
/// subset. THEORY.md §V.4 / §VII.1 honesty channel: the
/// `verified / unverified` split is the typed-primitive surface a
/// downstream `sekiban` strict-production admission verifier reads
/// alongside the [`ProbeCoverage`] signal — a record can carry full
/// probe coverage (`ran == 7, absent == 0`) AND partial verification
/// coverage (`verified == 2, unverified == 1`), where the two
/// orthogonal signals expose two distinct failure modes the
/// `compose_product_certification` call site otherwise flattens.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VerificationCoverage {
    /// Number of verification-bearing outcomes whose `is_verified()`
    /// returned `true` — the probe ran AND substantiated a positive
    /// verification verdict.
    pub verified: usize,
    /// Number of verification-bearing outcomes whose `is_verified()`
    /// returned `false` — the structural complement, which collapses
    /// every negative-verdict arm (`VerifyFailed`, `Unverified`,
    /// `Unsigned`) and the absent-probe arm (`ProbeAbsent`) into a
    /// single count at this surface.
    pub unverified: usize,
}

#[allow(dead_code)]
impl VerificationCoverage {
    /// Total number of verification-bearing outcomes counted. The
    /// invariant `verified + unverified == total` holds by construction.
    /// Arithmetic is `usize::saturating_add` rather than the panicking
    /// `+` — symmetric to [`ProbeCoverage::total`], which carries the
    /// same monoid-totality claim a future
    /// [`std::ops::Add`] impl on [`VerificationCoverage`] would compose
    /// with.
    pub fn total(&self) -> usize {
        self.verified.saturating_add(self.unverified)
    }
}

/// Walk a slice of `&dyn VerifiedOutcome` references and compute the
/// verification-coverage summary — the count of probes that
/// substantiated a positive verification verdict vs. the count that did
/// not. Linear in the slice length, no allocation. The
/// verification-trustworthiness peer of [`probe_coverage`]: the two
/// helpers walk orthogonal dimensions of the typed-outcome family (the
/// no-evidence dimension at [`ProbeOutcome::is_probe_absent`] for
/// `probe_coverage`, the verification-trustworthiness dimension at
/// [`VerifiedOutcome::is_verified`] for `verification_coverage`), so a
/// downstream `compose_product_certification` call site collects both
/// summaries against the same record without re-deriving the
/// discriminators per consumer.
#[allow(dead_code)]
pub fn verification_coverage<'a, I>(outcomes: I) -> VerificationCoverage
where
    I: IntoIterator<Item = &'a dyn VerifiedOutcome>,
{
    let mut verified = 0usize;
    let mut unverified = 0usize;
    for outcome in outcomes {
        if outcome.is_verified() {
            verified += 1;
        } else {
            unverified += 1;
        }
    }
    VerificationCoverage {
        verified,
        unverified,
    }
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

    /// A three-arm dummy with the unit-form `Verified` / `VerifyFailed`
    /// / `ProbeAbsent` shape — mirrors the
    /// [`crate::flux_source_verification::FluxSourceVerificationOutcome`]
    /// / [`crate::helm_release_signature::HelmReleaseSignatureOutcome`]
    /// / [`crate::network_policy_admission::NetworkPolicyAdmissionOutcome`]
    /// shape, without depending on the (feature-gated) attestation
    /// modules. Exercises the [`impl_verified_outcome!`](crate::impl_verified_outcome)
    /// macro against the unit-variant inherent-`is_verified` form.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum DummyVerifiedOutcome {
        Verified,
        VerifyFailed,
        ProbeAbsent,
    }
    impl DummyVerifiedOutcome {
        fn is_verified(&self) -> bool {
            matches!(self, Self::Verified)
        }
    }
    crate::impl_probe_outcome!(DummyVerifiedOutcome, ProbeAbsent);
    crate::impl_verified_outcome!(DummyVerifiedOutcome);

    /// A four-arm dummy with the struct-form `Verified { .. }` shape —
    /// mirrors the [`crate::helm_provenance::HelmProvenanceOutcome`] and
    /// [`crate::cosign::CosignVerifyOutcome`] shape, exercising the
    /// [`impl_verified_outcome!`](crate::impl_verified_outcome) macro
    /// against the struct-variant inherent-`is_verified` form. The
    /// inherent method uses `matches!(self, Self::Verified { .. })`;
    /// the macro lifts the verdict to the trait surface uniformly with
    /// the unit-form sibling above.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum DummyVerifiedFieldsOutcome {
        Verified { fingerprint: String },
        VerifyFailed,
        Unverified,
        ProbeAbsent,
    }
    impl DummyVerifiedFieldsOutcome {
        fn is_verified(&self) -> bool {
            matches!(self, Self::Verified { .. })
        }
    }
    crate::impl_probe_outcome!(DummyVerifiedFieldsOutcome, ProbeAbsent);
    crate::impl_verified_outcome!(DummyVerifiedFieldsOutcome);

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

    /// The four named arm-predicates (`is_empty`, `is_all_absent`,
    /// `is_fully_covered`, `is_mixed`) are mutually exclusive AND
    /// jointly exhaustive — exactly one of the four conditions holds
    /// for every reachable `ProbeCoverage` value. The structural pin
    /// closes the four-arm matrix the docstring on
    /// [`ProbeCoverage::is_fully_covered`] tabulates: a regression that
    /// decoupled the four predicates (e.g., made `is_all_absent` also
    /// return `true` at the empty arm, or made `is_mixed` drop the
    /// `ran > 0` conjunct so it fired at the all-absent floor) would
    /// fail this pin at the offending arm. The previous form of this test
    /// derived the mixed arm by negation (`!e && !a && !f`); after the
    /// `is_mixed` typed predicate landed, the partition pin reads four
    /// explicit predicates rather than three explicit predicates plus
    /// a derived condition — a regression decoupling `is_mixed` from
    /// the three extreme-arm predicates surfaces here directly.
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
            let m = c.is_mixed();
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
        assert!(mixed.is_mixed());
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

    /// `is_mixed()` returns `true` iff the counted probes split — some
    /// ran, some surfaced an absent default — `ran > 0 && absent > 0`.
    /// Pinned across the realistic Phase 2 deployment-attestation
    /// three-of-seven mixed shape, the half-and-half `(1, 1)` corner
    /// case, and three more mixed splits (1-of-2, 2-of-3, 89-of-100) so
    /// a future regression that hardcoded the predicate to one specific
    /// `ran` or `absent` value would fail across the others. The typed
    /// discriminator a downstream `sekiban` admission verifier reads to
    /// admit relaxed-staging partial-coverage progress (`is_mixed() ||
    /// is_fully_covered()`) without admitting the all-absent floor.
    #[test]
    fn test_is_mixed_when_both_components_non_zero_is_true() {
        assert!(ProbeCoverage { ran: 1, absent: 1 }.is_mixed());
        assert!(ProbeCoverage { ran: 3, absent: 4 }.is_mixed());
        assert!(ProbeCoverage { ran: 2, absent: 1 }.is_mixed());
        assert!(ProbeCoverage {
            ran: 89,
            absent: 11
        }
        .is_mixed());
    }

    /// `is_mixed()` returns `false` for every extreme-arm representative
    /// — the empty floor `(0, 0)`, the all-absent floor `(0, N)`, and
    /// the fully-covered ceiling `(M, 0)`. The structural mirror of the
    /// three sibling extreme-arm predicates: each fails at its own
    /// extreme and the other two extremes. A future regression that
    /// relaxed the predicate to `ran > 0` alone (dropping the
    /// `absent > 0` conjunct) would silently flip the fully-covered
    /// ceiling to `true` and conflate the mixed arm with the ceiling;
    /// similarly a regression that relaxed to `absent > 0` alone would
    /// flip the all-absent floor to `true`. Both arms closed here.
    #[test]
    fn test_is_mixed_at_extreme_arms_is_false() {
        assert!(!ProbeCoverage { ran: 0, absent: 0 }.is_mixed());
        assert!(!ProbeCoverage { ran: 0, absent: 7 }.is_mixed());
        assert!(!ProbeCoverage { ran: 3, absent: 0 }.is_mixed());
        assert!(!ProbeCoverage { ran: 4, absent: 0 }.is_mixed());
        assert!(!ProbeCoverage { ran: 7, absent: 0 }.is_mixed());
    }

    /// `is_mixed()` composes with the monoid `Add` shape exactly the
    /// way a downstream fleet-wide aggregator depends on: summing two
    /// fully-covered phases stays fully-covered (not mixed); summing a
    /// fully-covered phase with an all-absent phase yields a mixed
    /// aggregate (the fully-covered phase contributed `ran > 0`, the
    /// all-absent phase contributed `absent > 0`); summing two
    /// all-absent phases stays all-absent (not mixed). Mirrors the
    /// structural intuition: a product certification's aggregate is
    /// mixed only when at least one phase contributed evidence AND at
    /// least one phase contributed (or surfaced) an absent default.
    #[test]
    fn test_is_mixed_composes_under_monoid_add() {
        let build_covered = ProbeCoverage { ran: 3, absent: 0 };
        let chart_covered = ProbeCoverage { ran: 4, absent: 0 };
        let deployment_absent = ProbeCoverage { ran: 0, absent: 7 };
        assert!(!build_covered.is_mixed());
        assert!(!chart_covered.is_mixed());
        assert!(!deployment_absent.is_mixed());
        assert!(!(build_covered + chart_covered).is_mixed());
        assert!((build_covered + deployment_absent).is_mixed());
        assert!((build_covered + chart_covered + deployment_absent).is_mixed());
        assert!(!(deployment_absent + deployment_absent).is_mixed());
    }

    /// `is_mixed()` stays saturation-robust at the
    /// `(ran: usize::MAX, absent: usize::MAX)` arm — both `is_mixed`
    /// AND `is_saturated` are `true`, the discriminator does not
    /// silently flip the way `coverage_ratio() == 0.5` would at that
    /// state (which reads as `1.0` against the true 0.5 ratio). The
    /// integer-arithmetic body `ran > 0 && absent > 0` reads against
    /// the components themselves, not against the post-saturation
    /// derived ratio, so the predicate stays robust where the f64
    /// surface drifts. Symmetric to
    /// `test_is_all_absent_stays_robust_at_saturated_absent` one layer
    /// over: the saturation-robust discipline holds at every named
    /// arm-predicate, not just the extreme-arm three.
    #[test]
    fn test_is_mixed_stays_robust_at_saturated_state() {
        let saturated_both = ProbeCoverage {
            ran: usize::MAX,
            absent: usize::MAX,
        };
        assert!(saturated_both.is_mixed());
        assert!(saturated_both.is_saturated());
        assert!(!saturated_both.is_empty());
        assert!(!saturated_both.is_fully_covered());
        assert!(!saturated_both.is_all_absent());
        assert_eq!(saturated_both.coverage_ratio(), 1.0);
        assert_eq!(saturated_both.coverage_ratio_pct(), 100);

        let saturated_ran_only = ProbeCoverage {
            ran: usize::MAX,
            absent: 0,
        };
        assert!(!saturated_ran_only.is_mixed());
        assert!(saturated_ran_only.is_fully_covered());

        let saturated_absent_only = ProbeCoverage {
            ran: 0,
            absent: usize::MAX,
        };
        assert!(!saturated_absent_only.is_mixed());
        assert!(saturated_absent_only.is_all_absent());
    }

    /// `has_evidence()` returns `true` iff at least one counted probe ran
    /// — `ran > 0`. Pinned across the fully-covered ceiling (3, 4, 7) AND
    /// the realistic Phase 2 mixed three-of-seven shape, the half-and-half
    /// (1, 1) corner, and the 2-of-3 / 89-of-100 splits so a regression
    /// that hardcoded the predicate to one specific value (or accidentally
    /// dropped a non-zero `absent` arm) would fail across the others. The
    /// typed-primitive surface the relaxed-staging admission gate reads
    /// directly — every value where `has_evidence()` is `true` is an
    /// admissible relaxed-staging coverage record.
    #[test]
    fn test_has_evidence_when_any_probe_ran_is_true() {
        assert!(ProbeCoverage { ran: 3, absent: 0 }.has_evidence());
        assert!(ProbeCoverage { ran: 4, absent: 0 }.has_evidence());
        assert!(ProbeCoverage { ran: 7, absent: 0 }.has_evidence());
        assert!(ProbeCoverage { ran: 1, absent: 1 }.has_evidence());
        assert!(ProbeCoverage { ran: 3, absent: 4 }.has_evidence());
        assert!(ProbeCoverage { ran: 2, absent: 1 }.has_evidence());
        assert!(ProbeCoverage {
            ran: 89,
            absent: 11
        }
        .has_evidence());
    }

    /// `has_evidence()` returns `false` for both `ran == 0` arms — the
    /// empty floor `(0, 0)` and the all-absent floor `(0, N)`. Pinned
    /// across both arms (and across three sizes of the all-absent floor:
    /// 3, 4, 7 — the per-phase build / chart / deployment counts the prior
    /// pins use) so a future regression that relaxed the predicate to
    /// `total() > 0` (the structural sibling that admits the all-absent
    /// floor) would flip the all-absent floor to `true` and fail this pin.
    /// Today's `compose_product_certification` /
    /// `compute_chart_attestation` / `compute_build_attestation` call-site
    /// state sits at exactly the all-absent floor — the relaxed-staging
    /// admission gate correctly refuses this state because
    /// `has_evidence() == false`.
    #[test]
    fn test_has_evidence_at_no_ran_arms_is_false() {
        assert!(!ProbeCoverage { ran: 0, absent: 0 }.has_evidence());
        assert!(!ProbeCoverage { ran: 0, absent: 3 }.has_evidence());
        assert!(!ProbeCoverage { ran: 0, absent: 4 }.has_evidence());
        assert!(!ProbeCoverage { ran: 0, absent: 7 }.has_evidence());
    }

    /// `has_evidence()` is structurally equivalent to the two-call
    /// disjunction `is_mixed() || is_fully_covered()` it lifts from the
    /// consumer surface. Pinned across the four arms of the matrix the
    /// docstring on [`ProbeCoverage::is_fully_covered`] tabulates so a
    /// future regression that decoupled `has_evidence` from the two-arm
    /// disjunction (e.g., hand-rolled the body as `total() > 0`, which
    /// would admit the all-absent floor that neither `is_mixed` nor
    /// `is_fully_covered` admits) would fail this pin at the all-absent
    /// arm. The structural equivalence is what makes the typed primitive
    /// the proper one-oracle surface for the relaxed-staging admission
    /// gate: a verifier reading `has_evidence()` reads exactly what
    /// `is_mixed() || is_fully_covered()` reads, with no behavioural seam.
    #[test]
    fn test_has_evidence_equals_disjunction_of_mixed_and_fully_covered() {
        let cases = [
            ProbeCoverage { ran: 0, absent: 0 },
            ProbeCoverage { ran: 0, absent: 7 },
            ProbeCoverage { ran: 3, absent: 4 },
            ProbeCoverage { ran: 3, absent: 0 },
            ProbeCoverage { ran: 1, absent: 1 },
            ProbeCoverage { ran: 7, absent: 0 },
            ProbeCoverage { ran: 0, absent: 3 },
        ];
        for c in cases {
            assert_eq!(
                c.has_evidence(),
                c.is_mixed() || c.is_fully_covered(),
                "has_evidence must equal the two-arm disjunction at {c:?}",
            );
        }
    }

    /// `has_evidence()` composes with the monoid `Add` shape exactly the
    /// way a downstream fleet-wide aggregator depends on: a per-phase
    /// no-evidence coverage summed with any per-phase has-evidence
    /// coverage produces a has-evidence aggregate (one phase contributing
    /// `ran > 0` lifts the aggregate off the no-evidence floor). Mirrors
    /// the structural intuition: a product certification has evidence iff
    /// any phase contributed evidence. A future regression that swapped
    /// `ran` and `absent` in the impl body of `Add` would silently flip a
    /// has-evidence build-phase coverage into a no-evidence aggregate;
    /// this pin closes that arm at the typed-primitive surface.
    #[test]
    fn test_has_evidence_composes_under_monoid_add() {
        let build_absent = ProbeCoverage { ran: 0, absent: 3 };
        let chart_absent = ProbeCoverage { ran: 0, absent: 4 };
        let deployment_absent = ProbeCoverage { ran: 0, absent: 7 };
        let chart_ran = ProbeCoverage { ran: 1, absent: 3 };
        assert!(!build_absent.has_evidence());
        assert!(!chart_absent.has_evidence());
        assert!(!deployment_absent.has_evidence());
        assert!(chart_ran.has_evidence());
        assert!(!(build_absent + chart_absent).has_evidence());
        assert!(!(build_absent + chart_absent + deployment_absent).has_evidence());
        assert!((build_absent + chart_ran).has_evidence());
        assert!((build_absent + chart_ran + deployment_absent).has_evidence());
    }

    /// `has_evidence()` stays saturation-robust: the body `ran > 0` reads
    /// against the `ran` component itself, not against any derived ratio.
    /// At the post-saturation state `{ran: usize::MAX, absent: 0}` it
    /// correctly reads `true` (every counted probe — even the dropped
    /// past-ceiling increments — ran); at the post-saturation state `{ran:
    /// 0, absent: usize::MAX}` it correctly reads `false` (no counted
    /// probe ran). The symmetric saturated state `{ran: MAX, absent: MAX}`
    /// reads `true` (both components are non-zero), matching the typed-arm
    /// disjunction `is_mixed() || is_fully_covered() == true || false ==
    /// true` at that state. Mirrors the saturation-robust discipline the
    /// `test_is_mixed_stays_robust_at_saturated_state` /
    /// `test_is_all_absent_stays_robust_at_saturated_absent` siblings pin
    /// for the arm-predicates one layer up.
    #[test]
    fn test_has_evidence_stays_robust_at_saturated_state() {
        let saturated_ran_only = ProbeCoverage {
            ran: usize::MAX,
            absent: 0,
        };
        assert!(saturated_ran_only.has_evidence());
        assert!(saturated_ran_only.is_saturated());
        assert!(saturated_ran_only.is_fully_covered());

        let saturated_absent_only = ProbeCoverage {
            ran: 0,
            absent: usize::MAX,
        };
        assert!(!saturated_absent_only.has_evidence());
        assert!(saturated_absent_only.is_saturated());
        assert!(saturated_absent_only.is_all_absent());

        let saturated_both = ProbeCoverage {
            ran: usize::MAX,
            absent: usize::MAX,
        };
        assert!(saturated_both.has_evidence());
        assert!(saturated_both.is_saturated());
        assert!(saturated_both.is_mixed());
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

    /// Strict-production admission gate is `true` exactly at the
    /// `is_fully_covered() && !is_saturated()` corner of the matrix.
    /// Pinned across the three load-bearing total counts (3 / 4 / 7,
    /// matching the build / chart / deployment phase probe counts) so a
    /// regression that pinned the predicate to a single phase's total
    /// would fail at the other two.
    #[test]
    fn test_is_admission_eligible_strict_at_fully_covered_non_saturated_arm_is_true() {
        for total in [3usize, 4, 7] {
            let c = ProbeCoverage {
                ran: total,
                absent: 0,
            };
            assert!(
                c.is_admission_eligible_strict(),
                "fully-covered non-saturated arm must pass the strict gate at {c:?}",
            );
        }
    }

    /// Strict gate rejects every non-(fully-covered) arm. Pins:
    /// - empty floor `(0, 0)` — `is_fully_covered()` false (`ran == 0`)
    /// - all-absent floor `(0, N)` — `is_fully_covered()` false (same)
    /// - mixed arm `(N, M)` with both positive — `is_fully_covered()`
    ///   false (`absent > 0`)
    /// All three rejection arms close at the `is_fully_covered() == false`
    /// factor of the conjunction; the saturation factor is exercised
    /// separately below.
    #[test]
    fn test_is_admission_eligible_strict_rejects_non_fully_covered_arms() {
        let empty = ProbeCoverage { ran: 0, absent: 0 };
        let all_absent = ProbeCoverage { ran: 0, absent: 7 };
        let mixed_low = ProbeCoverage { ran: 1, absent: 1 };
        let mixed_high = ProbeCoverage {
            ran: 89,
            absent: 11,
        };
        for c in [empty, all_absent, mixed_low, mixed_high] {
            assert!(
                !c.is_admission_eligible_strict(),
                "non-fully-covered arm must fail the strict gate at {c:?}",
            );
        }
    }

    /// Strict gate rejects every saturated state, INCLUDING the
    /// `{ran: usize::MAX, absent: 0}` representative that
    /// `is_fully_covered()` reads as `true`. Saturation-robustness is
    /// the load-bearing factor — the `coverage_ratio()` /
    /// `coverage_ratio_pct()` reads at `{MAX, 0}` round to `1.0` / `100`
    /// honestly (every counted probe up to the ceiling ran), but the
    /// saturating-add clamp means an unknown number of past-ceiling
    /// increments were dropped, so the derived ratio cannot be trusted
    /// — the strict gate refuses to admit.
    #[test]
    fn test_is_admission_eligible_strict_at_saturated_state_is_false() {
        let saturated_ran_only = ProbeCoverage {
            ran: usize::MAX,
            absent: 0,
        };
        let saturated_absent_only = ProbeCoverage {
            ran: 0,
            absent: usize::MAX,
        };
        let saturated_both = ProbeCoverage {
            ran: usize::MAX,
            absent: usize::MAX,
        };
        for c in [saturated_ran_only, saturated_absent_only, saturated_both] {
            assert!(
                !c.is_admission_eligible_strict(),
                "saturated state must fail the strict gate at {c:?} — the \
                 saturating-add clamp dropped past-ceiling increments, so \
                 the derived ratio surfaces cannot be trusted",
            );
        }
    }

    /// Structural equivalence with the documented consumer composition
    /// `!is_saturated() && is_fully_covered()`. Pins the one-oracle
    /// invariant the typed primitive carries — a regression that
    /// hand-rolled the body (e.g., `is_fully_covered() && !is_empty()`)
    /// would fail at the saturated `{MAX, 0}` arm where
    /// `is_fully_covered() == true` AND `is_empty() == false` AND
    /// `is_saturated() == true`, so the divergent composition would
    /// erroneously admit a state the documented strict gate refuses.
    /// Walks every cell of the cross product
    /// `({empty, all_absent, mixed, fully_covered} × {saturated,
    /// non_saturated})` (the empty arm is structurally non-saturated
    /// only, since both components are 0; the other three each admit
    /// both saturation states).
    #[test]
    fn test_is_admission_eligible_strict_equals_documented_composition() {
        let cases = [
            ProbeCoverage { ran: 0, absent: 0 }, // empty (always non-saturated)
            ProbeCoverage { ran: 0, absent: 7 }, // all-absent non-saturated
            ProbeCoverage {
                ran: 0,
                absent: usize::MAX,
            }, // all-absent saturated
            ProbeCoverage { ran: 3, absent: 4 }, // mixed non-saturated
            ProbeCoverage {
                ran: usize::MAX,
                absent: usize::MAX,
            }, // mixed saturated
            ProbeCoverage { ran: 7, absent: 0 }, // fully-covered non-saturated
            ProbeCoverage {
                ran: usize::MAX,
                absent: 0,
            }, // fully-covered saturated
        ];
        for c in cases {
            let direct = c.is_admission_eligible_strict();
            let composed = !c.is_saturated() && c.is_fully_covered();
            assert_eq!(
                direct, composed,
                "typed-primitive surface must equal the documented \
                 consumer composition at {c:?} — a regression that hand-rolled \
                 the body would fail this pin at the saturated `{{MAX, 0}}` arm \
                 where the discriminators decouple",
            );
        }
    }

    /// Under the saturating monoid `Add`, any phase whose contribution
    /// has `absent > 0` breaks the strict gate at the aggregate — the
    /// aggregate's `absent` field inherits the contributing phase's
    /// `absent` (monoid `Add` is component-wise saturating add), so the
    /// aggregate's `is_fully_covered() == (absent == 0 && ran > 0)`
    /// reads `false` whenever any phase contributed an absent probe.
    /// The fleet-wide aggregate the `Sum` fold computes thus admits
    /// the strict gate only when EVERY phase is fully covered AND no
    /// component reached the saturating ceiling. Pinned across two
    /// representative two-phase aggregates: one where both phases are
    /// fully covered (aggregate passes), one where one phase
    /// contributes an absent (aggregate fails).
    #[test]
    fn test_is_admission_eligible_strict_composes_under_monoid_add() {
        let phase_a_full = ProbeCoverage { ran: 3, absent: 0 };
        let phase_b_full = ProbeCoverage { ran: 4, absent: 0 };
        let aggregate_full = phase_a_full + phase_b_full;
        assert!(
            aggregate_full.is_admission_eligible_strict(),
            "two fully-covered phases sum to a fully-covered aggregate \
             that passes the strict gate — {aggregate_full:?}",
        );

        let phase_b_partial = ProbeCoverage { ran: 3, absent: 1 };
        let aggregate_with_absent = phase_a_full + phase_b_partial;
        assert!(
            !aggregate_with_absent.is_admission_eligible_strict(),
            "any phase contributing an absent probe breaks the \
             aggregate's strict gate — {aggregate_with_absent:?}",
        );
    }

    /// Pin the load-bearing [`VerifiedOutcome`] trait invariant against
    /// the unit-variant form: only the `Verified` arm reads `true`, the
    /// negative-evidence and absent-probe arms read `false`. The macro-
    /// generated impl delegates through `<Self>::is_verified(self)` so
    /// this also pins the structural equivalence between the trait
    /// surface and the inherent surface at every reachable arm — a
    /// regression that hand-rolled a divergent trait impl (e.g. returned
    /// a hardcoded `false` because the implementor "doesn't have a
    /// Verified arm at the trait surface", or returned `true` for the
    /// absent arm — the structurally-impossible `(true, true)` corner
    /// of the two-dimension matrix) would fail this pin.
    #[test]
    fn test_verified_outcome_trait_pins_unit_form() {
        assert!(VerifiedOutcome::is_verified(
            &DummyVerifiedOutcome::Verified
        ));
        assert!(!VerifiedOutcome::is_verified(
            &DummyVerifiedOutcome::VerifyFailed
        ));
        assert!(!VerifiedOutcome::is_verified(
            &DummyVerifiedOutcome::ProbeAbsent
        ));
    }

    /// Pin the same load-bearing invariant against the struct-variant
    /// form (`Verified { fingerprint: String }`): the macro lifts the
    /// inherent `matches!(self, Self::Verified { .. })` body to the
    /// trait surface unchanged. The four-arm shape (`Verified` +
    /// `Unverified` + `VerifyFailed` + `ProbeAbsent`) mirrors
    /// [`HelmProvenanceOutcome`]; the test pins each arm's verdict so a
    /// regression that flattened `Unverified` and `VerifyFailed` into a
    /// single arm or that misread the struct-form variant as not-
    /// verified would fail.
    #[test]
    fn test_verified_outcome_trait_pins_struct_form() {
        let verified = DummyVerifiedFieldsOutcome::Verified {
            fingerprint: "sha256:abc".to_string(),
        };
        assert!(VerifiedOutcome::is_verified(&verified));
        assert!(!VerifiedOutcome::is_verified(
            &DummyVerifiedFieldsOutcome::Unverified
        ));
        assert!(!VerifiedOutcome::is_verified(
            &DummyVerifiedFieldsOutcome::VerifyFailed
        ));
        assert!(!VerifiedOutcome::is_verified(
            &DummyVerifiedFieldsOutcome::ProbeAbsent
        ));
    }

    /// Pin that [`VerifiedOutcome`] is object-safe — a slice of `&dyn
    /// VerifiedOutcome` references can be collected and walked through
    /// the trait-object surface without depending on the concrete
    /// implementor type. The heterogeneous slice mixes the unit-form
    /// and struct-form dummies, exactly as the future
    /// `verification_coverage(&[&dyn VerifiedOutcome])` helper would
    /// walk a deployment record's three verification-bearing probes
    /// (flux-source / network-policy / helm-release-signature, all
    /// unit-form) alongside the chart record's provenance probe
    /// (helm-provenance, struct-form) and the image record's cosign
    /// probe (cosign, struct-form). The filter-count of two pins the
    /// dyn-dispatch surface: a regression that broke object safety
    /// would fail to compile this test.
    #[test]
    fn test_verified_outcome_is_object_safe_across_variant_shapes() {
        let unit_verified = DummyVerifiedOutcome::Verified;
        let unit_failed = DummyVerifiedOutcome::VerifyFailed;
        let unit_absent = DummyVerifiedOutcome::ProbeAbsent;
        let struct_verified = DummyVerifiedFieldsOutcome::Verified {
            fingerprint: "sha256:xyz".to_string(),
        };
        let struct_unverified = DummyVerifiedFieldsOutcome::Unverified;
        let outcomes: [&dyn VerifiedOutcome; 5] = [
            &unit_verified,
            &unit_failed,
            &unit_absent,
            &struct_verified,
            &struct_unverified,
        ];
        let verified_count = outcomes.iter().filter(|o| o.is_verified()).count();
        assert_eq!(
            verified_count, 2,
            "exactly two of five outcomes are Verified — the trait-\
             object slice must count both the unit-form and struct-form \
             verified arms uniformly without depending on the concrete \
             implementor type"
        );
    }

    /// Pin the orthogonal decomposition of the two structural
    /// discriminators ([`ProbeOutcome::is_probe_absent`] and
    /// [`VerifiedOutcome::is_verified`]) into a `(is_probe_absent,
    /// is_verified)` two-bool pair. Three of the four matrix cells are
    /// reachable: `(false, true)` for the `Verified` arm, `(false,
    /// false)` for any non-absent non-verified arm (`VerifyFailed`,
    /// `Unverified`), and `(true, false)` for the `ProbeAbsent` arm.
    /// The fourth corner `(true, true)` — a probe that did not run yet
    /// substantiated a positive verdict — is structurally unreachable
    /// on every implementor and the test does not list it; any
    /// regression that introduced a fourth-corner arm at any dummy
    /// would fail at compile or at this pin.
    #[test]
    fn test_probe_absent_and_verified_decompose_orthogonally() {
        let verified = DummyVerifiedOutcome::Verified;
        let failed = DummyVerifiedOutcome::VerifyFailed;
        let absent = DummyVerifiedOutcome::ProbeAbsent;

        assert_eq!(
            (
                verified.is_probe_absent(),
                VerifiedOutcome::is_verified(&verified)
            ),
            (false, true),
            "Verified arm: probe ran AND substantiated positive verdict"
        );
        assert_eq!(
            (
                failed.is_probe_absent(),
                VerifiedOutcome::is_verified(&failed)
            ),
            (false, false),
            "VerifyFailed arm: probe ran AND substantiated negative verdict"
        );
        assert_eq!(
            (
                absent.is_probe_absent(),
                VerifiedOutcome::is_verified(&absent)
            ),
            (true, false),
            "ProbeAbsent arm: no probe ran AND no verdict"
        );
    }

    /// `verification_coverage` over an empty slice returns
    /// `VerificationCoverage { verified: 0, unverified: 0 }` —
    /// structurally equal to `VerificationCoverage::default()`. The
    /// boundary case a future
    /// `compose_product_certification` call site may surface during
    /// integration-test paths where no `Verified`-bearing typed outcomes
    /// were materialized. Mirrors
    /// [`test_probe_coverage_empty_slice`] one helper over.
    #[test]
    fn test_verification_coverage_empty_slice() {
        let outcomes: [&dyn VerifiedOutcome; 0] = [];
        let coverage = verification_coverage(outcomes.iter().copied());
        assert_eq!(
            coverage,
            VerificationCoverage {
                verified: 0,
                unverified: 0
            }
        );
        assert_eq!(coverage, VerificationCoverage::default());
        assert_eq!(coverage.total(), 0);
    }

    /// `verification_coverage` counts the verified vs. unverified split
    /// correctly across a heterogeneous slice that mixes both the
    /// unit-variant dummy (`Verified` / `VerifyFailed` / `ProbeAbsent`)
    /// and the struct-variant dummy
    /// (`Verified { fingerprint }` / `Unverified` / `VerifyFailed` /
    /// `ProbeAbsent`) through the `&dyn VerifiedOutcome` trait-object
    /// form — pins that the helper walks the trait-object surface
    /// uniformly across both variant shapes, exactly as the future
    /// `compose_product_certification` call site walks the
    /// `FluxSourceVerificationOutcome` / `HelmReleaseSignatureOutcome`
    /// / `NetworkPolicyAdmissionOutcome` (unit form) alongside the
    /// `HelmProvenanceOutcome` / `CosignVerifyOutcome` (struct form).
    /// Two of five outcomes are `Verified`, three are not.
    #[test]
    fn test_verification_coverage_mixed_slice() {
        let unit_verified = DummyVerifiedOutcome::Verified;
        let unit_failed = DummyVerifiedOutcome::VerifyFailed;
        let unit_absent = DummyVerifiedOutcome::ProbeAbsent;
        let struct_verified = DummyVerifiedFieldsOutcome::Verified {
            fingerprint: "sha256:abc".to_string(),
        };
        let struct_unverified = DummyVerifiedFieldsOutcome::Unverified;
        let outcomes: [&dyn VerifiedOutcome; 5] = [
            &unit_verified,
            &unit_failed,
            &unit_absent,
            &struct_verified,
            &struct_unverified,
        ];
        let coverage = verification_coverage(outcomes.iter().copied());
        assert_eq!(
            coverage,
            VerificationCoverage {
                verified: 2,
                unverified: 3
            }
        );
        assert_eq!(coverage.total(), 5);
    }

    /// `verification_coverage` counts `VerificationCoverage { verified:
    /// N, unverified: 0 }` when every outcome substantiated a positive
    /// verification verdict — the all-verified ceiling the
    /// strict-production `sekiban` admission gate fails-closed against.
    /// Mirrors [`test_probe_coverage_all_ran`] one helper over.
    #[test]
    fn test_verification_coverage_all_verified() {
        let a = DummyVerifiedOutcome::Verified;
        let b = DummyVerifiedOutcome::Verified;
        let c = DummyVerifiedFieldsOutcome::Verified {
            fingerprint: "sha256:xyz".to_string(),
        };
        let outcomes: [&dyn VerifiedOutcome; 3] = [&a, &b, &c];
        let coverage = verification_coverage(outcomes.iter().copied());
        assert_eq!(
            coverage,
            VerificationCoverage {
                verified: 3,
                unverified: 0
            }
        );
        assert_eq!(coverage.total(), 3);
    }

    /// `verification_coverage` counts `VerificationCoverage { verified:
    /// 0, unverified: N }` when no outcome substantiated a positive
    /// verdict — pins the structural collapse of the negative-verdict
    /// arms (`VerifyFailed`, `Unverified`) and the absent-probe arm
    /// (`ProbeAbsent`) into the single `unverified` count at this
    /// surface, the documented behavior of the bare-bool
    /// [`VerifiedOutcome::is_verified`] discriminator. A consumer that
    /// wants to recover the (negative-verdict / absent-probe) split
    /// walks the same slice through the `&dyn ProbeOutcome` peer trait
    /// and joins on the `(is_probe_absent, is_verified)` two-bool
    /// decomposition the
    /// [`test_probe_absent_and_verified_decompose_orthogonally`]
    /// pin documents.
    #[test]
    fn test_verification_coverage_all_unverified() {
        let failed = DummyVerifiedOutcome::VerifyFailed;
        let absent = DummyVerifiedOutcome::ProbeAbsent;
        let struct_unverified = DummyVerifiedFieldsOutcome::Unverified;
        let outcomes: [&dyn VerifiedOutcome; 3] = [&failed, &absent, &struct_unverified];
        let coverage = verification_coverage(outcomes.iter().copied());
        assert_eq!(
            coverage,
            VerificationCoverage {
                verified: 0,
                unverified: 3
            }
        );
        assert_eq!(coverage.total(), 3);
    }

    /// `VerificationCoverage::total` saturates at `usize::MAX` rather
    /// than panicking — the monoid totality claim a future
    /// [`std::ops::Add`] impl on [`VerificationCoverage`] will compose
    /// with, symmetric to the saturating ceiling
    /// [`ProbeCoverage::total`] upholds. The post-ceiling state
    /// `VerificationCoverage { verified: usize::MAX, unverified:
    /// usize::MAX }` returns `usize::MAX` here, not a panic in debug or
    /// a silent wrap in release. The three load-bearing
    /// representative arms exercised mirror the
    /// [`test_total_saturates_at_usize_max`] sibling against
    /// `ProbeCoverage`.
    #[test]
    fn test_verification_coverage_total_saturates_at_usize_max() {
        let saturated_both = VerificationCoverage {
            verified: usize::MAX,
            unverified: usize::MAX,
        };
        assert_eq!(saturated_both.total(), usize::MAX);

        let saturated_verified_only = VerificationCoverage {
            verified: usize::MAX,
            unverified: 1,
        };
        assert_eq!(saturated_verified_only.total(), usize::MAX);

        let saturated_unverified_only = VerificationCoverage {
            verified: 1,
            unverified: usize::MAX,
        };
        assert_eq!(saturated_unverified_only.total(), usize::MAX);
    }

    /// Pin the orthogonal-axis composition: the same heterogeneous slice
    /// of `Verified`-bearing typed outcomes can be walked through BOTH
    /// the [`probe_coverage`] helper (over `&dyn ProbeOutcome` — the
    /// no-evidence dimension) AND the [`verification_coverage`] helper
    /// (over `&dyn VerifiedOutcome` — the
    /// verification-trustworthiness dimension), and the two summaries
    /// carry orthogonal-but-related counts:
    ///
    /// - `ProbeCoverage::total() == VerificationCoverage::total()` —
    ///   both helpers count every element of the slice exactly once;
    /// - `ProbeCoverage::absent == count(ProbeAbsent arm)`; the
    ///   `VerificationCoverage::unverified` count INCLUDES that absent
    ///   count and ADDS the negative-verdict count on top, by the
    ///   `(false, true)` corner being unreachable on every
    ///   `Verified`-bearing implementor — `ProbeCoverage::ran ==
    ///   VerificationCoverage::verified + (count of probes that ran
    ///   but failed verification)`.
    ///
    /// The five-outcome slice from
    /// [`test_verification_coverage_mixed_slice`] exercises every
    /// reachable corner of the `(is_probe_absent, is_verified)`
    /// two-bool matrix:
    /// - `(false, true)`: 2 verified (`unit_verified`,
    ///   `struct_verified`)
    /// - `(false, false)`: 2 ran-but-failed (`unit_failed`,
    ///   `struct_unverified`)
    /// - `(true, false)`: 1 absent (`unit_absent`)
    /// - `(true, true)`: structurally unreachable
    ///
    /// So the slice surfaces `ProbeCoverage { ran: 4, absent: 1 }` AND
    /// `VerificationCoverage { verified: 2, unverified: 3 }` and the
    /// two totals agree at `5`.
    #[test]
    fn test_probe_and_verification_coverage_compose_orthogonally() {
        let unit_verified = DummyVerifiedOutcome::Verified;
        let unit_failed = DummyVerifiedOutcome::VerifyFailed;
        let unit_absent = DummyVerifiedOutcome::ProbeAbsent;
        let struct_verified = DummyVerifiedFieldsOutcome::Verified {
            fingerprint: "sha256:abc".to_string(),
        };
        let struct_unverified = DummyVerifiedFieldsOutcome::Unverified;

        let probe_outcomes: [&dyn ProbeOutcome; 5] = [
            &unit_verified,
            &unit_failed,
            &unit_absent,
            &struct_verified,
            &struct_unverified,
        ];
        let verified_outcomes: [&dyn VerifiedOutcome; 5] = [
            &unit_verified,
            &unit_failed,
            &unit_absent,
            &struct_verified,
            &struct_unverified,
        ];

        let probe = probe_coverage(probe_outcomes.iter().copied());
        let verification = verification_coverage(verified_outcomes.iter().copied());

        assert_eq!(probe, ProbeCoverage { ran: 4, absent: 1 });
        assert_eq!(
            verification,
            VerificationCoverage {
                verified: 2,
                unverified: 3
            }
        );
        assert_eq!(
            probe.total(),
            verification.total(),
            "both helpers count every element of the slice exactly once"
        );
    }
}
