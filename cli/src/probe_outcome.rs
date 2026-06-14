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
    ///
    /// The parallel-composed peer at the two-axis surface is
    /// [`compose_admission_eligible_strict`], which seals the
    /// four-way conjunction
    /// `!probe.is_saturated() && probe.is_fully_covered() &&
    /// !verification.is_saturated() && verification.is_fully_verified()`
    /// at one site so a downstream strict-production verifier reads
    /// one bool across both orthogonal axes rather than composing
    /// `probe.is_admission_eligible_strict() &&
    /// verification.is_admission_eligible_strict()` at the consumer
    /// surface.
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

    /// True iff every counted verification-bearing outcome substantiated a
    /// positive verification verdict — `verified > 0 && unverified == 0`.
    /// The orthogonal-axis peer of [`ProbeCoverage::is_fully_covered`]: the
    /// typed discriminator for the strict-production `sekiban` admission
    /// verifier gate (THEORY §VII.1: attestation-gated deployments are
    /// structural, not policy overlays) at the verification-trustworthiness
    /// dimension. A downstream reconciliation that fails-closed unless
    /// every verification-bearing probe substantiated its claim reads one
    /// bool here rather than re-deriving `verification.verified > 0 &&
    /// verification.unverified == 0` per call site.
    ///
    /// The four reachable arms of [`VerificationCoverage`] resolve as:
    ///
    /// | `verified` | `unverified` | `is_empty()` | `is_fully_verified()` | `verification_ratio()` |
    /// |------------|--------------|--------------|-----------------------|------------------------|
    /// | `0`        | `0`          | `true`       | `false`               | `0.0`                  |
    /// | `0`        | `N`          | `false`      | `false`               | `0.0`                  |
    /// | `M`        | `N`          | `false`      | `false`               | `M/(M+N)`              |
    /// | `M`        | `0`          | `false`      | `true`                | `1.0`                  |
    ///
    /// The two-boolean discriminator pair `(is_empty, is_fully_verified)`
    /// is mutually exclusive and structurally disambiguates the empty-
    /// slice boundary (no verification-bearing outcomes counted) from the
    /// all-verified ceiling (every counted outcome substantiated a
    /// positive verdict) — both of which sit at the edge of
    /// [`verification_ratio`]'s range but carry distinct operational
    /// meaning. A downstream verifier that conditioned only on
    /// `verification_ratio() == 1.0` would silently accept the empty-slice
    /// case (where the `total == 0` guard returns `0.0`, not `1.0`, but
    /// the symmetry pin matters); conditioning on `is_fully_verified()`
    /// instead forces the verifier through the typed discriminator the
    /// empty case cannot satisfy.
    ///
    /// [`verification_ratio`]: VerificationCoverage::verification_ratio
    ///
    /// THEORY §VI.1 one-oracle discipline: the predicate is derived at
    /// one site (here), not re-inlined as `verification.verified > 0 &&
    /// verification.unverified == 0` per consumer. THEORY §V.4 / §VII.1
    /// honesty channel: the discriminator names "every verification-
    /// bearing probe substantiated a positive verdict," the load-bearing
    /// precondition the Phase 1 / Phase 2 strict admission gate
    /// fails-closed on at the orthogonal axis to [`ProbeCoverage::
    /// is_fully_covered`]'s "every probe produced evidence."
    pub fn is_fully_verified(&self) -> bool {
        self.verified > 0 && self.unverified == 0
    }

    /// True iff zero verification-bearing outcomes were counted —
    /// `total() == 0`. The structural boundary case
    /// [`verification_coverage`] over an empty iterator produces (the only
    /// [`VerificationCoverage`] value with `total() == 0`, since
    /// `verified` and `unverified` are both `usize` and non-negative).
    /// Distinguishes "no verification-bearing outcomes counted" from
    /// "every counted outcome unverified" — both collapse to the same
    /// [`verification_ratio`] == 0.0 arm, but a downstream verifier
    /// that wants to disambiguate (e.g., to treat the empty-slice case
    /// as a no-op while gating against the all-unverified case) reads
    /// [`is_empty`] directly rather than `verification.total() == 0` at
    /// each call site.
    ///
    /// The structural complement of [`is_fully_verified`]'s edge case:
    /// the two predicates partition the [`verification_ratio`] == 0.0 /
    /// [`verification_ratio`] == 1.0 boundary into the four mutually-
    /// exclusive arms tabulated on [`is_fully_verified`]. Mirrors the
    /// standard-collection [`Vec::is_empty`] / [`HashMap::is_empty`]
    /// idiom every pleme-io consumer already reaches for, and the
    /// orthogonal-axis peer [`ProbeCoverage::is_empty`] one impl group
    /// up.
    ///
    /// [`is_empty`]: VerificationCoverage::is_empty
    /// [`is_fully_verified`]: VerificationCoverage::is_fully_verified
    /// [`verification_ratio`]: VerificationCoverage::verification_ratio
    /// [`Vec::is_empty`]: std::vec::Vec::is_empty
    /// [`HashMap::is_empty`]: std::collections::HashMap::is_empty
    pub fn is_empty(&self) -> bool {
        self.total() == 0
    }

    /// True iff every counted verification-bearing outcome failed to
    /// substantiate a positive verdict — `verified == 0 && unverified > 0`.
    /// The orthogonal-axis peer of [`ProbeCoverage::is_all_absent`] at the
    /// verification-trustworthiness dimension: where the no-evidence-axis
    /// peer names "every counted probe surfaced the absent default,"
    /// this names "every counted verification-bearing probe surfaced its
    /// `Unverified` / `VerifyFailed` arm." The structural mirror of
    /// [`is_fully_verified`] (`verified > 0 && unverified == 0`): both
    /// predicates name an extreme arm of the four-arm `(verified,
    /// unverified)` matrix, bracketing the empty arm `(0, 0)` where
    /// neither holds.
    ///
    /// Names the operational floor today's
    /// [`compose_product_certification`] / [`compute_chart_attestation`]
    /// / [`compute_build_attestation`] call sites sit at: every counted
    /// `Verified`-bearing typed outcome (helm-release-signature,
    /// flux-source-verification, helm-provenance, cosign-image-signature,
    /// network-policy-admission) binds at its `Unverified` /
    /// `VerifyFailed` arm before the five probe sites wire real
    /// substantiations, so `verified == 0 && unverified == N` uniformly
    /// across the deployment / chart / build aggregates. The strict-
    /// production `sekiban` admission verifier fails closed on this
    /// state; the relaxed-staging gate also fails closed on it (since
    /// `has_evidence() == false` holds at the all-unverified floor); the
    /// typed discriminator a downstream verifier reads to gate Phase 1 /
    /// Phase 2 admission against this specific floor reads one bool —
    /// `verification.is_all_unverified()` — rather than re-deriving
    /// `verification.verified == 0 && verification.unverified > 0` per
    /// call site.
    ///
    /// The compounding shape: before this predicate, a downstream
    /// verifier wanting to reject "every counted verification failed"
    /// (the operational state forge's call sites sit at today) had to
    /// compose `!verification.is_empty() && verification.verification_ratio()
    /// == 0.0` at the consumer surface, mixing the float-form ratio's
    /// IEEE-754-imprecise equality comparison with the boundary-case
    /// predicate. After this predicate, the verifier reads one bool —
    /// `verification.is_all_unverified()` — and the integer-arithmetic
    /// body `verified == 0 && unverified > 0` forecloses the float-
    /// comparison drift class the consumer-side composition would
    /// inherit. Mirrors [`ProbeCoverage::is_all_absent`]'s integer-form
    /// foreclosure at the orthogonal axis exactly.
    ///
    /// The four reachable arms of the `(verified, unverified)` matrix
    /// resolve cleanly under the three named predicates: [`is_empty`]
    /// flags the empty arm `(0, 0)`, `is_all_unverified` flags the
    /// all-unverified arm `(0, N)`, [`is_fully_verified`] flags the
    /// fully-verified arm `(M, 0)`, and the mixed arm `(M, N)` with
    /// `M > 0 && N > 0` is the negation of all three. The three named
    /// predicates are pairwise mutually exclusive on every reachable
    /// [`VerificationCoverage`] value, mirroring the discipline
    /// [`ProbeCoverage::is_all_absent`] establishes at the orthogonal
    /// axis.
    ///
    /// Orthogonal to [`is_saturated`]: the all-unverified arm at
    /// `(verified: 0, unverified: usize::MAX)` is both
    /// `is_all_unverified() == true` AND `is_saturated() == true`. The
    /// predicate stays saturation-robust (the load-bearing tests are
    /// `verified == 0` and `unverified > 0`, not arithmetic on the sum)
    /// so a downstream verifier reading `is_all_unverified()` against
    /// the saturated state cannot drift the way `verification_ratio()
    /// == 0.0` would (which reads as `0.0` correctly here — the
    /// saturated `unverified` component does not poison the numerator —
    /// but the symmetric `{verified: usize::MAX, unverified: 0}` shape
    /// against `verification_ratio() == 1.0` would not be able to
    /// disambiguate "every counted outcome verified" from "the
    /// saturating clamp dropped equal substantiation at the ceiling").
    /// Mirrors [`ProbeCoverage::is_all_absent`]'s saturation-robust
    /// discipline at the orthogonal axis exactly.
    ///
    /// The structural complement of `!has_evidence()` is the disjunction
    /// of the two `verified == 0` arms ([`is_empty`] at `(0, 0)` and
    /// `is_all_unverified` at `(0, N)`); after this predicate, the two
    /// arms each carry an explicit typed name — `verification.is_empty()
    /// || verification.is_all_unverified()` is the load-bearing
    /// disjunction `!has_evidence()` collapses to one bool. A future
    /// parallel-axis sibling `compose_is_all_no_evidence(probe,
    /// verification)` returning `(probe.is_all_absent() ||
    /// probe.is_empty()) && (verification.is_all_unverified() ||
    /// verification.is_empty())` — the both-axes no-evidence floor the
    /// fleet-wide-aggregate `sekiban` admission gate consults — depends
    /// on this typed name existing at the verification axis.
    ///
    /// [`compose_product_certification`]: crate::commands::attestation::compose_product_certification
    /// [`compute_build_attestation`]: crate::commands::attestation::compute_build_attestation
    /// [`compute_chart_attestation`]: crate::commands::attestation::compute_chart_attestation
    /// [`is_empty`]: VerificationCoverage::is_empty
    /// [`is_fully_verified`]: VerificationCoverage::is_fully_verified
    /// [`is_saturated`]: VerificationCoverage::is_saturated
    ///
    /// THEORY.md §VI.1 one-oracle discipline: the predicate is derived
    /// at one site (here), not re-inlined as `!verification.is_empty()
    /// && verification.verification_ratio() == 0.0` per consumer (which
    /// would inherit the IEEE-754 imprecision the float-equality
    /// comparison admits at the saturated state). THEORY.md §V.4 /
    /// §VII.1 honesty channel: the discriminator names "every counted
    /// verification-bearing probe surfaced the honest no-substantiation
    /// arm," the load-bearing precondition the Phase 1 / Phase 2
    /// admission gate fails-closed on at today's call-site state,
    /// mirroring [`ProbeCoverage::is_all_absent`]'s discipline at the
    /// orthogonal axis exactly.
    pub fn is_all_unverified(&self) -> bool {
        self.verified == 0 && self.unverified > 0
    }

    /// True iff at least one counted verification-bearing outcome
    /// substantiated a positive verdict — `verified > 0`. The
    /// orthogonal-axis peer of [`ProbeCoverage::has_evidence`] at the
    /// verification-trustworthiness dimension: where the no-evidence-axis
    /// peer lifts the relaxed-staging gate's two-arm disjunction
    /// `is_mixed() || is_fully_covered()` over the `(ran, absent)` axis
    /// to one bool, this lifts the equivalent two-arm disjunction "mixed
    /// verification OR fully verified" over the `(verified, unverified)`
    /// axis to one bool. Before this predicate, a downstream
    /// `sekiban` admission verifier wanting to admit "any positive
    /// verification verdict was substantiated" (the relaxed-staging gate
    /// that admits both the some-verified-some-unverified intermediate
    /// arm AND the all-verified ceiling arm while rejecting the empty and
    /// all-unverified floors) had to compose
    /// `verification.verified > 0 && !verification.is_empty()` or
    /// equivalently `verification.verified > 0` at the consumer surface;
    /// after this predicate, the verifier reads one bool —
    /// `verification.has_evidence()` — and the integer-arithmetic body
    /// `self.verified > 0` collapses the disjunction at the typed-
    /// primitive surface.
    ///
    /// The structural complement of `!has_evidence()` is "no counted
    /// verification-bearing outcome substantiated a positive verdict" —
    /// the disjunction of the two `verified == 0` arms ([`is_empty`] at
    /// `(0, 0)` and the all-unverified floor at `(0, N)`), the
    /// operational floor today's
    /// [`crate::commands::attestation::compose_product_certification`] /
    /// [`crate::commands::attestation::compute_chart_attestation`] /
    /// [`crate::commands::attestation::compute_build_attestation`] call
    /// sites sit at before the five `Verified`-bearing typed outcomes
    /// wire real substantiations at their probe sites (every counted
    /// outcome currently surfaces an `Unverified` or `VerifyFailed` arm,
    /// so `verified == 0` uniformly). The relaxed-staging policy
    /// fails closed at `!has_evidence()` and admits everything above; the
    /// strict-production policy gates the additional ratio-and-
    /// trustworthiness composition `!is_saturated() &&
    /// is_fully_verified()` one layer up at
    /// [`is_admission_eligible_strict`].
    ///
    /// Symmetric to [`is_saturated`] in the orthogonality dimension:
    /// every reachable `VerificationCoverage` value carries an
    /// `(has_evidence, is_saturated)` two-bool pair the strict-production
    /// admission gate reads as `(true, false)` to admit, where the
    /// relaxed-staging gate reads only `has_evidence == true`.
    /// Saturation-robust by construction: the body is integer arithmetic
    /// against `verified` alone, so the post-saturation state
    /// `{verified: usize::MAX, unverified: 0}` correctly reads
    /// `has_evidence() == true` (every counted verification — even the
    /// dropped past-ceiling increments — cleared), and the post-
    /// saturation state `{verified: 0, unverified: usize::MAX}` correctly
    /// reads `has_evidence() == false` (no counted verification cleared).
    /// Mirrors [`ProbeCoverage::has_evidence`]'s saturation-robust
    /// discipline at the orthogonal axis exactly: both surfaces compose
    /// without a structural seam at the saturated state, the load-
    /// bearing precondition the future
    /// [`compose_has_evidence`](self)-style two-axis parallel-composed
    /// disjunction the [`compose_is_empty`] sibling already establishes
    /// the structural complement of (`compose_is_empty` is the AND of
    /// per-axis emptiness; the natural De Morgan dual is the OR of
    /// per-axis `has_evidence`, the precondition the fleet-wide
    /// relaxed-staging admission gate consults across both orthogonal
    /// axes).
    ///
    /// [`is_admission_eligible_strict`]: VerificationCoverage::is_admission_eligible_strict
    /// [`is_empty`]: VerificationCoverage::is_empty
    /// [`is_saturated`]: VerificationCoverage::is_saturated
    ///
    /// THEORY.md §VI.1 one-oracle discipline: the predicate is derived
    /// at one site (here), not re-inlined as `verification.verified > 0`
    /// per downstream consumer (which would inherit a drift class on the
    /// day a third intermediate arm is added — every consumer would need
    /// to extend their composition in lockstep, exactly the structural
    /// seam this helper forecloses, mirroring the discipline
    /// [`ProbeCoverage::has_evidence`] already establishes at the
    /// orthogonal axis). THEORY.md §V.4 / §VII.1 honesty channel: the
    /// discriminator names "at least one counted verification-bearing
    /// probe substantiated a positive verdict," the load-bearing
    /// precondition the relaxed-staging admission gate admits and the
    /// all-unverified-floor / empty-boundary failure case rejects,
    /// mirroring the no-evidence-axis peer's discipline at the
    /// orthogonal axis exactly.
    pub fn has_evidence(&self) -> bool {
        self.verified > 0
    }

    /// Fraction of counted verification-bearing outcomes that
    /// substantiated a positive verdict — `verified as f64 / total as
    /// f64` when `total > 0`, and `0.0` when `total == 0` (the empty-
    /// slice boundary case [`verification_coverage`] returns
    /// `VerificationCoverage { verified: 0, unverified: 0 }` for). The
    /// orthogonal-axis peer of [`ProbeCoverage::coverage_ratio`]: where
    /// `coverage_ratio` projects the no-evidence dimension over the full
    /// seventeen-outcome attestation pipeline, `verification_ratio`
    /// projects the verification-trustworthiness dimension over the
    /// five-outcome [`VerifiedOutcome`] subset.
    ///
    /// The structural distinction between "no verification-bearing
    /// outcomes counted" and "every counted outcome unverified" is
    /// preserved at the [`total`] field, not flattened into the ratio:
    /// a consumer that wants to disambiguate "no outcomes counted
    /// because the slice was empty" from "no outcomes counted because
    /// every outcome failed verification" reads `total() == 0` vs.
    /// `total() > 0 && verification_ratio() == 0.0` — the same
    /// disambiguator pattern [`ProbeCoverage::coverage_ratio`] admits at
    /// the orthogonal axis.
    ///
    /// The bare-f64 surface is the largest common shape a future
    /// telemetry emission site at `commands::attestation` cheaply
    /// admits — `tracing`'s `Visit` API records `f64` directly without
    /// the per-emission `unwrap_or` an `Option<f64>` surface would force
    /// at every call site (and without the structurally-divergent
    /// sentinel — `f64::NAN`, `-1.0`, `Empty` — each call site would
    /// otherwise pick). The empty-slice 0.0 collapse documented above is
    /// the load-bearing decision the test suite pins; the structural
    /// disambiguator stays at `total()`. Symmetric to
    /// [`ProbeCoverage::coverage_ratio`]'s decision at the orthogonal
    /// axis: the two ratio surfaces compose without a structural seam
    /// at the empty-input boundary.
    ///
    /// Lifts the derivation `verified as f64 / total as f64` from the
    /// downstream verifier the prior matrix-column reference gestured
    /// at to the composition site, so a future
    /// `*_verification_coverage_ratio` field a `sekiban` admission
    /// verifier (THEORY §V.4 / §VII.1 honesty channel) / Prometheus
    /// alert rule reads with one field-name pattern across build /
    /// chart / deployment attestation records — the same emission
    /// shape `*_probe_coverage_ratio` already carries at the orthogonal
    /// axis. THEORY §VI.1 one-oracle discipline: the ratio is derived
    /// at one site (here), not re-inlined as `verification.verified as
    /// f64 / verification.total() as f64` per consumer (which would
    /// admit the `verification.total() == 0` panic the `if total == 0`
    /// guard forecloses here, AND would force every consumer to
    /// re-derive the f64 cast).
    ///
    /// Saturation drift mirrors [`ProbeCoverage::coverage_ratio`]'s at
    /// the orthogonal axis: at the post-saturation state `{verified:
    /// usize::MAX, unverified: usize::MAX}` (reachable asymptotically
    /// via the saturating monoid [`Add`](std::ops::Add) impl), the true
    /// 0.5 ratio reads as 1.0 through the f64 division because [`total`]
    /// saturates at `usize::MAX` and the division collapses against the
    /// clamped ceiling. The orthogonal [`is_saturated`] flag — peer of
    /// [`ProbeCoverage::is_saturated`] at the verification axis — is the
    /// load-bearing trustworthiness signal a downstream verifier reads
    /// alongside this field; gating on
    /// `!is_saturated() && verification_ratio() >= 0.9` forecloses the
    /// post-saturation drift at the typed-primitive surface the same
    /// way the [`ProbeCoverage`] analogue already does.
    ///
    /// The integer-percent peer is [`verification_ratio_pct`]: the
    /// `u8` surface every Prometheus `*_verification_coverage_ratio_pct
    /// >= 90` alert rule / typed-policy threshold gate admits cheaply
    /// (integer arithmetic against an integer threshold, no IEEE-754
    /// epsilon drift at the `>= 0.9` decision boundary), mirroring the
    /// [`ProbeCoverage::coverage_ratio`] / [`ProbeCoverage::
    /// coverage_ratio_pct`] split at the no-evidence axis.
    ///
    /// [`is_saturated`]: VerificationCoverage::is_saturated
    /// [`total`]: VerificationCoverage::total
    /// [`verification_ratio_pct`]: VerificationCoverage::verification_ratio_pct
    pub fn verification_ratio(&self) -> f64 {
        let total = self.total();
        if total == 0 {
            0.0
        } else {
            self.verified as f64 / total as f64
        }
    }

    /// True iff at least one component has reached the saturating-add
    /// ceiling — `verified == usize::MAX || unverified == usize::MAX`.
    /// The orthogonal-axis peer of [`ProbeCoverage::is_saturated`]: the
    /// typed-primitive trustworthiness flag a downstream `sekiban`
    /// admission verifier reads to know the derived [`verification_ratio`]
    /// is unreliable. At every state this predicate returns `true`, the
    /// float division `verified as f64 / total() as f64` has dropped at
    /// least one true increment past the saturating clamp the monoid
    /// [`Add`](std::ops::Add) impl admits — the post-saturation state
    /// `{verified: usize::MAX, unverified: usize::MAX}` reads as
    /// `verification_ratio() == 1.0` against the true 0.5 ratio, exactly
    /// the drift class [`ProbeCoverage::is_saturated`] forecloses at the
    /// no-evidence axis.
    ///
    /// When the flag is `true`, the verifier falls back on the
    /// saturation-robust [`is_fully_verified`] (`unverified == 0` is the
    /// load-bearing test, not arithmetic on the sum) and [`is_empty`]
    /// (`total() == 0` is `false` at every saturated state since both
    /// components are non-negative and at least one is `usize::MAX`)
    /// discriminators. Symmetric to [`ProbeCoverage::is_saturated`]'s
    /// fallback to [`ProbeCoverage::is_fully_covered`] /
    /// [`ProbeCoverage::is_empty`] one impl group up.
    ///
    /// Orthogonal to the four-arm matrix the docstring on
    /// [`is_fully_verified`] tabulates: every reachable
    /// `VerificationCoverage` value sits at exactly one arm of `(is_empty,
    /// is_fully_verified, mixed, all-unverified)`, but every arm can
    /// independently be saturated or unsaturated. The empty arm
    /// `{verified: 0, unverified: 0}` is the only arm that is
    /// structurally unsaturated (both components are 0, neither at
    /// `usize::MAX`); the three non-empty arms each admit both a
    /// saturated and an unsaturated representative. Mirrors the
    /// [`ProbeCoverage::is_saturated`] orthogonality at the no-evidence
    /// axis exactly.
    ///
    /// The strict-production admission gate reads
    /// `!is_saturated() && is_fully_verified()` against the two flags
    /// — the same two-bool conjunction
    /// [`ProbeCoverage::is_admission_eligible_strict`] lifts at the
    /// no-evidence axis. The verification-axis peer
    /// [`is_admission_eligible_strict`] lifts this two-bool conjunction
    /// to one typed primitive, mirroring
    /// [`ProbeCoverage::is_admission_eligible_strict`] at the orthogonal
    /// axis.
    ///
    /// [`is_admission_eligible_strict`]: VerificationCoverage::is_admission_eligible_strict
    ///
    /// THEORY.md §VI.1 one-oracle discipline: the saturation predicate
    /// is derived at one site (here), not re-inlined as
    /// `verification.verified == usize::MAX || verification.unverified
    /// == usize::MAX` per downstream telemetry consumer. THEORY.md
    /// §V.4 / §VII.1 honesty channel: the verification-axis honesty
    /// signal surfaces both the verification ratio AND its
    /// trustworthiness — a downstream verifier that gated only on
    /// `verification_ratio() >= 0.9` (or its integer peer
    /// [`verification_ratio_pct`] `>= 90`) would silently accept the
    /// `{verified: MAX, unverified: MAX}` post-saturation state (true
    /// 0.5 ratio reading as 1.0 / 100); gating on `!is_saturated() &&
    /// verification_ratio() >= 0.9` (or the integer-form
    /// `!is_saturated() && verification_ratio_pct() >= 90`) instead
    /// forecloses that drift class at the typed-primitive surface,
    /// mirroring [`ProbeCoverage::is_saturated`]'s discipline at the
    /// orthogonal axis.
    ///
    /// [`is_empty`]: VerificationCoverage::is_empty
    /// [`is_fully_verified`]: VerificationCoverage::is_fully_verified
    /// [`verification_ratio`]: VerificationCoverage::verification_ratio
    /// [`verification_ratio_pct`]: VerificationCoverage::verification_ratio_pct
    pub fn is_saturated(&self) -> bool {
        self.verified == usize::MAX || self.unverified == usize::MAX
    }

    /// Verification fraction as an integer percent in `0..=100`. Returns
    /// `0` for the empty-slice boundary case (`total() == 0`), and
    /// `(verified * 100) / total()` (Euclidean floor) for every
    /// reachable non-empty value. The orthogonal-axis peer of
    /// [`ProbeCoverage::coverage_ratio_pct`]: where the no-evidence-axis
    /// peer projects the `(ran, absent)` percent over the seventeen-
    /// outcome attestation pipeline, this projects the
    /// `(verified, unverified)` percent over the five-outcome
    /// [`VerifiedOutcome`] subset.
    ///
    /// The companion of [`verification_ratio`]: the float surface is the
    /// largest common shape every `tracing::Visit::record_f64` consumer
    /// admits cheaply, the integer surface is the largest common shape
    /// every Prometheus `*_verification_coverage_ratio_pct >= 90` alert
    /// rule / typed-policy threshold gate admits cheaply (integer
    /// arithmetic against an integer threshold, no IEEE-754 epsilon
    /// drift at the decision boundary `>= 0.9` floats imprecisely
    /// surface — `0.9_f64` is `0.8999...` under the binary fraction, so
    /// a fleet-wide aggregator summing per-record ratios across N
    /// records reads `N * 0.9_f64` against an `N * 0.9_f64 + epsilon`
    /// threshold and may admit or reject the same evidence depending on
    /// N). The integer surface forecloses that drift class at the
    /// typed-primitive site, parallel to
    /// [`ProbeCoverage::coverage_ratio_pct`]'s discipline one impl group
    /// up.
    ///
    /// Routes through `u128` arithmetic to foreclose overflow at the
    /// `verified * 100` multiplication — `usize::MAX * 100` overflows
    /// `u128` only at `u128::MAX / 100 ≈ 3.4e34`, well above the
    /// `usize::MAX ≈ 1.8e19` (64-bit) reach of the saturating monoid
    /// `Add`, so the integer arithmetic is total over every reachable
    /// `VerificationCoverage` value. The post-saturation state
    /// `{verified: MAX, unverified: MAX}` reads `100` here (the true
    /// 0.5 ratio is dropped past the saturating clamp, same drift as
    /// [`verification_ratio`]'s float reading of `1.0`); the orthogonal
    /// [`is_saturated`] flag is the load-bearing trustworthiness signal
    /// a downstream verifier reads alongside this field to gate on
    /// `!is_saturated() && verification_ratio_pct() >= 90` against the
    /// post-saturation drift, mirroring
    /// [`ProbeCoverage::coverage_ratio_pct`]'s discipline at the
    /// orthogonal axis.
    ///
    /// The cast to `u8` is structurally lossless: the quotient
    /// `(verified * 100) / total <= 100` by construction (`verified <=
    /// total` since `total = verified + unverified` componentwise with
    /// both components non-negative), so the result always fits in
    /// `u8`. A regression that hand-rolled the body with `* 100` BEFORE
    /// the division (the post-overflow form `(self.verified * 100) /
    /// self.total()` in `usize` arithmetic) would panic at any
    /// `verified > usize::MAX / 100` in debug and silently wrap in
    /// release — both arms closed at the `u128` cast.
    ///
    /// THEORY.md §VI.1 one-oracle discipline: the percent form is
    /// derived at one site (here), not re-inlined as `(verification.
    /// verified as f64 / verification.total() as f64 * 100.0) as u8`
    /// per consumer (which would inherit the float-imprecision drift at
    /// the `0.9_f64` boundary the no-evidence-axis peer's docstring
    /// names). THEORY.md §V.4 / §VII.1 honesty channel: the
    /// verification-axis honesty signal now surfaces both the float and
    /// the integer ratio forms — a downstream verifier reads whichever
    /// shape its admission gate's threshold representation aligns with,
    /// without re-deriving the conversion at the consumer surface.
    ///
    /// [`is_saturated`]: VerificationCoverage::is_saturated
    /// [`verification_ratio`]: VerificationCoverage::verification_ratio
    pub fn verification_ratio_pct(&self) -> u8 {
        let total = self.total();
        if total == 0 {
            return 0;
        }
        let verified = self.verified as u128;
        let total = total as u128;
        ((verified * 100) / total) as u8
    }

    /// True iff every counted verification-bearing probe substantiated a
    /// positive verification verdict AND the verification signal is
    /// trustworthy — the typed primitive for the strict-production
    /// admission gate the [`is_saturated`] / [`is_fully_verified`]
    /// docstrings have named since the saturation flag landed at the
    /// verification axis: a downstream `sekiban` admission verifier
    /// wanting to admit only records whose verification channel both
    /// fully cleared AND whose derived ratio surfaces are reliable
    /// composes `!is_saturated() && is_fully_verified()` at the consumer
    /// surface. Before this predicate, every strict-production gate at
    /// the verification axis had to retype that two-bool conjunction.
    /// After this predicate, the gate reads one bool —
    /// `verification.is_admission_eligible_strict()` — and the
    /// integer-arithmetic body collapses the two-bool composition at the
    /// typed-primitive surface.
    ///
    /// The orthogonal-axis peer of
    /// [`ProbeCoverage::is_admission_eligible_strict`]: where the
    /// no-evidence-axis peer reads `!is_saturated() &&
    /// is_fully_covered()` over the seventeen-outcome attestation
    /// pipeline (the `(ran, absent)` axis), this reads `!is_saturated()
    /// && is_fully_verified()` over the five-outcome [`VerifiedOutcome`]
    /// subset (the `(verified, unverified)` axis). The two strict gates
    /// compose in parallel against the same record at the same emission
    /// site — the strict-production admission verifier reads
    /// `probe.is_admission_eligible_strict() &&
    /// verification.is_admission_eligible_strict()` to gate on "every
    /// probe ran AND every verification cleared AND both signals are
    /// trustworthy," the load-bearing four-way conjunction the
    /// typed-primitive surface now collapses to a two-bool consumer
    /// shape (one bool per orthogonal axis, not four — the inner
    /// trustworthiness clamps are sealed at the typed-primitive site).
    ///
    /// Saturation-robust by construction: [`is_fully_verified`] reads
    /// `unverified == 0 && verified > 0` against the components
    /// themselves (never against derived arithmetic), so the
    /// post-saturation state `{verified: usize::MAX, unverified: 0}` is
    /// structurally `is_fully_verified() == true` BUT `is_saturated() ==
    /// true`, so the conjunction correctly rejects (`true && !true ==
    /// false`) — the saturated state cannot pass the strict gate even
    /// though every counted verification (up to the ceiling) cleared.
    /// This is the load-bearing trustworthiness clamp: the float-form
    /// [`verification_ratio`] and the integer-form
    /// [`verification_ratio_pct`] both round to `1.0` / `100` at
    /// `{verified: MAX, unverified: 0}` and against the true ratio at
    /// `{verified: MAX, unverified: MAX}` — the strict gate forecloses
    /// both drift classes uniformly through the `!is_saturated()`
    /// factor, mirroring [`ProbeCoverage::is_admission_eligible_strict`]'s
    /// discipline at the orthogonal axis exactly.
    ///
    /// At every reachable `(verified, unverified)` value, the predicate
    /// equals the documented consumer composition exactly — the
    /// structural equivalence
    /// `is_admission_eligible_strict() == (!is_saturated() &&
    /// is_fully_verified())`
    /// is pinned across the empty / all-unverified / mixed /
    /// fully-verified arms AND each of the three saturated
    /// representatives by
    /// [`test_verification_is_admission_eligible_strict_equals_documented_composition`].
    ///
    /// [`is_fully_verified`]: VerificationCoverage::is_fully_verified
    /// [`is_saturated`]: VerificationCoverage::is_saturated
    /// [`verification_ratio`]: VerificationCoverage::verification_ratio
    /// [`verification_ratio_pct`]: VerificationCoverage::verification_ratio_pct
    ///
    /// THEORY.md §VI.1 one-oracle discipline: the strict-production
    /// verification-axis admission predicate is derived at one site
    /// (here), not re-inlined as `!verification.is_saturated() &&
    /// verification.is_fully_verified()` per downstream consumer.
    /// THEORY.md §V.4 / §VII.1 honesty channel: the strict gate names
    /// "complete AND trustworthy verification," the load-bearing
    /// precondition the strict-production admission gate admits at the
    /// verification axis, mirroring the no-evidence-axis peer's
    /// discipline at the orthogonal axis.
    ///
    /// The parallel-composed peer at the two-axis surface is
    /// [`compose_admission_eligible_strict`], which seals the
    /// four-way conjunction across both orthogonal axes at one site
    /// so a downstream strict-production verifier reads one bool
    /// across both axes rather than composing
    /// `probe.is_admission_eligible_strict() &&
    /// verification.is_admission_eligible_strict()` at the consumer
    /// surface.
    pub fn is_admission_eligible_strict(&self) -> bool {
        !self.is_saturated() && self.is_fully_verified()
    }
}

/// Componentwise `usize::saturating_add` over [`VerificationCoverage`] —
/// `(a.verified + b.verified, a.unverified + b.unverified)`. The
/// structural monoid `(VerificationCoverage, +, default())` lifts the
/// per-phase verification-trustworthiness signal a future emission site
/// at `commands::attestation` will produce (the Phase 1 flux-source /
/// helm-release-signature shape composed with the Phase 2 helm-
/// provenance / cosign / network-policy shape) to a single product-
/// level signal a downstream verifier can compose with `[build, chart,
/// deployment].iter().copied().sum::<VerificationCoverage>()` — one
/// site, not per-field-summed at every downstream consumer (THEORY
/// §VI.1 one-oracle discipline). The orthogonal-axis peer of the
/// [`ProbeCoverage`] monoid one impl group up: the two monoids compose
/// in parallel against the same record, surfacing the
/// no-evidence-dimension aggregate and the verification-trustworthiness-
/// dimension aggregate at the same product-level emission site.
///
/// `saturating_add` rather than the panicking `+` is the load-bearing
/// arithmetic: a fleet-wide aggregator summing the per-record coverage
/// across every Phase 1 / Phase 2 verification-bearing record (multi-
/// product, multi-cluster, multi-environment) cannot panic on overflow
/// at `usize::MAX` — the saturating ceiling preserves the monoid's
/// totality (every pair of `VerificationCoverage` values has a defined
/// sum) where the unchecked addition would surface a panic on the
/// pathological aggregate (1 << 64 verification records on a 64-bit
/// target, realistically unreachable but structurally foreclosed here),
/// composing with the [`VerificationCoverage::total`] saturating
/// ceiling one impl up so the post-`Add` state can be handed to
/// `total()` without re-introducing the panic the sibling impl already
/// foreclosed.
impl std::ops::Add for VerificationCoverage {
    type Output = VerificationCoverage;

    fn add(self, rhs: Self) -> Self::Output {
        VerificationCoverage {
            verified: self.verified.saturating_add(rhs.verified),
            unverified: self.unverified.saturating_add(rhs.unverified),
        }
    }
}

/// In-place sibling of [`Add`](std::ops::Add) above. The `*self = *self
/// + rhs` body reuses the `Copy` derive on [`VerificationCoverage`]
/// (the type is two `usize`s — trivially copyable) so the assign form
/// is a one-line delegation that cannot drift from the `Add` semantics.
/// Mirrors [`ProbeCoverage`]'s `AddAssign` at the orthogonal axis.
impl std::ops::AddAssign for VerificationCoverage {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

/// Owned-iterator [`Sum`] impl: `iter.fold(default(), Add::add)`. Lifts
/// a `Vec<VerificationCoverage>` / `[VerificationCoverage; N]` /
/// `impl Iterator<Item = VerificationCoverage>` to a single aggregate
/// value the downstream telemetry emission site can hand to
/// `tracing::info!` alongside the per-phase fields. The empty-iterator
/// case returns [`VerificationCoverage::default`] (0 verified, 0
/// unverified) — the same empty-slice boundary [`verification_coverage`]
/// returns, so the two surfaces compose without a structural seam at
/// the empty-input boundary.
impl std::iter::Sum for VerificationCoverage {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::default(), std::ops::Add::add)
    }
}

/// Borrowed-iterator [`Sum`] impl: lets a `&[VerificationCoverage]`
/// borrow reach `.iter().sum::<VerificationCoverage>()` without an
/// explicit `.copied()` at the call site — the idiomatic shape every
/// other numeric `Sum` in `std` already admits (`<i64 as Sum<&'a i64>>`
/// etc.). The delegation through `.copied()` reuses the `Copy` derive
/// on [`VerificationCoverage`] so the borrowed form cannot drift from
/// the owned `Sum` semantics one impl up. Mirrors [`ProbeCoverage`]'s
/// borrowed `Sum` at the orthogonal axis.
impl<'a> std::iter::Sum<&'a VerificationCoverage> for VerificationCoverage {
    fn sum<I: Iterator<Item = &'a VerificationCoverage>>(iter: I) -> Self {
        iter.copied().sum()
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

/// Parallel-composed strict-production admission predicate over the two
/// orthogonal typed-primitive surfaces — the four-way conjunction
/// `!probe.is_saturated() && probe.is_fully_covered() &&
/// !verification.is_saturated() && verification.is_fully_verified()`
/// collapsed to one bool at one site. Reads `true` iff EVERY counted
/// probe ran (no-evidence axis fully covered), EVERY counted
/// verification cleared (verification-trustworthiness axis fully
/// verified), AND BOTH derived-ratio surfaces are trustworthy (neither
/// component reached the `usize::saturating_add` ceiling).
///
/// The natural follow-up commit 05eee86 named: where
/// [`ProbeCoverage::is_admission_eligible_strict`] (commit e25a22e)
/// and [`VerificationCoverage::is_admission_eligible_strict`] (commit
/// 05eee86) each seal the two-bool conjunction at one orthogonal axis,
/// this seals the four-way conjunction across both axes at one site.
/// A downstream `sekiban` strict-production admission verifier reads
/// one bool — `compose_admission_eligible_strict(&probe, &verification)`
/// — rather than composing the two-bool per-axis surface
/// `probe.is_admission_eligible_strict() &&
/// verification.is_admission_eligible_strict()` at every consumer.
/// Before this helper, every strict-production gate had to retype the
/// two-bool consumer composition (with the drift class a regression
/// that dropped one axis silently admits the one-axis-failing state
/// the documented gate refuses); after this helper, the gate reads
/// one bool and the parallel-axis composition is sealed at the
/// typed-primitive surface.
///
/// Saturation-robust by construction: each per-axis
/// `is_admission_eligible_strict` integrates its own `!is_saturated()`
/// trustworthiness clamp at the typed-primitive site (see commits
/// e25a22e and 05eee86), so the parallel composition inherits both
/// clamps automatically — neither axis can drift by dropping its
/// saturation factor. The post-saturation state
/// `{ran: usize::MAX, absent: 0}` on the no-evidence axis OR
/// `{verified: usize::MAX, unverified: 0}` on the verification axis
/// — each of which surfaces the derived ratio as `1.0` / `100`
/// honestly against the counted increments BUT against the true
/// ratio loses past-ceiling increments — fails the composition
/// through its respective axis's strict gate.
///
/// At every reachable `(probe, verification)` pair, the predicate
/// equals the documented two-axis composition exactly — the
/// structural equivalence
/// `compose_admission_eligible_strict(p, v) ==
/// (p.is_admission_eligible_strict() && v.is_admission_eligible_strict())`
/// is pinned across the cross product of per-axis representatives
/// by [`tests::test_compose_admission_eligible_strict_equals_documented_composition`].
///
/// THEORY.md §VI.1 one-oracle discipline: the four-way conjunction is
/// derived at one site (here), not re-inlined as `probe.<axis-strict>()
/// && verification.<axis-strict>()` per downstream consumer (which
/// would inherit a drift class on the day a third orthogonal axis is
/// added — every consumer would need to extend their composition in
/// lockstep, exactly the structural seam this helper forecloses).
/// THEORY.md §V.4 / §VII.1 honesty channel: the strict-production
/// admission verdict surfaces at the typed-primitive surface as a
/// single bool reading "complete AND trustworthy evidence on BOTH
/// orthogonal axes" — the load-bearing precondition the strict-
/// production admission gate admits and every other arm
/// (any-axis-empty, any-axis-mixed, any-axis-saturated) rejects.
///
/// Frontier lineage: SLSA L3+ admission policy gates partition the
/// admission decision into per-axis predicates (build-provenance,
/// source-integrity, package-signature, runtime-attestation) so the
/// gate composition is auditably "every axis admits AND every axis
/// is trustworthy" — exactly the parallel-composed shape this helper
/// lifts at the typed-primitive surface. Sigstore's policy
/// controller reads the verification verdict through a single
/// typed-primitive surface that integrates both the verdict AND its
/// trustworthiness so a downstream verifier cannot drift by dropping
/// a trustworthiness factor; this helper lifts the same discipline
/// across the two-axis composition.
#[allow(dead_code)]
pub fn compose_admission_eligible_strict(
    probe: &ProbeCoverage,
    verification: &VerificationCoverage,
) -> bool {
    probe.is_admission_eligible_strict() && verification.is_admission_eligible_strict()
}

/// Parallel-composed trustworthiness-broken predicate over the two
/// orthogonal typed-primitive surfaces — the two-bool disjunction
/// `probe.is_saturated() || verification.is_saturated()` collapsed to
/// one bool at one site. Reads `true` iff AT LEAST ONE counted axis
/// has reached its saturating-add ceiling, meaning the derived ratio
/// surface on that axis ([`ProbeCoverage::coverage_ratio`] /
/// [`ProbeCoverage::coverage_ratio_pct`] on the no-evidence axis,
/// [`VerificationCoverage::verification_ratio`] /
/// [`VerificationCoverage::verification_ratio_pct`] on the
/// verification axis) no longer carries a trustworthy reading against
/// past-ceiling increments. The structural dual of
/// [`compose_admission_eligible_strict`]: where the strict gate is the
/// four-way conjunction `complete AND trustworthy on BOTH axes`, this
/// is the disjunction `untrustworthy on AT LEAST ONE axis` — the
/// negation `!compose_is_saturated(probe, verification)` reads `true`
/// iff BOTH axes are trustworthy, which is exactly the
/// trustworthiness factor pair the strict gate integrates as
/// `!probe.is_saturated() && !verification.is_saturated()`.
///
/// The orthogonal-axis peer of the two per-axis [`is_saturated`]
/// predicates: where each per-axis predicate collapses the two-bool
/// `ran/verified == usize::MAX || absent/unverified == usize::MAX`
/// disjunction at one orthogonal axis to one bool at the
/// typed-primitive surface (commits 23fc103 and 70fa38a), this
/// collapses the two-bool axis-level disjunction `probe.is_saturated()
/// || verification.is_saturated()` across both axes to one bool at one
/// site. A downstream consumer emitting an aggregate-trustworthiness
/// telemetry field across both axes (the natural follow-up to the
/// per-axis `*_probes_saturated` / `*_verifications_saturated` fields
/// the `emit_probe_coverage!` macro family will extend) reads one bool
/// — `compose_is_saturated(&probe, &verification)` — rather than
/// composing the two-bool per-axis surface at every consumer. Before
/// this helper, every aggregate-trustworthiness emitter had to retype
/// the two-bool consumer composition (with the drift class a
/// regression that dropped one axis silently reads the
/// one-axis-saturated state as trustworthy); after this helper, the
/// emitter reads one bool and the parallel-axis composition is sealed
/// at the typed-primitive surface so a future third orthogonal axis
/// (e.g., a compliance-dimensions axis the
/// [`crate::compliance_dimensions`] family hints at) extends the
/// composition here, not at every downstream consumer in lockstep.
///
/// Disjunction (not conjunction) is structurally load-bearing here:
/// trustworthiness is the AND of per-axis trustworthiness factors,
/// untrustworthiness (its negation) is the OR of per-axis
/// untrustworthiness factors by De Morgan — saturation on ANY axis is
/// enough to break the aggregate's trustworthiness, exactly as
/// saturation on ANY component (`ran` OR `absent`) is enough to break
/// the per-axis trustworthiness one impl group up. A regression that
/// composed the conjunction `probe.is_saturated() &&
/// verification.is_saturated()` would silently admit the
/// one-axis-saturated state as trustworthy (the drift class this
/// helper exists to foreclose).
///
/// At every reachable `(probe, verification)` pair, the predicate
/// equals the documented two-axis composition exactly — the
/// structural equivalence
/// `compose_is_saturated(p, v) == (p.is_saturated() ||
/// v.is_saturated())`
/// is pinned across the cross product of per-axis representatives by
/// [`tests::test_compose_is_saturated_equals_documented_composition`].
/// The negation `!compose_is_saturated(p, v) == (!p.is_saturated() &&
/// !v.is_saturated())` is the De Morgan peer the strict gate's
/// trustworthiness factor reads — pinned at
/// [`tests::test_compose_is_saturated_negation_matches_strict_trustworthiness_factor`].
///
/// THEORY.md §VI.1 one-oracle discipline: the two-axis
/// trust-broken disjunction is derived at one site (here), not
/// re-inlined as `probe.is_saturated() || verification.is_saturated()`
/// per downstream consumer (which would inherit a drift class on the
/// day a third orthogonal axis is added — every consumer would need
/// to extend their composition in lockstep, exactly the structural
/// seam this helper forecloses, mirroring the discipline
/// [`compose_admission_eligible_strict`] establishes for the
/// complementary `complete AND trustworthy` gate). THEORY.md §V.4 /
/// §VII.1 honesty channel: the aggregate-trustworthiness surface
/// reads one bool naming "the derived ratio is unreliable on AT LEAST
/// ONE orthogonal axis," the load-bearing precondition the
/// fleet-wide aggregate-ratio emitter consults before publishing a
/// derived ratio across both axes. The negation reads "BOTH ratios
/// are reliable" — the typed-primitive precondition any aggregate
/// derived ratio across the two axes requires to be a faithful
/// reading of the true counts.
///
/// Frontier lineage: Bazel's `--remote_cache_ttl` / Buck2's remote-
/// cache `validity` field surface a per-cache trust flag the build-
/// invocation gate consults before consuming a cache hit; SLSA L3+'s
/// provenance-validity gate composes per-source-of-evidence trust
/// flags as a disjunction (any source past its validity window
/// breaks the aggregate trust) mirroring the discipline this helper
/// lifts at the typed-primitive surface for the two-axis coverage
/// trustworthiness factor pair. Sigstore's policy controller reads
/// per-attestation freshness flags as a disjunction (any attestation
/// past its expiration breaks the aggregate trust); this helper
/// lifts the same discipline across the two-axis composition.
///
/// [`is_saturated`]: ProbeCoverage::is_saturated
#[allow(dead_code)]
pub fn compose_is_saturated(probe: &ProbeCoverage, verification: &VerificationCoverage) -> bool {
    probe.is_saturated() || verification.is_saturated()
}

/// Parallel-composed vacuous-aggregate predicate over the two
/// orthogonal typed-primitive surfaces — the two-bool conjunction
/// `probe.is_empty() && verification.is_empty()` collapsed to one bool
/// at one site. Reads `true` iff EVERY counted axis surfaced zero
/// records, meaning the fleet-wide aggregate carries no evidence on
/// either dimension: the no-evidence axis ([`ProbeCoverage`] over the
/// seventeen-outcome attestation pipeline) and the
/// verification-trustworthiness axis ([`VerificationCoverage`] over the
/// five-outcome [`VerifiedOutcome`] subset) are both at the structural
/// boundary [`probe_coverage`] / [`verification_coverage`] return for
/// the empty-iterator input.
///
/// The structural peer of [`compose_admission_eligible_strict`] /
/// [`compose_is_saturated`] at the empty-aggregate axis: where the
/// strict gate (commit 7d818bd) is the four-way conjunction "complete
/// AND trustworthy on BOTH axes" and the trust-broken disjunction
/// (commit 2ea2240) is "untrustworthy on AT LEAST ONE axis", this is
/// the structural boundary "vacuous on BOTH axes" — the load-bearing
/// boundary case the fleet-wide aggregate-ratio emission site at
/// `commands::attestation` reads to gate "emit derived ratio fields
/// honestly" vs. "the aggregate is structurally vacuous; the derived
/// ratio surfaces are no-ops". Conjunction (not disjunction) is
/// structurally load-bearing here: the aggregate is vacuous only when
/// NEITHER axis carries records — if either axis surfaced even one
/// record, that axis's ratio surface ([`ProbeCoverage::coverage_ratio`]
/// / [`VerificationCoverage::verification_ratio`]) is a meaningful
/// reading. A regression that composed the disjunction
/// `probe.is_empty() || verification.is_empty()` would silently classify
/// the one-axis-empty / one-axis-populated state as vacuous (the drift
/// class this helper exists to foreclose), suppressing telemetry from
/// the populated axis.
///
/// The orthogonal-axis peer of the two per-axis [`is_empty`]
/// predicates: where each per-axis predicate collapses the
/// `total() == 0` boundary at one orthogonal axis to one bool at the
/// typed-primitive surface, this collapses the two-bool axis-level
/// conjunction `probe.is_empty() && verification.is_empty()` across
/// both axes to one bool at one site. A downstream consumer emitting
/// an aggregate-vacuous telemetry field across both axes (the natural
/// follow-up to the per-axis `*_probes_empty` /
/// `*_verifications_empty` fields the `emit_probe_coverage!` macro
/// family will extend) reads one bool —
/// `compose_is_empty(&probe, &verification)` — rather than composing
/// the two-bool per-axis surface at every consumer. Before this
/// helper, every aggregate-vacuous emitter had to retype the two-bool
/// consumer composition (with the drift class a regression that
/// disjuncted the per-axis flags silently admits the
/// one-axis-empty-one-axis-populated state as vacuous); after this
/// helper, the emitter reads one bool and the parallel-axis
/// composition is sealed at the typed-primitive surface so a future
/// third orthogonal axis (e.g., a compliance-dimensions axis the
/// [`crate::compliance_dimensions`] family hints at) extends the
/// composition here, not at every downstream consumer in lockstep.
///
/// Saturation-robust by construction: each per-axis `is_empty()` reads
/// `total() == 0` against the components themselves; the
/// `usize::saturating_add` clamp the monoid [`Add`](std::ops::Add)
/// impl admits cannot reach `total() == 0` from any non-empty state
/// (both components are non-negative, and saturating-add only ever
/// increases a non-negative sum or clamps it at `usize::MAX`). The
/// post-saturation state `{ran: usize::MAX, absent: 0}` /
/// `{verified: usize::MAX, unverified: 0}` is structurally `is_empty()
/// == false` on its respective axis, so the saturated-but-vacuous
/// drift class is foreclosed at the typed-primitive surface.
///
/// At every reachable `(probe, verification)` pair, the predicate
/// equals the documented two-axis composition exactly — the
/// structural equivalence
/// `compose_is_empty(p, v) == (p.is_empty() && v.is_empty())`
/// is pinned across the cross product of per-axis representatives by
/// [`tests::test_compose_is_empty_equals_documented_composition`].
///
/// THEORY.md §VI.1 one-oracle discipline: the two-axis
/// vacuous-aggregate conjunction is derived at one site (here), not
/// re-inlined as `probe.is_empty() && verification.is_empty()` per
/// downstream consumer (which would inherit a drift class on the day
/// a third orthogonal axis is added — every consumer would need to
/// extend their composition in lockstep, exactly the structural seam
/// this helper forecloses, mirroring the discipline
/// [`compose_admission_eligible_strict`] and [`compose_is_saturated`]
/// establish for the complementary gates). THEORY.md §V.4 / §VII.1
/// honesty channel: the aggregate-vacuous surface reads one bool
/// naming "the aggregate carries zero records on EVERY orthogonal
/// axis," the load-bearing precondition the fleet-wide aggregate-
/// ratio emitter consults before emitting a derived ratio across
/// both axes — at the vacuous-aggregate state, the derived ratio
/// surfaces are structurally no-ops (both [`ProbeCoverage::
/// coverage_ratio`] and [`VerificationCoverage::verification_ratio`]
/// collapse to `0.0` at the empty-arm via their `if total == 0`
/// guards), so the emitter typically suppresses the field or annotates
/// it as the vacuous-aggregate boundary case.
///
/// Frontier lineage: Bazel's `--build_event_stream` / Buck2's
/// build-event surface a structural "no records" boundary distinct
/// from the "all records cleared" boundary — the empty-aggregate
/// case is a no-op in their telemetry, not a degenerate "all pass"
/// reading. SLSA L3+'s provenance-attestation gate distinguishes
/// "no attestations produced" (structurally vacuous, gate fails-
/// closed by absence) from "every attestation cleared" (gate
/// admits); this helper lifts the same distinction at the two-axis
/// typed-primitive surface. Sigstore's policy controller surfaces
/// "no attestations matched the policy" as a distinct boundary the
/// admission gate reads separately from "every matched attestation
/// cleared"; this helper lifts the same discipline across the two-
/// axis composition.
///
/// [`is_empty`]: ProbeCoverage::is_empty
#[allow(dead_code)]
pub fn compose_is_empty(probe: &ProbeCoverage, verification: &VerificationCoverage) -> bool {
    probe.is_empty() && verification.is_empty()
}

/// Parallel-composed both-axes-complete predicate over the two
/// orthogonal typed-primitive surfaces — the two-bool conjunction
/// `probe.is_fully_covered() && verification.is_fully_verified()`
/// collapsed to one bool at one site. Reads `true` iff EVERY counted
/// probe ran (no-evidence axis fully covered: `ran > 0 && absent == 0`)
/// AND EVERY counted verification cleared (verification-trustworthiness
/// axis fully verified: `verified > 0 && unverified == 0`). The
/// structural complement of [`compose_is_empty`] at the other end of the
/// totality axis: where [`compose_is_empty`] flags the both-axes-vacuous
/// boundary `({ran: 0, absent: 0}, {verified: 0, unverified: 0})`, this
/// flags the both-axes-complete boundary where every counted record on
/// every axis surfaced its honest-positive arm.
///
/// The structural peer of [`compose_admission_eligible_strict`] /
/// [`compose_is_saturated`] / [`compose_is_empty`] at the
/// both-axes-complete axis: where the strict gate (commit 7d818bd) is
/// the four-way conjunction "complete AND trustworthy on BOTH axes",
/// the trust-broken disjunction (commit 2ea2240) is "untrustworthy on AT
/// LEAST ONE axis", and the vacuous-aggregate conjunction (commit
/// a50a371) is "vacuous on BOTH axes", this is the completeness factor
/// of the strict gate: "complete on BOTH axes" — the load-bearing
/// decomposition factor a downstream verifier reads to separate the
/// completeness reading from the trustworthiness reading at the
/// composed-axis surface. The four helpers close the parallel-axis
/// compose family across both axes: AND of completeness, AND of
/// strict admission, OR of saturation, AND of emptiness — the four
/// structural arms the two-axis admission decomposition surfaces.
///
/// Conjunction (not disjunction) is structurally load-bearing here:
/// completeness is the AND of per-axis completeness — every counted
/// axis must surface its fully-covered/fully-verified arm for the
/// composed reading to admit. A regression that composed the
/// disjunction `probe.is_fully_covered() || verification.is_fully_verified()`
/// would silently admit the one-axis-incomplete state as "complete"
/// (the drift class this helper exists to foreclose), surfacing a
/// false completeness reading at every downstream consumer that gates
/// on the composed bool.
///
/// The orthogonal-axis peer of the two per-axis [`is_fully_covered`] /
/// [`is_fully_verified`] predicates: where each per-axis predicate
/// collapses its component-level two-condition shape at one orthogonal
/// axis to one bool at the typed-primitive surface, this collapses the
/// two-bool axis-level conjunction `probe.is_fully_covered() &&
/// verification.is_fully_verified()` across both axes to one bool at
/// one site. A downstream consumer emitting an aggregate-completeness
/// telemetry field across both axes (the natural follow-up to the
/// per-axis `*_probes_fully_covered` / `*_verifications_fully_verified`
/// fields the `emit_probe_coverage!` macro family will extend) reads
/// one bool — `compose_is_fully_complete(&probe, &verification)` —
/// rather than composing the two-bool per-axis surface at every
/// consumer. Before this helper, every aggregate-completeness emitter
/// had to retype the two-bool consumer composition (with the drift
/// class a regression that disjuncted the per-axis flags silently
/// reads the one-axis-incomplete state as complete); after this
/// helper, the emitter reads one bool and the parallel-axis
/// composition is sealed at the typed-primitive surface so a future
/// third orthogonal axis (e.g., a compliance-dimensions axis the
/// [`crate::compliance_dimensions`] family hints at) extends the
/// composition here, not at every downstream consumer in lockstep.
///
/// The load-bearing decomposition `compose_admission_eligible_strict(p,
/// v) == compose_is_fully_complete(p, v) && !compose_is_saturated(p, v)`
/// separates the two orthogonal admission factors at the composed-axis
/// surface: completeness ("every counted axis surfaced its fully-covered
/// arm") and trustworthiness ("neither axis reached the saturating-add
/// ceiling"). The strict gate integrates BOTH factors; this helper
/// surfaces ONLY the completeness factor, so a downstream consumer can
/// gate on completeness without the trustworthiness clamp (e.g., to
/// emit a per-axis completeness telemetry field independently of the
/// trustworthiness telemetry field) without retyping the four-way
/// conjunction the strict gate seals. Pinned at
/// [`tests::test_compose_is_fully_complete_decomposes_strict_admission`].
///
/// Saturation distinction (load-bearing): this helper reads `true` at
/// the saturated-but-honest-completeness arm `{ran: usize::MAX, absent:
/// 0}` / `{verified: usize::MAX, unverified: 0}` — at these arms, the
/// component-level completeness test `ran > 0 && absent == 0` /
/// `verified > 0 && unverified == 0` reads `true` honestly against the
/// counted increments (every counted probe DID run, every counted
/// verification DID clear), BUT the saturating-add ceiling means
/// past-ceiling increments are lost so the reading is no longer
/// trustworthy against the true counts. The strict gate clamps this arm
/// at the trustworthiness factor `!is_saturated()`; this helper does
/// NOT — it surfaces the completeness factor honestly and leaves the
/// trustworthiness clamp to the downstream consumer (via
/// [`compose_is_saturated`] or the strict gate composition). The
/// distinction is the load-bearing reason the helper exists separately
/// from `compose_admission_eligible_strict`: the two factors are
/// orthogonal and a downstream consumer can read either independently.
///
/// At every reachable `(probe, verification)` pair, the predicate
/// equals the documented two-axis composition exactly — the
/// structural equivalence
/// `compose_is_fully_complete(p, v) == (p.is_fully_covered() &&
/// v.is_fully_verified())`
/// is pinned across the cross product of per-axis representatives by
/// [`tests::test_compose_is_fully_complete_equals_documented_composition`].
///
/// THEORY.md §VI.1 one-oracle discipline: the two-axis completeness
/// conjunction is derived at one site (here), not re-inlined as
/// `probe.is_fully_covered() && verification.is_fully_verified()` per
/// downstream consumer (which would inherit a drift class on the day a
/// third orthogonal axis is added — every consumer would need to extend
/// their composition in lockstep, exactly the structural seam this
/// helper forecloses, mirroring the discipline
/// [`compose_admission_eligible_strict`], [`compose_is_saturated`], and
/// [`compose_is_empty`] establish for the complementary gates).
/// THEORY.md §V.4 / §VII.1 honesty channel: the aggregate-completeness
/// surface reads one bool naming "every counted record on every
/// orthogonal axis surfaced its honest-positive arm," the load-bearing
/// completeness factor the strict-production admission gate integrates
/// alongside the orthogonal trustworthiness factor.
///
/// Frontier lineage: Bazel's `--build_event_stream` / Buck2's
/// build-event surface distinguish the "every action succeeded" event
/// (structural completeness reading, independent of cache-trust
/// freshness) from the "every action succeeded AND every cache hit was
/// trustworthy" composed admission gate. SLSA L3+'s provenance gate
/// distinguishes "every required attestation present" (structural
/// completeness, the precondition the gate reads first) from "every
/// attestation present AND trustworthy" (the admission-eligible
/// reading the gate admits on); this helper lifts the same
/// completeness-vs-trustworthiness decomposition at the two-axis
/// typed-primitive surface. Sigstore's policy controller surfaces "every
/// matched attestation cleared" as a distinct completeness reading
/// before integrating per-attestation freshness; this helper lifts the
/// same discipline across the two-axis composition.
///
/// [`is_fully_covered`]: ProbeCoverage::is_fully_covered
/// [`is_fully_verified`]: VerificationCoverage::is_fully_verified
#[allow(dead_code)]
pub fn compose_is_fully_complete(
    probe: &ProbeCoverage,
    verification: &VerificationCoverage,
) -> bool {
    probe.is_fully_covered() && verification.is_fully_verified()
}

/// Parallel-composed any-axis-has-evidence predicate over the two
/// orthogonal typed-primitive surfaces — the two-bool disjunction
/// `probe.has_evidence() || verification.has_evidence()` collapsed to
/// one bool at one site. Reads `true` iff AT LEAST ONE counted probe
/// ran (no-evidence axis: `ran > 0`) OR AT LEAST ONE counted
/// verification cleared (verification-trustworthiness axis: `verified
/// > 0`) — the relaxed-staging admission precondition the fleet-wide
/// gate consults across both orthogonal axes.
///
/// The structural completion of the parallel-axis compose family:
/// where [`compose_admission_eligible_strict`] (commit 7d818bd) is the
/// four-way conjunction "complete AND trustworthy on BOTH axes",
/// [`compose_is_saturated`] (commit 2ea2240) is "untrustworthy on AT
/// LEAST ONE axis", [`compose_is_empty`] (commit a50a371) is "vacuous
/// on BOTH axes", and [`compose_is_fully_complete`] (commit 078826b)
/// is "complete on BOTH axes", this is the relaxed admission factor
/// "evidence on AT LEAST ONE axis" — the load-bearing precondition the
/// fleet-wide relaxed-staging admission gate at `commands::attestation`
/// reads to admit "any honest-positive arm surfaced on any orthogonal
/// axis" vs. reject "every counted record on every axis collapsed to
/// the no-evidence floor (absent / unverified) or the empty-boundary
/// state". The five-member compose family now closes the structural
/// arms the two-axis admission decomposition surfaces: AND of
/// completeness, AND of strict admission, OR of saturation, AND of
/// emptiness, OR of has-evidence.
///
/// Disjunction (not conjunction) is structurally load-bearing here:
/// has-evidence is the OR of per-axis has-evidence — evidence on
/// EITHER axis is enough to admit the relaxed precondition. A
/// regression that composed the conjunction `probe.has_evidence() &&
/// verification.has_evidence()` would silently reject the
/// one-axis-evidenced state as no-evidence (the drift class this
/// helper exists to foreclose), suppressing the relaxed-staging
/// admission gate at every state where only one axis has surfaced
/// positive evidence — the typical Phase 1 / Phase 2 partial-progress
/// state the relaxed gate exists to admit.
///
/// The orthogonal-axis peer of the two per-axis [`has_evidence`]
/// predicates: where each per-axis predicate collapses the `ran > 0`
/// / `verified > 0` boundary at one orthogonal axis to one bool at
/// the typed-primitive surface, this collapses the two-bool axis-
/// level disjunction `probe.has_evidence() ||
/// verification.has_evidence()` across both axes to one bool at one
/// site. A downstream consumer emitting an aggregate-has-evidence
/// telemetry field across both axes (the natural follow-up to the
/// per-axis `*_probes_have_evidence` /
/// `*_verifications_have_evidence` fields the `emit_probe_coverage!`
/// macro family will extend) reads one bool —
/// `compose_has_evidence(&probe, &verification)` — rather than
/// composing the two-bool per-axis surface at every consumer. Before
/// this helper, every aggregate-has-evidence emitter had to retype
/// the two-bool consumer composition (with the drift class a
/// regression that conjuncted the per-axis flags silently rejects the
/// one-axis-evidenced state as no-evidence); after this helper, the
/// emitter reads one bool and the parallel-axis composition is sealed
/// at the typed-primitive surface so a future third orthogonal axis
/// (e.g., a compliance-dimensions axis the
/// [`crate::compliance_dimensions`] family hints at) extends the
/// composition here, not at every downstream consumer in lockstep.
///
/// The load-bearing structural relation
/// `compose_has_evidence(p, v) == !(p.is_empty() && v.is_empty()) ==
/// !compose_is_empty(p, v)` does NOT hold in general — `has_evidence`
/// is the strictly stronger discriminator: at the all-absent /
/// all-unverified states (`{ran: 0, absent: N}` /
/// `{verified: 0, unverified: M}`, both `N > 0` and `M > 0`),
/// `compose_is_empty` reads `false` (records counted on both axes)
/// but `compose_has_evidence` also reads `false` (zero
/// honest-positive arms surfaced). The distinction is the
/// load-bearing reason this helper exists separately from
/// `!compose_is_empty`: the relaxed-staging gate admits only on
/// positive evidence, not on the presence of any record (including
/// every-absent records that, structurally, do NOT clear the
/// admission gate at any tier). Pinned at
/// [`tests::test_compose_has_evidence_strictly_stronger_than_not_empty`].
///
/// Saturation-robust by construction: each per-axis `has_evidence()`
/// reads its `ran` / `verified` component itself, not against any
/// derived ratio. At the post-saturation arm `{ran: usize::MAX,
/// absent: 0}` / `{verified: usize::MAX, unverified: 0}` the
/// composition correctly reads `true` (every counted record — even
/// the dropped past-ceiling increments — surfaced its honest-positive
/// arm on at least one axis). At the inverse-saturation arm
/// `{ran: 0, absent: usize::MAX}` / `{verified: 0, unverified:
/// usize::MAX}` paired with the empty opposite axis, the composition
/// correctly reads `false` (no counted record surfaced its
/// honest-positive arm on either axis). The saturated-but-rolled
/// drift class is foreclosed at the typed-primitive surface, mirroring
/// the discipline [`compose_is_empty`] and [`compose_is_fully_complete`]
/// already establish for the structural complements.
///
/// At every reachable `(probe, verification)` pair, the predicate
/// equals the documented two-axis composition exactly — the
/// structural equivalence
/// `compose_has_evidence(p, v) == (p.has_evidence() ||
/// v.has_evidence())`
/// is pinned across the cross product of per-axis representatives by
/// [`tests::test_compose_has_evidence_equals_documented_composition`].
///
/// THEORY.md §VI.1 one-oracle discipline: the two-axis
/// any-axis-has-evidence disjunction is derived at one site (here),
/// not re-inlined as `probe.has_evidence() ||
/// verification.has_evidence()` per downstream consumer (which would
/// inherit a drift class on the day a third orthogonal axis is added
/// — every consumer would need to extend their composition in
/// lockstep, exactly the structural seam this helper forecloses,
/// mirroring the discipline [`compose_admission_eligible_strict`],
/// [`compose_is_saturated`], [`compose_is_empty`], and
/// [`compose_is_fully_complete`] already established for the
/// complementary gates). THEORY.md §V.4 / §VII.1 honesty channel: the
/// aggregate-has-evidence surface reads one bool naming "at least one
/// counted record on at least one orthogonal axis surfaced its
/// honest-positive arm," the load-bearing relaxed-staging admission
/// precondition the fleet-wide gate consults before integrating the
/// strict gate's completeness AND trustworthiness factors. The
/// decomposition pin `is_fully_complete => has_evidence` (every
/// both-axes-complete state strictly carries evidence on at least one
/// axis, since completeness on either axis implies `ran > 0` or
/// `verified > 0` on that axis) seals the relaxed-vs-strict ordering
/// at the composed-axis surface.
///
/// Frontier lineage: Bazel's `--build_event_stream` / Buck2's
/// build-event surface emit a per-axis "any action completed
/// successfully" relaxed event distinct from the strict "every action
/// completed successfully" event the fully-complete reading carries;
/// the per-axis relaxed gate consults the "any" event across the
/// composed axes the same way `compose_has_evidence` lifts here.
/// SLSA L3+'s provenance gate distinguishes "at least one required
/// attestation present" (the relaxed precondition the gate reads
/// first to detect any progress toward the attestation requirement)
/// from "every required attestation present" (the strict admission
/// reading); this helper lifts the same relaxed-vs-strict
/// decomposition across the two-axis typed-primitive surface.
/// Sigstore's policy controller surfaces "at least one matched
/// attestation cleared" as a distinct relaxed reading before
/// integrating the strict "every matched attestation cleared" gate;
/// this helper lifts the same discipline across the two-axis
/// composition.
///
/// [`has_evidence`]: ProbeCoverage::has_evidence
#[allow(dead_code)]
pub fn compose_has_evidence(probe: &ProbeCoverage, verification: &VerificationCoverage) -> bool {
    probe.has_evidence() || verification.has_evidence()
}

/// Parallel-composed relaxed-staging admission predicate over the two
/// orthogonal typed-primitive surfaces — the two-bool conjunction
/// `compose_has_evidence(p, v) && !compose_is_saturated(p, v)` collapsed
/// to one bool at one site. Reads `true` iff AT LEAST ONE counted record
/// on AT LEAST ONE orthogonal axis surfaced its honest-positive arm AND
/// the derived-ratio surfaces on BOTH axes remain trustworthy (neither
/// component reached the `usize::saturating_add` ceiling).
///
/// The structural relaxed-vs-strict peer of
/// [`compose_admission_eligible_strict`] at the
/// dev/staging-vs-production admission boundary: where the strict gate
/// (commit 7d818bd) integrates "complete AND trustworthy on BOTH axes"
/// — the Phase 2 prod admission precondition — this integrates
/// "evidence on AT LEAST ONE axis AND trustworthy on BOTH axes" — the
/// Phase 1 dev/staging admission precondition the [`crate::commands::
/// attestation`] composition site reads to admit records that have made
/// partial progress toward the strict gate without yet clearing every
/// axis. The six-member compose family now closes the strict/relaxed
/// pair against the three structural-boundary helpers
/// ([`compose_is_empty`], [`compose_is_fully_complete`],
/// [`compose_is_saturated`]) and the two relaxed-precondition helpers
/// ([`compose_has_evidence`]) the prior five commits landed.
///
/// The load-bearing structural ordering
/// `compose_admission_eligible_strict(p, v) =>
/// compose_admission_eligible_relaxed(p, v)` holds at every reachable
/// `(probe, verification)` pair because strict admission requires
/// `is_fully_complete && !is_saturated` and `is_fully_complete =>
/// has_evidence` (every both-axes-complete state carries `ran > 0` AND
/// `verified > 0`, structurally implying `has_evidence` on both axes);
/// the trustworthiness clamp `!compose_is_saturated` is shared verbatim
/// across the two gates. Pinned at
/// [`tests::test_compose_admission_eligible_strict_implies_compose_admission_eligible_relaxed`].
/// The relaxed gate is the strictly weaker discriminator: there exist
/// `(probe, verification)` pairs (e.g., the one-axis-evidenced state
/// where the opposite axis carries every-absent records) where
/// `compose_admission_eligible_relaxed` admits and
/// `compose_admission_eligible_strict` refuses — the structural witness
/// the Phase 1 / Phase 2 distinction exists to surface.
///
/// Conjunction (not disjunction) is structurally load-bearing on the
/// trustworthiness clamp: the relaxed gate inherits the saturating-add
/// trustworthiness factor identically to the strict gate, so a regression
/// that dropped the `!compose_is_saturated` factor (e.g., a body that
/// returned `compose_has_evidence(p, v)` alone) would silently admit the
/// post-saturation state `{ran: usize::MAX, absent: 0}` /
/// `{verified: usize::MAX, unverified: 0}` where past-ceiling increments
/// are lost so the derived ratios are no longer trustworthy — the drift
/// class this helper exists to foreclose. Symmetrically, a regression
/// that dropped the `compose_has_evidence` factor would silently admit
/// the both-no-evidence floor `({ran: 0, absent: N}, {verified: 0,
/// unverified: M})` where every counted record on both axes collapsed
/// to its no-evidence arm — the relaxed gate refuses this state at the
/// load-bearing fail-closed boundary.
///
/// The orthogonal-axis peer of the inline relaxed-staging gate every
/// downstream consumer would otherwise retype as
/// `(probe.has_evidence() || verification.has_evidence()) &&
///  !probe.is_saturated() && !verification.is_saturated()` (the
/// six-arm shape after fully expanding both compose helpers): this
/// helper collapses the two-bool consumer composition to one bool at
/// one site, so a downstream `sekiban` Phase 1 admission verifier (or
/// the relaxed-staging tier the [`compose_admission_eligible_strict`]
/// docstring names) reads one bool — `compose_admission_eligible_relaxed
/// (&probe, &verification)` — rather than composing the six-arm
/// expansion at every consumer. Before this helper, every relaxed-
/// staging admission gate had to retype the two-bool helper conjunction
/// (with the drift class a regression that dropped one factor silently
/// admits the state the documented gate refuses); after this helper,
/// the gate reads one bool and the parallel-axis composition is sealed
/// at the typed-primitive surface so a future third orthogonal axis
/// (e.g., a compliance-dimensions axis the
/// [`crate::compliance_dimensions`] family hints at) extends both
/// admission gates here in lockstep with their three structural-
/// boundary peers, not at every downstream consumer.
///
/// At every reachable `(probe, verification)` pair, the predicate
/// equals the documented two-helper composition exactly — the
/// structural equivalence
/// `compose_admission_eligible_relaxed(p, v) == (compose_has_evidence(p,
/// v) && !compose_is_saturated(p, v))`
/// is pinned across the cross product of per-axis representatives by
/// [`tests::test_compose_admission_eligible_relaxed_equals_documented_composition`].
///
/// THEORY.md §V.4 two-phase signature composition: the relaxed-staging
/// admission predicate is the typed-primitive surface for the Phase 1
/// dev/staging admission precondition — Phase 1 signatures are produced
/// the moment the artifact is rendered (evidence present on at least
/// one orthogonal axis), and the derived-ratio surfaces must remain
/// trustworthy (the saturating-add ceiling clamp) before any Phase 1
/// admission tier can read the per-axis ratios honestly. The strict
/// admission predicate is the typed-primitive surface for the Phase 2
/// production admission precondition — Phase 2 requires the full
/// completeness arm on every orthogonal axis (every counted record
/// surfaced its honest-positive arm) alongside the same trustworthiness
/// clamp; the relaxed-vs-strict ordering this helper pins
/// (`strict => relaxed`) mirrors V.4's "Phase 2 admits where Phase 1
/// admits AND every compliance attestation cleared" decomposition at
/// the two-axis typed-primitive surface. THEORY.md §VI.1 one-oracle
/// discipline: the two-helper conjunction is derived at one site
/// (here), not re-inlined as `compose_has_evidence(p, v) &&
/// !compose_is_saturated(p, v)` per downstream consumer (which would
/// inherit a drift class on the day a third orthogonal axis is added —
/// every consumer would need to extend their composition in lockstep,
/// exactly the structural seam this helper forecloses, mirroring the
/// discipline [`compose_admission_eligible_strict`],
/// [`compose_is_saturated`], [`compose_is_empty`],
/// [`compose_is_fully_complete`], and [`compose_has_evidence`] already
/// established for the complementary gates).
///
/// Frontier lineage: SLSA L3+'s build-provenance admission policy
/// distinguishes the "any required attestation present AND every
/// present attestation is trustworthy" relaxed precondition the
/// staging tier admits from the "every required attestation present
/// AND every present attestation is trustworthy" strict precondition
/// the production tier admits; this helper lifts the same relaxed-vs-
/// strict decomposition across the two-axis typed-primitive surface
/// with the trustworthiness factor sealed identically across both
/// tiers. Sigstore's policy controller surfaces the same partition
/// across its keyless-vs-keyed admission tiers — the keyless tier
/// admits on "at least one matched attestation present AND trustworthy
/// freshness window" (the relaxed staging precondition), the keyed
/// tier admits on "every matched attestation present AND trustworthy
/// freshness window" (the strict production precondition); this
/// helper lifts the same discipline at the two-axis composition.
/// Bazel's `--build_event_stream` / Buck2's build-event surface emit a
/// per-stage "any action completed successfully AND every completion
/// is fresh" relaxed event (the staging trigger) distinct from the
/// "every action completed successfully AND every completion is fresh"
/// strict event (the release trigger); this helper lifts the same
/// staging-vs-release decomposition at the two-axis surface.
#[allow(dead_code)]
pub fn compose_admission_eligible_relaxed(
    probe: &ProbeCoverage,
    verification: &VerificationCoverage,
) -> bool {
    compose_has_evidence(probe, verification) && !compose_is_saturated(probe, verification)
}

/// Parallel-composed both-axes-no-evidence floor predicate over the two
/// orthogonal typed-primitive surfaces — the four-arm disjunction-of-
/// disjunctions `(probe.is_all_absent() || probe.is_empty()) &&
/// (verification.is_all_unverified() || verification.is_empty())`
/// collapsed to one bool at one site. Reads `true` iff EVERY counted
/// record on the no-evidence axis ([`ProbeCoverage`] over the seventeen-
/// outcome attestation pipeline) collapsed to the absent arm OR no
/// records were counted there, AND EVERY counted record on the
/// verification-trustworthiness axis ([`VerificationCoverage`] over the
/// five-outcome [`VerifiedOutcome`] subset) collapsed to the unverified
/// arm OR no records were counted there. The both-axes no-positive-
/// evidence floor — the operational fleet-wide state every observed
/// `(probe, verification)` pair sits at today, before the five
/// `Verified`-bearing typed outcomes wire real substantiations at their
/// probe sites.
///
/// The structural complement of [`compose_has_evidence`] at the two-axis
/// surface: where [`compose_has_evidence`] reads `true` iff AT LEAST ONE
/// counted record on AT LEAST ONE axis surfaced its honest-positive arm,
/// this reads `true` iff EVERY counted record on EVERY axis surfaced its
/// no-evidence arm (or no records were counted at all). The load-bearing
/// De Morgan equivalence
/// `compose_is_all_no_evidence(p, v) == !compose_has_evidence(p, v)`
/// holds at every reachable `(probe, verification)` pair — pinned by
/// [`tests::test_compose_is_all_no_evidence_equals_negation_of_compose_has_evidence`]
/// — because `(p.is_all_absent() || p.is_empty()) == (p.ran == 0) ==
/// !p.has_evidence()` (the union of the two `ran == 0` arms exhausts the
/// no-positive-evidence cases on the probe axis), symmetrically on the
/// verification axis, and the conjunction across axes mirrors the
/// disjunction in `compose_has_evidence` under De Morgan. The seven-
/// member parallel-axis compose family now closes the structural arms
/// the two-axis admission decomposition surfaces: AND of completeness,
/// AND of strict admission, OR of saturation, AND of emptiness, OR of
/// has-evidence, OR of admission eligibility (relaxed), AND of no-
/// evidence floor.
///
/// Conjunction (not disjunction) is structurally load-bearing on the
/// outer combinator: the both-axes no-evidence floor is the AND of per-
/// axis no-evidence — EVERY counted axis must surface its no-evidence
/// arm for the composed reading to admit. A regression that composed
/// the outer disjunction `(p.is_all_absent() || p.is_empty()) ||
/// (v.is_all_unverified() || v.is_empty())` would silently classify the
/// one-axis-evidenced state as no-evidence (the drift class this helper
/// exists to foreclose), surfacing a false-no-evidence reading at every
/// downstream consumer that gates on the composed bool. Symmetrically,
/// disjunction (not conjunction) is structurally load-bearing on the
/// inner per-axis combinator: the per-axis no-evidence reading is the
/// OR of the two structural arms `is_all_absent` (records counted, all
/// collapsed to absent) and `is_empty` (no records counted) — both
/// share the load-bearing structural property `ran == 0` (or
/// `verified == 0`) at the per-axis level. A regression that conjuncted
/// the inner per-axis arms `is_all_absent() && is_empty()` would
/// reduce to the contradiction `false` at the per-axis level (the two
/// arms are disjoint by `is_all_absent` requiring `absent > 0` and
/// `is_empty` requiring `absent == 0`), silently collapsing the
/// composed reading to `false` at every reachable state — exactly the
/// drift class the named-arms disjunction-of-disjunctions form
/// forecloses against the De Morgan negation form `!has_evidence()`.
///
/// The orthogonal-axis peer of the two per-axis named-floor predicates
/// [`ProbeCoverage::is_all_absent`] and
/// [`VerificationCoverage::is_all_unverified`]: where each per-axis
/// predicate names the floor arm of the four-arm per-axis matrix
/// (`(0, N)` at the no-evidence axis / `(0, N)` at the verification-
/// trustworthiness axis), this composes the floor arms of both
/// per-axis matrices into one bool at the typed-primitive surface,
/// the four-corner-product floor of the joint two-axis matrix. A
/// downstream `sekiban` admission verifier wanting to reject the
/// fleet-wide "every counted record on every axis collapsed to its
/// no-evidence arm" state — the load-bearing precondition for the
/// fail-closed admission gate at the no-attestation-pipeline-wired
/// frontier state — reads one bool — `compose_is_all_no_evidence(&
/// probe, &verification)` — rather than composing the four-arm
/// disjunction-of-disjunctions at the consumer surface (or, equivalently
/// but with the kind-of-claim erased, `!compose_has_evidence(&probe,
/// &verification)`). Before this helper, every fleet-wide no-evidence-
/// floor consumer had to retype the four-arm composition (with the
/// drift class a regression that swapped the inner / outer combinators
/// silently admits the state the documented floor refuses); after this
/// helper, the consumer reads one bool and the parallel-axis composition
/// is sealed at the typed-primitive surface so a future third orthogonal
/// axis (e.g., a compliance-dimensions axis the
/// [`crate::compliance_dimensions`] family hints at) extends the
/// composition here, not at every downstream consumer in lockstep.
///
/// The load-bearing decomposition `compose_admission_eligible_relaxed(p,
/// v) == !compose_is_all_no_evidence(p, v) && !compose_is_saturated(p,
/// v)` separates the two orthogonal admission factors at the composed-
/// axis surface: presence-of-evidence ("at least one counted axis
/// surfaced its honest-positive arm" — the De Morgan negation of the
/// no-evidence floor) and trustworthiness ("neither axis reached the
/// saturating-add ceiling"). The relaxed gate integrates BOTH factors;
/// this helper surfaces the negated presence-of-evidence factor and
/// leaves the trustworthiness clamp to the downstream consumer.
///
/// Saturation-robust by construction: each per-axis arm predicate reads
/// the per-axis component itself (`ran == 0` / `verified == 0`), not
/// against any derived ratio. At the post-saturation arm `{ran: 0,
/// absent: usize::MAX}` / `{verified: 0, unverified: usize::MAX}` the
/// composition correctly reads `true` (every counted record — even the
/// dropped past-ceiling no-evidence increments — surfaced its no-evidence
/// arm on each axis). At the inverse-saturation arm `{ran: usize::MAX,
/// absent: 0}` / `{verified: usize::MAX, unverified: 0}` paired with the
/// empty opposite axis, the composition correctly reads `false` (every
/// counted record on the saturated axis surfaced its honest-positive
/// arm, so the per-axis no-evidence reading is structurally `false` on
/// that axis even though the saturating-add ceiling has been reached).
/// The saturated-but-rolled drift class is foreclosed at the typed-
/// primitive surface, mirroring the discipline [`compose_is_empty`],
/// [`compose_is_fully_complete`], and [`compose_has_evidence`] establish
/// for the structural complements.
///
/// At every reachable `(probe, verification)` pair, the predicate
/// equals the documented four-arm composition exactly — the
/// structural equivalence
/// `compose_is_all_no_evidence(p, v) == (p.is_all_absent() ||
/// p.is_empty()) && (v.is_all_unverified() || v.is_empty())`
/// is pinned across the cross product of per-axis representatives by
/// [`tests::test_compose_is_all_no_evidence_equals_documented_composition`].
///
/// THEORY.md §V.4 honesty channel: the both-axes no-evidence floor
/// surface reads one bool naming "every counted verification-bearing
/// probe AND every counted no-evidence probe surfaced the honest no-
/// substantiation arm" — the load-bearing precondition the strict-
/// production admission gate fails-closed on at today's call-site state
/// before the five `Verified`-bearing typed outcomes wire real
/// substantiations. THEORY.md §VI.1 one-oracle discipline: the two-axis
/// no-evidence-floor conjunction is derived at one site (here), not re-
/// inlined as `(p.is_all_absent() || p.is_empty()) && (v.is_all_unverified()
/// || v.is_empty())` per downstream consumer (which would inherit a
/// drift class on the day a third orthogonal axis is added — every
/// consumer would need to extend their composition in lockstep, exactly
/// the structural seam this helper forecloses, mirroring the discipline
/// [`compose_admission_eligible_strict`], [`compose_is_saturated`],
/// [`compose_is_empty`], [`compose_is_fully_complete`],
/// [`compose_has_evidence`], and [`compose_admission_eligible_relaxed`]
/// already established for the complementary gates).
///
/// Frontier lineage: SLSA provenance verification distinguishes "no
/// attestations produced anywhere in the pipeline" (the fleet-wide no-
/// evidence floor, the operational state the gate reads first to surface
/// the structural fail-closed reason) from "at least one attestation
/// produced somewhere" (the relaxed precondition the gate admits on);
/// this helper lifts the same fleet-wide no-evidence-floor reading at
/// the two-axis typed-primitive surface. Sigstore's policy controller
/// surfaces "no policy-matched attestations across any namespace" as a
/// distinct fail-closed reading the admission gate consults before
/// integrating per-attestation freshness — the same fleet-wide no-
/// evidence-floor discipline this helper lifts across the two-axis
/// composition. Bazel's `--build_event_stream` / Buck2's build-event
/// surface emit a structural "no actions completed successfully anywhere
/// in the build" boundary distinct from the "every action completed
/// successfully" ceiling — the fleet-wide no-positive-evidence floor a
/// downstream consumer reads to gate "the build is structurally empty of
/// progress" vs. "at least one action made progress"; this helper lifts
/// the same floor distinction at forge's two-axis surface.
///
/// [`ProbeCoverage::is_all_absent`]: ProbeCoverage::is_all_absent
/// [`VerificationCoverage::is_all_unverified`]: VerificationCoverage::is_all_unverified
#[allow(dead_code)]
pub fn compose_is_all_no_evidence(
    probe: &ProbeCoverage,
    verification: &VerificationCoverage,
) -> bool {
    (probe.is_all_absent() || probe.is_empty())
        && (verification.is_all_unverified() || verification.is_empty())
}

/// Parallel-composed fleet-wide relaxed-gate fail-closed disjunction over
/// the two orthogonal typed-primitive surfaces — the two-helper
/// disjunction `compose_is_all_no_evidence(p, v) ||
/// compose_is_saturated(p, v)` collapsed to one bool at one site. Reads
/// `true` iff EVERY counted record on EVERY axis collapsed to its
/// no-evidence arm (or no records were counted) OR AT LEAST ONE axis
/// reached its `usize::saturating_add` ceiling. The structural
/// fail-closed reason a relaxed-staging admission gate
/// ([`compose_admission_eligible_relaxed`]) refuses on — under De Morgan
/// the negation of the relaxed gate decomposes exactly as
/// `!compose_admission_eligible_relaxed(p, v) ==
///  compose_is_all_no_evidence(p, v) || compose_is_saturated(p, v)`
/// because `!(compose_has_evidence && !compose_is_saturated) ==
///  !compose_has_evidence || compose_is_saturated ==
///  compose_is_all_no_evidence || compose_is_saturated`
/// (the second step uses the load-bearing De Morgan equivalence
/// `compose_is_all_no_evidence(p, v) == !compose_has_evidence(p, v)` the
/// prior commit pinned).
///
/// The structural complement of [`compose_admission_eligible_relaxed`] at
/// the two-axis surface: where the relaxed gate (commit e6810b2)
/// integrates "evidence on AT LEAST ONE axis AND trustworthy on BOTH
/// axes" — the Phase 1 dev/staging admission precondition — this surfaces
/// the disjunction of the two structural fail-closed reasons (the
/// no-evidence floor OR the saturation ceiling) the gate refuses on with
/// the kind-of-claim preserved (rather than the bare bool the De Morgan
/// negation `!compose_admission_eligible_relaxed(p, v)` would surface).
/// A downstream `sekiban` admission verifier wanting to surface the
/// fleet-wide structural fail-closed reason — distinguishing "no
/// progress made on any axis" from "progress made but trust broken" at
/// the typed-primitive surface — reads one bool from this helper and
/// branches on the two component helpers individually rather than
/// re-deriving the four-arm disjunction-of-disjunctions at the consumer
/// surface (or, equivalently but with the kind-of-claim erased,
/// `!compose_admission_eligible_relaxed(p, v)`).
///
/// Disjunction (not conjunction) is structurally load-bearing on the
/// outer combinator: the relaxed gate refuses iff EITHER fail-closed
/// reason holds — no positive evidence anywhere OR untrustworthy ratio
/// surface on at least one axis. A regression that composed the
/// conjunction `compose_is_all_no_evidence(p, v) &&
/// compose_is_saturated(p, v)` would silently admit the load-bearing
/// "evidence-bearing but saturated" state (e.g.,
/// `{ran: usize::MAX, absent: 0}`) as relaxed-eligible, dropping the
/// trustworthiness factor the relaxed gate inherits verbatim from the
/// strict gate; symmetrically it would silently admit the "no evidence
/// but trustworthy" state as relaxed-eligible, dropping the
/// presence-of-evidence factor the relaxed gate requires.
///
/// The eight-member parallel-axis compose family now closes the
/// structural complements the two-axis admission decomposition surfaces:
/// AND of completeness, AND of strict admission, OR of saturation, AND
/// of emptiness, OR of has-evidence, OR of admission eligibility
/// (relaxed), AND of no-evidence floor, OR of no-evidence-OR-saturated
/// (relaxed-refuse). The relaxed-gate decomposition
/// `compose_admission_eligible_relaxed(p, v) ==
/// !compose_is_all_no_evidence_or_saturated(p, v)` is the De Morgan
/// peer the natural-language description of the relaxed gate ("admit iff
/// evidence present and trust intact" ↔ "refuse iff no evidence or
/// trust broken") makes auditable at the typed-primitive surface —
/// pinned by
/// [`tests::test_compose_is_all_no_evidence_or_saturated_equals_negation_of_compose_admission_eligible_relaxed`].
///
/// Saturation-robust by construction: the second disjunct
/// `compose_is_saturated` explicitly reads the saturating-add ceiling
/// across both axes, so the post-saturation state every other relaxed-
/// gate ratio surface would lose past-ceiling increments at is
/// structurally classified as fail-closed here. The first disjunct
/// `compose_is_all_no_evidence` reads the `ran == 0` / `verified == 0`
/// per-axis component itself (not against any derived ratio), so the
/// saturated-but-no-evidence arm `{ran: 0, absent: usize::MAX}` /
/// `{verified: 0, unverified: usize::MAX}` reads `true` honestly through
/// both disjuncts.
///
/// At every reachable `(probe, verification)` pair, the predicate
/// equals the documented two-helper composition exactly — the
/// structural equivalence
/// `compose_is_all_no_evidence_or_saturated(p, v) ==
/// (compose_is_all_no_evidence(p, v) || compose_is_saturated(p, v))`
/// is pinned across the cross product of per-axis representatives by
/// [`tests::test_compose_is_all_no_evidence_or_saturated_equals_documented_composition`].
///
/// THEORY.md §V.4 honesty channel: the relaxed-gate fail-closed
/// disjunction surface reads one bool naming "the fleet-wide aggregate
/// has either made no progress (every counted record on every axis
/// collapsed to no-evidence) or lost trust (a derived-ratio axis hit
/// the saturating-add ceiling)" — the structural fail-closed reason the
/// Phase 1 admission gate refuses on, decomposable into its two named
/// per-helper components at the consumer surface. THEORY.md §VI.1
/// one-oracle discipline: the two-helper disjunction is derived at one
/// site (here), not re-inlined as `compose_is_all_no_evidence(p, v) ||
/// compose_is_saturated(p, v)` per downstream consumer (which would
/// inherit a drift class on the day a third orthogonal axis is added —
/// every consumer would need to extend the composition in lockstep,
/// exactly the structural seam this helper forecloses, mirroring the
/// discipline the seven prior compose helpers established for the
/// complementary gates).
///
/// Frontier lineage: SLSA L3+ admission policy gates surface the
/// fail-closed reason as a structural disjunction "no required
/// attestations present anywhere OR at least one freshness window
/// expired" distinct from the bare admission bool, so a downstream
/// auditor can branch on the structural reason the gate refused; this
/// helper lifts the same fail-closed-disjunction surface at the
/// two-axis typed-primitive level. Sigstore's policy controller emits
/// the rejected-admission reason as the disjunction "no matched
/// attestations OR freshness-window violation" preserving the named
/// per-axis reason for downstream remediation; this helper lifts the
/// same structural-reason discipline at the two-axis composition.
/// Bazel's `--build_event_stream` / Buck2's build-event surface emit a
/// per-stage "no actions completed successfully anywhere OR cache trust
/// broken" fail-closed disjunction distinct from the bare admission
/// bool — the fleet-wide structural-reason readout a downstream
/// consumer branches on; this helper lifts the same structural-reason
/// distinction at forge's two-axis surface.
#[allow(dead_code)]
pub fn compose_is_all_no_evidence_or_saturated(
    probe: &ProbeCoverage,
    verification: &VerificationCoverage,
) -> bool {
    compose_is_all_no_evidence(probe, verification) || compose_is_saturated(probe, verification)
}

/// Parallel-composed strict-gate fail-closed disjunction over the two
/// orthogonal typed-primitive surfaces — the two-bool disjunction
/// `!compose_is_fully_complete(probe, verification) ||
///  compose_is_saturated(probe, verification)` collapsed to one bool
/// at one site. Reads `true` iff AT LEAST ONE counted axis failed to
/// surface its fully-covered / fully-verified arm (the incompleteness
/// floor: some counted record collapsed to its no-evidence arm, or no
/// records were counted on at least one axis) OR AT LEAST ONE axis
/// reached its `usize::saturating_add` ceiling (the trustworthiness
/// break: a derived-ratio axis can no longer be read honestly against
/// past-ceiling increments). The structural fail-closed reason a
/// strict-staging admission gate ([`compose_admission_eligible_strict`])
/// refuses on — under De Morgan the negation of the strict gate
/// decomposes exactly as
/// `!compose_admission_eligible_strict(p, v) ==
///  !compose_is_fully_complete(p, v) || compose_is_saturated(p, v)`
/// because `!(compose_is_fully_complete && !compose_is_saturated) ==
///  !compose_is_fully_complete || compose_is_saturated`
/// (the load-bearing decomposition
/// `compose_admission_eligible_strict(p, v) == compose_is_fully_complete(p,
///  v) && !compose_is_saturated(p, v)` the prior commit 078826b pinned).
///
/// The structural complement of [`compose_admission_eligible_strict`] at
/// the two-axis surface: where the strict gate (commit 7d818bd)
/// integrates "complete on BOTH axes AND trustworthy on BOTH axes" —
/// the load-bearing Phase 2 production admission precondition the
/// `commands::attestation` fleet-wide certify step reads — this
/// surfaces the disjunction of the two structural fail-closed reasons
/// (the incompleteness floor OR the saturation ceiling) the gate
/// refuses on with the kind-of-claim preserved (rather than the bare
/// bool the De Morgan negation
/// `!compose_admission_eligible_strict(p, v)` would surface). A
/// downstream `sekiban` admission verifier wanting to surface the
/// fleet-wide structural fail-closed reason — distinguishing
/// "incomplete on at least one axis" from "trust broken on at least
/// one axis" at the typed-primitive surface — reads one bool from
/// this helper and branches on the two component helpers individually
/// rather than re-deriving the disjunction at the consumer surface
/// (or, equivalently but with the kind-of-claim erased,
/// `!compose_admission_eligible_strict(p, v)`).
///
/// The structural peer of [`compose_is_all_no_evidence_or_saturated`]
/// at the strict-gate tier: where the relaxed-gate helper (commit
/// 86d81f7) surfaces the relaxed-gate fail-closed disjunction
/// `compose_is_all_no_evidence || compose_is_saturated` (the De Morgan
/// negation of [`compose_admission_eligible_relaxed`]), this surfaces
/// the strict-gate fail-closed disjunction
/// `!compose_is_fully_complete || compose_is_saturated` (the De Morgan
/// negation of [`compose_admission_eligible_strict`]). Both helpers
/// share the trustworthiness-broken second disjunct verbatim — the
/// saturation factor is shared between the relaxed and strict gates
/// (commit 2ea2240's `compose_is_saturated` is the one-oracle source).
/// The discriminator is the first disjunct: the relaxed-gate floor is
/// "no evidence anywhere" (the negation of `compose_has_evidence` by
/// commit e652297's De Morgan pin), the strict-gate floor is
/// "incomplete on at least one axis" (the negation of
/// `compose_is_fully_complete` directly). The strict floor is
/// strictly weaker — every state the relaxed gate refuses on the
/// strict gate also refuses on (the structural witness of the
/// strict ⇒ relaxed ordering pinned at
/// [`tests::test_compose_admission_eligible_strict_implies_compose_admission_eligible_relaxed`]
/// commit c5f8 / e6810b2). The dual implication
/// `compose_is_all_no_evidence_or_saturated(p, v) =>
///  compose_is_incomplete_or_saturated(p, v)`
/// — the contrapositive of the strict ⇒ relaxed ordering — pins the
/// structural ordering at the fail-closed surface and is pinned by
/// [`tests::test_compose_is_all_no_evidence_or_saturated_implies_compose_is_incomplete_or_saturated`].
///
/// Disjunction (not conjunction) is structurally load-bearing on the
/// outer combinator: the strict gate refuses iff EITHER fail-closed
/// reason holds — at least one axis failed to surface its
/// fully-complete arm OR at least one axis hit its saturating-add
/// ceiling. A regression that composed the conjunction
/// `!compose_is_fully_complete(p, v) && compose_is_saturated(p, v)`
/// would silently admit the load-bearing "incomplete but trustworthy"
/// state (e.g., `({ran: 3, absent: 4}, {verified: 2, unverified: 3})`)
/// as strict-eligible, dropping the completeness factor the strict
/// gate integrates; symmetrically it would silently admit the
/// "complete but saturated" state (e.g.,
/// `({ran: usize::MAX, absent: 0}, {verified: usize::MAX, unverified: 0})`)
/// as strict-eligible, dropping the trustworthiness factor the
/// strict gate clamps to.
///
/// The nine-member parallel-axis compose family now closes the
/// structural complements the two-axis admission decomposition
/// surfaces at BOTH tiers: AND of completeness, AND of strict
/// admission, OR of saturation, AND of emptiness, OR of has-evidence,
/// OR of admission eligibility (relaxed), AND of no-evidence floor,
/// OR of no-evidence-OR-saturated (relaxed-refuse), OR of
/// incomplete-OR-saturated (strict-refuse). The strict-gate
/// decomposition
/// `compose_admission_eligible_strict(p, v) ==
///  !compose_is_incomplete_or_saturated(p, v)` is the De Morgan peer
/// the natural-language description of the strict gate ("admit iff
/// complete on every axis and trust intact" ↔ "refuse iff incomplete
/// on at least one axis or trust broken") makes auditable at the
/// typed-primitive surface — pinned by
/// [`tests::test_compose_is_incomplete_or_saturated_equals_negation_of_compose_admission_eligible_strict`].
///
/// Saturation-robust by construction: the second disjunct
/// `compose_is_saturated` explicitly reads the saturating-add ceiling
/// across both axes, so the post-saturation state every other strict-
/// gate ratio surface would lose past-ceiling increments at is
/// structurally classified as fail-closed here. The first disjunct
/// `!compose_is_fully_complete` reads the `is_fully_covered` /
/// `is_fully_verified` per-axis component itself (not against any
/// derived ratio), so the saturated-fully-evidenced arm
/// `({ran: usize::MAX, absent: 0}, {verified: usize::MAX, unverified: 0})`
/// — where `compose_is_fully_complete` reads `true` honestly through
/// the `absent == 0 && unverified == 0` factor — reads `true` here
/// only through the second disjunct (the saturation ceiling break),
/// preserving the strict gate's fail-closed verdict on the
/// saturated-fully-evidenced state the strict gate refuses through
/// the trustworthiness clamp.
///
/// At every reachable `(probe, verification)` pair, the predicate
/// equals the documented two-helper composition exactly — the
/// structural equivalence
/// `compose_is_incomplete_or_saturated(p, v) ==
/// (!compose_is_fully_complete(p, v) || compose_is_saturated(p, v))`
/// is pinned across the cross product of per-axis representatives by
/// [`tests::test_compose_is_incomplete_or_saturated_equals_documented_composition`].
///
/// THEORY.md §V.4 honesty channel: the strict-gate fail-closed
/// disjunction surface reads one bool naming "the fleet-wide aggregate
/// has either failed to surface completeness on at least one axis
/// (some counted record collapsed to its no-evidence arm, or no
/// records were counted) or lost trust (a derived-ratio axis hit the
/// saturating-add ceiling)" — the structural fail-closed reason the
/// Phase 2 production admission gate refuses on, decomposable into
/// its two named per-helper components at the consumer surface.
/// THEORY.md §VI.1 one-oracle discipline: the two-helper disjunction
/// is derived at one site (here), not re-inlined as
/// `!compose_is_fully_complete(p, v) || compose_is_saturated(p, v)`
/// per downstream consumer (which would inherit a drift class on the
/// day a third orthogonal axis is added — every consumer would need
/// to extend the composition in lockstep, exactly the structural
/// seam this helper forecloses, mirroring the discipline the eight
/// prior compose helpers established for the complementary gates).
///
/// Frontier lineage: SLSA L3+ admission policy gates surface the
/// strict-tier fail-closed reason as a structural disjunction
/// "required attestation missing on at least one input OR provenance
/// freshness window expired on at least one source" distinct from
/// the relaxed-tier fail-closed disjunction, so a downstream auditor
/// can branch on the strict-tier structural reason the gate refused;
/// this helper lifts the same fail-closed-disjunction surface at the
/// two-axis typed-primitive level. Sigstore's policy controller emits
/// the strict-rejected-admission reason as the disjunction "no
/// matched attestations on at least one required predicate OR
/// freshness-window violation" preserving the named per-axis reason
/// for downstream remediation; this helper lifts the same
/// structural-reason discipline at the two-axis composition. Bazel's
/// `--build_event_stream` / Buck2's build-event surface emit a
/// per-stage "incomplete actions on at least one input OR cache
/// trust broken" strict-tier fail-closed disjunction distinct from
/// the relaxed-tier "no actions completed anywhere OR cache trust
/// broken" disjunction — the fleet-wide structural-reason readout a
/// downstream consumer branches on at the strict tier; this helper
/// lifts the same structural-reason distinction at forge's two-axis
/// surface.
#[allow(dead_code)]
pub fn compose_is_incomplete_or_saturated(
    probe: &ProbeCoverage,
    verification: &VerificationCoverage,
) -> bool {
    !compose_is_fully_complete(probe, verification) || compose_is_saturated(probe, verification)
}

/// Parallel-composed fleet-wide staging-only admission band over the two
/// orthogonal typed-primitive surfaces — the two-helper conjunction
/// `compose_admission_eligible_relaxed(p, v) &&
///  !compose_admission_eligible_strict(p, v)` collapsed to one bool at one
/// site. Reads `true` iff the Phase 1 relaxed staging gate admits AND the
/// Phase 2 strict production gate refuses — the load-bearing partial-
/// progress band where deploy proceeds to staging but holds before
/// production. The structural gap between the two admission tiers the
/// nine prior compose helpers established at the gate / refuse surfaces:
/// the strict gate (`compose_admission_eligible_strict`, commit 7d818bd)
/// names the Phase 2 production-ready state, the relaxed gate
/// (`compose_admission_eligible_relaxed`, commit e6810b2) names the
/// Phase 1 staging-ready state, the strict-refuse disjunction
/// (`compose_is_incomplete_or_saturated`, commit 9a9e97a) names the
/// strict-tier fail-closed reason, the relaxed-refuse disjunction
/// (`compose_is_all_no_evidence_or_saturated`, commit 86d81f7) names the
/// relaxed-tier fail-closed reason — but the band BETWEEN the two
/// gates, the staging-only state, has been re-derived at every consumer
/// surface as `relaxed && !strict`. After this helper, the staging-only
/// band carries a typed name and the structural three-way partition
/// the two-tier admission gate establishes — `strict_eligible XOR
/// staging_only XOR refused` — is sealed at the typed-primitive surface.
///
/// Equivalent three-factor decomposition: because relaxed eligibility
/// requires `!compose_is_saturated`, the band collapses structurally to
/// `compose_has_evidence(p, v) && !compose_is_saturated(p, v) &&
///  !compose_is_fully_complete(p, v)` — "evidence on at least one axis
/// AND trust intact on both axes AND incomplete on at least one axis."
/// The disjunctive disjunct of the strict-refuse predicate
/// (`compose_is_saturated`) is foreclosed by the relaxed gate's
/// trustworthiness clamp, so the band reduces to the incompleteness
/// factor alone within the relaxed-admitted subset. A regression that
/// hand-rolled the band as `compose_has_evidence(p, v) &&
/// !compose_is_fully_complete(p, v)` (dropping the trust-intact factor)
/// would silently admit the saturated-incomplete state as staging-only,
/// breaking the load-bearing structural decomposition.
///
/// The structural complement of `compose_admission_eligible_strict` and
/// `compose_is_incomplete_or_saturated` at the relaxed-admitted subset:
/// among states the relaxed gate admits, this distinguishes the
/// strict-eligible band (`compose_admission_eligible_strict` reads
/// `true` — promote to production) from the staging-only band (this
/// helper reads `true` — hold at staging). The disjoint three-way
/// partition `compose_admission_eligible_strict(p, v) XOR
/// compose_relaxed_eligible_strict_refused(p, v) XOR
/// !compose_admission_eligible_relaxed(p, v)` covers every reachable
/// `(probe, verification)` pair exactly once — the load-bearing
/// structural pin
/// [`tests::test_compose_admission_three_way_partition_covers_every_state`]
/// surfaces. A downstream deploy orchestrator wanting to branch on the
/// admission tier (production-eligible / staging-only / refused) reads
/// the three predicates as a disjoint cover rather than a nested
/// if-else cascade that would inherit a drift class on the day a third
/// tier is added between staging and production.
///
/// Conjunction (not disjunction) is structurally load-bearing on the
/// outer combinator: the staging-only band admits iff BOTH "relaxed
/// admits" AND "strict refuses" hold — the band is the asymmetric set
/// difference of the relaxed-admitted set minus the strict-admitted
/// subset, NOT the symmetric difference. A regression that composed the
/// disjunction `compose_admission_eligible_relaxed(p, v) ||
/// !compose_admission_eligible_strict(p, v)` would silently admit
/// "every refused state where strict gate refuses" as staging-only —
/// flattening the relaxed-tier floor and dropping the structural
/// distinction this helper names.
///
/// The ten-member parallel-axis compose family now closes the
/// structural complements the two-axis admission decomposition
/// surfaces at BOTH gate tiers AND at the gap between them: AND of
/// completeness, AND of strict admission, OR of saturation, AND of
/// emptiness, OR of has-evidence, AND of relaxed admission, AND of
/// no-evidence floor, OR of relaxed-refuse, OR of strict-refuse, AND
/// of staging-only band. The staging-only band's decomposition
/// `compose_relaxed_eligible_strict_refused(p, v) ==
/// compose_admission_eligible_relaxed(p, v) &&
/// !compose_admission_eligible_strict(p, v)` is the structural
/// definition the natural-language description of the two-tier
/// admission gap ("Phase 1 admits and Phase 2 refuses" ↔ "advance to
/// staging, hold from production") makes auditable at the typed-
/// primitive surface — pinned by
/// [`tests::test_compose_relaxed_eligible_strict_refused_equals_documented_composition`].
///
/// Saturation-robust by construction: the band requires
/// `!compose_is_saturated` via the relaxed gate's trustworthiness
/// clamp, so the saturated-anywhere state — the post-saturation state
/// every other admission-band ratio surface would lose past-ceiling
/// increments at — is structurally classified as NOT-staging-only here
/// (refused, not staging-only); the saturated-fully-evidenced arm
/// `({ran: usize::MAX, absent: 0}, {verified: usize::MAX, unverified:
/// 0})` reads `false` honestly through the relaxed gate's saturation
/// clamp even though the completeness factor reads `true` (the
/// structural witness the staging-only band is the gap WITHIN the
/// trust-intact admission space, not across the saturation ceiling).
///
/// At every reachable `(probe, verification)` pair, the predicate
/// equals the documented two-helper conjunction exactly — the
/// structural equivalence
/// `compose_relaxed_eligible_strict_refused(p, v) ==
/// (compose_admission_eligible_relaxed(p, v) &&
///  !compose_admission_eligible_strict(p, v))`
/// is pinned across the cross product of per-axis representatives by
/// [`tests::test_compose_relaxed_eligible_strict_refused_equals_documented_composition`].
///
/// THEORY.md §V.4 honesty channel: the staging-only band surface reads
/// one bool naming "the fleet-wide aggregate has surfaced positive
/// evidence on at least one axis AND trust intact on both axes AND
/// failed to surface completeness on at least one axis" — the
/// structural Phase 1 admit / Phase 2 hold state a two-tier deploy
/// gate consults to advance staging without releasing production,
/// decomposable into its three named per-factor components at the
/// consumer surface for telemetry. THEORY.md §VI.1 one-oracle
/// discipline: the band is derived at one site (here), not re-inlined
/// as `compose_admission_eligible_relaxed(p, v) &&
/// !compose_admission_eligible_strict(p, v)` per downstream consumer
/// (which would inherit a drift class on the day a third admission
/// tier is added between staging and production — every consumer
/// would need to extend the band in lockstep, exactly the structural
/// seam this helper forecloses, mirroring the discipline the nine
/// prior compose helpers established for the complementary gates).
///
/// Frontier lineage: SLSA L3+ admission policy gates surface the
/// staging-only band as a structural conjunction "Phase 1 attestation
/// floor met AND Phase 2 provenance freshness not yet established" —
/// the band between the two tier-level gates a downstream auditor
/// branches on to advance the artifact through staging-tier
/// promotion while holding production-tier promotion; this helper
/// lifts the same staging-tier band surface at the two-axis typed-
/// primitive level. Sigstore's policy controller emits the
/// intermediate-tier admit reason as the conjunction "matched
/// attestations on at least one required predicate AND freshness-
/// window not yet established on every predicate" — the structural
/// partial-progress band between the two-tier admit / refuse surfaces.
/// Bazel's `--build_event_stream` / Buck2's build-event surface emit
/// a per-stage "actions completed on at least one input AND
/// incomplete actions on at least one input AND cache trust intact"
/// intermediate-tier band distinct from the bare admit / refuse
/// bools — the fleet-wide partial-progress readout a downstream
/// consumer branches on to surface the staging-tier admission; this
/// helper lifts the same structural-distinction discipline at
/// forge's two-axis composition. Tekton's `PipelineRun` tiered
/// admission gate surfaces the staging-tier band as the structural
/// conjunction "task-level success on at least one task AND not all
/// tasks succeeded AND no retries exhausted" — the intermediate
/// admit-to-staging band the production-promote step gates on.
#[allow(dead_code)]
pub fn compose_relaxed_eligible_strict_refused(
    probe: &ProbeCoverage,
    verification: &VerificationCoverage,
) -> bool {
    compose_admission_eligible_relaxed(probe, verification)
        && !compose_admission_eligible_strict(probe, verification)
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

    /// `VerificationCoverage::default()` is the empty-slice
    /// [`verification_coverage`] result and the identity element of the
    /// monoid `Add` impl below. Pins both surfaces against the same
    /// `{verified: 0, unverified: 0}` zero so a future regression that
    /// returned a non-zero default (e.g., `{verified: 1, unverified: 0}`
    /// as a "probably verified" stub) would fail this pin at both arms.
    /// Mirrors [`test_default_is_empty_probe_coverage`] at the
    /// orthogonal axis.
    #[test]
    fn test_default_is_empty_verification_coverage() {
        assert_eq!(
            VerificationCoverage::default(),
            VerificationCoverage {
                verified: 0,
                unverified: 0
            }
        );
        let empty: [&dyn VerifiedOutcome; 0] = [];
        assert_eq!(
            verification_coverage(empty.iter().copied()),
            VerificationCoverage::default()
        );
    }

    /// `Add` composes componentwise — `(a.verified + b.verified,
    /// a.unverified + b.unverified)` — and `total()` adds the same way
    /// (10 = 4 + 6; 4 = 3 + 1). The realistic Phase-1-flux / Phase-1-
    /// helm-release-signature / Phase-2-cosign fold a future product-
    /// level signal will run at the `compose_product_certification`
    /// call site: three per-record coverages summed into one product-
    /// record aggregate. A regression that swapped `verified` /
    /// `unverified` in the impl body would flip a high-trust product
    /// record into a fully-unverified one; this pin closes that arm.
    /// Mirrors [`test_add_composes_componentwise`] at the orthogonal
    /// axis.
    #[test]
    fn test_verification_add_composes_componentwise() {
        let flux = VerificationCoverage {
            verified: 3,
            unverified: 0,
        };
        let helm_signature = VerificationCoverage {
            verified: 1,
            unverified: 3,
        };
        let cosign = VerificationCoverage {
            verified: 0,
            unverified: 3,
        };
        let product = flux + helm_signature + cosign;
        assert_eq!(
            product,
            VerificationCoverage {
                verified: 4,
                unverified: 6
            }
        );
        assert_eq!(product.total(), 10);
    }

    /// `Default` is the identity of `Add` — `c + default() == c` and
    /// `default() + c == c` for every `c`. The monoid law THEORY §VI.1
    /// one-oracle discipline depends on at the orthogonal axis: a
    /// downstream verifier reading `product =
    /// phases.iter().sum::<VerificationCoverage>()` cannot drift from
    /// `product = phases[0] + phases[1] + ...` because the empty-fold
    /// seed is `default()` and `default()` is structurally the
    /// identity. A regression that returned a non-zero default would
    /// fail this pin at both arms. Mirrors
    /// [`test_add_default_is_identity`] at the orthogonal axis.
    #[test]
    fn test_verification_add_default_is_identity() {
        let c = VerificationCoverage {
            verified: 3,
            unverified: 4,
        };
        assert_eq!(c + VerificationCoverage::default(), c);
        assert_eq!(VerificationCoverage::default() + c, c);
    }

    /// `Add` is commutative and associative — the structural monoid
    /// laws that make `[a, b, c].iter().sum::<VerificationCoverage>()`
    /// independent of iteration order. A fleet-wide aggregator that
    /// folds across an unordered set of per-record coverages (a
    /// `HashMap<ProductId, VerificationCoverage>::values()` walk, for
    /// example) reads the same aggregate regardless of hash-map
    /// iteration order; this pin closes the "Add silently depends on
    /// argument order" regression arm. Mirrors
    /// [`test_add_is_commutative_and_associative`] at the orthogonal
    /// axis.
    #[test]
    fn test_verification_add_is_commutative_and_associative() {
        let a = VerificationCoverage {
            verified: 3,
            unverified: 0,
        };
        let b = VerificationCoverage {
            verified: 1,
            unverified: 3,
        };
        let c = VerificationCoverage {
            verified: 0,
            unverified: 3,
        };
        assert_eq!(a + b, b + a);
        assert_eq!((a + b) + c, a + (b + c));
    }

    /// `Add` saturates at `usize::MAX` rather than panicking on
    /// overflow — the load-bearing arithmetic the docstring above
    /// names. A fleet-wide aggregator summing across pathologically
    /// many per-record coverages (1 << 64 verification records on a
    /// 64-bit target, unreachable in practice but structurally
    /// foreclosed here) cannot drive a panic the unchecked `+` would
    /// surface; the monoid stays total over the full `usize` range and
    /// composes with the saturating
    /// [`VerificationCoverage::total`] ceiling one impl up so the
    /// post-`Add` aggregate can be handed to `total()` without
    /// re-introducing the panic. Mirrors
    /// [`test_add_saturates_at_usize_max`] at the orthogonal axis.
    #[test]
    fn test_verification_add_saturates_at_usize_max() {
        let max = VerificationCoverage {
            verified: usize::MAX,
            unverified: usize::MAX,
        };
        let plus_one = VerificationCoverage {
            verified: 1,
            unverified: 1,
        };
        assert_eq!(
            max + plus_one,
            VerificationCoverage {
                verified: usize::MAX,
                unverified: usize::MAX,
            }
        );
    }

    /// `AddAssign` is the in-place sibling of `Add` and produces the
    /// same value. A regression that decoupled the two impls (e.g.,
    /// reimplemented `add_assign` directly with a different arithmetic)
    /// would fail this pin. The `*self = *self + rhs` delegation in
    /// the impl body relies on the `Copy` derive on
    /// `VerificationCoverage`; this test exercises the round-trip.
    /// Mirrors [`test_add_assign_matches_add`] at the orthogonal axis.
    #[test]
    fn test_verification_add_assign_matches_add() {
        let mut acc = VerificationCoverage {
            verified: 3,
            unverified: 0,
        };
        acc += VerificationCoverage {
            verified: 1,
            unverified: 3,
        };
        acc += VerificationCoverage {
            verified: 0,
            unverified: 3,
        };
        assert_eq!(
            acc,
            VerificationCoverage {
                verified: 4,
                unverified: 6
            }
        );
    }

    /// `Sum` over an owned iterator folds with `Add` from `default()`.
    /// The realistic call-site shape a future product-level emission
    /// will use: collect per-phase coverages into a `Vec` (or an inline
    /// array), call `.into_iter().sum::<VerificationCoverage>()`, emit
    /// the aggregate as `product_verification_coverage_ratio`.
    /// Equivalent to the explicit `a + b + c` fold one assertion up —
    /// this pin closes the "Sum drifts from Add" regression arm.
    /// Mirrors [`test_sum_owned_iterator_folds_with_add`] at the
    /// orthogonal axis.
    #[test]
    fn test_verification_sum_owned_iterator_folds_with_add() {
        let phases = vec![
            VerificationCoverage {
                verified: 3,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 1,
                unverified: 3,
            },
            VerificationCoverage {
                verified: 0,
                unverified: 3,
            },
        ];
        let product: VerificationCoverage = phases.into_iter().sum();
        assert_eq!(
            product,
            VerificationCoverage {
                verified: 4,
                unverified: 6
            }
        );
        assert_eq!(product.total(), 10);
    }

    /// `Sum` over a borrowed iterator
    /// (`.iter().sum::<VerificationCoverage>()` — no `.copied()` at the
    /// call site) returns the same aggregate as the owned form. The
    /// borrowed `Sum<&'a Self>` impl exists so `&[VerificationCoverage]`
    /// reaches the idiomatic numeric-`Sum` shape every `<i64 as Sum<&'a
    /// i64>>`-style impl in `std` already admits; a regression that
    /// diverged the two surfaces would fail this pin. Mirrors
    /// [`test_sum_borrowed_iterator_matches_owned`] at the orthogonal
    /// axis.
    #[test]
    fn test_verification_sum_borrowed_iterator_matches_owned() {
        let phases = [
            VerificationCoverage {
                verified: 3,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 1,
                unverified: 3,
            },
            VerificationCoverage {
                verified: 0,
                unverified: 3,
            },
        ];
        let borrowed: VerificationCoverage = phases.iter().sum();
        let owned: VerificationCoverage = phases.into_iter().sum();
        assert_eq!(borrowed, owned);
        assert_eq!(
            borrowed,
            VerificationCoverage {
                verified: 4,
                unverified: 6
            }
        );
    }

    /// `Sum` over an empty iterator returns `default()` — the identity
    /// of the monoid. Symmetric to
    /// [`test_verification_coverage_empty_slice`] one layer over: the
    /// empty-slice trait-object walk and the empty-`Vec`-of-coverages
    /// fold produce the same `VerificationCoverage { verified: 0,
    /// unverified: 0 }` value, so the two surfaces compose without a
    /// structural seam at the empty-input boundary. Mirrors
    /// [`test_sum_empty_iterator_is_default`] at the orthogonal axis.
    #[test]
    fn test_verification_sum_empty_iterator_is_default() {
        let empty: Vec<VerificationCoverage> = Vec::new();
        let aggregate: VerificationCoverage = empty.into_iter().sum();
        assert_eq!(aggregate, VerificationCoverage::default());
        assert_eq!(aggregate.total(), 0);
    }

    /// `is_fully_verified()` returns `true` iff every counted
    /// verification-bearing outcome substantiated a positive verdict —
    /// `verified > 0 && unverified == 0`. Pinned across the three
    /// load-bearing total counts (2 for Phase 1 flux-source +
    /// helm-release-signature, 3 for Phase 2 helm-provenance + cosign +
    /// network-policy, 5 for the full Phase 1 + Phase 2 aggregate) so a
    /// future regression that hardcoded the unverified-count check to
    /// one specific N would fail against the other two. The typed
    /// discriminator a downstream `sekiban` strict-production admission
    /// verifier reads at the orthogonal axis to
    /// [`ProbeCoverage::is_fully_covered`] — the empty-slice boundary
    /// (`verified: 0, unverified: 0`) does NOT satisfy this predicate,
    /// structurally separating the all-verified ceiling from the
    /// empty boundary the future `verification_ratio()` collapses with
    /// the all-unverified floor (sibling pin
    /// `test_is_fully_verified_empty_returns_false` closes that arm).
    #[test]
    fn test_is_fully_verified_all_verified_is_true() {
        assert!(VerificationCoverage {
            verified: 2,
            unverified: 0
        }
        .is_fully_verified());
        assert!(VerificationCoverage {
            verified: 3,
            unverified: 0
        }
        .is_fully_verified());
        assert!(VerificationCoverage {
            verified: 5,
            unverified: 0
        }
        .is_fully_verified());
    }

    /// `is_fully_verified()` returns `false` for the empty-slice
    /// boundary case `verification_coverage` over an empty iterator
    /// produces (`verified: 0, unverified: 0`). The structural
    /// discriminator from the all-verified ceiling arm one pin up: both
    /// the empty case and the all-unverified floor will collapse to the
    /// future `verification_ratio() == 0.0` arm the ratio lift will
    /// produce, but the empty case must not satisfy `is_fully_verified`.
    /// A future regression that relaxed the predicate to `unverified ==
    /// 0` alone (dropping the `verified > 0` conjunct) would silently
    /// flip the empty case to `true` and pass the strict-production gate
    /// vacuously; this pin closes that arm. Mirrors
    /// `test_is_fully_covered_empty_returns_false` at the orthogonal
    /// axis.
    #[test]
    fn test_is_fully_verified_empty_returns_false() {
        let empty = VerificationCoverage {
            verified: 0,
            unverified: 0,
        };
        assert!(!empty.is_fully_verified());
        assert!(empty.is_empty());
    }

    /// `is_fully_verified()` returns `false` when any counted outcome
    /// failed to substantiate a positive verdict — the all-unverified
    /// floor (today's `compose_product_certification` call-site state
    /// before the five `Verified`-bearing outcomes wire real verification
    /// substantiations at their probe sites) and the mixed-split
    /// intermediate states a follow-up that wires positive verdicts at
    /// some-but-not-all of the five sites will produce. Pinned across
    /// the all-unverified floor and three realistic mixed-split shapes
    /// (1-of-2, 3-of-5, 2-of-3) so a future regression that hardcoded
    /// the predicate to one specific `unverified` value would fail across
    /// the others. Mirrors `test_is_fully_covered_any_absent_is_false`
    /// at the orthogonal axis.
    #[test]
    fn test_is_fully_verified_any_unverified_is_false() {
        assert!(!VerificationCoverage {
            verified: 0,
            unverified: 5
        }
        .is_fully_verified());
        assert!(!VerificationCoverage {
            verified: 1,
            unverified: 1
        }
        .is_fully_verified());
        assert!(!VerificationCoverage {
            verified: 3,
            unverified: 2
        }
        .is_fully_verified());
        assert!(!VerificationCoverage {
            verified: 2,
            unverified: 1
        }
        .is_fully_verified());
    }

    /// `is_fully_verified()` composes with the monoid `Add` shape exactly
    /// the way a downstream fleet-wide aggregator depends on: summing a
    /// fully-verified Phase 1 coverage with an any-unverified Phase 2
    /// coverage produces an any-unverified aggregate (one unverified
    /// outcome in any phase poisons the strict-production gate). Mirrors
    /// the structural intuition: a product certification is fully
    /// verified only when every phase is fully verified, the orthogonal
    /// peer of `test_is_fully_covered_sums_under_monoid_add`.
    #[test]
    fn test_is_fully_verified_sums_under_monoid_add() {
        let phase_1 = VerificationCoverage {
            verified: 2,
            unverified: 0,
        };
        let phase_2_partial = VerificationCoverage {
            verified: 1,
            unverified: 2,
        };
        let phase_2_fully_verified = VerificationCoverage {
            verified: 3,
            unverified: 0,
        };
        assert!(phase_1.is_fully_verified());
        assert!(!phase_2_partial.is_fully_verified());
        assert!(phase_2_fully_verified.is_fully_verified());
        assert!(!(phase_1 + phase_2_partial).is_fully_verified());
        assert!((phase_1 + phase_2_fully_verified).is_fully_verified());
        assert!(!(phase_1 + phase_2_partial + phase_2_fully_verified).is_fully_verified());
    }

    /// `is_empty()` returns `true` for the empty-slice boundary case
    /// `verification_coverage` over an empty iterator produces
    /// (`verified: 0, unverified: 0`), and `false` for every reachable
    /// non-empty `VerificationCoverage` value. The structural
    /// disambiguator a downstream verifier reads to separate "no
    /// verification-bearing outcomes counted" from "every counted
    /// outcome unverified" — both will collapse to the future
    /// `verification_ratio() == 0.0` arm the ratio lift will produce,
    /// but only the former satisfies `is_empty()`. Pinned across the
    /// all-unverified floor (`verified: 0, unverified: N`) and three
    /// mixed splits to close the "regression that hardcoded
    /// `is_empty` to `verified == 0`" arm (which would silently satisfy
    /// the all-unverified case). Mirrors `test_is_empty_pins_empty_
    /// boundary` at the orthogonal axis.
    #[test]
    fn test_verification_is_empty_pins_empty_boundary() {
        assert!(VerificationCoverage::default().is_empty());
        assert!(VerificationCoverage {
            verified: 0,
            unverified: 0
        }
        .is_empty());
        assert!(!VerificationCoverage {
            verified: 0,
            unverified: 5
        }
        .is_empty());
        assert!(!VerificationCoverage {
            verified: 2,
            unverified: 3
        }
        .is_empty());
        assert!(!VerificationCoverage {
            verified: 5,
            unverified: 0
        }
        .is_empty());
    }

    /// `is_empty()` and `is_fully_verified()` are mutually exclusive — no
    /// reachable `VerificationCoverage` value satisfies both. The empty
    /// case fails `is_fully_verified` (the `verified > 0` conjunct
    /// excludes it), and the fully-verified case fails `is_empty`
    /// (`verified > 0 && unverified == 0` implies `total() > 0`). Pinned
    /// across the four-arm decision matrix the docstring on
    /// [`VerificationCoverage::is_fully_verified`] tabulates so a
    /// regression that decoupled the two predicates would fail the
    /// mutual-exclusion invariant here. Mirrors
    /// `test_is_empty_and_is_fully_covered_are_mutually_exclusive` at
    /// the orthogonal axis.
    #[test]
    fn test_verification_is_empty_and_is_fully_verified_are_mutually_exclusive() {
        let empty = VerificationCoverage {
            verified: 0,
            unverified: 0,
        };
        let all_unverified = VerificationCoverage {
            verified: 0,
            unverified: 5,
        };
        let mixed = VerificationCoverage {
            verified: 2,
            unverified: 3,
        };
        let fully_verified = VerificationCoverage {
            verified: 5,
            unverified: 0,
        };
        for c in [empty, all_unverified, mixed, fully_verified] {
            assert!(
                !(c.is_empty() && c.is_fully_verified()),
                "is_empty and is_fully_verified must be mutually exclusive at {c:?}",
            );
        }
    }

    /// `is_all_unverified()` returns `true` at the all-unverified floor —
    /// every counted verification-bearing outcome failed to substantiate
    /// a positive verdict — `verified == 0 && unverified > 0`. Pinned
    /// across the three load-bearing total counts (2 for Phase 1
    /// flux-source + helm-release-signature, 3 for Phase 2
    /// helm-provenance + cosign + network-policy, 5 for the full
    /// Phase 1 + Phase 2 aggregate) so a future regression that
    /// hardcoded the `unverified > 0` check to one specific N would
    /// fail against the other two. The typed discriminator the
    /// strict-production / relaxed-staging admission verifiers read to
    /// fail closed on today's call-site state — every counted
    /// `Verified`-bearing typed outcome bound at its `Unverified` /
    /// `VerifyFailed` arm. Mirrors `test_is_all_absent_when_no_probe_ran_is_true`
    /// at the orthogonal axis.
    #[test]
    fn test_is_all_unverified_when_no_outcome_verified_is_true() {
        assert!(VerificationCoverage {
            verified: 0,
            unverified: 2
        }
        .is_all_unverified());
        assert!(VerificationCoverage {
            verified: 0,
            unverified: 3
        }
        .is_all_unverified());
        assert!(VerificationCoverage {
            verified: 0,
            unverified: 5
        }
        .is_all_unverified());
    }

    /// `is_all_unverified()` returns `false` for the empty-slice boundary
    /// case `verification_coverage` over an empty iterator produces
    /// (`verified: 0, unverified: 0`). The structural disambiguator from
    /// the all-unverified arm: both have `verified == 0` but only the
    /// all-unverified arm has `unverified > 0`. A future regression that
    /// relaxed the predicate to `verified == 0` alone (dropping the
    /// `unverified > 0` conjunct) would silently flip the empty case to
    /// `true` and conflate the boundary; this pin closes that arm.
    /// Symmetric to `test_is_all_absent_empty_returns_false` at the
    /// orthogonal axis.
    #[test]
    fn test_is_all_unverified_empty_returns_false() {
        let empty = VerificationCoverage {
            verified: 0,
            unverified: 0,
        };
        assert!(!empty.is_all_unverified());
        assert!(empty.is_empty());
    }

    /// `is_all_unverified()` returns `false` whenever any counted
    /// verification-bearing outcome substantiated a positive verdict —
    /// the fully-verified ceiling AND the mixed-split intermediate
    /// states. Pinned across the all-verified ceiling (2, 3, 5) plus
    /// three mixed-split shapes (1-of-2, 3-of-5, 2-of-3) so a future
    /// regression that hardcoded the predicate to one specific
    /// `verified` value would fail across the others. Symmetric to
    /// `test_is_all_absent_any_ran_is_false` at the orthogonal axis.
    #[test]
    fn test_is_all_unverified_any_verified_is_false() {
        assert!(!VerificationCoverage {
            verified: 2,
            unverified: 0
        }
        .is_all_unverified());
        assert!(!VerificationCoverage {
            verified: 3,
            unverified: 0
        }
        .is_all_unverified());
        assert!(!VerificationCoverage {
            verified: 5,
            unverified: 0
        }
        .is_all_unverified());
        assert!(!VerificationCoverage {
            verified: 1,
            unverified: 1
        }
        .is_all_unverified());
        assert!(!VerificationCoverage {
            verified: 3,
            unverified: 2
        }
        .is_all_unverified());
        assert!(!VerificationCoverage {
            verified: 2,
            unverified: 1
        }
        .is_all_unverified());
    }

    /// `is_all_unverified()` composes with the monoid `Add` shape the
    /// way a downstream fleet-wide aggregator depends on: summing two
    /// all-unverified per-phase verifications stays all-unverified (no
    /// phase added a positive substantiation), but summing an
    /// all-unverified phase with any phase that has `verified > 0`
    /// produces a non-all-unverified aggregate (any phase that
    /// substantiated a positive verdict lifts the aggregate off the
    /// all-unverified floor). Mirrors `test_is_all_absent_sums_under_monoid_add`
    /// at the orthogonal axis: a product certification rests on the
    /// all-unverified floor only when every phase rested there too.
    #[test]
    fn test_is_all_unverified_sums_under_monoid_add() {
        let phase1_unverified = VerificationCoverage {
            verified: 0,
            unverified: 2,
        };
        let phase2_unverified = VerificationCoverage {
            verified: 0,
            unverified: 3,
        };
        let phase2_verified = VerificationCoverage {
            verified: 1,
            unverified: 2,
        };
        assert!(phase1_unverified.is_all_unverified());
        assert!(phase2_unverified.is_all_unverified());
        assert!(!phase2_verified.is_all_unverified());
        assert!((phase1_unverified + phase2_unverified).is_all_unverified());
        assert!(!(phase1_unverified + phase2_verified).is_all_unverified());
        assert!(!(phase2_unverified + phase2_verified).is_all_unverified());
    }

    /// `is_all_unverified()` stays saturation-robust at the
    /// `(verified: 0, unverified: usize::MAX)` arm — both
    /// `is_all_unverified` AND `is_saturated` are `true`, the
    /// discriminator does not silently flip at the saturated state.
    /// `verification_ratio()` reads as `0.0` correctly here (the
    /// saturated `unverified` component does not poison the numerator),
    /// but the symmetric `{verified: usize::MAX, unverified: usize::MAX}`
    /// shape against `verification_ratio() == 0.0` would not be able to
    /// disambiguate "every counted outcome unverified" from "the
    /// saturating clamp dropped equal substantiation at the ceiling"
    /// (the post-saturation state reads ratio 1.0). The integer-
    /// arithmetic body `verified == 0 && unverified > 0` forecloses
    /// both drift directions through equality / inequality tests on the
    /// components themselves. Mirrors
    /// `test_is_all_absent_stays_robust_at_saturated_absent` at the
    /// orthogonal axis exactly.
    #[test]
    fn test_is_all_unverified_stays_robust_at_saturated_unverified() {
        let saturated_unverified = VerificationCoverage {
            verified: 0,
            unverified: usize::MAX,
        };
        assert!(saturated_unverified.is_all_unverified());
        assert!(saturated_unverified.is_saturated());
        assert!(!saturated_unverified.is_empty());
        assert!(!saturated_unverified.is_fully_verified());
        assert_eq!(saturated_unverified.verification_ratio(), 0.0);
        assert_eq!(saturated_unverified.verification_ratio_pct(), 0);

        let saturated_both = VerificationCoverage {
            verified: usize::MAX,
            unverified: usize::MAX,
        };
        assert!(!saturated_both.is_all_unverified());
    }

    /// `verification_ratio()` returns `0.0` for the empty-slice boundary
    /// case `verification_coverage` over an empty iterator produces. The
    /// structural distinction between "no outcomes counted" and "every
    /// outcome unverified" is preserved at `total()` (which returns `0`
    /// here vs. `N` for the all-unverified floor), not flattened into
    /// the ratio. A future regression that hand-rolled the division
    /// without guarding the `total == 0` denominator would emit
    /// `f64::NAN` and fail this pin, surfacing the boundary case at the
    /// typed-primitive site rather than at a downstream tracing-field
    /// emission. Mirrors `test_coverage_ratio_empty_returns_zero` at
    /// the orthogonal axis.
    #[test]
    fn test_verification_ratio_empty_returns_zero() {
        let coverage = VerificationCoverage {
            verified: 0,
            unverified: 0,
        };
        assert_eq!(coverage.total(), 0);
        assert_eq!(coverage.verification_ratio(), 0.0);
    }

    /// `verification_ratio()` returns `1.0` when every counted outcome
    /// substantiated a positive verdict — the all-verified ceiling.
    /// Pinned across the three load-bearing total counts (2 for Phase 1
    /// flux-source + helm-release-signature, 3 for Phase 2
    /// helm-provenance + cosign + network-policy, 5 for the full
    /// Phase 1 + Phase 2 aggregate) so a future regression that
    /// hardcoded the denominator to one specific total would fail
    /// against the other two. Mirrors
    /// `test_coverage_ratio_all_ran_is_one` at the orthogonal axis.
    #[test]
    fn test_verification_ratio_all_verified_is_one() {
        assert_eq!(
            VerificationCoverage {
                verified: 2,
                unverified: 0
            }
            .verification_ratio(),
            1.0
        );
        assert_eq!(
            VerificationCoverage {
                verified: 3,
                unverified: 0
            }
            .verification_ratio(),
            1.0
        );
        assert_eq!(
            VerificationCoverage {
                verified: 5,
                unverified: 0
            }
            .verification_ratio(),
            1.0
        );
    }

    /// `verification_ratio()` returns `0.0` when every counted outcome
    /// failed verification — the all-unverified floor today's
    /// `compose_product_certification` call-site state sits at before
    /// the five `Verified`-bearing outcomes wire real substantiations
    /// at their probe sites. The structural disambiguator from the
    /// empty-slice case is `total() > 0` here vs. `total() == 0` for
    /// the empty boundary; both produce `verification_ratio() == 0.0`
    /// but a consumer can recover the kind-of-claim from the `total`
    /// field. Mirrors `test_coverage_ratio_all_absent_is_zero` at the
    /// orthogonal axis.
    #[test]
    fn test_verification_ratio_all_unverified_is_zero() {
        let coverage = VerificationCoverage {
            verified: 0,
            unverified: 5,
        };
        assert_eq!(coverage.total(), 5);
        assert_eq!(coverage.verification_ratio(), 0.0);
    }

    /// `verification_ratio()` returns the arithmetic fraction for the
    /// mixed split — the realistic Phase 1 + Phase 2
    /// verification-trustworthiness intermediate state a follow-up that
    /// wires positive verdicts at some-but-not-all of the five sites
    /// will produce. The half-and-half (1, 1) corner pins `0.5`
    /// exactly under IEEE-754 (no floating-point rounding to chase);
    /// the 2-of-5 split exercises the realistic Phase 1
    /// flux-source-verified + helm-release-signature-failed +
    /// Phase 2 three-of-three-failed shape. A regression that swapped
    /// `verified` and `unverified` in the numerator would flip `2/5`
    /// to `3/5` and fail this pin. Mirrors
    /// `test_coverage_ratio_mixed_split_arithmetic` at the orthogonal
    /// axis.
    #[test]
    fn test_verification_ratio_mixed_split_arithmetic() {
        assert_eq!(
            VerificationCoverage {
                verified: 1,
                unverified: 1
            }
            .verification_ratio(),
            0.5
        );
        assert_eq!(
            VerificationCoverage {
                verified: 2,
                unverified: 3
            }
            .verification_ratio(),
            2.0 / 5.0
        );
        assert_eq!(
            VerificationCoverage {
                verified: 1,
                unverified: 2
            }
            .verification_ratio(),
            1.0 / 3.0
        );
    }

    /// `verification_ratio()` does not panic at the post-saturation
    /// state `{verified: usize::MAX, unverified: usize::MAX}` — it
    /// routes through `total()`, which saturates at `usize::MAX` rather
    /// than overflowing on `verified + unverified`. The float
    /// arithmetic `usize::MAX as f64 / usize::MAX as f64` is `1.0` in
    /// IEEE-754 (both numerator and denominator round identically to
    /// the same `f64`), which the pin asserts directly. A future
    /// regression that reverted `total()` to the unchecked `+` would
    /// panic at this call site in debug and produce a nonsensical
    /// wrapped ratio in release — both arms closed here. Mirrors
    /// `test_coverage_ratio_does_not_panic_at_saturated_state` at the
    /// orthogonal axis: the monoid totality is upheld at every method
    /// a future telemetry emission site reads, not just at `Add`.
    #[test]
    fn test_verification_ratio_does_not_panic_at_saturated_state() {
        let saturated = VerificationCoverage {
            verified: usize::MAX,
            unverified: usize::MAX,
        };
        assert_eq!(saturated.verification_ratio(), 1.0);
    }

    /// `verification_ratio()` is deterministic — repeated calls on the
    /// same `VerificationCoverage` value return bit-identical `f64`s.
    /// Pins that the method is a pure function of `verified` /
    /// `unverified` with no hidden state (e.g. a stray `rand` or a
    /// cached interior-mutable field), the load-bearing invariant a
    /// downstream `sekiban` admission verifier reconciliation depends
    /// on when comparing two telemetry emissions of the same
    /// `VerificationCoverage` for equality. Mirrors
    /// `test_coverage_ratio_is_deterministic` at the orthogonal axis.
    #[test]
    fn test_verification_ratio_is_deterministic() {
        let coverage = VerificationCoverage {
            verified: 2,
            unverified: 3,
        };
        let first = coverage.verification_ratio();
        let second = coverage.verification_ratio();
        assert_eq!(first.to_bits(), second.to_bits());
    }

    /// `is_saturated()` returns `true` at every state where at least one
    /// component has hit the saturating-add ceiling `usize::MAX`. Pinned
    /// across the five reachable saturated arms — `verified` only
    /// saturated, `unverified` only saturated, both at the ceiling, and
    /// the asymmetric `(MAX, N)` / `(N, MAX)` representatives — so a
    /// future regression that hardcoded the predicate to one component
    /// would fail against the others. Mirrors the
    /// [`test_is_saturated_at_any_component_max_is_true`] pin at the
    /// orthogonal axis. The typed-primitive flag a downstream `sekiban`
    /// admission verifier reads alongside `verification_ratio()` to know
    /// the derived ratio is unreliable: at every state this predicate
    /// returns `true`, the float division `verified as f64 / total() as
    /// f64` has dropped at least one true increment past the saturating
    /// clamp.
    #[test]
    fn test_verification_is_saturated_at_any_component_max_is_true() {
        assert!(VerificationCoverage {
            verified: usize::MAX,
            unverified: 0,
        }
        .is_saturated());
        assert!(VerificationCoverage {
            verified: 0,
            unverified: usize::MAX,
        }
        .is_saturated());
        assert!(VerificationCoverage {
            verified: usize::MAX,
            unverified: usize::MAX,
        }
        .is_saturated());
        assert!(VerificationCoverage {
            verified: usize::MAX,
            unverified: 42,
        }
        .is_saturated());
        assert!(VerificationCoverage {
            verified: 42,
            unverified: usize::MAX,
        }
        .is_saturated());
    }

    /// `is_saturated()` returns `false` for every realistically-sized
    /// `VerificationCoverage` value. Pinned across the four arms of the
    /// matrix the docstring on [`VerificationCoverage::is_fully_verified`]
    /// tabulates (empty, all-unverified, mixed, fully-verified) so a
    /// future regression that flipped the predicate to a vacuous `true`
    /// would fail every arm here. Symmetric to the saturated-true pin one
    /// test up: the two pins together pin the boundary between the
    /// saturated and unsaturated regions of `VerificationCoverage`
    /// exactly at the component-MAX inflection. Mirrors
    /// [`test_is_saturated_below_ceiling_is_false`] at the orthogonal
    /// axis, with the four-arm shape adapted to the verification axis
    /// (`{0, 0}` empty, `{0, 5}` all-unverified, `{2, 3}` mixed, `{3, 0}`
    /// fully-verified) plus the just-below-ceiling pair the no-evidence
    /// axis test also pins.
    #[test]
    fn test_verification_is_saturated_below_ceiling_is_false() {
        assert!(!VerificationCoverage {
            verified: 0,
            unverified: 0,
        }
        .is_saturated());
        assert!(!VerificationCoverage {
            verified: 0,
            unverified: 5,
        }
        .is_saturated());
        assert!(!VerificationCoverage {
            verified: 2,
            unverified: 3,
        }
        .is_saturated());
        assert!(!VerificationCoverage {
            verified: 3,
            unverified: 0,
        }
        .is_saturated());
        assert!(!VerificationCoverage {
            verified: usize::MAX - 1,
            unverified: usize::MAX - 1,
        }
        .is_saturated());
    }

    /// `is_saturated()` is the load-bearing trustworthiness flag at the
    /// `{verified: MAX, unverified: MAX}` post-saturation state where the
    /// true ratio is 0.5 (every saturated component dropped equal evidence
    /// past the ceiling), but `verification_ratio()` reads as `1.0` — the
    /// f64 division `MAX as f64 / MAX as f64` rounds identically against
    /// the IEEE-754 representation. A downstream verifier that gates only
    /// on `verification_ratio() >= 0.5` would silently accept this state
    /// as fully verified; the typed `is_saturated()` flag forces the
    /// verifier through the trustworthiness predicate the f64 division
    /// alone cannot surface. This pin is the structural witness for the
    /// docstring's "honest-signal drift" claim — `is_saturated` is `true`
    /// exactly at the state where `verification_ratio` is untrustworthy.
    /// Mirrors [`test_is_saturated_flags_coverage_ratio_drift_at_
    /// saturated_state`] at the orthogonal axis, with the additional
    /// `is_fully_verified` / `is_empty` saturation-robustness arms
    /// matching the `is_fully_covered` / `is_empty` shape one impl group
    /// up.
    #[test]
    fn test_verification_is_saturated_flags_verification_ratio_drift_at_saturated_state() {
        let saturated = VerificationCoverage {
            verified: usize::MAX,
            unverified: usize::MAX,
        };
        assert!(saturated.is_saturated());
        assert_eq!(saturated.verification_ratio(), 1.0);
        assert!(!saturated.is_fully_verified());
        assert!(!saturated.is_empty());
    }

    /// `is_saturated()` is reachable in finite steps from any unsaturated
    /// starting point via the monoid `Add` — the saturating-add clamp at
    /// the component level forecloses `usize::MAX` as an asymptotic limit
    /// of repeated addition. Mirrors the
    /// [`test_verification_add_saturates_at_usize_max`] pin one layer
    /// over: the pin there proves the saturating clamp at the `Add` impl,
    /// this pin proves the typed-primitive flag surfaces the resulting
    /// state. Together they close the round-trip: a fleet-wide aggregator
    /// summing per-record coverages via
    /// `.iter().sum::<VerificationCoverage>()` reaches the saturated state
    /// in finite steps, and the resulting telemetry record flags itself
    /// as saturated through the typed predicate here. Mirrors
    /// [`test_is_saturated_reached_through_monoid_add`] at the orthogonal
    /// axis.
    #[test]
    fn test_verification_is_saturated_reached_through_monoid_add() {
        let high = VerificationCoverage {
            verified: usize::MAX - 3,
            unverified: 0,
        };
        let increment = VerificationCoverage {
            verified: 7,
            unverified: 0,
        };
        let aggregate = high + increment;
        assert_eq!(aggregate.verified, usize::MAX);
        assert!(aggregate.is_saturated());
        assert!(!high.is_saturated());
    }

    /// `is_saturated()` composes with the monoid `Add` shape exactly the
    /// way a downstream fleet-wide aggregator depends on: summing a
    /// saturated Phase 1 flux-source coverage with an unsaturated Phase 2
    /// helm-provenance coverage produces a saturated aggregate (one
    /// saturated component in any phase poisons the trustworthiness
    /// signal). Mirrors the
    /// [`test_is_saturated_propagates_under_monoid_add`] pin at the
    /// orthogonal axis: a product certification's `verification_ratio()`
    /// is trustworthy only when every phase is unsaturated.
    #[test]
    fn test_verification_is_saturated_propagates_under_monoid_add() {
        let flux_saturated = VerificationCoverage {
            verified: usize::MAX,
            unverified: 0,
        };
        let helm_release_normal = VerificationCoverage {
            verified: 1,
            unverified: 0,
        };
        let helm_provenance_normal = VerificationCoverage {
            verified: 0,
            unverified: 3,
        };
        assert!(flux_saturated.is_saturated());
        assert!(!helm_release_normal.is_saturated());
        assert!(!helm_provenance_normal.is_saturated());
        assert!((flux_saturated + helm_release_normal).is_saturated());
        assert!((helm_release_normal + helm_provenance_normal + flux_saturated).is_saturated());
        assert!(!(helm_release_normal + helm_provenance_normal).is_saturated());
    }

    /// `verification_ratio_pct()` returns `0` for the empty-slice
    /// boundary case `verification_coverage` over an empty iterator
    /// produces. The structural distinction between "no outcomes
    /// counted" and "every outcome unverified" stays at `total()`
    /// (which returns `0` here vs. `N` for the all-unverified floor),
    /// not flattened into the integer percent. Mirrors
    /// `test_coverage_ratio_pct_empty_returns_zero` at the orthogonal
    /// axis and `test_verification_ratio_empty_returns_zero` for the
    /// float surface.
    #[test]
    fn test_verification_ratio_pct_empty_returns_zero() {
        let empty = VerificationCoverage {
            verified: 0,
            unverified: 0,
        };
        assert_eq!(empty.total(), 0);
        assert_eq!(empty.verification_ratio_pct(), 0);
    }

    /// `verification_ratio_pct()` returns `100` for the all-verified
    /// ceiling. Pinned across the three load-bearing total counts (2
    /// for Phase 1 flux-source + helm-release-signature, 3 for Phase 2
    /// helm-provenance + cosign + network-policy, 5 for the full
    /// Phase 1 + Phase 2 aggregate) so a future regression that
    /// hardcoded the denominator to one specific total would fail
    /// against the other two. The integer-form ceiling the typed
    /// admission gate `*_verification_coverage_ratio_pct >= 100` reads
    /// against, dual of the float-form `verification_ratio() == 1.0`
    /// ceiling. Mirrors `test_coverage_ratio_pct_all_ran_is_hundred` at
    /// the orthogonal axis.
    #[test]
    fn test_verification_ratio_pct_all_verified_is_hundred() {
        assert_eq!(
            VerificationCoverage {
                verified: 2,
                unverified: 0,
            }
            .verification_ratio_pct(),
            100
        );
        assert_eq!(
            VerificationCoverage {
                verified: 3,
                unverified: 0,
            }
            .verification_ratio_pct(),
            100
        );
        assert_eq!(
            VerificationCoverage {
                verified: 5,
                unverified: 0,
            }
            .verification_ratio_pct(),
            100
        );
    }

    /// `verification_ratio_pct()` returns `0` when every counted
    /// outcome failed verification — the all-unverified floor today's
    /// `compose_product_certification` call-site state sits at before
    /// the five `Verified`-bearing outcomes wire real substantiations.
    /// The structural disambiguator from the empty-slice case is
    /// `total() > 0` here vs. `total() == 0` for the empty boundary;
    /// both produce `verification_ratio_pct() == 0` but a consumer can
    /// recover the kind-of-claim from the `total` field. Mirrors
    /// `test_coverage_ratio_pct_all_absent_is_zero` at the orthogonal
    /// axis.
    #[test]
    fn test_verification_ratio_pct_all_unverified_is_zero() {
        let all_unverified = VerificationCoverage {
            verified: 0,
            unverified: 5,
        };
        assert_eq!(all_unverified.total(), 5);
        assert_eq!(all_unverified.verification_ratio_pct(), 0);
    }

    /// `verification_ratio_pct()` floors `(verified * 100) / total` to
    /// the nearest integer percent (Euclidean division, no rounding).
    /// Pinned across the half-and-half `(1, 1)` corner, the realistic
    /// Phase 1 + Phase 2 two-of-five split, and the just-below-90%
    /// state so a future regression that swapped `verified` and
    /// `unverified` in the numerator would flip `2/5 = 40` to
    /// `3/5 = 60` and fail this pin. The floor discipline is
    /// load-bearing for the admission threshold: a verifier gating `>=
    /// 90` against `(verified: 89, unverified: 11)` reads
    /// `verification_ratio_pct() == 89` (the floor of `89.0/100 = 89%`,
    /// dropping the 0.0 fractional), correctly refusing the
    /// just-below state, where a round-half-up form would silently
    /// admit the just-below-90% state. Mirrors
    /// `test_coverage_ratio_pct_mixed_split_arithmetic` at the
    /// orthogonal axis.
    #[test]
    fn test_verification_ratio_pct_mixed_split_arithmetic() {
        assert_eq!(
            VerificationCoverage {
                verified: 1,
                unverified: 1,
            }
            .verification_ratio_pct(),
            50
        );
        assert_eq!(
            VerificationCoverage {
                verified: 2,
                unverified: 3,
            }
            .verification_ratio_pct(),
            40
        );
        assert_eq!(
            VerificationCoverage {
                verified: 1,
                unverified: 2,
            }
            .verification_ratio_pct(),
            33
        );
        assert_eq!(
            VerificationCoverage {
                verified: 89,
                unverified: 11,
            }
            .verification_ratio_pct(),
            89,
            "the just-below-90% state floors to 89 — the strict \
             admission threshold `>= 90` correctly refuses this state"
        );
    }

    /// `verification_ratio_pct()` does not panic at the post-saturation
    /// state `{verified: usize::MAX, unverified: usize::MAX}` — the
    /// `u128` cast at the multiplication forecloses the `verified *
    /// 100` overflow `usize::MAX * 100` would surface in the unchecked
    /// `usize` arithmetic. The `MAX * 100 / MAX` reading is `100`
    /// (every saturated component dropped equal evidence past the
    /// ceiling), the same drift `verification_ratio()`'s float reading
    /// of `1.0` against the true `0.5` surfaces — the orthogonal
    /// [`VerificationCoverage::is_saturated`] flag is the trust-
    /// worthiness signal a downstream verifier reads alongside this
    /// field to foreclose the drift class at the wire level. Mirrors
    /// `test_coverage_ratio_pct_does_not_panic_at_saturated_state` at
    /// the orthogonal axis: the monoid totality is upheld at the
    /// integer-percent surface as well.
    #[test]
    fn test_verification_ratio_pct_does_not_panic_at_saturated_state() {
        let saturated = VerificationCoverage {
            verified: usize::MAX,
            unverified: usize::MAX,
        };
        assert_eq!(saturated.verification_ratio_pct(), 100);
        assert!(saturated.is_saturated());
    }

    /// `verification_ratio_pct()` is in `0..=100` for every reachable
    /// `VerificationCoverage` value — the invariant the `u8` return
    /// type surfaces structurally. The cast `((verified * 100) /
    /// total) as u8` is structurally lossless because `verified <=
    /// total` (componentwise) implies `(verified * 100) / total <=
    /// 100`. Pinned across the four arms of the matrix the docstring
    /// on [`VerificationCoverage::is_fully_verified`] tabulates
    /// (empty, all-unverified, mixed, fully-verified) AND the
    /// saturated boundary so a future regression that decoupled the
    /// `<= 100` bound would fail this pin at one of the arms it
    /// over-shot. Mirrors `test_coverage_ratio_pct_is_in_range_0_to_100`
    /// at the orthogonal axis.
    #[test]
    fn test_verification_ratio_pct_is_in_range_0_to_100() {
        let cases = [
            VerificationCoverage {
                verified: 0,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 0,
                unverified: 5,
            },
            VerificationCoverage {
                verified: 2,
                unverified: 3,
            },
            VerificationCoverage {
                verified: 5,
                unverified: 0,
            },
            VerificationCoverage {
                verified: usize::MAX,
                unverified: 0,
            },
            VerificationCoverage {
                verified: usize::MAX,
                unverified: usize::MAX,
            },
        ];
        for c in cases {
            let pct = c.verification_ratio_pct();
            assert!(
                pct <= 100,
                "verification_ratio_pct must be in 0..=100 at {c:?} — got {pct}",
            );
        }
    }

    /// `verification_ratio_pct()` floors to the same integer the
    /// f64-multiplied `verification_ratio() * 100.0` form reads at
    /// every non-saturated value. Pinned across the four arms of the
    /// matrix plus a near-boundary just-below-threshold case so a
    /// regression that drifted between the float and integer surfaces
    /// (e.g., hand-rolled the integer body via the f64 round-trip
    /// `(self.verification_ratio() * 100.0) as u8`, which would
    /// inherit the IEEE-754 imprecision the docstring names) would
    /// fail this pin at the just-below state where the float form
    /// rounds differently than the integer floor. Mirrors
    /// `test_coverage_ratio_pct_matches_floor_of_float_ratio_times_hundred`
    /// at the orthogonal axis.
    #[test]
    fn test_verification_ratio_pct_matches_floor_of_float_ratio_times_hundred() {
        let cases = [
            VerificationCoverage {
                verified: 0,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 0,
                unverified: 5,
            },
            VerificationCoverage {
                verified: 2,
                unverified: 3,
            },
            VerificationCoverage {
                verified: 5,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 1,
                unverified: 1,
            },
            VerificationCoverage {
                verified: 89,
                unverified: 11,
            },
        ];
        for c in cases {
            let pct = c.verification_ratio_pct();
            let expected = (c.verification_ratio() * 100.0).floor() as u8;
            assert_eq!(
                pct, expected,
                "integer floor must match floor(f64_ratio * 100) at {c:?}",
            );
        }
    }

    /// Strict-production verification-axis admission gate is `true`
    /// exactly at the `is_fully_verified() && !is_saturated()` corner of
    /// the matrix. Pinned across the three load-bearing total counts
    /// (2 / 3 / 5, matching the Phase 1 flux + helm-release-signature
    /// count, the Phase 2 helm-provenance + cosign + network-policy
    /// count, and the aggregate over the [`VerifiedOutcome`] subset) so
    /// a regression that pinned the predicate to a single phase's total
    /// would fail at the other two. Mirrors
    /// `test_is_admission_eligible_strict_at_fully_covered_non_saturated_arm_is_true`
    /// at the no-evidence axis.
    #[test]
    fn test_verification_is_admission_eligible_strict_at_fully_verified_non_saturated_arm_is_true()
    {
        for total in [2usize, 3, 5] {
            let c = VerificationCoverage {
                verified: total,
                unverified: 0,
            };
            assert!(
                c.is_admission_eligible_strict(),
                "fully-verified non-saturated arm must pass the strict gate at {c:?}",
            );
        }
    }

    /// Strict gate rejects every non-(fully-verified) arm. Pins:
    /// - empty floor `(0, 0)` — `is_fully_verified()` false (`verified == 0`)
    /// - all-unverified floor `(0, N)` — `is_fully_verified()` false (same)
    /// - mixed arm `(N, M)` with both positive — `is_fully_verified()`
    ///   false (`unverified > 0`)
    ///
    /// All three rejection arms close at the `is_fully_verified() == false`
    /// factor of the conjunction; the saturation factor is exercised
    /// separately below. Mirrors
    /// `test_is_admission_eligible_strict_rejects_non_fully_covered_arms`
    /// at the no-evidence axis.
    #[test]
    fn test_verification_is_admission_eligible_strict_rejects_non_fully_verified_arms() {
        let empty = VerificationCoverage {
            verified: 0,
            unverified: 0,
        };
        let all_unverified = VerificationCoverage {
            verified: 0,
            unverified: 5,
        };
        let mixed_low = VerificationCoverage {
            verified: 1,
            unverified: 1,
        };
        let mixed_high = VerificationCoverage {
            verified: 89,
            unverified: 11,
        };
        for c in [empty, all_unverified, mixed_low, mixed_high] {
            assert!(
                !c.is_admission_eligible_strict(),
                "non-fully-verified arm must fail the strict gate at {c:?}",
            );
        }
    }

    /// Strict gate rejects every saturated state, INCLUDING the
    /// `{verified: usize::MAX, unverified: 0}` representative that
    /// `is_fully_verified()` reads as `true`. Saturation-robustness is
    /// the load-bearing factor — the `verification_ratio()` /
    /// `verification_ratio_pct()` reads at `{MAX, 0}` round to `1.0` /
    /// `100` honestly (every counted verification up to the ceiling
    /// cleared), but the saturating-add clamp means an unknown number
    /// of past-ceiling increments were dropped, so the derived ratio
    /// cannot be trusted — the strict gate refuses to admit. Mirrors
    /// `test_is_admission_eligible_strict_at_saturated_state_is_false`
    /// at the no-evidence axis.
    #[test]
    fn test_verification_is_admission_eligible_strict_at_saturated_state_is_false() {
        let saturated_verified_only = VerificationCoverage {
            verified: usize::MAX,
            unverified: 0,
        };
        let saturated_unverified_only = VerificationCoverage {
            verified: 0,
            unverified: usize::MAX,
        };
        let saturated_both = VerificationCoverage {
            verified: usize::MAX,
            unverified: usize::MAX,
        };
        for c in [
            saturated_verified_only,
            saturated_unverified_only,
            saturated_both,
        ] {
            assert!(
                !c.is_admission_eligible_strict(),
                "saturated state must fail the strict gate at {c:?} — the \
                 saturating-add clamp dropped past-ceiling increments, so \
                 the derived ratio surfaces cannot be trusted",
            );
        }
    }

    /// Structural equivalence with the documented consumer composition
    /// `!is_saturated() && is_fully_verified()`. Pins the one-oracle
    /// invariant the typed primitive carries — a regression that
    /// hand-rolled the body (e.g., `is_fully_verified() && !is_empty()`)
    /// would fail at the saturated `{MAX, 0}` arm where
    /// `is_fully_verified() == true` AND `is_empty() == false` AND
    /// `is_saturated() == true`, so the divergent composition would
    /// erroneously admit a state the documented strict gate refuses.
    /// Walks every cell of the cross product
    /// `({empty, all_unverified, mixed, fully_verified} × {saturated,
    /// non_saturated})` (the empty arm is structurally non-saturated
    /// only, since both components are 0; the other three each admit
    /// both saturation states). Mirrors
    /// `test_is_admission_eligible_strict_equals_documented_composition`
    /// at the no-evidence axis exactly.
    #[test]
    fn test_verification_is_admission_eligible_strict_equals_documented_composition() {
        let cases = [
            VerificationCoverage {
                verified: 0,
                unverified: 0,
            }, // empty (always non-saturated)
            VerificationCoverage {
                verified: 0,
                unverified: 5,
            }, // all-unverified non-saturated
            VerificationCoverage {
                verified: 0,
                unverified: usize::MAX,
            }, // all-unverified saturated
            VerificationCoverage {
                verified: 2,
                unverified: 3,
            }, // mixed non-saturated
            VerificationCoverage {
                verified: usize::MAX,
                unverified: usize::MAX,
            }, // mixed saturated
            VerificationCoverage {
                verified: 5,
                unverified: 0,
            }, // fully-verified non-saturated
            VerificationCoverage {
                verified: usize::MAX,
                unverified: 0,
            }, // fully-verified saturated
        ];
        for c in cases {
            let direct = c.is_admission_eligible_strict();
            let composed = !c.is_saturated() && c.is_fully_verified();
            assert_eq!(
                direct, composed,
                "typed-primitive surface must equal the documented \
                 consumer composition at {c:?} — a regression that \
                 hand-rolled the body would fail this pin at the \
                 saturated `{{MAX, 0}}` arm where the discriminators \
                 decouple",
            );
        }
    }

    /// Under the saturating monoid `Add`, any phase whose contribution
    /// has `unverified > 0` breaks the strict gate at the aggregate —
    /// the aggregate's `unverified` field inherits the contributing
    /// phase's `unverified` (monoid `Add` is component-wise saturating
    /// add), so the aggregate's `is_fully_verified() == (unverified ==
    /// 0 && verified > 0)` reads `false` whenever any phase contributed
    /// an unverified record. The fleet-wide aggregate the `Sum` fold
    /// computes thus admits the strict gate only when EVERY phase is
    /// fully verified AND no component reached the saturating ceiling.
    /// Pinned across two representative two-phase aggregates: one where
    /// both phases are fully verified (aggregate passes), one where one
    /// phase contributes an unverified (aggregate fails). Mirrors
    /// `test_is_admission_eligible_strict_composes_under_monoid_add` at
    /// the no-evidence axis.
    #[test]
    fn test_verification_is_admission_eligible_strict_composes_under_monoid_add() {
        let phase_1_full = VerificationCoverage {
            verified: 2,
            unverified: 0,
        };
        let phase_2_full = VerificationCoverage {
            verified: 3,
            unverified: 0,
        };
        let aggregate_full = phase_1_full + phase_2_full;
        assert!(
            aggregate_full.is_admission_eligible_strict(),
            "two fully-verified phases sum to a fully-verified aggregate \
             that passes the strict gate — {aggregate_full:?}",
        );

        let phase_2_partial = VerificationCoverage {
            verified: 2,
            unverified: 1,
        };
        let aggregate_with_unverified = phase_1_full + phase_2_partial;
        assert!(
            !aggregate_with_unverified.is_admission_eligible_strict(),
            "any phase contributing an unverified record breaks the \
             aggregate's strict gate — {aggregate_with_unverified:?}",
        );
    }

    /// Parallel-composed strict gate is `true` exactly when BOTH
    /// orthogonal axes admit at their strict gate. Pinned across the
    /// three load-bearing axis-aligned shapes (`(3, 0)` no-evidence
    /// axis paired with `(2, 0)` verification axis = Phase 1 build /
    /// flux-source, `(4, 0)` with `(3, 0)` = Phase 1 chart / helm-
    /// provenance, `(7, 0)` with `(5, 0)` = Phase 2 deployment /
    /// aggregate-verified-subset). A regression that collapsed the
    /// two-axis composition to one axis (e.g., returned only
    /// `probe.is_admission_eligible_strict()` or only
    /// `verification.is_admission_eligible_strict()`) would still pass
    /// this arm at the all-axes-strict corner, but would fail the
    /// per-axis rejection arms below where the dropped axis is the
    /// failing one.
    #[test]
    fn test_compose_admission_eligible_strict_at_both_strict_arm_is_true() {
        let cases = [
            (
                ProbeCoverage { ran: 3, absent: 0 },
                VerificationCoverage {
                    verified: 2,
                    unverified: 0,
                },
            ),
            (
                ProbeCoverage { ran: 4, absent: 0 },
                VerificationCoverage {
                    verified: 3,
                    unverified: 0,
                },
            ),
            (
                ProbeCoverage { ran: 7, absent: 0 },
                VerificationCoverage {
                    verified: 5,
                    unverified: 0,
                },
            ),
        ];
        for (probe, verification) in cases {
            assert!(
                compose_admission_eligible_strict(&probe, &verification),
                "both-axes-strict arm must pass the composed gate at \
                 ({probe:?}, {verification:?})",
            );
        }
    }

    /// Composed gate rejects every no-evidence-axis failure
    /// regardless of the verification axis's verdict. Pins the
    /// load-bearing factor: the composition reads the no-evidence
    /// axis as a strict precondition, not as a relaxation of the
    /// verification axis. Pairs the four no-evidence-axis rejection
    /// arms (empty, all-absent, mixed-low, saturated-fully-covered)
    /// with the all-axes-strict verification arm `(5, 0)` so the
    /// only failing factor is the no-evidence axis — a regression
    /// that returned only the verification axis's verdict would
    /// erroneously pass these arms.
    #[test]
    fn test_compose_admission_eligible_strict_rejects_probe_axis_failures() {
        let strict_verification = VerificationCoverage {
            verified: 5,
            unverified: 0,
        };
        let probe_failures = [
            ProbeCoverage { ran: 0, absent: 0 }, // empty
            ProbeCoverage { ran: 0, absent: 7 }, // all-absent
            ProbeCoverage { ran: 3, absent: 4 }, // mixed
            ProbeCoverage {
                ran: usize::MAX,
                absent: 0,
            }, // saturated-fully-covered
        ];
        for probe in probe_failures {
            assert!(
                !compose_admission_eligible_strict(&probe, &strict_verification),
                "no-evidence-axis failure must break the composed gate \
                 at probe={probe:?} verification={strict_verification:?} \
                 — a regression that dropped the probe axis would \
                 erroneously admit this state",
            );
        }
    }

    /// Composed gate rejects every verification-axis failure
    /// regardless of the no-evidence axis's verdict. The structural
    /// peer of the test above at the orthogonal axis. Pairs the four
    /// verification-axis rejection arms (empty, all-unverified,
    /// mixed, saturated-fully-verified) with the all-axes-strict
    /// no-evidence arm `(7, 0)` so the only failing factor is the
    /// verification axis — a regression that returned only the
    /// no-evidence axis's verdict would erroneously pass these arms.
    #[test]
    fn test_compose_admission_eligible_strict_rejects_verification_axis_failures() {
        let strict_probe = ProbeCoverage { ran: 7, absent: 0 };
        let verification_failures = [
            VerificationCoverage {
                verified: 0,
                unverified: 0,
            }, // empty
            VerificationCoverage {
                verified: 0,
                unverified: 5,
            }, // all-unverified
            VerificationCoverage {
                verified: 2,
                unverified: 3,
            }, // mixed
            VerificationCoverage {
                verified: usize::MAX,
                unverified: 0,
            }, // saturated-fully-verified
        ];
        for verification in verification_failures {
            assert!(
                !compose_admission_eligible_strict(&strict_probe, &verification),
                "verification-axis failure must break the composed gate \
                 at probe={strict_probe:?} verification={verification:?} \
                 — a regression that dropped the verification axis would \
                 erroneously admit this state",
            );
        }
    }

    /// Structural equivalence with the documented two-axis consumer
    /// composition
    /// `probe.is_admission_eligible_strict() &&
    /// verification.is_admission_eligible_strict()`. Pins the
    /// one-oracle invariant the typed primitive carries — a regression
    /// that hand-rolled the body (e.g., returned the disjunction
    /// `probe.is_admission_eligible_strict() ||
    /// verification.is_admission_eligible_strict()`, or composed only
    /// the inner `is_fully_*` factors and dropped the saturation
    /// clamps) would fail at the corresponding axis-failing arm where
    /// the divergent composition decouples. Walks the cross product
    /// of three per-axis representatives (a strict-arm pass, a
    /// fully-covered-but-saturated pass-the-shape-fail-the-clamp arm,
    /// and a mixed-arm rejection) so every (probe-arm × verification-
    /// arm) cell is pinned against the documented composition.
    #[test]
    fn test_compose_admission_eligible_strict_equals_documented_composition() {
        let probe_cases = [
            ProbeCoverage { ran: 7, absent: 0 }, // strict-pass
            ProbeCoverage {
                ran: usize::MAX,
                absent: 0,
            }, // saturated-fully-covered (rejected by saturation clamp)
            ProbeCoverage { ran: 3, absent: 4 }, // mixed (rejected by fully-covered factor)
            ProbeCoverage { ran: 0, absent: 0 }, // empty (rejected by both factors composed)
        ];
        let verification_cases = [
            VerificationCoverage {
                verified: 5,
                unverified: 0,
            }, // strict-pass
            VerificationCoverage {
                verified: usize::MAX,
                unverified: 0,
            }, // saturated-fully-verified (rejected by saturation clamp)
            VerificationCoverage {
                verified: 2,
                unverified: 3,
            }, // mixed (rejected by fully-verified factor)
            VerificationCoverage {
                verified: 0,
                unverified: 0,
            }, // empty (rejected by both factors composed)
        ];
        for probe in probe_cases {
            for verification in verification_cases {
                let direct = compose_admission_eligible_strict(&probe, &verification);
                let composed = probe.is_admission_eligible_strict()
                    && verification.is_admission_eligible_strict();
                assert_eq!(
                    direct, composed,
                    "typed-primitive composition must equal the documented \
                     two-axis consumer composition at probe={probe:?} \
                     verification={verification:?} — a regression that \
                     dropped one axis or replaced the conjunction with a \
                     disjunction would fail this pin at the corresponding \
                     axis-failing cell",
                );
            }
        }
    }

    /// Saturation on EITHER axis breaks the composed gate even at the
    /// otherwise-fully-covered / fully-verified arm. Pins the
    /// load-bearing trustworthiness clamp at both axes: the float-form
    /// `coverage_ratio` / `verification_ratio` and the integer-form
    /// `coverage_ratio_pct` / `verification_ratio_pct` round to `1.0` /
    /// `100` at the post-saturation `{*: MAX, opposite: 0}` arm against
    /// the counted increments BUT against the true ratio lose past-
    /// ceiling increments, so the composed gate refuses to admit
    /// whenever either axis surfaces a saturated state. A regression
    /// that dropped the saturation clamp on either axis would
    /// erroneously admit these arms.
    #[test]
    fn test_compose_admission_eligible_strict_at_saturated_states_is_false() {
        let strict_probe = ProbeCoverage { ran: 7, absent: 0 };
        let strict_verification = VerificationCoverage {
            verified: 5,
            unverified: 0,
        };
        let saturated_probe = ProbeCoverage {
            ran: usize::MAX,
            absent: 0,
        };
        let saturated_verification = VerificationCoverage {
            verified: usize::MAX,
            unverified: 0,
        };

        assert!(
            !compose_admission_eligible_strict(&saturated_probe, &strict_verification),
            "probe-axis saturation must break the composed gate even at \
             the otherwise-strict verification arm",
        );
        assert!(
            !compose_admission_eligible_strict(&strict_probe, &saturated_verification),
            "verification-axis saturation must break the composed gate \
             even at the otherwise-strict probe arm",
        );
        assert!(
            !compose_admission_eligible_strict(&saturated_probe, &saturated_verification),
            "both-axes saturation must break the composed gate",
        );
    }

    /// The composed strict gate respects monoid `Add` on each axis:
    /// fleet-wide aggregates `[phase_a, phase_b].iter().sum::<_>()` on
    /// each axis pass the composed gate iff each axis's aggregate
    /// passes its own strict gate. Pins the parallel-composition
    /// invariant against the two-phase aggregate the future `commands::
    /// attestation` emission site will collect — the saturating-add
    /// monoid composes through each axis independently, then the
    /// composed gate reads the two aggregates together. A regression
    /// that broke either axis's monoid (e.g., a non-saturating `+`
    /// that panicked, or a `Sum` impl that returned the identity in a
    /// non-empty case) would fail this pin at the aggregate-reading
    /// step.
    #[test]
    fn test_compose_admission_eligible_strict_respects_monoid_add_on_both_axes() {
        let probe_phase_a = ProbeCoverage { ran: 3, absent: 0 };
        let probe_phase_b = ProbeCoverage { ran: 4, absent: 0 };
        let verification_phase_a = VerificationCoverage {
            verified: 2,
            unverified: 0,
        };
        let verification_phase_b = VerificationCoverage {
            verified: 3,
            unverified: 0,
        };

        let probe_aggregate = probe_phase_a + probe_phase_b;
        let verification_aggregate = verification_phase_a + verification_phase_b;
        assert!(
            compose_admission_eligible_strict(&probe_aggregate, &verification_aggregate),
            "two-axis aggregate over fully-passing phases must pass the \
             composed gate — probe={probe_aggregate:?} \
             verification={verification_aggregate:?}",
        );

        let probe_phase_b_partial = ProbeCoverage { ran: 3, absent: 1 };
        let probe_aggregate_partial = probe_phase_a + probe_phase_b_partial;
        assert!(
            !compose_admission_eligible_strict(&probe_aggregate_partial, &verification_aggregate),
            "any phase contributing a probe-axis absent breaks the \
             aggregate's composed gate",
        );

        let verification_phase_b_partial = VerificationCoverage {
            verified: 2,
            unverified: 1,
        };
        let verification_aggregate_partial = verification_phase_a + verification_phase_b_partial;
        assert!(
            !compose_admission_eligible_strict(&probe_aggregate, &verification_aggregate_partial),
            "any phase contributing a verification-axis unverified \
             breaks the aggregate's composed gate",
        );
    }

    /// Parallel-composed saturation predicate is `false` exactly when
    /// BOTH orthogonal axes are unsaturated — the two-axis
    /// trustworthiness ceiling every reachable non-saturated
    /// `(probe, verification)` pair sits at. Pins the load-bearing
    /// shape the negation `!compose_is_saturated(p, v)` carries: the
    /// trustworthiness factor pair the strict gate integrates as
    /// `!probe.is_saturated() && !verification.is_saturated()` is
    /// equivalent to `!compose_is_saturated(&probe, &verification)`
    /// by De Morgan, so a downstream emitter that surfaces
    /// "aggregate ratio is trustworthy" reads the negation of this
    /// helper rather than re-composing the per-axis factors.
    #[test]
    fn test_compose_is_saturated_at_unsaturated_arm_is_false() {
        let cases = [
            (
                ProbeCoverage { ran: 3, absent: 0 },
                VerificationCoverage {
                    verified: 2,
                    unverified: 0,
                },
            ),
            (
                ProbeCoverage { ran: 4, absent: 3 },
                VerificationCoverage {
                    verified: 1,
                    unverified: 2,
                },
            ),
            (
                ProbeCoverage { ran: 0, absent: 0 },
                VerificationCoverage {
                    verified: 0,
                    unverified: 0,
                },
            ),
        ];
        for (probe, verification) in cases {
            assert!(
                !compose_is_saturated(&probe, &verification),
                "both-axes-unsaturated arm must read trustworthy at \
                 ({probe:?}, {verification:?})",
            );
        }
    }

    /// Composed saturation predicate accepts every probe-axis
    /// saturated state regardless of the verification axis's
    /// trustworthiness. Pins the load-bearing factor: the
    /// composition reads saturation on EITHER axis as enough to
    /// break aggregate trustworthiness, not as a relaxation against
    /// the orthogonal axis. Pairs the three probe-axis saturated
    /// representatives (`{ran: MAX, absent: 0}` /
    /// `{ran: 0, absent: MAX}` / `{ran: MAX, absent: MAX}`) with an
    /// unsaturated verification arm so the only trust-breaking
    /// factor is the probe axis — a regression that dropped the
    /// probe axis would erroneously read these arms as trustworthy.
    #[test]
    fn test_compose_is_saturated_accepts_probe_axis_saturation() {
        let trusted_verification = VerificationCoverage {
            verified: 5,
            unverified: 0,
        };
        let probe_saturated = [
            ProbeCoverage {
                ran: usize::MAX,
                absent: 0,
            },
            ProbeCoverage {
                ran: 0,
                absent: usize::MAX,
            },
            ProbeCoverage {
                ran: usize::MAX,
                absent: usize::MAX,
            },
        ];
        for probe in probe_saturated {
            assert!(
                compose_is_saturated(&probe, &trusted_verification),
                "probe-axis saturation must break aggregate \
                 trustworthiness at probe={probe:?} \
                 verification={trusted_verification:?} — a regression \
                 that dropped the probe axis would erroneously read \
                 this state as trustworthy",
            );
        }
    }

    /// Composed saturation predicate accepts every verification-axis
    /// saturated state regardless of the probe axis's
    /// trustworthiness. The structural peer of the test above at the
    /// orthogonal axis. Pairs the three verification-axis saturated
    /// representatives (`{verified: MAX, unverified: 0}` /
    /// `{verified: 0, unverified: MAX}` /
    /// `{verified: MAX, unverified: MAX}`) with an unsaturated probe
    /// arm so the only trust-breaking factor is the verification
    /// axis — a regression that dropped the verification axis would
    /// erroneously read these arms as trustworthy.
    #[test]
    fn test_compose_is_saturated_accepts_verification_axis_saturation() {
        let trusted_probe = ProbeCoverage { ran: 7, absent: 0 };
        let verification_saturated = [
            VerificationCoverage {
                verified: usize::MAX,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 0,
                unverified: usize::MAX,
            },
            VerificationCoverage {
                verified: usize::MAX,
                unverified: usize::MAX,
            },
        ];
        for verification in verification_saturated {
            assert!(
                compose_is_saturated(&trusted_probe, &verification),
                "verification-axis saturation must break aggregate \
                 trustworthiness at probe={trusted_probe:?} \
                 verification={verification:?} — a regression that \
                 dropped the verification axis would erroneously read \
                 this state as trustworthy",
            );
        }
    }

    /// Structural equivalence with the documented two-axis consumer
    /// composition `probe.is_saturated() ||
    /// verification.is_saturated()`. Pins the one-oracle invariant
    /// the typed primitive carries — a regression that hand-rolled
    /// the body (e.g., returned the conjunction
    /// `probe.is_saturated() && verification.is_saturated()`, which
    /// would silently admit the one-axis-saturated state as
    /// trustworthy, the drift class this helper exists to foreclose)
    /// would fail at the corresponding one-axis-saturated cell where
    /// the divergent composition decouples. Walks the cross product
    /// of three per-axis representatives (unsaturated, saturated
    /// fully-fired, saturated-and-absent) so every
    /// (probe-arm × verification-arm) cell is pinned against the
    /// documented composition.
    #[test]
    fn test_compose_is_saturated_equals_documented_composition() {
        let probe_cases = [
            ProbeCoverage { ran: 7, absent: 0 },
            ProbeCoverage {
                ran: usize::MAX,
                absent: 0,
            },
            ProbeCoverage {
                ran: 0,
                absent: usize::MAX,
            },
            ProbeCoverage { ran: 0, absent: 0 },
        ];
        let verification_cases = [
            VerificationCoverage {
                verified: 5,
                unverified: 0,
            },
            VerificationCoverage {
                verified: usize::MAX,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 0,
                unverified: usize::MAX,
            },
            VerificationCoverage {
                verified: 0,
                unverified: 0,
            },
        ];
        for probe in probe_cases {
            for verification in verification_cases {
                let direct = compose_is_saturated(&probe, &verification);
                let composed = probe.is_saturated() || verification.is_saturated();
                assert_eq!(
                    direct, composed,
                    "typed-primitive composition must equal the documented \
                     two-axis consumer composition at probe={probe:?} \
                     verification={verification:?} — a regression that \
                     replaced the disjunction with a conjunction would \
                     fail this pin at the one-axis-saturated cells",
                );
            }
        }
    }

    /// De Morgan peer: the negation
    /// `!compose_is_saturated(&probe, &verification)` equals the
    /// strict gate's trustworthiness factor pair
    /// `!probe.is_saturated() && !verification.is_saturated()` at
    /// every reachable `(probe, verification)` pair. Pins the
    /// load-bearing structural identity an aggregate-trustworthiness
    /// emitter relies on: rather than retyping the two-factor
    /// conjunction at every consumer surface (which would inherit
    /// the same drift class
    /// [`compose_admission_eligible_strict`] forecloses for the
    /// complementary `complete AND trustworthy` gate), the consumer
    /// reads `!compose_is_saturated(&probe, &verification)` as one
    /// bool. Walks the cross product of per-axis representatives so
    /// every (probe-arm × verification-arm) cell pins the
    /// De Morgan identity.
    #[test]
    fn test_compose_is_saturated_negation_matches_strict_trustworthiness_factor() {
        let probe_cases = [
            ProbeCoverage { ran: 7, absent: 0 },
            ProbeCoverage {
                ran: usize::MAX,
                absent: 0,
            },
            ProbeCoverage {
                ran: 0,
                absent: usize::MAX,
            },
            ProbeCoverage { ran: 0, absent: 0 },
        ];
        let verification_cases = [
            VerificationCoverage {
                verified: 5,
                unverified: 0,
            },
            VerificationCoverage {
                verified: usize::MAX,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 0,
                unverified: usize::MAX,
            },
            VerificationCoverage {
                verified: 0,
                unverified: 0,
            },
        ];
        for probe in probe_cases {
            for verification in verification_cases {
                let trustworthy_aggregate = !compose_is_saturated(&probe, &verification);
                let trustworthy_factor_pair = !probe.is_saturated() && !verification.is_saturated();
                assert_eq!(
                    trustworthy_aggregate, trustworthy_factor_pair,
                    "De Morgan identity must hold at probe={probe:?} \
                     verification={verification:?} — the negation of \
                     the disjunction equals the conjunction of the \
                     per-axis negations, the load-bearing identity the \
                     strict gate's trustworthiness factor pair relies \
                     on",
                );
            }
        }
    }

    /// The composed saturation predicate respects monoid `Add` on
    /// each axis: a fleet-wide aggregate `[phase_a, phase_b].iter().
    /// sum::<_>()` is unsaturated iff no phase pushes either axis to
    /// the ceiling, AND becomes saturated as soon as any phase pair
    /// reaches the ceiling on either axis. Pins the parallel-
    /// composition invariant against the two-phase aggregate the
    /// future `commands::attestation` emission site will collect —
    /// the saturating-add monoid composes through each axis
    /// independently, then the composed saturation predicate reads
    /// the two aggregates together. A regression that broke either
    /// axis's saturating-add semantics (e.g., a non-saturating `+`
    /// that wrapped at `usize::MAX`) would fail this pin at the
    /// aggregate-reading step where the wrap would reset the
    /// trustworthiness signal.
    #[test]
    fn test_compose_is_saturated_respects_monoid_add_on_both_axes() {
        let probe_phase_a = ProbeCoverage { ran: 3, absent: 0 };
        let probe_phase_b = ProbeCoverage { ran: 4, absent: 0 };
        let verification_phase_a = VerificationCoverage {
            verified: 2,
            unverified: 0,
        };
        let verification_phase_b = VerificationCoverage {
            verified: 3,
            unverified: 0,
        };

        let probe_aggregate = probe_phase_a + probe_phase_b;
        let verification_aggregate = verification_phase_a + verification_phase_b;
        assert!(
            !compose_is_saturated(&probe_aggregate, &verification_aggregate),
            "two-axis aggregate over unsaturated phases must read \
             trustworthy — probe={probe_aggregate:?} \
             verification={verification_aggregate:?}",
        );

        let probe_phase_saturated = ProbeCoverage {
            ran: usize::MAX,
            absent: 0,
        };
        let probe_aggregate_saturated = probe_phase_a + probe_phase_saturated;
        assert!(
            compose_is_saturated(&probe_aggregate_saturated, &verification_aggregate),
            "any phase pushing the probe axis to the ceiling breaks \
             aggregate trustworthiness — probe={probe_aggregate_saturated:?}",
        );

        let verification_phase_saturated = VerificationCoverage {
            verified: usize::MAX,
            unverified: 0,
        };
        let verification_aggregate_saturated = verification_phase_a + verification_phase_saturated;
        assert!(
            compose_is_saturated(&probe_aggregate, &verification_aggregate_saturated),
            "any phase pushing the verification axis to the ceiling \
             breaks aggregate trustworthiness — \
             verification={verification_aggregate_saturated:?}",
        );
    }

    /// Parallel-composed vacuous-aggregate predicate is `true` exactly
    /// at the single both-axes-empty arm `({ran: 0, absent: 0}, {verified:
    /// 0, unverified: 0})` — the structural boundary [`probe_coverage`]
    /// and [`verification_coverage`] over empty iterators produce. Pins
    /// the load-bearing shape the fleet-wide aggregate-vacuous emission
    /// site reads at: a downstream emitter that gates "emit derived
    /// ratio fields honestly" on `!compose_is_empty(&probe,
    /// &verification)` admits the meaningful-aggregate state and
    /// suppresses telemetry only at the single both-axes-empty arm. A
    /// regression that returned `false` at this arm would over-emit
    /// vacuous ratio fields the empty-iterator boundary case structurally
    /// makes no-ops.
    #[test]
    fn test_compose_is_empty_at_both_empty_arm_is_true() {
        let probe = ProbeCoverage { ran: 0, absent: 0 };
        let verification = VerificationCoverage {
            verified: 0,
            unverified: 0,
        };
        assert!(
            compose_is_empty(&probe, &verification),
            "both-axes-empty arm must read vacuous at \
             ({probe:?}, {verification:?})",
        );
    }

    /// Parallel-composed vacuous-aggregate predicate rejects every
    /// probe-axis-populated state regardless of the verification axis's
    /// emptiness. Pins the load-bearing factor: the composition reads
    /// records on EITHER axis as enough to make the aggregate
    /// meaningful, not as a relaxation against the orthogonal axis.
    /// Pairs the three probe-axis non-empty representatives (mixed,
    /// fully-covered, all-absent) with an empty verification arm so the
    /// only meaningful-aggregate factor is the probe axis — a regression
    /// that returned the disjunction would erroneously read these arms
    /// as vacuous and suppress the populated probe axis's telemetry.
    #[test]
    fn test_compose_is_empty_rejects_probe_axis_populated() {
        let empty_verification = VerificationCoverage {
            verified: 0,
            unverified: 0,
        };
        let probe_populated = [
            ProbeCoverage { ran: 3, absent: 4 },
            ProbeCoverage { ran: 7, absent: 0 },
            ProbeCoverage { ran: 0, absent: 5 },
        ];
        for probe in probe_populated {
            assert!(
                !compose_is_empty(&probe, &empty_verification),
                "probe-axis records must make the aggregate \
                 meaningful at probe={probe:?} \
                 verification={empty_verification:?} — a regression \
                 that returned the disjunction would erroneously read \
                 this state as vacuous and suppress the populated probe \
                 axis's telemetry",
            );
        }
    }

    /// Parallel-composed vacuous-aggregate predicate rejects every
    /// verification-axis-populated state regardless of the probe axis's
    /// emptiness. The structural peer of the test above at the
    /// orthogonal axis. Pairs the three verification-axis non-empty
    /// representatives (mixed, fully-verified, all-unverified) with an
    /// empty probe arm so the only meaningful-aggregate factor is the
    /// verification axis — a regression that returned the disjunction
    /// would erroneously read these arms as vacuous and suppress the
    /// populated verification axis's telemetry.
    #[test]
    fn test_compose_is_empty_rejects_verification_axis_populated() {
        let empty_probe = ProbeCoverage { ran: 0, absent: 0 };
        let verification_populated = [
            VerificationCoverage {
                verified: 1,
                unverified: 2,
            },
            VerificationCoverage {
                verified: 5,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 0,
                unverified: 3,
            },
        ];
        for verification in verification_populated {
            assert!(
                !compose_is_empty(&empty_probe, &verification),
                "verification-axis records must make the aggregate \
                 meaningful at probe={empty_probe:?} \
                 verification={verification:?} — a regression that \
                 returned the disjunction would erroneously read this \
                 state as vacuous and suppress the populated \
                 verification axis's telemetry",
            );
        }
    }

    /// Structural equivalence with the documented two-axis consumer
    /// composition `probe.is_empty() && verification.is_empty()`. Pins
    /// the one-oracle invariant the typed primitive carries — a
    /// regression that hand-rolled the body (e.g., returned the
    /// disjunction `probe.is_empty() || verification.is_empty()`, which
    /// would silently classify the one-axis-empty / one-axis-populated
    /// state as vacuous, the drift class this helper exists to
    /// foreclose) would fail at the corresponding one-axis-populated
    /// cell where the divergent composition decouples. Walks the cross
    /// product of four per-axis representatives (empty,
    /// all-absent/all-unverified, mixed, fully-covered/fully-verified)
    /// so every (probe-arm × verification-arm) cell is pinned against
    /// the documented composition.
    #[test]
    fn test_compose_is_empty_equals_documented_composition() {
        let probe_cases = [
            ProbeCoverage { ran: 0, absent: 0 },
            ProbeCoverage { ran: 0, absent: 5 },
            ProbeCoverage { ran: 3, absent: 4 },
            ProbeCoverage { ran: 7, absent: 0 },
        ];
        let verification_cases = [
            VerificationCoverage {
                verified: 0,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 0,
                unverified: 3,
            },
            VerificationCoverage {
                verified: 1,
                unverified: 2,
            },
            VerificationCoverage {
                verified: 5,
                unverified: 0,
            },
        ];
        for probe in probe_cases {
            for verification in verification_cases {
                let direct = compose_is_empty(&probe, &verification);
                let composed = probe.is_empty() && verification.is_empty();
                assert_eq!(
                    direct, composed,
                    "typed-primitive composition must equal the documented \
                     two-axis consumer composition at probe={probe:?} \
                     verification={verification:?} — a regression that \
                     replaced the conjunction with a disjunction would \
                     fail this pin at the one-axis-empty cells",
                );
            }
        }
    }

    /// Saturation-robust pin: at every saturated state on either axis,
    /// `compose_is_empty` reads `false` — the saturating monoid
    /// `Add` cannot reach `total() == 0` from any non-empty input on
    /// either axis (both components are non-negative and at least one
    /// component is `usize::MAX` at every saturated state). Pins the
    /// load-bearing trustworthiness clamp: a regression that confused
    /// "empty" with "saturated and rolled" would fail this pin at the
    /// `{ran: usize::MAX, absent: 0}` / `{verified: usize::MAX,
    /// unverified: 0}` arms that surface a derived ratio of `1.0` /
    /// `100` honestly against the counted increments but are
    /// structurally NOT empty. Walks the three saturated
    /// representatives on each axis paired with an empty opposite axis,
    /// then the both-axes-saturated corner.
    #[test]
    fn test_compose_is_empty_at_saturated_states_is_false() {
        let empty_probe = ProbeCoverage { ran: 0, absent: 0 };
        let empty_verification = VerificationCoverage {
            verified: 0,
            unverified: 0,
        };
        let probe_saturated = [
            ProbeCoverage {
                ran: usize::MAX,
                absent: 0,
            },
            ProbeCoverage {
                ran: 0,
                absent: usize::MAX,
            },
            ProbeCoverage {
                ran: usize::MAX,
                absent: usize::MAX,
            },
        ];
        for probe in probe_saturated {
            assert!(
                !compose_is_empty(&probe, &empty_verification),
                "saturated probe axis at probe={probe:?} must read \
                 non-vacuous against empty verification — saturation \
                 strictly implies non-emptiness on its axis",
            );
        }
        let verification_saturated = [
            VerificationCoverage {
                verified: usize::MAX,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 0,
                unverified: usize::MAX,
            },
            VerificationCoverage {
                verified: usize::MAX,
                unverified: usize::MAX,
            },
        ];
        for verification in verification_saturated {
            assert!(
                !compose_is_empty(&empty_probe, &verification),
                "saturated verification axis at \
                 verification={verification:?} must read non-vacuous \
                 against empty probe — saturation strictly implies \
                 non-emptiness on its axis",
            );
        }
    }

    /// The composed vacuous-aggregate predicate respects monoid `Add`
    /// on each axis: a fleet-wide aggregate `[phase_a, phase_b]
    /// .iter().sum::<_>()` is vacuous iff EVERY phase contributed zero
    /// records to BOTH axes, AND becomes non-vacuous as soon as any
    /// phase pushes either axis off the empty arm. Pins the parallel-
    /// composition invariant against the two-phase aggregate the
    /// future `commands::attestation` emission site will collect — the
    /// saturating-add monoid composes through each axis independently,
    /// then the composed vacuous-aggregate predicate reads the two
    /// aggregates together. A regression that broke either axis's
    /// monoid identity (e.g., a non-zero default that made the empty
    /// phase non-empty under sum) would fail this pin at the
    /// aggregate-reading step where the spurious record would defeat
    /// the empty discriminator.
    #[test]
    fn test_compose_is_empty_respects_monoid_add_on_both_axes() {
        let probe_empty_a = ProbeCoverage { ran: 0, absent: 0 };
        let probe_empty_b = ProbeCoverage { ran: 0, absent: 0 };
        let verification_empty_a = VerificationCoverage {
            verified: 0,
            unverified: 0,
        };
        let verification_empty_b = VerificationCoverage {
            verified: 0,
            unverified: 0,
        };

        let probe_aggregate_empty = probe_empty_a + probe_empty_b;
        let verification_aggregate_empty = verification_empty_a + verification_empty_b;
        assert!(
            compose_is_empty(&probe_aggregate_empty, &verification_aggregate_empty),
            "two-axis aggregate over empty phases must read vacuous — \
             probe={probe_aggregate_empty:?} \
             verification={verification_aggregate_empty:?}",
        );

        let probe_phase_populated = ProbeCoverage { ran: 3, absent: 0 };
        let probe_aggregate_populated = probe_empty_a + probe_phase_populated;
        assert!(
            !compose_is_empty(&probe_aggregate_populated, &verification_aggregate_empty),
            "any phase contributing records on the probe axis breaks \
             the vacuous-aggregate state — \
             probe={probe_aggregate_populated:?}",
        );

        let verification_phase_populated = VerificationCoverage {
            verified: 2,
            unverified: 0,
        };
        let verification_aggregate_populated = verification_empty_a + verification_phase_populated;
        assert!(
            !compose_is_empty(&probe_aggregate_empty, &verification_aggregate_populated),
            "any phase contributing records on the verification axis \
             breaks the vacuous-aggregate state — \
             verification={verification_aggregate_populated:?}",
        );
    }

    /// Parallel-composed both-axes-complete predicate is `true` at the
    /// fully-covered/fully-verified arm where every counted probe ran
    /// AND every counted verification cleared. Pins the load-bearing
    /// shape the fleet-wide aggregate-completeness emission site reads
    /// at: a downstream emitter that gates on the composed bool admits
    /// only the both-axes-complete state. Walks the three honest
    /// fully-covered probe representatives paired with the three honest
    /// fully-verified verification representatives (small, medium, and
    /// the saturated-but-honest `usize::MAX` arm where every counted
    /// record surfaced its positive arm) — at every such cross-product
    /// cell, the composition admits. A regression that returned
    /// `false` at these arms would over-suppress completeness telemetry
    /// at the load-bearing strict-production state.
    #[test]
    fn test_compose_is_fully_complete_at_both_complete_arm_is_true() {
        let probe_fully_covered = [
            ProbeCoverage { ran: 1, absent: 0 },
            ProbeCoverage { ran: 7, absent: 0 },
            ProbeCoverage {
                ran: usize::MAX,
                absent: 0,
            },
        ];
        let verification_fully_verified = [
            VerificationCoverage {
                verified: 1,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 5,
                unverified: 0,
            },
            VerificationCoverage {
                verified: usize::MAX,
                unverified: 0,
            },
        ];
        for probe in probe_fully_covered {
            for verification in verification_fully_verified {
                assert!(
                    compose_is_fully_complete(&probe, &verification),
                    "both-axes-complete arm must read complete at \
                     probe={probe:?} verification={verification:?}",
                );
            }
        }
    }

    /// Parallel-composed both-axes-complete predicate rejects every
    /// probe-axis-incomplete state regardless of the verification axis's
    /// completeness. Pins the load-bearing factor: completeness on the
    /// verification axis alone is NOT enough to make the aggregate
    /// complete — every axis must surface its fully-covered arm. Pairs
    /// the three probe-axis non-fully-covered representatives (empty,
    /// all-absent, mixed) with a fully-verified verification arm so the
    /// only completeness-blocking factor is the probe axis — a
    /// regression that returned the disjunction would erroneously
    /// admit these states as complete.
    #[test]
    fn test_compose_is_fully_complete_rejects_probe_axis_incomplete() {
        let fully_verified = VerificationCoverage {
            verified: 5,
            unverified: 0,
        };
        let probe_incomplete = [
            ProbeCoverage { ran: 0, absent: 0 },
            ProbeCoverage { ran: 0, absent: 5 },
            ProbeCoverage { ran: 3, absent: 4 },
        ];
        for probe in probe_incomplete {
            assert!(
                !compose_is_fully_complete(&probe, &fully_verified),
                "probe-axis incompleteness must block the composed \
                 complete reading at probe={probe:?} \
                 verification={fully_verified:?} — a regression that \
                 returned the disjunction would erroneously admit this \
                 state as complete and over-emit completeness telemetry",
            );
        }
    }

    /// Parallel-composed both-axes-complete predicate rejects every
    /// verification-axis-incomplete state regardless of the probe axis's
    /// completeness. The structural peer of the test above at the
    /// orthogonal axis. Pairs the three verification-axis non-fully-
    /// verified representatives (empty, all-unverified, mixed) with a
    /// fully-covered probe arm so the only completeness-blocking factor
    /// is the verification axis — a regression that returned the
    /// disjunction would erroneously admit these states as complete.
    #[test]
    fn test_compose_is_fully_complete_rejects_verification_axis_incomplete() {
        let fully_covered = ProbeCoverage { ran: 7, absent: 0 };
        let verification_incomplete = [
            VerificationCoverage {
                verified: 0,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 0,
                unverified: 3,
            },
            VerificationCoverage {
                verified: 1,
                unverified: 2,
            },
        ];
        for verification in verification_incomplete {
            assert!(
                !compose_is_fully_complete(&fully_covered, &verification),
                "verification-axis incompleteness must block the \
                 composed complete reading at probe={fully_covered:?} \
                 verification={verification:?} — a regression that \
                 returned the disjunction would erroneously admit this \
                 state as complete and over-emit completeness telemetry",
            );
        }
    }

    /// Structural equivalence with the documented two-axis consumer
    /// composition `probe.is_fully_covered() && verification.
    /// is_fully_verified()`. Pins the one-oracle invariant the typed
    /// primitive carries — a regression that hand-rolled the body (e.g.,
    /// returned the disjunction `probe.is_fully_covered() ||
    /// verification.is_fully_verified()`, which would silently admit the
    /// one-axis-complete-one-axis-incomplete state as complete, the
    /// drift class this helper exists to foreclose) would fail at the
    /// corresponding one-axis-incomplete cells where the divergent
    /// composition decouples. Walks the cross product of four per-axis
    /// representatives (empty, all-absent/all-unverified, mixed,
    /// fully-covered/fully-verified) so every (probe-arm ×
    /// verification-arm) cell is pinned against the documented
    /// composition.
    #[test]
    fn test_compose_is_fully_complete_equals_documented_composition() {
        let probe_cases = [
            ProbeCoverage { ran: 0, absent: 0 },
            ProbeCoverage { ran: 0, absent: 5 },
            ProbeCoverage { ran: 3, absent: 4 },
            ProbeCoverage { ran: 7, absent: 0 },
        ];
        let verification_cases = [
            VerificationCoverage {
                verified: 0,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 0,
                unverified: 3,
            },
            VerificationCoverage {
                verified: 1,
                unverified: 2,
            },
            VerificationCoverage {
                verified: 5,
                unverified: 0,
            },
        ];
        for probe in probe_cases {
            for verification in verification_cases {
                let direct = compose_is_fully_complete(&probe, &verification);
                let composed = probe.is_fully_covered() && verification.is_fully_verified();
                assert_eq!(
                    direct, composed,
                    "typed-primitive composition must equal the documented \
                     two-axis consumer composition at probe={probe:?} \
                     verification={verification:?} — a regression that \
                     replaced the conjunction with a disjunction would \
                     fail this pin at the one-axis-complete cells",
                );
            }
        }
    }

    /// The load-bearing decomposition pin:
    /// `compose_admission_eligible_strict(p, v) ==
    ///  compose_is_fully_complete(p, v) && !compose_is_saturated(p, v)`.
    /// Separates the strict gate into its two orthogonal admission
    /// factors at the composed-axis surface — completeness (this
    /// helper) and trustworthiness ([`compose_is_saturated`] negated) —
    /// and pins that the strict gate is exactly the AND of the two.
    /// Walks the full 4x4 cross product of per-axis representatives
    /// (empty, all-absent/all-unverified, mixed, fully-covered/
    /// fully-verified) AND every saturated probe × saturated
    /// verification corner (the post-saturation arms where the
    /// completeness reading and the trustworthiness reading diverge —
    /// `{ran: usize::MAX, absent: 0}` is structurally fully-covered
    /// but NOT trustworthy, so the strict gate fails it through the
    /// trustworthiness factor). A regression that drifted either factor
    /// from the strict gate's body would fail at the corresponding cell
    /// where the decomposition diverges.
    #[test]
    fn test_compose_is_fully_complete_decomposes_strict_admission() {
        let probe_cases = [
            ProbeCoverage { ran: 0, absent: 0 },
            ProbeCoverage { ran: 0, absent: 5 },
            ProbeCoverage { ran: 3, absent: 4 },
            ProbeCoverage { ran: 7, absent: 0 },
            ProbeCoverage {
                ran: usize::MAX,
                absent: 0,
            },
            ProbeCoverage {
                ran: 0,
                absent: usize::MAX,
            },
            ProbeCoverage {
                ran: usize::MAX,
                absent: usize::MAX,
            },
        ];
        let verification_cases = [
            VerificationCoverage {
                verified: 0,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 0,
                unverified: 3,
            },
            VerificationCoverage {
                verified: 1,
                unverified: 2,
            },
            VerificationCoverage {
                verified: 5,
                unverified: 0,
            },
            VerificationCoverage {
                verified: usize::MAX,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 0,
                unverified: usize::MAX,
            },
            VerificationCoverage {
                verified: usize::MAX,
                unverified: usize::MAX,
            },
        ];
        for probe in probe_cases {
            for verification in verification_cases {
                let strict = compose_admission_eligible_strict(&probe, &verification);
                let decomposed = compose_is_fully_complete(&probe, &verification)
                    && !compose_is_saturated(&probe, &verification);
                assert_eq!(
                    strict, decomposed,
                    "strict gate must equal the AND of completeness and \
                     trustworthiness factors at probe={probe:?} \
                     verification={verification:?} — a regression that \
                     drifted either factor would fail this pin",
                );
            }
        }
    }

    /// The composed both-axes-complete predicate respects monoid `Add`
    /// on each axis: a fleet-wide aggregate `[phase_a, phase_b]
    /// .iter().sum::<_>()` reads complete iff both phases together
    /// produce the fully-covered/fully-verified arm on both axes —
    /// any phase contributing an `absent`/`unverified` increment breaks
    /// the completeness state via the `absent == 0` / `unverified == 0`
    /// component-level test. Pins the parallel-composition invariant
    /// against the two-phase aggregate the future
    /// `commands::attestation` emission site will collect — the
    /// saturating-add monoid composes through each axis independently,
    /// then the composed predicate reads the two aggregates together.
    #[test]
    fn test_compose_is_fully_complete_respects_monoid_add_on_both_axes() {
        let probe_phase_a = ProbeCoverage { ran: 3, absent: 0 };
        let probe_phase_b = ProbeCoverage { ran: 4, absent: 0 };
        let verification_phase_a = VerificationCoverage {
            verified: 2,
            unverified: 0,
        };
        let verification_phase_b = VerificationCoverage {
            verified: 3,
            unverified: 0,
        };

        let probe_aggregate_complete = probe_phase_a + probe_phase_b;
        let verification_aggregate_complete = verification_phase_a + verification_phase_b;
        assert!(
            compose_is_fully_complete(&probe_aggregate_complete, &verification_aggregate_complete),
            "two-axis aggregate over fully-complete phases must read \
             complete — probe={probe_aggregate_complete:?} \
             verification={verification_aggregate_complete:?}",
        );

        let probe_phase_absent = ProbeCoverage { ran: 0, absent: 1 };
        let probe_aggregate_broken = probe_phase_a + probe_phase_absent;
        assert!(
            !compose_is_fully_complete(&probe_aggregate_broken, &verification_aggregate_complete),
            "any phase contributing an absent record on the probe axis \
             breaks the both-axes-complete state — \
             probe={probe_aggregate_broken:?}",
        );

        let verification_phase_unverified = VerificationCoverage {
            verified: 0,
            unverified: 1,
        };
        let verification_aggregate_broken = verification_phase_a + verification_phase_unverified;
        assert!(
            !compose_is_fully_complete(&probe_aggregate_complete, &verification_aggregate_broken),
            "any phase contributing an unverified record on the \
             verification axis breaks the both-axes-complete state — \
             verification={verification_aggregate_broken:?}",
        );
    }

    /// `VerificationCoverage::has_evidence()` returns `true` iff at
    /// least one counted verification cleared — `verified > 0`. Pinned
    /// across the fully-verified ceiling (2, 3, 5 — the load-bearing
    /// Phase 1 / Phase 2 / aggregate counts) AND the realistic
    /// intermediate mixed shapes the relaxed-staging admission gate
    /// admits (half-and-half corner, 2-of-5 and 3-of-5 splits) so a
    /// regression that hardcoded the predicate to one specific value (or
    /// accidentally gated on `unverified == 0` as well) would fail
    /// across the others. The typed-primitive surface the relaxed-
    /// staging admission gate reads directly at the verification axis —
    /// every value where `has_evidence()` is `true` is an admissible
    /// relaxed-staging verification-coverage record. Mirrors
    /// `test_has_evidence_when_any_probe_ran_is_true` at the
    /// orthogonal axis exactly.
    #[test]
    fn test_verification_has_evidence_when_any_verified_is_true() {
        assert!(VerificationCoverage {
            verified: 2,
            unverified: 0
        }
        .has_evidence());
        assert!(VerificationCoverage {
            verified: 3,
            unverified: 0
        }
        .has_evidence());
        assert!(VerificationCoverage {
            verified: 5,
            unverified: 0
        }
        .has_evidence());
        assert!(VerificationCoverage {
            verified: 1,
            unverified: 1
        }
        .has_evidence());
        assert!(VerificationCoverage {
            verified: 2,
            unverified: 3
        }
        .has_evidence());
        assert!(VerificationCoverage {
            verified: 3,
            unverified: 2
        }
        .has_evidence());
    }

    /// `VerificationCoverage::has_evidence()` returns `false` for both
    /// `verified == 0` arms — the empty floor `(0, 0)` and the
    /// all-unverified floor `(0, N)`. Pinned across both arms (and
    /// across three sizes of the all-unverified floor: 2, 3, 5 — the
    /// per-phase Phase 1 / Phase 2 / aggregate counts the prior pins
    /// use) so a future regression that relaxed the predicate to
    /// `total() > 0` (the structural sibling that admits the all-
    /// unverified floor) would flip the all-unverified floor to `true`
    /// and fail this pin. Today's `compose_product_certification` /
    /// `compute_chart_attestation` / `compute_build_attestation` call-
    /// site state sits at exactly the all-unverified floor at the
    /// verification axis — the relaxed-staging admission gate correctly
    /// refuses this state because `has_evidence() == false`. Mirrors
    /// `test_has_evidence_at_no_ran_arms_is_false` at the orthogonal
    /// axis exactly.
    #[test]
    fn test_verification_has_evidence_at_no_verified_arms_is_false() {
        assert!(!VerificationCoverage {
            verified: 0,
            unverified: 0
        }
        .has_evidence());
        assert!(!VerificationCoverage {
            verified: 0,
            unverified: 2
        }
        .has_evidence());
        assert!(!VerificationCoverage {
            verified: 0,
            unverified: 3
        }
        .has_evidence());
        assert!(!VerificationCoverage {
            verified: 0,
            unverified: 5
        }
        .has_evidence());
    }

    /// `VerificationCoverage::has_evidence()` is structurally equivalent
    /// to the disjunction `!is_empty() && !is_fully_verified()` OR
    /// `is_fully_verified()` — i.e., the two `verified > 0` arms of the
    /// four-arm matrix the docstring on
    /// [`VerificationCoverage::is_fully_verified`] tabulates (the
    /// some-verified-some-unverified intermediate arm at `verified > 0
    /// && unverified > 0` AND the fully-verified ceiling at `verified > 0
    /// && unverified == 0`). Pinned across the four arms of that matrix
    /// so a future regression that decoupled `has_evidence` from those
    /// two arms (e.g., hand-rolled the body as `total() > 0`, which
    /// would admit the all-unverified floor that neither the mixed arm
    /// nor the fully-verified arm admits) would fail this pin at the
    /// all-unverified arm. The structural equivalence is what makes the
    /// typed primitive the proper one-oracle surface for the relaxed-
    /// staging admission gate at the verification axis: a verifier
    /// reading `has_evidence()` reads exactly what the two-arm
    /// `verified > 0` disjunction reads, with no behavioural seam.
    /// Mirrors `test_has_evidence_equals_disjunction_of_mixed_and_
    /// fully_covered` at the orthogonal axis exactly.
    #[test]
    fn test_verification_has_evidence_equals_two_verified_arm_disjunction() {
        let cases = [
            VerificationCoverage {
                verified: 0,
                unverified: 0,
            }, // empty
            VerificationCoverage {
                verified: 0,
                unverified: 5,
            }, // all-unverified
            VerificationCoverage {
                verified: 2,
                unverified: 3,
            }, // mixed
            VerificationCoverage {
                verified: 5,
                unverified: 0,
            }, // fully-verified
            VerificationCoverage {
                verified: 1,
                unverified: 1,
            }, // half-and-half corner
            VerificationCoverage {
                verified: 3,
                unverified: 0,
            }, // Phase 2 ceiling
            VerificationCoverage {
                verified: 0,
                unverified: 2,
            }, // Phase 1 all-unverified
        ];
        for c in cases {
            let mixed_arm = c.verified > 0 && c.unverified > 0;
            let fully_verified_arm = c.is_fully_verified();
            assert_eq!(
                c.has_evidence(),
                mixed_arm || fully_verified_arm,
                "has_evidence must equal the two-verified-arm \
                 disjunction at {c:?}",
            );
        }
    }

    /// `VerificationCoverage::has_evidence()` composes with the monoid
    /// `Add` shape exactly the way a downstream fleet-wide aggregator
    /// depends on: a per-phase no-evidence verification-coverage summed
    /// with any per-phase has-evidence verification-coverage produces a
    /// has-evidence aggregate (one phase contributing `verified > 0`
    /// lifts the aggregate off the no-evidence floor). Mirrors the
    /// structural intuition: a product certification has positive
    /// verification evidence iff any phase contributed a positive
    /// verdict. A future regression that swapped `verified` and
    /// `unverified` in the impl body of `Add` would silently flip a
    /// has-evidence Phase 1 verification into a no-evidence aggregate;
    /// this pin closes that arm at the typed-primitive surface. Mirrors
    /// `test_has_evidence_composes_under_monoid_add` at the orthogonal
    /// axis exactly.
    #[test]
    fn test_verification_has_evidence_composes_under_monoid_add() {
        let phase_1_unverified = VerificationCoverage {
            verified: 0,
            unverified: 2,
        };
        let phase_2_unverified = VerificationCoverage {
            verified: 0,
            unverified: 3,
        };
        let aggregate_unverified = VerificationCoverage {
            verified: 0,
            unverified: 5,
        };
        let phase_1_verified = VerificationCoverage {
            verified: 1,
            unverified: 1,
        };
        assert!(!phase_1_unverified.has_evidence());
        assert!(!phase_2_unverified.has_evidence());
        assert!(!aggregate_unverified.has_evidence());
        assert!(phase_1_verified.has_evidence());
        assert!(!(phase_1_unverified + phase_2_unverified).has_evidence());
        assert!((phase_1_unverified + phase_1_verified).has_evidence());
        assert!((phase_1_verified + phase_2_unverified).has_evidence());
        assert!((phase_1_unverified + phase_1_verified + phase_2_unverified).has_evidence());
    }

    /// `VerificationCoverage::has_evidence()` stays saturation-robust:
    /// the body `verified > 0` reads against the `verified` component
    /// itself, not against any derived ratio. At the post-saturation
    /// state `{verified: usize::MAX, unverified: 0}` it correctly reads
    /// `true` (every counted verification — even the dropped past-
    /// ceiling increments — cleared); at the post-saturation state
    /// `{verified: 0, unverified: usize::MAX}` it correctly reads
    /// `false` (no counted verification cleared). The symmetric saturated
    /// state `{verified: MAX, unverified: MAX}` reads `true` (both
    /// components are non-zero), matching the two-verified-arm
    /// disjunction's reading at that state. Mirrors the saturation-
    /// robust discipline
    /// `test_has_evidence_stays_robust_at_saturated_state` pins for the
    /// orthogonal-axis peer one impl group up; the two surfaces compose
    /// without a structural seam at the saturated state, the
    /// load-bearing precondition the future
    /// `compose_has_evidence`-style two-axis parallel-composed
    /// disjunction (the natural De Morgan dual of `compose_is_empty`)
    /// will rely on at the composed-axis surface.
    #[test]
    fn test_verification_has_evidence_stays_robust_at_saturated_state() {
        let saturated_verified_only = VerificationCoverage {
            verified: usize::MAX,
            unverified: 0,
        };
        assert!(saturated_verified_only.has_evidence());
        assert!(saturated_verified_only.is_saturated());
        assert!(saturated_verified_only.is_fully_verified());

        let saturated_unverified_only = VerificationCoverage {
            verified: 0,
            unverified: usize::MAX,
        };
        assert!(!saturated_unverified_only.has_evidence());
        assert!(saturated_unverified_only.is_saturated());
        assert!(!saturated_unverified_only.is_fully_verified());

        let saturated_both = VerificationCoverage {
            verified: usize::MAX,
            unverified: usize::MAX,
        };
        assert!(saturated_both.has_evidence());
        assert!(saturated_both.is_saturated());
        assert!(!saturated_both.is_fully_verified());
    }

    /// Parallel-composed any-axis-has-evidence predicate reads `true`
    /// at every state where at least one orthogonal axis has surfaced
    /// a counted honest-positive arm. Pins the load-bearing relaxed-
    /// staging admission precondition: the composition admits as soon
    /// as `ran > 0` OR `verified > 0` on either axis. Walks the cross
    /// product of the three per-axis evidenced representatives (mixed,
    /// fully-covered/fully-verified small, saturated-but-honest
    /// `usize::MAX`) against the four per-axis representatives
    /// (empty, no-evidence floor, mixed, fully-positive) on the
    /// opposite axis — at every cross-product cell where at least one
    /// axis carries evidence, the composition admits. A regression
    /// that returned the conjunction would over-reject the
    /// one-axis-evidenced states at the cells the
    /// no-evidence-opposite-axis arms pair against.
    #[test]
    fn test_compose_has_evidence_at_any_axis_evidence_arm_is_true() {
        let probe_evidenced = [
            ProbeCoverage { ran: 3, absent: 4 },
            ProbeCoverage { ran: 7, absent: 0 },
            ProbeCoverage {
                ran: usize::MAX,
                absent: 0,
            },
        ];
        let verification_opposites = [
            VerificationCoverage {
                verified: 0,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 0,
                unverified: 3,
            },
            VerificationCoverage {
                verified: 1,
                unverified: 2,
            },
            VerificationCoverage {
                verified: 5,
                unverified: 0,
            },
        ];
        for probe in probe_evidenced {
            for verification in verification_opposites {
                assert!(
                    compose_has_evidence(&probe, &verification),
                    "probe-axis evidence must admit the relaxed-staging \
                     precondition at probe={probe:?} \
                     verification={verification:?} — a regression that \
                     returned the conjunction would erroneously reject \
                     the one-axis-evidenced state and suppress the \
                     relaxed admission gate",
                );
            }
        }
        let verification_evidenced = [
            VerificationCoverage {
                verified: 1,
                unverified: 2,
            },
            VerificationCoverage {
                verified: 5,
                unverified: 0,
            },
            VerificationCoverage {
                verified: usize::MAX,
                unverified: 0,
            },
        ];
        let probe_opposites = [
            ProbeCoverage { ran: 0, absent: 0 },
            ProbeCoverage { ran: 0, absent: 5 },
            ProbeCoverage { ran: 3, absent: 4 },
            ProbeCoverage { ran: 7, absent: 0 },
        ];
        for verification in verification_evidenced {
            for probe in probe_opposites {
                assert!(
                    compose_has_evidence(&probe, &verification),
                    "verification-axis evidence must admit the relaxed-\
                     staging precondition at probe={probe:?} \
                     verification={verification:?} — a regression that \
                     returned the conjunction would erroneously reject \
                     the one-axis-evidenced state and suppress the \
                     relaxed admission gate",
                );
            }
        }
    }

    /// Parallel-composed any-axis-has-evidence predicate rejects every
    /// no-evidence-on-both-axes state — the two structural arms where
    /// `compose_has_evidence` must read `false`: the both-empty
    /// boundary `({ran: 0, absent: 0}, {verified: 0, unverified: 0})`
    /// and the both-no-evidence floor (all-absent probe paired with
    /// all-unverified verification). Pins the load-bearing
    /// fail-closed boundary the relaxed-staging admission gate fails-
    /// closed against — at these states, zero counted record on
    /// either axis surfaced a positive arm, so the relaxed
    /// precondition has nothing to admit. Walks the small / medium /
    /// large representatives of each no-evidence arm so the
    /// fail-closed reading is pinned across the realistic count
    /// scales.
    #[test]
    fn test_compose_has_evidence_at_no_evidence_arms_is_false() {
        let empty_probe = ProbeCoverage { ran: 0, absent: 0 };
        let empty_verification = VerificationCoverage {
            verified: 0,
            unverified: 0,
        };
        assert!(
            !compose_has_evidence(&empty_probe, &empty_verification),
            "both-axes-empty boundary must read no-evidence at \
             ({empty_probe:?}, {empty_verification:?}) — the \
             fail-closed boundary the relaxed-staging admission gate \
             rejects",
        );

        let probe_no_evidence = [
            ProbeCoverage { ran: 0, absent: 1 },
            ProbeCoverage { ran: 0, absent: 5 },
            ProbeCoverage {
                ran: 0,
                absent: usize::MAX,
            },
        ];
        let verification_no_evidence = [
            VerificationCoverage {
                verified: 0,
                unverified: 1,
            },
            VerificationCoverage {
                verified: 0,
                unverified: 3,
            },
            VerificationCoverage {
                verified: 0,
                unverified: usize::MAX,
            },
        ];
        for probe in probe_no_evidence {
            for verification in verification_no_evidence {
                assert!(
                    !compose_has_evidence(&probe, &verification),
                    "both-axes-no-evidence floor must read no-evidence \
                     at probe={probe:?} verification={verification:?} \
                     — zero counted record on either axis surfaced an \
                     honest-positive arm; the relaxed-staging \
                     admission gate fails closed",
                );
            }
        }
    }

    /// Structural equivalence with the documented two-axis consumer
    /// composition `probe.has_evidence() ||
    /// verification.has_evidence()`. Pins the one-oracle invariant the
    /// typed primitive carries — a regression that hand-rolled the
    /// body (e.g., returned the conjunction `probe.has_evidence() &&
    /// verification.has_evidence()`, which would silently reject the
    /// one-axis-evidenced state, the drift class this helper exists
    /// to foreclose) would fail at the corresponding
    /// one-axis-evidenced cells where the divergent composition
    /// decouples. Walks the cross product of four per-axis
    /// representatives (empty, all-absent/all-unverified, mixed,
    /// fully-covered/fully-verified) so every (probe-arm ×
    /// verification-arm) cell is pinned against the documented
    /// composition.
    #[test]
    fn test_compose_has_evidence_equals_documented_composition() {
        let probe_cases = [
            ProbeCoverage { ran: 0, absent: 0 },
            ProbeCoverage { ran: 0, absent: 5 },
            ProbeCoverage { ran: 3, absent: 4 },
            ProbeCoverage { ran: 7, absent: 0 },
        ];
        let verification_cases = [
            VerificationCoverage {
                verified: 0,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 0,
                unverified: 3,
            },
            VerificationCoverage {
                verified: 1,
                unverified: 2,
            },
            VerificationCoverage {
                verified: 5,
                unverified: 0,
            },
        ];
        for probe in probe_cases {
            for verification in verification_cases {
                let direct = compose_has_evidence(&probe, &verification);
                let composed = probe.has_evidence() || verification.has_evidence();
                assert_eq!(
                    direct, composed,
                    "typed-primitive composition must equal the \
                     documented two-axis consumer composition at \
                     probe={probe:?} verification={verification:?} — \
                     a regression that replaced the disjunction with a \
                     conjunction would fail this pin at the \
                     one-axis-evidenced cells",
                );
            }
        }
    }

    /// The `compose_has_evidence` predicate is the strictly stronger
    /// discriminator over `!compose_is_empty`: there exist
    /// `(probe, verification)` pairs where `!compose_is_empty(p, v)`
    /// reads `true` (records counted on at least one axis) but
    /// `compose_has_evidence(p, v)` reads `false` (zero honest-
    /// positive arms surfaced on either axis). The all-absent-floor /
    /// all-unverified-floor pair is the structural witness — both
    /// axes carry counted records but every record surfaced its
    /// no-evidence arm. Pins the load-bearing distinction the helper
    /// exists to seal at the typed-primitive surface: the relaxed
    /// admission gate admits only on positive evidence, not on the
    /// mere presence of any record. A regression that conflated the
    /// two surfaces (e.g., defined `compose_has_evidence` as
    /// `!compose_is_empty`) would silently admit the both-no-evidence
    /// state and over-emit the relaxed admission verdict at the load-
    /// bearing fail-closed boundary.
    #[test]
    fn test_compose_has_evidence_strictly_stronger_than_not_empty() {
        let probe_no_evidence = ProbeCoverage { ran: 0, absent: 3 };
        let verification_no_evidence = VerificationCoverage {
            verified: 0,
            unverified: 5,
        };
        assert!(
            !compose_is_empty(&probe_no_evidence, &verification_no_evidence),
            "all-absent-floor + all-unverified-floor pair is NOT \
             vacuous at ({probe_no_evidence:?}, \
             {verification_no_evidence:?}) — records counted on both \
             axes",
        );
        assert!(
            !compose_has_evidence(&probe_no_evidence, &verification_no_evidence),
            "all-absent-floor + all-unverified-floor pair has NO \
             evidence at ({probe_no_evidence:?}, \
             {verification_no_evidence:?}) — zero honest-positive arms \
             surfaced; `compose_has_evidence` is the strictly stronger \
             discriminator than `!compose_is_empty`",
        );

        let probe_evidence_only = ProbeCoverage { ran: 0, absent: 3 };
        let verification_evidence = VerificationCoverage {
            verified: 2,
            unverified: 0,
        };
        assert!(compose_has_evidence(
            &probe_evidence_only,
            &verification_evidence
        ));
        assert!(!compose_is_empty(
            &probe_evidence_only,
            &verification_evidence
        ));
    }

    /// The load-bearing relaxed-vs-strict ordering pin: every
    /// both-axes-complete state strictly carries evidence on at least
    /// one axis. Pins the implication
    /// `compose_is_fully_complete(p, v) => compose_has_evidence(p, v)`
    /// across the cross product of the three per-axis honest fully-
    /// covered probe representatives × three per-axis honest fully-
    /// verified verification representatives — at every both-axes-
    /// complete cell, the relaxed precondition also admits, so the
    /// strict-and-relaxed gate composition `strict || has_evidence`
    /// degenerates to `has_evidence` over the strict-admitted subset.
    /// A regression that broke either compose helper's structural
    /// reading (e.g., a body that decoupled `has_evidence` from the
    /// `ran > 0` / `verified > 0` per-axis components) would fail
    /// this pin at the both-axes-complete cells where the strict gate
    /// admits but the relaxed gate would erroneously reject.
    #[test]
    fn test_compose_is_fully_complete_implies_compose_has_evidence() {
        let probe_fully_covered = [
            ProbeCoverage { ran: 1, absent: 0 },
            ProbeCoverage { ran: 7, absent: 0 },
            ProbeCoverage {
                ran: usize::MAX,
                absent: 0,
            },
        ];
        let verification_fully_verified = [
            VerificationCoverage {
                verified: 1,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 5,
                unverified: 0,
            },
            VerificationCoverage {
                verified: usize::MAX,
                unverified: 0,
            },
        ];
        for probe in probe_fully_covered {
            for verification in verification_fully_verified {
                assert!(
                    compose_is_fully_complete(&probe, &verification),
                    "both-axes-complete precondition must admit at \
                     probe={probe:?} verification={verification:?}",
                );
                assert!(
                    compose_has_evidence(&probe, &verification),
                    "both-axes-complete state must imply has-evidence \
                     at probe={probe:?} verification={verification:?} \
                     — the strict-and-relaxed gate ordering is \
                     structurally load-bearing",
                );
            }
        }
    }

    /// The composed any-axis-has-evidence predicate respects monoid
    /// `Add` on each axis: a fleet-wide aggregate `[phase_a,
    /// phase_b].iter().sum::<_>()` has evidence iff AT LEAST ONE phase
    /// contributed an honest-positive increment to AT LEAST ONE axis,
    /// AND stays no-evidence as long as every phase contributes zero
    /// `ran` / `verified` increments. Pins the parallel-composition
    /// invariant against the two-phase aggregate the future
    /// `commands::attestation` emission site will collect — the
    /// saturating-add monoid composes through each axis independently,
    /// then the composed any-axis-has-evidence predicate reads the
    /// two aggregates together. A regression that broke either axis's
    /// monoid identity (e.g., a non-zero default that made the empty
    /// phase falsely surface evidence under sum) would fail this pin
    /// at the aggregate-reading step where the spurious record would
    /// defeat the no-evidence discriminator.
    #[test]
    fn test_compose_has_evidence_respects_monoid_add_on_both_axes() {
        let probe_no_evidence_a = ProbeCoverage { ran: 0, absent: 2 };
        let probe_no_evidence_b = ProbeCoverage { ran: 0, absent: 3 };
        let verification_no_evidence_a = VerificationCoverage {
            verified: 0,
            unverified: 1,
        };
        let verification_no_evidence_b = VerificationCoverage {
            verified: 0,
            unverified: 4,
        };

        let probe_aggregate_no_evidence = probe_no_evidence_a + probe_no_evidence_b;
        let verification_aggregate_no_evidence =
            verification_no_evidence_a + verification_no_evidence_b;
        assert!(
            !compose_has_evidence(
                &probe_aggregate_no_evidence,
                &verification_aggregate_no_evidence,
            ),
            "two-axis aggregate over no-evidence phases must read \
             no-evidence — probe={probe_aggregate_no_evidence:?} \
             verification={verification_aggregate_no_evidence:?}",
        );

        let probe_phase_evidenced = ProbeCoverage { ran: 3, absent: 0 };
        let probe_aggregate_evidenced = probe_no_evidence_a + probe_phase_evidenced;
        assert!(
            compose_has_evidence(
                &probe_aggregate_evidenced,
                &verification_aggregate_no_evidence,
            ),
            "any phase contributing `ran > 0` on the probe axis lifts \
             the aggregate off the no-evidence floor — \
             probe={probe_aggregate_evidenced:?}",
        );

        let verification_phase_evidenced = VerificationCoverage {
            verified: 2,
            unverified: 0,
        };
        let verification_aggregate_evidenced =
            verification_no_evidence_a + verification_phase_evidenced;
        assert!(
            compose_has_evidence(
                &probe_aggregate_no_evidence,
                &verification_aggregate_evidenced,
            ),
            "any phase contributing `verified > 0` on the verification \
             axis lifts the aggregate off the no-evidence floor — \
             verification={verification_aggregate_evidenced:?}",
        );
    }

    /// Parallel-composed relaxed-staging admission predicate admits
    /// every evidenced-and-trustworthy state — the structural arms
    /// where `compose_admission_eligible_relaxed` must read `true`:
    /// each axis carries at least one honest-positive arm
    /// (`ran > 0` / `verified > 0`) AND neither axis has reached the
    /// `usize::saturating_add` ceiling. Walks the cross product of the
    /// honest one-axis-evidenced / two-axes-evidenced representatives
    /// AND the four-arm (any-positive × trustworthy) shape so the
    /// honest-admit reading is pinned across the Phase 1 dev/staging
    /// admission tier the helper exists to surface.
    #[test]
    fn test_compose_admission_eligible_relaxed_at_evidenced_trustworthy_states_is_true() {
        let probe_evidenced_trustworthy = [
            ProbeCoverage { ran: 1, absent: 0 },
            ProbeCoverage { ran: 3, absent: 4 },
            ProbeCoverage { ran: 7, absent: 0 },
        ];
        let verification_evidenced_trustworthy = [
            VerificationCoverage {
                verified: 1,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 5,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 2,
                unverified: 3,
            },
        ];
        for probe in probe_evidenced_trustworthy {
            for verification in verification_evidenced_trustworthy {
                assert!(
                    compose_admission_eligible_relaxed(&probe, &verification),
                    "both-axes-evidenced-trustworthy state must admit \
                     the relaxed staging gate at probe={probe:?} \
                     verification={verification:?} — a regression that \
                     dropped either factor would fail this pin at the \
                     load-bearing honest-admit arm",
                );
            }
        }

        let probe_evidence_only = ProbeCoverage { ran: 2, absent: 0 };
        let verification_no_records = VerificationCoverage {
            verified: 0,
            unverified: 0,
        };
        assert!(
            compose_admission_eligible_relaxed(&probe_evidence_only, &verification_no_records),
            "one-axis-evidenced state must admit the relaxed staging \
             gate even when the opposite axis carries zero records — \
             the Phase 1 / Phase 2 partial-progress state the relaxed \
             gate exists to admit",
        );

        let probe_no_records = ProbeCoverage { ran: 0, absent: 0 };
        let verification_evidence_only = VerificationCoverage {
            verified: 1,
            unverified: 0,
        };
        assert!(
            compose_admission_eligible_relaxed(&probe_no_records, &verification_evidence_only),
            "one-axis-evidenced state must admit the relaxed staging \
             gate symmetrically when only the verification axis \
             surfaced a positive arm",
        );
    }

    /// Parallel-composed relaxed-staging admission predicate rejects
    /// every both-no-evidence state — the structural arms where
    /// `compose_admission_eligible_relaxed` must read `false` through
    /// the `compose_has_evidence` factor: the both-empty boundary and
    /// the both-no-evidence floor (all-absent paired with
    /// all-unverified). Pins the load-bearing fail-closed boundary the
    /// Phase 1 dev/staging admission gate refuses through the
    /// has-evidence factor — at these states zero honest-positive arms
    /// surfaced on either axis, so the relaxed precondition has
    /// nothing to admit.
    #[test]
    fn test_compose_admission_eligible_relaxed_at_no_evidence_arms_is_false() {
        let empty_probe = ProbeCoverage { ran: 0, absent: 0 };
        let empty_verification = VerificationCoverage {
            verified: 0,
            unverified: 0,
        };
        assert!(
            !compose_admission_eligible_relaxed(&empty_probe, &empty_verification),
            "both-axes-empty boundary must read no-admit at \
             ({empty_probe:?}, {empty_verification:?}) — the \
             fail-closed boundary the relaxed staging admission gate \
             rejects through the has-evidence factor",
        );

        let probe_no_evidence = [
            ProbeCoverage { ran: 0, absent: 1 },
            ProbeCoverage { ran: 0, absent: 5 },
        ];
        let verification_no_evidence = [
            VerificationCoverage {
                verified: 0,
                unverified: 1,
            },
            VerificationCoverage {
                verified: 0,
                unverified: 4,
            },
        ];
        for probe in probe_no_evidence {
            for verification in verification_no_evidence {
                assert!(
                    !compose_admission_eligible_relaxed(&probe, &verification),
                    "both-axes-no-evidence floor must read no-admit at \
                     probe={probe:?} verification={verification:?} — \
                     zero counted record on either axis surfaced an \
                     honest-positive arm; the relaxed staging gate \
                     fails closed through the has-evidence factor",
                );
            }
        }
    }

    /// Parallel-composed relaxed-staging admission predicate rejects
    /// every saturated state on either axis — the structural arms
    /// where `compose_admission_eligible_relaxed` must read `false`
    /// through the `!compose_is_saturated` trustworthiness clamp. At
    /// these states, the per-axis component has reached the
    /// `usize::saturating_add` ceiling so past-ceiling increments are
    /// lost and the derived-ratio surfaces are no longer trustworthy
    /// against the true counts — the clamp the strict gate inherits
    /// identically. Walks the three saturated-on-one-axis arms
    /// (probe-ran-saturated, probe-absent-saturated, verification-
    /// verified-saturated, verification-unverified-saturated) paired
    /// with evidenced honest opposites so each rejection is pinned
    /// against a baseline that would otherwise admit. A regression
    /// that dropped the saturation factor (returning
    /// `compose_has_evidence(p, v)` alone) would fail at exactly
    /// these cells.
    #[test]
    fn test_compose_admission_eligible_relaxed_at_saturated_states_is_false() {
        let saturated_probes = [
            ProbeCoverage {
                ran: usize::MAX,
                absent: 0,
            },
            ProbeCoverage {
                ran: 0,
                absent: usize::MAX,
            },
            ProbeCoverage {
                ran: usize::MAX,
                absent: 1,
            },
            ProbeCoverage {
                ran: 1,
                absent: usize::MAX,
            },
        ];
        let honest_verification = VerificationCoverage {
            verified: 3,
            unverified: 2,
        };
        for probe in saturated_probes {
            assert!(
                !compose_admission_eligible_relaxed(&probe, &honest_verification),
                "probe-axis-saturated state must read no-admit at \
                 probe={probe:?} verification={honest_verification:?} \
                 — past-ceiling increments are lost; the relaxed \
                 staging gate refuses the untrustworthy axis through \
                 the saturation factor",
            );
        }

        let saturated_verifications = [
            VerificationCoverage {
                verified: usize::MAX,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 0,
                unverified: usize::MAX,
            },
            VerificationCoverage {
                verified: usize::MAX,
                unverified: 1,
            },
            VerificationCoverage {
                verified: 1,
                unverified: usize::MAX,
            },
        ];
        let honest_probe = ProbeCoverage { ran: 5, absent: 1 };
        for verification in saturated_verifications {
            assert!(
                !compose_admission_eligible_relaxed(&honest_probe, &verification),
                "verification-axis-saturated state must read no-admit \
                 at probe={honest_probe:?} verification={verification:?} \
                 — past-ceiling increments are lost; the relaxed \
                 staging gate refuses the untrustworthy axis through \
                 the saturation factor",
            );
        }
    }

    /// Structural equivalence with the documented two-helper consumer
    /// composition `compose_has_evidence(p, v) &&
    /// !compose_is_saturated(p, v)`. Pins the one-oracle invariant the
    /// typed primitive carries — a regression that hand-rolled the
    /// body (e.g., returned `compose_has_evidence(p, v)` alone,
    /// dropping the trustworthiness clamp, or returned
    /// `compose_admission_eligible_strict` and silently rejected
    /// the one-axis-evidenced partial-progress state the relaxed gate
    /// exists to admit) would fail at the corresponding divergent
    /// cells. Walks the cross product of four per-axis representatives
    /// (empty, no-evidence, mixed, fully-positive) plus the saturated
    /// per-axis representatives so every (probe-arm × verification-arm)
    /// cell — honest AND saturated — is pinned against the documented
    /// composition.
    #[test]
    fn test_compose_admission_eligible_relaxed_equals_documented_composition() {
        let probe_cases = [
            ProbeCoverage { ran: 0, absent: 0 },
            ProbeCoverage { ran: 0, absent: 3 },
            ProbeCoverage { ran: 2, absent: 4 },
            ProbeCoverage { ran: 7, absent: 0 },
            ProbeCoverage {
                ran: usize::MAX,
                absent: 0,
            },
            ProbeCoverage {
                ran: 0,
                absent: usize::MAX,
            },
        ];
        let verification_cases = [
            VerificationCoverage {
                verified: 0,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 0,
                unverified: 3,
            },
            VerificationCoverage {
                verified: 1,
                unverified: 2,
            },
            VerificationCoverage {
                verified: 5,
                unverified: 0,
            },
            VerificationCoverage {
                verified: usize::MAX,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 0,
                unverified: usize::MAX,
            },
        ];
        for probe in probe_cases {
            for verification in verification_cases {
                let direct = compose_admission_eligible_relaxed(&probe, &verification);
                let composed = compose_has_evidence(&probe, &verification)
                    && !compose_is_saturated(&probe, &verification);
                assert_eq!(
                    direct, composed,
                    "typed-primitive composition must equal the \
                     documented two-helper consumer composition at \
                     probe={probe:?} verification={verification:?} — \
                     a regression that dropped either factor would \
                     fail this pin at the corresponding divergent cell",
                );
            }
        }
    }

    /// The load-bearing relaxed-vs-strict ordering pin: every state
    /// the strict-production admission gate admits is also admitted by
    /// the relaxed-staging admission gate. Pins the structural
    /// implication
    /// `compose_admission_eligible_strict(p, v) =>
    ///  compose_admission_eligible_relaxed(p, v)`
    /// across the cross product of the three per-axis honest
    /// fully-covered probe representatives × three per-axis honest
    /// fully-verified verification representatives (the strict-admitted
    /// subset, deliberately excluding the saturated representatives
    /// the strict gate refuses through its own `!is_saturated()` clamp).
    /// Mirrors the Phase 1 / Phase 2 ordering THEORY.md §V.4
    /// establishes — Phase 2 admits where Phase 1 admits AND every
    /// compliance attestation cleared. A regression that broke either
    /// helper's structural reading (e.g., a relaxed body that
    /// decoupled the trustworthiness clamp from the strict version, or
    /// a strict body that admitted the no-evidence floor) would fail
    /// this pin at the both-axes-complete cells where the strict gate
    /// admits but the relaxed gate would erroneously reject (or vice
    /// versa for the no-evidence floor).
    #[test]
    fn test_compose_admission_eligible_strict_implies_compose_admission_eligible_relaxed() {
        let probe_fully_covered_honest = [
            ProbeCoverage { ran: 1, absent: 0 },
            ProbeCoverage { ran: 7, absent: 0 },
            ProbeCoverage {
                ran: usize::MAX - 1,
                absent: 0,
            },
        ];
        let verification_fully_verified_honest = [
            VerificationCoverage {
                verified: 1,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 5,
                unverified: 0,
            },
            VerificationCoverage {
                verified: usize::MAX - 1,
                unverified: 0,
            },
        ];
        for probe in probe_fully_covered_honest {
            for verification in verification_fully_verified_honest {
                assert!(
                    compose_admission_eligible_strict(&probe, &verification),
                    "strict admission precondition must admit at \
                     probe={probe:?} verification={verification:?}",
                );
                assert!(
                    compose_admission_eligible_relaxed(&probe, &verification),
                    "strict admission must imply relaxed admission at \
                     probe={probe:?} verification={verification:?} — \
                     the Phase 1 / Phase 2 ordering THEORY §V.4 \
                     establishes is structurally load-bearing",
                );
            }
        }

        let probe_evidence_only = ProbeCoverage { ran: 0, absent: 3 };
        let verification_evidence_only = VerificationCoverage {
            verified: 2,
            unverified: 0,
        };
        assert!(
            !compose_admission_eligible_strict(&probe_evidence_only, &verification_evidence_only),
            "strict admission must refuse the one-axis-incomplete \
             state at probe={probe_evidence_only:?} \
             verification={verification_evidence_only:?}",
        );
        assert!(
            compose_admission_eligible_relaxed(&probe_evidence_only, &verification_evidence_only),
            "relaxed admission must admit the one-axis-incomplete \
             evidenced state — the structural witness the relaxed gate \
             is strictly weaker than the strict gate at the Phase 1 / \
             Phase 2 partial-progress boundary",
        );
    }

    /// Pins the floor reading at the four no-evidence representative
    /// states — the cross product of the two per-axis no-evidence arms
    /// (`is_empty` at `(0, 0)`, `is_all_absent` / `is_all_unverified` at
    /// `(0, N>0)`) on each axis. Every combination must read `true`,
    /// pinning the both-axes no-positive-evidence floor uniformly across
    /// the four inner-disjunction arms.
    #[test]
    fn test_compose_is_all_no_evidence_at_both_axes_no_evidence_arms_is_true() {
        let probe_empty = ProbeCoverage { ran: 0, absent: 0 };
        let probe_all_absent = ProbeCoverage { ran: 0, absent: 4 };
        let verification_empty = VerificationCoverage {
            verified: 0,
            unverified: 0,
        };
        let verification_all_unverified = VerificationCoverage {
            verified: 0,
            unverified: 6,
        };
        for probe in [probe_empty, probe_all_absent] {
            for verification in [verification_empty, verification_all_unverified] {
                assert!(
                    compose_is_all_no_evidence(&probe, &verification),
                    "both-axes no-evidence floor must admit at \
                     probe={probe:?} verification={verification:?} — \
                     every per-axis-no-evidence × per-axis-no-evidence \
                     combination is the load-bearing both-axes-no-\
                     positive-evidence floor THEORY §V.4 names",
                );
            }
        }
    }

    /// Pins the rejection reading at every state where AT LEAST ONE axis
    /// has surfaced positive evidence. Covers the three per-axis evidence
    /// representatives (mixed `(R>0, A>0)`, fully-covered `(M, 0)`,
    /// saturated-fully-covered `(usize::MAX, 0)`) on each axis composed
    /// against the four no-evidence representatives on the opposite axis,
    /// plus the diagonal cross product of evidence × evidence. Every
    /// combination must read `false`, foreclosing the drift class where a
    /// regression swapping the outer combinator (AND → OR) would silently
    /// admit the one-axis-evidenced state as no-evidence.
    #[test]
    fn test_compose_is_all_no_evidence_at_any_axis_evidence_arms_is_false() {
        let probe_no_evidence = [
            ProbeCoverage { ran: 0, absent: 0 },
            ProbeCoverage { ran: 0, absent: 4 },
        ];
        let probe_evidence = [
            ProbeCoverage { ran: 2, absent: 3 },
            ProbeCoverage { ran: 7, absent: 0 },
            ProbeCoverage {
                ran: usize::MAX,
                absent: 0,
            },
        ];
        let verification_no_evidence = [
            VerificationCoverage {
                verified: 0,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 0,
                unverified: 6,
            },
        ];
        let verification_evidence = [
            VerificationCoverage {
                verified: 1,
                unverified: 4,
            },
            VerificationCoverage {
                verified: 5,
                unverified: 0,
            },
            VerificationCoverage {
                verified: usize::MAX,
                unverified: 0,
            },
        ];
        for probe in probe_evidence {
            for verification in verification_no_evidence {
                assert!(
                    !compose_is_all_no_evidence(&probe, &verification),
                    "no-evidence floor must refuse the probe-axis-\
                     evidenced state at probe={probe:?} \
                     verification={verification:?}",
                );
            }
        }
        for probe in probe_no_evidence {
            for verification in verification_evidence {
                assert!(
                    !compose_is_all_no_evidence(&probe, &verification),
                    "no-evidence floor must refuse the verification-\
                     axis-evidenced state at probe={probe:?} \
                     verification={verification:?}",
                );
            }
        }
        for probe in probe_evidence {
            for verification in verification_evidence {
                assert!(
                    !compose_is_all_no_evidence(&probe, &verification),
                    "no-evidence floor must refuse the both-axes-\
                     evidenced state at probe={probe:?} \
                     verification={verification:?}",
                );
            }
        }
    }

    /// Pins the structural equivalence with the documented four-arm
    /// disjunction-of-disjunctions composition across the cross product
    /// of representative per-axis arms (empty, all-absent/all-unverified,
    /// mixed, fully-covered/fully-verified, both saturated polarities).
    /// A regression that swapped any combinator (outer AND ↔ OR, or
    /// either inner OR ↔ AND) would fail this pin at the corresponding
    /// divergent cell.
    #[test]
    fn test_compose_is_all_no_evidence_equals_documented_composition() {
        let probe_cases = [
            ProbeCoverage { ran: 0, absent: 0 },
            ProbeCoverage { ran: 0, absent: 3 },
            ProbeCoverage { ran: 2, absent: 4 },
            ProbeCoverage { ran: 7, absent: 0 },
            ProbeCoverage {
                ran: usize::MAX,
                absent: 0,
            },
            ProbeCoverage {
                ran: 0,
                absent: usize::MAX,
            },
        ];
        let verification_cases = [
            VerificationCoverage {
                verified: 0,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 0,
                unverified: 3,
            },
            VerificationCoverage {
                verified: 1,
                unverified: 2,
            },
            VerificationCoverage {
                verified: 5,
                unverified: 0,
            },
            VerificationCoverage {
                verified: usize::MAX,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 0,
                unverified: usize::MAX,
            },
        ];
        for probe in probe_cases {
            for verification in verification_cases {
                let direct = compose_is_all_no_evidence(&probe, &verification);
                let composed = (probe.is_all_absent() || probe.is_empty())
                    && (verification.is_all_unverified() || verification.is_empty());
                assert_eq!(
                    direct, composed,
                    "typed-primitive composition must equal the \
                     documented four-arm consumer composition at \
                     probe={probe:?} verification={verification:?} — \
                     a regression that swapped any combinator would \
                     fail this pin at the corresponding divergent cell",
                );
            }
        }
    }

    /// Pins the load-bearing De Morgan equivalence
    /// `compose_is_all_no_evidence(p, v) == !compose_has_evidence(p, v)`
    /// across the same cross product of representative per-axis arms.
    /// The equivalence holds because `(p.is_all_absent() || p.is_empty())
    /// == (p.ran == 0) == !p.has_evidence()` (the union of the two
    /// `ran == 0` arms exhausts the no-positive-evidence cases on the
    /// probe axis), symmetrically on the verification axis, and the
    /// conjunction across axes mirrors the disjunction in
    /// `compose_has_evidence` under De Morgan. Pinning this equivalence
    /// at the test surface forecloses the drift class where a regression
    /// to either helper would silently break the structural complement
    /// relation the parallel-axis compose family relies on (e.g., a
    /// regression to `has_evidence` that flipped the AND ↔ OR inner
    /// combinator would break the equivalence at the all-absent ×
    /// all-unverified cell — exactly the structural seam the De Morgan
    /// equivalence pin surfaces).
    #[test]
    fn test_compose_is_all_no_evidence_equals_negation_of_compose_has_evidence() {
        let probe_cases = [
            ProbeCoverage { ran: 0, absent: 0 },
            ProbeCoverage { ran: 0, absent: 3 },
            ProbeCoverage { ran: 2, absent: 4 },
            ProbeCoverage { ran: 7, absent: 0 },
            ProbeCoverage {
                ran: usize::MAX,
                absent: 0,
            },
            ProbeCoverage {
                ran: 0,
                absent: usize::MAX,
            },
        ];
        let verification_cases = [
            VerificationCoverage {
                verified: 0,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 0,
                unverified: 3,
            },
            VerificationCoverage {
                verified: 1,
                unverified: 2,
            },
            VerificationCoverage {
                verified: 5,
                unverified: 0,
            },
            VerificationCoverage {
                verified: usize::MAX,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 0,
                unverified: usize::MAX,
            },
        ];
        for probe in probe_cases {
            for verification in verification_cases {
                let floor = compose_is_all_no_evidence(&probe, &verification);
                let evidence = compose_has_evidence(&probe, &verification);
                assert_eq!(
                    floor, !evidence,
                    "load-bearing De Morgan equivalence \
                     compose_is_all_no_evidence(p, v) == \
                     !compose_has_evidence(p, v) must hold at \
                     probe={probe:?} verification={verification:?} — \
                     a regression to either helper that broke the \
                     structural complement relation would fail this \
                     pin at the corresponding divergent cell",
                );
            }
        }
    }

    /// Pins the saturation-robust reading at the post-saturation arms
    /// of both axes. The all-absent / all-unverified arm at the
    /// `usize::MAX` count `({ran: 0, absent: usize::MAX}, {verified: 0,
    /// unverified: usize::MAX})` must still read `true` (every counted
    /// record — even the dropped past-ceiling no-evidence increments —
    /// collapsed to the no-evidence arm on each axis). The inverse-
    /// saturation arm `{ran: usize::MAX, absent: 0}` / `{verified:
    /// usize::MAX, unverified: 0}` must read `false` (every counted
    /// record on the saturated axis surfaced its honest-positive arm,
    /// so the per-axis no-evidence reading is structurally `false` on
    /// that axis — even though the saturating-add ceiling has been
    /// reached). The integer-arithmetic body of each per-axis arm
    /// predicate forecloses both drift directions through the
    /// component-level tests on the components themselves.
    #[test]
    fn test_compose_is_all_no_evidence_stays_robust_at_saturated_states() {
        let probe_saturated_no_evidence = ProbeCoverage {
            ran: 0,
            absent: usize::MAX,
        };
        let verification_saturated_no_evidence = VerificationCoverage {
            verified: 0,
            unverified: usize::MAX,
        };
        assert!(
            compose_is_all_no_evidence(
                &probe_saturated_no_evidence,
                &verification_saturated_no_evidence,
            ),
            "saturated-but-no-evidence arm must still read `true` at \
             the both-axes no-evidence floor — the per-axis \
             integer-arithmetic body forecloses the saturated-but-\
             rolled drift class through the `ran == 0` / `verified == \
             0` component-level tests",
        );
        let probe_saturated_evidence = ProbeCoverage {
            ran: usize::MAX,
            absent: 0,
        };
        let verification_saturated_evidence = VerificationCoverage {
            verified: usize::MAX,
            unverified: 0,
        };
        assert!(
            !compose_is_all_no_evidence(
                &probe_saturated_evidence,
                &verification_saturated_evidence,
            ),
            "saturated-fully-evidenced arm must read `false` at the \
             both-axes no-evidence floor — the saturating-add ceiling \
             on the evidence component cannot drift the per-axis \
             no-evidence reading away from `false` because the \
             component-level test reads `ran == 0` / `verified == 0` \
             against the saturated component itself",
        );
        assert!(
            !compose_is_all_no_evidence(
                &probe_saturated_evidence,
                &verification_saturated_no_evidence,
            ),
            "saturated-fully-evidenced probe × saturated-all-unverified \
             verification arm must read `false` — the per-axis \
             no-evidence reading is structurally `false` on the \
             saturated-evidenced probe axis, foreclosing the composed \
             AND",
        );
    }

    /// Pins the disjunction reading at the two structural fail-closed
    /// reasons individually — the no-evidence floor arm AND the
    /// saturation ceiling arm must each independently surface `true`.
    /// Mirrors the relaxed gate's fail-closed decomposition: a state
    /// where every counted record collapsed to no-evidence (the floor) OR
    /// any axis reached its saturating-add ceiling (the trust break) is
    /// fail-closed under the relaxed-staging admission gate.
    #[test]
    fn test_compose_is_all_no_evidence_or_saturated_at_floor_and_ceiling_arms_is_true() {
        let probe_all_absent = ProbeCoverage { ran: 0, absent: 4 };
        let probe_empty = ProbeCoverage { ran: 0, absent: 0 };
        let verification_all_unverified = VerificationCoverage {
            verified: 0,
            unverified: 6,
        };
        let verification_empty = VerificationCoverage {
            verified: 0,
            unverified: 0,
        };
        for probe in [probe_empty, probe_all_absent] {
            for verification in [verification_empty, verification_all_unverified] {
                assert!(
                    compose_is_all_no_evidence_or_saturated(&probe, &verification),
                    "relaxed-gate fail-closed disjunction must admit at \
                     the no-evidence floor probe={probe:?} \
                     verification={verification:?} — the first disjunct \
                     (compose_is_all_no_evidence) surfaces `true` here",
                );
            }
        }

        let probe_saturated_evidence = ProbeCoverage {
            ran: usize::MAX,
            absent: 0,
        };
        let probe_saturated_absent = ProbeCoverage {
            ran: 0,
            absent: usize::MAX,
        };
        let verification_saturated_evidence = VerificationCoverage {
            verified: usize::MAX,
            unverified: 0,
        };
        let verification_saturated_absent = VerificationCoverage {
            verified: 0,
            unverified: usize::MAX,
        };
        let probe_evidenced_non_saturated = ProbeCoverage { ran: 3, absent: 1 };
        let verification_evidenced_non_saturated = VerificationCoverage {
            verified: 2,
            unverified: 1,
        };
        for probe in [probe_saturated_evidence, probe_saturated_absent] {
            assert!(
                compose_is_all_no_evidence_or_saturated(
                    &probe,
                    &verification_evidenced_non_saturated,
                ),
                "relaxed-gate fail-closed disjunction must admit at the \
                 probe-axis saturation ceiling probe={probe:?} — the \
                 second disjunct (compose_is_saturated) surfaces `true` \
                 here even when the verification axis is \
                 trustworthy/evidenced",
            );
        }
        for verification in [
            verification_saturated_evidence,
            verification_saturated_absent,
        ] {
            assert!(
                compose_is_all_no_evidence_or_saturated(
                    &probe_evidenced_non_saturated,
                    &verification,
                ),
                "relaxed-gate fail-closed disjunction must admit at the \
                 verification-axis saturation ceiling \
                 verification={verification:?} — the second disjunct \
                 (compose_is_saturated) surfaces `true` here even when \
                 the probe axis is trustworthy/evidenced",
            );
        }
    }

    /// Pins the rejection reading at the relaxed-eligible states — every
    /// `(probe, verification)` pair where AT LEAST ONE axis surfaced
    /// positive evidence AND BOTH axes remain below the saturating-add
    /// ceiling must read `false`. Forecloses the drift class where a
    /// regression that swapped the outer combinator (OR → AND) would
    /// silently classify the relaxed-eligible state as fail-closed
    /// (collapsing the disjunction to the empty intersection of the
    /// no-evidence floor and the saturation ceiling — structurally
    /// impossible since the saturated component requires
    /// `ran == usize::MAX || verified == usize::MAX` while
    /// `compose_is_all_no_evidence` requires `ran == 0 && verified == 0`,
    /// so the conjunction is `false` everywhere a regression would
    /// surface).
    #[test]
    fn test_compose_is_all_no_evidence_or_saturated_at_relaxed_eligible_states_is_false() {
        let probe_evidence_non_saturated = [
            ProbeCoverage { ran: 2, absent: 3 },
            ProbeCoverage { ran: 7, absent: 0 },
            ProbeCoverage { ran: 1, absent: 0 },
            ProbeCoverage {
                ran: usize::MAX - 1,
                absent: 0,
            },
        ];
        let verification_no_evidence_non_saturated = [
            VerificationCoverage {
                verified: 0,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 0,
                unverified: 4,
            },
        ];
        for probe in probe_evidence_non_saturated {
            for verification in verification_no_evidence_non_saturated {
                assert!(
                    !compose_is_all_no_evidence_or_saturated(&probe, &verification),
                    "relaxed-gate fail-closed disjunction must refuse \
                     the probe-axis-evidenced trustworthy state at \
                     probe={probe:?} verification={verification:?} — \
                     evidence on at least one axis AND no saturation \
                     anywhere is the load-bearing relaxed-eligible \
                     reading",
                );
            }
        }

        let probe_no_evidence_non_saturated = [
            ProbeCoverage { ran: 0, absent: 0 },
            ProbeCoverage { ran: 0, absent: 4 },
        ];
        let verification_evidence_non_saturated = [
            VerificationCoverage {
                verified: 1,
                unverified: 4,
            },
            VerificationCoverage {
                verified: 5,
                unverified: 0,
            },
            VerificationCoverage {
                verified: usize::MAX - 1,
                unverified: 0,
            },
        ];
        for probe in probe_no_evidence_non_saturated {
            for verification in verification_evidence_non_saturated {
                assert!(
                    !compose_is_all_no_evidence_or_saturated(&probe, &verification),
                    "relaxed-gate fail-closed disjunction must refuse \
                     the verification-axis-evidenced trustworthy state \
                     at probe={probe:?} verification={verification:?}",
                );
            }
        }

        for probe in probe_evidence_non_saturated {
            for verification in verification_evidence_non_saturated {
                assert!(
                    !compose_is_all_no_evidence_or_saturated(&probe, &verification),
                    "relaxed-gate fail-closed disjunction must refuse \
                     the both-axes-evidenced trustworthy state at \
                     probe={probe:?} verification={verification:?} — \
                     this is the strict-eligible subset which must also \
                     be relaxed-eligible by the prior-pinned strict ⇒ \
                     relaxed ordering",
                );
            }
        }
    }

    /// Pins the structural equivalence with the documented two-helper
    /// disjunction composition across the cross product of representative
    /// per-axis arms (empty, all-absent/all-unverified, mixed,
    /// fully-covered/fully-verified, both saturated polarities). A
    /// regression that swapped the outer combinator (OR ↔ AND) or
    /// dropped either component helper would fail this pin at the
    /// corresponding divergent cell.
    #[test]
    fn test_compose_is_all_no_evidence_or_saturated_equals_documented_composition() {
        let probe_cases = [
            ProbeCoverage { ran: 0, absent: 0 },
            ProbeCoverage { ran: 0, absent: 3 },
            ProbeCoverage { ran: 2, absent: 4 },
            ProbeCoverage { ran: 7, absent: 0 },
            ProbeCoverage {
                ran: usize::MAX,
                absent: 0,
            },
            ProbeCoverage {
                ran: 0,
                absent: usize::MAX,
            },
        ];
        let verification_cases = [
            VerificationCoverage {
                verified: 0,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 0,
                unverified: 3,
            },
            VerificationCoverage {
                verified: 1,
                unverified: 2,
            },
            VerificationCoverage {
                verified: 5,
                unverified: 0,
            },
            VerificationCoverage {
                verified: usize::MAX,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 0,
                unverified: usize::MAX,
            },
        ];
        for probe in probe_cases {
            for verification in verification_cases {
                let direct = compose_is_all_no_evidence_or_saturated(&probe, &verification);
                let composed = compose_is_all_no_evidence(&probe, &verification)
                    || compose_is_saturated(&probe, &verification);
                assert_eq!(
                    direct, composed,
                    "typed-primitive composition must equal the \
                     documented two-helper disjunction composition at \
                     probe={probe:?} verification={verification:?} — \
                     a regression that swapped the outer combinator or \
                     dropped either component would fail this pin at \
                     the corresponding divergent cell",
                );
            }
        }
    }

    /// Pins the load-bearing De Morgan equivalence
    /// `compose_is_all_no_evidence_or_saturated(p, v) ==
    /// !compose_admission_eligible_relaxed(p, v)` across the same cross
    /// product of representative per-axis arms. The equivalence holds
    /// because `compose_admission_eligible_relaxed == compose_has_evidence
    /// && !compose_is_saturated`, so its negation expands to
    /// `!compose_has_evidence || compose_is_saturated`, and by the
    /// previously-pinned De Morgan equivalence
    /// `!compose_has_evidence == compose_is_all_no_evidence` (commit
    /// e652297) this reduces to `compose_is_all_no_evidence ||
    /// compose_is_saturated`. Pinning this equivalence at the test
    /// surface forecloses the drift class where a regression to either
    /// helper would silently break the structural complement relation
    /// the parallel-axis compose family relies on.
    #[test]
    fn test_compose_is_all_no_evidence_or_saturated_equals_negation_of_compose_admission_eligible_relaxed(
    ) {
        let probe_cases = [
            ProbeCoverage { ran: 0, absent: 0 },
            ProbeCoverage { ran: 0, absent: 3 },
            ProbeCoverage { ran: 2, absent: 4 },
            ProbeCoverage { ran: 7, absent: 0 },
            ProbeCoverage {
                ran: usize::MAX,
                absent: 0,
            },
            ProbeCoverage {
                ran: 0,
                absent: usize::MAX,
            },
        ];
        let verification_cases = [
            VerificationCoverage {
                verified: 0,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 0,
                unverified: 3,
            },
            VerificationCoverage {
                verified: 1,
                unverified: 2,
            },
            VerificationCoverage {
                verified: 5,
                unverified: 0,
            },
            VerificationCoverage {
                verified: usize::MAX,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 0,
                unverified: usize::MAX,
            },
        ];
        for probe in probe_cases {
            for verification in verification_cases {
                let fail_closed = compose_is_all_no_evidence_or_saturated(&probe, &verification);
                let relaxed = compose_admission_eligible_relaxed(&probe, &verification);
                assert_eq!(
                    fail_closed, !relaxed,
                    "load-bearing De Morgan equivalence \
                     compose_is_all_no_evidence_or_saturated(p, v) == \
                     !compose_admission_eligible_relaxed(p, v) must \
                     hold at probe={probe:?} verification={verification:?} \
                     — a regression to either helper that broke the \
                     structural complement relation would fail this pin \
                     at the corresponding divergent cell",
                );
            }
        }
    }

    /// Pins the saturation-robust reading at the two named saturation
    /// arms across both axes. The `{ran: usize::MAX, absent: 0}` /
    /// `{verified: usize::MAX, unverified: 0}` saturated-fully-evidenced
    /// arms — where every other relaxed-gate ratio surface would lose
    /// past-ceiling increments — must read `true` honestly through the
    /// second disjunct. The `{ran: 0, absent: usize::MAX}` /
    /// `{verified: 0, unverified: usize::MAX}` saturated-all-absent /
    /// saturated-all-unverified arms must read `true` honestly through
    /// EITHER disjunct (both `compose_is_all_no_evidence` and
    /// `compose_is_saturated` surface `true` independently). Forecloses
    /// the drift class where a regression dropped the second disjunct
    /// (silently admitting the saturated-evidenced state as relaxed-
    /// eligible) and the dual drift where a regression dropped the
    /// first disjunct (silently admitting the no-evidence non-saturated
    /// floor as relaxed-eligible).
    #[test]
    fn test_compose_is_all_no_evidence_or_saturated_stays_robust_at_saturated_states() {
        let probe_saturated_evidence = ProbeCoverage {
            ran: usize::MAX,
            absent: 0,
        };
        let verification_saturated_evidence = VerificationCoverage {
            verified: usize::MAX,
            unverified: 0,
        };
        assert!(
            compose_is_all_no_evidence_or_saturated(
                &probe_saturated_evidence,
                &verification_saturated_evidence,
            ),
            "saturated-fully-evidenced both axes must read `true` — \
             every relaxed-gate ratio surface loses past-ceiling \
             increments here so the gate refuses through the saturation \
             disjunct, even though both axes carry positive evidence",
        );
        let verification_non_saturated_evidence = VerificationCoverage {
            verified: 3,
            unverified: 0,
        };
        assert!(
            compose_is_all_no_evidence_or_saturated(
                &probe_saturated_evidence,
                &verification_non_saturated_evidence,
            ),
            "one-axis-saturated-evidenced must read `true` — the \
             saturation disjunct admits through the saturated probe \
             axis even though the verification axis is trustworthy",
        );

        let probe_saturated_no_evidence = ProbeCoverage {
            ran: 0,
            absent: usize::MAX,
        };
        let verification_saturated_no_evidence = VerificationCoverage {
            verified: 0,
            unverified: usize::MAX,
        };
        assert!(
            compose_is_all_no_evidence_or_saturated(
                &probe_saturated_no_evidence,
                &verification_saturated_no_evidence,
            ),
            "saturated-all-absent / saturated-all-unverified both axes \
             must read `true` — both disjuncts independently surface \
             `true` (compose_is_all_no_evidence because ran == 0 / \
             verified == 0, compose_is_saturated because absent / \
             unverified == usize::MAX), the load-bearing both-disjuncts-\
             surface arm",
        );

        let probe_evidence_non_saturated = ProbeCoverage { ran: 3, absent: 0 };
        let verification_evidence_non_saturated = VerificationCoverage {
            verified: 2,
            unverified: 0,
        };
        assert!(
            !compose_is_all_no_evidence_or_saturated(
                &probe_evidence_non_saturated,
                &verification_evidence_non_saturated,
            ),
            "fully-evidenced non-saturated both axes must read `false` \
             — neither disjunct surfaces `true` (evidence on both axes \
             AND no saturation anywhere is the relaxed-eligible state \
             the gate admits, the structural witness the De Morgan \
             equivalence with !compose_admission_eligible_relaxed pins)",
        );
    }

    /// Pins the disjunction reading at the two structural fail-closed
    /// reasons individually — the incompleteness floor arm AND the
    /// saturation ceiling arm must each independently surface `true`.
    /// Mirrors the strict gate's fail-closed decomposition: a state
    /// where at least one axis failed to surface its fully-complete arm
    /// (the incompleteness floor: empty axis, all-no-evidence axis, or
    /// mixed axis) OR any axis reached its saturating-add ceiling (the
    /// trust break) is fail-closed under the strict-staging admission
    /// gate. The structural peer of
    /// `test_compose_is_all_no_evidence_or_saturated_at_floor_and_ceiling_arms_is_true`
    /// at the strict tier.
    #[test]
    fn test_compose_is_incomplete_or_saturated_at_fail_closed_arms_is_true() {
        let probe_incomplete = [
            ProbeCoverage { ran: 0, absent: 0 },
            ProbeCoverage { ran: 0, absent: 5 },
            ProbeCoverage { ran: 3, absent: 4 },
        ];
        let verification_fully_verified = VerificationCoverage {
            verified: 5,
            unverified: 0,
        };
        for probe in probe_incomplete {
            assert!(
                compose_is_incomplete_or_saturated(&probe, &verification_fully_verified),
                "strict-gate fail-closed disjunction must admit at the \
                 probe-axis incompleteness floor probe={probe:?} — the \
                 first disjunct (!compose_is_fully_complete) surfaces \
                 `true` here even when the verification axis is fully \
                 verified",
            );
        }

        let probe_fully_covered = ProbeCoverage { ran: 7, absent: 0 };
        let verification_incomplete = [
            VerificationCoverage {
                verified: 0,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 0,
                unverified: 3,
            },
            VerificationCoverage {
                verified: 2,
                unverified: 3,
            },
        ];
        for verification in verification_incomplete {
            assert!(
                compose_is_incomplete_or_saturated(&probe_fully_covered, &verification),
                "strict-gate fail-closed disjunction must admit at the \
                 verification-axis incompleteness floor \
                 verification={verification:?} — the first disjunct \
                 (!compose_is_fully_complete) surfaces `true` here even \
                 when the probe axis is fully covered",
            );
        }

        let probe_saturated_evidence = ProbeCoverage {
            ran: usize::MAX,
            absent: 0,
        };
        let probe_saturated_absent = ProbeCoverage {
            ran: 0,
            absent: usize::MAX,
        };
        let verification_saturated_evidence = VerificationCoverage {
            verified: usize::MAX,
            unverified: 0,
        };
        let verification_saturated_absent = VerificationCoverage {
            verified: 0,
            unverified: usize::MAX,
        };
        let probe_evidenced_non_saturated = ProbeCoverage { ran: 3, absent: 0 };
        let verification_evidenced_non_saturated = VerificationCoverage {
            verified: 2,
            unverified: 0,
        };
        for probe in [probe_saturated_evidence, probe_saturated_absent] {
            assert!(
                compose_is_incomplete_or_saturated(&probe, &verification_evidenced_non_saturated,),
                "strict-gate fail-closed disjunction must admit at the \
                 probe-axis saturation ceiling probe={probe:?} — the \
                 second disjunct (compose_is_saturated) surfaces `true` \
                 here even when the verification axis is fully-verified \
                 trustworthy",
            );
        }
        for verification in [
            verification_saturated_evidence,
            verification_saturated_absent,
        ] {
            assert!(
                compose_is_incomplete_or_saturated(&probe_evidenced_non_saturated, &verification,),
                "strict-gate fail-closed disjunction must admit at the \
                 verification-axis saturation ceiling \
                 verification={verification:?} — the second disjunct \
                 (compose_is_saturated) surfaces `true` here even when \
                 the probe axis is fully-covered trustworthy",
            );
        }
    }

    /// Pins the rejection reading at the strict-eligible states — every
    /// `(probe, verification)` pair where BOTH axes surfaced their
    /// fully-complete arm AND BOTH axes remain below the saturating-add
    /// ceiling must read `false`. Forecloses the drift class where a
    /// regression that swapped the outer combinator (OR → AND) would
    /// silently classify the strict-eligible state as fail-closed
    /// (collapsing the disjunction to the empty intersection of the
    /// incompleteness floor and the saturation ceiling — structurally
    /// impossible since `!compose_is_fully_complete` requires at least
    /// one axis to be non-fully-covered/non-fully-verified while
    /// `compose_is_saturated` requires
    /// `ran == usize::MAX || absent == usize::MAX || verified ==
    ///  usize::MAX || unverified == usize::MAX`,
    /// and the fully-evidenced saturated state
    /// `{ran: usize::MAX, absent: 0}` reads `is_fully_covered == true`
    /// honestly through the `absent == 0` factor — so a regression
    /// would silently admit the strict-eligible state as fail-closed).
    /// The structural peer of
    /// `test_compose_is_all_no_evidence_or_saturated_at_relaxed_eligible_states_is_false`
    /// at the strict tier.
    #[test]
    fn test_compose_is_incomplete_or_saturated_at_strict_eligible_states_is_false() {
        let probe_strict_eligible = [
            ProbeCoverage { ran: 1, absent: 0 },
            ProbeCoverage { ran: 7, absent: 0 },
            ProbeCoverage {
                ran: usize::MAX - 1,
                absent: 0,
            },
        ];
        let verification_strict_eligible = [
            VerificationCoverage {
                verified: 1,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 5,
                unverified: 0,
            },
            VerificationCoverage {
                verified: usize::MAX - 1,
                unverified: 0,
            },
        ];
        for probe in probe_strict_eligible {
            for verification in verification_strict_eligible {
                assert!(
                    !compose_is_incomplete_or_saturated(&probe, &verification),
                    "strict-gate fail-closed disjunction must refuse the \
                     both-axes-complete trustworthy state at \
                     probe={probe:?} verification={verification:?} — \
                     completeness on both axes AND no saturation \
                     anywhere is the load-bearing strict-eligible reading",
                );
            }
        }
    }

    /// Pins the structural equivalence with the documented two-helper
    /// disjunction composition across the cross product of representative
    /// per-axis arms (empty, all-absent/all-unverified, mixed,
    /// fully-covered/fully-verified, both saturated polarities). A
    /// regression that swapped the outer combinator (OR ↔ AND) or
    /// dropped either component helper would fail this pin at the
    /// corresponding divergent cell. The structural peer of
    /// `test_compose_is_all_no_evidence_or_saturated_equals_documented_composition`
    /// at the strict tier.
    #[test]
    fn test_compose_is_incomplete_or_saturated_equals_documented_composition() {
        let probe_cases = [
            ProbeCoverage { ran: 0, absent: 0 },
            ProbeCoverage { ran: 0, absent: 3 },
            ProbeCoverage { ran: 2, absent: 4 },
            ProbeCoverage { ran: 7, absent: 0 },
            ProbeCoverage {
                ran: usize::MAX,
                absent: 0,
            },
            ProbeCoverage {
                ran: 0,
                absent: usize::MAX,
            },
        ];
        let verification_cases = [
            VerificationCoverage {
                verified: 0,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 0,
                unverified: 3,
            },
            VerificationCoverage {
                verified: 1,
                unverified: 2,
            },
            VerificationCoverage {
                verified: 5,
                unverified: 0,
            },
            VerificationCoverage {
                verified: usize::MAX,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 0,
                unverified: usize::MAX,
            },
        ];
        for probe in probe_cases {
            for verification in verification_cases {
                let direct = compose_is_incomplete_or_saturated(&probe, &verification);
                let composed = !compose_is_fully_complete(&probe, &verification)
                    || compose_is_saturated(&probe, &verification);
                assert_eq!(
                    direct, composed,
                    "typed-primitive composition must equal the \
                     documented two-helper disjunction composition at \
                     probe={probe:?} verification={verification:?} — \
                     a regression that swapped the outer combinator or \
                     dropped either component would fail this pin at \
                     the corresponding divergent cell",
                );
            }
        }
    }

    /// Pins the load-bearing De Morgan equivalence
    /// `compose_is_incomplete_or_saturated(p, v) ==
    /// !compose_admission_eligible_strict(p, v)` across the same cross
    /// product of representative per-axis arms. The equivalence holds
    /// because `compose_admission_eligible_strict == compose_is_fully_complete
    /// && !compose_is_saturated` (the load-bearing decomposition pinned at
    /// `test_compose_is_fully_complete_decomposes_strict_admission`, commit
    /// 078826b), so its negation expands directly to
    /// `!compose_is_fully_complete || compose_is_saturated`. Pinning this
    /// equivalence at the test surface forecloses the drift class where a
    /// regression to either helper would silently break the structural
    /// complement relation the parallel-axis compose family relies on.
    /// The structural peer of
    /// `test_compose_is_all_no_evidence_or_saturated_equals_negation_of_compose_admission_eligible_relaxed`
    /// at the strict tier.
    #[test]
    fn test_compose_is_incomplete_or_saturated_equals_negation_of_compose_admission_eligible_strict(
    ) {
        let probe_cases = [
            ProbeCoverage { ran: 0, absent: 0 },
            ProbeCoverage { ran: 0, absent: 3 },
            ProbeCoverage { ran: 2, absent: 4 },
            ProbeCoverage { ran: 7, absent: 0 },
            ProbeCoverage {
                ran: usize::MAX,
                absent: 0,
            },
            ProbeCoverage {
                ran: 0,
                absent: usize::MAX,
            },
        ];
        let verification_cases = [
            VerificationCoverage {
                verified: 0,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 0,
                unverified: 3,
            },
            VerificationCoverage {
                verified: 1,
                unverified: 2,
            },
            VerificationCoverage {
                verified: 5,
                unverified: 0,
            },
            VerificationCoverage {
                verified: usize::MAX,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 0,
                unverified: usize::MAX,
            },
        ];
        for probe in probe_cases {
            for verification in verification_cases {
                let fail_closed = compose_is_incomplete_or_saturated(&probe, &verification);
                let strict = compose_admission_eligible_strict(&probe, &verification);
                assert_eq!(
                    fail_closed, !strict,
                    "load-bearing De Morgan equivalence \
                     compose_is_incomplete_or_saturated(p, v) == \
                     !compose_admission_eligible_strict(p, v) must \
                     hold at probe={probe:?} verification={verification:?} \
                     — a regression to either helper that broke the \
                     structural complement relation would fail this pin \
                     at the corresponding divergent cell",
                );
            }
        }
    }

    /// Pins the structural ordering between the two tier-level
    /// fail-closed disjunctions: every state the relaxed-gate
    /// fail-closed disjunction admits, the strict-gate fail-closed
    /// disjunction also admits — the contrapositive of the
    /// strict ⇒ relaxed admission ordering pinned at commit e6810b2's
    /// `test_compose_admission_eligible_strict_implies_compose_admission_eligible_relaxed`.
    /// Equivalently:
    /// `compose_is_all_no_evidence_or_saturated(p, v) =>
    ///  compose_is_incomplete_or_saturated(p, v)`
    /// because the relaxed-gate floor `compose_is_all_no_evidence` is
    /// strictly stronger than the strict-gate floor
    /// `!compose_is_fully_complete` (every state with no positive
    /// evidence anywhere is also a state with at least one axis not
    /// fully complete — the all-absent axis is not fully covered), and
    /// the saturation disjunct is shared verbatim between both tiers.
    /// The dual implication does NOT hold: the strict-gate fail-closed
    /// disjunction admits the mixed-evidence state
    /// `({ran: 3, absent: 4}, {verified: 2, unverified: 3})` (the
    /// completeness factor is broken) while the relaxed-gate
    /// fail-closed disjunction refuses it (positive evidence on both
    /// axes AND no saturation). Pinning this ordering forecloses the
    /// drift class where a regression to either tier-level helper
    /// would silently invert the ordering at the fail-closed surface,
    /// breaking the structural witness the two-tier admission decision
    /// surface (Phase 1 relaxed → Phase 2 strict) relies on.
    #[test]
    fn test_compose_is_all_no_evidence_or_saturated_implies_compose_is_incomplete_or_saturated() {
        let probe_cases = [
            ProbeCoverage { ran: 0, absent: 0 },
            ProbeCoverage { ran: 0, absent: 3 },
            ProbeCoverage { ran: 2, absent: 4 },
            ProbeCoverage { ran: 7, absent: 0 },
            ProbeCoverage {
                ran: usize::MAX,
                absent: 0,
            },
            ProbeCoverage {
                ran: 0,
                absent: usize::MAX,
            },
        ];
        let verification_cases = [
            VerificationCoverage {
                verified: 0,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 0,
                unverified: 3,
            },
            VerificationCoverage {
                verified: 1,
                unverified: 2,
            },
            VerificationCoverage {
                verified: 5,
                unverified: 0,
            },
            VerificationCoverage {
                verified: usize::MAX,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 0,
                unverified: usize::MAX,
            },
        ];
        let mut saw_strict_only_fail_closed = false;
        for probe in probe_cases {
            for verification in verification_cases {
                let relaxed_fail_closed =
                    compose_is_all_no_evidence_or_saturated(&probe, &verification);
                let strict_fail_closed = compose_is_incomplete_or_saturated(&probe, &verification);
                if relaxed_fail_closed {
                    assert!(
                        strict_fail_closed,
                        "relaxed-gate fail-closed must imply \
                         strict-gate fail-closed at probe={probe:?} \
                         verification={verification:?} — the \
                         contrapositive of the strict ⇒ relaxed \
                         admission ordering pinned at \
                         test_compose_admission_eligible_strict_implies_compose_admission_eligible_relaxed",
                    );
                }
                if strict_fail_closed && !relaxed_fail_closed {
                    saw_strict_only_fail_closed = true;
                }
            }
        }
        assert!(
            saw_strict_only_fail_closed,
            "test corpus must surface at least one state where the \
             strict-gate fail-closed disjunction admits but the \
             relaxed-gate fail-closed disjunction refuses (the \
             mixed-evidence partial-completeness state \
             `((ran: 2, absent: 4), (verified: 1, unverified: 2))` is \
             the structural witness the dual implication does NOT hold)",
        );

        let mixed_probe = ProbeCoverage { ran: 2, absent: 4 };
        let mixed_verification = VerificationCoverage {
            verified: 1,
            unverified: 2,
        };
        assert!(
            compose_is_incomplete_or_saturated(&mixed_probe, &mixed_verification),
            "mixed-evidence partial-completeness state must read `true` \
             through the strict-gate fail-closed disjunction (the \
             completeness factor is broken on both axes)",
        );
        assert!(
            !compose_is_all_no_evidence_or_saturated(&mixed_probe, &mixed_verification),
            "mixed-evidence partial-completeness state must read \
             `false` through the relaxed-gate fail-closed disjunction \
             (positive evidence on both axes AND no saturation \
             anywhere — the load-bearing structural witness the \
             strict-gate floor is strictly weaker than the relaxed-\
             gate floor)",
        );
    }

    /// Pins the saturation-robust reading at the two named saturation
    /// arms across both axes. The `{ran: usize::MAX, absent: 0}` /
    /// `{verified: usize::MAX, unverified: 0}` saturated-fully-evidenced
    /// arms — where the strict gate refuses through the trustworthiness
    /// clamp even though the completeness factor reads `true` honestly
    /// — must read `true` through the second disjunct (the saturation
    /// ceiling) while the first disjunct (`!compose_is_fully_complete`)
    /// reads `false` (the structural witness the trustworthiness clamp
    /// is the strict gate's load-bearing failure mode at the saturated-
    /// fully-evidenced arm, not the completeness factor). The
    /// `{ran: 0, absent: usize::MAX}` / `{verified: 0, unverified:
    ///  usize::MAX}` saturated-all-absent / saturated-all-unverified
    /// arms must read `true` through BOTH disjuncts independently. The
    /// structural peer of
    /// `test_compose_is_all_no_evidence_or_saturated_stays_robust_at_saturated_states`
    /// at the strict tier.
    #[test]
    fn test_compose_is_incomplete_or_saturated_stays_robust_at_saturated_states() {
        let probe_saturated_evidence = ProbeCoverage {
            ran: usize::MAX,
            absent: 0,
        };
        let verification_saturated_evidence = VerificationCoverage {
            verified: usize::MAX,
            unverified: 0,
        };
        assert!(
            compose_is_incomplete_or_saturated(
                &probe_saturated_evidence,
                &verification_saturated_evidence,
            ),
            "saturated-fully-evidenced both axes must read `true` — the \
             trustworthiness clamp `compose_is_saturated` surfaces \
             `true` honestly through the second disjunct even though \
             the completeness factor `compose_is_fully_complete` reads \
             `true` here (the load-bearing structural witness the \
             strict-gate trustworthiness clamp is the failure mode at \
             the saturated-fully-evidenced arm)",
        );
        assert!(
            compose_is_fully_complete(&probe_saturated_evidence, &verification_saturated_evidence,),
            "saturated-fully-evidenced both axes must read \
             `compose_is_fully_complete == true` — the completeness \
             factor reads `is_fully_covered / is_fully_verified` \
             honestly through the `absent == 0 && unverified == 0` \
             factor at the saturated-fully-evidenced arm (the \
             structural witness the first disjunct of \
             `compose_is_incomplete_or_saturated` does NOT surface \
             `true` here, so the second disjunct \
             `compose_is_saturated` is load-bearing)",
        );

        let verification_non_saturated_evidence = VerificationCoverage {
            verified: 3,
            unverified: 0,
        };
        assert!(
            compose_is_incomplete_or_saturated(
                &probe_saturated_evidence,
                &verification_non_saturated_evidence,
            ),
            "one-axis-saturated-evidenced must read `true` — the \
             saturation disjunct admits through the saturated probe \
             axis even though the verification axis is fully-covered \
             trustworthy",
        );

        let probe_saturated_no_evidence = ProbeCoverage {
            ran: 0,
            absent: usize::MAX,
        };
        let verification_saturated_no_evidence = VerificationCoverage {
            verified: 0,
            unverified: usize::MAX,
        };
        assert!(
            compose_is_incomplete_or_saturated(
                &probe_saturated_no_evidence,
                &verification_saturated_no_evidence,
            ),
            "saturated-all-absent / saturated-all-unverified both axes \
             must read `true` — both disjuncts independently surface \
             `true` (!compose_is_fully_complete because absent / \
             unverified == usize::MAX implies not fully covered / \
             verified, compose_is_saturated because absent / \
             unverified == usize::MAX), the load-bearing both-disjuncts-\
             surface arm",
        );

        let probe_strict_eligible = ProbeCoverage { ran: 3, absent: 0 };
        let verification_strict_eligible = VerificationCoverage {
            verified: 2,
            unverified: 0,
        };
        assert!(
            !compose_is_incomplete_or_saturated(
                &probe_strict_eligible,
                &verification_strict_eligible,
            ),
            "fully-evidenced non-saturated both axes must read `false` \
             — neither disjunct surfaces `true` (completeness on both \
             axes AND no saturation anywhere is the strict-eligible \
             state the gate admits, the structural witness the De \
             Morgan equivalence with !compose_admission_eligible_strict \
             pins)",
        );
    }

    /// Pins the positive band reading at every state where the relaxed
    /// gate admits and the strict gate refuses — the staging-only
    /// partial-progress band. Covers the cross product of the
    /// representative per-axis evidenced-incomplete arms (mixed
    /// `(ran > 0, absent > 0)` / mixed `(verified > 0, unverified > 0)`)
    /// against the representative per-axis fully-evidenced arms on the
    /// opposite axis, plus the symmetric one-axis-incomplete-other-axis-
    /// fully-evidenced arms. Every combination must read `true`,
    /// pinning the structural witness the staging-only band carries a
    /// typed name at the parallel-axis surface for the load-bearing
    /// partial-progress state where the deploy orchestrator advances to
    /// staging but holds before production.
    #[test]
    fn test_compose_relaxed_eligible_strict_refused_at_partial_progress_arms_is_true() {
        let probe_mixed_evidence = ProbeCoverage { ran: 2, absent: 3 };
        let probe_fully_covered = ProbeCoverage { ran: 4, absent: 0 };
        let verification_mixed_evidence = VerificationCoverage {
            verified: 1,
            unverified: 2,
        };
        let verification_fully_verified = VerificationCoverage {
            verified: 5,
            unverified: 0,
        };

        let partial_progress_pairs = [
            (probe_mixed_evidence, verification_mixed_evidence),
            (probe_mixed_evidence, verification_fully_verified),
            (probe_fully_covered, verification_mixed_evidence),
        ];
        for (probe, verification) in partial_progress_pairs {
            assert!(
                compose_relaxed_eligible_strict_refused(&probe, &verification),
                "staging-only band must admit at probe={probe:?} \
                 verification={verification:?} — relaxed gate admits \
                 (evidence on at least one axis AND trust intact on both) \
                 AND strict gate refuses (incomplete on at least one \
                 axis), the load-bearing partial-progress state the \
                 two-tier admission gate establishes",
            );
            assert!(
                compose_admission_eligible_relaxed(&probe, &verification),
                "relaxed gate must admit the staging-only state at \
                 probe={probe:?} verification={verification:?} — \
                 structural sanity check the band sits inside the \
                 relaxed-admitted set",
            );
            assert!(
                !compose_admission_eligible_strict(&probe, &verification),
                "strict gate must refuse the staging-only state at \
                 probe={probe:?} verification={verification:?} — \
                 structural sanity check the band sits outside the \
                 strict-admitted subset",
            );
        }
    }

    /// Pins the rejection reading at every strict-eligible state — the
    /// production-ready states the strict gate admits must read `false`
    /// through the staging-only band (they are production-eligible, NOT
    /// staging-only). Covers the cross product of the three per-axis
    /// fully-covered probe representatives × three per-axis fully-
    /// verified verification representatives. Forecloses the drift
    /// class where a regression that swapped the inner negation
    /// (`!compose_admission_eligible_strict` → `compose_admission_
    /// eligible_strict`) would silently classify the production-ready
    /// state as staging-only, flattening the structural distinction
    /// between the two admission tiers.
    #[test]
    fn test_compose_relaxed_eligible_strict_refused_at_strict_eligible_states_is_false() {
        let probe_fully_covered_honest = [
            ProbeCoverage { ran: 1, absent: 0 },
            ProbeCoverage { ran: 7, absent: 0 },
            ProbeCoverage {
                ran: usize::MAX - 1,
                absent: 0,
            },
        ];
        let verification_fully_verified_honest = [
            VerificationCoverage {
                verified: 1,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 5,
                unverified: 0,
            },
            VerificationCoverage {
                verified: usize::MAX - 1,
                unverified: 0,
            },
        ];
        for probe in probe_fully_covered_honest {
            for verification in verification_fully_verified_honest {
                assert!(
                    !compose_relaxed_eligible_strict_refused(&probe, &verification),
                    "staging-only band must refuse the strict-eligible \
                     state at probe={probe:?} verification={verification:?} \
                     — production-ready states sit in the strict-admitted \
                     subset (promote to production), NOT in the staging-\
                     only band (hold at staging), the structural witness \
                     the band excludes the strict-admitted subset",
                );
            }
        }
    }

    /// Pins the rejection reading at every both-axes no-evidence state
    /// — the relaxed-tier fail-closed floor must read `false` through
    /// the staging-only band (they are refused, NOT staging-only).
    /// Covers the cross product of the two per-axis no-evidence arms
    /// (`is_empty` at `(0, 0)`, `is_all_absent` / `is_all_unverified`
    /// at `(0, N>0)`) on each axis. Forecloses the drift class where a
    /// regression that hand-rolled the band as `!compose_admission_
    /// eligible_strict` alone (dropping the relaxed-admitted floor)
    /// would silently classify the both-axes no-evidence floor as
    /// staging-only, flattening the relaxed-tier admission floor.
    #[test]
    fn test_compose_relaxed_eligible_strict_refused_at_no_evidence_floor_is_false() {
        let probe_empty = ProbeCoverage { ran: 0, absent: 0 };
        let probe_all_absent = ProbeCoverage { ran: 0, absent: 4 };
        let verification_empty = VerificationCoverage {
            verified: 0,
            unverified: 0,
        };
        let verification_all_unverified = VerificationCoverage {
            verified: 0,
            unverified: 6,
        };
        for probe in [probe_empty, probe_all_absent] {
            for verification in [verification_empty, verification_all_unverified] {
                assert!(
                    !compose_relaxed_eligible_strict_refused(&probe, &verification),
                    "staging-only band must refuse the both-axes no-\
                     evidence floor at probe={probe:?} \
                     verification={verification:?} — the relaxed gate \
                     refuses (no evidence on either axis), so the band \
                     reads `false` honestly through the conjunction's \
                     first factor, the structural witness the band sits \
                     inside the relaxed-admitted set",
                );
            }
        }
    }

    /// Pins the rejection reading at every saturated state — the
    /// trustworthiness-broken states must read `false` through the
    /// staging-only band (they are refused, NOT staging-only). The
    /// relaxed gate's saturation clamp forecloses every saturated state
    /// from admission regardless of completeness; this test pins that
    /// the staging-only band inherits the clamp honestly. Critically
    /// pins the saturated-fully-evidenced arm `({ran: usize::MAX,
    /// absent: 0}, {verified: usize::MAX, unverified: 0})` where the
    /// completeness factor reads `true` — a regression that hand-rolled
    /// the band as `compose_has_evidence && !compose_is_fully_complete`
    /// (dropping the trust-intact factor) would silently misclassify
    /// the saturated-completed state as staging-only. The saturated-
    /// incomplete arms must also read `false` — the saturation clamp
    /// applies BEFORE the completeness factor is consulted.
    #[test]
    fn test_compose_relaxed_eligible_strict_refused_at_saturated_states_is_false() {
        let probe_saturated_evidence = ProbeCoverage {
            ran: usize::MAX,
            absent: 0,
        };
        let probe_saturated_no_evidence = ProbeCoverage {
            ran: 0,
            absent: usize::MAX,
        };
        let verification_saturated_evidence = VerificationCoverage {
            verified: usize::MAX,
            unverified: 0,
        };
        let verification_saturated_no_evidence = VerificationCoverage {
            verified: 0,
            unverified: usize::MAX,
        };
        let probe_evidenced_non_saturated = ProbeCoverage { ran: 3, absent: 2 };
        let verification_evidenced_non_saturated = VerificationCoverage {
            verified: 2,
            unverified: 3,
        };

        let saturated_pairs = [
            (probe_saturated_evidence, verification_saturated_evidence),
            (probe_saturated_evidence, verification_saturated_no_evidence),
            (probe_saturated_no_evidence, verification_saturated_evidence),
            (
                probe_saturated_no_evidence,
                verification_saturated_no_evidence,
            ),
            (
                probe_saturated_evidence,
                verification_evidenced_non_saturated,
            ),
            (
                probe_evidenced_non_saturated,
                verification_saturated_evidence,
            ),
            (
                probe_saturated_no_evidence,
                verification_evidenced_non_saturated,
            ),
            (
                probe_evidenced_non_saturated,
                verification_saturated_no_evidence,
            ),
        ];
        for (probe, verification) in saturated_pairs {
            assert!(
                !compose_relaxed_eligible_strict_refused(&probe, &verification),
                "staging-only band must refuse the saturated state at \
                 probe={probe:?} verification={verification:?} — the \
                 relaxed gate's trustworthiness clamp foreclosed the \
                 admission floor, so the band reads `false` honestly \
                 through the conjunction's first factor; a regression \
                 that dropped the trust-intact factor would silently \
                 misclassify the saturated state as staging-only",
            );
        }
    }

    /// Pins the load-bearing structural equivalence with the documented
    /// two-helper conjunction across the cross product of representative
    /// per-axis arms (empty, all-absent / all-unverified, mixed-evidence,
    /// fully-covered / fully-verified, both saturated polarities). The
    /// structural drift class this pin forecloses: a regression that
    /// re-wrote the body as the symmetric difference
    /// `compose_admission_eligible_relaxed(p, v) ^
    ///  compose_admission_eligible_strict(p, v)` would pass the smoke
    /// tests for the strict-eligible subset (the strict-relaxed AND
    /// reduces to strict, the symmetric difference reads `false`) but
    /// fail at the refused subset (the conjunction reads `false`, the
    /// symmetric difference reads `false` — both are equivalent at the
    /// refused subset by accident); this exhaustive cross product pins
    /// the equivalence at every reachable arm not just the smoke arms.
    #[test]
    fn test_compose_relaxed_eligible_strict_refused_equals_documented_composition() {
        let probe_reps = [
            ProbeCoverage { ran: 0, absent: 0 },
            ProbeCoverage { ran: 0, absent: 4 },
            ProbeCoverage { ran: 2, absent: 3 },
            ProbeCoverage { ran: 7, absent: 0 },
            ProbeCoverage {
                ran: usize::MAX,
                absent: 0,
            },
            ProbeCoverage {
                ran: 0,
                absent: usize::MAX,
            },
        ];
        let verification_reps = [
            VerificationCoverage {
                verified: 0,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 0,
                unverified: 6,
            },
            VerificationCoverage {
                verified: 1,
                unverified: 2,
            },
            VerificationCoverage {
                verified: 5,
                unverified: 0,
            },
            VerificationCoverage {
                verified: usize::MAX,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 0,
                unverified: usize::MAX,
            },
        ];
        for probe in probe_reps {
            for verification in verification_reps {
                let documented = compose_admission_eligible_relaxed(&probe, &verification)
                    && !compose_admission_eligible_strict(&probe, &verification);
                assert_eq!(
                    compose_relaxed_eligible_strict_refused(&probe, &verification),
                    documented,
                    "compose_relaxed_eligible_strict_refused must equal \
                     the two-helper conjunction `compose_admission_\
                     eligible_relaxed(p, v) && !compose_admission_\
                     eligible_strict(p, v)` at probe={probe:?} \
                     verification={verification:?}",
                );
            }
        }
    }

    /// Pins the equivalent three-factor decomposition the staging-only
    /// band collapses to within the trust-intact admission space:
    /// `compose_relaxed_eligible_strict_refused(p, v) ==
    ///  compose_has_evidence(p, v) && !compose_is_saturated(p, v) &&
    ///  !compose_is_fully_complete(p, v)`. The disjunctive disjunct of
    /// the strict-refuse predicate (`compose_is_saturated`) is
    /// foreclosed by the relaxed gate's trustworthiness clamp, so the
    /// band reduces to the incompleteness factor alone within the
    /// relaxed-admitted subset. Forecloses the drift class where a
    /// regression that hand-rolled the band as the two-factor
    /// `compose_has_evidence && !compose_is_fully_complete` (dropping
    /// the trust-intact factor) would silently misclassify the
    /// saturated-completed state as staging-only.
    #[test]
    fn test_compose_relaxed_eligible_strict_refused_decomposes_into_three_factors() {
        let probe_reps = [
            ProbeCoverage { ran: 0, absent: 0 },
            ProbeCoverage { ran: 0, absent: 4 },
            ProbeCoverage { ran: 2, absent: 3 },
            ProbeCoverage { ran: 7, absent: 0 },
            ProbeCoverage {
                ran: usize::MAX,
                absent: 0,
            },
            ProbeCoverage {
                ran: 0,
                absent: usize::MAX,
            },
        ];
        let verification_reps = [
            VerificationCoverage {
                verified: 0,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 0,
                unverified: 6,
            },
            VerificationCoverage {
                verified: 1,
                unverified: 2,
            },
            VerificationCoverage {
                verified: 5,
                unverified: 0,
            },
            VerificationCoverage {
                verified: usize::MAX,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 0,
                unverified: usize::MAX,
            },
        ];
        for probe in probe_reps {
            for verification in verification_reps {
                let three_factor = compose_has_evidence(&probe, &verification)
                    && !compose_is_saturated(&probe, &verification)
                    && !compose_is_fully_complete(&probe, &verification);
                assert_eq!(
                    compose_relaxed_eligible_strict_refused(&probe, &verification),
                    three_factor,
                    "compose_relaxed_eligible_strict_refused must equal \
                     the three-factor decomposition `compose_has_evidence \
                     && !compose_is_saturated && !compose_is_fully_complete` \
                     at probe={probe:?} verification={verification:?} — \
                     the load-bearing structural equivalence the relaxed \
                     gate's trustworthiness clamp establishes by \
                     collapsing the disjunctive disjunct of the strict-\
                     refuse predicate within the relaxed-admitted subset",
                );
            }
        }
    }

    /// Pins the load-bearing disjoint three-way partition the two-tier
    /// admission gate establishes: every reachable `(probe,
    /// verification)` pair satisfies exactly one of
    /// `compose_admission_eligible_strict`,
    /// `compose_relaxed_eligible_strict_refused`,
    /// `!compose_admission_eligible_relaxed` — the production-eligible
    /// / staging-only / refused tier-decomposition the typed-primitive
    /// surface seals at one site. Forecloses the drift class where a
    /// regression that broke any one of the three predicates would
    /// silently break the disjoint cover (e.g., a regression that
    /// broke the staging-only band's first factor would surface a state
    /// classified as both refused AND staging-only, OR neither). The
    /// XOR (exclusive-or) reading is the load-bearing structural pin —
    /// a downstream deploy orchestrator branching on the admission
    /// tier relies on the disjoint cover to avoid a nested if-else
    /// cascade that would inherit a drift class on the day a third
    /// tier is added.
    #[test]
    fn test_compose_admission_three_way_partition_covers_every_state() {
        let probe_reps = [
            ProbeCoverage { ran: 0, absent: 0 },
            ProbeCoverage { ran: 0, absent: 4 },
            ProbeCoverage { ran: 2, absent: 3 },
            ProbeCoverage { ran: 7, absent: 0 },
            ProbeCoverage {
                ran: usize::MAX,
                absent: 0,
            },
            ProbeCoverage {
                ran: 0,
                absent: usize::MAX,
            },
        ];
        let verification_reps = [
            VerificationCoverage {
                verified: 0,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 0,
                unverified: 6,
            },
            VerificationCoverage {
                verified: 1,
                unverified: 2,
            },
            VerificationCoverage {
                verified: 5,
                unverified: 0,
            },
            VerificationCoverage {
                verified: usize::MAX,
                unverified: 0,
            },
            VerificationCoverage {
                verified: 0,
                unverified: usize::MAX,
            },
        ];
        for probe in probe_reps {
            for verification in verification_reps {
                let strict_eligible = compose_admission_eligible_strict(&probe, &verification);
                let staging_only = compose_relaxed_eligible_strict_refused(&probe, &verification);
                let refused = !compose_admission_eligible_relaxed(&probe, &verification);
                let exactly_one = (strict_eligible as u8) + (staging_only as u8) + (refused as u8);
                assert_eq!(
                    exactly_one, 1,
                    "the three-way admission partition must cover every \
                     state exactly once at probe={probe:?} \
                     verification={verification:?} — \
                     strict_eligible={strict_eligible}, \
                     staging_only={staging_only}, refused={refused}; \
                     the disjoint-union structure is the load-bearing \
                     structural pin the deploy orchestrator's tier-\
                     branching surface relies on",
                );
            }
        }
    }
}
