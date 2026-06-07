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
    /// [`coverage_ratio`]: ProbeCoverage::coverage_ratio
    pub fn total(&self) -> usize {
        self.ran + self.absent
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
}
