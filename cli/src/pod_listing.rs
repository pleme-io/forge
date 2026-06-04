//! Typed Kubernetes pod-listing count probe outcome for forge's Phase 2
//! deployment attestation — the pod-count peer of
//! [`crate::pod_health`] (pod-Ready / pod-phase probe, commit e76db87),
//! [`crate::helm_release_signature`] (HelmRelease-signature probe),
//! [`crate::network_policy_admission`] (network-segmentation probe),
//! [`crate::flux_source_verification`] (FluxCD source-verification probe),
//! [`crate::cosign`] (image-signature probe),
//! [`crate::helm_provenance`] (chart-signature probe),
//! [`crate::helm_lint`] (chart-quality probe),
//! [`crate::kensa_policy`] (chart-policy probe),
//! [`crate::git_signature`] (source-commit-signature probe),
//! [`crate::nix_reproducibility`] (build-determinism probe),
//! [`crate::oci_architecture`] (image-architecture probe),
//! [`crate::oci_manifest`] (manifest-identity oracle),
//! [`crate::openpgp_signature`] (OpenPGP v4 signature packet parser),
//! [`crate::security_scan`] (SBOM / vuln-scan probes), and
//! [`crate::deployment_manifest`] (rendered-manifest fingerprint).
//!
//! ## What this module closes
//!
//! `commands/attestation.rs::compose_product_certification` previously
//! stamped a literal `0` into every Phase 2 `DeploymentAttestation`'s
//! `running_pods` field:
//!
//! ```ignore
//! let deployment = DeploymentAttestation {
//!     namespace: format!("{}-{}", product, environment),
//!     ...
//!     running_pods: 0,                                       // <-- this line
//!     all_healthy: pod_health_outcome.is_healthy(),
//! };
//! ```
//!
//! The usize surface is honest for the no-probe-ran world (a Phase 2
//! deployment attestation that records `running_pods: 0` against a
//! certification function that never spawned a `kubectl get pods` probe
//! is correctly zero — no evidence was collected), but flattens two
//! structurally distinct operational worlds — `Counted { count: 0 }`
//! (probe RAN against an empty namespace and observed zero pods) and
//! `ProbeAbsent` (no probe ran inside the certification function) — into
//! a single zero a downstream verifier cannot recover the kind-of-claim
//! from. The `Counted { count: 0 }` collapse is the load-bearing
//! discriminator loss: a Phase 2 deployment attestation that records
//! `running_pods: 0` against a namespace whose `kubectl get pods -n <ns>
//! -o json` probe RAN and observed an empty `PodList.items` array
//! (evidence of a rollout whose workloads have not yet been scheduled,
//! or a deployment step that admitted the `HelmRelease` without ever
//! materialising any `Pod` — the structural failure THEORY §V.4 Phase 2
//! names as the post-admission honesty channel) is structurally
//! indistinguishable from one against a namespace whose probe was never
//! spawned (no evidence either way). A downstream `sekiban` strict-
//! production policy that fails-closed on evidence of an empty
//! deployment (probe ran AND running_pods == 0 — a Phase 2 record that
//! the cluster admitted the release but never materialised any
//! workloads, the load-bearing failure for a rollout that hit no-pod
//! limits or crashed every replica before the readiness probe could
//! observe) cannot express that gate against the pre-fix bare usize —
//! every Phase 2 record asserts the same zero regardless of whether
//! `kubectl get pods` substantiated an empty-namespace state or whether
//! it simply never ran. The typed primitive closes the gap the same way
//! commits e76db87 / 8b1407d / f8a5d8e / 5931e32 / 72424bd / c1e83d5 /
//! d81f639 / 2f3a7dc / b98eb5a / fffca30 / b8a1d8a / 0ff67e1 / e8a2df7
//! / 443bd22 / 9c5a99f / a5376a6 / 5baaa50 / 36d90b6 closed sibling
//! Phase 1 and Phase 2 gaps one shape away: a typed outcome enum over
//! the operational worlds a downstream probe could report, the probe-
//! evidence claim computed by the typed primitive over the typed shape,
//! and the every-arm distinction preserved structurally so a downstream
//! verifier recovers the kind-of-claim from the value alone.
//!
//! ## The two operational worlds
//!
//! A Kubernetes pod-listing count probe (the `Pod` resources covering a
//! namespace's deployed workloads, queried by `kubectl get pods -n <ns>
//! -o json` or by a typed `kube::Api::<Pod>::list(...)` query, with the
//! resulting `PodList.items.len()` collected) distinguishes two
//! operational worlds the prior `0` hardcode flattened into a single
//! claim:
//!
//! 1. **Probe absent** — `compose_product_certification` did not query
//!    the cluster at all, or the certification function ran outside the
//!    cluster (e.g. an integration-test path that constructed the
//!    deployment attestation directly without going through a `kubectl
//!    get pods` probe). No probe ran. There is no evidence either way.
//!    The prior `0` hardcode reported a zero pod count against this
//!    state every time — including for namespaces whose pod set was in
//!    fact non-empty.
//! 2. **Counted** — the probe ran and the namespace's pod set has been
//!    enumerated: `PodList.items.len()` is the count carried by the
//!    arm's `count: usize` field. The count may itself be zero (the
//!    namespace truly is empty — the probe ran and observed zero `Pod`
//!    resources) or any positive integer; the structural distinction
//!    from `ProbeAbsent` is that a probe RAN and produced evidence,
//!    regardless of the magnitude that evidence reports. A namespace
//!    with `count: 0` is the load-bearing discriminator: a downstream
//!    verifier reading the typed outcome can distinguish "probe ran and
//!    namespace is empty" (evidence-of-empty-deployment, a Phase 2
//!    failure mode THEORY §V.4 / §VII.1 name as post-admission honesty
//!    that the rollout never materialised any workloads) from "no probe
//!    ran" (no evidence), where the pre-fix bare usize flattened them
//!    indistinguishably into `0`.
//!
//! ## Why two arms, not three
//!
//! Unlike [`crate::pod_health::PodHealthOutcome`] (three arms: `Healthy`
//! / `UnhealthyPods` / `ProbeAbsent`) one layer over, the pod-listing
//! count world has no positive-vs-negative-evidence axis the count itself
//! does not already carry. A probed namespace has `count: N` for some
//! `N: usize`; the count IS the evidence, with `count: 0` carrying the
//! evidence-of-empty-deployment claim a third arm would have named
//! redundantly. Splitting `Counted { count: 0 }` from `Counted { count:
//! 1.. }` would force every consumer to reassemble the count from a
//! match arm without surfacing a structural distinction the call site
//! does not already recover from the bare `count` field. Same shape
//! discipline as [`crate::deployment_manifest::
//! DeploymentManifestRenderOutcome`] (three arms because `Rendered`
//! carries a structurally distinct fingerprint surface from `RenderFailed`
//! AND `ProbeAbsent`) and [`crate::compliance_dimensions`] (no enum
//! arms because the fingerprint IS the canonical surface and no `Probe
//! absent` world exists at the dimensions layer).
//!
//! ## What this commit does NOT do
//!
//! This commit introduces the typed primitive and routes the call site
//! through the `ProbeAbsent` arm: `compose_product_certification` does
//! not yet spawn a Kubernetes `Pod` listing probe itself. The Phase 2
//! deployment attestation continues to record `running_pods: 0`, but now
//! records it through the typed `PodListingOutcome::ProbeAbsent.
//! running_pods()` expression — honestly naming "no pod-listing probe
//! ran inside the certification function" rather than asserting a single
//! zero that a probe-detected empty-namespace state would have also
//! produced. The `Counted { count }` arm is the future enrichment point:
//! a follow-up commit that wires `tokio::process::Command::new("kubectl")
//! .args(["get", "pods", "-n", &namespace, "-o", "json"]).output().await`
//! (or a typed `kube::Api::<Pod>::list(...)` query against
//! `ListParams::default()`) at the call site and walks the resulting
//! `PodList.items.len()` will flip the call-site outcome to `Counted {
//! count }` with the cluster-observed value. Same deferral shape as
//! commit e76db87's [`crate::pod_health::PodHealthOutcome::ProbeAbsent`]
//! arm at the pod-readiness layer (the sibling probe at the same kubectl
//! shell-out — a follow-up that wires the kubectl probe at the call
//! site can populate BOTH the `running_pods` count AND the `all_healthy`
//! claim from the same `PodList` walk).
//!
//! ## Frontier inspiration
//!
//! THEORY §V.4 ("Two-phase signature composition") and §VII.1
//! ("Attestation-gated deployments") name the Phase 2 deployment record
//! as the post-admission honesty channel: the structural evidence that
//! the deployment actually landed workloads in the cluster the pre-
//! Phase-2 Phase 1 signatures were composed against. Kubernetes' `Pod`
//! resource carries that evidence in `PodList.items` — every `Pod`
//! materialised under a `Deployment`, `StatefulSet`, `DaemonSet`, or
//! bare `Pod` spec admitted into the namespace. A Phase 2 deployment
//! attestation that records `running_pods: 0` against a namespace whose
//! `Pod` resources were never queried fails every reconciliation a
//! `sekiban admission audit` pass could surface against the same
//! cluster state. The typed `ProbeAbsent` arm names that gap honestly
//! rather than flattening it with a constant — the same discipline
//! [`crate::pod_health::PodHealthOutcome::ProbeAbsent`],
//! [`crate::helm_release_signature::HelmReleaseSignatureOutcome::
//! ProbeAbsent`], [`crate::network_policy_admission::
//! NetworkPolicyAdmissionOutcome::ProbeAbsent`],
//! [`crate::flux_source_verification::FluxSourceVerificationOutcome::
//! ProbeAbsent`], [`crate::cosign::CosignVerifyOutcome::ProbeAbsent`],
//! [`crate::helm_provenance::HelmProvenanceOutcome::ProbeAbsent`],
//! [`crate::helm_lint::HelmLintOutcome::ProbeAbsent`],
//! [`crate::kensa_policy::KensaPolicyOutcome::ProbeAbsent`],
//! [`crate::git_signature::GitCommitSignatureOutcome::ProbeAbsent`],
//! [`crate::nix_reproducibility::NixReproducibilityOutcome::
//! ProbeAbsent`], [`crate::security_scan::SbomProbeOutcome::Absent`],
//! and [`crate::security_scan::VulnScanProbeOutcome::Absent`] apply at
//! the pod-readiness, HelmRelease-signature, network-segmentation,
//! source-verification, image-signature, chart-signature, chart-quality,
//! chart-policy, source-commit-signature, build-determinism, SBOM, and
//! vuln-scan layers. The pod-count probe is the natural companion of the
//! pod-readiness probe at the same `PodList.items` walk: a single
//! follow-up that wires `kube::Api::<Pod>::list(...)` at the call site
//! populates both the `running_pods` count AND the `all_healthy` claim
//! from the same response.

/// Outcome of probing a namespace's Kubernetes `Pod` listing for the
/// running-pod count — the Phase 2 `running_pods` claim. The two arms
/// preserve the probe-absent vs probed distinction the Phase 2
/// deployment attestation depends on; the prior `0` hardcode conflated
/// no-probe-ran with probed-empty-namespace into a single zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PodListingOutcome {
    /// Kubernetes pod-listing probe ran and the namespace's
    /// `PodList.items.len()` was collected. `count` is the cluster-
    /// observed running-pod count, which may itself be zero (the
    /// namespace truly is empty — probe ran and observed zero `Pod`
    /// resources) or any positive integer. The structural distinction
    /// from `ProbeAbsent` is that a probe RAN and produced evidence,
    /// regardless of the magnitude that evidence reports. A downstream
    /// `sekiban` strict-production policy that fails-closed on
    /// evidence of an empty deployment can express that gate against
    /// `Counted { count: 0 }`, where the pre-fix bare usize flattened
    /// it indistinguishably into `ProbeAbsent`.
    Counted { count: usize },
    /// `compose_product_certification` did not query the cluster at all
    /// (no `kubectl get pods` shell-out, no typed
    /// `kube::Api::<Pod>::list(...)` query), or the certification
    /// function ran outside the cluster (e.g. an integration-test path
    /// that constructed the deployment attestation directly without
    /// going through a kubectl probe). No probe was made; no evidence
    /// was collected. The prior `0` hardcode reported the same value
    /// here as for the `Counted { count: 0 }` arm, conflating "no
    /// kubectl probe ran" with "probe ran and the namespace is empty".
    ProbeAbsent,
}

impl PodListingOutcome {
    /// The `usize` the Phase 2 deployment attestation's `running_pods`
    /// field carries. `Counted { count }` passes the cluster-observed
    /// count through; `ProbeAbsent` collapses to `0`, matching the
    /// pre-fix bare-usize semantics exactly at the surface level while
    /// preserving the structural discriminator the bare usize erased.
    pub fn running_pods(&self) -> usize {
        match self {
            Self::Counted { count } => *count,
            Self::ProbeAbsent => 0,
        }
    }
}

crate::impl_probe_outcome!(PodListingOutcome, ProbeAbsent);

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the two-arm `running_pods` collapse table. `Counted { count
    /// }` passes the count through unchanged for every value in the
    /// `usize` domain a `PodList.items.len()` could yield; `ProbeAbsent`
    /// collapses to `0`. Same shape as `test_is_healthy_pins_all_arms`
    /// for [`crate::pod_health::PodHealthOutcome`] one layer over.
    #[test]
    fn test_running_pods_pins_all_arms() {
        assert_eq!(PodListingOutcome::ProbeAbsent.running_pods(), 0);
        assert_eq!(
            PodListingOutcome::Counted { count: 0 }.running_pods(),
            0,
            "Counted{{count: 0}} must pass through unchanged — the \
             probe ran and the namespace is empty, structurally \
             distinct from ProbeAbsent even though both surface as 0",
        );
        assert_eq!(PodListingOutcome::Counted { count: 1 }.running_pods(), 1);
        assert_eq!(PodListingOutcome::Counted { count: 42 }.running_pods(), 42);
        assert_eq!(
            PodListingOutcome::Counted { count: usize::MAX }.running_pods(),
            usize::MAX,
            "Counted must passthrough the full usize domain; a future \
             refactor that introduced an arithmetic transform (cap, \
             saturating cast, downcast to u32) would fail this pin",
        );
    }

    /// `ProbeAbsent` collapses to `running_pods == 0` — the load-bearing
    /// honesty invariant the call site rests on. The pre-fix call site
    /// stamped `0` regardless of whether the cluster had been probed;
    /// the typed primitive routes through `running_pods()` which returns
    /// `0` here. The surface value is the same, but the structural shape
    /// carries the discriminator the pre-fix literal erased — a
    /// downstream verifier reading `running_pods: 0` from a Phase 2
    /// deployment attestation can recover "no pod-listing probe ran
    /// inside the certification function" as one of the two possible
    /// kind-of-claims, where the pre-fix `0` conflated it indistinguishably
    /// with the probed-empty-namespace arm.
    #[test]
    fn test_probe_absent_collapses_to_zero() {
        assert_eq!(
            PodListingOutcome::ProbeAbsent.running_pods(),
            0,
            "ProbeAbsent must collapse to running_pods=0; the pre-fix \
             `0` hardcode flattened this no-evidence-collected world \
             into the same usize as the probed-empty-namespace \
             `Counted {{ count: 0 }}` arm, losing the discriminator a \
             strict-production policy needs",
        );
    }

    /// `Counted { count: 0 }` and `ProbeAbsent` collapse to the same
    /// `usize` at the surface (`0`) but remain structurally distinct at
    /// the enum level — `Counted { count: 0 }` is the "kubectl probe
    /// ran and the namespace contains zero pods" world (evidence-of-
    /// empty-deployment, a Phase 2 failure mode THEORY §V.4 / §VII.1
    /// name as post-admission honesty that the rollout never
    /// materialised any workloads), while `ProbeAbsent` is the "no
    /// kubectl probe ran inside certification" world (no evidence
    /// either way). Both collapse to the same Phase 2 usize value but
    /// carry distinct evidence semantics a future enrichment can route
    /// into a structural verdict field on `DeploymentAttestation`.
    #[test]
    fn test_counted_zero_collapses_to_zero_but_stays_distinct() {
        let probed_empty = PodListingOutcome::Counted { count: 0 };
        let absent = PodListingOutcome::ProbeAbsent;
        assert_eq!(probed_empty.running_pods(), absent.running_pods());
        assert_ne!(
            probed_empty, absent,
            "Counted{{count: 0}} must remain structurally distinct from \
             ProbeAbsent at the enum level even though both surface as \
             usize 0 — the discriminator the pre-fix `0` hardcode erased",
        );
    }

    /// The arms are mutually distinct under structural equality across
    /// representative values. Pins the load-bearing discriminator-
    /// preservation invariant the typed primitive exists to enforce:
    /// `Counted { count: 0 }` (probe ran and namespace empty),
    /// `Counted { count: N }` (probe ran and namespace has N pods),
    /// and `ProbeAbsent` (no probe ran inside certification) all
    /// remain structurally distinct at the enum level. A downstream
    /// verifier walking the enum recovers the kind-of-claim from the
    /// variant alone. Same shape as `test_arms_are_structurally_distinct`
    /// for [`crate::pod_health::PodHealthOutcome`] one layer over.
    #[test]
    fn test_arms_are_structurally_distinct() {
        let probed_empty = PodListingOutcome::Counted { count: 0 };
        let probed_one = PodListingOutcome::Counted { count: 1 };
        let probed_many = PodListingOutcome::Counted { count: 42 };
        let absent = PodListingOutcome::ProbeAbsent;
        assert_ne!(probed_empty, probed_one);
        assert_ne!(probed_empty, probed_many);
        assert_ne!(probed_one, probed_many);
        assert_ne!(probed_empty, absent);
        assert_ne!(probed_one, absent);
        assert_ne!(probed_many, absent);
    }

    /// Counted passes the count through unchanged for every value — no
    /// arithmetic transform, no cap, no downcast. The full `usize`
    /// domain is preserved. A future refactor that introduced a
    /// saturating cast (e.g. `usize -> u32` because a downstream
    /// attestation field had narrower type) would silently truncate
    /// cluster-observed counts above `u32::MAX` and fail this pin.
    #[test]
    fn test_counted_is_a_passthrough() {
        for n in [0usize, 1, 2, 3, 10, 100, 1_000, 1_000_000] {
            assert_eq!(
                PodListingOutcome::Counted { count: n }.running_pods(),
                n,
                "Counted{{count: {n}}} must pass through unchanged",
            );
        }
    }

    /// `ProbeOutcome` impl pin: `ProbeAbsent` identifies as absent;
    /// `Counted { .. }` does not. The load-bearing structural
    /// discriminator the trait names, anchored at this module so a
    /// future regression that hand-rolled a divergent impl is caught
    /// locally rather than only at the trait-module test.
    #[test]
    fn test_probe_outcome_impl() {
        use crate::probe_outcome::ProbeOutcome;
        assert!(PodListingOutcome::ProbeAbsent.is_probe_absent());
        assert!(!PodListingOutcome::Counted { count: 0 }.is_probe_absent());
        assert!(!PodListingOutcome::Counted { count: 7 }.is_probe_absent());
    }
}
