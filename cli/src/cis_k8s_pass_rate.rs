//! Typed kensa CIS-Kubernetes-Benchmark pass-rate probe outcome for forge's
//! Phase 2 deployment attestation — the f64-ratio peer of
//! [`crate::pod_listing`] (running-pod count probe, commit d002374),
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
//! stamped a literal `0.0` into every Phase 2 `DeploymentAttestation`'s
//! `cis_k8s_pass_rate` field:
//!
//! ```ignore
//! let deployment = DeploymentAttestation {
//!     namespace: format!("{}-{}", product, environment),
//!     ...
//!     cis_k8s_pass_rate: 0.0, // Populated post-deploy by kensa
//!     ...
//! };
//! ```
//!
//! The `f64` surface is honest for the no-probe-ran world (a Phase 2
//! deployment attestation that records `cis_k8s_pass_rate: 0.0` against a
//! certification function that never spawned a `kensa cis-k8s` probe is
//! correctly zero — no evidence was collected, and the surface value
//! fails-closed under any policy whose `min_cis_pass_rate > 0.0`), but
//! flattens two structurally distinct operational worlds — `Probed {
//! ratio: 0.0 }` (probe RAN against a cluster that failed every CIS
//! Kubernetes Benchmark control — evidence of a zero-pass-rate posture
//! the policy gate fails closed on for a substantiated reason) and
//! `ProbeAbsent` (no probe ran inside the certification function — no
//! evidence either way, fails closed on the same surface value for an
//! unsubstantiated reason) — into a single zero a downstream verifier
//! cannot recover the kind-of-claim from. The `Probed { ratio: 0.0 }`
//! collapse is the load-bearing discriminator loss: a Phase 2 deployment
//! attestation that records `cis_k8s_pass_rate: 0.0` against a cluster
//! whose `kensa cis-k8s` probe RAN and observed zero passing controls
//! (the structural failure mode CIS Kubernetes Benchmark §1–§5 names —
//! every control in the Master-Node, etcd, Control-Plane,
//! Worker-Node, and Policies sections failed) is structurally
//! indistinguishable from one against a cluster whose probe was never
//! spawned (no evidence either way). A downstream `sekiban` strict-
//! production policy that fails-closed on evidence of a zero-pass-rate
//! posture (probe ran AND ratio == 0.0 — a Phase 2 record that the
//! cluster admits no CIS control, the load-bearing failure for a freshly
//! provisioned cluster or a cluster whose CIS baseline never landed)
//! cannot express that gate against the pre-fix bare `f64` — every
//! Phase 2 record asserts the same zero regardless of whether `kensa
//! cis-k8s` substantiated a zero-pass-rate state or whether it simply
//! never ran. The typed primitive closes the gap the same way commits
//! d002374 / e76db87 / 8b1407d / f8a5d8e / 5931e32 / 72424bd / c1e83d5 /
//! d81f639 / 2f3a7dc / b98eb5a / fffca30 / b8a1d8a / 0ff67e1 / e8a2df7 /
//! 443bd22 / 9c5a99f / a5376a6 / 5baaa50 / 36d90b6 closed sibling Phase
//! 1 and Phase 2 gaps one shape away: a typed outcome enum over the
//! operational worlds a downstream probe could report, the probe-
//! evidence claim computed by the typed primitive over the typed shape,
//! and the every-arm distinction preserved structurally so a downstream
//! verifier recovers the kind-of-claim from the value alone.
//!
//! ## The two operational worlds
//!
//! A kensa CIS-Kubernetes-Benchmark probe (the `kensa cis-k8s
//! --cluster <ctx>` shell-out, or its typed `kensa::cis_k8s::audit(...)`
//! library equivalent, with the resulting `passed / total` ratio over
//! the union of Master-Node, etcd, Control-Plane, Worker-Node, and
//! Policies controls collected) distinguishes two operational worlds the
//! prior `0.0` hardcode flattened into a single claim:
//!
//! 1. **Probe absent** — `compose_product_certification` did not run a
//!    `kensa cis-k8s` audit at all, or the certification function ran
//!    outside the cluster (e.g. an integration-test path that
//!    constructed the deployment attestation directly without going
//!    through a kensa probe). No probe ran. There is no evidence either
//!    way. The prior `0.0` hardcode reported a zero pass rate against
//!    this state every time — including for clusters whose CIS posture
//!    was in fact non-zero.
//! 2. **Probed** — the probe ran and the cluster's CIS pass ratio has
//!    been computed: `passed_controls as f64 / total_controls as f64`
//!    is the ratio carried by the arm's `ratio: f64` field. The ratio
//!    may itself be `0.0` (the cluster truly failed every control —
//!    the probe ran and observed zero passing controls) or any value in
//!    `[0.0, 1.0]`; the structural distinction from `ProbeAbsent` is
//!    that a probe RAN and produced evidence, regardless of the
//!    magnitude that evidence reports. A cluster with `ratio: 0.0` is
//!    the load-bearing discriminator: a downstream verifier reading the
//!    typed outcome can distinguish "probe ran and posture is
//!    zero-pass-rate" (evidence-of-empty-CIS-baseline, a Phase 2 failure
//!    mode THEORY §V.4 / §VII.1 name as post-admission honesty that the
//!    cluster admits no CIS control) from "no probe ran" (no evidence),
//!    where the pre-fix bare `f64` flattened them indistinguishably into
//!    `0.0`.
//!
//! ## Why two arms, not three
//!
//! Unlike [`crate::pod_health::PodHealthOutcome`] (three arms: `Healthy`
//! / `UnhealthyPods` / `ProbeAbsent`) one layer over, the CIS-pass-rate
//! world has no positive-vs-negative-evidence axis the ratio itself does
//! not already carry. A probed cluster has `ratio: r` for some `r: f64`
//! in `[0.0, 1.0]`; the ratio IS the evidence, with `ratio: 0.0`
//! carrying the evidence-of-zero-pass-rate claim a third arm would have
//! named redundantly. Splitting `Probed { ratio: 0.0 }` from `Probed {
//! ratio: 0.0001.. }` would force every consumer to reassemble the
//! ratio from a match arm without surfacing a structural distinction
//! the call site does not already recover from the bare `ratio` field.
//! Same shape discipline as [`crate::pod_listing::PodListingOutcome`]
//! (two arms because the count IS the evidence and a `Counted { count:
//! 0 }` carries the empty-namespace claim a third arm would have
//! redundantly named).
//!
//! ## What this commit does NOT do
//!
//! This commit introduces the typed primitive and routes the call site
//! through the `ProbeAbsent` arm: `compose_product_certification` does
//! not yet spawn a kensa CIS-Kubernetes-Benchmark probe itself. The
//! Phase 2 deployment attestation continues to record
//! `cis_k8s_pass_rate: 0.0`, but now records it through the typed
//! `CisK8sPassRateOutcome::ProbeAbsent.pass_rate()` expression —
//! honestly naming "no kensa CIS probe ran inside the certification
//! function" rather than asserting a single zero that a
//! probe-detected zero-pass-rate cluster would have also produced.
//! The `Probed { ratio }` arm is the future enrichment point: a
//! follow-up commit that wires `tokio::process::Command::new("kensa")
//! .args(["cis-k8s", "--cluster", &cluster, "--format", "json"])
//! .output().await` (or the typed `kensa::cis_k8s::audit(...)` library
//! call) at the call site and walks the resulting `passed_count /
//! total_count` ratio will flip the call-site outcome to `Probed {
//! ratio }` with the cluster-observed value. Same deferral shape as
//! commit d002374's [`crate::pod_listing::PodListingOutcome::
//! ProbeAbsent`] arm at the pod-count layer.
//!
//! ## Frontier inspiration
//!
//! THEORY §V.4 ("Two-phase signature composition") and §VII.1
//! ("Attestation-gated deployments") name the Phase 2 deployment record
//! as the post-admission honesty channel: the structural evidence that
//! the deployment actually landed workloads in a cluster whose
//! configuration meets the CIS Kubernetes Benchmark baseline the
//! pre-Phase-2 Phase 1 signatures were composed against. The CIS
//! Kubernetes Benchmark (CIS) carries that evidence as a per-control
//! pass/fail set over `§1 Master-Node Security Configuration`, `§2 etcd
//! Node Configuration`, `§3 Control-Plane Configuration`, `§4
//! Worker-Node Configuration`, and `§5 Policies` — the cluster-level
//! audit a tool like `kube-bench`, `kensa cis-k8s`, or
//! `Aqua-Security/kube-bench` runs to substantiate the Phase 2
//! `cis_k8s_pass_rate` claim. A Phase 2 deployment attestation that
//! records `cis_k8s_pass_rate: 0.0` against a cluster whose CIS
//! controls were never audited fails every reconciliation a `sekiban
//! admission audit` pass could surface against the same cluster state.
//! The typed `ProbeAbsent` arm names that gap honestly rather than
//! flattening it with a constant — the same discipline
//! [`crate::pod_listing::PodListingOutcome::ProbeAbsent`],
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
//! the pod-count, pod-readiness, HelmRelease-signature, network-
//! segmentation, source-verification, image-signature, chart-signature,
//! chart-quality, chart-policy, source-commit-signature, build-
//! determinism, SBOM, and vuln-scan layers. With this commit, the last
//! remaining hardcoded scalar field on the Phase 2
//! `DeploymentAttestation` — `cis_k8s_pass_rate` — closes the typed-
//! primitive route, leaving every Phase 2 field grounded in a typed
//! probe outcome.

/// Outcome of running a kensa CIS-Kubernetes-Benchmark audit probe for
/// the Phase 2 `cis_k8s_pass_rate` claim. The two arms preserve the
/// probe-absent vs probed distinction the Phase 2 deployment attestation
/// depends on; the prior `0.0` hardcode conflated no-probe-ran with
/// probed-zero-pass-rate-cluster into a single zero.
///
/// `PartialEq` only (not `Eq`) because the `Probed { ratio }` arm
/// carries an `f64` payload, and `f64` does not implement `Eq`
/// (`NaN != NaN`). The structural distinctness invariant the typed
/// primitive enforces is still observable through `PartialEq`: every
/// pair of arms compares unequal except where the inner `f64` ratios
/// are bit-equal, and `ProbeAbsent` is always structurally distinct
/// from `Probed { ratio }` regardless of the ratio's value.
#[derive(Debug, Clone, PartialEq)]
pub enum CisK8sPassRateOutcome {
    /// kensa CIS-Kubernetes-Benchmark audit probe ran and the cluster's
    /// pass ratio over the union of Master-Node, etcd, Control-Plane,
    /// Worker-Node, and Policies controls was computed. `ratio` is the
    /// cluster-observed `passed_controls as f64 / total_controls as
    /// f64`, which may itself be `0.0` (the cluster failed every CIS
    /// control — probe ran and observed zero passing controls) or any
    /// value in `[0.0, 1.0]`. The structural distinction from
    /// `ProbeAbsent` is that a probe RAN and produced evidence,
    /// regardless of the magnitude that evidence reports. A downstream
    /// `sekiban` strict-production policy that fails-closed on
    /// evidence of a zero-pass-rate cluster can express that gate
    /// against `Probed { ratio: 0.0 }`, where the pre-fix bare `f64`
    /// flattened it indistinguishably into `ProbeAbsent`.
    Probed { ratio: f64 },
    /// `compose_product_certification` did not run a `kensa cis-k8s`
    /// audit at all (no `kensa` shell-out, no typed
    /// `kensa::cis_k8s::audit(...)` library call), or the certification
    /// function ran outside the cluster (e.g. an integration-test path
    /// that constructed the deployment attestation directly without
    /// going through a kensa probe). No probe was made; no evidence was
    /// collected. The prior `0.0` hardcode reported the same value
    /// here as for the `Probed { ratio: 0.0 }` arm, conflating "no
    /// kensa probe ran" with "probe ran and the cluster fails every
    /// CIS control".
    ProbeAbsent,
}

impl CisK8sPassRateOutcome {
    /// The `f64` the Phase 2 deployment attestation's
    /// `cis_k8s_pass_rate` field carries. `Probed { ratio }` passes the
    /// cluster-observed ratio through; `ProbeAbsent` collapses to
    /// `0.0`, matching the pre-fix bare-`f64` semantics exactly at the
    /// surface level while preserving the structural discriminator the
    /// bare `f64` erased.
    pub fn pass_rate(&self) -> f64 {
        match self {
            Self::Probed { ratio } => *ratio,
            Self::ProbeAbsent => 0.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the two-arm `pass_rate` collapse table. `Probed { ratio }`
    /// passes the ratio through unchanged for every representative value
    /// in `[0.0, 1.0]` a CIS audit could yield; `ProbeAbsent` collapses
    /// to `0.0`. Same shape as `test_running_pods_pins_all_arms` for
    /// [`crate::pod_listing::PodListingOutcome`] one layer over.
    #[test]
    fn test_pass_rate_pins_all_arms() {
        assert_eq!(CisK8sPassRateOutcome::ProbeAbsent.pass_rate(), 0.0);
        assert_eq!(
            CisK8sPassRateOutcome::Probed { ratio: 0.0 }.pass_rate(),
            0.0,
            "Probed{{ratio: 0.0}} must pass through unchanged — the \
             probe ran and the cluster fails every CIS control, \
             structurally distinct from ProbeAbsent even though both \
             surface as 0.0",
        );
        assert_eq!(
            CisK8sPassRateOutcome::Probed { ratio: 0.5 }.pass_rate(),
            0.5,
        );
        assert_eq!(
            CisK8sPassRateOutcome::Probed { ratio: 0.92 }.pass_rate(),
            0.92,
        );
        assert_eq!(
            CisK8sPassRateOutcome::Probed { ratio: 1.0 }.pass_rate(),
            1.0,
            "Probed{{ratio: 1.0}} must pass through unchanged — the \
             probe ran and the cluster passes every CIS control, the \
             full-baseline ceiling for the Phase 2 claim",
        );
    }

    /// `ProbeAbsent` collapses to `pass_rate == 0.0` — the load-bearing
    /// honesty invariant the call site rests on. The pre-fix call site
    /// stamped `0.0` regardless of whether the cluster had been audited;
    /// the typed primitive routes through `pass_rate()` which returns
    /// `0.0` here. The surface value is the same, but the structural
    /// shape carries the discriminator the pre-fix literal erased — a
    /// downstream verifier reading `cis_k8s_pass_rate: 0.0` from a
    /// Phase 2 deployment attestation can recover "no kensa CIS probe
    /// ran inside the certification function" as one of the two
    /// possible kind-of-claims, where the pre-fix `0.0` conflated it
    /// indistinguishably with the probed-zero-pass-rate-cluster arm.
    #[test]
    fn test_probe_absent_collapses_to_zero() {
        assert_eq!(
            CisK8sPassRateOutcome::ProbeAbsent.pass_rate(),
            0.0,
            "ProbeAbsent must collapse to pass_rate=0.0; the pre-fix \
             `0.0` hardcode flattened this no-evidence-collected world \
             into the same f64 as the probed-zero-pass-rate-cluster \
             `Probed {{ ratio: 0.0 }}` arm, losing the discriminator a \
             strict-production policy needs",
        );
    }

    /// `Probed { ratio: 0.0 }` and `ProbeAbsent` collapse to the same
    /// `f64` at the surface (`0.0`) but remain structurally distinct at
    /// the enum level — `Probed { ratio: 0.0 }` is the "kensa CIS probe
    /// ran and the cluster fails every control" world (evidence-of-
    /// zero-pass-rate, a Phase 2 failure mode THEORY §V.4 / §VII.1 name
    /// as post-admission honesty that the cluster admits no CIS
    /// control), while `ProbeAbsent` is the "no kensa CIS probe ran
    /// inside certification" world (no evidence either way). Both
    /// collapse to the same Phase 2 `f64` value but carry distinct
    /// evidence semantics a future enrichment can route into a
    /// structural verdict field on `DeploymentAttestation`.
    #[test]
    fn test_probed_zero_collapses_to_zero_but_stays_distinct() {
        let probed_failing = CisK8sPassRateOutcome::Probed { ratio: 0.0 };
        let absent = CisK8sPassRateOutcome::ProbeAbsent;
        assert_eq!(probed_failing.pass_rate(), absent.pass_rate());
        assert_ne!(
            probed_failing, absent,
            "Probed{{ratio: 0.0}} must remain structurally distinct \
             from ProbeAbsent at the enum level even though both \
             surface as f64 0.0 — the discriminator the pre-fix `0.0` \
             hardcode erased",
        );
    }

    /// The arms are mutually distinct under structural equality across
    /// representative values. Pins the load-bearing discriminator-
    /// preservation invariant the typed primitive exists to enforce:
    /// `Probed { ratio: 0.0 }` (probe ran and cluster fails every CIS
    /// control), `Probed { ratio: 0.5 }` / `Probed { ratio: 0.92 }` /
    /// `Probed { ratio: 1.0 }` (probe ran and cluster passes a
    /// substantive fraction of CIS controls), and `ProbeAbsent` (no
    /// probe ran inside certification) all remain structurally distinct
    /// at the enum level. A downstream verifier walking the enum
    /// recovers the kind-of-claim from the variant alone. Same shape as
    /// `test_arms_are_structurally_distinct` for
    /// [`crate::pod_listing::PodListingOutcome`] one layer over.
    #[test]
    fn test_arms_are_structurally_distinct() {
        let probed_failing = CisK8sPassRateOutcome::Probed { ratio: 0.0 };
        let probed_half = CisK8sPassRateOutcome::Probed { ratio: 0.5 };
        let probed_near_full = CisK8sPassRateOutcome::Probed { ratio: 0.92 };
        let probed_full = CisK8sPassRateOutcome::Probed { ratio: 1.0 };
        let absent = CisK8sPassRateOutcome::ProbeAbsent;
        assert_ne!(probed_failing, probed_half);
        assert_ne!(probed_failing, probed_near_full);
        assert_ne!(probed_failing, probed_full);
        assert_ne!(probed_half, probed_near_full);
        assert_ne!(probed_half, probed_full);
        assert_ne!(probed_near_full, probed_full);
        assert_ne!(probed_failing, absent);
        assert_ne!(probed_half, absent);
        assert_ne!(probed_near_full, absent);
        assert_ne!(probed_full, absent);
    }

    /// `Probed` passes the ratio through unchanged for every value — no
    /// arithmetic transform, no clamp, no rounding. The full
    /// representative `[0.0, 1.0]` domain of CIS pass ratios is
    /// preserved. A future refactor that introduced a percentage cast
    /// (e.g. `ratio * 100.0`) or a clamp into a narrower bound would
    /// silently transform cluster-observed ratios and fail this pin.
    #[test]
    fn test_probed_is_a_passthrough() {
        for ratio in [0.0_f64, 0.1, 0.25, 0.5, 0.75, 0.92, 0.99, 1.0] {
            assert_eq!(
                CisK8sPassRateOutcome::Probed { ratio }.pass_rate(),
                ratio,
                "Probed{{ratio: {ratio}}} must pass through unchanged",
            );
        }
    }
}
