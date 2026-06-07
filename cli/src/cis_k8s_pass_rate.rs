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

crate::impl_probe_outcome!(CisK8sPassRateOutcome, ProbeAbsent);

/// Recover the typed two-arm [`CisK8sPassRateOutcome`] from the
/// JSON-encoded kensa CIS-Kubernetes-Benchmark audit surface a
/// `kensa cis-k8s --cluster <ctx> --format json` shell-out (or its typed
/// `kensa::cis_k8s::audit(...)` library equivalent) yields. The parser is
/// the sixth parser in the Phase 2 deployment-probe family — after
/// [`crate::flux_source_verification::parse_gitrepository_status`] (commit
/// e07d64d, three-arm over `status.conditions[]`),
/// [`crate::helm_release_signature::parse_helmrelease_list`] (commit
/// 1f2f9a3, three-arm universal-quantifier over
/// `items[].metadata.annotations[]`),
/// [`crate::pod_listing::parse_pod_list`] (commit 46165ef, two-arm
/// items-len count over `PodList.items[]`),
/// [`crate::pod_health::parse_pod_health`] (commit c1faa28, three-arm
/// universal-quantifier over `PodList.items[]`), and
/// [`crate::network_policy_admission::parse_networkpolicy_list`] (commit
/// 7465feb, three-arm universal-quantifier over
/// `NetworkPolicyList.items[]`). It is the first parser whose typed
/// outcome carries an `f64` payload (the ratio) and the second two-arm
/// parser in the family — same shape discipline as
/// [`crate::pod_listing::parse_pod_list`] (the count IS the evidence;
/// no third arm names a structural distinction the bare payload does
/// not already carry).
///
/// ## What the parser closes
///
/// `commands/attestation.rs::compose_product_certification` today stamps
/// the typed primitive's [`CisK8sPassRateOutcome::ProbeAbsent`] arm at
/// the call site with no parser, so the Phase 2 deployment attestation's
/// `cis_k8s_pass_rate` field surfaces a hardcoded `0.0` against every
/// certification. With the parser landed, the call site can pipe the
/// JSON response from `kensa cis-k8s --cluster <ctx> --format json`
/// straight into [`parse_cis_k8s_audit_json`] and route the call-site
/// outcome through [`CisK8sPassRateOutcome::Probed { ratio }`] /
/// [`CisK8sPassRateOutcome::ProbeAbsent`] arms structurally — no inline
/// ratio computation, no per-call-site JSON walk over the kensa shape,
/// no implicit `ProbeAbsent` collapse hidden in a shell-out match. The
/// parser is testable in isolation against canonical kensa response
/// shapes (no cluster, no kensa, no kube-rs runtime), which means the
/// shell-out call-site code stays narrow (spawn + read stdout + pass to
/// parser), and every regression in the JSON-to-ratio map fails the
/// parser tests pinned here rather than surfacing at integration test
/// time against a live cluster.
///
/// ## The two-arm mapping
///
/// 1. The JSON deserializes AND both `passed_controls` and
///    `total_controls` are non-negative integer values AND
///    `total_controls` is strictly positive →
///    [`CisK8sPassRateOutcome::Probed`] with `ratio: passed as f64 /
///    total as f64`. The ratio is passed through without clamp or
///    round, preserving the full `[0.0, ∞)` `f64` domain a passed /
///    total quotient could yield (in practice always in `[0.0, 1.0]` for
///    a well-formed kensa response). A cluster that fails every control
///    parses to `Probed { ratio: 0.0 }` — the load-bearing structural
///    discriminator the typed primitive exists to preserve, distinct from
///    [`CisK8sPassRateOutcome::ProbeAbsent`] even though both collapse to
///    `pass_rate(): 0.0` at the `f64` surface.
/// 2. Every other input — malformed JSON, missing `passed_controls`,
///    missing `total_controls`, fields that fail integer coercion (e.g.
///    string-encoded "92" or a floating-point `92.5`), negative integer
///    fields, or `total_controls == 0` (the division-by-zero degenerate
///    that produces no usable evidence — a kensa run that audited zero
///    CIS controls yields no ratio to attest) — folds into
///    [`CisK8sPassRateOutcome::ProbeAbsent`]. Same exit-agnostic,
///    no-panic discipline
///    [`crate::flux_source_verification::parse_gitrepository_status`]
///    and the sibling parsers carry one and several layers over.
///
/// ## Why `total_controls == 0` collapses to `ProbeAbsent`, not `Probed { ratio: 0.0 }`
///
/// The `Probed { ratio: 0.0 }` arm names "kensa ran and observed zero
/// passing controls against a non-empty audit set" (the load-bearing
/// zero-pass-rate posture a Phase 2 record encodes as evidence of an
/// un-baselined cluster). A `total_controls == 0` response carries no
/// per-control evidence at all — the divisor is undefined, the ratio
/// cannot be honestly computed, and the resulting `f64::NAN` (or the
/// arbitrary `0.0` a default branch would produce) is no evidence,
/// structurally indistinguishable from a probe that never ran. The
/// honest collapse is [`CisK8sPassRateOutcome::ProbeAbsent`]: same
/// discipline as the sibling parsers' fold of malformed inputs into the
/// no-usable-evidence arm.
///
/// THEORY §V.1: make invalid states unrepresentable. The two-arm codomain
/// `{Probed, ProbeAbsent}` is foreclosed at the type level; a regression
/// that wanted to introduce a `Malformed` arm would force every consumer
/// to handle a world the parser does not produce. THEORY §VI.1: one
/// oracle, not a per-consumer re-derivation. The parser is the one site
/// that walks the `passed_controls / total_controls` shape for its
/// ratio; downstream consumers pattern-match the typed two-arm enum.
#[allow(dead_code)]
pub fn parse_cis_k8s_audit_json(json_text: &str) -> CisK8sPassRateOutcome {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(json_text) else {
        return CisK8sPassRateOutcome::ProbeAbsent;
    };
    let Some(passed) = value.get("passed_controls").and_then(|v| v.as_u64()) else {
        return CisK8sPassRateOutcome::ProbeAbsent;
    };
    let Some(total) = value.get("total_controls").and_then(|v| v.as_u64()) else {
        return CisK8sPassRateOutcome::ProbeAbsent;
    };
    if total == 0 {
        return CisK8sPassRateOutcome::ProbeAbsent;
    }
    CisK8sPassRateOutcome::Probed {
        ratio: passed as f64 / total as f64,
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

    /// `ProbeOutcome` impl pin: `ProbeAbsent` identifies as absent;
    /// `Probed { .. }` does not. The load-bearing structural
    /// discriminator the trait names, anchored at this module.
    #[test]
    fn test_probe_outcome_impl() {
        use crate::probe_outcome::ProbeOutcome;
        assert!(CisK8sPassRateOutcome::ProbeAbsent.is_probe_absent());
        assert!(!CisK8sPassRateOutcome::Probed { ratio: 0.0 }.is_probe_absent());
        assert!(!CisK8sPassRateOutcome::Probed { ratio: 0.92 }.is_probe_absent());
    }

    /// A canonical `kensa cis-k8s --cluster <ctx> --format json` response
    /// reporting 92 passed of 100 total CIS Kubernetes Benchmark controls
    /// (the headline near-baseline posture a hardened cluster produces).
    /// Parses to [`CisK8sPassRateOutcome::Probed`] with `ratio: 0.92` —
    /// the one arm that lets the Phase 2 deployment attestation record a
    /// non-zero `cis_k8s_pass_rate` claim grounded in a real kensa
    /// observation.
    #[test]
    fn test_parse_near_baseline_yields_probed_ratio() {
        let json = r#"{
            "passed_controls": 92,
            "total_controls": 100
        }"#;
        assert_eq!(
            parse_cis_k8s_audit_json(json),
            CisK8sPassRateOutcome::Probed { ratio: 0.92 },
        );
    }

    /// A kensa response reporting every CIS control passing
    /// (`100 / 100`) — the full-baseline ceiling a hardened cluster
    /// produces. Parses to [`CisK8sPassRateOutcome::Probed`] with
    /// `ratio: 1.0`. Pins the upper bound of the `[0.0, 1.0]` domain
    /// the parser passes through without clamp.
    #[test]
    fn test_parse_perfect_pass_yields_probed_one() {
        let json = r#"{"passed_controls": 50, "total_controls": 50}"#;
        assert_eq!(
            parse_cis_k8s_audit_json(json),
            CisK8sPassRateOutcome::Probed { ratio: 1.0 },
        );
    }

    /// A kensa response reporting zero passing controls
    /// (`0 / 100`) — the load-bearing zero-pass-rate posture a freshly
    /// provisioned cluster or one whose CIS baseline never landed
    /// produces. Parses to [`CisK8sPassRateOutcome::Probed`] with
    /// `ratio: 0.0`. The load-bearing structural discriminator: a
    /// regression that collapsed `passed_controls: 0` into
    /// [`CisK8sPassRateOutcome::ProbeAbsent`] would force every
    /// zero-pass-rate cluster's evidence-of-empty-CIS-baseline state to
    /// surface as no-probe-ran, erasing the distinction the typed
    /// primitive exists to preserve. The pre-fix `0.0` literal at the
    /// call site already collapsed both worlds to the same `f64`; the
    /// parser must hold the discriminator at the enum level even where
    /// the surface `f64` is shared.
    #[test]
    fn test_parse_zero_passing_yields_probed_zero() {
        let json = r#"{"passed_controls": 0, "total_controls": 100}"#;
        assert_eq!(
            parse_cis_k8s_audit_json(json),
            CisK8sPassRateOutcome::Probed { ratio: 0.0 },
        );
    }

    /// A kensa response missing the `passed_controls` field — a malformed
    /// kensa output, or a CIS audit that failed to enumerate the passed
    /// set. Parses to [`CisK8sPassRateOutcome::ProbeAbsent`]: no usable
    /// evidence at the per-field shape the parser walks.
    #[test]
    fn test_parse_missing_passed_controls_yields_probe_absent() {
        let json = r#"{"total_controls": 100}"#;
        assert_eq!(
            parse_cis_k8s_audit_json(json),
            CisK8sPassRateOutcome::ProbeAbsent,
        );
    }

    /// A kensa response missing the `total_controls` field — the divisor
    /// the ratio depends on is absent. Parses to
    /// [`CisK8sPassRateOutcome::ProbeAbsent`]: no usable evidence to
    /// compute the per-cluster pass rate.
    #[test]
    fn test_parse_missing_total_controls_yields_probe_absent() {
        let json = r#"{"passed_controls": 50}"#;
        assert_eq!(
            parse_cis_k8s_audit_json(json),
            CisK8sPassRateOutcome::ProbeAbsent,
        );
    }

    /// A kensa response whose `total_controls` is exactly zero — the
    /// degenerate divisor-zero state a kensa run that audited zero CIS
    /// controls produces (no Master-Node, etcd, Control-Plane,
    /// Worker-Node, or Policies controls evaluated). Parses to
    /// [`CisK8sPassRateOutcome::ProbeAbsent`]: same honest collapse the
    /// module docstring names as "no usable evidence; the divisor is
    /// undefined". A regression that returned `Probed { ratio: 0.0 }`
    /// here would conflate "kensa ran and the cluster failed every
    /// non-trivial CIS control" with "kensa ran but had no controls to
    /// evaluate" — two structurally distinct worlds the parser must
    /// distinguish, and a regression that produced `Probed { ratio:
    /// f64::NAN }` would silently propagate a non-comparable `f64`
    /// through the Phase 2 attestation field.
    #[test]
    fn test_parse_zero_total_controls_yields_probe_absent() {
        let json = r#"{"passed_controls": 0, "total_controls": 0}"#;
        assert_eq!(
            parse_cis_k8s_audit_json(json),
            CisK8sPassRateOutcome::ProbeAbsent,
        );
    }

    /// A kensa response whose `passed_controls` field is a string
    /// (`"92"`) rather than a JSON number — a malformed kensa output
    /// shape no real CIS audit produces, but a robust parser must
    /// collapse honestly. Parses to [`CisK8sPassRateOutcome::
    /// ProbeAbsent`]. A regression that string-coerced the field would
    /// silently produce ratios from malformed input.
    #[test]
    fn test_parse_string_passed_yields_probe_absent() {
        let json = r#"{"passed_controls": "92", "total_controls": 100}"#;
        assert_eq!(
            parse_cis_k8s_audit_json(json),
            CisK8sPassRateOutcome::ProbeAbsent,
        );
    }

    /// A kensa response whose `passed_controls` field is a negative
    /// integer (`-1`) — no real CIS audit produces this, but the
    /// `as_u64()` coercion the parser uses returns `None` for negative
    /// values, structurally folding the malformed-input world into
    /// [`CisK8sPassRateOutcome::ProbeAbsent`]. A regression that
    /// hand-rolled `as_i64()` followed by an `as f64` cast would
    /// silently produce a negative ratio.
    #[test]
    fn test_parse_negative_passed_yields_probe_absent() {
        let json = r#"{"passed_controls": -1, "total_controls": 100}"#;
        assert_eq!(
            parse_cis_k8s_audit_json(json),
            CisK8sPassRateOutcome::ProbeAbsent,
        );
    }

    /// `kensa: command not found` shell-mode stderr output (not JSON at
    /// all) parses to [`CisK8sPassRateOutcome::ProbeAbsent`] without
    /// panic — the honest no-evidence-collected collapse. A regression
    /// that panicked on unparseable input would surface a shell-out
    /// failure as a runtime panic rather than as a typed no-evidence
    /// outcome.
    #[test]
    fn test_parse_malformed_json_yields_probe_absent() {
        let json = "kensa: command not found";
        assert_eq!(
            parse_cis_k8s_audit_json(json),
            CisK8sPassRateOutcome::ProbeAbsent,
        );
    }

    /// An empty JSON object `{}` parses to [`CisK8sPassRateOutcome::
    /// ProbeAbsent`] — neither field is present, no ratio can be
    /// honestly computed. Pins the both-fields-required contract: the
    /// parser does not synthesize a default `0` for either field, and
    /// does not assume any default total (e.g. the kube-bench default
    /// control count).
    #[test]
    fn test_parse_empty_object_yields_probe_absent() {
        assert_eq!(
            parse_cis_k8s_audit_json("{}"),
            CisK8sPassRateOutcome::ProbeAbsent,
        );
    }

    /// Pin the load-bearing discriminator at the parser surface: a
    /// canonical `Probed { ratio: 0.0 }` response (zero passing controls
    /// over a non-empty audit set) collapses to the same `pass_rate()
    /// == 0.0` as `ProbeAbsent`, but remains structurally distinct at
    /// the enum level. The pre-typed `0.0` literal flattened both worlds
    /// indistinguishably into the same Phase 2 `cis_k8s_pass_rate`
    /// f64; the parser preserves the discriminator from JSON input to
    /// typed enum. Same shape as
    /// [`crate::pod_listing::tests::test_parse_counted_zero_distinct_from_probe_absent`]
    /// one layer over.
    #[test]
    fn test_parse_probed_zero_distinct_from_probe_absent() {
        let probed_failing =
            parse_cis_k8s_audit_json(r#"{"passed_controls": 0, "total_controls": 100}"#);
        let absent = parse_cis_k8s_audit_json("not json");
        assert_eq!(probed_failing.pass_rate(), absent.pass_rate());
        assert_ne!(
            probed_failing, absent,
            "parser must preserve the Probed{{ratio: 0.0}} vs \
             ProbeAbsent discriminator across the JSON-to-enum boundary \
             — the same invariant \
             test_probed_zero_collapses_to_zero_but_stays_distinct pins \
             at the enum-construction layer",
        );
    }

    /// Pin a representative sweep of integer pass / total combinations
    /// the kensa CIS audit could yield across the realistic
    /// `[0, total]` domain. Each combination's ratio is passed through
    /// without clamp or round; the parser's `passed as f64 / total as
    /// f64` quotient matches the call-site `pass_rate()` field exactly
    /// for every input. A future refactor that introduced a clamp or a
    /// percentage cast (e.g. `* 100.0`) would silently transform
    /// cluster-observed ratios and fail this pin.
    #[test]
    fn test_parse_sweep_of_realistic_ratios() {
        for (passed, total, expected) in [
            (0_u64, 1_u64, 0.0_f64),
            (1, 1, 1.0),
            (1, 2, 0.5),
            (1, 4, 0.25),
            (3, 4, 0.75),
            (92, 100, 0.92),
            (99, 100, 0.99),
            (250, 500, 0.5),
        ] {
            let json = format!(r#"{{"passed_controls": {passed}, "total_controls": {total}}}"#);
            assert_eq!(
                parse_cis_k8s_audit_json(&json),
                CisK8sPassRateOutcome::Probed { ratio: expected },
                "parser must yield Probed{{ratio: {expected}}} for \
                 {passed}/{total}",
            );
        }
    }
}
