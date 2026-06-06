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

/// Recover the typed two-arm [`PodListingOutcome`] from the JSON-encoded
/// Kubernetes `PodList` surface a `kubectl get pods -n <ns> -o json` (or
/// typed `kube::Api::<Pod>::list(...)`) shell-out yields. The parser is
/// the third parser in the Phase 2 deployment-probe family, after
/// [`crate::flux_source_verification::parse_gitrepository_status`]
/// (commit e07d64d, over `status.conditions[]`) and
/// [`crate::helm_release_signature::parse_helmrelease_list`] (commit
/// 1f2f9a3, over `items[].metadata.annotations[]` — universal quantifier
/// shape), and the first parser over the `core/v1` `PodList.items[]`
/// surface the pod-readiness peer
/// [`crate::pod_health::PodHealthOutcome`] (commit e76db87) shares as
/// its input domain.
///
/// ## What the parser closes
///
/// `commands/attestation.rs::compose_product_certification` today
/// stamps the typed primitive's [`PodListingOutcome::ProbeAbsent`] arm
/// at the call site with no parser, so the Phase 2 deployment
/// attestation's `running_pods` field surfaces a hardcoded `0` against
/// every certification. With the parser landed, the call site can pipe
/// the JSON response from `kubectl get pods -n <ns> -o json` straight
/// into [`parse_pod_list`] and route the call-site outcome through
/// [`PodListingOutcome::Counted { count }`] / [`PodListingOutcome::
/// ProbeAbsent`] arms structurally — no inline counting, no per-call-
/// site JSON walk over `PodList.items`, no implicit `ProbeAbsent`
/// collapse hidden in a shell-out match. The parser is testable in
/// isolation against canonical `PodList` response shapes (no cluster,
/// no kubectl, no kube-rs runtime), which means the shell-out call-
/// site code stays narrow (spawn + read stdout + pass to parser), and
/// every regression in the JSON-to-count map fails the parser tests
/// pinned here rather than surfacing at integration test time against
/// a live cluster.
///
/// ## The two-arm mapping
///
/// 1. The JSON deserializes AND `.items` is an array →
///    [`PodListingOutcome::Counted`] with `count: items.len()`. The
///    array may itself be empty (the namespace is probed and contains
///    zero `Pod` resources — `Counted { count: 0 }` carries the
///    evidence-of-empty-deployment claim THEORY §V.4 / §VII.1 name as
///    post-admission honesty that the rollout never materialised any
///    workloads), or any positive integer length; the structural
///    distinction from [`PodListingOutcome::ProbeAbsent`] is that a
///    probe RAN and produced evidence, regardless of the magnitude
///    that evidence reports.
/// 2. Every other input — malformed JSON, missing `items` field,
///    `items` present but not an array (e.g. a kubectl error-mode
///    response with no list shape, or a non-`PodList` resource fed in
///    by mistake) — folds into [`PodListingOutcome::ProbeAbsent`].
///    Same exit-agnostic, no-panic discipline
///    [`crate::flux_source_verification::parse_gitrepository_status`]
///    and [`crate::helm_release_signature::parse_helmrelease_list`]
///    carry one and two layers over.
///
/// THEORY §V.1: make invalid states unrepresentable. The two-arm
/// codomain `{Counted, ProbeAbsent}` is foreclosed at the type level;
/// a regression that wanted to introduce a `Malformed` arm would force
/// every consumer to handle a world the parser does not produce.
/// THEORY §VI.1: one oracle, not a per-consumer re-derivation. The
/// parser is the one site that walks the `items[]` array for its
/// length; downstream consumers pattern-match the typed two-arm enum.
#[allow(dead_code)]
pub fn parse_pod_list(json_text: &str) -> PodListingOutcome {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(json_text) else {
        return PodListingOutcome::ProbeAbsent;
    };
    let Some(items) = value.get("items").and_then(|items| items.as_array()) else {
        return PodListingOutcome::ProbeAbsent;
    };
    PodListingOutcome::Counted { count: items.len() }
}

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

    /// A canonical `kubectl get pods -n <ns> -o json` response with a
    /// single `Pod` in the namespace parses to [`PodListingOutcome::
    /// Counted`] with `count: 1` — the one arm that lets the Phase 2
    /// deployment attestation record a non-zero `running_pods` claim
    /// grounded in a real cluster observation.
    #[test]
    fn test_parse_single_pod_yields_counted_one() {
        let json = r#"{
            "apiVersion": "v1",
            "kind": "PodList",
            "items": [
                {"metadata": {"name": "svc-0", "namespace": "demo"},
                 "status": {"phase": "Running"}}
            ]
        }"#;
        assert_eq!(
            parse_pod_list(json),
            PodListingOutcome::Counted { count: 1 },
        );
    }

    /// A `PodList` carrying three `items[]` entries parses to
    /// [`PodListingOutcome::Counted`] with `count: 3`. Pins that the
    /// parser walks the full array rather than peeking at the first
    /// entry or capping at a constant — a regression that hard-coded
    /// `items[0].is_some() as usize` would pass the single-pod test
    /// but fail this one.
    #[test]
    fn test_parse_three_pods_yields_counted_three() {
        let json = r#"{
            "items": [
                {"metadata": {"name": "svc-0"}},
                {"metadata": {"name": "svc-1"}},
                {"metadata": {"name": "svc-2"}}
            ]
        }"#;
        assert_eq!(
            parse_pod_list(json),
            PodListingOutcome::Counted { count: 3 },
        );
    }

    /// A canonical `PodList` response with an empty `items[]` array
    /// (the namespace is probed and contains zero `Pod` resources —
    /// the evidence-of-empty-deployment world THEORY §V.4 / §VII.1
    /// name as post-admission honesty that the rollout never
    /// materialised any workloads) parses to [`PodListingOutcome::
    /// Counted`] with `count: 0`. The load-bearing discriminator: a
    /// regression that collapsed empty-items into
    /// [`PodListingOutcome::ProbeAbsent`] would force every probed-
    /// empty-namespace state to surface as no-probe-ran, erasing the
    /// distinction the typed primitive exists to preserve.
    #[test]
    fn test_parse_empty_items_yields_counted_zero() {
        let json = r#"{"apiVersion": "v1", "kind": "PodList", "items": []}"#;
        assert_eq!(
            parse_pod_list(json),
            PodListingOutcome::Counted { count: 0 },
        );
    }

    /// A response missing the `items` field entirely — a non-list
    /// resource (e.g. a single `Pod` response from `kubectl get pod
    /// <name>` rather than `kubectl get pods`) or a malformed list
    /// shape. Parses to [`PodListingOutcome::ProbeAbsent`]: no
    /// usable evidence, the parser is exit-agnostic by construction.
    #[test]
    fn test_parse_missing_items_yields_probe_absent() {
        let json = r#"{"apiVersion": "v1", "kind": "Pod",
                       "metadata": {"name": "svc-0"}}"#;
        assert_eq!(parse_pod_list(json), PodListingOutcome::ProbeAbsent);
    }

    /// A response whose `items` field is present but not a JSON array
    /// (e.g. an object or a string — a structural malformation no real
    /// `PodList` produces, but a robust parser must collapse honestly).
    /// Parses to [`PodListingOutcome::ProbeAbsent`]. A regression that
    /// treated `items: null` or `items: {}` as `Counted { count: 0 }`
    /// would silently report an empty-namespace claim against a
    /// malformed-input world.
    #[test]
    fn test_parse_items_not_array_yields_probe_absent() {
        let json = r#"{"items": {"unexpected": "object"}}"#;
        assert_eq!(parse_pod_list(json), PodListingOutcome::ProbeAbsent);
    }

    /// kubectl `Error from server (Forbidden): ...` stderr-mode output
    /// (not JSON at all) parses to [`PodListingOutcome::ProbeAbsent`]
    /// without panic — the honest no-evidence-collected collapse. A
    /// regression that panicked on unparseable input would surface a
    /// shell-out failure as a runtime panic rather than as a typed
    /// no-evidence outcome.
    #[test]
    fn test_parse_malformed_json_yields_probe_absent() {
        let json = "Error from server (Forbidden): pods is forbidden";
        assert_eq!(parse_pod_list(json), PodListingOutcome::ProbeAbsent);
    }

    /// Pin the load-bearing discriminator at the parser surface: a
    /// canonical empty-`items[]` response parses to `Counted { count:
    /// 0 }`, which is structurally distinct from `ProbeAbsent` even
    /// though both collapse to `running_pods: 0` at the usize surface.
    /// The pre-typed `0` literal flattened both worlds; the parser
    /// preserves the discriminator from JSON input to typed enum.
    #[test]
    fn test_parse_counted_zero_distinct_from_probe_absent() {
        let probed_empty = parse_pod_list(r#"{"items": []}"#);
        let absent = parse_pod_list("not json");
        assert_eq!(probed_empty.running_pods(), absent.running_pods());
        assert_ne!(
            probed_empty, absent,
            "parser must preserve the Counted{{count: 0}} vs \
             ProbeAbsent discriminator across the JSON-to-enum \
             boundary — the same invariant \
             test_counted_zero_collapses_to_zero_but_stays_distinct \
             pins at the enum-construction layer",
        );
    }

    /// A `PodList` whose `items[]` carries 100 entries parses to
    /// `Counted { count: 100 }`. Pins the parser walks the full array
    /// at scale; a regression that capped at a constant (e.g. 16 from
    /// a stack-allocated buffer) would silently truncate cluster-
    /// observed counts in a large namespace and fail this pin.
    #[test]
    fn test_parse_large_items_passes_full_count_through() {
        let entries = (0..100)
            .map(|i| format!(r#"{{"metadata": {{"name": "svc-{i}"}}}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let json = format!(r#"{{"items": [{entries}]}}"#);
        assert_eq!(
            parse_pod_list(&json),
            PodListingOutcome::Counted { count: 100 },
        );
    }
}
