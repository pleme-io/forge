//! Typed Kubernetes pod-health admission probe outcome for forge's
//! Phase 2 deployment attestation — the pod-health peer of
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
//! [`crate::openpgp_signature`] (OpenPGP v4 signature packet parser), and
//! [`crate::security_scan`] (SBOM / vuln-scan probes).
//!
//! ## What this module closes
//!
//! `commands/attestation.rs::compose_product_certification` previously
//! stamped a literal `false` into every Phase 2 `DeploymentAttestation`'s
//! `all_healthy` field:
//!
//! ```ignore
//! let deployment = DeploymentAttestation {
//!     namespace: format!("{}-{}", product, environment),
//!     kustomization: format!("{}-{}", product, environment),
//!     source_commit: source.commit.clone(),
//!     source_verified: source_verification_outcome.is_verified(),
//!     manifest_hash: Blake3Hash::digest(b"pending-deployment"),
//!     all_releases_signed: helm_release_signature_outcome.is_verified(),
//!     cis_k8s_pass_rate: 0.0,
//!     network_policies_verified: network_policy_outcome.is_verified(),
//!     running_pods: 0,
//!     all_healthy: false,                                    // <-- this line
//! };
//! ```
//!
//! The bool surface is honest for the no-probe-ran world (a Phase 2
//! deployment attestation that records `all_healthy: false` against a
//! certification function that never spawned a `kubectl get pods` probe
//! is correctly negative), but flattens three structurally distinct
//! operational worlds — `Healthy`, `UnhealthyPods`, `ProbeAbsent` — into
//! a single negative bool a downstream verifier cannot recover the
//! kind-of-claim from. The `UnhealthyPods` collapse is the most load-
//! bearing: a Phase 2 deployment attestation that records
//! `all_healthy: false` against a namespace whose `kubectl get pods -n
//! <ns> -o json` probe RAN and observed one or more pods in `Pending`,
//! `Failed`, `Unknown`, or `Running`-but-not-`Ready` state (evidence of
//! a rollout that landed unhealthy workloads — the structural failure
//! THEORY §V.4 Phase 2 names) is structurally indistinguishable from one
//! against a namespace whose probe was never spawned (no evidence either
//! way). A downstream `sekiban` strict-production policy that fails-
//! closed on evidence of unhealthy pods cannot express that gate against
//! the pre-fix bare bool — every Phase 2 record asserts the same
//! negative value regardless of whether `kubectl get pods` substantiated
//! an unhealthy-pod state or whether it simply never ran. The typed
//! primitive closes the gap the same way commits 8b1407d / f8a5d8e /
//! 5931e32 / 72424bd / c1e83d5 / d81f639 / 2f3a7dc / b98eb5a / fffca30
//! / b8a1d8a / 0ff67e1 / e8a2df7 / 443bd22 / 9c5a99f / a5376a6 / 5baaa50
//! closed sibling Phase 1 and Phase 2 gaps one shape away: a typed
//! outcome enum over the operational worlds a downstream probe could
//! report, the probe-evidence claim computed by the typed primitive over
//! the typed shape, and the every-arm distinction preserved structurally
//! so a downstream verifier recovers the kind-of-claim from the value
//! alone.
//!
//! ## The three operational worlds
//!
//! A Kubernetes pod-health admission probe (the `Pod` resources covering
//! a namespace's deployed workloads, queried by `kubectl get pods -n
//! <ns> -o json` or by a typed `kube::Api::<Pod>::list(...)` query, with
//! each item's `status.phase` walked for `"Running"` and each item's
//! `status.conditions` walked for a `Ready` entry whose `status` is
//! `"True"`) distinguishes three operational worlds the prior `false`
//! hardcode flattened into a single negative claim:
//!
//! 1. **Probe absent** — `compose_product_certification` did not query
//!    the cluster at all, or the certification function ran outside the
//!    cluster (e.g. an integration-test path that constructed the
//!    deployment attestation directly without going through a `kubectl
//!    get pods` probe). No probe ran. There is no evidence either way.
//!    The prior `false` hardcode reported a negative pod-health claim
//!    against this state every time — including for namespaces whose
//!    pods were in fact all `Running` and `Ready`.
//! 2. **Unhealthy pods** — the probe ran and the namespace's pod set is
//!    incomplete: one or more `Pod` resources have a `status.phase`
//!    other than `"Running"` (i.e. `"Pending"`, `"Failed"`, `"Unknown"`,
//!    or in a `Running`-but-not-`Ready` state where the `Ready`
//!    condition's `status` is `"False"` or `"Unknown"`). In every
//!    sub-case (pod stuck pending, pod crashlooping, pod failed, pod
//!    running but readiness probe failing), there is no positive Phase
//!    2 pod-health evidence; the prior `false` hardcode would have
//!    collapsed this structurally distinct evidence-of-unhealthy-pod arm
//!    into the same bool value as the no-probe-ran arm.
//! 3. **Healthy** — the probe ran and every `Pod` resource in the
//!    namespace has `status.phase == "Running"` AND a `Ready` condition
//!    with `status == "True"`, OR the namespace contains zero `Pod`
//!    resources at all (an empty namespace trivially satisfies "all
//!    pods are healthy" — the universal-quantifier over an empty set).
//!    The Phase 2 deployment attestation can honestly claim
//!    `all_healthy: true` only in this arm.
//!
//! ## Why three arms, not two or four
//!
//! - **Three rather than two** (`Healthy` / `ProbeAbsent`): an
//!   `UnhealthyPods` outcome is a structurally distinct world from both
//!   `Healthy` AND `ProbeAbsent` — the kubectl probe ran and observed
//!   actual cluster state (which is itself a positive evidence event
//!   the no-probe-ran world cannot generate), but the observed state
//!   failed the pod-health invariant. Collapsing `UnhealthyPods` into a
//!   single boolean would re-introduce the discriminator loss the typed
//!   primitive exists to prevent (THEORY §V.1: make invalid states
//!   unrepresentable — an `all_healthy: false` value that conflates "no
//!   kubectl probe ran" with "probe ran and the namespace has
//!   crashlooping pods" is a flat state where a downstream verifier
//!   cannot recover the kind-of-claim, and a strict-production policy
//!   that requires evidence-of-healthy-pods cannot distinguish from a
//!   probe-absent world).
//! - **Three rather than four** (no `Malformed` arm yet): this commit
//!   introduces the typed primitive but does NOT introduce a parser for
//!   `kubectl get pods -o json` output — no `parse_pod_list` function
//!   exists here. `Pod` is a core Kubernetes resource whose canonical
//!   observable surface is the strongly-typed `PodList.items` array —
//!   when a follow-up commit wires the kubectl shell-out (or `kube-rs`
//!   typed query) at the `compose_product_certification` call site, the
//!   integration will deserialize the response directly via the
//!   `k8s_openapi::api::core::v1::Pod` schema rather than re-parse a
//!   text-mode summary, and any malformed JSON / missing field will fold
//!   into `ProbeAbsent` (response received but no usable evidence =
//!   no-evidence-collected). Adding a speculative `Malformed` arm today
//!   would force every consumer to handle a world the actual probe layer
//!   will not produce. The enum stays additive: a future commit may
//!   widen to four arms without changing the `Healthy` / `UnhealthyPods`
//!   / `ProbeAbsent` semantics this commit pins. Same deferral
//!   discipline as [`crate::helm_release_signature::
//!   HelmReleaseSignatureOutcome`] one layer over and
//!   [`crate::network_policy_admission::NetworkPolicyAdmissionOutcome`]
//!   two layers over.
//!
//! ## What this commit does NOT do
//!
//! This commit introduces the typed primitive and routes the call site
//! through the `ProbeAbsent` arm: `compose_product_certification` does
//! not yet spawn a Kubernetes `Pod` probe itself. The Phase 2 deployment
//! attestation continues to record `all_healthy: false`, but now records
//! it through the typed `PodHealthOutcome::ProbeAbsent.is_healthy()`
//! expression — honestly naming "no pod-health probe ran inside the
//! certification function" rather than asserting a single negative bool
//! that a probe-detected unhealthy-pod state would have also produced.
//! The `Healthy` / `UnhealthyPods` arms are the future enrichment point:
//! a follow-up commit that wires `tokio::process::Command::new("kubectl")
//! .args(["get", "pods", "-n", &namespace, "-o", "json"]).output().await`
//! (or a typed `kube::Api::<Pod>::list(...)` query against
//! `ListParams::default()`) at the call site and walks the resulting
//! `PodList.items` array for each item's `status.phase` / `status.
//! conditions[type=Ready]` entries will flip the call-site outcome to
//! `Healthy` for namespaces whose every Pod is `Running` and `Ready`
//! and to `UnhealthyPods` for namespaces with one or more pods in any
//! non-`Running` or non-`Ready` state. Same deferral shape as commit
//! 8b1407d's [`crate::helm_release_signature::HelmReleaseSignatureOutcome
//! ::ProbeAbsent`] arm at the HelmRelease-signature layer, commit
//! f8a5d8e's [`crate::network_policy_admission::
//! NetworkPolicyAdmissionOutcome::ProbeAbsent`] arm at the network-
//! segmentation layer, commit 5931e32's [`crate::flux_source_verification
//! ::FluxSourceVerificationOutcome::ProbeAbsent`] arm at the source-
//! verification layer, commit 72424bd's [`crate::nix_reproducibility::
//! NixReproducibilityOutcome::ProbeAbsent`] arm at the build-determinism
//! layer, commit c1e83d5's [`crate::kensa_policy::KensaPolicyOutcome::
//! ProbeAbsent`] arm at the chart-policy layer, commit d81f639's
//! [`crate::helm_lint::HelmLintOutcome::ProbeAbsent`] arm at the chart-
//! quality layer, and commit b98eb5a's [`crate::security_scan::
//! SbomProbeOutcome::Absent`] / [`crate::security_scan::
//! VulnScanProbeOutcome::Absent`] arms at the SBOM / vuln-scan layer
//! (typed primitive available, real probe wired in by a follow-up).
//!
//! ## Frontier inspiration
//!
//! THEORY §V.4 ("Two-phase signature composition") and §VII.1
//! ("Attestation-gated deployments") name the Phase 2 deployment record
//! as the post-admission honesty channel: the structural evidence that
//! the deployment actually landed healthy workloads in the cluster the
//! pre-Phase-2 Phase 1 signatures were composed against. Kubernetes'
//! `Pod` resource carries that evidence in `status.phase` (the lifecycle
//! position — `Pending`, `Running`, `Succeeded`, `Failed`, `Unknown`)
//! and in `status.conditions[type=Ready]` (the readiness signal that
//! gates Service endpoint inclusion — a `Running` pod with `Ready=False`
//! is excluded from load-balancer targets even though its lifecycle
//! phase is positive). A Phase 2 deployment attestation that records
//! `all_healthy: false` against a namespace whose `Pod` resources were
//! never queried fails every reconciliation a `sekiban admission audit`
//! pass could surface against the same cluster state. The typed
//! `ProbeAbsent` arm names that gap honestly rather than flattening it
//! with a constant — the same discipline
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
//! the HelmRelease-signature, network-segmentation, source-verification,
//! image-signature, chart-signature, chart-quality, chart-policy,
//! source-commit-signature, build-determinism, SBOM, and vuln-scan
//! layers.

/// Outcome of probing a namespace's Kubernetes `Pod` resources for
/// `Running` + `Ready` health — the Phase 2 `all_healthy` claim. The
/// three arms preserve the probe-absent vs unhealthy-pods vs healthy
/// distinction the Phase 2 deployment attestation depends on; the prior
/// `false` hardcode conflated probe-absent with unhealthy-pods into a
/// single negative claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PodHealthOutcome {
    /// Kubernetes pod-health probe ran AND every `Pod` resource in the
    /// namespace has `status.phase == "Running"` AND a `Ready` condition
    /// with `status == "True"`, OR the namespace contains zero `Pod`
    /// resources at all (an empty namespace trivially satisfies "all
    /// pods are healthy" — the universal-quantifier over an empty set).
    /// The Phase 2 deployment attestation can honestly claim
    /// `all_healthy: true` only in this arm.
    Healthy,
    /// Kubernetes pod-health probe ran but one or more `Pod` resources
    /// in the namespace are in a non-healthy state: `status.phase`
    /// other than `"Running"` (`"Pending"`, `"Failed"`, `"Unknown"`,
    /// `"Succeeded"`-for-a-long-running-workload), OR `status.phase ==
    /// "Running"` but the `Ready` condition's `status` is `"False"` or
    /// `"Unknown"` (the pod is alive but failing its readiness probe,
    /// excluded from Service endpoint sets). In every sub-case, there
    /// is no positive Phase 2 pod-health evidence; the prior `false`
    /// hardcode collapsed this structurally distinct evidence-of-
    /// unhealthy-pod arm into the same bool value as the no-probe-ran
    /// arm. A downstream `sekiban` strict-production policy that
    /// fails-closed on evidence of unhealthy pods can express that gate
    /// against the typed `UnhealthyPods` arm, where the pre-fix bare
    /// bool flattened it indistinguishably into `ProbeAbsent`.
    UnhealthyPods,
    /// `compose_product_certification` did not query the cluster at all
    /// (no `kubectl get pods` shell-out, no typed
    /// `kube::Api::<Pod>::list(...)` query), or the certification
    /// function ran outside the cluster (e.g. an integration-test path
    /// that constructed the deployment attestation directly without
    /// going through a kubectl probe). No probe was made; no evidence
    /// was collected. The prior `false` hardcode reported the same
    /// value here as for the `UnhealthyPods` arm, conflating "no
    /// kubectl probe ran" with "probe ran and the namespace has
    /// unhealthy pods".
    ProbeAbsent,
}

impl PodHealthOutcome {
    /// True iff the Kubernetes pod-health probe ran AND reported every
    /// `Pod` resource in the namespace as `Running` and `Ready`. The
    /// boolean the Phase 2 deployment attestation's `all_healthy` field
    /// carries. The other two arms collapse to `false` at this surface
    /// — they remain structurally distinct at the enum level so the
    /// call site can record them separately if needed (e.g. a future
    /// enrichment that surfaces the unhealthy-pod-name set on the
    /// deployment attestation).
    pub fn is_healthy(&self) -> bool {
        matches!(self, Self::Healthy)
    }
}

crate::impl_probe_outcome!(PodHealthOutcome, ProbeAbsent);

/// Parse the JSON output of `kubectl get pods -n <ns> -o json` (or the
/// equivalent `kube::Api::<Pod>::list(...)` serialization) and recover
/// the typed [`PodHealthOutcome`] for the namespace's collective
/// `all_healthy` claim.
///
/// The function is the parser-layer peer of
/// [`crate::pod_listing::parse_pod_list`] one layer over (same
/// `PodList.items[]` input domain, distinct semantic axis: that parser
/// walks `.items.len()` into a two-arm count, while this parser walks
/// `.items[*]` applying a universal-quantifier predicate over each
/// item's `status.phase` and `status.conditions[type=Ready]` into a
/// three-arm verdict) and the universal-quantifier peer of
/// [`crate::helm_release_signature::parse_helmrelease_list`] two layers
/// over (same shape: walk `.items[*]`, apply per-item predicate, fold
/// into `Healthy` / `UnhealthyPods` / `ProbeAbsent`). Same exit-
/// agnostic discipline (no exit code consulted), same honest
/// collapse-into-[`PodHealthOutcome::ProbeAbsent`] on malformed input.
/// A follow-up commit that wires the kubectl shell-out at the
/// [`crate::commands::attestation::compose_product_certification`]
/// call site composes ONE `kubectl get pods -o json` invocation with
/// both parsers — feeding the same JSON stdout into
/// [`crate::pod_listing::parse_pod_list`] for the `running_pods` claim
/// AND into [`parse_pod_health`] for the `all_healthy` claim. The two
/// parsers' shared input domain is the structural prerequisite for
/// that single-probe / two-claim composition: a regression that
/// drifted one parser's `items[]` walk off the canonical
/// [`k8s_openapi::api::core::v1::PodList`] shape (e.g. peeking at a
/// different field path) would surface at parser-test time against
/// canonical fixtures rather than at integration-test time against a
/// live cluster.
///
/// ## The three-arm mapping
///
/// 1. The JSON deserializes AND `.items[]` is present AND every entry
///    satisfies `status.phase == "Running"` AND has a
///    `status.conditions[]` entry with `type == "Ready"` AND
///    `status == "True"` → [`PodHealthOutcome::Healthy`]. An empty
///    `.items[]` array also yields [`PodHealthOutcome::Healthy`] — the
///    universal quantifier over the empty set is vacuously satisfied
///    (the module-level docstring's `Healthy` arm names this case
///    explicitly: "the namespace contains zero `Pod` resources at all
///    — an empty namespace trivially satisfies all pods are healthy").
///    Same vacuous-truth-on-empty discipline
///    [`crate::helm_release_signature::parse_helmrelease_list`]
///    carries one layer over.
/// 2. The JSON deserializes AND `.items[]` is present AND one or more
///    entries fail the predicate (any of: `status` block missing,
///    `status.phase != "Running"`, no `Ready` condition entry,
///    `Ready` condition's `status != "True"`) →
///    [`PodHealthOutcome::UnhealthyPods`]. The discriminator
///    distinguishes this "probe ran and observed actual unhealthy
///    cluster state" world from the "probe never ran" world the
///    [`PodHealthOutcome::ProbeAbsent`] arm names — the load-bearing
///    structural distinction the pre-typed `false` hardcode erased by
///    flattening both worlds into the same `all_healthy: false` bool.
///    The `metav1.ConditionStatus` tristate (`True` / `False` /
///    `Unknown`) informs the `Unknown -> UnhealthyPods` collapse: a
///    `Ready=Unknown` pod is a probe-observed not-positively-ready
///    state (the kubelet has not confirmed readiness), structurally
///    distinct from the no-probe-ran world.
/// 3. Every other input — malformed JSON, missing `.items` array,
///    `.items` not an array — folds into
///    [`PodHealthOutcome::ProbeAbsent`]. The parser is exit-agnostic
///    by construction; a kubectl failure surfaces upstream as a
///    [`PodHealthOutcome::ProbeAbsent`] outcome chosen at the shell-
///    out call site rather than as a parser arm.
///
/// THEORY §V.2: attestation is cryptographic evidence, not a wish.
/// The parser preserves the structural distinction between "probe ran
/// and observed one or more pods that are not `Running`-and-`Ready`"
/// and "no probe ran / no usable evidence" — the pre-typed `false`
/// hardcode collapsed both into a single negative claim.
/// THEORY §VI.1: one oracle, not a per-consumer re-derivation. The
/// parser is the one site that walks `items[*].status.phase` and
/// `items[*].status.conditions[type=Ready]`; downstream consumers
/// pattern-match the typed three-arm enum.
#[allow(dead_code)]
pub fn parse_pod_health(json_text: &str) -> PodHealthOutcome {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(json_text) else {
        return PodHealthOutcome::ProbeAbsent;
    };
    let Some(items) = value.get("items").and_then(|i| i.as_array()) else {
        return PodHealthOutcome::ProbeAbsent;
    };
    for item in items {
        let Some(status) = item.get("status") else {
            return PodHealthOutcome::UnhealthyPods;
        };
        let phase_running = status
            .get("phase")
            .and_then(|p| p.as_str())
            .is_some_and(|p| p == "Running");
        if !phase_running {
            return PodHealthOutcome::UnhealthyPods;
        }
        let ready_true = status
            .get("conditions")
            .and_then(|c| c.as_array())
            .is_some_and(|conds| {
                conds.iter().any(|cond| {
                    cond.get("type").and_then(|t| t.as_str()) == Some("Ready")
                        && cond.get("status").and_then(|s| s.as_str()) == Some("True")
                })
            });
        if !ready_true {
            return PodHealthOutcome::UnhealthyPods;
        }
    }
    PodHealthOutcome::Healthy
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the three-arm `is_healthy` truth table: only `Healthy`
    /// collapses to `true`. The other two arms collapse to `false` at
    /// the bool surface but stay structurally distinct at the enum
    /// level — same shape as `test_is_verified_pins_all_arms` for
    /// [`crate::helm_release_signature::HelmReleaseSignatureOutcome`]
    /// one layer over and
    /// [`crate::network_policy_admission::NetworkPolicyAdmissionOutcome`]
    /// two layers over.
    #[test]
    fn test_is_healthy_pins_all_arms() {
        assert!(PodHealthOutcome::Healthy.is_healthy());
        assert!(!PodHealthOutcome::UnhealthyPods.is_healthy());
        assert!(!PodHealthOutcome::ProbeAbsent.is_healthy());
    }

    /// `ProbeAbsent` collapses to `all_healthy: false` — the load-
    /// bearing honesty invariant the call site rests on. The pre-fix
    /// call site stamped `false` regardless of whether the cluster had
    /// been probed; the typed primitive routes through `is_healthy()`
    /// which returns `false` here. The bool value is the same, but the
    /// structural shape carries the discriminator the pre-fix literal
    /// erased — a downstream verifier reading `all_healthy: false` from
    /// a Phase 2 deployment attestation can recover "no pod-health
    /// probe ran inside the certification function" as one of the two
    /// possible kind-of-claims, where the pre-fix `false` conflated it
    /// indistinguishably with the evidence-of-unhealthy-pod arm.
    #[test]
    fn test_probe_absent_collapses_to_false() {
        assert!(
            !PodHealthOutcome::ProbeAbsent.is_healthy(),
            "ProbeAbsent must collapse to all_healthy=false; the \
             pre-fix `false` hardcode flattened this no-evidence-\
             collected world into the same bool as the evidence-of-\
             unhealthy-pod `UnhealthyPods` arm, losing the \
             discriminator a strict-production policy needs",
        );
    }

    /// `UnhealthyPods` also collapses to `false`, but stays structurally
    /// distinct from `ProbeAbsent` at the enum level — `UnhealthyPods`
    /// is the "kubectl probe ran and observed one or more pods that
    /// are not Running-and-Ready" world (evidence-of-unhealthy-pod),
    /// while `ProbeAbsent` is the "no kubectl probe ran inside
    /// certification" world (no evidence either way). Both collapse to
    /// the same Phase 2 bool value but carry distinct evidence
    /// semantics a future enrichment can route into a structural
    /// verdict field on `DeploymentAttestation`.
    #[test]
    fn test_unhealthy_pods_collapses_to_false() {
        assert!(
            !PodHealthOutcome::UnhealthyPods.is_healthy(),
            "UnhealthyPods must collapse to all_healthy=false; the \
             pre-fix `false` hardcode would have collapsed this \
             evidence-of-unhealthy-pod world (kubectl probe ran and \
             one or more pods are not Running-and-Ready) into the \
             same bool as the no-probe-ran world, defeating the \
             discriminator a downstream `sekiban` strict-production \
             policy that fails-closed on evidence of unhealthy pods \
             needs",
        );
    }

    /// The three arms are mutually distinct under structural equality.
    /// Pins the load-bearing discriminator-preservation invariant the
    /// typed primitive exists to enforce: `Healthy` (kubectl probe ran
    /// and every pod is Running-and-Ready), `UnhealthyPods` (probe ran
    /// and one or more pods are not Running-and-Ready), and
    /// `ProbeAbsent` (no kubectl probe ran inside certification) all
    /// collapse to distinct `true` / `false` shapes at the bool surface
    /// but remain structurally distinct at the enum level. A downstream
    /// verifier walking the enum recovers the kind-of-claim from the
    /// variant alone. Same shape as `test_arms_are_structurally_distinct`
    /// for [`crate::helm_release_signature::HelmReleaseSignatureOutcome`]
    /// one layer over and
    /// [`crate::network_policy_admission::NetworkPolicyAdmissionOutcome`]
    /// two layers over.
    #[test]
    fn test_arms_are_structurally_distinct() {
        let healthy = PodHealthOutcome::Healthy;
        let unhealthy = PodHealthOutcome::UnhealthyPods;
        let absent = PodHealthOutcome::ProbeAbsent;
        assert_ne!(healthy, unhealthy);
        assert_ne!(healthy, absent);
        assert_ne!(unhealthy, absent);
    }

    /// `ProbeOutcome` impl pin: `ProbeAbsent` identifies as absent;
    /// `Healthy` and `UnhealthyPods` do not.
    #[test]
    fn test_probe_outcome_impl() {
        use crate::probe_outcome::ProbeOutcome;
        assert!(PodHealthOutcome::ProbeAbsent.is_probe_absent());
        assert!(!PodHealthOutcome::Healthy.is_probe_absent());
        assert!(!PodHealthOutcome::UnhealthyPods.is_probe_absent());
    }

    /// A canonical `kubectl get pods -n <ns> -o json` response with a
    /// single `Pod` whose `status.phase == "Running"` AND whose
    /// `status.conditions[]` carries a `Ready=True` entry — the world
    /// a properly-rolled-out Phase 2 deployment produces. Parses to
    /// [`PodHealthOutcome::Healthy`] — the one arm that lets the
    /// Phase 2 deployment attestation honestly claim `all_healthy:
    /// true`.
    #[test]
    fn test_parse_single_running_ready_yields_healthy() {
        let json = r#"{
            "apiVersion": "v1",
            "kind": "PodList",
            "items": [
                {
                    "metadata": {"name": "svc-0", "namespace": "demo"},
                    "status": {
                        "phase": "Running",
                        "conditions": [
                            {"type": "Ready", "status": "True"}
                        ]
                    }
                }
            ]
        }"#;
        assert_eq!(parse_pod_health(json), PodHealthOutcome::Healthy);
    }

    /// Three `Running` + `Ready=True` pods yield
    /// [`PodHealthOutcome::Healthy`]. Pairs with the
    /// `one-unhealthy-in-multi` test below to pin the all-items
    /// universal-quantifier semantics: every entry must pass the
    /// predicate, not just the first.
    #[test]
    fn test_parse_multiple_running_ready_yield_healthy() {
        let json = r#"{
            "items": [
                {"status": {"phase": "Running",
                            "conditions": [{"type": "Ready", "status": "True"}]}},
                {"status": {"phase": "Running",
                            "conditions": [{"type": "Ready", "status": "True"}]}},
                {"status": {"phase": "Running",
                            "conditions": [{"type": "Ready", "status": "True"}]}}
            ]
        }"#;
        assert_eq!(parse_pod_health(json), PodHealthOutcome::Healthy);
    }

    /// A canonical `PodList` response with an empty `items[]` array
    /// (the namespace is probed and contains zero `Pod` resources)
    /// parses to [`PodHealthOutcome::Healthy`] — the vacuous
    /// universal-quantifier over the empty set, as the module-level
    /// `Healthy` arm's docstring names explicitly. A regression that
    /// folded empty-items into [`PodHealthOutcome::UnhealthyPods`]
    /// would force every namespace without pods into a permanent
    /// negative Phase 2 pod-health verdict. Same vacuous-truth
    /// discipline [`crate::helm_release_signature::
    /// parse_helmrelease_list`] applies to empty `HelmReleaseList`
    /// responses.
    #[test]
    fn test_parse_empty_items_yields_healthy_vacuously() {
        let json = r#"{"apiVersion": "v1", "kind": "PodList", "items": []}"#;
        assert_eq!(parse_pod_health(json), PodHealthOutcome::Healthy);
    }

    /// A pod whose `status.phase == "Pending"` (scheduler couldn't
    /// place it, or the image is still pulling) parses to
    /// [`PodHealthOutcome::UnhealthyPods`]. Structurally distinct
    /// from [`PodHealthOutcome::ProbeAbsent`]: the kubectl probe ran
    /// and observed actual unhealthy cluster state.
    #[test]
    fn test_parse_pending_pod_yields_unhealthy() {
        let json = r#"{
            "items": [
                {"status": {"phase": "Pending",
                            "conditions": [{"type": "PodScheduled",
                                            "status": "False",
                                            "reason": "Unschedulable"}]}}
            ]
        }"#;
        assert_eq!(parse_pod_health(json), PodHealthOutcome::UnhealthyPods);
    }

    /// A pod whose `status.phase == "Failed"` (crashlooping past the
    /// restart budget, or a Job-style pod that exited non-zero) parses
    /// to [`PodHealthOutcome::UnhealthyPods`]. Pins the `Failed` arm
    /// of the `status.phase` non-`Running` set the module-level
    /// `UnhealthyPods` docstring names.
    #[test]
    fn test_parse_failed_pod_yields_unhealthy() {
        let json = r#"{
            "items": [
                {"status": {"phase": "Failed"}}
            ]
        }"#;
        assert_eq!(parse_pod_health(json), PodHealthOutcome::UnhealthyPods);
    }

    /// The load-bearing discriminator: a pod whose `status.phase ==
    /// "Running"` BUT whose `Ready` condition's `status == "False"`
    /// (the pod is alive but its readiness probe is failing — Kubernetes
    /// excludes it from Service endpoint sets even though the lifecycle
    /// phase is positive) parses to [`PodHealthOutcome::UnhealthyPods`].
    /// A regression that consulted only `status.phase` and ignored the
    /// `Ready` condition would pass every test above but fail this one
    /// — silently claiming `all_healthy: true` against a namespace
    /// whose pods are alive but failing readiness, the precise failure
    /// the module-level docstring's `Running`-but-not-`Ready` sub-case
    /// names as load-bearing.
    #[test]
    fn test_parse_running_not_ready_yields_unhealthy() {
        let json = r#"{
            "items": [
                {"status": {"phase": "Running",
                            "conditions": [
                                {"type": "Ready", "status": "False",
                                 "reason": "ContainersNotReady"}
                            ]}}
            ]
        }"#;
        assert_eq!(parse_pod_health(json), PodHealthOutcome::UnhealthyPods);
    }

    /// A pod whose `Ready` condition carries the `metav1.
    /// ConditionStatus` tristate value `"Unknown"` (kubelet has not yet
    /// confirmed readiness — transient in-flight reconciliation, or the
    /// node hosting the pod has gone unreachable) parses to
    /// [`PodHealthOutcome::UnhealthyPods`]. The `Unknown -> UnhealthyPods`
    /// collapse mirrors the discipline `parse_gitrepository_status`
    /// applies at the FluxCD layer two parsers over, with one structural
    /// difference: at the source-verification layer, `Unknown ->
    /// ProbeAbsent` because an in-flight Flux reconciliation is no-
    /// usable-evidence; at the pod-readiness layer, `Ready=Unknown` IS
    /// itself evidence (the kubelet ran AND has not confirmed the pod
    /// healthy), so the cluster has produced positive observation of a
    /// not-positively-ready state — structurally distinct from no-probe-
    /// ran. A regression that mapped `Ready=Unknown` to `Healthy` (or to
    /// `ProbeAbsent`) would defeat the Phase 2 honesty channel against
    /// a transient unhealthy state.
    #[test]
    fn test_parse_ready_status_unknown_yields_unhealthy() {
        let json = r#"{
            "items": [
                {"status": {"phase": "Running",
                            "conditions": [
                                {"type": "Ready", "status": "Unknown",
                                 "reason": "NodeLost"}
                            ]}}
            ]
        }"#;
        assert_eq!(parse_pod_health(json), PodHealthOutcome::UnhealthyPods);
    }

    /// A pod whose `status.phase == "Running"` AND whose
    /// `status.conditions[]` carries no `Ready` entry at all (only
    /// `PodScheduled`, `Initialized`, `ContainersReady`) parses to
    /// [`PodHealthOutcome::UnhealthyPods`]. Missing `Ready` entry is
    /// structurally equivalent to `Ready=False` at the verdict layer:
    /// the cluster has not produced positive Ready evidence, so the
    /// Phase 2 deployment attestation cannot honestly claim healthy.
    /// A regression that defaulted absent `Ready` entries to true
    /// would silently approve every pod whose kubelet had not yet
    /// emitted the readiness condition.
    #[test]
    fn test_parse_no_ready_condition_yields_unhealthy() {
        let json = r#"{
            "items": [
                {"status": {"phase": "Running",
                            "conditions": [
                                {"type": "PodScheduled", "status": "True"},
                                {"type": "Initialized", "status": "True"}
                            ]}}
            ]
        }"#;
        assert_eq!(parse_pod_health(json), PodHealthOutcome::UnhealthyPods);
    }

    /// Three pods — the first two `Running` + `Ready=True`, the third
    /// `Pending` — parses to [`PodHealthOutcome::UnhealthyPods`]. Pins
    /// the parser walks the full `items[]` array and short-circuits at
    /// the first failing predicate rather than peeking at `items[0]`.
    /// A regression that hard-coded `items[0]` would pass the
    /// healthy-first / all-healthy / pending-only cases but fail this
    /// one.
    #[test]
    fn test_parse_one_unhealthy_in_multi_yields_unhealthy() {
        let json = r#"{
            "items": [
                {"status": {"phase": "Running",
                            "conditions": [{"type": "Ready", "status": "True"}]}},
                {"status": {"phase": "Running",
                            "conditions": [{"type": "Ready", "status": "True"}]}},
                {"status": {"phase": "Pending"}}
            ]
        }"#;
        assert_eq!(parse_pod_health(json), PodHealthOutcome::UnhealthyPods);
    }

    /// A pod with no `status` block at all (a freshly-admitted Pod the
    /// kubelet has not yet reconciled, or a malformed item with only a
    /// `metadata` block) parses to [`PodHealthOutcome::UnhealthyPods`].
    /// Absence of evidence-of-readiness is treated as evidence-of-
    /// not-ready at the per-pod predicate layer — structurally
    /// equivalent to a pod whose status block is present but reports
    /// `Pending`. This mirrors the `parse_helmrelease_list` discipline
    /// where a missing `metadata.annotations` block on an item folds
    /// into [`crate::helm_release_signature::
    /// HelmReleaseSignatureOutcome::VerifyFailed`] rather than
    /// silently passing.
    #[test]
    fn test_parse_missing_status_block_yields_unhealthy() {
        let json = r#"{
            "items": [
                {"metadata": {"name": "svc-0"}}
            ]
        }"#;
        assert_eq!(parse_pod_health(json), PodHealthOutcome::UnhealthyPods);
    }

    /// A response missing the `items` field entirely — a non-list
    /// resource (e.g. a single `Pod` response from `kubectl get pod
    /// <name>` rather than `kubectl get pods`) or a malformed list
    /// shape. Parses to [`PodHealthOutcome::ProbeAbsent`]:
    /// structurally distinct from [`PodHealthOutcome::UnhealthyPods`]
    /// because the absence of the list shape is evidence-of-no-probe,
    /// not evidence-of-unhealthy-pod.
    #[test]
    fn test_parse_missing_items_yields_probe_absent() {
        let json = r#"{"apiVersion": "v1", "kind": "Pod",
                       "metadata": {"name": "svc-0"}}"#;
        assert_eq!(parse_pod_health(json), PodHealthOutcome::ProbeAbsent);
    }

    /// A response whose `items` field is present but not a JSON array
    /// parses to [`PodHealthOutcome::ProbeAbsent`]. A regression that
    /// treated `items: null` or `items: {}` as
    /// [`PodHealthOutcome::Healthy`] (the empty-set vacuous-truth arm)
    /// would silently claim healthy against a malformed-input world.
    #[test]
    fn test_parse_items_not_array_yields_probe_absent() {
        let json = r#"{"items": {"unexpected": "object"}}"#;
        assert_eq!(parse_pod_health(json), PodHealthOutcome::ProbeAbsent);
    }

    /// kubectl `Error from server (Forbidden): ...` stderr-mode output
    /// (not JSON at all) parses to [`PodHealthOutcome::ProbeAbsent`]
    /// without panic — the honest no-evidence-collected collapse. A
    /// regression that panicked on unparseable input would surface a
    /// shell-out failure as a runtime panic rather than as a typed
    /// no-evidence outcome.
    #[test]
    fn test_parse_malformed_json_yields_probe_absent() {
        let json = "Error from server (Forbidden): pods is forbidden";
        assert_eq!(parse_pod_health(json), PodHealthOutcome::ProbeAbsent);
    }

    /// The two parsers over `PodList.items[]` —
    /// [`crate::pod_listing::parse_pod_list`] (count) and
    /// [`parse_pod_health`] (universal-quantifier health predicate) —
    /// compose against the SAME canonical `PodList` JSON: feeding one
    /// healthy-pod response into both parsers yields `Counted { count:
    /// 1 }` AND `Healthy`, structurally pinning the single-probe /
    /// two-claim composition the future
    /// [`crate::commands::attestation::compose_product_certification`]
    /// shell-out depends on. A regression that drifted either parser
    /// off the canonical `items[]` walk (e.g. peeked at a different
    /// field path) would surface here rather than at integration-test
    /// time against a live cluster.
    #[test]
    fn test_both_pod_list_parsers_compose_against_one_response() {
        use crate::pod_listing::{parse_pod_list, PodListingOutcome};
        let json = r#"{
            "apiVersion": "v1",
            "kind": "PodList",
            "items": [
                {"metadata": {"name": "svc-0"},
                 "status": {"phase": "Running",
                            "conditions": [{"type": "Ready", "status": "True"}]}}
            ]
        }"#;
        assert_eq!(
            parse_pod_list(json),
            PodListingOutcome::Counted { count: 1 }
        );
        assert_eq!(parse_pod_health(json), PodHealthOutcome::Healthy);
    }
}
