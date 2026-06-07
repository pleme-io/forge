//! Typed Kubernetes `NetworkPolicy` admission probe outcome for forge's
//! Phase 2 deployment attestation — the network-segmentation peer of
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
//! `network_policies_verified` field:
//!
//! ```ignore
//! let deployment = DeploymentAttestation {
//!     namespace: format!("{}-{}", product, environment),
//!     kustomization: format!("{}-{}", product, environment),
//!     source_commit: source.commit.clone(),
//!     source_verified: source_verification_outcome.is_verified(),
//!     manifest_hash: Blake3Hash::digest(b"pending-deployment"),
//!     all_releases_signed: false,
//!     cis_k8s_pass_rate: 0.0,
//!     network_policies_verified: false,                       // <-- this line
//!     running_pods: 0,
//!     all_healthy: false,
//! };
//! ```
//!
//! The bool surface is honest for the no-probe-ran world (a Phase 2
//! deployment attestation that records `network_policies_verified: false`
//! against a certification function that never spawned a kubectl probe is
//! correctly negative), but flattens three structurally distinct
//! operational worlds — `Verified`, `VerifyFailed`, `ProbeAbsent` — into
//! a single negative bool a downstream verifier cannot recover the
//! kind-of-claim from. The `VerifyFailed` collapse is the most load-
//! bearing: a Phase 2 deployment attestation that records
//! `network_policies_verified: false` against a namespace whose
//! `kubectl get networkpolicy -n <ns> -o json` probe RAN and reported
//! zero matching policies (evidence of an open / unsegmented namespace,
//! the structural failure CIS Kubernetes Benchmark §5.3.2 names) is
//! structurally indistinguishable from one against a namespace whose
//! probe was never spawned (no evidence either way). A downstream
//! `sekiban` admission webhook that fails-closed on evidence of
//! missing network segmentation cannot express that gate against the
//! pre-fix bare bool — every Phase 2 record asserts the same negative
//! value regardless of whether `kubectl get networkpolicy` substantiated
//! a missing-policy state or whether it simply never ran. The typed
//! primitive closes the gap the same way commits 5931e32 / 72424bd /
//! c1e83d5 / d81f639 / 2f3a7dc / b98eb5a / fffca30 / b8a1d8a / 0ff67e1
//! / e8a2df7 / 443bd22 / 9c5a99f / a5376a6 closed sibling Phase 1 and
//! Phase 2 gaps one shape away: a typed outcome enum over the
//! operational worlds a downstream probe could report, the
//! probe-evidence claim computed by the typed primitive over the typed
//! shape, and the every-arm distinction preserved structurally so a
//! downstream verifier recovers the kind-of-claim from the value alone.
//!
//! ## The three operational worlds
//!
//! A Kubernetes `NetworkPolicy` admission probe (the
//! `networking.k8s.io/v1` `NetworkPolicy` resources covering a
//! namespace's pods, queried by `kubectl get networkpolicy -n <ns> -o
//! json` or by a typed `kube::Api::<NetworkPolicy>::list(...)` query)
//! distinguishes three operational worlds the prior `false` hardcode
//! flattened into a single negative claim:
//!
//! 1. **Probe absent** — `compose_product_certification` did not query
//!    the cluster at all, or the certification function ran outside the
//!    cluster (e.g. an integration-test path that constructed the
//!    deployment attestation directly without going through a `kubectl
//!    get networkpolicy` probe). No probe ran. There is no evidence
//!    either way. The prior `false` hardcode reported a negative
//!    network-policy claim against this state every time.
//! 2. **Verify failed** — the probe ran and the namespace's covered-
//!    pod set is incomplete (one or more workloads have no matching
//!    `podSelector` from any `NetworkPolicy`, the default-deny baseline
//!    CIS Kubernetes Benchmark §5.3.2 names is absent, or no
//!    `NetworkPolicy` resources exist in the namespace at all). In
//!    every sub-case, there is no positive Phase 2 network-segmentation
//!    evidence; the prior `false` hardcode would have collapsed this
//!    structurally distinct evidence-of-missing-segmentation arm into
//!    the same bool value as the no-probe-ran arm.
//! 3. **Verified** — the probe ran and every workload in the namespace
//!    has at least one matching `NetworkPolicy` `podSelector` (or the
//!    namespace carries a default-deny `NetworkPolicy` matching all
//!    pods, which is the strict-baseline shape `sekiban` strict-
//!    production policy expects). The Phase 2 deployment attestation
//!    can honestly claim `network_policies_verified: true` only in this
//!    arm.
//!
//! ## Why three arms, not two or four
//!
//! - **Three rather than two** (`Verified` / `ProbeAbsent`): a
//!   `VerifyFailed` outcome is a structurally distinct world from both
//!   `Verified` AND `ProbeAbsent` — the kubectl probe ran and observed
//!   actual cluster state (which is itself a positive evidence event
//!   the no-probe-ran world cannot generate), but the observed state
//!   failed the network-segmentation invariant. Collapsing `VerifyFailed`
//!   into a single boolean would re-introduce the discriminator loss
//!   the typed primitive exists to prevent (THEORY §V.1: make invalid
//!   states unrepresentable — a `network_policies_verified: false`
//!   value that conflates "no kubectl probe ran" with "probe ran and
//!   the namespace has no covering NetworkPolicy" is a flat state where
//!   a downstream verifier cannot recover the kind-of-claim, and a
//!   strict-production policy that requires evidence-of-segmentation
//!   cannot distinguish from a probe-absent world).
//! - **Three rather than four** (no `Malformed` arm yet): this commit
//!   introduces the typed primitive but does NOT introduce a parser
//!   for `kubectl get networkpolicy -o json` output — no
//!   `parse_networkpolicy_list` function exists here. The `Malformed`
//!   arm in [`crate::helm_lint::HelmLintOutcome::Malformed`] is paired
//!   with [`crate::helm_lint::parse_lint_output`] over Helm's
//!   canonical summary-line grammar (Helm is an external project with
//!   a stable, documented output shape). `NetworkPolicy` is a typed
//!   Kubernetes CRD whose canonical observable surface is the
//!   strongly-typed `NetworkPolicyList.items` array — when a follow-up
//!   commit wires the kubectl shell-out (or `kube-rs` typed query) at
//!   the `compose_product_certification` call site, the integration
//!   will deserialize the response directly via the `networking.k8s.io/
//!   v1` schema rather than re-parse a text-mode summary, and any
//!   malformed JSON / missing field will fold into `ProbeAbsent`
//!   (response received but no usable evidence = no-evidence-collected).
//!   Adding a speculative `Malformed` arm today would force every
//!   consumer to handle a world the actual probe layer will not
//!   produce. The enum stays additive: a future commit may widen to
//!   four arms without changing the `Verified` / `VerifyFailed` /
//!   `ProbeAbsent` semantics this commit pins. Same deferral
//!   discipline as [`crate::flux_source_verification::
//!   FluxSourceVerificationOutcome`] one layer over.
//!
//! ## What this commit does NOT do
//!
//! This commit introduces the typed primitive and routes the call site
//! through the `ProbeAbsent` arm: `compose_product_certification` does
//! not yet spawn a Kubernetes `NetworkPolicy` probe itself. The Phase
//! 2 deployment attestation continues to record
//! `network_policies_verified: false`, but now records it through the
//! typed `NetworkPolicyAdmissionOutcome::ProbeAbsent.is_verified()`
//! expression — honestly naming "no NetworkPolicy admission probe ran
//! inside the certification function" rather than asserting a single
//! negative bool that a probe-detected missing-policy state would have
//! also produced. The `Verified` / `VerifyFailed` arms are the future
//! enrichment point: a follow-up commit that wires `tokio::process::
//! Command::new("kubectl").args(["get", "networkpolicy", "-n",
//! &namespace, "-o", "json"]).output().await` (or a typed
//! `kube::Api::<NetworkPolicy>::list(...)` query against `ListParams::
//! default()`) at the call site and walks the resulting
//! `NetworkPolicyList.items` array against the namespace's pod-listing
//! will flip the call-site outcome to `Verified` for namespaces whose
//! every workload is covered by at least one `NetworkPolicy`
//! `podSelector` and to `VerifyFailed` for namespaces missing the
//! covering policies. Same deferral shape as commit 5931e32's
//! [`crate::flux_source_verification::FluxSourceVerificationOutcome::
//! ProbeAbsent`] arm at the source-verification layer, commit 72424bd's
//! [`crate::nix_reproducibility::NixReproducibilityOutcome::
//! ProbeAbsent`] arm at the build-determinism layer, commit c1e83d5's
//! [`crate::kensa_policy::KensaPolicyOutcome::ProbeAbsent`] arm at the
//! chart-policy layer, commit d81f639's [`crate::helm_lint::
//! HelmLintOutcome::ProbeAbsent`] arm at the chart-quality layer, and
//! commit b98eb5a's [`crate::security_scan::SbomProbeOutcome::Absent`]
//! / [`crate::security_scan::VulnScanProbeOutcome::Absent`] arms at
//! the SBOM / vuln-scan layer (typed primitive available, real probe
//! wired in by a follow-up).
//!
//! ## Frontier inspiration
//!
//! CIS Kubernetes Benchmark §5.3.2 ("Ensure that all Namespaces have
//! Network Policies defined") is the canonical strict-baseline
//! reference cited by THEORY §V.3 / §VII.1 for in-cluster network-
//! segmentation evidence. The `networking.k8s.io/v1` `NetworkPolicy`
//! resource is the typed evidence channel — a `kubectl get
//! networkpolicy -n <ns>` response (or its typed `kube-rs`
//! equivalent) is what the strict-production policy's
//! `require_network_policies` floor reconciles against. SLSA v1.0
//! §"Deployment" and in-toto's pull-side verification layer both
//! treat the cluster's admission verdict as evidence-bearing — never
//! as a constant asserted by the publisher. A Phase 2 deployment
//! attestation that records `network_policies_verified: false`
//! against a namespace whose `NetworkPolicy` resources were never
//! queried fails every reconciliation a `kubectl describe
//! networkpolicy` / `kensa cis 5.3.2` / `falco rules` pass could
//! surface against the same cluster state. The typed `ProbeAbsent`
//! arm names that gap honestly rather than flattening it with a
//! constant — the same discipline
//! [`crate::flux_source_verification::FluxSourceVerificationOutcome::
//! ProbeAbsent`], [`crate::cosign::CosignVerifyOutcome::ProbeAbsent`],
//! [`crate::helm_provenance::HelmProvenanceOutcome::ProbeAbsent`],
//! [`crate::helm_lint::HelmLintOutcome::ProbeAbsent`],
//! [`crate::kensa_policy::KensaPolicyOutcome::ProbeAbsent`],
//! [`crate::git_signature::GitCommitSignatureOutcome::ProbeAbsent`],
//! [`crate::nix_reproducibility::NixReproducibilityOutcome::
//! ProbeAbsent`], [`crate::security_scan::SbomProbeOutcome::Absent`],
//! and [`crate::security_scan::VulnScanProbeOutcome::Absent`] apply
//! at the FluxCD source-verification, image-signature, chart-
//! signature, chart-quality, chart-policy, source-commit-signature,
//! build-determinism, SBOM, and vuln-scan layers.

/// Outcome of probing a namespace's Kubernetes `NetworkPolicy`
/// resources for the Phase 2 `network_policies_verified` claim. The
/// three arms preserve the probe-absent vs verify-failed vs verified
/// distinction the Phase 2 deployment attestation depends on; the
/// prior `false` hardcode conflated probe-absent with verify-failed
/// into a single negative claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkPolicyAdmissionOutcome {
    /// Kubernetes admission probe ran AND every workload in the
    /// namespace has at least one matching `NetworkPolicy`
    /// `podSelector` (or the namespace carries a default-deny
    /// `NetworkPolicy` matching all pods, which is the strict-baseline
    /// shape CIS Kubernetes Benchmark §5.3.2 names). The Phase 2
    /// deployment attestation can honestly claim
    /// `network_policies_verified: true` only in this arm.
    Verified,
    /// Kubernetes admission probe ran but the namespace's covered-pod
    /// set is incomplete: one or more workloads have no matching
    /// `podSelector` from any `NetworkPolicy`, OR no `NetworkPolicy`
    /// resources exist in the namespace at all, OR the default-deny
    /// baseline is absent. In every sub-case, there is no positive
    /// Phase 2 network-segmentation evidence; the prior `false`
    /// hardcode collapsed this structurally distinct evidence-of-
    /// missing-segmentation arm into the same bool value as the
    /// no-probe-ran arm. A downstream `sekiban` strict-production
    /// policy that fails-closed on evidence of missing network
    /// segmentation can express that gate against the typed
    /// `VerifyFailed` arm, where the pre-fix bare bool flattened it
    /// indistinguishably into `ProbeAbsent`.
    VerifyFailed,
    /// `compose_product_certification` did not query the cluster at
    /// all (no `kubectl get networkpolicy` shell-out, no typed
    /// `kube::Api::<NetworkPolicy>::list(...)` query), or the
    /// certification function ran outside the cluster (e.g. an
    /// integration-test path that constructed the deployment
    /// attestation directly without going through a kubectl probe).
    /// No probe was made; no evidence was collected. The prior `false`
    /// hardcode reported the same value here as for the `VerifyFailed`
    /// arm, conflating "no kubectl probe ran" with "probe ran and the
    /// namespace has no covering NetworkPolicy".
    ProbeAbsent,
}

impl NetworkPolicyAdmissionOutcome {
    /// True iff the Kubernetes admission probe ran AND reported every
    /// workload in the namespace as covered by at least one
    /// `NetworkPolicy`. The boolean the Phase 2 deployment
    /// attestation's `network_policies_verified` field carries. The
    /// other two arms collapse to `false` at this surface — they
    /// remain structurally distinct at the enum level so the call
    /// site can record them separately if needed (e.g. a future
    /// enrichment that surfaces the matched-policy-count or the
    /// uncovered-workload-set on the deployment attestation).
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified)
    }
}

crate::impl_probe_outcome!(NetworkPolicyAdmissionOutcome, ProbeAbsent);

/// Parse the JSON output of `kubectl get networkpolicy -n <ns> -o json`
/// (or the equivalent `kube::Api::<NetworkPolicy>::list(...)`
/// serialization) and recover the typed
/// [`NetworkPolicyAdmissionOutcome`] for the namespace's collective
/// `network_policies_verified` claim.
///
/// The function is the fifth parser in the Phase 2 deployment-probe
/// family — after [`crate::flux_source_verification::
/// parse_gitrepository_status`] (universal-quantifier over FluxCD
/// `GitRepository.status.conditions[type=SourceVerified]`, three-arm),
/// [`crate::helm_release_signature::parse_helmrelease_list`]
/// (universal-quantifier over FluxCD `HelmReleaseList.items[*].metadata.
/// annotations[sekiban.pleme.io/signature]`, three-arm),
/// [`crate::pod_listing::parse_pod_list`] (items-len count over `core/v1`
/// `PodList.items[]`, two-arm), and [`crate::pod_health::parse_pod_health`]
/// (universal-quantifier over `PodList.items[*].status.{phase,
/// conditions[type=Ready]}`, three-arm) — and the second universal-
/// quantifier parser to walk the `*.items[]` shape for the
/// `Verified` / `VerifyFailed` / `ProbeAbsent` trichotomy. Same
/// exit-agnostic discipline (no exit code consulted), same honest
/// collapse-into-[`Self::ProbeAbsent`] on malformed input. A follow-up
/// commit that wires the kubectl shell-out at the
/// [`crate::commands::attestation::compose_product_certification`]
/// call site composes ONE `kubectl get networkpolicy -o json` invocation
/// with this parser to route the call site out of its current
/// unconditional [`Self::ProbeAbsent`] arm.
///
/// ## The three-arm mapping
///
/// 1. The JSON deserializes AND `.items[]` is present AND non-empty AND
///    every entry carries a `spec.podSelector` field (the required key
///    on the `networking.k8s.io/v1` `NetworkPolicy.spec` schema — an
///    empty `podSelector: {}` matches every pod in the namespace, the
///    canonical default-deny baseline CIS Kubernetes Benchmark §5.3.2
///    names as the strict-production floor) → [`Self::Verified`].
/// 2. The JSON deserializes AND `.items[]` is present AND empty (the
///    namespace contains zero `NetworkPolicy` resources — an
///    unsegmented namespace), OR one or more entries lack a
///    `spec.podSelector` field (a structurally malformed policy that
///    cannot cover any workload) → [`Self::VerifyFailed`]. The
///    empty-items collapse is the CIS §5.3.2 break with the vacuous-
///    truth-on-empty discipline [`crate::helm_release_signature::
///    parse_helmrelease_list`] and [`crate::pod_health::parse_pod_health`]
///    apply one layer over: zero `NetworkPolicy` resources in a namespace
///    is itself the evidence-of-missing-segmentation the CIS strict
///    baseline names as a failure, NOT a vacuous-truth-on-empty pass.
///    The discriminator distinguishes this "probe ran and observed
///    actual missing-policy cluster state" world from the "probe never
///    ran" world the [`Self::ProbeAbsent`] arm names — the load-bearing
///    structural distinction the pre-typed `false` hardcode erased by
///    flattening both worlds into the same `network_policies_verified:
///    false` bool.
/// 3. Every other input — malformed JSON, missing `.items` array,
///    `.items` not an array — folds into [`Self::ProbeAbsent`]. The
///    module-level docstring names this fold explicitly: "any malformed
///    JSON / missing field will fold into `ProbeAbsent` (response
///    received but no usable evidence = no-evidence-collected)." The
///    parser is exit-agnostic by construction; a kubectl failure
///    surfaces upstream as a [`Self::ProbeAbsent`] outcome chosen at
///    the shell-out call site rather than as a parser arm.
///
/// THEORY §V.2: attestation is cryptographic evidence, not a wish. The
/// parser preserves the structural distinction between "probe ran and
/// observed a namespace with zero or structurally malformed
/// NetworkPolicy resources" and "no probe ran / no usable evidence" —
/// the pre-typed `false` hardcode collapsed both into a single negative
/// claim.
/// THEORY §VI.1: one oracle, not a per-consumer re-derivation. The
/// parser is the one site that walks `items[*].spec.podSelector`;
/// downstream consumers pattern-match the typed three-arm enum.
#[allow(dead_code)]
pub fn parse_networkpolicy_list(json_text: &str) -> NetworkPolicyAdmissionOutcome {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(json_text) else {
        return NetworkPolicyAdmissionOutcome::ProbeAbsent;
    };
    let Some(items) = value.get("items").and_then(|i| i.as_array()) else {
        return NetworkPolicyAdmissionOutcome::ProbeAbsent;
    };
    if items.is_empty() {
        return NetworkPolicyAdmissionOutcome::VerifyFailed;
    }
    for item in items {
        let has_pod_selector = item
            .get("spec")
            .and_then(|s| s.get("podSelector"))
            .is_some();
        if !has_pod_selector {
            return NetworkPolicyAdmissionOutcome::VerifyFailed;
        }
    }
    NetworkPolicyAdmissionOutcome::Verified
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the three-arm `is_verified` truth table: only `Verified`
    /// collapses to `true`. The other two arms collapse to `false` at
    /// the bool surface but stay structurally distinct at the enum
    /// level — same shape as `test_is_verified_pins_all_arms` for
    /// [`crate::flux_source_verification::FluxSourceVerificationOutcome`]
    /// one layer over and `test_is_reproducible_pins_all_arms` for
    /// [`crate::nix_reproducibility::NixReproducibilityOutcome`] two
    /// layers over.
    #[test]
    fn test_is_verified_pins_all_arms() {
        assert!(NetworkPolicyAdmissionOutcome::Verified.is_verified());
        assert!(!NetworkPolicyAdmissionOutcome::VerifyFailed.is_verified());
        assert!(!NetworkPolicyAdmissionOutcome::ProbeAbsent.is_verified());
    }

    /// `ProbeAbsent` collapses to `network_policies_verified: false` —
    /// the load-bearing honesty invariant the call site rests on. The
    /// pre-fix call site stamped `false` regardless of whether the
    /// cluster had been probed; the typed primitive routes through
    /// `is_verified()` which returns `false` here. The bool value is
    /// the same, but the structural shape carries the discriminator
    /// the pre-fix literal erased — a downstream verifier reading
    /// `network_policies_verified: false` from a Phase 2 deployment
    /// attestation can recover "no NetworkPolicy admission probe ran
    /// inside the certification function" as one of the two possible
    /// kind-of-claims, where the pre-fix `false` conflated it
    /// indistinguishably with the evidence-of-missing-policy arm.
    #[test]
    fn test_probe_absent_collapses_to_false() {
        assert!(
            !NetworkPolicyAdmissionOutcome::ProbeAbsent.is_verified(),
            "ProbeAbsent must collapse to network_policies_verified=\
             false; the pre-fix `false` hardcode flattened this no-\
             evidence-collected world into the same bool as the \
             evidence-of-missing-policy `VerifyFailed` arm, losing \
             the discriminator a strict-production policy needs",
        );
    }

    /// `VerifyFailed` also collapses to `false`, but stays
    /// structurally distinct from `ProbeAbsent` at the enum level —
    /// `VerifyFailed` is the "kubectl probe ran and observed actual
    /// cluster state, but the observed state failed the network-
    /// segmentation invariant" world (evidence-of-missing-policy),
    /// while `ProbeAbsent` is the "no kubectl probe ran inside
    /// certification" world (no evidence either way). Both collapse
    /// to the same Phase 2 bool value but carry distinct evidence
    /// semantics a future enrichment can route into a structural
    /// verdict field on `DeploymentAttestation`.
    #[test]
    fn test_verify_failed_collapses_to_false() {
        assert!(
            !NetworkPolicyAdmissionOutcome::VerifyFailed.is_verified(),
            "VerifyFailed must collapse to network_policies_verified=\
             false; the pre-fix `false` hardcode would have collapsed \
             this evidence-of-missing-policy world (kubectl probe ran \
             and the namespace has zero covering NetworkPolicy \
             resources) into the same bool as the no-probe-ran world, \
             defeating the discriminator a downstream `sekiban` \
             strict-production policy that fails-closed on evidence \
             of missing segmentation needs",
        );
    }

    /// The three arms are mutually distinct under structural equality.
    /// Pins the load-bearing discriminator-preservation invariant the
    /// typed primitive exists to enforce: `Verified` (kubectl probe
    /// ran and every workload is covered), `VerifyFailed` (probe ran
    /// and one or more workloads lack a covering NetworkPolicy), and
    /// `ProbeAbsent` (no kubectl probe ran inside certification) all
    /// collapse to distinct `true` / `false` shapes at the bool
    /// surface but remain structurally distinct at the enum level. A
    /// downstream verifier walking the enum recovers the kind-of-
    /// claim from the variant alone. Same shape as
    /// `test_arms_are_structurally_distinct` for
    /// [`crate::flux_source_verification::FluxSourceVerificationOutcome`]
    /// one layer over and
    /// [`crate::nix_reproducibility::NixReproducibilityOutcome`] two
    /// layers over.
    #[test]
    fn test_arms_are_structurally_distinct() {
        let verified = NetworkPolicyAdmissionOutcome::Verified;
        let verify_failed = NetworkPolicyAdmissionOutcome::VerifyFailed;
        let absent = NetworkPolicyAdmissionOutcome::ProbeAbsent;
        assert_ne!(verified, verify_failed);
        assert_ne!(verified, absent);
        assert_ne!(verify_failed, absent);
    }

    /// `ProbeOutcome` impl pin: `ProbeAbsent` identifies as absent;
    /// `Verified` and `VerifyFailed` do not.
    #[test]
    fn test_probe_outcome_impl() {
        use crate::probe_outcome::ProbeOutcome;
        assert!(NetworkPolicyAdmissionOutcome::ProbeAbsent.is_probe_absent());
        assert!(!NetworkPolicyAdmissionOutcome::Verified.is_probe_absent());
        assert!(!NetworkPolicyAdmissionOutcome::VerifyFailed.is_probe_absent());
    }

    /// A canonical `kubectl get networkpolicy -n <ns> -o json` response
    /// with one `NetworkPolicy` whose `spec.podSelector` is the
    /// default-deny baseline (`{}` — match every pod in the namespace —
    /// the strict-baseline shape CIS Kubernetes Benchmark §5.3.2 names)
    /// parses to [`NetworkPolicyAdmissionOutcome::Verified`]. The one
    /// arm that lets the Phase 2 deployment attestation honestly claim
    /// `network_policies_verified: true`.
    #[test]
    fn test_parse_default_deny_policy_yields_verified() {
        let json = r#"{
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicyList",
            "items": [
                {
                    "metadata": {"name": "default-deny", "namespace": "demo"},
                    "spec": {"podSelector": {}}
                }
            ]
        }"#;
        assert_eq!(
            parse_networkpolicy_list(json),
            NetworkPolicyAdmissionOutcome::Verified
        );
    }

    /// A `NetworkPolicy` whose `spec.podSelector.matchLabels` names a
    /// specific workload (the targeted-policy shape, not the default-
    /// deny baseline) also parses to
    /// [`NetworkPolicyAdmissionOutcome::Verified`] — the parser pins
    /// the existence of a `podSelector` field, not its specific shape.
    /// A regression that required `podSelector: {}` exactly would force
    /// every targeted policy into the negative arm.
    #[test]
    fn test_parse_targeted_policy_yields_verified() {
        let json = r#"{
            "items": [
                {
                    "metadata": {"name": "allow-frontend"},
                    "spec": {
                        "podSelector": {"matchLabels": {"app": "frontend"}},
                        "policyTypes": ["Ingress"]
                    }
                }
            ]
        }"#;
        assert_eq!(
            parse_networkpolicy_list(json),
            NetworkPolicyAdmissionOutcome::Verified
        );
    }

    /// Two `NetworkPolicy` resources (a default-deny baseline plus a
    /// targeted ingress allow) both carrying `spec.podSelector` yield
    /// [`NetworkPolicyAdmissionOutcome::Verified`]. Pairs with
    /// `one-malformed-in-multi` below to pin the all-items
    /// universal-quantifier semantics: every entry must pass the
    /// predicate, not just the first.
    #[test]
    fn test_parse_multiple_policies_yield_verified() {
        let json = r#"{
            "items": [
                {"metadata": {"name": "default-deny"},
                 "spec": {"podSelector": {}}},
                {"metadata": {"name": "allow-frontend"},
                 "spec": {"podSelector": {"matchLabels": {"app": "frontend"}}}}
            ]
        }"#;
        assert_eq!(
            parse_networkpolicy_list(json),
            NetworkPolicyAdmissionOutcome::Verified
        );
    }

    /// A canonical `NetworkPolicyList` response with an empty `items[]`
    /// array — the namespace was probed and contains zero
    /// `NetworkPolicy` resources, the CIS Kubernetes Benchmark §5.3.2
    /// failure mode — parses to
    /// [`NetworkPolicyAdmissionOutcome::VerifyFailed`], NOT vacuously
    /// to [`NetworkPolicyAdmissionOutcome::Verified`]. This is the
    /// load-bearing semantic break with the vacuous-truth-on-empty
    /// discipline [`crate::helm_release_signature::parse_helmrelease_list`]
    /// and [`crate::pod_health::parse_pod_health`] apply one layer over:
    /// at the helmrelease / pod-health layers, an empty namespace
    /// trivially satisfies the per-item invariant (zero items, zero
    /// failures); at the network-segmentation layer, zero items IS
    /// itself the evidence of an unsegmented namespace the CIS strict
    /// baseline names as failure. A regression that folded empty-items
    /// into [`NetworkPolicyAdmissionOutcome::Verified`] would silently
    /// approve every namespace that landed in the cluster without a
    /// covering policy — precisely the gap the typed primitive exists
    /// to close.
    #[test]
    fn test_parse_empty_items_yields_verify_failed() {
        let json = r#"{
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicyList",
            "items": []
        }"#;
        assert_eq!(
            parse_networkpolicy_list(json),
            NetworkPolicyAdmissionOutcome::VerifyFailed,
            "empty items must collapse to VerifyFailed (CIS §5.3.2 \
             failure: namespace has zero covering NetworkPolicy), NOT \
             to Verified via vacuous-truth-on-empty as parse_helmrelease_\
             list and parse_pod_health do one layer over",
        );
    }

    /// An item with no `spec` block at all (a structurally malformed
    /// `NetworkPolicy` resource — the `spec.podSelector` field is
    /// required by the `networking.k8s.io/v1` schema and admission
    /// would have rejected the resource at creation, but a tampered or
    /// hand-rolled JSON response could surface this shape) parses to
    /// [`NetworkPolicyAdmissionOutcome::VerifyFailed`]. Structurally
    /// distinct from [`NetworkPolicyAdmissionOutcome::ProbeAbsent`]:
    /// the kubectl probe ran and observed actual unhealthy cluster
    /// state.
    #[test]
    fn test_parse_item_missing_spec_yields_verify_failed() {
        let json = r#"{
            "items": [
                {"metadata": {"name": "broken"}}
            ]
        }"#;
        assert_eq!(
            parse_networkpolicy_list(json),
            NetworkPolicyAdmissionOutcome::VerifyFailed
        );
    }

    /// An item whose `spec` block is present but lacks the required
    /// `podSelector` key parses to
    /// [`NetworkPolicyAdmissionOutcome::VerifyFailed`]. A regression
    /// that consulted only the existence of `spec` and ignored the
    /// `podSelector` key would pass every test above but fail this one
    /// — silently claiming `network_policies_verified: true` against a
    /// namespace whose policy carries no pod-selection rule.
    #[test]
    fn test_parse_item_missing_pod_selector_yields_verify_failed() {
        let json = r#"{
            "items": [
                {"metadata": {"name": "broken"},
                 "spec": {"policyTypes": ["Ingress"]}}
            ]
        }"#;
        assert_eq!(
            parse_networkpolicy_list(json),
            NetworkPolicyAdmissionOutcome::VerifyFailed
        );
    }

    /// Two `NetworkPolicy` resources — the first valid (default-deny
    /// baseline), the second malformed (missing `spec.podSelector`) —
    /// parses to [`NetworkPolicyAdmissionOutcome::VerifyFailed`]. Pins
    /// the parser walks the full `items[]` array and short-circuits at
    /// the first failing predicate rather than peeking at `items[0]`.
    /// A regression that hard-coded `items[0]` would pass the
    /// healthy-first / all-healthy / empty-only cases but fail this
    /// one. Same all-items discipline as
    /// [`crate::pod_health::parse_pod_health`]'s
    /// `test_parse_one_unhealthy_in_multi_yields_unhealthy`.
    #[test]
    fn test_parse_one_malformed_in_multi_yields_verify_failed() {
        let json = r#"{
            "items": [
                {"metadata": {"name": "default-deny"},
                 "spec": {"podSelector": {}}},
                {"metadata": {"name": "broken"},
                 "spec": {"policyTypes": ["Ingress"]}}
            ]
        }"#;
        assert_eq!(
            parse_networkpolicy_list(json),
            NetworkPolicyAdmissionOutcome::VerifyFailed
        );
    }

    /// A response missing the `items` field entirely — a non-list
    /// resource (e.g. a single `NetworkPolicy` response from
    /// `kubectl get networkpolicy <name>` rather than the list-mode
    /// `kubectl get networkpolicy`) or a malformed list shape. Parses
    /// to [`NetworkPolicyAdmissionOutcome::ProbeAbsent`]: structurally
    /// distinct from [`NetworkPolicyAdmissionOutcome::VerifyFailed`]
    /// because the absence of the list shape is evidence-of-no-probe,
    /// not evidence-of-missing-policy.
    #[test]
    fn test_parse_missing_items_yields_probe_absent() {
        let json = r#"{"apiVersion": "networking.k8s.io/v1",
                       "kind": "NetworkPolicy",
                       "metadata": {"name": "default-deny"}}"#;
        assert_eq!(
            parse_networkpolicy_list(json),
            NetworkPolicyAdmissionOutcome::ProbeAbsent
        );
    }

    /// A response whose `items` field is present but not a JSON array
    /// parses to [`NetworkPolicyAdmissionOutcome::ProbeAbsent`]. A
    /// regression that treated `items: null` or `items: {}` as an
    /// empty-items [`NetworkPolicyAdmissionOutcome::VerifyFailed`]
    /// would silently route malformed-input worlds into the evidence-
    /// of-missing-policy arm, defeating the discriminator between
    /// "probe shape is broken" and "probe ran and observed an
    /// unsegmented namespace".
    #[test]
    fn test_parse_items_not_array_yields_probe_absent() {
        let json = r#"{"items": {"unexpected": "object"}}"#;
        assert_eq!(
            parse_networkpolicy_list(json),
            NetworkPolicyAdmissionOutcome::ProbeAbsent
        );
    }

    /// kubectl `Error from server (Forbidden): ...` stderr-mode output
    /// (not JSON at all) parses to
    /// [`NetworkPolicyAdmissionOutcome::ProbeAbsent`] without panic —
    /// the honest no-evidence-collected collapse. A regression that
    /// panicked on unparseable input would surface a shell-out failure
    /// as a runtime panic rather than as a typed no-evidence outcome.
    /// Same exit-agnostic discipline as
    /// [`crate::pod_health::parse_pod_health`]'s
    /// `test_parse_malformed_json_yields_probe_absent`.
    #[test]
    fn test_parse_malformed_json_yields_probe_absent() {
        let json = "Error from server (Forbidden): networkpolicies is forbidden";
        assert_eq!(
            parse_networkpolicy_list(json),
            NetworkPolicyAdmissionOutcome::ProbeAbsent
        );
    }
}
