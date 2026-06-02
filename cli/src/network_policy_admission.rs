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
}
