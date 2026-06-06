//! Typed FluxCD `HelmRelease` signature-annotation admission probe
//! outcome for forge's Phase 2 deployment attestation — the
//! HelmRelease-signature peer of
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
//! `all_releases_signed` field:
//!
//! ```ignore
//! let deployment = DeploymentAttestation {
//!     namespace: format!("{}-{}", product, environment),
//!     kustomization: format!("{}-{}", product, environment),
//!     source_commit: source.commit.clone(),
//!     source_verified: source_verification_outcome.is_verified(),
//!     manifest_hash: Blake3Hash::digest(b"pending-deployment"),
//!     all_releases_signed: false,                          // <-- this line
//!     cis_k8s_pass_rate: 0.0,
//!     network_policies_verified: network_policy_outcome.is_verified(),
//!     running_pods: 0,
//!     all_healthy: false,
//! };
//! ```
//!
//! The bool surface is honest for the no-probe-ran world (a Phase 2
//! deployment attestation that records `all_releases_signed: false`
//! against a certification function that never spawned a HelmRelease
//! probe is correctly negative), but flattens three structurally
//! distinct operational worlds — `Verified`, `VerifyFailed`,
//! `ProbeAbsent` — into a single negative bool a downstream verifier
//! cannot recover the kind-of-claim from. The `VerifyFailed` collapse
//! is the most load-bearing: a Phase 2 deployment attestation that
//! records `all_releases_signed: false` against a namespace whose
//! `kubectl get helmrelease -n <ns> -o json` probe RAN and observed one
//! or more `HelmRelease` resources whose `metadata.annotations` lack a
//! valid sekiban signature is structurally indistinguishable from one
//! against a namespace whose probe was never spawned (no evidence
//! either way). A downstream `sekiban` strict-production policy that
//! fails-closed on evidence of unsigned `HelmRelease` admissions
//! (THEORY §V.4 Phase 2: only Phase-2-signed resources are admitted
//! into production) cannot express that gate against the pre-fix bare
//! bool — every Phase 2 record asserts the same negative value
//! regardless of whether `kubectl get helmrelease` substantiated an
//! unsigned-release state or whether it simply never ran. The typed
//! primitive closes the gap the same way commits f8a5d8e / 5931e32 /
//! 72424bd / c1e83d5 / d81f639 / 2f3a7dc / b98eb5a / fffca30 / b8a1d8a
//! / 0ff67e1 / e8a2df7 / 443bd22 / 9c5a99f / a5376a6 / 5baaa50 closed
//! sibling Phase 1 and Phase 2 gaps one shape away: a typed outcome
//! enum over the operational worlds a downstream probe could report,
//! the probe-evidence claim computed by the typed primitive over the
//! typed shape, and the every-arm distinction preserved structurally
//! so a downstream verifier recovers the kind-of-claim from the value
//! alone.
//!
//! ## The three operational worlds
//!
//! A FluxCD `HelmRelease` signature-annotation admission probe (the
//! `helm.toolkit.fluxcd.io/v2beta2` `HelmRelease` resources covering a
//! namespace's deployments, queried by `kubectl get helmrelease -n <ns>
//! -o json` or by a typed `kube::Api::<HelmRelease>::list(...)` query,
//! with each item's `metadata.annotations` walked for the
//! `tameshi::ci::ANNOTATION_SIGNATURE` entry that `sekiban` admission
//! webhook recognises) distinguishes three operational worlds the
//! prior `false` hardcode flattened into a single negative claim:
//!
//! 1. **Probe absent** — `compose_product_certification` did not query
//!    the cluster at all, or the certification function ran outside the
//!    cluster (e.g. an integration-test path that constructed the
//!    deployment attestation directly without going through a `kubectl
//!    get helmrelease` probe). No probe ran. There is no evidence
//!    either way. The prior `false` hardcode reported a negative
//!    HelmRelease-signature claim against this state every time —
//!    including for namespaces whose HelmReleases were in fact all
//!    properly signed by a previous deployment pipeline.
//! 2. **Verify failed** — the probe ran and the namespace's
//!    HelmRelease set is incomplete: one or more `HelmRelease`
//!    resources have no `tameshi::ci::ANNOTATION_SIGNATURE` annotation
//!    on their `metadata` (the annotation forge's `deploy` step
//!    injects, which `sekiban` admission verifies before admitting the
//!    resource into the cluster — THEORY §VII.1: sekiban admission
//!    webhook refuses any resource without a valid Phase 2 signature
//!    at the K8s API server). In every sub-case, there is no positive
//!    Phase 2 release-signature evidence; the prior `false` hardcode
//!    would have collapsed this structurally distinct evidence-of-
//!    unsigned-release arm into the same bool value as the
//!    no-probe-ran arm.
//! 3. **Verified** — the probe ran and every `HelmRelease` resource
//!    in the namespace carries a valid `tameshi::ci::
//!    ANNOTATION_SIGNATURE` annotation, OR the namespace contains zero
//!    `HelmRelease` resources at all (an empty namespace trivially
//!    satisfies "all releases are signed" — the universal-quantifier
//!    over an empty set). The Phase 2 deployment attestation can
//!    honestly claim `all_releases_signed: true` only in this arm.
//!
//! ## Why three arms, not two or four
//!
//! - **Three rather than two** (`Verified` / `ProbeAbsent`): a
//!   `VerifyFailed` outcome is a structurally distinct world from both
//!   `Verified` AND `ProbeAbsent` — the kubectl probe ran and observed
//!   actual cluster state (which is itself a positive evidence event
//!   the no-probe-ran world cannot generate), but the observed state
//!   failed the release-signature invariant. Collapsing `VerifyFailed`
//!   into a single boolean would re-introduce the discriminator loss
//!   the typed primitive exists to prevent (THEORY §V.1: make invalid
//!   states unrepresentable — an `all_releases_signed: false` value
//!   that conflates "no kubectl probe ran" with "probe ran and the
//!   namespace has unsigned HelmReleases" is a flat state where a
//!   downstream verifier cannot recover the kind-of-claim, and a
//!   strict-production policy that requires evidence-of-signed-
//!   releases cannot distinguish from a probe-absent world).
//! - **Three rather than four** (no `Malformed` arm yet): this commit
//!   introduces the typed primitive but does NOT introduce a parser
//!   for `kubectl get helmrelease -o json` output — no
//!   `parse_helmrelease_list` function exists here. `HelmRelease` is a
//!   typed Kubernetes CRD whose canonical observable surface is the
//!   strongly-typed `HelmReleaseList.items` array — when a follow-up
//!   commit wires the kubectl shell-out (or `kube-rs` typed query) at
//!   the `compose_product_certification` call site, the integration
//!   will deserialize the response directly via the
//!   `helm.toolkit.fluxcd.io/v2` schema rather than re-parse a
//!   text-mode summary, and any malformed JSON / missing field will
//!   fold into `ProbeAbsent` (response received but no usable evidence
//!   = no-evidence-collected). Adding a speculative `Malformed` arm
//!   today would force every consumer to handle a world the actual
//!   probe layer will not produce. The enum stays additive: a future
//!   commit may widen to four arms without changing the `Verified` /
//!   `VerifyFailed` / `ProbeAbsent` semantics this commit pins. Same
//!   deferral discipline as [`crate::network_policy_admission::
//!   NetworkPolicyAdmissionOutcome`] one layer over and
//!   [`crate::flux_source_verification::FluxSourceVerificationOutcome`]
//!   two layers over.
//!
//! ## What this commit does NOT do
//!
//! This commit introduces the typed primitive and routes the call site
//! through the `ProbeAbsent` arm: `compose_product_certification` does
//! not yet spawn a Kubernetes `HelmRelease` probe itself. The Phase 2
//! deployment attestation continues to record
//! `all_releases_signed: false`, but now records it through the typed
//! `HelmReleaseSignatureOutcome::ProbeAbsent.is_verified()` expression
//! — honestly naming "no HelmRelease signature-annotation probe ran
//! inside the certification function" rather than asserting a single
//! negative bool that a probe-detected unsigned-release state would
//! have also produced. The `Verified` / `VerifyFailed` arms are the
//! future enrichment point: a follow-up commit that wires `tokio::
//! process::Command::new("kubectl").args(["get", "helmrelease", "-n",
//! &namespace, "-o", "json"]).output().await` (or a typed
//! `kube::Api::<HelmRelease>::list(...)` query against `ListParams::
//! default()`) at the call site and walks the resulting
//! `HelmReleaseList.items` array for each item's `metadata.
//! annotations[tameshi::ci::ANNOTATION_SIGNATURE]` entry will flip the
//! call-site outcome to `Verified` for namespaces whose every
//! HelmRelease carries the signature annotation and to `VerifyFailed`
//! for namespaces with one or more unsigned releases. Same deferral
//! shape as commit f8a5d8e's [`crate::network_policy_admission::
//! NetworkPolicyAdmissionOutcome::ProbeAbsent`] arm at the network-
//! segmentation layer, commit 5931e32's
//! [`crate::flux_source_verification::FluxSourceVerificationOutcome::
//! ProbeAbsent`] arm at the source-verification layer, commit
//! 72424bd's [`crate::nix_reproducibility::NixReproducibilityOutcome::
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
//! THEORY §V.4 ("Two-phase signature composition") names the Phase 2
//! signature as the one `sekiban` admission webhook verifies before
//! admitting a resource into a production namespace: only Phase-2-
//! signed `HelmRelease` resources are admitted; Phase-1 records are
//! refused in production namespaces. THEORY §VII.1 ("Attestation-
//! gated deployments") names the gate as structural rather than a
//! policy overlay — `sekiban` admission runs in every cluster, refusing
//! any resource without a valid Phase 2 signature at the K8s API
//! server itself. The typed evidence channel for the Phase 2
//! `all_releases_signed` claim is therefore the
//! `metadata.annotations[tameshi::ci::ANNOTATION_SIGNATURE]` field on
//! each `HelmRelease` resource the namespace carries (the annotation
//! forge's `deploy` step injects, derived from
//! `commands/attestation.rs::generate_annotation_map`). A Phase 2
//! deployment attestation that records `all_releases_signed: false`
//! against a namespace whose `HelmRelease` resources were never queried
//! fails every reconciliation a `sekiban admission audit` pass could
//! surface against the same cluster state. The typed `ProbeAbsent`
//! arm names that gap honestly rather than flattening it with a
//! constant — the same discipline
//! [`crate::network_policy_admission::NetworkPolicyAdmissionOutcome::
//! ProbeAbsent`], [`crate::flux_source_verification::
//! FluxSourceVerificationOutcome::ProbeAbsent`],
//! [`crate::cosign::CosignVerifyOutcome::ProbeAbsent`],
//! [`crate::helm_provenance::HelmProvenanceOutcome::ProbeAbsent`],
//! [`crate::helm_lint::HelmLintOutcome::ProbeAbsent`],
//! [`crate::kensa_policy::KensaPolicyOutcome::ProbeAbsent`],
//! [`crate::git_signature::GitCommitSignatureOutcome::ProbeAbsent`],
//! [`crate::nix_reproducibility::NixReproducibilityOutcome::
//! ProbeAbsent`], [`crate::security_scan::SbomProbeOutcome::Absent`],
//! and [`crate::security_scan::VulnScanProbeOutcome::Absent`] apply
//! at the network-segmentation, source-verification, image-signature,
//! chart-signature, chart-quality, chart-policy, source-commit-
//! signature, build-determinism, SBOM, and vuln-scan layers.

/// Outcome of probing a namespace's FluxCD `HelmRelease` resources
/// for valid sekiban signature annotations — the Phase 2
/// `all_releases_signed` claim. The three arms preserve the
/// probe-absent vs verify-failed vs verified distinction the Phase 2
/// deployment attestation depends on; the prior `false` hardcode
/// conflated probe-absent with verify-failed into a single negative
/// claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelmReleaseSignatureOutcome {
    /// Kubernetes admission probe ran AND every `HelmRelease` resource
    /// in the namespace carries a valid `tameshi::ci::
    /// ANNOTATION_SIGNATURE` annotation on its `metadata.annotations`,
    /// OR the namespace contains zero `HelmRelease` resources at all
    /// (an empty namespace trivially satisfies "all releases are
    /// signed" — the universal-quantifier over an empty set). The
    /// Phase 2 deployment attestation can honestly claim
    /// `all_releases_signed: true` only in this arm.
    Verified,
    /// Kubernetes admission probe ran but one or more `HelmRelease`
    /// resources in the namespace lack a valid `tameshi::ci::
    /// ANNOTATION_SIGNATURE` annotation on their `metadata.
    /// annotations`. In every sub-case (annotation missing,
    /// annotation present but empty, annotation present but
    /// malformed), there is no positive Phase 2 release-signature
    /// evidence; the prior `false` hardcode collapsed this
    /// structurally distinct evidence-of-unsigned-release arm into
    /// the same bool value as the no-probe-ran arm. A downstream
    /// `sekiban` strict-production policy that fails-closed on
    /// evidence of unsigned `HelmRelease` admissions can express
    /// that gate against the typed `VerifyFailed` arm, where the
    /// pre-fix bare bool flattened it indistinguishably into
    /// `ProbeAbsent`.
    VerifyFailed,
    /// `compose_product_certification` did not query the cluster at
    /// all (no `kubectl get helmrelease` shell-out, no typed
    /// `kube::Api::<HelmRelease>::list(...)` query), or the
    /// certification function ran outside the cluster (e.g. an
    /// integration-test path that constructed the deployment
    /// attestation directly without going through a kubectl probe).
    /// No probe was made; no evidence was collected. The prior
    /// `false` hardcode reported the same value here as for the
    /// `VerifyFailed` arm, conflating "no kubectl probe ran" with
    /// "probe ran and the namespace has unsigned HelmReleases".
    ProbeAbsent,
}

impl HelmReleaseSignatureOutcome {
    /// True iff the Kubernetes admission probe ran AND reported every
    /// `HelmRelease` resource in the namespace as carrying a valid
    /// `tameshi::ci::ANNOTATION_SIGNATURE` annotation. The boolean
    /// the Phase 2 deployment attestation's `all_releases_signed`
    /// field carries. The other two arms collapse to `false` at this
    /// surface — they remain structurally distinct at the enum level
    /// so the call site can record them separately if needed (e.g. a
    /// future enrichment that surfaces the unsigned-release-name set
    /// on the deployment attestation).
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified)
    }
}

crate::impl_probe_outcome!(HelmReleaseSignatureOutcome, ProbeAbsent);

/// Parse the JSON output of `kubectl get helmrelease -n <ns> -o json`
/// (or the equivalent `kube::Api::<HelmRelease>::list(...)`
/// serialization) and recover the typed [`HelmReleaseSignatureOutcome`]
/// for the namespace's collective `all_releases_signed` claim.
///
/// The function is the parser-layer peer of
/// [`crate::flux_source_verification::parse_gitrepository_status`] one
/// layer over: same shape (raw kubectl JSON → typed outcome), same
/// exit-agnostic discipline (no exit code consulted), same honest
/// collapse-into-[`HelmReleaseSignatureOutcome::ProbeAbsent`] on
/// malformed input. The semantic axis differs — the FluxCD parser walks
/// `status.conditions[*]` for a single binary verdict, while this
/// parser walks the `items[*]` array and applies a universal quantifier
/// over each item's `metadata.annotations[tameshi::ci::
/// ANNOTATION_SIGNATURE]` field. A follow-up commit that wires
/// `tokio::process::Command::new("kubectl").args(["get", "helmrelease",
/// "-n", &namespace, "-o", "json"])` (or a typed
/// `kube::Api::<HelmRelease>::list(...)`) at the
/// [`crate::commands::attestation::compose_product_certification`] call
/// site composes the shell-out with this parser to route the call site
/// out of its current unconditional [`Self::ProbeAbsent`] arm.
///
/// ## The three-arm mapping
///
/// 1. The JSON deserializes AND `.items[]` is present AND every entry
///    carries a non-empty `metadata.annotations[
///    "sekiban.pleme.io/signature"]` value →
///    [`Self::Verified`]. An empty `.items[]` array also yields
///    [`Self::Verified`] (the universal quantifier over the empty set is
///    vacuously satisfied — a namespace with zero `HelmRelease`
///    resources trivially satisfies "all releases are signed", as the
///    module-level docstring's `Verified` arm names explicitly).
/// 2. The JSON deserializes AND `.items[]` is present AND one or more
///    entries lack a non-empty signature annotation (annotation missing,
///    annotation present but the empty string, `metadata` or
///    `annotations` block absent on the entry) → [`Self::VerifyFailed`].
///    The discriminator distinguishes this "probe ran and observed
///    actual unsigned cluster state" world from the "probe never ran"
///    world the [`Self::ProbeAbsent`] arm names — the load-bearing
///    structural distinction the pre-typed `false` hardcode erased by
///    flattening both worlds into the same `all_releases_signed: false`
///    bool.
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
/// observed one or more HelmRelease resources lacking the sekiban
/// signature annotation" and "no probe ran / no usable evidence" — the
/// pre-typed `false` hardcode collapsed both into a single negative
/// claim.
#[allow(dead_code)]
pub fn parse_helmrelease_list(json_text: &str) -> HelmReleaseSignatureOutcome {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(json_text) else {
        return HelmReleaseSignatureOutcome::ProbeAbsent;
    };
    let Some(items) = value.get("items").and_then(|i| i.as_array()) else {
        return HelmReleaseSignatureOutcome::ProbeAbsent;
    };
    for item in items {
        let signed = item
            .get("metadata")
            .and_then(|m| m.get("annotations"))
            .and_then(|a| a.get(tameshi::ci::ANNOTATION_SIGNATURE))
            .and_then(|s| s.as_str())
            .is_some_and(|s| !s.is_empty());
        if !signed {
            return HelmReleaseSignatureOutcome::VerifyFailed;
        }
    }
    HelmReleaseSignatureOutcome::Verified
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the three-arm `is_verified` truth table: only `Verified`
    /// collapses to `true`. The other two arms collapse to `false` at
    /// the bool surface but stay structurally distinct at the enum
    /// level — same shape as `test_is_verified_pins_all_arms` for
    /// [`crate::network_policy_admission::NetworkPolicyAdmissionOutcome`]
    /// one layer over and
    /// [`crate::flux_source_verification::FluxSourceVerificationOutcome`]
    /// two layers over.
    #[test]
    fn test_is_verified_pins_all_arms() {
        assert!(HelmReleaseSignatureOutcome::Verified.is_verified());
        assert!(!HelmReleaseSignatureOutcome::VerifyFailed.is_verified());
        assert!(!HelmReleaseSignatureOutcome::ProbeAbsent.is_verified());
    }

    /// `ProbeAbsent` collapses to `all_releases_signed: false` — the
    /// load-bearing honesty invariant the call site rests on. The
    /// pre-fix call site stamped `false` regardless of whether the
    /// cluster had been probed; the typed primitive routes through
    /// `is_verified()` which returns `false` here. The bool value is
    /// the same, but the structural shape carries the discriminator
    /// the pre-fix literal erased — a downstream verifier reading
    /// `all_releases_signed: false` from a Phase 2 deployment
    /// attestation can recover "no HelmRelease admission probe ran
    /// inside the certification function" as one of the two possible
    /// kind-of-claims, where the pre-fix `false` conflated it
    /// indistinguishably with the evidence-of-unsigned-release arm.
    #[test]
    fn test_probe_absent_collapses_to_false() {
        assert!(
            !HelmReleaseSignatureOutcome::ProbeAbsent.is_verified(),
            "ProbeAbsent must collapse to all_releases_signed=false; \
             the pre-fix `false` hardcode flattened this no-evidence-\
             collected world into the same bool as the evidence-of-\
             unsigned-release `VerifyFailed` arm, losing the \
             discriminator a strict-production policy needs",
        );
    }

    /// `VerifyFailed` also collapses to `false`, but stays
    /// structurally distinct from `ProbeAbsent` at the enum level —
    /// `VerifyFailed` is the "kubectl probe ran and observed one or
    /// more HelmRelease resources without a valid sekiban signature
    /// annotation" world (evidence-of-unsigned-release), while
    /// `ProbeAbsent` is the "no kubectl probe ran inside
    /// certification" world (no evidence either way). Both collapse
    /// to the same Phase 2 bool value but carry distinct evidence
    /// semantics a future enrichment can route into a structural
    /// verdict field on `DeploymentAttestation`.
    #[test]
    fn test_verify_failed_collapses_to_false() {
        assert!(
            !HelmReleaseSignatureOutcome::VerifyFailed.is_verified(),
            "VerifyFailed must collapse to all_releases_signed=false; \
             the pre-fix `false` hardcode would have collapsed this \
             evidence-of-unsigned-release world (kubectl probe ran and \
             one or more HelmRelease resources lack a valid sekiban \
             signature annotation) into the same bool as the no-probe-\
             ran world, defeating the discriminator a downstream \
             `sekiban` strict-production policy that fails-closed on \
             evidence of unsigned releases needs",
        );
    }

    /// The three arms are mutually distinct under structural equality.
    /// Pins the load-bearing discriminator-preservation invariant the
    /// typed primitive exists to enforce: `Verified` (kubectl probe
    /// ran and every HelmRelease is signed), `VerifyFailed` (probe
    /// ran and one or more HelmReleases lack the signature
    /// annotation), and `ProbeAbsent` (no kubectl probe ran inside
    /// certification) all collapse to distinct `true` / `false`
    /// shapes at the bool surface but remain structurally distinct
    /// at the enum level. A downstream verifier walking the enum
    /// recovers the kind-of-claim from the variant alone. Same shape
    /// as `test_arms_are_structurally_distinct` for
    /// [`crate::network_policy_admission::NetworkPolicyAdmissionOutcome`]
    /// one layer over and
    /// [`crate::flux_source_verification::FluxSourceVerificationOutcome`]
    /// two layers over.
    #[test]
    fn test_arms_are_structurally_distinct() {
        let verified = HelmReleaseSignatureOutcome::Verified;
        let verify_failed = HelmReleaseSignatureOutcome::VerifyFailed;
        let absent = HelmReleaseSignatureOutcome::ProbeAbsent;
        assert_ne!(verified, verify_failed);
        assert_ne!(verified, absent);
        assert_ne!(verify_failed, absent);
    }

    /// `ProbeOutcome` impl pin: `ProbeAbsent` identifies as absent;
    /// `Verified` and `VerifyFailed` do not.
    #[test]
    fn test_probe_outcome_impl() {
        use crate::probe_outcome::ProbeOutcome;
        assert!(HelmReleaseSignatureOutcome::ProbeAbsent.is_probe_absent());
        assert!(!HelmReleaseSignatureOutcome::Verified.is_probe_absent());
        assert!(!HelmReleaseSignatureOutcome::VerifyFailed.is_probe_absent());
    }

    /// A canonical `kubectl get helmrelease -o json` response whose
    /// `items[]` carries a single `HelmRelease` resource with a
    /// non-empty `metadata.annotations["sekiban.pleme.io/signature"]`
    /// value — the world a properly-signed Phase 2 deployment produces.
    /// Parses to [`HelmReleaseSignatureOutcome::Verified`] — the one
    /// arm that lets the Phase 2 deployment attestation honestly claim
    /// `all_releases_signed: true`.
    #[test]
    fn test_parse_single_signed_release_yields_verified() {
        let json = r#"{
            "apiVersion": "v1",
            "kind": "List",
            "items": [
                {
                    "apiVersion": "helm.toolkit.fluxcd.io/v2",
                    "kind": "HelmRelease",
                    "metadata": {
                        "name": "billing",
                        "namespace": "pleme-prod",
                        "annotations": {
                            "sekiban.pleme.io/signature": "blake3:abc123"
                        }
                    }
                }
            ]
        }"#;
        assert_eq!(
            parse_helmrelease_list(json),
            HelmReleaseSignatureOutcome::Verified,
        );
    }

    /// Multiple `HelmRelease` items, every one carrying a non-empty
    /// sekiban signature annotation — pins the universal-quantifier
    /// semantics across an item count greater than one. Parses to
    /// [`HelmReleaseSignatureOutcome::Verified`]. A regression that
    /// short-circuited on the first signed item without walking the
    /// rest would mask an unsigned tail; pairs with
    /// `test_parse_one_unsigned_in_multi_yields_verify_failed` to pin
    /// the all-items invariant.
    #[test]
    fn test_parse_multiple_signed_releases_yield_verified() {
        let json = r#"{
            "items": [
                {"metadata": {"annotations": {"sekiban.pleme.io/signature": "a"}}},
                {"metadata": {"annotations": {"sekiban.pleme.io/signature": "b"}}},
                {"metadata": {"annotations": {"sekiban.pleme.io/signature": "c"}}}
            ]
        }"#;
        assert_eq!(
            parse_helmrelease_list(json),
            HelmReleaseSignatureOutcome::Verified,
        );
    }

    /// An empty `items[]` array — the world a namespace has zero
    /// `HelmRelease` resources at all. The universal quantifier over the
    /// empty set is vacuously satisfied; the module-level docstring's
    /// `Verified` arm names this case explicitly: "the namespace contains
    /// zero `HelmRelease` resources at all (an empty namespace trivially
    /// satisfies 'all releases are signed' — the universal-quantifier
    /// over an empty set)." Parses to
    /// [`HelmReleaseSignatureOutcome::Verified`]. A regression that
    /// folded empty-items into [`HelmReleaseSignatureOutcome::
    /// VerifyFailed`] would force every namespace without a HelmRelease
    /// resource into a permanent negative Phase 2 verdict — the
    /// structural mismatch the typed primitive's docstring foreclosed.
    #[test]
    fn test_parse_empty_items_yields_verified_vacuously() {
        let json = r#"{"items": []}"#;
        assert_eq!(
            parse_helmrelease_list(json),
            HelmReleaseSignatureOutcome::Verified,
        );
    }

    /// A single `HelmRelease` item whose `metadata.annotations` block
    /// is present but carries no `sekiban.pleme.io/signature` entry —
    /// the world an unsigned release was admitted somehow (e.g. the
    /// `sekiban` admission webhook was bypassed, or the resource was
    /// applied before the webhook was deployed). Parses to
    /// [`HelmReleaseSignatureOutcome::VerifyFailed`] — the
    /// evidence-of-unsigned-release arm the typed primitive
    /// structurally distinguishes from [`HelmReleaseSignatureOutcome::
    /// ProbeAbsent`].
    #[test]
    fn test_parse_unsigned_release_yields_verify_failed() {
        let json = r#"{
            "items": [
                {
                    "metadata": {
                        "name": "rogue",
                        "annotations": {
                            "other.annotation/key": "value"
                        }
                    }
                }
            ]
        }"#;
        assert_eq!(
            parse_helmrelease_list(json),
            HelmReleaseSignatureOutcome::VerifyFailed,
        );
    }

    /// Multiple items, the first two signed and the third missing the
    /// sekiban signature annotation — pins that the parser walks the
    /// full `items[]` array rather than peeking at only the first
    /// entry. A regression that hard-coded `items[0]` would pass the
    /// signed-first cases above but fail this one. Parses to
    /// [`HelmReleaseSignatureOutcome::VerifyFailed`].
    #[test]
    fn test_parse_one_unsigned_in_multi_yields_verify_failed() {
        let json = r#"{
            "items": [
                {"metadata": {"annotations": {"sekiban.pleme.io/signature": "a"}}},
                {"metadata": {"annotations": {"sekiban.pleme.io/signature": "b"}}},
                {"metadata": {"name": "third-unsigned"}}
            ]
        }"#;
        assert_eq!(
            parse_helmrelease_list(json),
            HelmReleaseSignatureOutcome::VerifyFailed,
        );
    }

    /// A `HelmRelease` item whose signature annotation is present but
    /// is the empty string — the module-level docstring's `VerifyFailed`
    /// arm names this sub-case explicitly: "annotation present but
    /// empty". The empty-string is structurally distinct from a valid
    /// signature; the parser folds it into
    /// [`HelmReleaseSignatureOutcome::VerifyFailed`] rather than letting
    /// an empty value masquerade as evidence of a valid Phase 2
    /// signature. A regression that treated annotation-present-but-empty
    /// as `Verified` would let an attacker who could set the annotation
    /// key (but not produce a valid signature) bypass the Phase 2
    /// `all_releases_signed` claim.
    #[test]
    fn test_parse_empty_signature_annotation_yields_verify_failed() {
        let json = r#"{
            "items": [
                {
                    "metadata": {
                        "annotations": {
                            "sekiban.pleme.io/signature": ""
                        }
                    }
                }
            ]
        }"#;
        assert_eq!(
            parse_helmrelease_list(json),
            HelmReleaseSignatureOutcome::VerifyFailed,
        );
    }

    /// A `HelmRelease` item whose `metadata.annotations` block is
    /// missing entirely — no annotations of any kind on the resource.
    /// The module-level docstring's `VerifyFailed` arm names this case
    /// implicitly: there is no valid signature annotation. Parses to
    /// [`HelmReleaseSignatureOutcome::VerifyFailed`]. The parser does
    /// not require the `annotations` block to exist for the signature
    /// lookup; a missing block is structurally equivalent to a present-
    /// but-unsigned block at the verdict layer.
    #[test]
    fn test_parse_missing_annotations_block_yields_verify_failed() {
        let json = r#"{
            "items": [
                {
                    "metadata": {
                        "name": "no-annotations"
                    }
                }
            ]
        }"#;
        assert_eq!(
            parse_helmrelease_list(json),
            HelmReleaseSignatureOutcome::VerifyFailed,
        );
    }

    /// A response missing the `items` array entirely — not a valid
    /// `HelmReleaseList` shape. The module-level docstring names this
    /// fold explicitly: "any malformed JSON / missing field will fold
    /// into `ProbeAbsent`." Parses to [`HelmReleaseSignatureOutcome::
    /// ProbeAbsent`]. Structurally distinct from
    /// [`HelmReleaseSignatureOutcome::VerifyFailed`]: the absence of
    /// the list shape is evidence-of-no-probe, not evidence-of-
    /// unsigned-release.
    #[test]
    fn test_parse_missing_items_array_yields_probe_absent() {
        let json = r#"{
            "apiVersion": "v1",
            "kind": "List"
        }"#;
        assert_eq!(
            parse_helmrelease_list(json),
            HelmReleaseSignatureOutcome::ProbeAbsent,
        );
    }

    /// Malformed JSON — the world a kubectl shell-out failed entirely
    /// (the command produced text on stderr that is not parseable as
    /// JSON, e.g. an RBAC denial or a missing-namespace error). The
    /// module-level docstring names this fold explicitly. Parses to
    /// [`HelmReleaseSignatureOutcome::ProbeAbsent`] without panic — the
    /// honest no-evidence-collected collapse, not a runtime panic that
    /// would surface the shell-out failure inside composition.
    #[test]
    fn test_parse_malformed_json_yields_probe_absent() {
        let json =
            "Error from server (Forbidden): helmreleases.helm.toolkit.fluxcd.io is forbidden";
        assert_eq!(
            parse_helmrelease_list(json),
            HelmReleaseSignatureOutcome::ProbeAbsent,
        );
    }

    /// The signature annotation key string is the one
    /// `tameshi::ci::ANNOTATION_SIGNATURE` constant — a regression that
    /// hard-coded a stale or typo'd annotation key (e.g.
    /// `sekiban.pleme.io/sig` or the legacy
    /// `pleme.io/sekiban-signature`) would still pass every fixture
    /// above (because those fixtures use the literal canonical key)
    /// but would fail this pin against any change to the canonical
    /// key the tameshi crate publishes. The parser sources the
    /// annotation key from `tameshi::ci::ANNOTATION_SIGNATURE` at
    /// compile time; this test pins that single source of truth.
    #[test]
    fn test_parse_uses_canonical_annotation_key() {
        let json = format!(
            r#"{{"items": [{{"metadata": {{"annotations": {{"{}": "sig"}}}}}}]}}"#,
            tameshi::ci::ANNOTATION_SIGNATURE,
        );
        assert_eq!(
            parse_helmrelease_list(&json),
            HelmReleaseSignatureOutcome::Verified,
        );
    }
}
