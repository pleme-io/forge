//! Typed FluxCD `GitRepository.status.SourceVerified` probe outcome for
//! forge's Phase 2 deployment attestation — the deployment-side peer of
//! [`crate::cosign`] (image-signature probe),
//! [`crate::helm_provenance`] (chart-signature probe),
//! [`crate::helm_lint`] (chart-quality probe),
//! [`crate::kensa_policy`] (chart-policy probe),
//! [`crate::git_signature`] (source-commit-signature probe),
//! [`crate::oci_architecture`] (image-architecture probe),
//! [`crate::oci_manifest`] (manifest-identity oracle),
//! [`crate::openpgp_signature`] (OpenPGP v4 signature packet parser),
//! and [`crate::security_scan`] (SBOM / vuln-scan probes).
//!
//! ## What this module closes
//!
//! `commands/attestation.rs::compose_product_certification` previously
//! stamped a literal `true` into every Phase 2 `DeploymentAttestation`'s
//! `source_verified` field:
//!
//! ```ignore
//! let deployment = DeploymentAttestation {
//!     namespace: format!("{}-{}", product, environment),
//!     kustomization: format!("{}-{}", product, environment),
//!     source_commit: source.commit.clone(),
//!     source_verified: true,                                  // <-- this line
//!     manifest_hash: Blake3Hash::digest(b"pending-deployment"),
//!     all_releases_signed: false,
//!     cis_k8s_pass_rate: 0.0,
//!     network_policies_verified: false,
//!     running_pods: 0,
//!     all_healthy: false,
//! };
//! ```
//!
//! The remaining seven fields are honest: the namespace / kustomization /
//! source-commit identities flow from the typed inputs; the
//! `manifest_hash` carries the explicit `b"pending-deployment"` sentinel;
//! `all_releases_signed`, `network_policies_verified`, and `all_healthy`
//! are honestly `false` (no post-deploy probe ran inside composition);
//! `cis_k8s_pass_rate` and `running_pods` are honestly `0.0` / `0` (no
//! `kensa cis` probe, no kubectl pod listing). The `source_verified:
//! true` literal is the one dishonest claim left — composition does not
//! query FluxCD's `GitRepository` `SourceVerified` condition (or any
//! equivalent signature-verification probe) inside the certification
//! function, yet seals a positive `source_verified` claim into every
//! Phase 2 record regardless. A Phase 2 deployment attestation that
//! records `source_verified: true` against a build whose FluxCD
//! `GitRepository` was never queried — and which may not even carry a
//! `verify` block on its spec — is false by construction (THEORY §V.2:
//! attestation is cryptographic evidence, not a wish; THEORY §VII.1:
//! attestation-gated deployments are structural, not policy overlays —
//! `sekiban` admission rejects Phase 1 in production namespaces and
//! Phase 2 in production-tier policies requires `require_source_
//! verification` to hold against real evidence, not a call-site
//! constant).
//!
//! This is the same false-by-construction shape commit a5376a6 closed
//! for `commit_signed` (`.unwrap_or(false)` collapse →
//! [`crate::git_signature::GitCommitSignatureOutcome`]), commit c1e83d5
//! closed for `policy_passed` (`true` → [`crate::kensa_policy::
//! KensaPolicyOutcome`]), commit d81f639 closed for `linter_passed`
//! (`true` → [`crate::helm_lint::HelmLintOutcome`]), commit 2f3a7dc
//! closed for `signer_key_id` (`None` → [`crate::openpgp_signature::
//! SignaturePacketOutcome`]), commit b98eb5a closed for the SBOM /
//! vuln-scan hashes (name-keyed constants → [`crate::security_scan::
//! SbomProbeOutcome`] / [`crate::security_scan::VulnScanProbeOutcome`]),
//! commit fffca30 closed for the image `architecture` field (`"amd64"`
//! literal → [`crate::oci_architecture::OciArchitectureOutcome`]),
//! commit b8a1d8a closed for the chart `provenance_verified` bool
//! (`false` hardcode → [`crate::helm_provenance::HelmProvenanceOutcome`]),
//! commit 0ff67e1 closed for the image `cosign_verified` bool
//! (`is_ok()` fold → [`crate::cosign::CosignVerifyOutcome`]),
//! commit e8a2df7 closed for `chart_hash` (`Blake3Hash::digest(format!
//! ("chart-{name}", ...))` → `b"no-chart-dir"`), commit 443bd22 closed
//! for `manifest_hash` (`b"no-manifest"`), and commit 9c5a99f closed
//! for `tree_hash` (`b"no-tree-listing"`).
//!
//! ## The three operational worlds
//!
//! A FluxCD source-controller `GitRepository` probe (the
//! `source.toolkit.fluxcd.io/v1` `GitRepository.status.conditions[*]`
//! `SourceVerified` condition emitted by the reconciler after each
//! signature-verification pass against the bundle's keyring) distinguishes
//! three operational worlds the prior `true` hardcode flattened into a
//! single positive claim:
//!
//! 1. **Probe absent** — `compose_product_certification` did not query
//!    FluxCD at all, or the certification function ran outside the
//!    cluster (e.g. an integration-test path that constructed the
//!    deployment attestation directly without going through a `kubectl
//!    get gitrepository` probe). No probe ran. There is no evidence
//!    either way. The prior `true` hardcode reported a green source-
//!    verified claim against this state every time.
//! 2. **Verify failed** — the FluxCD `GitRepository.status.conditions`
//!    surface reported `SourceVerified=False`. Either the `verify` block
//!    is absent (signature-checking is not configured for the source),
//!    or the configured keyring did not match the commit signature, or
//!    the source-controller reconciliation has not yet completed. In
//!    every sub-case, there is no positive Phase 2 source-verification
//!    evidence; the prior `true` hardcode would have falsely sealed a
//!    green source-verified claim against this state.
//! 3. **Verified** — the FluxCD `GitRepository.status.conditions`
//!    surface reported `SourceVerified=True`. The reconciler verified
//!    the commit signature against the bundle's keyring within the
//!    last reconciliation interval. The Phase 2 deployment attestation
//!    can honestly claim `source_verified: true` only in this arm.
//!
//! ## Why three arms, not two or four
//!
//! - **Three rather than two** (`Verified` / `ProbeAbsent`): the
//!   `SourceVerified` condition is binary True/False by construction —
//!   a `VerifyFailed` outcome is a structurally distinct world from
//!   both `Verified` AND `ProbeAbsent`. Collapsing `VerifyFailed` into
//!   a single boolean would re-introduce the discriminator loss the
//!   typed primitive exists to prevent (THEORY §V.1: make invalid
//!   states unrepresentable — a `source_verified: false` value that
//!   conflates "no kubectl probe ran" with "probe ran and the
//!   GitRepository's SourceVerified condition was False" is a flat
//!   state where a downstream verifier cannot recover the kind-of-
//!   claim).
//! - **Three rather than four** (no `Malformed` arm yet): this commit
//!   introduces the typed primitive but does NOT introduce a parser
//!   for FluxCD's `kubectl get gitrepository -o json` output grammar —
//!   no `parse_gitrepository_status` function exists here. The
//!   `Malformed` arm in [`crate::helm_lint::HelmLintOutcome::Malformed`]
//!   is paired with [`crate::helm_lint::parse_lint_output`] over Helm's
//!   canonical summary-line grammar (Helm is an external project with a
//!   stable, documented output shape). FluxCD's `GitRepository` is a
//!   typed Kubernetes CRD whose canonical observable surface is the
//!   strongly-typed `Status.Conditions` array — when a follow-up commit
//!   wires the `kubectl` shell-out (or `kube-rs` typed query) at the
//!   `compose_product_certification` call site, the integration will
//!   deserialize the CRD response directly via the `source.toolkit.
//!   fluxcd.io/v1` schema rather than re-parse a text-mode summary,
//!   and any malformed JSON / missing condition will fold into
//!   `ProbeAbsent` (response received but no usable evidence =
//!   no-evidence-collected). Adding a speculative `Malformed` arm
//!   today would force every consumer to handle a world the actual
//!   probe layer will not produce. The enum stays additive: a future
//!   commit may widen to four arms without changing the `Verified` /
//!   `VerifyFailed` / `ProbeAbsent` semantics this commit pins. Same
//!   deferral discipline as [`crate::kensa_policy::KensaPolicyOutcome`]
//!   one layer over.
//!
//! ## What this commit does NOT do
//!
//! This commit introduces the typed primitive and routes the call site
//! through the `ProbeAbsent` arm: `compose_product_certification` does
//! not yet spawn a FluxCD GitRepository probe itself. The Phase 2
//! deployment attestation now records `source_verified: false` instead
//! of an unconditional `true`, honestly naming "no FluxCD source-
//! verification probe ran inside the certification function" rather
//! than asserting a green source-verified claim flow-control alone
//! cannot substantiate. The `Verified` / `VerifyFailed` arms are the
//! future enrichment point: a follow-up commit that wires `tokio::
//! process::Command::new("kubectl").args(["get", "gitrepository",
//! &namespace, "-o", "json"]).output().await` (or a typed `kube::Api::
//! <GitRepository>::get(...)` query) at the call site and walks the
//! resulting `status.conditions` array for the `SourceVerified` entry
//! will flip the call-site outcome to `Verified` for sources whose
//! signature verification has been confirmed by FluxCD's source-
//! controller within the last reconciliation interval. Same deferral
//! shape as commit c1e83d5's [`crate::kensa_policy::KensaPolicyOutcome::
//! ProbeAbsent`] arm, commit d81f639's [`crate::helm_lint::
//! HelmLintOutcome::ProbeAbsent`] arm, and commit b98eb5a's
//! [`crate::security_scan::SbomProbeOutcome::Absent`] /
//! [`crate::security_scan::VulnScanProbeOutcome::Absent`] arms (typed
//! primitive available, real probe wired in by a follow-up).
//!
//! ## Frontier inspiration
//!
//! FluxCD's source-controller (`source.toolkit.fluxcd.io/v1`
//! `GitRepository.spec.verify`) is the canonical pull-side signature-
//! verification surface in the GitOps lineage (cited by THEORY §VII.2:
//! FluxCD is the process manager for every cluster). Its `Status.
//! Conditions[type=SourceVerified]` condition is the typed evidence
//! channel — emitted only after the reconciler has fetched the commit,
//! resolved the bundle, and verified the signature against the keyring
//! within the reconciliation interval. SLSA v1.0 §"Source" and in-toto's
//! pull-side verification layer both treat the GitOps-controller's
//! verification verdict as evidence-bearing — never as a constant
//! asserted by the publisher. A Phase 2 deployment attestation that
//! records `source_verified: true` against a deployment whose FluxCD
//! `GitRepository` was never queried (and may not even carry a `verify`
//! block on its spec) fails every reconciliation a `flux verify
//! gitrepository` / `kubectl describe gitrepository` /
//! `in-toto verify` pass could surface against the same controller
//! state. The typed `ProbeAbsent` arm names that gap honestly rather
//! than inflating it with a constant — the same discipline
//! [`crate::cosign::CosignVerifyOutcome::ProbeAbsent`],
//! [`crate::helm_provenance::HelmProvenanceOutcome::ProbeAbsent`],
//! [`crate::helm_lint::HelmLintOutcome::ProbeAbsent`],
//! [`crate::kensa_policy::KensaPolicyOutcome::ProbeAbsent`],
//! [`crate::git_signature::GitCommitSignatureOutcome::ProbeAbsent`],
//! [`crate::security_scan::SbomProbeOutcome::Absent`], and
//! [`crate::security_scan::VulnScanProbeOutcome::Absent`] apply at the
//! image-signature, chart-signature, chart-quality, chart-policy,
//! source-commit-signature, SBOM, and vuln-scan layers.

/// Outcome of probing the FluxCD source-controller for a deployment's
/// `GitRepository.status.SourceVerified` condition. The three arms
/// preserve the probe-absent vs verify-failed vs verified distinction
/// the Phase 2 deployment attestation depends on; the prior `true`
/// hardcode conflated all three into a single positive claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FluxSourceVerificationOutcome {
    /// FluxCD source-controller reported the deployment's
    /// `GitRepository.status.conditions[type=SourceVerified]` condition
    /// as `True` within the last reconciliation interval — the
    /// reconciler verified the commit signature against the configured
    /// keyring bundle. The Phase 2 deployment attestation can honestly
    /// claim `source_verified: true` only in this arm.
    Verified,
    /// FluxCD source-controller reported the deployment's
    /// `GitRepository.status.conditions[type=SourceVerified]` condition
    /// as `False`, OR the `GitRepository` resource exists but carries
    /// no `verify` block on its `spec` (signature verification is not
    /// configured for the source), OR the reconciliation has not yet
    /// run a signature-verification pass since the last `spec` change.
    /// In every sub-case, there is no positive Phase 2 source-
    /// verification evidence; the prior `true` hardcode would have
    /// falsely sealed a green source-verified claim against this
    /// state.
    VerifyFailed,
    /// `compose_product_certification` did not query FluxCD at all
    /// (no `kubectl get gitrepository` shell-out, no typed
    /// `kube::Api::<GitRepository>::get(...)` query), or the
    /// certification function ran outside the cluster (e.g. an
    /// integration-test path that constructed the deployment
    /// attestation directly without going through a Flux probe). No
    /// probe was made; no evidence was collected. The prior `true`
    /// hardcode reported the same value here as for the `Verified`
    /// arm, conflating "no probe ran" with "FluxCD reconciled and
    /// confirmed source verification".
    ProbeAbsent,
}

impl FluxSourceVerificationOutcome {
    /// True iff the FluxCD source-controller probe ran AND reported
    /// `SourceVerified=True`. The boolean the Phase 2 deployment
    /// attestation's `source_verified` field carries. The other two
    /// arms collapse to `false` at this surface — they remain
    /// structurally distinct at the enum level so the call site can
    /// record them separately if needed (e.g. a future enrichment
    /// that surfaces the FluxCD reconciliation timestamp or the
    /// matched key-bundle identifier on the deployment attestation).
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified)
    }
}

crate::impl_probe_outcome!(FluxSourceVerificationOutcome, ProbeAbsent);

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the three-arm `is_verified` truth table: only `Verified`
    /// collapses to `true`. The other two arms collapse to `false` at
    /// the bool surface but stay structurally distinct at the enum
    /// level — same shape as `test_is_passed_pins_all_arms` for
    /// [`crate::kensa_policy::KensaPolicyOutcome`] one layer over and
    /// `test_is_verified_pins_all_arms` for
    /// [`crate::cosign::CosignVerifyOutcome`] two layers over.
    #[test]
    fn test_is_verified_pins_all_arms() {
        assert!(FluxSourceVerificationOutcome::Verified.is_verified());
        assert!(!FluxSourceVerificationOutcome::VerifyFailed.is_verified());
        assert!(!FluxSourceVerificationOutcome::ProbeAbsent.is_verified());
    }

    /// `ProbeAbsent` collapses to `source_verified: false` — the
    /// load-bearing honesty invariant. The pre-fix call site stamped
    /// `true` regardless of whether FluxCD had been probed; the typed
    /// primitive routes through `is_verified()` which returns `false`
    /// here. A downstream verifier reading `source_verified: false`
    /// from a Phase 2 deployment attestation can recover "no FluxCD
    /// source-verification probe ran inside the certification
    /// function" as one of the possible kind-of-claims, where the
    /// pre-fix `true` would have asserted "FluxCD verified the source"
    /// with no evidence to back it.
    #[test]
    fn test_probe_absent_collapses_to_false() {
        assert!(
            !FluxSourceVerificationOutcome::ProbeAbsent.is_verified(),
            "ProbeAbsent must collapse to source_verified=false; the \
             pre-fix `true` hardcode sealed a green source-verified \
             claim from nothing",
        );
    }

    /// `VerifyFailed` also collapses to `false`, but stays structurally
    /// distinct from `ProbeAbsent` at the enum level — `VerifyFailed`
    /// is the "FluxCD probe ran and reported `SourceVerified=False` (or
    /// the `verify` block is absent on the GitRepository spec)" world,
    /// while `ProbeAbsent` is the "no kubectl probe ran inside
    /// certification" world. Both collapse to the same Phase 2 bool
    /// value but carry distinct evidence semantics a future enrichment
    /// can route into a structural verdict field on
    /// `DeploymentAttestation`.
    #[test]
    fn test_verify_failed_collapses_to_false() {
        assert!(
            !FluxSourceVerificationOutcome::VerifyFailed.is_verified(),
            "VerifyFailed must collapse to source_verified=false; the \
             pre-fix `true` hardcode would have falsely sealed a green \
             source-verified claim against a FluxCD `SourceVerified=False` \
             condition",
        );
    }

    /// The three arms are mutually distinct under structural equality.
    /// Pins the load-bearing discriminator-preservation invariant the
    /// typed primitive exists to enforce: `Verified` (FluxCD reported
    /// `SourceVerified=True`), `VerifyFailed` (FluxCD reported
    /// `SourceVerified=False`, or the verify block is absent, or
    /// reconciliation has not yet run a verification pass), and
    /// `ProbeAbsent` (no kubectl probe ran inside certification) all
    /// collapse to distinct `true` / `false` shapes at the bool
    /// surface but remain structurally distinct at the enum level. A
    /// downstream verifier walking the enum recovers the kind-of-
    /// claim from the variant alone. Same shape as
    /// `test_arms_are_structurally_distinct` for
    /// [`crate::kensa_policy::KensaPolicyOutcome`] one layer over.
    #[test]
    fn test_arms_are_structurally_distinct() {
        let verified = FluxSourceVerificationOutcome::Verified;
        let verify_failed = FluxSourceVerificationOutcome::VerifyFailed;
        let absent = FluxSourceVerificationOutcome::ProbeAbsent;
        assert_ne!(verified, verify_failed);
        assert_ne!(verified, absent);
        assert_ne!(verify_failed, absent);
    }

    /// `ProbeOutcome` impl pin: `ProbeAbsent` identifies as absent;
    /// `Verified` and `VerifyFailed` do not.
    #[test]
    fn test_probe_outcome_impl() {
        use crate::probe_outcome::ProbeOutcome;
        assert!(FluxSourceVerificationOutcome::ProbeAbsent.is_probe_absent());
        assert!(!FluxSourceVerificationOutcome::Verified.is_probe_absent());
        assert!(!FluxSourceVerificationOutcome::VerifyFailed.is_probe_absent());
    }
}
