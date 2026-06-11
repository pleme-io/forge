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
crate::impl_verified_outcome!(FluxSourceVerificationOutcome);

/// Parse the JSON output of `kubectl get gitrepository <name> -n <ns>
/// -o json` (or the equivalent `kube::Api::<GitRepository>::get(...)`
/// serialization) and recover the typed
/// [`FluxSourceVerificationOutcome`] for the source's `SourceVerified`
/// condition.
///
/// The function is the parser-layer peer of
/// [`crate::helm_lint::parse_lint_output`] one layer over:
/// `parse_lint_output` recovers the typed
/// [`crate::helm_lint::HelmLintOutcome`] from `helm lint` text-mode
/// summary lines; this function recovers
/// [`FluxSourceVerificationOutcome`] from the JSON-encoded
/// `source.toolkit.fluxcd.io/v1` `GitRepository.status.conditions`
/// surface. A follow-up commit that wires
/// `tokio::process::Command::new("kubectl").args(["get",
/// "gitrepository", &name, "-n", &namespace, "-o", "json"])` (or a typed
/// `kube::Api::<GitRepository>::get(...)`) at the
/// [`crate::commands::attestation::compose_product_certification`] call
/// site composes the shell-out with this parser to route the call site
/// out of its current unconditional [`Self::ProbeAbsent`] arm.
///
/// ## The three-arm mapping
///
/// 1. The JSON deserializes AND `.status.conditions[]` contains an
///    entry with `type == "SourceVerified"` AND `status == "True"` →
///    [`Self::Verified`]. FluxCD's source-controller verified the
///    commit signature against the bundle's keyring within the last
///    reconciliation interval; the Phase 2 deployment attestation can
///    honestly claim `source_verified: true`.
/// 2. The JSON deserializes AND `.status.conditions[]` contains an
///    entry with `type == "SourceVerified"` AND `status == "False"` →
///    [`Self::VerifyFailed`]. FluxCD's source-controller observed the
///    `GitRepository` and emitted the condition, but the verification
///    did not succeed (signature mismatch, missing key in keyring, etc.).
///    Phase 2 cannot claim `source_verified: true`; the discriminator
///    distinguishes this "probe ran and reported negative" world from
///    the "probe never ran" world the [`Self::ProbeAbsent`] arm names.
/// 3. Every other input — malformed JSON, missing `status`, missing
///    `conditions`, no `SourceVerified` entry in the array, a
///    `SourceVerified` entry with `status` equal to `"Unknown"` or any
///    other non-`True`/`False` value — folds into [`Self::ProbeAbsent`].
///    The module-level docstring names this fold explicitly: "any
///    malformed JSON / missing condition will fold into `ProbeAbsent`
///    (response received but no usable evidence = no-evidence-
///    collected)." The parser is exit-agnostic by construction — exit
///    code is not consulted; a kubectl failure surfaces upstream as a
///    [`Self::ProbeAbsent`] outcome chosen at the shell-out call site
///    rather than as a parser arm.
///
/// THEORY §V.2: attestation is cryptographic evidence, not a wish. The
/// parser preserves the structural distinction between "probe ran and
/// reported negative" and "no probe ran / no usable evidence" — the
/// pre-typed `true` hardcode collapsed both into a single positive
/// claim.
#[allow(dead_code)]
pub fn parse_gitrepository_status(json_text: &str) -> FluxSourceVerificationOutcome {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(json_text) else {
        return FluxSourceVerificationOutcome::ProbeAbsent;
    };
    let Some(conditions) = value
        .get("status")
        .and_then(|status| status.get("conditions"))
        .and_then(|conditions| conditions.as_array())
    else {
        return FluxSourceVerificationOutcome::ProbeAbsent;
    };
    for condition in conditions {
        if condition.get("type").and_then(|t| t.as_str()) != Some("SourceVerified") {
            continue;
        }
        return match condition.get("status").and_then(|s| s.as_str()) {
            Some("True") => FluxSourceVerificationOutcome::Verified,
            Some("False") => FluxSourceVerificationOutcome::VerifyFailed,
            _ => FluxSourceVerificationOutcome::ProbeAbsent,
        };
    }
    FluxSourceVerificationOutcome::ProbeAbsent
}

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

    /// A canonical `kubectl get gitrepository -o json` response whose
    /// `status.conditions[]` array carries a `SourceVerified=True`
    /// entry — the world FluxCD's source-controller produces after
    /// fetching the commit, resolving the bundle, and verifying the
    /// signature against the keyring within the last reconciliation
    /// interval. Parses to [`FluxSourceVerificationOutcome::Verified`]
    /// — the one arm that lets the Phase 2 deployment attestation
    /// honestly claim `source_verified: true`.
    #[test]
    fn test_parse_source_verified_true_yields_verified() {
        let json = r#"{
            "apiVersion": "source.toolkit.fluxcd.io/v1",
            "kind": "GitRepository",
            "status": {
                "conditions": [
                    {"type": "Ready", "status": "True"},
                    {"type": "SourceVerified", "status": "True",
                     "reason": "Succeeded",
                     "message": "verified signature of revision main@sha1:abc"}
                ]
            }
        }"#;
        assert_eq!(
            parse_gitrepository_status(json),
            FluxSourceVerificationOutcome::Verified,
        );
    }

    /// A `kubectl get gitrepository -o json` response whose
    /// `status.conditions[]` carries a `SourceVerified=False` entry —
    /// the world FluxCD's source-controller produces when signature
    /// verification fails (the keyring did not match the commit
    /// signature, or an explicit verify failure). Parses to
    /// [`FluxSourceVerificationOutcome::VerifyFailed`]. The
    /// discriminator distinguishes this "probe ran and reported
    /// negative" world from the "no probe ran" world the
    /// [`FluxSourceVerificationOutcome::ProbeAbsent`] arm names —
    /// the load-bearing structural distinction the pre-typed `true`
    /// hardcode erased.
    #[test]
    fn test_parse_source_verified_false_yields_verify_failed() {
        let json = r#"{
            "status": {
                "conditions": [
                    {"type": "SourceVerified", "status": "False",
                     "reason": "VerificationFailed",
                     "message": "no matching key in bundle"}
                ]
            }
        }"#;
        assert_eq!(
            parse_gitrepository_status(json),
            FluxSourceVerificationOutcome::VerifyFailed,
        );
    }

    /// A `kubectl get gitrepository -o json` response whose
    /// `status.conditions[]` carries no `SourceVerified` entry at all
    /// — the world where `GitRepository.spec.verify` is not
    /// configured for the source, so the source-controller never
    /// emits the condition. The module-level docstring names this
    /// fold explicitly: "any malformed JSON / missing condition will
    /// fold into `ProbeAbsent`." Parses to
    /// [`FluxSourceVerificationOutcome::ProbeAbsent`]. A regression
    /// that collapsed this case into [`FluxSourceVerificationOutcome::
    /// VerifyFailed`] would conflate "verify is not configured" with
    /// "verify is configured and reported negative" — two structurally
    /// distinct worlds the typed primitive preserves.
    #[test]
    fn test_parse_missing_source_verified_condition_yields_probe_absent() {
        let json = r#"{
            "status": {
                "conditions": [
                    {"type": "Ready", "status": "True"},
                    {"type": "Reconciling", "status": "False"}
                ]
            }
        }"#;
        assert_eq!(
            parse_gitrepository_status(json),
            FluxSourceVerificationOutcome::ProbeAbsent,
        );
    }

    /// A response missing the `status` block entirely — the world a
    /// `GitRepository` resource exists at but the source-controller
    /// has not yet reconciled it (no status fields populated). Parses
    /// to [`FluxSourceVerificationOutcome::ProbeAbsent`] — no usable
    /// evidence, the parser is exit-agnostic by construction.
    #[test]
    fn test_parse_missing_status_block_yields_probe_absent() {
        let json = r#"{
            "apiVersion": "source.toolkit.fluxcd.io/v1",
            "kind": "GitRepository",
            "spec": {"url": "https://example.com/repo.git"}
        }"#;
        assert_eq!(
            parse_gitrepository_status(json),
            FluxSourceVerificationOutcome::ProbeAbsent,
        );
    }

    /// A response whose `status.conditions` is an empty array.
    /// Reconciliation has run but emitted no conditions yet (an
    /// intermediate state). Parses to [`FluxSourceVerificationOutcome::
    /// ProbeAbsent`].
    #[test]
    fn test_parse_empty_conditions_array_yields_probe_absent() {
        let json = r#"{"status": {"conditions": []}}"#;
        assert_eq!(
            parse_gitrepository_status(json),
            FluxSourceVerificationOutcome::ProbeAbsent,
        );
    }

    /// A `SourceVerified` condition with a `status` value of
    /// `"Unknown"` — the standard Kubernetes condition-status tristate
    /// the source-controller may emit transiently while reconciliation
    /// is in-flight (per the `metav1.ConditionStatus` enum used by
    /// every K8s controller). Parses to
    /// [`FluxSourceVerificationOutcome::ProbeAbsent`]: no positive
    /// `True` evidence and no explicit `False` verdict either, so the
    /// honest collapse is into the no-usable-evidence arm. A
    /// regression that mapped `"Unknown"` to
    /// [`FluxSourceVerificationOutcome::VerifyFailed`] would seal a
    /// negative Phase 2 verdict against a state where the controller
    /// has not yet completed verification.
    #[test]
    fn test_parse_unknown_status_yields_probe_absent() {
        let json = r#"{
            "status": {
                "conditions": [
                    {"type": "SourceVerified", "status": "Unknown",
                     "reason": "Progressing"}
                ]
            }
        }"#;
        assert_eq!(
            parse_gitrepository_status(json),
            FluxSourceVerificationOutcome::ProbeAbsent,
        );
    }

    /// Malformed JSON — the world a kubectl shell-out failed entirely
    /// (the command produced text on stderr that is not parseable as
    /// JSON, or the resource was not found). The module-level
    /// docstring names this fold explicitly. Parses to
    /// [`FluxSourceVerificationOutcome::ProbeAbsent`]. A regression
    /// that panicked on unparseable input would surface the shell-out
    /// failure as a runtime panic rather than as an honest
    /// no-evidence-collected outcome.
    #[test]
    fn test_parse_malformed_json_yields_probe_absent() {
        let json = "Error from server (NotFound): gitrepositories.source.toolkit.fluxcd.io \"missing\" not found";
        assert_eq!(
            parse_gitrepository_status(json),
            FluxSourceVerificationOutcome::ProbeAbsent,
        );
    }

    /// A `SourceVerified` condition appears AFTER several unrelated
    /// conditions in the `conditions[]` array — the parser walks the
    /// full array rather than peeking at the first entry. Pins that
    /// the parser is order-independent over the conditions array; a
    /// future regression that hard-coded `conditions[0]` would fail
    /// this test.
    #[test]
    fn test_parse_source_verified_after_other_conditions_yields_verified() {
        let json = r#"{
            "status": {
                "conditions": [
                    {"type": "Ready", "status": "True"},
                    {"type": "Reconciling", "status": "False"},
                    {"type": "Stalled", "status": "False"},
                    {"type": "SourceVerified", "status": "True"}
                ]
            }
        }"#;
        assert_eq!(
            parse_gitrepository_status(json),
            FluxSourceVerificationOutcome::Verified,
        );
    }

    /// A `SourceVerified` condition with the `status` field omitted
    /// — a malformed condition entry that does not present a verdict.
    /// Parses to [`FluxSourceVerificationOutcome::ProbeAbsent`]. The
    /// parser does not guess the verdict from absence of the
    /// `status` field; the honest collapse is into no-usable-evidence.
    #[test]
    fn test_parse_source_verified_without_status_field_yields_probe_absent() {
        let json = r#"{
            "status": {
                "conditions": [
                    {"type": "SourceVerified", "reason": "Pending"}
                ]
            }
        }"#;
        assert_eq!(
            parse_gitrepository_status(json),
            FluxSourceVerificationOutcome::ProbeAbsent,
        );
    }
}
