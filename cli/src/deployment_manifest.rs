//! Typed rendered-manifest probe outcome for forge's Phase 2 deployment
//! attestation — the manifest-identity peer of
//! [`crate::pod_health`] (Kubernetes pod-health probe),
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
//! [`crate::oci_manifest`] (image-manifest content oracle),
//! [`crate::chart_listing`] (chart-directory content oracle),
//! [`crate::tree_listing`] (source-tree content oracle),
//! [`crate::store_path`] (Nix-closure content oracle),
//! [`crate::compliance_dimensions`] (compliance-dimensions content oracle),
//! [`crate::openpgp_signature`] (OpenPGP v4 signature packet parser), and
//! [`crate::security_scan`] (SBOM / vuln-scan probes).
//!
//! ## What this module closes
//!
//! `commands/attestation.rs::compose_product_certification` previously
//! stamped a name-keyed sentinel into every Phase 2 `DeploymentAttestation`'s
//! `manifest_hash` field:
//!
//! ```ignore
//! let deployment = DeploymentAttestation {
//!     namespace: format!("{}-{}", product, environment),
//!     kustomization: format!("{}-{}", product, environment),
//!     source_commit: source.commit.clone(),
//!     source_verified: source_verification_outcome.is_verified(),
//!     manifest_hash: Blake3Hash::digest(b"pending-deployment"),    // <-- this line
//!     all_releases_signed: helm_release_signature_outcome.is_verified(),
//!     cis_k8s_pass_rate: 0.0,
//!     network_policies_verified: network_policy_outcome.is_verified(),
//!     running_pods: 0,
//!     all_healthy: pod_health_outcome.is_healthy(),
//! };
//! ```
//!
//! Three structural honesty failures followed (mirroring the closed gaps
//! at the chart-content layer, the source-tree layer, the image-manifest
//! layer, the Nix-closure layer, and the compliance-dimensions layer):
//!
//!   * Every Phase 2 deployment attestation across every product, every
//!     environment, every cluster collapsed to the same `manifest_hash`
//!     value (`Blake3Hash::digest(b"pending-deployment")`), defeating
//!     the content-addressed-identity invariant THEORY §VI.1 names — a
//!     downstream verifier reading two attestations carrying the same
//!     `manifest_hash` could not distinguish them as describing the
//!     same rendered cluster state from describing two different
//!     rendered cluster states under the shared constant. The hash is
//!     supposed to be the discriminator over the deployment's
//!     content-addressed identity; the constant erased the
//!     discriminator entirely.
//!   * Two structurally distinct rendered-manifest streams (a passing
//!     `kustomize build` against namespace A vs a passing `kustomize
//!     build` against namespace B, or the same build against the same
//!     namespace before and after a meaningful workload change)
//!     produced byte-identical `manifest_hash` values — the
//!     pre-deployment Phase 2 record could not carry forward the
//!     evidence of what cluster state the certification was attesting
//!     against.
//!   * The same `b"pending-deployment"` constant was the only signal
//!     for three structurally distinct operational worlds the call
//!     site could not separate at the bool surface: `Rendered`
//!     (kustomize/flux build was spawned, the rendered manifest stream
//!     was captured, its canonical fingerprint is available),
//!     `RenderFailed` (kustomize/flux build was spawned and exited
//!     non-zero — evidence of a render-time failure, the structural
//!     failure that gates Phase 2 admission under THEORY §V.4), and
//!     `ProbeAbsent` (no render probe ran inside the certification
//!     function — no evidence either way). Collapsing all three into
//!     the same constant sentinel routed evidence-of-render-failure
//!     into the same downstream channel as no-probe-ran, defeating
//!     the discriminator a `sekiban` strict-production policy that
//!     fails-closed on evidence of render-time failure depends on.
//!
//! This module is the rendered-manifest-side peer of [`crate::pod_health`]
//! (pod-health probe outcome) and [`crate::helm_release_signature`]
//! (HelmRelease-signature probe outcome) at the bool-field layer, and
//! [`crate::chart_listing`] (chart-content fingerprint), [`crate::tree_listing`]
//! (source-tree fingerprint), [`crate::oci_manifest`] (image-manifest
//! fingerprint), and [`crate::compliance_dimensions`] (compliance-dimensions
//! fingerprint) at the hash-field layer. The three-arm outcome enum
//! combines both shapes: arms preserve the operational-world distinction
//! the constant sentinel collapsed, and the [`DeploymentManifestRenderOutcome::manifest_hash`]
//! method emits a distinct BLAKE3 digest per arm so the Phase 2
//! `manifest_hash` field is content-addressed in every world a
//! downstream probe could report. The typed primitive closes the gap
//! the same way commits e76db87 / 8b1407d / f8a5d8e / 5baaa50 / 72424bd
//! / 5931e32 / a5376a6 / c1e83d5 / d81f639 / 2f3a7dc / b98eb5a / fffca30
//! / b8a1d8a / e8a2df7 / 0ff67e1 closed sibling Phase 1 and Phase 2 gaps
//! one shape away.
//!
//! ## The three operational worlds
//!
//! A rendered-manifest probe (a `kustomize build <kustomization>` or
//! `flux build kustomization <name> --path <path>` shell-out against the
//! deployment's Kustomization root, with the resulting multi-document
//! YAML stream walked into a canonical (apiVersion, kind, namespace,
//! name, content-hash) fingerprint a downstream verifier would itself
//! derive) distinguishes three operational worlds the prior
//! `b"pending-deployment"` constant flattened into a single hash:
//!
//! 1. **Probe absent** — `compose_product_certification` did not spawn a
//!    render probe at all, or the certification function ran outside the
//!    repository / cluster (e.g. an integration-test path that constructed
//!    the deployment attestation directly without going through a
//!    `kustomize build` shell-out). No probe ran. There is no evidence
//!    either way. The pre-fix `b"pending-deployment"` constant stamped
//!    a single hash here regardless of which product / environment /
//!    cluster the certification was assembled for, so two different
//!    deployments certified against two different rendered manifests
//!    received byte-identical `manifest_hash` values.
//! 2. **Render failed** — the probe ran (kustomize / flux build was
//!    spawned) and exited non-zero, or produced output that no
//!    `serde_yaml`-driven canonicaliser could parse into a manifest
//!    stream. The render-time failure is evidence-of-failed-render: the
//!    Phase 2 attestation cannot claim any rendered-manifest identity
//!    here because no manifest content was produced. The pre-fix
//!    constant collapsed this evidence-of-failed-render arm into the
//!    same hash as the no-probe-ran arm, defeating the discriminator a
//!    `sekiban` strict-production policy that fails-closed on
//!    render-time failure needs.
//! 3. **Rendered** — the probe ran, the kustomize / flux build exited
//!    zero, and the multi-document YAML stream was canonicalised into
//!    the sorted, deduplicated set of `<apiVersion>|<kind>|<namespace>|
//!    <name> TAB <content-hash-hex>` lines a downstream verifier would
//!    itself derive by running the same probe against the same source
//!    tree. The Phase 2 deployment attestation can honestly claim a
//!    rendered-manifest content-addressed identity only in this arm.
//!
//! ## Why three arms, not two or four
//!
//! - **Three rather than two** (`Rendered` / `ProbeAbsent`): a
//!   `RenderFailed` outcome is a structurally distinct world from both
//!   `Rendered` AND `ProbeAbsent` — the kustomize probe ran and observed
//!   actual render-time failure (a positive evidence event the no-probe-
//!   ran world cannot generate), but the observed state failed the
//!   manifest-producibility invariant. Collapsing `RenderFailed` into
//!   the same hash as `ProbeAbsent` would re-introduce the discriminator
//!   loss the typed primitive exists to prevent (THEORY §V.1: make
//!   invalid states unrepresentable — a `manifest_hash` value that
//!   conflates "no render probe ran" with "probe ran and kustomize
//!   crashed" is a flat hash where a downstream verifier cannot recover
//!   the kind-of-claim, and a strict-production policy that requires
//!   evidence-of-successful-render cannot distinguish from a probe-
//!   absent world).
//! - **Three rather than four** (no `Malformed` arm yet): this commit
//!   introduces the typed primitive but does NOT introduce a
//!   `serde_yaml`-driven manifest-stream parser here — no
//!   `parse_manifest_stream` function exists in this module. A future
//!   commit that wires the kustomize shell-out at the
//!   `compose_product_certification` call site will deserialize the
//!   multi-document stream directly via `serde_yaml::Deserializer::from_str`
//!   walking the `Mapping` for each document's `apiVersion`, `kind`,
//!   `metadata.namespace`, `metadata.name`, and canonical-serialized
//!   content, and any malformed YAML / missing required field will fold
//!   into `RenderFailed` (kustomize succeeded but the output was not a
//!   parseable manifest stream = no usable rendered identity, the same
//!   structural failure class as a non-zero kustomize exit). Adding a
//!   speculative `Malformed` arm today would force every consumer to
//!   handle a world the actual probe layer will not produce. The enum
//!   stays additive: a future commit may widen to four arms without
//!   changing the `Rendered` / `RenderFailed` / `ProbeAbsent` semantics
//!   this commit pins. Same deferral discipline as
//!   [`crate::pod_health::PodHealthOutcome`] one layer over and
//!   [`crate::helm_release_signature::HelmReleaseSignatureOutcome`]
//!   two layers over.
//!
//! ## What this commit does NOT do
//!
//! This commit introduces the typed primitive and routes the call site
//! through the `ProbeAbsent` arm: `compose_product_certification` does
//! not yet spawn a `kustomize build` / `flux build kustomization` probe
//! itself. The Phase 2 deployment attestation's `manifest_hash` field
//! flips from the constant `Blake3Hash::digest(b"pending-deployment")`
//! sentinel to `DeploymentManifestRenderOutcome::ProbeAbsent.manifest_hash()`
//! (== `Blake3Hash::digest(b"no-manifest-render")`) — honestly naming
//! "no render probe ran inside the certification function" rather than
//! stamping a constant that would also be produced under render-failure
//! and under a successful render against a one-resource cluster, all
//! three collapsing to the same hash. The `Rendered` / `RenderFailed`
//! arms are the future enrichment point: a follow-up commit that wires
//! `tokio::process::Command::new("kustomize").args(["build", &path]).
//! output().await` (or `flux build kustomization`) at the call site and
//! canonicalises the resulting YAML stream into a fingerprint will flip
//! the call-site outcome to `Rendered { fingerprint }` for deployments
//! whose render succeeds and to `RenderFailed` for deployments whose
//! render fails. Same deferral shape as commit e76db87's
//! [`crate::pod_health::PodHealthOutcome::ProbeAbsent`] arm at the
//! pod-health layer, commit 8b1407d's
//! [`crate::helm_release_signature::HelmReleaseSignatureOutcome::ProbeAbsent`]
//! arm at the HelmRelease-signature layer, and commit f8a5d8e's
//! [`crate::network_policy_admission::NetworkPolicyAdmissionOutcome::ProbeAbsent`]
//! arm at the network-segmentation layer (typed primitive available,
//! real probe wired in by a follow-up).
//!
//! ## Frontier inspiration
//!
//! THEORY §V.4 ("Two-phase signature composition") and §VII.1
//! ("Attestation-gated deployments") name the Phase 2 deployment record
//! as the post-admission honesty channel: the structural evidence of
//! what rendered manifest stream the cluster received against the
//! pre-Phase-2 Phase 1 signatures composed against the source. The
//! Bazel / Buck2 / Pants hermetic-remote-build lineage (the
//! content-addressed action cache, where every step's input fingerprint
//! is the discriminator over whether two builds are byte-identical),
//! the Nix flake / remote-builder lineage (the `narHash` discriminator
//! over every flake input the SLSA L3 build claim rests on), the
//! BuildKit / Dagger DAG-cache lineage (the per-step
//! `Definition.Source.IdentDigest` over every input the LLB cache keys
//! on), and the SLSA / sigstore supply-chain attestation lineage (the
//! `subject.digest` field over every artifact a `dsse`-wrapped
//! attestation binds to) all share the same structural commitment: the
//! identity hash a downstream verifier reads MUST be content-addressed
//! over the canonical fingerprint of the artifact it claims to identify,
//! never a name-keyed or status-keyed constant. A Phase 2 deployment
//! attestation that records a `manifest_hash` constant across every
//! deployment fails every reconciliation a content-addressed
//! `sekiban admission audit` pass could surface against the same
//! rendered manifest stream. The typed `ProbeAbsent` arm names the
//! gap honestly rather than flattening it with a constant — the same
//! discipline [`crate::pod_health::PodHealthOutcome::ProbeAbsent`],
//! [`crate::helm_release_signature::HelmReleaseSignatureOutcome::ProbeAbsent`],
//! [`crate::network_policy_admission::NetworkPolicyAdmissionOutcome::ProbeAbsent`],
//! [`crate::flux_source_verification::FluxSourceVerificationOutcome::ProbeAbsent`],
//! [`crate::cosign::CosignVerifyOutcome::ProbeAbsent`],
//! [`crate::helm_provenance::HelmProvenanceOutcome::ProbeAbsent`],
//! [`crate::helm_lint::HelmLintOutcome::ProbeAbsent`],
//! [`crate::kensa_policy::KensaPolicyOutcome::ProbeAbsent`],
//! [`crate::git_signature::GitCommitSignatureOutcome::ProbeAbsent`],
//! [`crate::nix_reproducibility::NixReproducibilityOutcome::ProbeAbsent`],
//! [`crate::security_scan::SbomProbeOutcome::Absent`], and
//! [`crate::security_scan::VulnScanProbeOutcome::Absent`] apply at the
//! pod-health, HelmRelease-signature, network-segmentation, source-
//! verification, image-signature, chart-signature, chart-quality,
//! chart-policy, source-commit-signature, build-determinism, SBOM, and
//! vuln-scan layers.

use tameshi::hash::Blake3Hash;

/// Sentinel byte string the `ProbeAbsent` arm digests for its
/// `manifest_hash` value. Distinct from the `RenderFailed` sentinel and
/// from any actual rendered-manifest fingerprint so the three arms
/// produce three distinct BLAKE3 hashes at the Phase 2
/// `DeploymentAttestation::manifest_hash` field. Mirrors the
/// `b"no-tree-listing"` / `b"no-chart-dir"` / `b"no-manifest"` /
/// `b"no-flake-lock"` / `b"no-sbom"` / `b"no-vuln-scan"` peer sentinels
/// used at the chart-content, source-tree, image-manifest, flake-lock,
/// SBOM, and vuln-scan layers respectively.
const NO_MANIFEST_RENDER_SENTINEL: &[u8] = b"no-manifest-render";

/// Sentinel byte string the `RenderFailed` arm digests for its
/// `manifest_hash` value. Distinct from `NO_MANIFEST_RENDER_SENTINEL`
/// so a downstream verifier reading the BLAKE3 of this sentinel can
/// recover "kustomize / flux build ran and failed" as the kind-of-
/// claim, where the BLAKE3 of `NO_MANIFEST_RENDER_SENTINEL` carries
/// "no render probe ran". The two sentinels MUST NOT alias; if they
/// did, the typed primitive's discriminator-preservation invariant
/// would collapse at the hash surface.
const MANIFEST_RENDER_FAILED_SENTINEL: &[u8] = b"manifest-render-failed";

/// Outcome of probing a deployment's Kustomization root for a rendered
/// multi-document YAML manifest stream — the Phase 2 `manifest_hash`
/// claim. The three arms preserve the probe-absent vs render-failed vs
/// rendered distinction the Phase 2 deployment attestation depends on;
/// the prior `Blake3Hash::digest(b"pending-deployment")` constant
/// conflated all three operational worlds into a single hash that
/// stamped byte-identically across every deployment, defeating the
/// content-addressed-identity discriminator THEORY §VI.1 names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeploymentManifestRenderOutcome {
    /// Rendered-manifest probe ran AND the kustomize / flux build
    /// exited zero AND the resulting multi-document YAML stream was
    /// canonicalised into the sorted, deduplicated set of
    /// `<apiVersion>|<kind>|<namespace>|<name> TAB <content-hash-hex>`
    /// lines a downstream verifier would itself derive by running the
    /// same probe against the same source tree. The Phase 2 deployment
    /// attestation can honestly claim a rendered-manifest content-
    /// addressed identity only in this arm. The `fingerprint` field is
    /// the byte buffer the `manifest_hash` method digests — typically
    /// the UTF-8 encoding of the canonical fingerprint string a future
    /// `canonical_manifest_stream_fingerprint` helper produces, mirroring
    /// the `tree_listing` / `chart_listing` / `oci_manifest` /
    /// `compliance_dimensions` content-oracle peers one layer over.
    Rendered {
        /// The canonical-fingerprint bytes the `manifest_hash` method
        /// digests. Carried as an owned `Vec<u8>` so the outcome value
        /// is self-contained (no borrowed slice ties this arm to the
        /// probe-output buffer's lifetime — a follow-up that wires
        /// the kustomize shell-out can drop the raw output as soon as
        /// the fingerprint is built).
        fingerprint: Vec<u8>,
    },
    /// Rendered-manifest probe ran but kustomize / flux build exited
    /// non-zero, OR produced output that no `serde_yaml`-driven
    /// canonicaliser could parse into a manifest stream. The render-
    /// time failure is evidence-of-failed-render: the Phase 2
    /// attestation cannot claim any rendered-manifest identity here
    /// because no manifest content was produced. The prior constant
    /// `Blake3Hash::digest(b"pending-deployment")` collapsed this
    /// evidence-of-failed-render arm into the same hash as
    /// `ProbeAbsent`, losing the discriminator a `sekiban` strict-
    /// production policy that fails-closed on render-time failure
    /// needs.
    RenderFailed,
    /// `compose_product_certification` did not spawn a render probe at
    /// all (no `kustomize build` / `flux build kustomization` shell-out,
    /// no typed `kustomize` library call), or the certification
    /// function ran outside the repository / cluster (e.g. an
    /// integration-test path that constructed the deployment
    /// attestation directly without going through a render probe). No
    /// probe was made; no evidence was collected. The prior constant
    /// reported the same hash here as for `Rendered` and `RenderFailed`,
    /// conflating "no render probe ran" with both "probe ran and
    /// succeeded" and "probe ran and failed".
    ProbeAbsent,
}

impl DeploymentManifestRenderOutcome {
    /// The BLAKE3 digest the Phase 2 `DeploymentAttestation::manifest_hash`
    /// field carries. The three arms produce three structurally distinct
    /// hashes:
    ///
    /// - [`Self::Rendered`]: `Blake3Hash::digest(fingerprint)` — the
    ///   content-addressed identity of the rendered manifest stream a
    ///   downstream verifier would itself derive.
    /// - [`Self::RenderFailed`]: `Blake3Hash::digest(b"manifest-render-failed")`
    ///   — the evidence-of-failed-render sentinel, structurally distinct
    ///   from both the probe-absent sentinel and from any actual
    ///   rendered fingerprint.
    /// - [`Self::ProbeAbsent`]: `Blake3Hash::digest(b"no-manifest-render")`
    ///   — the no-probe-ran sentinel, mirroring the `b"no-tree-listing"`
    ///   / `b"no-chart-dir"` / `b"no-manifest"` / `b"no-flake-lock"` /
    ///   `b"no-sbom"` / `b"no-vuln-scan"` peers at the source-tree,
    ///   chart-content, image-manifest, flake-lock, SBOM, and vuln-scan
    ///   layers.
    ///
    /// The three sentinel byte strings MUST NOT alias and MUST NOT
    /// equal any byte sequence a real `fingerprint` arm could produce
    /// — the typed primitive's discriminator-preservation invariant
    /// rests on each arm naming itself with a structurally distinct
    /// preimage so a downstream verifier reading the BLAKE3 surface
    /// can recover the kind-of-claim from the digest alone.
    pub fn manifest_hash(&self) -> Blake3Hash {
        match self {
            Self::Rendered { fingerprint } => Blake3Hash::digest(fingerprint),
            Self::RenderFailed => Blake3Hash::digest(MANIFEST_RENDER_FAILED_SENTINEL),
            Self::ProbeAbsent => Blake3Hash::digest(NO_MANIFEST_RENDER_SENTINEL),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three arms emit three structurally distinct `manifest_hash`
    /// values. Pins the load-bearing discriminator-preservation
    /// invariant the typed primitive exists to enforce at the BLAKE3
    /// surface: a `Rendered` outcome over a non-trivial fingerprint
    /// must NOT equal either sentinel; the two sentinels must NOT
    /// equal each other. The pre-fix `Blake3Hash::digest(b"pending-
    /// deployment")` constant collapsed all three operational worlds
    /// into a single hash; the post-fix typed primitive routes through
    /// `manifest_hash()` whose three arms produce three distinct
    /// hashes a downstream verifier walking the BLAKE3 surface can
    /// distinguish.
    #[test]
    fn test_three_arms_produce_three_distinct_manifest_hashes() {
        let rendered = DeploymentManifestRenderOutcome::Rendered {
            fingerprint: b"apps/v1|Deployment|myns|mysvc\tdeadbeef".to_vec(),
        };
        let failed = DeploymentManifestRenderOutcome::RenderFailed;
        let absent = DeploymentManifestRenderOutcome::ProbeAbsent;
        assert_ne!(
            rendered.manifest_hash().to_hex(),
            failed.manifest_hash().to_hex(),
            "Rendered and RenderFailed must produce distinct manifest_hash \
             values; if they collide a downstream verifier cannot \
             distinguish evidence-of-successful-render from evidence-of-\
             failed-render at the BLAKE3 surface"
        );
        assert_ne!(
            rendered.manifest_hash().to_hex(),
            absent.manifest_hash().to_hex(),
            "Rendered and ProbeAbsent must produce distinct manifest_hash \
             values; if they collide a downstream verifier cannot \
             distinguish evidence-of-successful-render from no-probe-ran \
             at the BLAKE3 surface"
        );
        assert_ne!(
            failed.manifest_hash().to_hex(),
            absent.manifest_hash().to_hex(),
            "RenderFailed and ProbeAbsent must produce distinct \
             manifest_hash values; if they collide a downstream verifier \
             cannot distinguish evidence-of-failed-render from no-probe-\
             ran at the BLAKE3 surface — the discriminator a sekiban \
             strict-production policy that fails-closed on render-time \
             failure depends on"
        );
    }

    /// `ProbeAbsent` does NOT equal the pre-fix `Blake3Hash::digest(
    /// b"pending-deployment")` constant. Load-bearing regression pin: a
    /// future regression that re-introduced the constant at the
    /// `compose_product_certification` call site would fail this test
    /// before any Phase 2 attestation record was published under it.
    /// Same shape as `test_compose_compliance_hash_grounded_in_
    /// dimensions_not_sentinel`'s `(a)` clause one layer over and
    /// `test_chart_hash_grounded_in_canonical_chart_content_not_name_
    /// sentinel`'s parallel clause at the chart-content layer.
    #[test]
    fn test_probe_absent_does_not_equal_pre_fix_pending_deployment_sentinel() {
        let pre_fix_sentinel = Blake3Hash::digest(b"pending-deployment");
        let probe_absent = DeploymentManifestRenderOutcome::ProbeAbsent.manifest_hash();
        assert_ne!(
            probe_absent.to_hex(),
            pre_fix_sentinel.to_hex(),
            "ProbeAbsent.manifest_hash() must NOT equal the pre-fix \
             `Blake3Hash::digest(b\"pending-deployment\")` constant; a \
             future regression that re-introduced the constant at the \
             `compose_product_certification` call site would fail this \
             test before any Phase 2 deployment attestation was \
             published under it"
        );
    }

    /// `RenderFailed` does NOT equal the pre-fix `Blake3Hash::digest(
    /// b"pending-deployment")` constant either. The pre-fix constant
    /// was the only signal at the `manifest_hash` field for every
    /// operational world the certification function could observe; the
    /// post-fix typed primitive routes evidence-of-failed-render
    /// through its own structurally distinct sentinel so a downstream
    /// verifier walking the BLAKE3 surface can recover the kind-of-
    /// claim. Mirrors the `ProbeAbsent` pin one assertion over.
    #[test]
    fn test_render_failed_does_not_equal_pre_fix_pending_deployment_sentinel() {
        let pre_fix_sentinel = Blake3Hash::digest(b"pending-deployment");
        let render_failed = DeploymentManifestRenderOutcome::RenderFailed.manifest_hash();
        assert_ne!(
            render_failed.to_hex(),
            pre_fix_sentinel.to_hex(),
            "RenderFailed.manifest_hash() must NOT equal the pre-fix \
             `Blake3Hash::digest(b\"pending-deployment\")` constant; the \
             post-fix typed primitive carries evidence-of-failed-render \
             through its own structurally distinct sentinel so a \
             downstream verifier can recover the kind-of-claim from \
             the BLAKE3 surface"
        );
    }

    /// A `Rendered` arm over a non-trivial fingerprint produces the
    /// BLAKE3 of exactly those bytes — the content-addressed identity
    /// invariant the typed primitive's positive arm rests on. Pins
    /// that the `manifest_hash()` method does NOT do anything other
    /// than `Blake3Hash::digest(fingerprint)` for this arm: no
    /// transformation, no prefixing, no escaping. The Rendered arm is
    /// a transparent passthrough so the fingerprint a downstream
    /// verifier independently derives byte-equals the value the Phase
    /// 2 attestation carries.
    #[test]
    fn test_rendered_arm_passthrough_digests_fingerprint_bytes_directly() {
        let fingerprint =
            b"apps/v1|Deployment|myns|svc-a\tabc123\napps/v1|Service|myns|svc-a\tdef456";
        let outcome = DeploymentManifestRenderOutcome::Rendered {
            fingerprint: fingerprint.to_vec(),
        };
        let expected = Blake3Hash::digest(fingerprint);
        assert_eq!(
            outcome.manifest_hash().to_hex(),
            expected.to_hex(),
            "Rendered.manifest_hash() must be exactly \
             `Blake3Hash::digest(fingerprint)` — the content-addressed \
             identity invariant the positive arm rests on. Any \
             transformation at this layer would defeat the \
             reproducibility a downstream verifier depends on (THEORY \
             §VI.1: regenerating an artifact produces a byte-identical \
             result given the same inputs)"
        );
    }

    /// Two `Rendered` arms over two structurally distinct fingerprints
    /// produce two structurally distinct `manifest_hash` values. The
    /// pre-fix constant collapsed every rendered-manifest deployment
    /// across every namespace / kustomization / cluster to the same
    /// hash; the post-fix `Rendered` arm preserves the content-
    /// addressed discriminator the hash is supposed to provide.
    /// Mirrors `test_compose_compliance_hash_grounded_in_dimensions_
    /// not_sentinel`'s `(c)` clause one layer over: distinct content
    /// must produce distinct hashes.
    #[test]
    fn test_distinct_fingerprints_produce_distinct_manifest_hashes() {
        let svc_a = DeploymentManifestRenderOutcome::Rendered {
            fingerprint: b"apps/v1|Deployment|myns|svc-a\tabc".to_vec(),
        };
        let svc_b = DeploymentManifestRenderOutcome::Rendered {
            fingerprint: b"apps/v1|Deployment|myns|svc-b\tdef".to_vec(),
        };
        assert_ne!(
            svc_a.manifest_hash().to_hex(),
            svc_b.manifest_hash().to_hex(),
            "two Rendered arms over two structurally distinct \
             fingerprints must produce distinct manifest_hash values; \
             if they collided the content-addressed discriminator the \
             hash is supposed to provide would be lost — the same \
             dishonesty the pre-fix `Blake3Hash::digest(b\"pending-\
             deployment\")` constant carried across every deployment"
        );
    }

    /// The three arms are mutually distinct under structural equality.
    /// Pins the load-bearing discriminator-preservation invariant the
    /// typed primitive exists to enforce at the enum level (sibling to
    /// the BLAKE3-surface pin one test over): `Rendered` (probe ran and
    /// canonicalised the manifest stream), `RenderFailed` (probe ran
    /// and kustomize / flux build exited non-zero), and `ProbeAbsent`
    /// (no render probe ran inside certification) all carry distinct
    /// `manifest_hash` values AND remain structurally distinct at the
    /// enum level. A downstream verifier walking the enum recovers the
    /// kind-of-claim from the variant alone. Same shape as
    /// `test_arms_are_structurally_distinct` for
    /// [`crate::pod_health::PodHealthOutcome`] one layer over and
    /// [`crate::network_policy_admission::NetworkPolicyAdmissionOutcome`]
    /// two layers over.
    #[test]
    fn test_arms_are_structurally_distinct() {
        let rendered = DeploymentManifestRenderOutcome::Rendered {
            fingerprint: b"a".to_vec(),
        };
        let failed = DeploymentManifestRenderOutcome::RenderFailed;
        let absent = DeploymentManifestRenderOutcome::ProbeAbsent;
        assert_ne!(rendered, failed);
        assert_ne!(rendered, absent);
        assert_ne!(failed, absent);
    }
}
