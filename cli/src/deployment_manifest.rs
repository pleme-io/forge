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

crate::impl_probe_outcome!(DeploymentManifestRenderOutcome, ProbeAbsent);

/// Recover the typed three-arm [`DeploymentManifestRenderOutcome`] from
/// the multi-document YAML stream a `kustomize build <kustomization>` or
/// `flux build kustomization <name> --path <path>` shell-out yields. The
/// parser is the seventh parser in the Phase 2 deployment-probe family —
/// after [`crate::flux_source_verification::parse_gitrepository_status`]
/// (commit e07d64d, three-arm over JSON `status.conditions[]`),
/// [`crate::helm_release_signature::parse_helmrelease_list`] (commit
/// 1f2f9a3, three-arm universal-quantifier over JSON
/// `items[].metadata.annotations[]`),
/// [`crate::pod_listing::parse_pod_list`] (commit 46165ef, two-arm
/// items-len count over JSON `PodList.items[]`),
/// [`crate::pod_health::parse_pod_health`] (commit c1faa28, three-arm
/// universal-quantifier over JSON `PodList.items[]`),
/// [`crate::network_policy_admission::parse_networkpolicy_list`] (commit
/// 7465feb, three-arm universal-quantifier over JSON
/// `NetworkPolicyList.items[]`), and
/// [`crate::cis_k8s_pass_rate::parse_cis_k8s_audit_json`] (commit 60c14c3,
/// two-arm ratio over JSON `{passed_controls, total_controls}`). It is the
/// FIRST parser in the family whose input is a multi-document YAML stream
/// rather than a single JSON value — the structurally distinct shape the
/// previous commit's body named as "the remaining gap … the natural next
/// leverage step".
///
/// ## What the parser closes
///
/// `commands/attestation.rs::compose_product_certification` today stamps
/// the typed primitive's [`DeploymentManifestRenderOutcome::ProbeAbsent`]
/// arm at the call site with no parser, so the Phase 2 deployment
/// attestation's `manifest_hash` field surfaces
/// `Blake3Hash::digest(b"no-manifest-render")` against every
/// certification. With the parser landed, a follow-up commit that wires
/// `tokio::process::Command::new("kustomize").args(["build", &path])
/// .output().await` at the call site can pipe the rendered stream
/// straight into [`parse_kustomize_output`] and route the call-site
/// outcome through [`DeploymentManifestRenderOutcome::Rendered { fingerprint }`]
/// / [`DeploymentManifestRenderOutcome::RenderFailed`] /
/// [`DeploymentManifestRenderOutcome::ProbeAbsent`] arms structurally
/// — no inline YAML walk at the call site, no per-call-site
/// canonical-content reconstruction, no implicit `ProbeAbsent` collapse
/// hidden in a shell-out match. The parser is testable in isolation
/// against canonical kustomize-output shapes (no cluster, no kustomize
/// binary, no kube-rs runtime), which means the shell-out call-site code
/// stays narrow (spawn + read stdout + pass to parser), and every
/// regression in the YAML-to-fingerprint map fails the parser tests
/// pinned here rather than surfacing at integration test time.
///
/// ## The three-arm mapping
///
/// 1. The YAML stream parses AND yields one or more non-null documents
///    AND every non-null document carries a string `apiVersion`, a string
///    `kind`, and a string `metadata.name` →
///    [`DeploymentManifestRenderOutcome::Rendered`] with `fingerprint`
///    set to the UTF-8 bytes of the sorted, deduplicated set of
///    `<apiVersion>|<kind>|<namespace>|<name> TAB <content-hash-hex>`
///    lines joined by `\n`, one per document. The `<namespace>` field is
///    the empty string for cluster-scoped resources (whose
///    `metadata.namespace` is legitimately absent). The
///    `<content-hash-hex>` is the lowercase-hex BLAKE3 of the canonical
///    JSON serialisation of the document — sorted-keys throughout (via
///    `serde_json::Value`'s default `BTreeMap` backing), so byte-
///    identical Kubernetes manifests with different key orderings
///    fingerprint identically. The line set is gathered into a
///    `BTreeSet<String>` for canonical ordering and dedup, mirroring the
///    same canonical-form discipline
///    [`crate::chart_listing::canonical_chart_fingerprint`] applies one
///    layer over and
///    [`crate::tree_listing::canonical_tree_fingerprint`] applies two
///    layers over.
/// 2. Every other input — malformed YAML (the stream itself is not
///    parseable), a non-mapping at any document root (e.g. a bare scalar
///    or sequence), a document missing `apiVersion`, missing `kind`, or
///    missing `metadata.name`, or an empty input that yields zero non-
///    null documents (the degenerate "kustomize was asked to render a
///    Kustomization that produced no resources" or "the stream was empty
///    altogether" world — no usable rendered identity, the same
///    structural failure class as a non-zero kustomize exit) — folds into
///    [`DeploymentManifestRenderOutcome::RenderFailed`]. Same exit-
///    agnostic, no-panic discipline the sibling parsers carry.
/// 3. [`DeploymentManifestRenderOutcome::ProbeAbsent`] is NOT a parser
///    output: it names the world where the call site did not spawn a
///    kustomize / flux build probe at all, and is constructed directly
///    by the call site when no shell-out fires. The parser maps a probe
///    that DID fire (either successfully or with parseable failure) into
///    the `Rendered` / `RenderFailed` arms only. This matches the
///    discipline at [`crate::network_policy_admission::parse_networkpolicy_list`]
///    (which produces `Verified` / `VerifyFailed` from a kubectl response
///    but leaves `ProbeAbsent` to the call site when no kubectl ran) and
///    [`crate::flux_source_verification::parse_gitrepository_status`]
///    (which produces `Verified` / `VerifyFailed` from a flux response
///    but leaves `ProbeAbsent` to the call site when no flux ran).
///
/// ## Why empty-stream collapses to `RenderFailed`, not vacuous `Rendered`
///
/// An empty multi-document YAML stream (zero `---`-separated non-null
/// documents) is the degenerate "kustomize ran and produced no rendered
/// resources" world — a Kustomization whose `resources:` field is empty,
/// or one whose every component build resulted in zero output. The
/// `Rendered` arm encodes "the canonical fingerprint of the rendered
/// manifest content"; a fingerprint over zero documents is the empty
/// string, structurally indistinguishable from any other zero-document
/// rendering and unable to discriminate one empty kustomization from
/// another at the BLAKE3 surface. The honest collapse is
/// [`DeploymentManifestRenderOutcome::RenderFailed`]: the kustomize probe
/// fired and produced no manifest content the Phase 2 attestation can
/// claim a rendered-manifest identity against. Sibling discipline:
/// [`crate::network_policy_admission::parse_networkpolicy_list`] folds
/// empty `items[]` into `VerifyFailed` (CIS §5.3.2 baseline failure on
/// an unsegmented namespace, not vacuous pass), the same shape one layer
/// over.
///
/// ## Why canonical JSON for the per-document content hash, not raw bytes
///
/// Two byte-identical Kubernetes manifests with different key orderings
/// (the kustomize output's `apiVersion` first vs `kind` first, or
/// `metadata.name` before `metadata.namespace` vs after — every
/// kustomize version produces a slightly different YAML serialisation
/// shape) must fingerprint identically: the content-addressed identity
/// invariant THEORY §VI.1 names rests on the canonical form, not on
/// any particular serialiser's output. The parser parses each document
/// into a `serde_json::Value` (whose `Map` is `BTreeMap`-backed by
/// default, sorting keys lexically), then `serde_json::to_string` emits
/// a canonical-key-order JSON serialisation. The BLAKE3 of those bytes
/// is the content-hash. A downstream verifier walking the same rendered
/// stream by running the same `kustomize build` against the same source
/// tree (potentially with a different kustomize version emitting a
/// different key order in YAML) recovers byte-identical content hashes
/// because both sides reduce through the same canonical-JSON oracle.
/// Same canonical-content discipline as
/// `commands/attestation.rs::test_manifest_hash_stable_across_key_order_and_metadata`
/// pins at the call-site layer.
///
/// THEORY §V.1: make invalid states unrepresentable. The three-arm
/// codomain `{Rendered, RenderFailed, ProbeAbsent}` is foreclosed at the
/// type level. THEORY §VI.1: one oracle, not a per-consumer re-
/// derivation. The parser is the one site that walks the multi-document
/// YAML stream into a canonical `<apiVersion>|<kind>|<namespace>|<name>
/// TAB <content-hash-hex>` fingerprint; downstream consumers pattern-
/// match the typed three-arm enum and read the canonical fingerprint
/// bytes from the `Rendered` arm. THEORY §VII.1: attestation-gated
/// deployments are structural — a `sekiban` strict-production policy
/// that fails-closed on evidence of render-time failure can express that
/// gate against the typed `RenderFailed` arm, where the pre-fix
/// `b"pending-deployment"` constant flattened it into the same hash as
/// `ProbeAbsent` and `Rendered`-over-any-stream.
#[allow(dead_code)]
pub fn parse_kustomize_output(yaml_text: &str) -> DeploymentManifestRenderOutcome {
    use serde::Deserialize;

    let mut lines: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for doc in serde_yaml::Deserializer::from_str(yaml_text) {
        let value = match serde_json::Value::deserialize(doc) {
            Ok(v) => v,
            Err(_) => return DeploymentManifestRenderOutcome::RenderFailed,
        };
        if value.is_null() {
            continue;
        }
        let Some(obj) = value.as_object() else {
            return DeploymentManifestRenderOutcome::RenderFailed;
        };
        let Some(api_version) = obj.get("apiVersion").and_then(|v| v.as_str()) else {
            return DeploymentManifestRenderOutcome::RenderFailed;
        };
        let Some(kind) = obj.get("kind").and_then(|v| v.as_str()) else {
            return DeploymentManifestRenderOutcome::RenderFailed;
        };
        let metadata = obj.get("metadata").and_then(|v| v.as_object());
        let Some(name) = metadata
            .and_then(|m| m.get("name"))
            .and_then(|v| v.as_str())
        else {
            return DeploymentManifestRenderOutcome::RenderFailed;
        };
        let namespace = metadata
            .and_then(|m| m.get("namespace"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let canonical_bytes =
            serde_json::to_vec(&value).expect("serde_json::Value always serialises to JSON bytes");
        let content_hash = blake3::hash(&canonical_bytes).to_hex().to_string();
        lines.insert(format!(
            "{api_version}|{kind}|{namespace}|{name}\t{content_hash}"
        ));
    }

    if lines.is_empty() {
        return DeploymentManifestRenderOutcome::RenderFailed;
    }

    let fingerprint = lines
        .into_iter()
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes();
    DeploymentManifestRenderOutcome::Rendered { fingerprint }
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

    /// `ProbeOutcome` impl pin: `ProbeAbsent` identifies as absent;
    /// `Rendered` and `RenderFailed` do not.
    #[test]
    fn test_probe_outcome_impl() {
        use crate::probe_outcome::ProbeOutcome;
        assert!(DeploymentManifestRenderOutcome::ProbeAbsent.is_probe_absent());
        assert!(!DeploymentManifestRenderOutcome::Rendered {
            fingerprint: b"x".to_vec(),
        }
        .is_probe_absent());
        assert!(!DeploymentManifestRenderOutcome::RenderFailed.is_probe_absent());
    }

    /// Helper: assert an outcome is `Rendered` and return its fingerprint
    /// bytes — keeps the parser tests free of pattern-match boilerplate
    /// while preserving the structural distinction at the assertion
    /// site.
    fn rendered_fingerprint(outcome: DeploymentManifestRenderOutcome) -> Vec<u8> {
        match outcome {
            DeploymentManifestRenderOutcome::Rendered { fingerprint } => fingerprint,
            other => panic!("expected Rendered, got {other:?}"),
        }
    }

    /// A canonical one-document `kustomize build` output (a single
    /// `apps/v1 Deployment` in namespace `myns`) parses to
    /// [`DeploymentManifestRenderOutcome::Rendered`] with a non-empty
    /// fingerprint whose single line carries the
    /// `apps/v1|Deployment|myns|svc-a` identity prefix the parser's
    /// canonical-line grammar names. Pins the load-bearing happy-path
    /// shape every downstream test composes against.
    #[test]
    fn test_parse_single_deployment_yields_rendered() {
        let yaml = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: svc-a
  namespace: myns
spec:
  replicas: 3
"#;
        let fp = rendered_fingerprint(parse_kustomize_output(yaml));
        let line = String::from_utf8(fp).unwrap();
        assert!(
            line.starts_with("apps/v1|Deployment|myns|svc-a\t"),
            "expected canonical line prefix, got {line:?}",
        );
        let parts: Vec<&str> = line.split('\t').collect();
        assert_eq!(parts.len(), 2, "expected exactly one TAB separator");
        assert_eq!(parts[1].len(), 64, "BLAKE3 hex is 64 chars; got {parts:?}");
    }

    /// A multi-document `kustomize build` output (a `Service` and a
    /// `Deployment` in the same namespace) parses to
    /// [`DeploymentManifestRenderOutcome::Rendered`] with TWO canonical
    /// lines, one per document, joined by `\n` in lexical order. The
    /// `Deployment` sorts before `Service` because the prefix
    /// `apps/v1|Deployment|…` lexically precedes `v1|Service|…`. Pins
    /// the multi-document walk over `serde_yaml::Deserializer::from_str`'s
    /// iterator — a regression that walked only the first document would
    /// fail this test with a single-line fingerprint.
    #[test]
    fn test_parse_multi_document_yields_one_line_per_document() {
        let yaml = r#"
apiVersion: v1
kind: Service
metadata:
  name: svc-a
  namespace: myns
spec:
  ports: [{port: 80}]
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: svc-a
  namespace: myns
spec:
  replicas: 3
"#;
        let fp = rendered_fingerprint(parse_kustomize_output(yaml));
        let text = String::from_utf8(fp).unwrap();
        let lines: Vec<&str> = text.split('\n').collect();
        assert_eq!(
            lines.len(),
            2,
            "expected two canonical lines, got {lines:?}"
        );
        assert!(
            lines[0].starts_with("apps/v1|Deployment|myns|svc-a\t"),
            "expected Deployment to sort first, got {lines:?}",
        );
        assert!(
            lines[1].starts_with("v1|Service|myns|svc-a\t"),
            "expected Service to sort second, got {lines:?}",
        );
    }

    /// Two kustomize streams whose documents appear in DIFFERENT orders
    /// but name the same `(apiVersion, kind, namespace, name, content)`
    /// set fingerprint identically. The load-bearing canonical-form
    /// property the `BTreeSet`-driven line-sort enforces: a downstream
    /// verifier walking the same kustomization but seeing kustomize emit
    /// its documents in a different order recovers the same fingerprint.
    /// Same canonical-form discipline as
    /// `chart_listing::test_canonical_fingerprint_is_order_independent`
    /// one layer over.
    #[test]
    fn test_parse_is_document_order_independent() {
        let forward = r#"
apiVersion: v1
kind: ConfigMap
metadata:
  name: cm-a
  namespace: myns
data: {x: "1"}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: svc-a
  namespace: myns
spec: {replicas: 1}
"#;
        let reversed = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: svc-a
  namespace: myns
spec: {replicas: 1}
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: cm-a
  namespace: myns
data: {x: "1"}
"#;
        assert_eq!(
            parse_kustomize_output(forward),
            parse_kustomize_output(reversed),
            "fingerprint must be document-order-independent — the load-\
             bearing canonical-form property a downstream verifier walking \
             the same kustomization depends on",
        );
    }

    /// Two kustomize documents whose key ORDER differs within the
    /// document (`apiVersion` first vs `kind` first; `spec` before
    /// `metadata` vs after) but whose key-VALUE pairs are identical
    /// fingerprint identically. The load-bearing canonical-content
    /// property the `serde_json::Value`-driven canonical-JSON
    /// serialisation enforces — `serde_json::Map` is `BTreeMap`-backed
    /// by default, sorting keys lexically, so the per-document content
    /// hash is invariant under key reordering. A future regression that
    /// hashed raw bytes (or enabled `serde_json`'s `preserve_order`
    /// feature) would silently make the fingerprint shape-dependent and
    /// fail this test. Same canonical-content discipline as
    /// `commands/attestation.rs::test_manifest_hash_stable_across_key_order_and_metadata`
    /// at the call-site layer.
    #[test]
    fn test_parse_is_key_order_independent_within_document() {
        let api_first = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: svc-a
  namespace: myns
spec:
  replicas: 3
"#;
        let kind_first = r#"
kind: Deployment
spec:
  replicas: 3
metadata:
  namespace: myns
  name: svc-a
apiVersion: apps/v1
"#;
        assert_eq!(
            parse_kustomize_output(api_first),
            parse_kustomize_output(kind_first),
            "fingerprint must be key-order-independent — the canonical-\
             JSON oracle sorts keys lexically so a downstream verifier \
             walking the same content under a different YAML key order \
             recovers the same fingerprint",
        );
    }

    /// A duplicate document (the same `(apiVersion, kind, namespace,
    /// name, content)` tuple appearing twice in the stream) collapses to
    /// ONE canonical line. The `BTreeSet`-driven line-dedup enforces
    /// this idempotently. Mirrors
    /// `chart_listing::test_canonical_fingerprint_dedups_repeated_entries`
    /// one layer over. A real kustomize output should never produce
    /// duplicate resources, but a malformed Kustomization that double-
    /// included a base could; the canonical-form property is what makes
    /// the fingerprint a function of the resource SET, not the document
    /// list.
    #[test]
    fn test_parse_dedups_repeated_documents() {
        let with_dup = r#"
apiVersion: v1
kind: Service
metadata:
  name: svc-a
  namespace: myns
spec: {ports: [{port: 80}]}
---
apiVersion: v1
kind: Service
metadata:
  name: svc-a
  namespace: myns
spec: {ports: [{port: 80}]}
"#;
        let without_dup = r#"
apiVersion: v1
kind: Service
metadata:
  name: svc-a
  namespace: myns
spec: {ports: [{port: 80}]}
"#;
        assert_eq!(
            parse_kustomize_output(with_dup),
            parse_kustomize_output(without_dup),
            "byte-identical duplicate documents must collapse to one \
             canonical line",
        );
    }

    /// A document missing `metadata.namespace` (a legitimately cluster-
    /// scoped resource such as a `ClusterRole` or a `Namespace` itself)
    /// parses to [`DeploymentManifestRenderOutcome::Rendered`] with an
    /// EMPTY namespace field in the canonical line. Pins the cluster-
    /// scoped resource discriminator: a regression that folded missing-
    /// namespace into `RenderFailed` would force every Kustomization
    /// that produced a cluster-scoped resource (every install of an
    /// operator CRD, every cluster-wide RBAC binding, every Namespace
    /// resource the Kustomization creates itself) into the failure arm.
    #[test]
    fn test_parse_cluster_scoped_resource_yields_empty_namespace() {
        let yaml = r#"
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: edit
rules: []
"#;
        let fp = rendered_fingerprint(parse_kustomize_output(yaml));
        let line = String::from_utf8(fp).unwrap();
        assert!(
            line.starts_with("rbac.authorization.k8s.io/v1|ClusterRole||edit\t"),
            "expected empty namespace field between two |s, got {line:?}",
        );
    }

    /// A document missing the top-level `apiVersion` field — a malformed
    /// kustomize output a real `kustomize build` should never produce,
    /// but a future kustomize regression or an upstream Kustomization
    /// that ate its `apiVersion:` line could. Parses to
    /// [`DeploymentManifestRenderOutcome::RenderFailed`]. No content
    /// claim is possible without an `apiVersion` discriminator at the
    /// per-resource line.
    #[test]
    fn test_parse_missing_api_version_yields_render_failed() {
        let yaml = r#"
kind: Deployment
metadata:
  name: svc-a
  namespace: myns
"#;
        assert_eq!(
            parse_kustomize_output(yaml),
            DeploymentManifestRenderOutcome::RenderFailed,
        );
    }

    /// A document missing the top-level `kind` field — symmetric to the
    /// missing-`apiVersion` failure mode above. Parses to
    /// [`DeploymentManifestRenderOutcome::RenderFailed`].
    #[test]
    fn test_parse_missing_kind_yields_render_failed() {
        let yaml = r#"
apiVersion: apps/v1
metadata:
  name: svc-a
  namespace: myns
"#;
        assert_eq!(
            parse_kustomize_output(yaml),
            DeploymentManifestRenderOutcome::RenderFailed,
        );
    }

    /// A document missing `metadata.name` — every Kubernetes resource
    /// REQUIRES a `metadata.name` (the cluster-scoped or namespace-
    /// scoped identity key the apiserver indexes by). Parses to
    /// [`DeploymentManifestRenderOutcome::RenderFailed`]. A regression
    /// that fell back to an empty name would silently collapse every
    /// nameless resource into the same canonical line, defeating the
    /// per-resource discriminator.
    #[test]
    fn test_parse_missing_metadata_name_yields_render_failed() {
        let yaml = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  namespace: myns
"#;
        assert_eq!(
            parse_kustomize_output(yaml),
            DeploymentManifestRenderOutcome::RenderFailed,
        );
    }

    /// A multi-document stream where one document parses cleanly and a
    /// subsequent one is missing `apiVersion` parses to
    /// [`DeploymentManifestRenderOutcome::RenderFailed`] — the parser
    /// walks every document and short-circuits on the first failing
    /// one. A regression that hard-coded `documents[0]` would pass this
    /// test with `Rendered` over the first document only and silently
    /// drop the failing second document from the fingerprint.
    #[test]
    fn test_parse_one_malformed_in_multi_yields_render_failed() {
        let yaml = r#"
apiVersion: v1
kind: ConfigMap
metadata:
  name: cm-a
  namespace: myns
data: {x: "1"}
---
kind: Deployment
metadata:
  name: svc-a
  namespace: myns
"#;
        assert_eq!(
            parse_kustomize_output(yaml),
            DeploymentManifestRenderOutcome::RenderFailed,
        );
    }

    /// A document whose root is a bare scalar (not a mapping) — a
    /// malformed kustomize output, or stderr-mode noise leaking into
    /// stdout. Parses to [`DeploymentManifestRenderOutcome::RenderFailed`].
    #[test]
    fn test_parse_non_mapping_root_yields_render_failed() {
        let yaml = "just a string";
        assert_eq!(
            parse_kustomize_output(yaml),
            DeploymentManifestRenderOutcome::RenderFailed,
        );
    }

    /// A document whose root is a YAML SEQUENCE rather than a mapping
    /// (e.g. a List-typed object the kustomize output forgot to expand)
    /// parses to [`DeploymentManifestRenderOutcome::RenderFailed`].
    #[test]
    fn test_parse_sequence_root_yields_render_failed() {
        let yaml = "- one\n- two\n";
        assert_eq!(
            parse_kustomize_output(yaml),
            DeploymentManifestRenderOutcome::RenderFailed,
        );
    }

    /// An empty input — the degenerate "kustomize ran and produced zero
    /// rendered resources" or "the stream was empty altogether" world.
    /// Parses to [`DeploymentManifestRenderOutcome::RenderFailed`]: no
    /// rendered-manifest identity can be claimed against a zero-document
    /// stream. Pins the load-bearing semantic break with vacuous
    /// `Rendered` over an empty fingerprint — a regression that emitted
    /// `Rendered { fingerprint: b"".to_vec() }` here would collapse every
    /// empty-render kustomization to the same BLAKE3 hash regardless of
    /// which Kustomization root produced it.
    #[test]
    fn test_parse_empty_input_yields_render_failed() {
        assert_eq!(
            parse_kustomize_output(""),
            DeploymentManifestRenderOutcome::RenderFailed,
        );
    }

    /// Whitespace-only input parses to
    /// [`DeploymentManifestRenderOutcome::RenderFailed`] — same shape
    /// as empty input. A kustomize binary that emitted only newlines
    /// (perhaps because every base was empty) maps to the same no-
    /// rendered-content arm.
    #[test]
    fn test_parse_whitespace_only_yields_render_failed() {
        assert_eq!(
            parse_kustomize_output("   \n\n   \n"),
            DeploymentManifestRenderOutcome::RenderFailed,
        );
    }

    /// A stream consisting only of a `---` separator (zero non-null
    /// documents) parses to
    /// [`DeploymentManifestRenderOutcome::RenderFailed`] — the parser
    /// skips null documents (a leading or trailing `---` is a legitimate
    /// YAML stream marker, not an error), but a stream with NO non-null
    /// documents has no rendered content to claim. Pins the dual
    /// invariant: null-document tolerance (the parser walks past them)
    /// AND empty-after-skipping → `RenderFailed`.
    #[test]
    fn test_parse_only_separators_yields_render_failed() {
        assert_eq!(
            parse_kustomize_output("---\n---\n"),
            DeploymentManifestRenderOutcome::RenderFailed,
        );
    }

    /// A real kustomize stream often ends with a trailing `---\n` after
    /// its last document — a benign YAML stream marker that produces a
    /// trailing null document. The parser SKIPS null documents rather
    /// than treating them as malformed; the leading non-null content
    /// still produces a `Rendered` outcome. Pins the load-bearing
    /// tolerance discriminator: a regression that folded the trailing
    /// null into `RenderFailed` would force every well-formed kustomize
    /// output that ended with a separator into the failure arm.
    #[test]
    fn test_parse_trailing_separator_still_yields_rendered() {
        let yaml = r#"
apiVersion: v1
kind: ConfigMap
metadata:
  name: cm-a
  namespace: myns
data: {x: "1"}
---
"#;
        let fp = rendered_fingerprint(parse_kustomize_output(yaml));
        let text = String::from_utf8(fp).unwrap();
        assert!(
            text.starts_with("v1|ConfigMap|myns|cm-a\t"),
            "expected one canonical line for the leading document, got {text:?}",
        );
    }

    /// Garbage non-YAML input (e.g. a `kustomize: command not found`
    /// stderr-mode line leaking into stdout) parses to
    /// [`DeploymentManifestRenderOutcome::RenderFailed`] without panic.
    /// Same exit-agnostic, no-panic discipline the sibling JSON parsers
    /// carry one layer over.
    #[test]
    fn test_parse_garbage_input_yields_render_failed_without_panic() {
        let yaml = "kustomize: command not found:\n  : : :  invalid : : :\n";
        assert_eq!(
            parse_kustomize_output(yaml),
            DeploymentManifestRenderOutcome::RenderFailed,
        );
    }

    /// Two kustomize streams over structurally distinct manifest content
    /// (same `(apiVersion, kind, namespace, name)` identity but different
    /// `spec` content — the load-bearing post-deployment-change
    /// discriminator a content-addressed `manifest_hash` must capture)
    /// produce distinct fingerprints AND distinct `manifest_hash`
    /// values. Pins the content-addressed-identity invariant THEORY
    /// §VI.1 names: a downstream verifier reading two attestations
    /// against the same identity tuple but different content recovers
    /// the discriminator at the BLAKE3 surface. Mirrors
    /// `chart_listing::test_canonical_fingerprint_changes_when_content_changes`
    /// one layer over.
    #[test]
    fn test_parse_distinct_content_produces_distinct_manifest_hashes() {
        let v1 = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: svc-a
  namespace: myns
spec:
  replicas: 3
"#;
        let v2 = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: svc-a
  namespace: myns
spec:
  replicas: 5
"#;
        let fp1 = parse_kustomize_output(v1);
        let fp2 = parse_kustomize_output(v2);
        assert_ne!(
            fp1, fp2,
            "two distinct manifest contents must produce distinct fingerprints",
        );
        assert_ne!(
            fp1.manifest_hash().to_hex(),
            fp2.manifest_hash().to_hex(),
            "two distinct manifest contents must produce distinct \
             manifest_hash values — the content-addressed-identity \
             invariant THEORY §VI.1 names",
        );
    }

    /// Two kustomize streams whose only difference is `metadata.name`
    /// (same content shape, different per-resource identity) produce
    /// distinct fingerprints. Pins the per-resource-identity
    /// discriminator on the line PREFIX (the `<apiVersion>|<kind>|
    /// <namespace>|<name>` key portion), distinct from the content-hash
    /// discriminator the prior test pins on the line SUFFIX.
    #[test]
    fn test_parse_distinct_names_produce_distinct_fingerprints() {
        let svc_a = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: svc-a
  namespace: myns
spec: {replicas: 3}
"#;
        let svc_b = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: svc-b
  namespace: myns
spec: {replicas: 3}
"#;
        assert_ne!(
            parse_kustomize_output(svc_a),
            parse_kustomize_output(svc_b),
            "two distinct resource names at the same content must \
             produce distinct fingerprints — the per-resource-identity \
             discriminator on the line prefix",
        );
    }

    /// The parser's `Rendered` output composes end-to-end with the
    /// `manifest_hash()` method: a typed-equal arm produces a typed-
    /// equal hash. Pins the single-probe / single-claim composition the
    /// call site rests on — a regression in either the parser OR the
    /// `manifest_hash()` method surfaces here rather than at integration
    /// time. Same composition-pin shape as
    /// `pod_health::test_both_pod_list_parsers_compose_against_one_response`
    /// one layer over.
    #[test]
    fn test_parser_and_manifest_hash_compose_end_to_end() {
        let yaml = r#"
apiVersion: v1
kind: ConfigMap
metadata:
  name: cm-a
  namespace: myns
data: {x: "1"}
"#;
        let outcome = parse_kustomize_output(yaml);
        let hash = outcome.manifest_hash();
        // Reconstruct the same outcome via the typed primitive directly
        // (using the fingerprint bytes the parser produced) and confirm
        // the hash agrees — the canonical-form invariant the call site
        // depends on.
        let DeploymentManifestRenderOutcome::Rendered { fingerprint } = &outcome else {
            panic!("expected Rendered outcome");
        };
        let manual = DeploymentManifestRenderOutcome::Rendered {
            fingerprint: fingerprint.clone(),
        };
        assert_eq!(
            hash.to_hex(),
            manual.manifest_hash().to_hex(),
            "parser-produced Rendered fingerprint must agree with a \
             typed-primitive-constructed Rendered over the same bytes",
        );
    }

    /// `RenderFailed` returned by the parser composes with the typed-
    /// primitive's `manifest_hash()` method to produce the same sentinel
    /// `Blake3Hash::digest(b"manifest-render-failed")` hash a typed-
    /// primitive-constructed `RenderFailed` produces. Pins the parser-
    /// to-typed-primitive equivalence at the failure arm: a downstream
    /// verifier reading the `manifest_hash` field cannot distinguish a
    /// call site that constructed `RenderFailed` directly from one that
    /// recovered it through `parse_kustomize_output` — both routes
    /// produce the same BLAKE3 surface.
    #[test]
    fn test_parser_render_failed_matches_typed_primitive_sentinel() {
        let parsed = parse_kustomize_output("not yaml ::: invalid");
        assert_eq!(
            parsed.manifest_hash().to_hex(),
            DeploymentManifestRenderOutcome::RenderFailed
                .manifest_hash()
                .to_hex(),
            "parser-produced RenderFailed must produce the same \
             manifest_hash as typed-primitive-constructed RenderFailed",
        );
    }
}
