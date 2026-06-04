//! Typed `Chart.yaml`-declared-dependency probe outcome for forge's
//! Phase 1 chart attestation — the dependency-graph peer of
//! [`crate::chart_listing`] (per-file chart-content fingerprint, commit
//! e8a2df7), [`crate::helm_provenance`] (chart-signature probe),
//! [`crate::helm_lint`] (chart-quality probe), and
//! [`crate::kensa_policy`] (chart-policy probe).
//!
//! ## What this module closes
//!
//! `commands/attestation.rs::compute_chart_attestation` previously
//! stamped a literal `vec![]` into every Phase 1 `ChartAttestation`'s
//! `dependency_hashes` field:
//!
//! ```ignore
//! Ok(ci::chart_attestation(
//!     chart_name,
//!     chart_version,
//!     chart_hash,
//!     provenance_outcome.is_verified(),
//!     vec![], // Dependency hashes: populated when chart deps are tracked
//!     lint_outcome.is_passed(),
//!     policy_outcome.is_passed(),
//!     registry_ref,
//! ))
//! ```
//!
//! The `Vec<DependencyHash>` surface is honest for the no-Chart.yaml-read
//! world (a Phase 1 chart attestation that records `dependency_hashes:
//! []` against a certification function that never read `Chart.yaml`
//! has collected no dep-graph evidence), but flattens two structurally
//! distinct operational worlds — `Listed { deps: vec![] }`
//! (Chart.yaml WAS read and the chart declares zero `dependencies:`
//! entries — evidence that the chart is a leaf in the dep graph) and
//! `ProbeAbsent` (Chart.yaml was never read, or was unreadable, or was
//! malformed — no evidence either way) — into the same empty vec a
//! downstream verifier cannot recover the kind-of-claim from. The
//! `Listed { deps: vec![] }` collapse is the load-bearing
//! discriminator loss: a downstream `sekiban` strict-production policy
//! that fails-closed on the absence of a Chart.yaml read inside the
//! certification function (the structural failure mode for a chart-
//! supply-chain provenance gate, where the operator must distinguish
//! "the chart truly declares no third-party deps" from "we never even
//! looked at Chart.yaml") cannot express that gate against the pre-fix
//! bare `Vec<DependencyHash>` — every Phase 1 record asserts the same empty
//! vec regardless of whether a Chart.yaml probe substantiated a
//! leaf-chart state or whether it simply never ran. The typed primitive
//! closes the gap the same way commits d002374 / e76db87 / 8b1407d /
//! f8a5d8e / 5931e32 / 72424bd / c1e83d5 / d81f639 / 2f3a7dc / b98eb5a /
//! fffca30 / 0ff67e1 / e8a2df7 / 443bd22 / 9c5a99f / a5376a6 / 5baaa50 /
//! 36d90b6 / f40dae7 / d002374 closed sibling Phase 1 and Phase 2 gaps
//! one shape away: a typed outcome enum over the operational worlds a
//! downstream probe could report, the probe-evidence claim computed by
//! the typed primitive over the typed shape, and every-arm distinction
//! preserved structurally so a downstream verifier recovers the
//! kind-of-claim from the value alone.
//!
//! ## The two operational worlds
//!
//! A Chart.yaml dependency probe (the `serde_yaml::from_str::<ChartYaml>`
//! deserialise of `<chart-path>/Chart.yaml` into the typed shape, with
//! the resulting `dependencies: Vec<Dep>` walked into the canonical
//! `(name, version, repository)` triple per declared dep) distinguishes
//! two operational worlds the prior `vec![]` hardcode flattened into a
//! single empty vec:
//!
//! 1. **Probe absent** — `compute_chart_attestation` did not read
//!    `Chart.yaml` at all, or `Chart.yaml` could not be read (`ENOENT` /
//!    permission error), or `Chart.yaml` was unparseable (YAML syntax
//!    error / structural error against the typed `ChartYaml` shape).
//!    No probe ran. There is no evidence either way. The prior `vec![]`
//!    hardcode reported an empty dep-hash vec against this state every
//!    time — including for charts whose declared dep graph was in fact
//!    non-empty.
//! 2. **Listed** — `Chart.yaml` was read and parsed, and the chart's
//!    declared `dependencies:` block was walked. `deps` carries one
//!    canonical [`ChartDependency`] entry per declared dep, sorted and
//!    deduplicated so two Chart.yaml layouts naming the same `(name,
//!    version, repository)` triple set fingerprint identically
//!    regardless of input ordering or YAML key ordering. The vec may
//!    itself be empty (the chart truly declares no `dependencies:`
//!    entries — a leaf chart) or carry N entries; the structural
//!    distinction from `ProbeAbsent` is that a probe RAN and produced
//!    evidence, regardless of the cardinality that evidence reports. A
//!    chart with `deps: vec![]` under `Listed` is the
//!    load-bearing discriminator: a downstream verifier reading the
//!    typed outcome can distinguish "Chart.yaml probe ran and the chart
//!    declares no deps" (evidence-of-leaf-chart, the Phase 1 substantive
//!    claim a dep-graph gate rests on) from "no Chart.yaml probe ran"
//!    (no evidence), where the pre-fix bare `Vec<DependencyHash>` flattened
//!    them indistinguishably into the same empty vec.
//!
//! ## Why two arms, not three
//!
//! Unlike [`crate::helm_provenance::HelmProvenanceOutcome`] (four arms
//! over the `Verified` / `Unverified` / `VerifyFailed` / `ProbeAbsent`
//! distinction the chart-signature world carries) one layer over, the
//! Chart.yaml-dependency world has no positive-vs-negative-evidence
//! axis the listed dep set itself does not already carry. A probed
//! Chart.yaml has `deps: Vec<ChartDependency>` for some N >= 0; the
//! vec IS the evidence, with `deps: vec![]` carrying the leaf-chart
//! claim a third arm would have named redundantly. Splitting
//! `Listed { deps: vec![] }` from `Listed { deps: vec![d] }`
//! would force every consumer to reassemble the vec from a match arm
//! without surfacing a structural distinction the call site does not
//! already recover from the bare `deps` field. Same shape
//! discipline as [`crate::pod_listing::PodListingOutcome`] (two arms
//! because the count IS the evidence and a `Counted { count: 0 }`
//! carries the empty-namespace claim a third arm would have redundantly
//! named) and [`crate::cis_k8s_pass_rate::CisK8sPassRateOutcome`] (two
//! arms because the ratio IS the evidence and a `Probed { ratio: 0.0 }`
//! carries the zero-pass-rate claim a third arm would have redundantly
//! named).
//!
//! ## Canonical fingerprint per dep
//!
//! Each declared dep canonicalises to a TAB-framed `name TAB version
//! TAB repository` line — the dep-graph-side peer of
//! [`crate::chart_listing::canonical_chart_fingerprint`]'s TAB-framed
//! `path TAB content-hash-hex` line one shape away. The TAB separator
//! forecloses the same boundary-collision failure mode the chart-listing
//! canonical form forecloses: two distinct dep triples
//! (`("ab", "cd", "ef")` vs `("a", "bcd", "ef")`) cannot collide under
//! the TAB-framed form even though their concatenations agree. The
//! per-dep hash is the BLAKE3 of the canonical line, surfaced as
//! [`tameshi::hash::Blake3Hash`] inside each
//! [`tameshi::certification::DependencyHash`] so the per-dep identity
//! composes directly into the Phase 1 `dependency_hashes` field. The
//! `deps` vec is sorted by canonical line content and deduplicated so
//! two Chart.yaml layouts naming the same triple set in different
//! orders fingerprint identically.
//!
//! ## What this commit does NOT do
//!
//! This commit introduces the typed primitive AND wires the probe at
//! `compute_chart_attestation` (Chart.yaml is already on disk at
//! `chart_path` — the probe is cheap, no shell-out required), unlike
//! commits f40dae7 / d002374 / e76db87 / 8b1407d / f8a5d8e / 5931e32 /
//! 72424bd / c1e83d5 / d81f639 / b98eb5a that introduce the typed
//! primitive but route the call site through the `ProbeAbsent` arm
//! pending a kubectl / `nix build --rebuild` / `kensa` / `syft` /
//! `helm lint` shell-out. The `parse_chart_yaml_dependencies` function
//! is pure (string in, typed outcome out) so the YAML-shape boundary
//! is unit-testable; `probe_chart_dependencies` is the thin I/O wrapper
//! around `tokio::fs::read_to_string`. Same probe shape as commit
//! a5376a6's wired-in `GitCommitSignatureOutcome::from_format_code`
//! (`git log --format=%G?` is cheap, so the probe is real at the
//! call site).
//!
//! ## Frontier inspiration
//!
//! THEORY §V.4 ("Two-phase signature composition") names the Phase 1
//! chart record as the pre-admission honesty channel: the structural
//! evidence that the chart's declared dep graph is content-addressed
//! and reproducible. Helm's own `Chart.yaml dependencies:` schema
//! (`helm.sh/chart-schema-v2`) names each dep by `(name, version,
//! repository)` — exactly the three fields a downstream verifier needs
//! to resolve the dep against an OCI registry or HTTP repo. SLSA L3
//! ("Hardened builds — Hermetic + reproducible") and SLSA L4
//! ("Two-person review") both rest on a content-addressed dep-graph
//! identity: a Phase 1 record that asserts `dependency_hashes: []`
//! against a chart whose `Chart.yaml dependencies:` block declares
//! third-party subcharts fails every reconciliation a `sekiban admission
//! audit` pass could surface against the same chart artifact. The
//! typed `ProbeAbsent` arm names that gap honestly rather than
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
//! ProbeAbsent`], [`crate::cis_k8s_pass_rate::CisK8sPassRateOutcome::
//! ProbeAbsent`], [`crate::security_scan::SbomProbeOutcome::Absent`],
//! and [`crate::security_scan::VulnScanProbeOutcome::Absent`] apply at
//! the pod-count, pod-readiness, HelmRelease-signature, network-
//! segmentation, source-verification, image-signature, chart-signature,
//! chart-quality, chart-policy, source-commit-signature, build-
//! determinism, CIS-pass-rate, SBOM, and vuln-scan layers.

use std::path::Path;

use tameshi::certification::DependencyHash;
use tameshi::hash::Blake3Hash;

/// A declared `Chart.yaml dependencies:` entry, reduced to the three
/// fields a downstream verifier needs to reconcile the dep against an
/// OCI registry or HTTP Helm repo. The canonical form is a TAB-framed
/// `name TAB version TAB repository` line — the dep-graph-side peer of
/// [`crate::chart_listing::canonical_chart_fingerprint`]'s
/// `path TAB content-hash-hex`.
///
/// Field order matches the `Chart.yaml` schema's natural ordering
/// (`name`, `version`, `repository`); the canonical line concatenates
/// them in that order. Two entries with identical `(name, version,
/// repository)` triples canonicalise identically; the dep-hash vec
/// deduplicates them.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ChartDependency {
    /// The dep's chart name (e.g. `"common"`, `"postgres"`).
    pub name: String,
    /// The dep's chart version (e.g. `"1.2.3"`).
    pub version: String,
    /// The dep's repository URL (e.g. `"oci://ghcr.io/pleme-io/charts"`
    /// or `"https://charts.bitnami.com/bitnami"`). Empty string when
    /// `Chart.yaml` omits the field — the canonical line still carries
    /// the TAB so the field-count is invariant.
    pub repository: String,
}

impl ChartDependency {
    /// The TAB-framed canonical line for this dep — `name TAB version
    /// TAB repository`. The per-dep identity the Phase 1
    /// `dependency_hashes` field is content-addressed over. TAB is the
    /// separator (matching [`crate::chart_listing`] one shape away) so
    /// two distinct dep triples cannot collide under the canonical
    /// form even when their concatenations agree (the
    /// boundary-collision failure mode raw-byte concatenation carries).
    pub fn canonical_line(&self) -> String {
        format!("{}\t{}\t{}", self.name, self.version, self.repository)
    }

    /// The BLAKE3 digest of this dep's canonical line — the per-dep
    /// content-addressed identity the Phase 1 `dependency_hashes`
    /// field composes from.
    pub fn dep_hash(&self) -> Blake3Hash {
        Blake3Hash::digest(self.canonical_line().as_bytes())
    }

    /// The [`DependencyHash`] tameshi value the Phase 1
    /// `dependency_hashes` field carries: the dep's `name` / `version`
    /// for downstream resolution against an OCI registry or HTTP repo,
    /// alongside the BLAKE3 of the TAB-framed canonical line as the
    /// content-addressed dep-graph identity. The hash is the
    /// load-bearing structural discriminator — `(name, version)`
    /// alone would let two distinct triples sharing a name/version but
    /// pointing at different repositories collide; the canonical-line
    /// hash forecloses that.
    pub fn to_dependency_hash(&self) -> DependencyHash {
        DependencyHash {
            name: self.name.clone(),
            version: self.version.clone(),
            hash: self.dep_hash(),
        }
    }
}

/// Outcome of probing `<chart-path>/Chart.yaml` for the chart's
/// declared `dependencies:` block — the typed source of the Phase 1
/// `dependency_hashes` field. The two arms preserve the
/// probe-absent vs probed distinction the Phase 1 chart attestation
/// depends on; the prior `vec![]` hardcode conflated no-Chart.yaml-read
/// with probed-leaf-chart into a single empty vec.
#[derive(Debug, Clone)]
pub enum ChartDependenciesOutcome {
    /// `Chart.yaml` was read and parsed, and the chart's declared
    /// `dependencies:` block was walked. `deps` carries one
    /// [`ChartDependency`] entry per declared dep, sorted by canonical
    /// line and deduplicated so two Chart.yaml layouts naming the same
    /// triple set in different orders fingerprint identically. The vec
    /// may itself be empty (the chart truly declares no deps — a leaf
    /// chart), structurally distinct from `ProbeAbsent` regardless of
    /// the cardinality. The [`ChartDependency`] entries are themselves
    /// the canonical-form source for both the
    /// `Vec<tameshi::certification::DependencyHash>` the Phase 1
    /// attestation seals and the per-dep BLAKE3 a future enrichment
    /// could route into a richer dep-graph claim.
    Listed { deps: Vec<ChartDependency> },
    /// `compute_chart_attestation` did not read `Chart.yaml` (no probe
    /// reached the file system at all), or the file could not be read
    /// (`ENOENT` / permission error), or the file was unparseable
    /// (YAML syntax error / structural error against the typed
    /// `ChartYaml` shape). No probe was made; no evidence was
    /// collected. The prior `vec![]` hardcode reported the same value
    /// here as for the `Listed { deps: vec![] }` arm, conflating
    /// "no Chart.yaml probe ran" with "probe ran and chart declares no
    /// deps".
    ProbeAbsent,
}

impl ChartDependenciesOutcome {
    /// The `Vec<DependencyHash>` the Phase 1 chart attestation's
    /// `dependency_hashes` field carries — each `Listed` entry maps
    /// through [`ChartDependency::to_dependency_hash`] (`name` /
    /// `version` carried for downstream resolution against an OCI
    /// registry or HTTP repo, the BLAKE3 of the TAB-framed canonical
    /// `name TAB version TAB repository` line carried as the
    /// content-addressed dep-graph identity). `ProbeAbsent` collapses
    /// to `vec![]`, matching the pre-fix bare-vec semantics exactly at
    /// the surface level while preserving the structural discriminator
    /// the bare vec erased.
    pub fn to_dependency_hashes(&self) -> Vec<DependencyHash> {
        match self {
            Self::Listed { deps } => deps
                .iter()
                .map(ChartDependency::to_dependency_hash)
                .collect(),
            Self::ProbeAbsent => Vec::new(),
        }
    }
}

/// Canonical, order-independent dep vec for a [`ChartDependency`]
/// set: sort each dep by its canonical line and deduplicate. Two
/// Chart.yaml layouts declaring the same `(name, version, repository)`
/// triple set in different orders produce byte-identical
/// `Vec<ChartDependency>` outputs. Two layouts with the same triple
/// set but a duplicated entry collapse to one entry — the dep-graph-
/// side peer of [`crate::chart_listing::canonical_chart_fingerprint`]'s
/// sorted-set canonical form.
pub fn canonical_deps(deps: impl IntoIterator<Item = ChartDependency>) -> Vec<ChartDependency> {
    let canonical_set: std::collections::BTreeSet<ChartDependency> = deps.into_iter().collect();
    canonical_set.into_iter().collect()
}

/// Parse `Chart.yaml` content into a typed [`ChartDependenciesOutcome`].
/// Pure (string in, typed outcome out) so the YAML-shape boundary is
/// unit-testable without touching the file system.
///
/// A successful parse always yields the `Listed` arm — even when the
/// chart declares no `dependencies:` block at all (`Listed { dep_hashes:
/// vec![] }` is the leaf-chart claim, structurally distinct from
/// `ProbeAbsent`). Parse failure (YAML syntax error, structural error
/// against the typed `ChartYaml` shape) yields `ProbeAbsent` — the
/// honest "we tried to read it but could not extract a dep-graph claim"
/// record, never an unprincipled silent empty.
pub fn parse_chart_yaml_dependencies(yaml: &str) -> ChartDependenciesOutcome {
    #[derive(serde::Deserialize)]
    struct ChartYaml {
        #[serde(default)]
        dependencies: Vec<Dep>,
    }
    #[derive(serde::Deserialize)]
    struct Dep {
        #[serde(default)]
        name: String,
        #[serde(default)]
        version: String,
        #[serde(default)]
        repository: String,
    }
    match serde_yaml::from_str::<ChartYaml>(yaml) {
        Ok(c) => {
            let deps = c.dependencies.into_iter().map(|d| ChartDependency {
                name: d.name,
                version: d.version,
                repository: d.repository,
            });
            ChartDependenciesOutcome::Listed {
                deps: canonical_deps(deps),
            }
        }
        Err(_) => ChartDependenciesOutcome::ProbeAbsent,
    }
}

/// Probe `<chart-path>/Chart.yaml` for the chart's declared
/// `dependencies:` block. Thin I/O wrapper over
/// [`parse_chart_yaml_dependencies`]: any read error
/// (`ENOENT` / permission error / I/O error) routes through the
/// `ProbeAbsent` arm, never a silent empty vec. A successful read
/// hands the bytes to the pure parser, which returns `Listed` on a
/// well-formed Chart.yaml and `ProbeAbsent` on a malformed one.
pub async fn probe_chart_dependencies(chart_path: &Path) -> ChartDependenciesOutcome {
    let chart_yaml = chart_path.join("Chart.yaml");
    match tokio::fs::read_to_string(&chart_yaml).await {
        Ok(content) => parse_chart_yaml_dependencies(&content),
        Err(_) => ChartDependenciesOutcome::ProbeAbsent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dep(name: &str, version: &str, repository: &str) -> ChartDependency {
        ChartDependency {
            name: name.to_string(),
            version: version.to_string(),
            repository: repository.to_string(),
        }
    }

    /// The canonical line is TAB-framed `name TAB version TAB
    /// repository` — the boundary discipline that forecloses the
    /// raw-byte concatenation failure mode the prior `vec![]` had no
    /// canonical form to address. Two distinct dep triples sharing a
    /// concatenated `name + version + repository` byte sequence cannot
    /// collide under the TAB-framed line.
    #[test]
    fn test_canonical_line_is_tab_framed() {
        let d = dep("common", "1.2.3", "oci://ghcr.io/pleme-io/charts");
        assert_eq!(
            d.canonical_line(),
            "common\t1.2.3\toci://ghcr.io/pleme-io/charts",
        );
    }

    /// Two distinct dep triples whose raw concatenations agree
    /// (`("ab", "cd", "ef")` vs `("a", "bcd", "ef")`) produce distinct
    /// canonical lines and therefore distinct per-dep hashes — the
    /// boundary-collision failure mode the TAB-framed form forecloses
    /// at the byte level.
    #[test]
    fn test_distinct_triples_with_same_concat_dont_collide() {
        let a = dep("ab", "cd", "ef");
        let b = dep("a", "bcd", "ef");
        assert_ne!(
            a.canonical_line(),
            b.canonical_line(),
            "TAB framing must separate fields with concat collisions",
        );
        assert_ne!(
            a.dep_hash(),
            b.dep_hash(),
            "TAB framing must make per-dep hashes distinct even when \
             raw concatenations agree",
        );
    }

    /// `canonical_deps` is order-independent: two dep sets with the
    /// same `(name, version, repository)` triples in different orders
    /// produce byte-identical vecs. Mirrors
    /// `test_canonical_fingerprint_is_order_independent` for
    /// [`crate::chart_listing::canonical_chart_fingerprint`] one shape
    /// away.
    #[test]
    fn test_canonical_deps_is_order_independent() {
        let forward = vec![
            dep("common", "1.0.0", "oci://ghcr.io/pleme-io/charts"),
            dep("postgres", "2.0.0", "oci://ghcr.io/pleme-io/charts"),
            dep("redis", "3.0.0", "oci://ghcr.io/pleme-io/charts"),
        ];
        let reversed: Vec<ChartDependency> = forward.iter().rev().cloned().collect();
        assert_eq!(
            canonical_deps(forward),
            canonical_deps(reversed),
            "canonical_deps must be order-independent",
        );
    }

    /// Repeated entries (same `(name, version, repository)` triple)
    /// collapse to one entry — the dep-graph-side peer of
    /// [`crate::chart_listing::canonical_chart_fingerprint`]'s dedup.
    #[test]
    fn test_canonical_deps_dedups_repeated_entries() {
        let deps = vec![
            dep("common", "1.0.0", "oci://ghcr.io/pleme-io/charts"),
            dep("common", "1.0.0", "oci://ghcr.io/pleme-io/charts"),
            dep("redis", "3.0.0", "oci://ghcr.io/pleme-io/charts"),
        ];
        let canonical = canonical_deps(deps);
        assert_eq!(
            canonical.len(),
            2,
            "repeated triples must collapse to one entry",
        );
    }

    /// Changing any one of `name`, `version`, or `repository` drifts
    /// the per-dep hash — the property that makes this the dep-graph
    /// content identity, not a hash of the name alone or the version
    /// alone.
    #[test]
    fn test_dep_hash_changes_when_any_field_changes() {
        let base = dep("common", "1.0.0", "oci://ghcr.io/pleme-io/charts");
        let name_diff = dep("common-renamed", "1.0.0", "oci://ghcr.io/pleme-io/charts");
        let version_diff = dep("common", "1.0.1", "oci://ghcr.io/pleme-io/charts");
        let repo_diff = dep("common", "1.0.0", "oci://ghcr.io/other/charts");
        assert_ne!(base.dep_hash(), name_diff.dep_hash());
        assert_ne!(base.dep_hash(), version_diff.dep_hash());
        assert_ne!(base.dep_hash(), repo_diff.dep_hash());
    }

    /// `parse_chart_yaml_dependencies` on a well-formed Chart.yaml
    /// with declared deps returns `Listed { deps }` with one entry per
    /// declared dep, and `to_dependency_hashes` surfaces one
    /// [`DependencyHash`] per dep — each carrying `(name, version,
    /// hash)` with `hash` being the BLAKE3 of the canonical line.
    #[test]
    fn test_parse_well_formed_chart_yaml_returns_listed_with_deps() {
        let yaml = r#"
apiVersion: v2
name: example
version: 0.1.0
dependencies:
  - name: common
    version: 1.0.0
    repository: "oci://ghcr.io/pleme-io/charts"
  - name: redis
    version: 3.0.0
    repository: "oci://ghcr.io/pleme-io/charts"
"#;
        let outcome = parse_chart_yaml_dependencies(yaml);
        match outcome {
            ChartDependenciesOutcome::Listed { deps } => {
                assert_eq!(deps.len(), 2);
                let common = dep("common", "1.0.0", "oci://ghcr.io/pleme-io/charts");
                let redis = dep("redis", "3.0.0", "oci://ghcr.io/pleme-io/charts");
                assert!(
                    deps.contains(&common),
                    "Listed deps must include the common dep entry",
                );
                assert!(
                    deps.contains(&redis),
                    "Listed deps must include the redis dep entry",
                );
            }
            ChartDependenciesOutcome::ProbeAbsent => {
                panic!("expected Listed, got ProbeAbsent")
            }
        }
        // The DependencyHash surface carries (name, version, hash).
        let surfaced = parse_chart_yaml_dependencies(yaml).to_dependency_hashes();
        assert_eq!(surfaced.len(), 2);
        let common = dep("common", "1.0.0", "oci://ghcr.io/pleme-io/charts");
        let common_present = surfaced.iter().any(|d| {
            d.name == common.name && d.version == common.version && d.hash == common.dep_hash()
        });
        assert!(
            common_present,
            "to_dependency_hashes must surface the common dep's name/version/canonical-hash",
        );
    }

    /// `parse_chart_yaml_dependencies` on a Chart.yaml that declares
    /// no `dependencies:` block returns `Listed { deps: vec![] }` —
    /// the leaf-chart claim, structurally distinct from `ProbeAbsent`
    /// even though both surface to `vec![]` at the
    /// `to_dependency_hashes()` boundary. The load-bearing
    /// discriminator the pre-fix `vec![]` literal erased.
    #[test]
    fn test_parse_leaf_chart_returns_listed_with_empty_deps() {
        let yaml = r#"
apiVersion: v2
name: example
version: 0.1.0
"#;
        let outcome = parse_chart_yaml_dependencies(yaml);
        match outcome {
            ChartDependenciesOutcome::Listed { deps } => {
                assert!(
                    deps.is_empty(),
                    "a Chart.yaml with no dependencies: block must yield \
                     Listed{{deps: vec![]}}, not ProbeAbsent",
                );
            }
            ChartDependenciesOutcome::ProbeAbsent => panic!(
                "Listed{{deps: vec![]}} (leaf chart) must remain structurally \
                 distinct from ProbeAbsent — the pre-fix vec![] literal \
                 erased this discriminator",
            ),
        }
    }

    /// `parse_chart_yaml_dependencies` on malformed YAML returns
    /// `ProbeAbsent` — the honest "we tried to read it but could not
    /// extract a dep-graph claim" record. The pre-fix code path
    /// silently dropped to `vec![]` regardless of parse success, so
    /// this pin closes the dishonesty arm.
    #[test]
    fn test_parse_malformed_yaml_returns_probe_absent() {
        let yaml = "this: is: not: valid: yaml: -\n-: bad\n  : also bad";
        assert!(
            matches!(
                parse_chart_yaml_dependencies(yaml),
                ChartDependenciesOutcome::ProbeAbsent
            ),
            "malformed Chart.yaml must yield ProbeAbsent, not a silent \
             empty Listed",
        );
    }

    /// Pin the two-arm `to_dependency_hashes` collapse table. `Listed`
    /// passes one [`DependencyHash`] per dep through (with `(name,
    /// version, canonical-hash)`); `ProbeAbsent` collapses to `vec![]`.
    /// Same shape as `test_pass_rate_pins_all_arms` for
    /// [`crate::cis_k8s_pass_rate::CisK8sPassRateOutcome`] one shape
    /// away.
    #[test]
    fn test_to_dependency_hashes_pins_all_arms() {
        assert!(
            ChartDependenciesOutcome::ProbeAbsent
                .to_dependency_hashes()
                .is_empty(),
            "ProbeAbsent must collapse to an empty Vec<DependencyHash>",
        );
        let common = dep("common", "1.0.0", "oci://ghcr.io/pleme-io/charts");
        let listed = ChartDependenciesOutcome::Listed {
            deps: vec![common.clone()],
        }
        .to_dependency_hashes();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, common.name);
        assert_eq!(listed[0].version, common.version);
        assert_eq!(listed[0].hash, common.dep_hash());
        assert!(
            ChartDependenciesOutcome::Listed { deps: Vec::new() }
                .to_dependency_hashes()
                .is_empty(),
            "Listed{{deps: vec![]}} must surface as vec![] — the \
             leaf-chart claim collapses to the same surface value as \
             ProbeAbsent",
        );
    }

    /// `Listed { deps: vec![] }` (leaf chart — probe ran, chart
    /// declares no deps) and `ProbeAbsent` (no probe ran) collapse to
    /// the same `Vec<DependencyHash>` at the surface (`vec![]`) but
    /// remain structurally distinct at the enum level. The load-
    /// bearing discriminator the pre-fix `vec![]` literal erased: a
    /// downstream verifier reading the Phase 1 `dependency_hashes`
    /// field can recover "Chart.yaml probe ran and the chart is a
    /// leaf" as one of the two possible kind-of-claims, where the
    /// pre-fix literal conflated it indistinguishably with the no-
    /// probe-ran arm.
    #[test]
    fn test_listed_empty_collapses_to_empty_but_stays_distinct_from_absent() {
        let listed_empty = ChartDependenciesOutcome::Listed { deps: Vec::new() };
        let absent = ChartDependenciesOutcome::ProbeAbsent;
        assert!(listed_empty.to_dependency_hashes().is_empty());
        assert!(absent.to_dependency_hashes().is_empty());
        assert!(
            matches!(listed_empty, ChartDependenciesOutcome::Listed { .. }),
            "Listed{{deps: vec![]}} must remain in the Listed arm — the \
             structural discriminator the pre-fix `vec![]` hardcode erased",
        );
        assert!(matches!(absent, ChartDependenciesOutcome::ProbeAbsent));
    }

    /// The arms are mutually distinct under variant-tag inspection
    /// across representative dep-set cardinalities. Pins the load-
    /// bearing discriminator-preservation invariant the typed primitive
    /// exists to enforce: `Listed { deps: vec![] }` (leaf chart),
    /// `Listed { deps: vec![d1] }` (one-dep chart),
    /// `Listed { deps: vec![d1, d2] }` (multi-dep chart) all remain
    /// in the `Listed` arm, while `ProbeAbsent` (no Chart.yaml probe
    /// ran) is the lone arm without evidence. The cardinality
    /// distinction is recoverable from `deps.len()`.
    #[test]
    fn test_arms_are_structurally_distinct() {
        let leaf = ChartDependenciesOutcome::Listed { deps: Vec::new() };
        let one_dep = ChartDependenciesOutcome::Listed {
            deps: vec![dep("a", "1.0", "r")],
        };
        let multi = ChartDependenciesOutcome::Listed {
            deps: vec![dep("a", "1.0", "r"), dep("b", "2.0", "r")],
        };
        let absent = ChartDependenciesOutcome::ProbeAbsent;
        match (&leaf, &one_dep, &multi, &absent) {
            (
                ChartDependenciesOutcome::Listed { deps: d0 },
                ChartDependenciesOutcome::Listed { deps: d1 },
                ChartDependenciesOutcome::Listed { deps: d2 },
                ChartDependenciesOutcome::ProbeAbsent,
            ) => {
                assert_eq!(d0.len(), 0);
                assert_eq!(d1.len(), 1);
                assert_eq!(d2.len(), 2);
            }
            _ => panic!("variant tags must be Listed / Listed / Listed / ProbeAbsent"),
        }
    }

    /// End-to-end through `probe_chart_dependencies`: a Chart.yaml on
    /// disk with declared deps yields `Listed { deps }` carrying the
    /// canonical entries. The async I/O wrapper behaves identically to
    /// the pure parser on the same input.
    #[tokio::test]
    async fn test_probe_chart_dependencies_returns_listed_for_chart_yaml_with_deps() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let chart_dir = tmp.path().join("example");
        std::fs::create_dir(&chart_dir).expect("mkdir chart");
        std::fs::write(
            chart_dir.join("Chart.yaml"),
            r#"
apiVersion: v2
name: example
version: 0.1.0
dependencies:
  - name: common
    version: 1.0.0
    repository: "oci://ghcr.io/pleme-io/charts"
"#,
        )
        .expect("write Chart.yaml");
        let outcome = probe_chart_dependencies(&chart_dir).await;
        match outcome {
            ChartDependenciesOutcome::Listed { deps } => {
                assert_eq!(
                    deps,
                    vec![dep("common", "1.0.0", "oci://ghcr.io/pleme-io/charts")],
                );
            }
            ChartDependenciesOutcome::ProbeAbsent => panic!("expected Listed, got ProbeAbsent"),
        }
    }

    /// End-to-end through `probe_chart_dependencies`: a missing
    /// `Chart.yaml` (the chart_path exists but no Chart.yaml inside)
    /// collapses to `ProbeAbsent` — the honest "no probe reached a
    /// dep-graph claim" record. The pre-fix `vec![]` hardcode
    /// reported an empty dep-hash vec against this state without
    /// distinguishing it from a leaf chart.
    #[tokio::test]
    async fn test_probe_chart_dependencies_returns_probe_absent_for_missing_chart_yaml() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let chart_dir = tmp.path().join("example");
        std::fs::create_dir(&chart_dir).expect("mkdir chart");
        let outcome = probe_chart_dependencies(&chart_dir).await;
        assert!(
            matches!(outcome, ChartDependenciesOutcome::ProbeAbsent),
            "missing Chart.yaml must yield ProbeAbsent, not a silent \
             empty Listed",
        );
    }
}
