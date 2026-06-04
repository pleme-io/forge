//! Typed OCI / Docker container-manifest architecture outcome for forge's
//! Phase 1 image attestation.
//!
//! `commands/attestation.rs::compute_image_attestation` previously hardcoded
//! `"amd64"` into [`ImageAttestation::architecture`] regardless of what the
//! `skopeo inspect --raw` manifest probe actually announced. Five operational
//! worlds were flattened into one false claim:
//!
//! 1. **Single-architecture index** — an OCI image index whose `manifests[]`
//!    points at exactly one per-platform manifest carries that platform's
//!    `architecture` directly in the manifest itself ("amd64", "arm64",
//!    "ppc64le", …).
//! 2. **Multi-architecture index** — an index pointing at multiple platforms
//!    announces them via `manifests[i].platform.architecture`; the manifest
//!    itself does not have a single architecture, it composes several.
//! 3. **Docker v1 manifest** — a legacy `schemaVersion: 1` manifest carries
//!    `architecture` as a top-level field directly in the manifest.
//! 4. **OCI image manifest / Docker v2 image manifest** — `application/vnd.
//!    oci.image.manifest.v1+json` or its Docker v2 peer references a config
//!    blob by digest (`config.digest`); the `architecture` field lives
//!    *inside that config blob*, not in the manifest itself. The `--raw`
//!    probe never fetched the config, so the architecture is structurally
//!    unrecoverable from the manifest alone. The honest record is "the
//!    architecture lives in the referenced config blob, this probe did not
//!    fetch it" — not a guess of `"amd64"`.
//! 5. **Probe absent / unparseable** — `skopeo inspect --raw` failed or the
//!    response was not a recognised manifest shape. No probe ran or its
//!    output yielded no architecture evidence. The honest record is
//!    `"unknown"`, distinct from any of the four substantive arms.
//!
//! The prior `architecture: "amd64"` hardcode misreported all five — false
//! by construction for every arm64 / ppc64le / s390x / multi-arch build,
//! and structurally dishonest even for an actual amd64 build (the manifest
//! probe alone never substantiated the claim).
//!
//! ## Why a typed enum, not a string
//!
//! THEORY §V.4 Phase 1 attestation: every claim a typed primitive can
//! populate must be populated honestly, not stubbed. THEORY §V.1: make
//! invalid states unrepresentable. A `String` field cannot tell a verifier
//! whether `"amd64"` came from the manifest, from a config blob the
//! manifest probe did not fetch, or from a hardcoded constant the build
//! never substantiated. The four-arm enum preserves the index-multi-vs-
//! index-single-vs-v1-explicit-vs-embedded-vs-absent distinction at the
//! type level, then collapses to a single attestation string via
//! [`OciArchitectureOutcome::to_attestation_arch`] with a Multi-prefixed
//! and Embedded-prefixed sentinel discipline so a downstream verifier can
//! recover the kind of claim from the string itself.
//!
//! This module is the typed peer of [`crate::cosign`] (cosign verify
//! outcome), [`crate::helm_provenance`] (Helm `.prov` outcome),
//! [`crate::oci_manifest`] (manifest-identity oracle), [`crate::tree_listing`]
//! and [`crate::store_path`] (source / build identity oracles), and
//! [`crate::chart_listing`] (chart-identity oracle). Each names the
//! canonical shape of one external probe the attestation chain depends
//! on, so the call site cannot accidentally lose a discriminator at the
//! boundary.
//!
//! ## Frontier inspiration
//!
//! OCI / Docker distribution spec — an image index (`application/vnd.oci.
//! image.index.v1+json` / `application/vnd.docker.distribution.manifest.
//! list.v2+json`) explicitly declares per-platform architectures via the
//! `manifests[i].platform` block; an image manifest does not, by design
//! (the architecture lives in the runtime config). A verifier reconciling
//! "which architecture did this build target?" reads the index's platform
//! blocks, OR fetches the image manifest's config blob and reads its
//! `architecture` field — never inflates the claim from a constant. The
//! `Embedded` arm records the second case honestly: forge's `--raw` probe
//! recovered the manifest, the architecture is structurally elsewhere,
//! and the record names that fact rather than synthesising a guess.

/// Sentinel string written into [`ImageAttestation::architecture`] when the
/// architecture lives in a referenced config blob the manifest probe did
/// not fetch. Distinct from any real architecture name; a verifier
/// reconciling architectures recognises this as "manifest probe alone
/// cannot substantiate the claim" rather than mistaking it for a literal
/// arch.
const EMBEDDED_SENTINEL: &str = "embedded-in-config";

/// Sentinel string written into [`ImageAttestation::architecture`] when the
/// manifest probe failed OR yielded no recoverable architecture evidence.
/// Distinct from `EMBEDDED_SENTINEL` so a downstream verifier can tell
/// "we saw a manifest with no arch info" from "the probe never ran".
const ABSENT_SENTINEL: &str = "unknown";

/// Prefix prepended to the comma-joined architecture set when a manifest
/// announces multiple architectures (an OCI index pointing at two or more
/// per-platform manifests). Distinguishes a composite claim from a literal
/// architecture name a verifier might otherwise mistake for the string
/// `"amd64,arm64"`.
const MULTI_PREFIX: &str = "multi:";

/// Outcome of parsing an OCI / Docker container manifest for architecture
/// evidence. Five operational worlds preserved at the type level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OciArchitectureOutcome {
    /// Manifest announces exactly one architecture directly: either a v1
    /// manifest with top-level `architecture`, or an index whose
    /// `manifests[]` collapsed to one platform.
    Single { arch: String },
    /// Index manifest announces multiple architectures via per-entry
    /// `platform.architecture`. The set is sorted and deduplicated by
    /// construction.
    Multi { archs: Vec<String> },
    /// Image manifest references a config blob by digest; the architecture
    /// lives inside that config blob, not in the manifest itself. The
    /// `--raw` manifest probe never fetched the config, so the architecture
    /// is structurally unrecoverable from this probe alone.
    EmbeddedInConfig,
    /// Manifest probe failed, returned an unparseable response, or yielded
    /// a JSON shape with no recoverable architecture evidence (not a
    /// v1 manifest, not an index, not an image manifest).
    Absent,
}

impl OciArchitectureOutcome {
    /// Collapse the typed outcome to the [`String`] the Phase 1
    /// [`ImageAttestation::architecture`] field carries.
    ///
    /// - `Single { arch }` → the bare arch name (e.g. `"arm64"`).
    /// - `Multi { archs }` → `"multi:arch1,arch2,…"` (sorted, deduplicated).
    /// - `EmbeddedInConfig` → `"embedded-in-config"`.
    /// - `Absent` → `"unknown"`.
    ///
    /// The Multi / Embedded / Absent sentinels are intentionally
    /// unmistakable for any real architecture string so a downstream
    /// verifier reading the attestation can recover the *kind* of claim
    /// from the value alone, without re-fetching the manifest.
    pub fn to_attestation_arch(&self) -> String {
        match self {
            Self::Single { arch } => arch.clone(),
            Self::Multi { archs } => format!("{}{}", MULTI_PREFIX, archs.join(",")),
            Self::EmbeddedInConfig => EMBEDDED_SENTINEL.to_string(),
            Self::Absent => ABSENT_SENTINEL.to_string(),
        }
    }
}

crate::impl_probe_outcome!(OciArchitectureOutcome, Absent);

/// Parse a `skopeo inspect --raw` manifest JSON document into an
/// [`OciArchitectureOutcome`].
///
/// Detection ladder, in priority order:
///
/// 1. **Top-level `architecture` string (Docker v1)** — wins outright;
///    a v1 manifest names its architecture directly and authoritatively.
/// 2. **`manifests[]` array (OCI / Docker v2 index)** — collect every
///    `platform.architecture` string into a sorted, deduplicated set:
///    zero → `Absent` (the index named no platforms), one → `Single`,
///    two-or-more → `Multi`.
/// 3. **`config.digest` (OCI / Docker v2 image manifest)** — the
///    architecture is in the referenced config blob; record
///    `EmbeddedInConfig` rather than guess.
/// 4. **Anything else** (malformed JSON, JSON-but-not-a-manifest, etc.)
///    → `Absent`.
///
/// Whitespace-only architecture strings are dropped (a registry that
/// emits empty platform blocks must not leak `""` into the attestation),
/// mirroring the `pick_identity` whitespace-rejection discipline in
/// [`crate::cosign`].
pub fn parse_manifest_architectures(manifest_json: &str) -> OciArchitectureOutcome {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(manifest_json) else {
        return OciArchitectureOutcome::Absent;
    };
    let Some(obj) = value.as_object() else {
        return OciArchitectureOutcome::Absent;
    };

    // (1) Docker v1: top-level `architecture` is authoritative.
    if let Some(arch) = obj
        .get("architecture")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return OciArchitectureOutcome::Single {
            arch: arch.to_string(),
        };
    }

    // (2) OCI / Docker v2 index: collect per-platform architectures.
    if let Some(manifests) = obj.get("manifests").and_then(|v| v.as_array()) {
        let mut archs: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for entry in manifests {
            if let Some(arch) = entry
                .get("platform")
                .and_then(|p| p.get("architecture"))
                .and_then(|a| a.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                archs.insert(arch.to_string());
            }
        }
        return match archs.len() {
            0 => OciArchitectureOutcome::Absent,
            1 => OciArchitectureOutcome::Single {
                arch: archs.into_iter().next().expect("len == 1"),
            },
            _ => OciArchitectureOutcome::Multi {
                archs: archs.into_iter().collect(),
            },
        };
    }

    // (3) OCI / Docker v2 image manifest: architecture is in the
    // referenced config blob the manifest probe did not fetch.
    if obj
        .get("config")
        .and_then(|c| c.get("digest"))
        .and_then(|d| d.as_str())
        .is_some_and(|s| !s.trim().is_empty())
    {
        return OciArchitectureOutcome::EmbeddedInConfig;
    }

    OciArchitectureOutcome::Absent
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A realistic 64-char lowercase-hex SHA-256 digest body fixture, reused
    /// across the manifest shapes so tests focus on the architecture-recovery
    /// surface rather than digest formatting.
    const D1: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const D2: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    /// Docker v1 manifest: top-level `architecture` is the authoritative
    /// per-manifest architecture claim. Recovers as `Single`.
    #[test]
    fn test_parse_docker_v1_top_level_architecture() {
        let json = format!(
            r#"{{
                "schemaVersion": 1,
                "architecture": "amd64",
                "fsLayers": [{{"blobSum": "sha256:{D1}"}}]
            }}"#
        );
        assert_eq!(
            parse_manifest_architectures(&json),
            OciArchitectureOutcome::Single {
                arch: "amd64".to_string()
            }
        );
    }

    /// OCI image index with one per-platform manifest collapses to `Single`
    /// (one architecture in the set after dedup).
    #[test]
    fn test_parse_oci_index_single_arch() {
        let json = format!(
            r#"{{
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [
                    {{"digest": "sha256:{D1}",
                      "platform": {{"architecture": "arm64", "os": "linux"}}}}
                ]
            }}"#
        );
        assert_eq!(
            parse_manifest_architectures(&json),
            OciArchitectureOutcome::Single {
                arch: "arm64".to_string()
            }
        );
    }

    /// OCI image index with multiple per-platform manifests recovers as
    /// `Multi { archs }`, sorted and deduplicated.
    #[test]
    fn test_parse_oci_index_multi_arch_sorted_dedup() {
        let json = format!(
            r#"{{
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [
                    {{"digest": "sha256:{D1}",
                      "platform": {{"architecture": "ppc64le", "os": "linux"}}}},
                    {{"digest": "sha256:{D2}",
                      "platform": {{"architecture": "amd64", "os": "linux"}}}},
                    {{"digest": "sha256:{D1}",
                      "platform": {{"architecture": "amd64", "os": "linux"}}}},
                    {{"digest": "sha256:{D2}",
                      "platform": {{"architecture": "arm64", "os": "linux"}}}}
                ]
            }}"#
        );
        assert_eq!(
            parse_manifest_architectures(&json),
            OciArchitectureOutcome::Multi {
                archs: vec![
                    "amd64".to_string(),
                    "arm64".to_string(),
                    "ppc64le".to_string()
                ]
            }
        );
    }

    /// OCI / Docker v2 image manifest references a config blob by digest
    /// but does not announce architecture directly. Recovers as
    /// `EmbeddedInConfig` — the honest "we saw a manifest, the arch lives
    /// in the referenced config blob" record.
    #[test]
    fn test_parse_oci_image_manifest_embedded_in_config() {
        let json = format!(
            r#"{{
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {{
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "digest": "sha256:{D1}",
                    "size": 1234
                }},
                "layers": [
                    {{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                      "digest": "sha256:{D2}", "size": 5000}}
                ]
            }}"#
        );
        assert_eq!(
            parse_manifest_architectures(&json),
            OciArchitectureOutcome::EmbeddedInConfig
        );
    }

    /// Docker v2 image manifest media type also produces `EmbeddedInConfig`
    /// — the detection is by `config.digest` presence, not media type, so
    /// both OCI and Docker v2 image-manifest forms are recognised.
    #[test]
    fn test_parse_docker_v2_image_manifest_embedded_in_config() {
        let json = format!(
            r#"{{
                "schemaVersion": 2,
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "config": {{"digest": "sha256:{D1}", "size": 999}},
                "layers": [{{"digest": "sha256:{D2}", "size": 500}}]
            }}"#
        );
        assert_eq!(
            parse_manifest_architectures(&json),
            OciArchitectureOutcome::EmbeddedInConfig
        );
    }

    /// An index whose `manifests[]` entries carry no `platform` blocks
    /// (rare but spec-legal — some registries omit them) collapses to
    /// `Absent`. We refuse to claim an architecture the manifest did not
    /// substantiate.
    #[test]
    fn test_parse_index_without_platform_blocks_is_absent() {
        let json = format!(
            r#"{{
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [
                    {{"digest": "sha256:{D1}"}},
                    {{"digest": "sha256:{D2}"}}
                ]
            }}"#
        );
        assert_eq!(
            parse_manifest_architectures(&json),
            OciArchitectureOutcome::Absent
        );
    }

    /// Whitespace-only architecture strings inside `platform.architecture`
    /// must NOT leak into the outcome — a registry emitting `"   "` is
    /// not announcing any architecture. Mirrors the
    /// `pick_identity` whitespace-rejection discipline in
    /// [`crate::cosign`].
    #[test]
    fn test_parse_drops_whitespace_only_architectures() {
        let json = format!(
            r#"{{
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [
                    {{"digest": "sha256:{D1}",
                      "platform": {{"architecture": "   ", "os": "linux"}}}},
                    {{"digest": "sha256:{D2}",
                      "platform": {{"architecture": "amd64", "os": "linux"}}}}
                ]
            }}"#
        );
        assert_eq!(
            parse_manifest_architectures(&json),
            OciArchitectureOutcome::Single {
                arch: "amd64".to_string()
            }
        );
    }

    /// Malformed JSON collapses to `Absent` rather than panic — the
    /// pre-fix hardcode would have stamped `"amd64"` regardless of what
    /// the bytes were, false by construction.
    #[test]
    fn test_parse_malformed_json_is_absent() {
        assert_eq!(
            parse_manifest_architectures("not json at all {{{"),
            OciArchitectureOutcome::Absent
        );
    }

    /// An empty string from a failed probe collapses to `Absent`.
    #[test]
    fn test_parse_empty_string_is_absent() {
        assert_eq!(
            parse_manifest_architectures(""),
            OciArchitectureOutcome::Absent
        );
    }

    /// A JSON document that is well-formed but is not a manifest shape
    /// (e.g. a top-level array, or an object with no architecture / no
    /// `manifests[]` / no `config.digest`) collapses to `Absent`. The
    /// outcome must not be inflated from a structurally-unrelated JSON
    /// document.
    #[test]
    fn test_parse_non_manifest_json_is_absent() {
        assert_eq!(
            parse_manifest_architectures("[1, 2, 3]"),
            OciArchitectureOutcome::Absent
        );
        assert_eq!(
            parse_manifest_architectures(r#"{"schemaVersion": 2}"#),
            OciArchitectureOutcome::Absent
        );
        // Object with a `config` block but no digest is malformed; do
        // not infer EmbeddedInConfig from the field name alone.
        assert_eq!(
            parse_manifest_architectures(r#"{"config": {"size": 1234}}"#),
            OciArchitectureOutcome::Absent
        );
    }

    /// The v1 top-level `architecture` arm wins over a `manifests[]` /
    /// `config.digest` arm when both are present (engineered cases). v1
    /// is authoritative because it names the architecture directly.
    #[test]
    fn test_parse_v1_top_level_wins_over_other_arms() {
        let json = format!(
            r#"{{
                "schemaVersion": 1,
                "architecture": "s390x",
                "config": {{"digest": "sha256:{D1}"}},
                "manifests": [
                    {{"digest": "sha256:{D2}",
                      "platform": {{"architecture": "amd64", "os": "linux"}}}}
                ]
            }}"#
        );
        assert_eq!(
            parse_manifest_architectures(&json),
            OciArchitectureOutcome::Single {
                arch: "s390x".to_string()
            }
        );
    }

    /// `to_attestation_arch` collapses each arm to the canonical string
    /// the Phase 1 [`ImageAttestation::architecture`] field carries.
    /// `Multi` is prefixed with `multi:` and the archs joined with `,`;
    /// `EmbeddedInConfig` and `Absent` carry unmistakable sentinels.
    #[test]
    fn test_to_attestation_arch_string_shape() {
        assert_eq!(
            OciArchitectureOutcome::Single {
                arch: "arm64".to_string()
            }
            .to_attestation_arch(),
            "arm64"
        );
        assert_eq!(
            OciArchitectureOutcome::Multi {
                archs: vec!["amd64".to_string(), "arm64".to_string()]
            }
            .to_attestation_arch(),
            "multi:amd64,arm64"
        );
        assert_eq!(
            OciArchitectureOutcome::EmbeddedInConfig.to_attestation_arch(),
            "embedded-in-config"
        );
        assert_eq!(
            OciArchitectureOutcome::Absent.to_attestation_arch(),
            "unknown"
        );
    }

    /// The four arms produce four distinct attestation strings — the
    /// load-bearing property that lets a downstream verifier recover the
    /// kind of claim from the string alone. The `Multi`-prefixed and
    /// `Embedded`-sentinel forms are unmistakable for any literal
    /// architecture name, so a verifier reading `"amd64"` knows it came
    /// from a v1 manifest or a single-arch index — not from a Multi
    /// composition the registry stripped.
    #[test]
    fn test_attestation_strings_are_mutually_distinct() {
        let single = OciArchitectureOutcome::Single {
            arch: "amd64".to_string(),
        }
        .to_attestation_arch();
        let multi = OciArchitectureOutcome::Multi {
            archs: vec!["amd64".to_string(), "arm64".to_string()],
        }
        .to_attestation_arch();
        let embedded = OciArchitectureOutcome::EmbeddedInConfig.to_attestation_arch();
        let absent = OciArchitectureOutcome::Absent.to_attestation_arch();
        let all = [&single, &multi, &embedded, &absent];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(
                    all[i], all[j],
                    "the four attestation strings must be mutually distinct \
                     so a verifier can recover the kind of claim from the \
                     value alone"
                );
            }
        }
    }

    /// Fail-before / pass-after pin: the prior `architecture: "amd64"`
    /// hardcode was false by construction for an arm64-only image. The
    /// typed primitive recovers the correct arch from the same `--raw`
    /// JSON the call site already fetched for `manifest_hash`. The
    /// outcome's attestation string must NOT be `"amd64"` for an arm64
    /// index — the property the prior body could not satisfy.
    #[test]
    fn test_arm64_only_index_does_not_misreport_as_amd64() {
        let json = format!(
            r#"{{
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [
                    {{"digest": "sha256:{D1}",
                      "platform": {{"architecture": "arm64", "os": "linux"}}}}
                ]
            }}"#
        );
        let outcome = parse_manifest_architectures(&json);
        let attestation_arch = outcome.to_attestation_arch();
        assert_eq!(attestation_arch, "arm64");
        assert_ne!(
            attestation_arch, "amd64",
            "an arm64-only manifest must NOT be reported as amd64; \
             the prior hardcode flattened this case to a false claim"
        );
    }

    /// `ProbeOutcome` impl pin: `Absent` identifies as absent (the
    /// alternative-named absent variant the `security_scan` modules
    /// also use); `Single`, `Multi`, and `EmbeddedInConfig` do not.
    #[test]
    fn test_probe_outcome_impl() {
        use crate::probe_outcome::ProbeOutcome;
        assert!(OciArchitectureOutcome::Absent.is_probe_absent());
        assert!(!OciArchitectureOutcome::Single {
            arch: "arm64".to_string(),
        }
        .is_probe_absent());
        assert!(!OciArchitectureOutcome::Multi {
            archs: vec!["amd64".to_string(), "arm64".to_string()],
        }
        .is_probe_absent());
        assert!(!OciArchitectureOutcome::EmbeddedInConfig.is_probe_absent());
    }
}
