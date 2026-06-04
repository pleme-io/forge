//! Typed probe outcomes for the build / image security-scan layer
//! (SBOM and vulnerability scan) — the typed peers of
//! [`crate::cosign`] (image-signature probe),
//! [`crate::helm_provenance`] (chart-provenance probe),
//! [`crate::oci_architecture`] (manifest-architecture probe), and
//! [`crate::oci_manifest`] (manifest-identity oracle).
//!
//! ## What this module closes
//!
//! `commands/attestation.rs::compute_build_attestation` and
//! `commands/attestation.rs::compute_image_attestation` previously stamped
//! four name-keyed deterministic constants into every Phase 1 build /
//! image attestation as the SBOM and vuln-scan identities:
//!
//! ```ignore
//! // compute_build_attestation
//! let sbom_hash      = Blake3Hash::digest(format!("sbom-{}",      service).as_bytes());
//! let vuln_scan_hash = Blake3Hash::digest(format!("vuln-scan-{}", service).as_bytes());
//! // compute_image_attestation
//! let sbom_hash      = Blake3Hash::digest(format!("image-sbom-{}", tag).as_bytes());
//! let vuln_scan_hash = Blake3Hash::digest(format!("image-vuln-{}", tag).as_bytes());
//! ```
//!
//! No syft / grype / trivy probe layer is integrated yet — none of these
//! hashes derive from a real SBOM document or vuln-scan report. Each is a
//! pure function of the artifact's *name*. A downstream verifier
//! reconciling the Phase 1 record against the actual artifact would find:
//!
//!   * Two distinct services with byte-identical Nix closures still
//!     produce different `sbom_hash` values (the name is the only input).
//!   * Two distinct image tags pointing at the same manifest still
//!     produce different `image_sbom` values, for the same reason.
//!   * The `cve_count: 0` / `critical_high_cves: 0` fields paired with
//!     the hashes assert "0 CVEs found" when in fact *no scan was run*.
//!
//! This is the same false-by-construction shape commit e8a2df7 closed
//! for `chart_hash` (`Blake3Hash::digest(format!("chart-{name}", ...))`
//! → `b"no-chart-dir"`), commit 9c5a99f closed for `tree_hash`
//! (`Blake3Hash::digest(b"")` → `b"no-tree-listing"`), commit 443bd22
//! closed for `manifest_hash` (`b"no-manifest"`), and commit fffca30
//! closed for the image `architecture` field (`"amd64"` literal →
//! [`crate::oci_architecture::OciArchitectureOutcome`]). The typed
//! primitive here completes the SBOM / vuln-scan side of the same
//! Phase 1 attestation-honesty arc (THEORY §V.2: attestation is
//! cryptographic evidence, not a wish — a hash that has no relationship
//! to a probe response cannot witness what the probe would have said).
//!
//! ## Why two typed enums, not four sentinels
//!
//! The minimal honesty fix would route each of the four call sites
//! through an explicit `b"no-sbom"` / `b"no-vuln-scan"` byte sentinel
//! and stop. The typed-enum shape compounds it: the `Collected` arm is
//! the future enrichment point. When a syft probe is wired into the
//! build pipeline, the call site changes from
//! `SbomProbeOutcome::Absent` to `SbomProbeOutcome::Collected { hash:
//! Blake3Hash::digest(&syft_canonical_output) }`, and the attestation
//! field automatically reflects the substantive evidence. The
//! `Absent` arm continues to exist for the build artifacts a syft probe
//! cannot reach (a Nix closure pre-realisation, a tagged image not yet
//! resident in the registry), so the typed primitive also names the
//! probe's reach honestly — the same shape
//! [`crate::cosign::CosignVerifyOutcome::ProbeAbsent`] gives the cosign
//! call site for the "no cosign on PATH" world.
//!
//! Two arms (not four) is the minimum that closes the dishonesty
//! without designing speculative discriminators a probe layer that
//! does not yet exist might emit. A future commit that integrates the
//! probe layer will know what discriminators its CLI actually
//! reports — at that point the enum can grow `ProbeFailed { stderr }`
//! / `ProbeAbsent` arms over the spawn-vs-op surface
//! [`crate::retry::classify_capture_query`] already canonicalises.
//!
//! ## Sentinel naming
//!
//! `Absent` collapses to `Blake3Hash::digest(b"no-sbom")` /
//! `Blake3Hash::digest(b"no-vuln-scan")` — single per-kind sentinels,
//! shared across build and image. The honesty being recovered is "no
//! probe layer integrated"; that fact is the same shape whether the
//! attested artifact is a Nix closure or a container image. A
//! downstream verifier reading `sbom_hash =
//! Blake3Hash::digest(b"no-sbom")` recovers the kind-of-claim ("no SBOM
//! evidence, by construction") from the value alone, without
//! re-resolving the artifact. The two sentinels are mutually distinct
//! and distinct from any real BLAKE3 of an actual SBOM / vuln-scan
//! document (which would be the hash of a JSON/XML/SPDX/CycloneDX
//! payload — never of the 7-byte ASCII string `"no-sbom"` or the
//! 13-byte ASCII string `"no-vuln-scan"`), so a verifier cannot
//! mistake one for the other or for a substantive claim.
//!
//! ## Frontier inspiration
//!
//! SLSA v1.0 §"Build Provenance" (specifically the `subject[].digest`
//! field on an in-toto Statement) requires every claimed artifact
//! identity to be a content-addressed digest of the artifact itself —
//! never a digest of its name or tag. anchore / syft, aquasecurity /
//! trivy, and the SPDX / CycloneDX SBOM specs all emit canonical
//! documents whose BLAKE3 / SHA256 digest IS the SBOM's identity; an
//! attestation that records a placeholder hash with no relationship to
//! the SBOM document fails every reconciliation an `in-toto verify` or
//! `sigstore-rs verify` pass could run. The typed `Absent` arm names
//! that gap honestly rather than inflating it with a constant — the
//! same discipline `OciArchitectureOutcome::Absent` /
//! `OciArchitectureOutcome::EmbeddedInConfig` apply at the OCI
//! manifest-architecture layer.

use tameshi::hash::Blake3Hash;

/// Outcome of probing for an SBOM (software bill of materials) for a
/// build artifact (Nix closure) or container image. Mirrors
/// [`crate::cosign::CosignVerifyOutcome`] /
/// [`crate::helm_provenance::HelmProvenanceOutcome`] /
/// [`crate::oci_architecture::OciArchitectureOutcome`]: a typed shape
/// over the operational worlds a downstream probe (syft, anchore-syft,
/// nix-sbom) could report. Two arms today — `Collected` /
/// `Absent` — over the only two worlds a *production* call site can
/// reach until a syft probe is integrated; the `Absent` arm is the
/// honest record of "no SBOM probe layer wired in yet" and is the
/// future enrichment point where a real syft document's BLAKE3 digest
/// will land.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SbomProbeOutcome {
    /// A real SBOM document was collected. `hash` is the BLAKE3 digest
    /// of the canonical SBOM payload (SPDX / CycloneDX / syft JSON;
    /// the canonical form is the probe-layer's responsibility) — the
    /// content-addressed identity the Phase 1 attestation seals.
    Collected { hash: Blake3Hash },
    /// No SBOM probe layer is integrated for this artifact, or the
    /// probe could not reach the artifact (e.g. closure not yet
    /// realised, image not yet resident in the registry). The
    /// attestation field collapses to
    /// `Blake3Hash::digest(b"no-sbom")` — a single per-kind sentinel,
    /// shared across build and image, distinct from any real BLAKE3
    /// of an actual SBOM document.
    Absent,
}

impl SbomProbeOutcome {
    /// The BLAKE3 digest the Phase 1 attestation's `sbom_hash` field
    /// carries. The `Collected` arm yields the captured hash; the
    /// `Absent` arm yields the `b"no-sbom"` sentinel (single per-kind
    /// constant, distinct from any real BLAKE3 of an actual SBOM
    /// document, so a downstream verifier can recover the kind-of-
    /// claim from the value alone).
    pub fn to_attestation_hash(&self) -> Blake3Hash {
        match self {
            Self::Collected { hash } => hash.clone(),
            Self::Absent => Blake3Hash::digest(b"no-sbom"),
        }
    }
}

crate::impl_probe_outcome!(SbomProbeOutcome, Absent);

/// Outcome of probing for a vulnerability scan (CVE enumeration)
/// against a build artifact or container image. Mirrors
/// [`SbomProbeOutcome`] one layer over — same `Collected` / `Absent`
/// shape, but the `Collected` arm carries the scan's CVE counts
/// alongside the hash, because the BuildAttestation /
/// ImageAttestation records co-bind `(vuln_scan_hash, cve_count,
/// critical_high_cves)` as one triple: the hash names the scan
/// document, the counts name what it found.
///
/// `Absent` collapses to
/// `(Blake3Hash::digest(b"no-vuln-scan"), 0, 0)` — a single per-kind
/// sentinel for the hash, and zero counts that honestly assert "no
/// CVE evidence collected". The prior call-site code separately
/// hardcoded `0, 0` for the counts AND a name-keyed hash for the
/// scan; collapsing both into one typed-outcome conversion ensures
/// the three fields cannot drift apart at the boundary (the
/// canonical "three claims, one source" discipline THEORY §VI.1
/// names).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VulnScanProbeOutcome {
    /// A real vulnerability scan was collected. `hash` is the BLAKE3
    /// digest of the canonical scan payload; `total_cves` is the
    /// total CVE count the scan found; `critical_high` is the count
    /// of CRITICAL- or HIGH-severity CVEs.
    Collected {
        hash: Blake3Hash,
        total_cves: usize,
        critical_high: usize,
    },
    /// No vuln-scan probe layer is integrated for this artifact, or
    /// the probe could not reach the artifact. The attestation triple
    /// collapses to `(Blake3Hash::digest(b"no-vuln-scan"), 0, 0)` —
    /// zero counts because no CVE evidence was collected, never to be
    /// confused with a real scan that found zero CVEs (the latter
    /// would carry the BLAKE3 of an actual scan document).
    Absent,
}

impl VulnScanProbeOutcome {
    /// The `(vuln_scan_hash, total_cves, critical_high)` triple the
    /// Phase 1 attestation records co-bind. The `Collected` arm
    /// yields the captured triple; the `Absent` arm yields
    /// `(b"no-vuln-scan"-sentinel, 0, 0)`. Returning the triple from
    /// one method ensures the three fields cannot drift apart at the
    /// call site (a future regression that hand-rolled the hash and
    /// the counts separately would re-open the gap commit e8a2df7 /
    /// fffca30 / this commit close).
    pub fn to_attestation_fields(&self) -> (Blake3Hash, usize, usize) {
        match self {
            Self::Collected {
                hash,
                total_cves,
                critical_high,
            } => (hash.clone(), *total_cves, *critical_high),
            Self::Absent => (Blake3Hash::digest(b"no-vuln-scan"), 0, 0),
        }
    }
}

crate::impl_probe_outcome!(VulnScanProbeOutcome, Absent);

#[cfg(test)]
mod tests {
    use super::*;

    /// `SbomProbeOutcome::Absent` collapses to the canonical
    /// `b"no-sbom"` sentinel — the load-bearing honesty invariant the
    /// rest of the Phase 1 build / image attestation depends on. The
    /// pre-fix call sites stamped `Blake3Hash::digest(format!(
    /// "sbom-{service}", ...))` and `Blake3Hash::digest(format!(
    /// "image-sbom-{tag}", ...))`, both of which produce a *different*
    /// hash for every service / tag, falsely advertising per-artifact
    /// SBOM evidence that was never collected. The Absent sentinel is
    /// a single constant, structurally distinct from any real BLAKE3
    /// of an actual SBOM document (which would be the hash of a JSON
    /// / SPDX / CycloneDX payload — never of the 7-byte ASCII string
    /// `"no-sbom"`), so a downstream verifier recovers "no probe ran"
    /// from the value alone.
    #[test]
    fn test_sbom_absent_collapses_to_no_sbom_sentinel() {
        assert_eq!(
            SbomProbeOutcome::Absent.to_attestation_hash(),
            Blake3Hash::digest(b"no-sbom"),
        );
    }

    /// `SbomProbeOutcome::Collected { hash }` returns the carried
    /// hash verbatim — the future enrichment point. When a syft probe
    /// lands, the attestation field will carry the BLAKE3 of the
    /// syft canonical document, and this floor pins that no
    /// surprising mutation happens in the conversion.
    #[test]
    fn test_sbom_collected_returns_carried_hash() {
        let h = Blake3Hash::digest(b"syft-spdx-canonical-payload");
        assert_eq!(
            SbomProbeOutcome::Collected { hash: h.clone() }.to_attestation_hash(),
            h,
        );
    }

    /// `VulnScanProbeOutcome::Absent` collapses to the canonical
    /// `b"no-vuln-scan"` sentinel plus zero counts. Pins both halves
    /// of the triple in one assertion so a regression that hand-
    /// rolled the hash but left the counts behind (or vice versa)
    /// would fail. Counts default to 0 — the honest "no evidence
    /// collected" record, NOT "real scan found zero CVEs" (which
    /// would carry a real scan-document BLAKE3 in the hash slot).
    #[test]
    fn test_vuln_scan_absent_collapses_to_no_vuln_scan_sentinel() {
        assert_eq!(
            VulnScanProbeOutcome::Absent.to_attestation_fields(),
            (Blake3Hash::digest(b"no-vuln-scan"), 0, 0),
        );
    }

    /// `VulnScanProbeOutcome::Collected { ... }` returns the carried
    /// triple verbatim. The future enrichment point: when a grype /
    /// trivy probe lands, the hash will be the BLAKE3 of the scan
    /// document and the counts will reflect what it found. This
    /// floor pins the one-triple-from-one-source discipline so a
    /// future regression cannot drop a field on the floor.
    #[test]
    fn test_vuln_scan_collected_returns_carried_triple() {
        let h = Blake3Hash::digest(b"grype-canonical-scan-payload");
        let triple = VulnScanProbeOutcome::Collected {
            hash: h.clone(),
            total_cves: 42,
            critical_high: 3,
        }
        .to_attestation_fields();
        assert_eq!(triple, (h, 42, 3));
    }

    /// The two per-kind sentinels are mutually distinct so a
    /// downstream verifier reading either value can recover the
    /// kind-of-claim (SBOM vs vuln-scan) from the value alone. The
    /// pre-fix `Blake3Hash::digest(format!("sbom-{x}"))` /
    /// `Blake3Hash::digest(format!("vuln-scan-{x}"))` constants were
    /// also mutually distinct, but that distinction was incidental
    /// (any two name templates would have collided differently); the
    /// typed sentinels make the distinction load-bearing at the type
    /// level.
    #[test]
    fn test_sbom_and_vuln_scan_sentinels_are_distinct() {
        let sbom = SbomProbeOutcome::Absent.to_attestation_hash();
        let (vuln, _, _) = VulnScanProbeOutcome::Absent.to_attestation_fields();
        assert_ne!(sbom, vuln);
    }

    /// `SbomProbeOutcome::Absent` is the same value for every call
    /// site — no per-service / per-tag drift. The load-bearing
    /// fail-before / pass-after invariant: the pre-fix
    /// `Blake3Hash::digest(format!("sbom-{}", "alpha"))` and
    /// `Blake3Hash::digest(format!("sbom-{}", "beta"))` produced
    /// *different* hashes; under the typed shape, two services with
    /// no probe layer produce the *same* hash — because the same
    /// fact ("no SBOM evidence collected") holds for both. A
    /// downstream verifier reconciling the two records can then
    /// recognise the shared sentinel as "no probe ran" rather than
    /// chasing two distinct hashes that have no probe response to
    /// reconcile against.
    #[test]
    fn test_sbom_absent_is_invariant_across_artifacts() {
        let alpha = SbomProbeOutcome::Absent.to_attestation_hash();
        let beta = SbomProbeOutcome::Absent.to_attestation_hash();
        assert_eq!(alpha, beta);
        // And distinct from the pre-fix name-keyed shape: the typed
        // sentinel is NOT what `format!("sbom-{}", "alpha")` would
        // have produced. (Pins the named gap the typed shape closes:
        // a verifier that previously read `sbom-alpha`'s BLAKE3 from
        // an attestation now reads `no-sbom`'s BLAKE3 instead.)
        let pre_fix_alpha = Blake3Hash::digest(format!("sbom-{}", "alpha").as_bytes());
        assert_ne!(alpha, pre_fix_alpha);
    }

    /// Sibling of `test_sbom_absent_is_invariant_across_artifacts`
    /// for the vuln-scan triple. Two tags with no probe layer produce
    /// the same `(hash, 0, 0)` triple; the pre-fix
    /// `Blake3Hash::digest(format!("image-vuln-{}", tag))` per-tag
    /// constants are gone.
    #[test]
    fn test_vuln_scan_absent_is_invariant_across_artifacts() {
        let alpha = VulnScanProbeOutcome::Absent.to_attestation_fields();
        let beta = VulnScanProbeOutcome::Absent.to_attestation_fields();
        assert_eq!(alpha, beta);
        let pre_fix_alpha = Blake3Hash::digest(format!("image-vuln-{}", "alpha").as_bytes());
        assert_ne!(alpha.0, pre_fix_alpha);
    }

    /// `ProbeOutcome` impl pin for both `SbomProbeOutcome` and
    /// `VulnScanProbeOutcome`: the `Absent` arm identifies as absent
    /// (this module uses the alternative `Absent` variant name —
    /// shared with `OciArchitectureOutcome`); the `Collected` arms do
    /// not.
    #[test]
    fn test_probe_outcome_impl() {
        use crate::probe_outcome::ProbeOutcome;
        assert!(SbomProbeOutcome::Absent.is_probe_absent());
        assert!(!SbomProbeOutcome::Collected {
            hash: Blake3Hash::digest(b"x"),
        }
        .is_probe_absent());
        assert!(VulnScanProbeOutcome::Absent.is_probe_absent());
        assert!(!VulnScanProbeOutcome::Collected {
            hash: Blake3Hash::digest(b"y"),
            total_cves: 0,
            critical_high: 0,
        }
        .is_probe_absent());
    }
}
