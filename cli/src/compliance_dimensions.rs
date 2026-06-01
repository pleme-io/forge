//! Canonical compliance-dimensions fingerprint for forge.
//!
//! A [`ComplianceAttestation`] (`tameshi::compliance::dimensions`) carries
//! a `compliance_hash` field whose canonical derivation is "sort the
//! `Vec<ComplianceDimension>` by the [`Display`] form of each dimension's
//! `dimension_type`, concatenate every dimension's 32-byte BLAKE3 hash,
//! BLAKE3 the result". This is the algorithm
//! `tameshi::compliance::dimensions::AttestationBuilder::build` runs
//! internally before stamping the composed hash on the attestation it
//! returns; any ComplianceAttestation produced by a different construction
//! path must reproduce the same algorithm or the same dimensions yield
//! two distinct `compliance_hash` values.
//!
//! `commands/attestation.rs::compose_product_certification` previously
//! sidestepped the builder and constructed [`ComplianceAttestation`] as a
//! bare struct, stamping `compliance_hash: Blake3Hash::digest(b"initial-
//! compliance")` — a name-keyed sentinel independent of the dimensions
//! vec actually composed into the attestation. Two structural honesty
//! failures followed (mirroring the closed gap at the source-tree
//! [`crate::tree_listing`], image-manifest [`crate::oci_manifest`], and
//! chart-content [`crate::chart_listing`] layers): (a) the same dimension
//! set yielded two distinct `compliance_hash` values depending on
//! construction path (forge bare vs tameshi builder), defeating the
//! attestation-hash-as-content-identity invariant THEORY §VI.1 names;
//! and (b) two structurally different dimension sets — one with a
//! passing SLSA-provenance dimension, one with a failing one — produced
//! identical `compliance_hash` values, since the stamp was constant.
//!
//! This module is the compliance-side peer of [`crate::tree_listing`] /
//! [`crate::oci_manifest`] / [`crate::chart_listing`]:
//! [`canonical_dimensions_fingerprint`] reduces a `&[ComplianceDimension]`
//! to the sorted concatenation of per-dimension 32-byte hash arrays that
//! the call site BLAKE3s — exactly what tameshi's builder runs — so the
//! `compliance_hash` field carries content-addressed evidence over the
//! dimensions, not a constant.

use tameshi::compliance::dimensions::ComplianceDimension;

/// Canonical, order-independent fingerprint of a compliance-dimensions
/// vec, derived from each dimension's 32-byte BLAKE3 hash.
///
/// The fingerprint is the concatenation of `dim.hash.0` bytes over the
/// dimensions sorted by `format!("{}", dim.dimension_type)` (the
/// [`Display`] form of [`DimensionType`]). The caller BLAKE3s the
/// returned bytes; the resulting hash is the `compliance_hash` field of
/// the [`ComplianceAttestation`] under construction.
///
/// The algorithm mirrors `tameshi::compliance::dimensions::AttestationBuilder::build`
/// exactly, so a [`ComplianceAttestation`] constructed by composing
/// dimensions through this helper and then BLAKE3-digesting the result
/// produces the same `compliance_hash` a builder-constructed attestation
/// with the same dimensions would produce. Two dimensions of the same
/// `dimension_type` retain insertion order under the stable sort —
/// matching the builder's behaviour.
///
/// An empty dimensions slice fingerprints to an empty byte slice — its
/// BLAKE3 is the digest of the empty string, structurally distinct from
/// any non-empty dim-set fingerprint and from the prior name-keyed
/// sentinel `Blake3Hash::digest(b"initial-compliance")`.
///
/// [`Display`]: std::fmt::Display
/// [`DimensionType`]: tameshi::compliance::dimensions::DimensionType
/// [`ComplianceAttestation`]: tameshi::compliance::dimensions::ComplianceAttestation
pub fn canonical_dimensions_fingerprint(dimensions: &[ComplianceDimension]) -> Vec<u8> {
    let mut sorted: Vec<&ComplianceDimension> = dimensions.iter().collect();
    sorted.sort_by(|a, b| format!("{}", a.dimension_type).cmp(&format!("{}", b.dimension_type)));
    let mut out = Vec::with_capacity(sorted.len() * 32);
    for dim in &sorted {
        out.extend_from_slice(&dim.hash.0);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tameshi::compliance::dimensions::DimensionType;
    use tameshi::hash::Blake3Hash;

    /// Build a [`ComplianceDimension`] of the given `dimension_type` with
    /// a known hash so the canonical-fingerprint properties can be pinned
    /// against the dimension hash's raw bytes directly.
    fn dim(dimension_type: DimensionType, hash_seed: &[u8]) -> ComplianceDimension {
        ComplianceDimension {
            dimension_type,
            hash: Blake3Hash::digest(hash_seed),
            passed: true,
            summary: String::new(),
            assessed_at: chrono::Utc::now(),
            required: true,
        }
    }

    /// An empty dimensions slice produces an empty fingerprint — its
    /// BLAKE3 is the digest of empty bytes, which is structurally
    /// distinct from the prior name-keyed sentinel
    /// `Blake3Hash::digest(b"initial-compliance")`. Fail-before /
    /// pass-after pin: a future regression that re-introduced the
    /// sentinel constant at the [`compose_product_certification`] call
    /// site would still produce its constant hash regardless of the
    /// dimensions composed into the attestation, but the empty-fingerprint
    /// BLAKE3 it would have to *match* is a different value entirely.
    ///
    /// [`compose_product_certification`]: crate::commands::attestation::compose_product_certification
    #[test]
    fn test_empty_fingerprint_distinct_from_initial_compliance_sentinel() {
        assert_eq!(
            canonical_dimensions_fingerprint(&[]),
            Vec::<u8>::new(),
            "no dimensions = empty fingerprint",
        );
        let empty_fingerprint_hash = Blake3Hash::digest(&canonical_dimensions_fingerprint(&[]));
        let sentinel_hash = Blake3Hash::digest(b"initial-compliance");
        assert_ne!(
            empty_fingerprint_hash.to_hex(),
            sentinel_hash.to_hex(),
            "BLAKE3 of the empty fingerprint must differ from the prior \
             `Blake3Hash::digest(b\"initial-compliance\")` sentinel; \
             collapsing them would let a future regression that brought \
             back the sentinel pass this test silently",
        );
    }

    /// The canonical fingerprint is order-independent: two slices with the
    /// same `(dimension_type, hash)` pairs in different positions produce
    /// byte-identical fingerprints. The load-bearing property the prior
    /// constant sentinel lacked — and the property
    /// [`AttestationBuilder::build`] establishes via its stable sort over
    /// the display-form of `dimension_type`.
    ///
    /// [`AttestationBuilder::build`]: tameshi::compliance::dimensions::AttestationBuilder::build
    #[test]
    fn test_fingerprint_order_independent_across_dimension_types() {
        let a = dim(DimensionType::SlsaProvenance, b"slsa-evidence");
        let b = dim(DimensionType::VulnerabilityScan, b"cve-evidence");
        let c = dim(DimensionType::CisBenchmark, b"cis-evidence");
        let forward = vec![a.clone(), b.clone(), c.clone()];
        let reversed = vec![c, b, a];
        assert_eq!(
            canonical_dimensions_fingerprint(&forward),
            canonical_dimensions_fingerprint(&reversed),
            "the canonical fingerprint must be invariant under input \
             permutation; a different ordering of the same dimension set \
             must produce the same `compliance_hash`",
        );
    }

    /// Two dimensions with the same `dimension_type` retain insertion
    /// order under the stable sort — matching
    /// [`AttestationBuilder::build`]'s behaviour. Two dim sets that
    /// differ only in the insertion order of two same-type dims thus
    /// produce *different* fingerprints (the per-type insertion order
    /// is load-bearing for the canonical form, just as it is in tameshi).
    ///
    /// [`AttestationBuilder::build`]: tameshi::compliance::dimensions::AttestationBuilder::build
    #[test]
    fn test_fingerprint_same_type_insertion_order_preserved() {
        let first = dim(DimensionType::Sbom, b"first");
        let second = dim(DimensionType::Sbom, b"second");
        let fp_forward = canonical_dimensions_fingerprint(&[first.clone(), second.clone()]);
        let fp_reversed = canonical_dimensions_fingerprint(&[second, first]);
        assert_ne!(
            fp_forward, fp_reversed,
            "same-type dimensions must preserve insertion order under the \
             stable sort; this matches the builder's behaviour and makes \
             the canonical form sensitive to per-type sequencing",
        );
    }

    /// Distinct dim hashes produce distinct fingerprints — the property
    /// that makes the fingerprint a content-addressed identity over the
    /// dimensions, not a stamp independent of them. The prior bare
    /// `Blake3Hash::digest(b"initial-compliance")` at the call site
    /// produced the same hash for every dimension set; this test pins
    /// that the new path is sensitive to dim-hash content.
    #[test]
    fn test_fingerprint_distinguishes_dimension_hash_content() {
        let fp_a = canonical_dimensions_fingerprint(&[dim(
            DimensionType::SlsaProvenance,
            b"slsa-evidence-a",
        )]);
        let fp_b = canonical_dimensions_fingerprint(&[dim(
            DimensionType::SlsaProvenance,
            b"slsa-evidence-b",
        )]);
        assert_ne!(
            fp_a, fp_b,
            "two SLSA dims with different evidence hashes must produce \
             different fingerprints; the prior sentinel returned the same \
             stamp regardless of evidence",
        );
        assert_ne!(
            Blake3Hash::digest(&fp_a).to_hex(),
            Blake3Hash::digest(&fp_b).to_hex(),
            "the BLAKE3 of each fingerprint must differ — the property \
             that propagates to `compliance_hash` at the call site",
        );
    }

    /// Pin the canonical form against a hand-computed expected value so a
    /// future refactor that drifted the algorithm (e.g. sorted by enum
    /// discriminant instead of [`Display`], or changed the per-dim
    /// concatenation, or inserted a separator) would fail this test
    /// before any downstream `compliance_hash` was published under the
    /// new shape. The Display-form sort key sequence is:
    /// `"CIS Benchmark" < "CVE/Vulnerability Scan" < "SLSA Provenance"`
    /// (lexical, case-sensitive — uppercase letters precede lowercase
    /// but in this alphabet all the type names share the same case
    /// boundary so ASCII order suffices).
    ///
    /// [`Display`]: std::fmt::Display
    #[test]
    fn test_fingerprint_matches_hand_computed_canonical_form() {
        let slsa = dim(DimensionType::SlsaProvenance, b"slsa");
        let cve = dim(DimensionType::VulnerabilityScan, b"cve");
        let cis = dim(DimensionType::CisBenchmark, b"cis");

        // Display order: "CIS Benchmark" < "CVE/Vulnerability Scan" <
        // "SLSA Provenance".
        let mut expected = Vec::with_capacity(96);
        expected.extend_from_slice(&cis.hash.0);
        expected.extend_from_slice(&cve.hash.0);
        expected.extend_from_slice(&slsa.hash.0);

        let actual = canonical_dimensions_fingerprint(&[slsa, cis, cve]);
        assert_eq!(
            actual, expected,
            "the canonical fingerprint must be the concatenation of dim \
             hashes in Display-order-of-dimension_type; this matches \
             `AttestationBuilder::build`'s sort and concat exactly",
        );
    }
}
