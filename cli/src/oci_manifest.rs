//! Canonical OCI / Docker container-manifest fingerprint for forge.
//!
//! An OCI image (and its Docker v2 / v1 / manifest-list peers) is a content-
//! addressed graph: the manifest names a config blob and a sequence of layer
//! blobs by their `<algorithm>:<hex>` digests, and an index manifest names
//! per-platform manifests the same way. Those digests ARE the image's
//! identity — two manifests naming the same `(config-digest, ordered
//! layer-digests)` are byte-equivalent images regardless of which JSON shape
//! the registry happened to serve, what key order the registry's serializer
//! chose, or which mutable annotations (`created` timestamp, free-form
//! labels) ride alongside.
//!
//! `commands/attestation.rs::compute_image_attestation` previously swallowed
//! `skopeo inspect --raw` failure to the empty string via `unwrap_or_default()`
//! and hashed the result with `Blake3Hash::digest(manifest_json.as_bytes())`.
//! Two honesty failures followed: (a) a probe that failed (skopeo not on
//! PATH, registry 404, network error, auth refusal) silently produced
//! `Blake3Hash::digest(b"")` — a deterministic constant stamped into every
//! Phase 1 image attestation as the OCI manifest identity, false by
//! construction; and (b) raw-byte hashing makes the fingerprint depend on
//! registry-side JSON formatting and on the manifest format negotiated by
//! the registry's Accept-header handling, so the same image served as an
//! OCI manifest vs a Docker v2 manifest, or with reordered top-level keys,
//! produced different image-attestation hashes for a byte-identical image.
//! This module is the typed peer of [`crate::store_path`] and
//! [`crate::tree_listing`]: the [`canonical_manifest_fingerprint`] reduces
//! the manifest to the role-prefixed, sorted, deduplicated set of its
//! content-addressed digests, so an unchanged image fingerprints the same
//! regardless of registry / format drift, and a probe failure routes through
//! an explicit `b"no-manifest"` sentinel at the call site (mirroring
//! `b"no-tree-listing"` / `b"no-flake-lock"`) rather than through silent
//! blake3-of-empty.

/// Length of the lowercase-hex digest body for each supported algorithm. The
/// digest forms the content identity of the blob it names; OCI/Docker accept
/// `sha256` and `sha512` as the standard registry-side algorithms (the OCI
/// distribution spec lists both as the canonical set).
const SHA256_HEX_LEN: usize = 64;
const SHA512_HEX_LEN: usize = 128;

/// Why a string failed to parse as an OCI / Docker content digest. Carries
/// the offending input so a caller can attach it to a failure record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentDigestError {
    /// The string did not contain the `:` separating algorithm from hex.
    MissingSeparator { input: String },
    /// The algorithm prefix was not one of the supported registry algorithms
    /// (`sha256` / `sha512`).
    UnsupportedAlgorithm { input: String },
    /// The hex body was not lowercase-hex of the algorithm's expected length.
    InvalidHex { input: String },
}

impl std::fmt::Display for ContentDigestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContentDigestError::MissingSeparator { input } => write!(
                f,
                "content digest '{input}' is missing the '<algorithm>:<hex>' separator"
            ),
            ContentDigestError::UnsupportedAlgorithm { input } => write!(
                f,
                "content digest '{input}' algorithm is not one of sha256 / sha512"
            ),
            ContentDigestError::InvalidHex { input } => write!(
                f,
                "content digest '{input}' hex body is not lowercase-hex of the algorithm's expected length"
            ),
        }
    }
}

impl std::error::Error for ContentDigestError {}

/// A validated OCI / Docker content-addressed digest: `<algorithm>:<hex>`.
///
/// Constructing a `ContentDigest` proves the string names a real blob the
/// registry could be asked to fetch — a malformed digest cannot enter the
/// canonical fingerprint and inflate the image identity with junk.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ContentDigest {
    full: String,
}

impl ContentDigest {
    /// Parse a string into a validated [`ContentDigest`]. Whitespace is
    /// trimmed at the edges so a stray newline from a captured registry
    /// response cannot prevent parsing of an otherwise-valid digest.
    pub fn parse(input: &str) -> Result<Self, ContentDigestError> {
        let trimmed = input.trim();
        let (algo, hex) =
            trimmed
                .split_once(':')
                .ok_or_else(|| ContentDigestError::MissingSeparator {
                    input: trimmed.to_string(),
                })?;
        let expected_len = match algo {
            "sha256" => SHA256_HEX_LEN,
            "sha512" => SHA512_HEX_LEN,
            _ => {
                return Err(ContentDigestError::UnsupportedAlgorithm {
                    input: trimmed.to_string(),
                })
            }
        };
        let hex_ok = hex.len() == expected_len
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !hex_ok {
            return Err(ContentDigestError::InvalidHex {
                input: trimmed.to_string(),
            });
        }
        Ok(Self {
            full: trimmed.to_string(),
        })
    }

    /// The full `<algorithm>:<hex>` digest string (trimmed). Read-back
    /// accessor for any consumer that wants the validated digest as a `&str`
    /// without re-parsing. `allow(dead_code)`: part of the primitive surface,
    /// as with `store_path::StorePath::as_str`.
    #[allow(dead_code)]
    pub fn as_str(&self) -> &str {
        &self.full
    }
}

impl std::fmt::Display for ContentDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.full)
    }
}

/// Canonical, key-order- and metadata-independent fingerprint of an OCI /
/// Docker container manifest, derived from its content-addressed digests.
///
/// The fingerprint is the lexically-sorted, deduplicated set of role-prefixed
/// digest lines drawn from the standard manifest shapes:
///
/// - `config:<digest>` — the runtime-config blob of an image manifest (OCI
///   `application/vnd.oci.image.manifest.v1+json` or its Docker v2 peer).
/// - `layer:<digest>` — each entry of `layers[]` in an image manifest.
/// - `manifest:<digest>` — each entry of `manifests[]` in an index / manifest
///   list (OCI `application/vnd.oci.image.index.v1+json` or its Docker v2
///   peer).
/// - `fsLayer:<digest>` — each entry of `fsLayers[]` in a Docker v1 manifest
///   (legacy registries still emit this).
///
/// The role prefix is load-bearing: a digest reachable as a layer is
/// structurally distinct from the same digest reachable as a config, even
/// though both happen to name the same blob bytes. The set is intersection-
/// of-roles, not bag-of-bytes.
///
/// Two manifests describing the same image content fingerprint identically
/// regardless of JSON key order, whitespace, registry-side reformatting, or
/// volatile metadata (`annotations`, `created`, free-form labels). A manifest
/// that is not valid JSON, or that carries no parseable digest in any
/// recognised role, fingerprints to the empty string; the call site
/// disambiguates this from the probe-failed case via an explicit sentinel.
pub fn canonical_manifest_fingerprint(manifest_json: &str) -> String {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(manifest_json) else {
        return String::new();
    };
    let mut lines: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    insert_digest_at(&value, &["config", "digest"], "config", &mut lines);
    insert_array_digests(&value, "layers", "digest", "layer", &mut lines);
    insert_array_digests(&value, "manifests", "digest", "manifest", &mut lines);
    insert_array_digests(&value, "fsLayers", "blobSum", "fsLayer", &mut lines);
    lines.into_iter().collect::<Vec<_>>().join("\n")
}

/// Insert one role-prefixed digest line drawn from a `value.<path…>` location,
/// skipping silently when the path does not resolve to a string or when the
/// string is not a well-formed digest. The skip is honesty-preserving: a
/// truncated or malformed manifest must narrow the fingerprint to the digests
/// that ARE well-formed, never inflate it with junk.
fn insert_digest_at(
    value: &serde_json::Value,
    path: &[&str],
    role: &str,
    out: &mut std::collections::BTreeSet<String>,
) {
    let mut cursor = value;
    for key in path {
        match cursor.get(key) {
            Some(v) => cursor = v,
            None => return,
        }
    }
    let Some(s) = cursor.as_str() else {
        return;
    };
    if let Ok(digest) = ContentDigest::parse(s) {
        out.insert(format!("{role}:{digest}"));
    }
}

/// Insert role-prefixed digest lines drawn from every `value.<array>[<i>].
/// <digest_key>` entry. Same skip discipline as [`insert_digest_at`]: any
/// element whose digest is absent / non-string / malformed is dropped.
fn insert_array_digests(
    value: &serde_json::Value,
    array_key: &str,
    digest_key: &str,
    role: &str,
    out: &mut std::collections::BTreeSet<String>,
) {
    let Some(items) = value.get(array_key).and_then(|v| v.as_array()) else {
        return;
    };
    for item in items {
        let Some(s) = item.get(digest_key).and_then(|v| v.as_str()) else {
            continue;
        };
        if let Ok(digest) = ContentDigest::parse(s) {
            out.insert(format!("{role}:{digest}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A realistic 64-char lowercase-hex SHA-256 digest body fixture.
    const D1: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    /// A second distinct SHA-256 digest body so order / dedup tests can show
    /// two real identities.
    const D2: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    /// A third distinct SHA-256 digest body for tests with three layers.
    const D3: &str = "aaaabbbbccccddddaaaabbbbccccddddaaaabbbbccccddddaaaabbbbccccdddd";

    #[test]
    fn test_parse_sha256_digest() {
        let d = ContentDigest::parse(&format!("sha256:{D1}")).unwrap();
        assert_eq!(d.as_str(), format!("sha256:{D1}"));
    }

    #[test]
    fn test_parse_sha512_digest() {
        let hex = "f".repeat(SHA512_HEX_LEN);
        let d = ContentDigest::parse(&format!("sha512:{hex}")).unwrap();
        assert_eq!(d.as_str(), format!("sha512:{hex}"));
    }

    #[test]
    fn test_parse_trims_whitespace() {
        let d = ContentDigest::parse(&format!("  sha256:{D1}\n")).unwrap();
        assert_eq!(d.as_str(), format!("sha256:{D1}"));
    }

    #[test]
    fn test_parse_rejects_missing_separator() {
        let err = ContentDigest::parse("sha256abc123").unwrap_err();
        assert!(matches!(err, ContentDigestError::MissingSeparator { .. }));
    }

    #[test]
    fn test_parse_rejects_unsupported_algorithm() {
        // MD5 / SHA-1 are not OCI distribution canonical digests.
        let err = ContentDigest::parse(&format!("md5:{D1}")).unwrap_err();
        assert!(matches!(
            err,
            ContentDigestError::UnsupportedAlgorithm { .. }
        ));
        let err =
            ContentDigest::parse("sha1:0123456789abcdef0123456789abcdef01234567").unwrap_err();
        assert!(matches!(
            err,
            ContentDigestError::UnsupportedAlgorithm { .. }
        ));
    }

    #[test]
    fn test_parse_rejects_wrong_hex_length() {
        // sha256 with only 60 hex chars.
        let err = ContentDigest::parse(&format!("sha256:{}", &D1[..60])).unwrap_err();
        assert!(matches!(err, ContentDigestError::InvalidHex { .. }));
    }

    #[test]
    fn test_parse_rejects_uppercase_hex() {
        // Registries emit lowercase hex; uppercase is non-canonical.
        let err = ContentDigest::parse(&format!("sha256:{}", D1.to_uppercase())).unwrap_err();
        assert!(matches!(err, ContentDigestError::InvalidHex { .. }));
    }

    #[test]
    fn test_parse_rejects_non_hex_byte() {
        // 64-char body but with a non-hex char ('g').
        let err = ContentDigest::parse(&format!("sha256:{}g", &D1[..63])).unwrap_err();
        assert!(matches!(err, ContentDigestError::InvalidHex { .. }));
    }

    #[test]
    fn test_error_display_names_offending_input() {
        let err = ContentDigest::parse("not-a-digest").unwrap_err();
        assert!(
            err.to_string().contains("not-a-digest"),
            "error must name the offending input; got: {err}"
        );
    }

    /// An OCI image manifest (the standard single-image shape skopeo
    /// returns for a `--raw` image lookup) fingerprints to the role-prefixed,
    /// lexically-sorted set of its config + layer digests.
    #[test]
    fn test_canonical_fingerprint_oci_image_manifest() {
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
                      "digest": "sha256:{D2}", "size": 5000}},
                    {{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                      "digest": "sha256:{D3}", "size": 6000}}
                ]
            }}"#
        );
        let fp = canonical_manifest_fingerprint(&json);
        // Sorted lexically: "config:..." < "layer:..." (both start with 'c'/'l'),
        // and within "layer:" the D2-prefixed line sorts before the D3-prefixed
        // line ('f' < 'a'? no, 'a' < 'f' — D3 starts with 'a', D2 with 'f').
        assert_eq!(
            fp,
            format!("config:sha256:{D1}\nlayer:sha256:{D3}\nlayer:sha256:{D2}"),
            "fingerprint is the role-prefixed, lexically-sorted, deduplicated digest set"
        );
    }

    /// An OCI image index (multi-arch manifest list) fingerprints to the
    /// `manifest:` entries — every per-platform manifest digest the index
    /// points at.
    #[test]
    fn test_canonical_fingerprint_oci_image_index() {
        let json = format!(
            r#"{{
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [
                    {{"digest": "sha256:{D1}", "platform": {{"architecture": "amd64"}}}},
                    {{"digest": "sha256:{D2}", "platform": {{"architecture": "arm64"}}}}
                ]
            }}"#
        );
        let fp = canonical_manifest_fingerprint(&json);
        assert_eq!(
            fp,
            format!("manifest:sha256:{D1}\nmanifest:sha256:{D2}"),
            "index fingerprint is the sorted set of per-platform manifest digests"
        );
    }

    /// A legacy Docker v1 manifest carries `fsLayers[].blobSum` instead of
    /// `layers[].digest`; the canonical form still extracts the content-
    /// addressed identities under the `fsLayer:` role.
    #[test]
    fn test_canonical_fingerprint_docker_v1_fs_layers() {
        let json = format!(
            r#"{{
                "schemaVersion": 1,
                "fsLayers": [
                    {{"blobSum": "sha256:{D1}"}},
                    {{"blobSum": "sha256:{D2}"}}
                ]
            }}"#
        );
        let fp = canonical_manifest_fingerprint(&json);
        assert_eq!(
            fp,
            format!("fsLayer:sha256:{D1}\nfsLayer:sha256:{D2}"),
            "v1 manifest fingerprint draws digests from fsLayers[].blobSum"
        );
    }

    /// The load-bearing canonical-form property: two manifest documents
    /// describing the SAME image (same config digest, same layer digest set)
    /// but emitted with different top-level key order, different volatile
    /// metadata (`annotations`), and different cosmetic whitespace must
    /// fingerprint identically. This is the gap the raw-byte digest lacked
    /// and the reason `compute_image_attestation`'s prior
    /// `Blake3Hash::digest(manifest_json.as_bytes())` drifted run-to-run for
    /// a byte-identical image.
    #[test]
    fn test_canonical_fingerprint_is_stable_where_raw_bytes_drift() {
        let json_a = format!(
            r#"{{
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {{"digest": "sha256:{D1}", "size": 1234}},
                "layers": [
                    {{"digest": "sha256:{D2}", "size": 5000}},
                    {{"digest": "sha256:{D3}", "size": 6000}}
                ],
                "annotations": {{"org.opencontainers.image.created": "2025-01-01T00:00:00Z"}}
            }}"#
        );
        // Same digests, different top-level key order, no annotations, layers
        // in reversed array order, and extra whitespace throughout.
        let json_b = format!(
            r#"{{
              "layers":  [
                  {{"digest" : "sha256:{D3}", "size": 999}} ,
                  {{"digest" : "sha256:{D2}", "size": 999}}
              ],
              "config" : {{"digest": "sha256:{D1}", "size": 999, "mediaType": "x"}},
              "mediaType" : "application/vnd.docker.distribution.manifest.v2+json",
              "schemaVersion" : 2
            }}"#
        );
        assert_eq!(
            canonical_manifest_fingerprint(&json_a),
            canonical_manifest_fingerprint(&json_b),
            "canonical fingerprint must be JSON-formatting and metadata-independent"
        );
        // The two raw inputs ARE distinct, so a raw-byte digest of either
        // would differ — the drift this canonical form closes.
        assert_ne!(json_a, json_b);
    }

    /// Annotations and other mutable metadata fields must NOT enter the
    /// fingerprint. Two manifests identical except for `annotations` and
    /// `subject` (an OCI artifact reference field) fingerprint identically.
    #[test]
    fn test_canonical_fingerprint_ignores_mutable_metadata() {
        let with_meta = format!(
            r#"{{
                "config": {{"digest": "sha256:{D1}"}},
                "layers": [{{"digest": "sha256:{D2}"}}],
                "annotations": {{"a": "1", "b": "2"}},
                "subject": {{"digest": "sha256:{D3}", "mediaType": "x"}}
            }}"#
        );
        let without_meta = format!(
            r#"{{
                "config": {{"digest": "sha256:{D1}"}},
                "layers": [{{"digest": "sha256:{D2}"}}]
            }}"#
        );
        assert_eq!(
            canonical_manifest_fingerprint(&with_meta),
            canonical_manifest_fingerprint(&without_meta),
            "annotations / subject must not drift the image identity"
        );
    }

    /// The role prefix is load-bearing: the same blob digest reachable as a
    /// config vs as a layer produces structurally distinct fingerprint lines.
    /// A blob that happens to appear in both roles (rare but possible across
    /// engineered manifests) is recorded under both, not collapsed.
    #[test]
    fn test_canonical_fingerprint_role_prefix_distinguishes_position() {
        let json = format!(
            r#"{{
                "config": {{"digest": "sha256:{D1}"}},
                "layers": [{{"digest": "sha256:{D1}"}}]
            }}"#
        );
        let fp = canonical_manifest_fingerprint(&json);
        assert_eq!(
            fp,
            format!("config:sha256:{D1}\nlayer:sha256:{D1}"),
            "the same digest in two roles must record as two distinct lines"
        );
    }

    /// Repeated layer digests (an image with two layers of identical
    /// content — rare but legal) deduplicate to one canonical line; the
    /// fingerprint is a set, not a list.
    #[test]
    fn test_canonical_fingerprint_dedups_repeated_digests() {
        let json = format!(
            r#"{{
                "layers": [
                    {{"digest": "sha256:{D1}"}},
                    {{"digest": "sha256:{D1}"}},
                    {{"digest": "sha256:{D2}"}}
                ]
            }}"#
        );
        let fp = canonical_manifest_fingerprint(&json);
        assert_eq!(
            fp,
            format!("layer:sha256:{D1}\nlayer:sha256:{D2}"),
            "repeated layer digests collapse to one canonical line"
        );
    }

    /// Changing a single layer's digest (the image now references different
    /// content at that position) must drift the fingerprint — the property
    /// that makes this the image identity, not a hash of the layer count
    /// alone.
    #[test]
    fn test_canonical_fingerprint_changes_when_content_changes() {
        let with_d1 = format!(r#"{{"layers": [{{"digest": "sha256:{D1}"}}]}}"#);
        let with_d2 = format!(r#"{{"layers": [{{"digest": "sha256:{D2}"}}]}}"#);
        assert_ne!(
            canonical_manifest_fingerprint(&with_d1),
            canonical_manifest_fingerprint(&with_d2),
            "different layer content must produce a different fingerprint"
        );
    }

    /// A malformed digest entry (wrong hex length, missing separator, etc.)
    /// is silently skipped: the canonical fingerprint narrows to the digests
    /// that ARE well-formed, never inflated with junk.
    #[test]
    fn test_canonical_fingerprint_skips_malformed_entries() {
        let json = format!(
            r#"{{
                "config": {{"digest": "not-a-digest-at-all"}},
                "layers": [
                    {{"digest": "sha256:{D1}"}},
                    {{"digest": "sha1:tooshort"}},
                    {{"digest": "sha256:{D2}"}},
                    {{"no_digest_key": "x"}}
                ]
            }}"#
        );
        let fp = canonical_manifest_fingerprint(&json);
        assert_eq!(
            fp,
            format!("layer:sha256:{D1}\nlayer:sha256:{D2}"),
            "malformed config + malformed layers are dropped; well-formed layers survive"
        );
    }

    /// Empty input, whitespace, malformed JSON, and a JSON object with no
    /// recognised digest fields all collapse to the empty fingerprint. The
    /// call site disambiguates "no parseable digests" from "skopeo probe
    /// failed" via an explicit sentinel; this function just reports the
    /// empty content case.
    #[test]
    fn test_canonical_fingerprint_empty_for_unparseable() {
        assert_eq!(canonical_manifest_fingerprint(""), "");
        assert_eq!(canonical_manifest_fingerprint("   "), "");
        assert_eq!(canonical_manifest_fingerprint("not json at all {{{"), "");
        // Valid JSON, but no digest-bearing field.
        assert_eq!(
            canonical_manifest_fingerprint(r#"{"schemaVersion": 2}"#),
            ""
        );
        // A JSON array at top level (not a manifest shape).
        assert_eq!(canonical_manifest_fingerprint(r#"[1, 2, 3]"#), "");
    }
}
