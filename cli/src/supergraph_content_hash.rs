//! Typed primitive for SHA-256 content-addressed hashing of the composed
//! `supergraph.graphql`.
//!
//! ## Duplication being lifted
//!
//! Two sibling sites computed the same digest over the composed supergraph:
//!
//! 1. [`crate::commands::supergraph_verification::calculate_hash`] — the
//!    canonical `pub fn` used by
//!    [`crate::commands::supergraph_verification::SupergraphMetadata::verify`]
//!    to compare a freshly-read `supergraph.graphql` against the digest
//!    persisted in `supergraph-metadata.json`.
//! 2. `commands/federation.rs::update_federation` — an inline stanza of the
//!    form
//!
//!    ```text
//!    use sha2::{Digest, Sha256};
//!    let mut hasher = Sha256::new();
//!    hasher.update(&supergraph_content);
//!    let hash_bytes = hasher.finalize();
//!    let supergraph_hash = format!("{:x}", hash_bytes);
//!    ```
//!
//!    at the ConfigMap-annotation step that stamps the hive-router
//!    Deployment with the same hash `SupergraphMetadata` persists.
//!
//! Both sites render the digest as lowercase hexadecimal via
//! `format!("{:x}", <finalize>)`. Divergence between them silently breaks
//! post-composition verification: the annotate gate stamps one string while
//! the verify path computes another, and every downstream comparison
//! (`SupergraphMetadata::verify`, the ConfigMap-hash equality gate) reports
//! `false` for a supergraph that is in fact byte-identical to the persisted
//! one — a false-negative that would force redundant router restarts and
//! obscure real divergence when it eventually happened.
//!
//! ## The primitive
//!
//! [`hash_supergraph_content`] is the single call both sites now forward
//! through, so the digest algorithm (`sha2::Sha256`), the encoding
//! (`format!("{:x}", …)`), and the return length (64 lowercase hex
//! characters) are pinned once and byte-oracle-tested here. Content-hash
//! divergence between "computed for annotation" and "computed for
//! verification" is now impossible to introduce through a local edit at
//! either call site; a future refactor that swaps the digest primitive
//! (SHA-256 → SHA-512, hex → Base64) fails the `SHA256_HEX_LEN`,
//! `HASH_OF_EMPTY_INPUT_IS_KNOWN_SHA256_HEX`, and
//! `HASH_OF_TEST_CONTENT_IS_KNOWN_SHA256_HEX` byte-oracles below rather than
//! silently diverging in production.

use sha2::{Digest, Sha256};

/// SHA-256 emits 32 bytes; the lowercase-hex rendering is exactly 64
/// characters. Public so callers that slice a short prefix
/// (`supergraph_hash_short = &hash[..16]`) can assert the full length
/// before slicing.
pub const SHA256_HEX_LEN: usize = 64;

/// Compute the SHA-256 hex hash of the given supergraph content bytes.
///
/// Returns a lowercase 64-character hexadecimal string. Byte-for-byte
/// identical to the pre-lift expression
/// `format!("{:x}", Sha256::new().chain_update(bytes).finalize())`.
///
/// This is the single canonical spelling for supergraph-content hashing.
/// Both the ConfigMap-annotation write path
/// (`commands/federation.rs::update_federation`) and the
/// `SupergraphMetadata::verify` read path
/// (`commands/supergraph_verification.rs`) forward through this function
/// so their digests cannot drift.
pub fn hash_supergraph_content(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: SHA-256 of the empty input has one canonical hex
    /// rendering. A future refactor that swaps the digest algorithm,
    /// changes the endianness, or replaces `format!("{:x}", …)` with
    /// uppercase hex / Base64 fails this test rather than silently
    /// diverging from every persisted `SupergraphMetadata::supergraph_hash`
    /// on disk.
    #[test]
    fn hash_of_empty_input_is_known_sha256_hex() {
        assert_eq!(
            hash_supergraph_content(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
    }

    /// Byte-oracle: pins the exact hex for a non-empty input so a
    /// regression that swaps to a different hash family (e.g. SHA-512
    /// truncated to 64 chars, BLAKE3) cannot pass merely because the
    /// output length still happens to be 64.
    #[test]
    fn hash_of_test_content_is_known_sha256_hex() {
        assert_eq!(
            hash_supergraph_content(b"test content"),
            "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72",
        );
    }

    /// Guard: pins the return length at 64 lowercase-hex characters. Sites
    /// that slice a short prefix (`&hash[..16]`) rely on this — a shorter
    /// return would panic at the slice; a longer return would silently
    /// change what `supergraph_hash_short` means.
    #[test]
    fn hash_return_is_64_lowercase_hex_chars() {
        let hash = hash_supergraph_content(b"anything");
        assert_eq!(hash.len(), SHA256_HEX_LEN);
        assert!(hash
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
    }

    /// Determinism guard: two calls on the same input return the same
    /// hex. Cheap, but pins an invariant readers (and downstream
    /// verification) rely on absolutely.
    #[test]
    fn hash_is_deterministic() {
        let a = hash_supergraph_content(b"deterministic");
        let b = hash_supergraph_content(b"deterministic");
        assert_eq!(a, b);
    }

    /// Distinctness guard: different inputs produce different digests.
    /// A degenerate implementation that returns a fixed string would
    /// pass the length and determinism tests but fails here.
    #[test]
    fn hash_distinguishes_distinct_inputs() {
        assert_ne!(
            hash_supergraph_content(b"input-a"),
            hash_supergraph_content(b"input-b"),
        );
    }
}
