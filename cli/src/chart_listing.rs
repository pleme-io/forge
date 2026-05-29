//! Canonical Helm chart-directory grammar for forge.
//!
//! A Helm chart on disk is a directory of files: `Chart.yaml`,
//! `values.yaml`, `templates/*`, optional `charts/<subchart>/...`
//! subcharts, plus ancillary text (`README.md`, `NOTES.txt`, `LICENSE`).
//! Its content-addressed identity is the set of `(relative_path,
//! content-blake3)` pairs over every regular file the chart carries —
//! the chart-side peer of `git ls-tree`'s per-blob `(mode, type, hash,
//! path)` (the source-tree case, [`crate::tree_listing`]) and `nix
//! path-info --recursive --json`'s set of per-store-object content
//! hashes (the closure case, [`crate::store_path::canonical_closure_fingerprint`]).
//!
//! `commands/attestation.rs::compute_chart_attestation` previously hashed
//! the chart directory through an ad-hoc `hash_directory` that walked the
//! tree, concatenated each file's *basename* and content (no separator)
//! into a single byte buffer, and digested the buffer. Three structural
//! honesty failures followed:
//!
//!   * No path/content boundary — `<basename><content>` for ("ab","cd")
//!     concatenates to `b"abcd"`, identical to ("abc","d"). A buffer with
//!     no framing makes the per-file identity recoverable only up to
//!     adjacent-pair concatenation, so distinct chart layouts can collide
//!     by construction.
//!   * Only the *basename* was hashed, never the repo-relative path. A
//!     `NOTES.txt` in `templates/` and a `NOTES.txt` in `charts/sub/
//!     templates/` are different chart content but the prior fingerprint
//!     could not tell them apart from their basenames alone.
//!   * Sibling directories were folded into the parent by hashing each
//!     subdir's recursive hash without any separator either, propagating
//!     the same boundary issue up the tree.
//!
//! This module is the chart-side peer of [`crate::tree_listing`] and
//! [`crate::oci_manifest`]: [`canonical_chart_fingerprint`] reduces a
//! chart-entry set to the sorted, deduplicated set of `<rel-path> TAB
//! <content-hash-hex>` lines (TAB-framed so adjacent fields cannot
//! ambiguously concatenate, hex-encoded content hash so the per-file
//! identity is content-addressed), and the call site routes the
//! missing-directory case through an explicit `b"no-chart-dir"` sentinel
//! mirroring the existing `b"no-tree-listing"`, `b"no-manifest"`, and
//! `b"no-flake-lock"` peers.

use tameshi::hash::Blake3Hash;

/// One validated chart-directory entry: a chart-relative path
/// (forward-slash-separated for filesystem portability) and the
/// lowercase-hex BLAKE3 digest of the file's bytes. The path is the key
/// (two files at the same path cannot coexist in a real directory) and
/// the content hash is the value — together they name the per-file
/// content-addressed identity a downstream verifier would itself derive
/// by walking the chart on disk.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ChartEntry {
    // Field order chosen so the derived `Ord` sorts by `path` first —
    // path is the natural lexical key for the canonical form.
    path: String,
    content_hash: String,
}

impl ChartEntry {
    /// Build a [`ChartEntry`] from a chart-relative path and the file's
    /// raw bytes. The content hash is the lowercase-hex BLAKE3 digest of
    /// `content` — the per-blob content-addressed identity. The path is
    /// stored verbatim; callers are expected to normalise to
    /// forward-slash separators before constructing (the chart-walk in
    /// `commands/attestation.rs` does so).
    pub fn new(path: String, content: &[u8]) -> Self {
        Self {
            path,
            content_hash: Blake3Hash::digest(content).to_hex(),
        }
    }

    /// The chart-relative path this entry names.
    #[allow(dead_code)]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The lowercase-hex BLAKE3 content hash — the per-file
    /// content-addressed identity the canonical fingerprint is built
    /// from.
    #[allow(dead_code)]
    pub fn content_hash(&self) -> &str {
        &self.content_hash
    }
}

/// Canonical, order-independent fingerprint of a Helm chart directory,
/// derived from the per-file content-addressed digests its blobs carry.
///
/// The fingerprint is the sorted, deduplicated set of validated
/// `<rel-path> TAB <content-hash-hex>` lines, joined one per line. Two
/// chart layouts naming the same set of `(path, content)` pairs
/// fingerprint identically regardless of input ordering or filesystem
/// directory-entry ordering. Two layouts with the same per-file basename
/// set but different repo-relative paths produce distinct fingerprints
/// — the path/content boundary is the TAB and the path includes every
/// parent component, so the basename-collision failure mode the prior
/// raw-byte `hash_directory` carried cannot recur. A chart-entry set
/// with no parseable entries fingerprints to the empty string; the call
/// site disambiguates this from the missing-directory case via an
/// explicit sentinel (`b"no-chart-dir"`, mirroring the existing
/// `b"no-tree-listing"`, `b"no-manifest"`, and `b"no-flake-lock"`).
pub fn canonical_chart_fingerprint(entries: impl IntoIterator<Item = ChartEntry>) -> String {
    let set: std::collections::BTreeSet<String> = entries
        .into_iter()
        .map(|e| format!("{}\t{}", e.path, e.content_hash))
        .collect();
    set.into_iter().collect::<Vec<_>>().join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(path: &str, content: &[u8]) -> ChartEntry {
        ChartEntry::new(path.to_string(), content)
    }

    /// A [`ChartEntry`] records the content-addressed identity of the
    /// file's bytes, not a hash of the path-and-content concatenation —
    /// so two entries with identical content under different paths share
    /// a content hash but produce distinct fingerprint lines.
    #[test]
    fn test_entry_content_hash_is_content_only() {
        let a = e("templates/a.yaml", b"hello");
        let b = e("templates/b.yaml", b"hello");
        assert_eq!(
            a.content_hash(),
            b.content_hash(),
            "identical content at different paths shares the content hash",
        );
        assert_eq!(
            a.content_hash(),
            Blake3Hash::digest(b"hello").to_hex(),
            "the content hash is the BLAKE3 of the bytes",
        );
    }

    /// Two chart-entry sets naming the same `(path, content)` pairs in
    /// different iteration orders must fingerprint identically. This is
    /// the load-bearing canonical-form property the raw-byte
    /// `hash_directory` lacked.
    #[test]
    fn test_canonical_fingerprint_is_order_independent() {
        let forward = vec![
            e("Chart.yaml", b"name: foo\n"),
            e("templates/svc.yaml", b"kind: Service\n"),
            e("values.yaml", b"replicas: 3\n"),
        ];
        let reversed: Vec<ChartEntry> = forward.iter().rev().cloned().collect();
        assert_eq!(
            canonical_chart_fingerprint(forward.clone()),
            canonical_chart_fingerprint(reversed),
            "fingerprint must be order-independent",
        );
    }

    /// Repeated entries (same path, same content) collapse to one
    /// canonical line — the chart-side peer of
    /// [`crate::tree_listing::canonical_tree_fingerprint`]'s dedup.
    #[test]
    fn test_canonical_fingerprint_dedups_repeated_entries() {
        let entries = vec![
            e("Chart.yaml", b"name: foo\n"),
            e("Chart.yaml", b"name: foo\n"),
            e("values.yaml", b"x: 1\n"),
        ];
        let fp = canonical_chart_fingerprint(entries);
        let chart_yaml_hash = Blake3Hash::digest(b"name: foo\n").to_hex();
        let values_yaml_hash = Blake3Hash::digest(b"x: 1\n").to_hex();
        let expected = format!("Chart.yaml\t{chart_yaml_hash}\nvalues.yaml\t{values_yaml_hash}",);
        assert_eq!(fp, expected, "repeated entries collapse to one line");
    }

    /// Changing a single file's content (same path) drifts the
    /// fingerprint — the property that makes this the chart-content
    /// identity, not a hash of the path set alone.
    #[test]
    fn test_canonical_fingerprint_changes_when_content_changes() {
        let v1 = vec![e("values.yaml", b"replicas: 3\n")];
        let v2 = vec![e("values.yaml", b"replicas: 5\n")];
        assert_ne!(
            canonical_chart_fingerprint(v1),
            canonical_chart_fingerprint(v2),
            "different content at the same path must produce a different fingerprint",
        );
    }

    /// Changing a single file's path (same content) drifts the
    /// fingerprint — the property that makes this the *layout* identity,
    /// not a hash of the content multiset alone.
    #[test]
    fn test_canonical_fingerprint_changes_when_path_changes() {
        let layout_a = vec![e("templates/svc.yaml", b"kind: Service\n")];
        let layout_b = vec![e("templates/deploy.yaml", b"kind: Service\n")];
        assert_ne!(
            canonical_chart_fingerprint(layout_a),
            canonical_chart_fingerprint(layout_b),
            "same content at different paths must produce different fingerprints",
        );
    }

    /// Two layouts whose per-file *basenames* coincide but whose
    /// repo-relative paths differ must fingerprint distinctly. The prior
    /// `hash_directory` hashed only `path.file_name()` plus content with
    /// no separator, so a `NOTES.txt` in the parent chart's `templates/`
    /// and a `NOTES.txt` in a subchart's `templates/` could collide.
    /// Pinning this here forecloses the regression at the canonical
    /// primitive.
    #[test]
    fn test_basename_collision_cannot_recur() {
        let parent_only = vec![e("templates/NOTES.txt", b"hello\n")];
        let subchart_only = vec![e("charts/sub/templates/NOTES.txt", b"hello\n")];
        assert_ne!(
            canonical_chart_fingerprint(parent_only),
            canonical_chart_fingerprint(subchart_only),
            "same basename + content at different parent paths must not collide",
        );
    }

    /// The path/content boundary is the TAB, so adjacent
    /// path-then-content concatenations cannot ambiguously rejoin: a
    /// file `"ab"` with content `"cd"` cannot fingerprint as a file
    /// `"abc"` with content `"d"`, both of which the raw-byte
    /// `extend_from_slice(filename) + extend_from_slice(content)` shape
    /// reduced to `b"abcd"`. This is the structural collision the
    /// canonical form forecloses.
    #[test]
    fn test_path_content_boundary_is_framed() {
        let left = vec![e("ab", b"cd")];
        let right = vec![e("abc", b"d")];
        assert_ne!(
            canonical_chart_fingerprint(left),
            canonical_chart_fingerprint(right),
            "TAB framing must keep the path/content boundary unambiguous",
        );
    }

    /// An empty entry set fingerprints to the empty string. The call
    /// site lifts this case into the explicit `b"no-chart-dir"` sentinel
    /// — this module just reports "no entries", consistent with
    /// [`crate::tree_listing::canonical_tree_fingerprint`] and
    /// [`crate::oci_manifest::canonical_manifest_fingerprint`].
    #[test]
    fn test_empty_entries_fingerprint_to_empty_string() {
        assert_eq!(canonical_chart_fingerprint(std::iter::empty()), "");
    }
}
