//! Canonical `git ls-tree -r HEAD` grammar for forge.
//!
//! A `git ls-tree -r HEAD` line is `<mode> SP <type> SP <hash> TAB <path>`:
//! `mode` is the 6-octal-digit file mode, `type` is one of git's object
//! types (`blob` / `tree` / `commit` / `tag`), `hash` is the lowercase-hex
//! content-addressed object identity (40 chars for a SHA-1 repo, 64 for a
//! SHA-256 repo), and `path` is the repo-relative path. The whole listing
//! is the source tree's content-addressed identity — every blob is named
//! by its content hash, so two trees with the same path-set, modes, and
//! object hashes are byte-identical sources.
//!
//! `commands/attestation.rs::compute_source_attestation` previously
//! swallowed `git ls-tree` failure to the empty string via
//! `unwrap_or_default()` and hashed the result with
//! `Blake3Hash::digest(tree_listing.as_bytes())`. Two honesty failures
//! followed: (a) a probe that failed (no git on PATH, no HEAD, repo not
//! checked out, I/O error) silently produced `Blake3Hash::digest(b"")` —
//! a deterministic constant that gets stamped into every Phase 1 source
//! attestation as the source-tree identity, false by construction; and
//! (b) raw-byte hashing makes the fingerprint dependent on any volatile
//! detail of git's output formatting (a future git version that drifted
//! the line shape would drift the source-tree claim for a byte-identical
//! tree). This module is the typed peer of [`crate::store_path`]: the
//! [`canonical_tree_fingerprint`] reduces the listing to the sorted,
//! deduplicated set of `(mode, type, hash, path)` content-addressed
//! identities its blobs already carry, so an unchanged tree fingerprints
//! the same regardless of formatting drift, and a probe failure routes
//! through an explicit `b"no-tree-listing"` sentinel at the call site
//! (mirroring the existing `b"no-flake-lock"` sentinel) rather than
//! through silent blake3-of-empty.

/// Lengths the `hash` field may take, in lowercase-hex characters.
/// `git ls-tree` emits the full object name, which is 40 hex chars in a
/// SHA-1 repo (the historical and still-default object format) and 64
/// hex chars in a SHA-256 repo (git 2.29+). Abbreviated hashes are
/// rejected — the canonical fingerprint requires the full content
/// identity.
const HASH_LEN_SHA1: usize = 40;
const HASH_LEN_SHA256: usize = 64;

/// Length of a git file mode in octal digits. Git emits modes as exactly
/// six digits left-padded with zeros (e.g. `100644`, `100755`, `040000`,
/// `120000`, `160000`); any other width is malformed.
const MODE_LEN: usize = 6;

/// Why a `git ls-tree` line failed to parse as a [`TreeEntry`]. Carries
/// the offending line so a caller can attach it to a failure record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeEntryError {
    /// The line did not contain a TAB separating the metadata from the
    /// path — `git ls-tree` always emits one TAB before the path.
    MissingTab { line: String },
    /// The metadata side (left of TAB) did not split into exactly
    /// `<mode> SP <type> SP <hash>`.
    WrongMetadataShape { line: String },
    /// The mode component was not exactly six octal digits.
    InvalidMode { line: String },
    /// The type component was not one of `blob` / `tree` / `commit` /
    /// `tag` — the git object types `ls-tree` can emit.
    InvalidType { line: String },
    /// The hash component was not a lowercase-hex string of the expected
    /// length (40 for SHA-1, 64 for SHA-256).
    InvalidHash { line: String },
    /// The path component (right of TAB) was empty.
    EmptyPath { line: String },
}

impl std::fmt::Display for TreeEntryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TreeEntryError::MissingTab { line } => write!(
                f,
                "tree-listing line '{line}' has no TAB separating metadata from path"
            ),
            TreeEntryError::WrongMetadataShape { line } => write!(
                f,
                "tree-listing line '{line}' metadata is not '<mode> <type> <hash>'"
            ),
            TreeEntryError::InvalidMode { line } => write!(
                f,
                "tree-listing line '{line}' has a mode that is not six octal digits"
            ),
            TreeEntryError::InvalidType { line } => write!(
                f,
                "tree-listing line '{line}' has an object type outside blob/tree/commit/tag"
            ),
            TreeEntryError::InvalidHash { line } => write!(
                f,
                "tree-listing line '{line}' hash is not lowercase-hex of length 40 or 64"
            ),
            TreeEntryError::EmptyPath { line } => {
                write!(f, "tree-listing line '{line}' has an empty path component")
            }
        }
    }
}

impl std::error::Error for TreeEntryError {}

/// A validated `git ls-tree -r HEAD` entry: one tree-recursive object
/// reference. Constructing a [`TreeEntry`] proves the line conforms to
/// git's `<mode> <type> <hash>\t<path>` shape and that the hash is a
/// well-formed content-addressed object identity. The fields are stored
/// as owned `String`s so the canonical fingerprint can re-serialize them
/// without lifetime-coupling to the input buffer.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TreeEntry {
    // Field order chosen to make the derived `Ord` sort by `path` first —
    // path is the natural lexical key for the tree's canonical form,
    // since two entries with the same path can never coexist in a real
    // tree (git enforces unique paths).
    path: String,
    mode: String,
    object_type: String,
    hash: String,
}

impl TreeEntry {
    /// Parse a single `git ls-tree -r HEAD` line into a validated
    /// [`TreeEntry`]. The line MUST NOT carry the trailing newline
    /// (`parse_tree_listing` splits on `\n` and strips empty trailing
    /// records before delegating).
    pub fn parse(line: &str) -> Result<Self, TreeEntryError> {
        let (meta, path) = line
            .split_once('\t')
            .ok_or_else(|| TreeEntryError::MissingTab {
                line: line.to_string(),
            })?;
        if path.is_empty() {
            return Err(TreeEntryError::EmptyPath {
                line: line.to_string(),
            });
        }
        let mut parts = meta.split(' ');
        let (Some(mode), Some(object_type), Some(hash), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(TreeEntryError::WrongMetadataShape {
                line: line.to_string(),
            });
        };
        if mode.len() != MODE_LEN || !mode.bytes().all(|b| b.is_ascii_digit()) {
            return Err(TreeEntryError::InvalidMode {
                line: line.to_string(),
            });
        }
        if !matches!(object_type, "blob" | "tree" | "commit" | "tag") {
            return Err(TreeEntryError::InvalidType {
                line: line.to_string(),
            });
        }
        let hash_ok = matches!(hash.len(), HASH_LEN_SHA1 | HASH_LEN_SHA256)
            && hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !hash_ok {
            return Err(TreeEntryError::InvalidHash {
                line: line.to_string(),
            });
        }
        Ok(Self {
            path: path.to_string(),
            mode: mode.to_string(),
            object_type: object_type.to_string(),
            hash: hash.to_string(),
        })
    }

    /// The lowercase-hex object hash — the content-addressed identity
    /// the canonical fingerprint is built from.
    #[allow(dead_code)]
    pub fn hash(&self) -> &str {
        &self.hash
    }

    /// The repo-relative path this entry names.
    #[allow(dead_code)]
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// Extract the validated entries from a `git ls-tree -r HEAD` listing,
/// in input order. Blank lines and lines that do not parse to the
/// grammar are skipped — a malformed line should narrow the fingerprint,
/// not corrupt it (mirrors [`crate::store_path::parse_closure_paths`]).
pub fn parse_tree_listing(listing: &str) -> Vec<TreeEntry> {
    listing
        .split('\n')
        .filter(|l| !l.is_empty())
        .filter_map(|l| TreeEntry::parse(l).ok())
        .collect()
}

/// Canonical, order-independent fingerprint of a `git ls-tree -r HEAD`
/// listing, derived from the content-addressed object identities its
/// blobs already carry.
///
/// The fingerprint is the sorted, deduplicated set of validated
/// `<mode> SP <type> SP <hash> TAB <path>` lines, joined one per line.
/// Two listings naming the same tree (same path → mode/type/hash
/// triples) fingerprint identically regardless of input ordering or
/// trailing-whitespace drift. A listing with no parseable entries
/// fingerprints to the empty string, which the call site disambiguates
/// from the probe-failed case via an explicit sentinel
/// (`b"no-tree-listing"`, mirroring the existing `b"no-flake-lock"`).
pub fn canonical_tree_fingerprint(listing: &str) -> String {
    let entries: std::collections::BTreeSet<String> = parse_tree_listing(listing)
        .into_iter()
        .map(|e| format!("{} {} {}\t{}", e.mode, e.object_type, e.hash, e.path))
        .collect();
    entries.into_iter().collect::<Vec<_>>().join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A realistic 40-char SHA-1 object name fixture (lowercase hex).
    const H1: &str = "0123456789abcdef0123456789abcdef01234567";
    /// A second distinct SHA-1 object name fixture so order/dedup tests
    /// can show two real identities.
    const H2: &str = "fedcba9876543210fedcba9876543210fedcba98";

    #[test]
    fn test_parse_blob_entry() {
        let e = TreeEntry::parse(&format!("100644 blob {H1}\tsrc/main.rs")).unwrap();
        assert_eq!(e.path(), "src/main.rs");
        assert_eq!(e.hash(), H1);
    }

    #[test]
    fn test_parse_executable_blob() {
        let e = TreeEntry::parse(&format!("100755 blob {H1}\tbin/run.sh")).unwrap();
        assert_eq!(e.path(), "bin/run.sh");
    }

    #[test]
    fn test_parse_submodule_commit_entry() {
        // `-r` recurses through trees but leaves submodule entries as
        // type=commit with mode 160000 — a real shape the grammar must
        // accept.
        let e = TreeEntry::parse(&format!("160000 commit {H1}\tvendor/sub")).unwrap();
        assert_eq!(e.path(), "vendor/sub");
    }

    #[test]
    fn test_parse_sha256_hash_accepted() {
        // SHA-256 git repos (git 2.29+) emit 64-char lowercase-hex hashes.
        let h256 = "0".repeat(64);
        let e = TreeEntry::parse(&format!("100644 blob {h256}\tfile")).unwrap();
        assert_eq!(e.hash().len(), 64);
    }

    #[test]
    fn test_parse_path_with_spaces() {
        // The metadata-side split is on space, but everything after the
        // TAB is the path — paths with spaces (the common case) must
        // round-trip without being split.
        let e = TreeEntry::parse(&format!("100644 blob {H1}\tdocs/My File.md")).unwrap();
        assert_eq!(e.path(), "docs/My File.md");
    }

    #[test]
    fn test_parse_rejects_missing_tab() {
        let err = TreeEntry::parse(&format!("100644 blob {H1} src/main.rs")).unwrap_err();
        assert!(matches!(err, TreeEntryError::MissingTab { .. }));
    }

    #[test]
    fn test_parse_rejects_wrong_metadata_shape() {
        // Only two metadata fields before the TAB.
        let err = TreeEntry::parse(&format!("100644 {H1}\tfile")).unwrap_err();
        assert!(matches!(err, TreeEntryError::WrongMetadataShape { .. }));
        // Four fields before the TAB.
        let err = TreeEntry::parse(&format!("100644 blob {H1} extra\tfile")).unwrap_err();
        assert!(matches!(err, TreeEntryError::WrongMetadataShape { .. }));
    }

    #[test]
    fn test_parse_rejects_invalid_mode() {
        // Non-digit in mode.
        let err = TreeEntry::parse(&format!("10064x blob {H1}\tfile")).unwrap_err();
        assert!(matches!(err, TreeEntryError::InvalidMode { .. }));
        // Wrong width.
        let err = TreeEntry::parse(&format!("10644 blob {H1}\tfile")).unwrap_err();
        assert!(matches!(err, TreeEntryError::InvalidMode { .. }));
    }

    #[test]
    fn test_parse_rejects_invalid_type() {
        let err = TreeEntry::parse(&format!("100644 widget {H1}\tfile")).unwrap_err();
        assert!(matches!(err, TreeEntryError::InvalidType { .. }));
    }

    #[test]
    fn test_parse_rejects_invalid_hash() {
        // Wrong length (abbreviated).
        let err = TreeEntry::parse("100644 blob 0123456\tfile").unwrap_err();
        assert!(matches!(err, TreeEntryError::InvalidHash { .. }));
        // Uppercase hex — git emits lowercase by canonical convention.
        let err =
            TreeEntry::parse(&format!("100644 blob {}\tfile", H1.to_uppercase())).unwrap_err();
        assert!(matches!(err, TreeEntryError::InvalidHash { .. }));
        // Non-hex character in an otherwise-correct-length string.
        let err = TreeEntry::parse(&format!("100644 blob {}g\tfile", &H1[..39])).unwrap_err();
        assert!(matches!(err, TreeEntryError::InvalidHash { .. }));
    }

    #[test]
    fn test_parse_rejects_empty_path() {
        let err = TreeEntry::parse(&format!("100644 blob {H1}\t")).unwrap_err();
        assert!(matches!(err, TreeEntryError::EmptyPath { .. }));
    }

    #[test]
    fn test_error_display_names_offending_line() {
        let err = TreeEntry::parse("garbage line").unwrap_err();
        assert!(
            err.to_string().contains("garbage line"),
            "error must name the offending line; got: {err}"
        );
    }

    #[test]
    fn test_parse_tree_listing_skips_malformed_and_blank() {
        let listing = format!(
            "100644 blob {H1}\ta\n\n\
             garbage line with no tab\n\
             100644 blob {H2}\tb\n"
        );
        let entries = parse_tree_listing(&listing);
        assert_eq!(
            entries.len(),
            2,
            "only the two well-formed entries parse; blank and garbage skipped"
        );
        assert_eq!(entries[0].path(), "a");
        assert_eq!(entries[1].path(), "b");
    }

    #[test]
    fn test_canonical_tree_fingerprint_is_order_independent() {
        // Two listings naming the same set of (mode, type, hash, path)
        // triples in different orders must fingerprint identically. This
        // is the load-bearing canonical-form property the raw-byte
        // digest lacked.
        let listing1 = format!("100644 blob {H1}\ta\n100644 blob {H2}\tb\n");
        let listing2 = format!("100644 blob {H2}\tb\n100644 blob {H1}\ta\n");
        assert_eq!(
            canonical_tree_fingerprint(&listing1),
            canonical_tree_fingerprint(&listing2),
            "fingerprint must be order-independent"
        );
        // The two raw inputs ARE distinct, so a raw-byte digest of either
        // would differ — the gap the canonical form closes.
        assert_ne!(listing1, listing2);
    }

    #[test]
    fn test_canonical_tree_fingerprint_dedups_repeated_entries() {
        let listing = format!(
            "100644 blob {H1}\ta\n\
             100644 blob {H1}\ta\n\
             100644 blob {H2}\tb\n"
        );
        let fp = canonical_tree_fingerprint(&listing);
        assert_eq!(
            fp,
            format!("100644 blob {H1}\ta\n100644 blob {H2}\tb"),
            "repeated entries collapse to one canonical line"
        );
    }

    #[test]
    fn test_canonical_tree_fingerprint_changes_when_content_changes() {
        // Changing a single blob's hash (the same path now points at
        // different content) must drift the fingerprint — the property
        // that makes this the source-tree identity, not a hash of the
        // path list alone.
        let listing1 = format!("100644 blob {H1}\ta\n");
        let listing2 = format!("100644 blob {H2}\ta\n");
        assert_ne!(
            canonical_tree_fingerprint(&listing1),
            canonical_tree_fingerprint(&listing2),
            "different blob content at the same path must produce a different fingerprint"
        );
    }

    #[test]
    fn test_canonical_tree_fingerprint_empty_for_unparseable() {
        // Empty input, whitespace-only, and a listing made entirely of
        // garbage all collapse to the same empty fingerprint. The call
        // site disambiguates this from a probe failure via an explicit
        // sentinel; this function itself just reports "no parseable
        // entries".
        assert_eq!(canonical_tree_fingerprint(""), "");
        assert_eq!(canonical_tree_fingerprint("\n\n\n"), "");
        assert_eq!(canonical_tree_fingerprint("not a tree listing"), "");
    }
}
