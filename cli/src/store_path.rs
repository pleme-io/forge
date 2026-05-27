//! Canonical Nix store-path grammar for forge.
//!
//! A Nix store object path is content-addressed by construction:
//! `/nix/store/<hash>-<name>`, where `<hash>` is exactly 32 characters of
//! the Nix base-32 alphabet (a 160-bit truncated digest of the object's
//! inputs) and `<name>` is the human-readable suffix. A derivation path is
//! the same shape with a trailing `.drv`. The 32-char content hash IS the
//! hermetic fingerprint the SLSA provenance claim rests on — a string that
//! does not parse to this grammar is not a store object and cannot
//! substantiate a provenance claim.
//!
//! forge had no typed home for this grammar: store paths flowed through the
//! pipeline as bare `String`s (nix-build stdout → `attic push` arg →
//! attestation), and the one place that needed to know "is this a real
//! store path?" — the SLSA provenance gate in
//! `commands/attestation.rs::build_slsa_level` — asked the *negative*
//! question `!derivation.starts_with("/nix/store/unknown-")`, recognising
//! only the one specific `/nix/store/unknown-{service}.drv` I/O-error
//! sentinel and silently treating an empty, relative, or otherwise
//! malformed derivation as if it carried provenance. This module is the
//! single oracle that answers the *positive* question — is this string a
//! well-formed, content-addressed store object path? — so the provenance
//! gate, and any future store-path consumer (attic push validation, closure
//! parsing), share one grammar instead of re-deriving sentinel checks.

/// The Nix base-32 alphabet: digits plus lowercase letters omitting
/// `e`, `o`, `u`, `t`. Exactly 32 symbols (5 bits each); a store-path hash
/// is 32 of these (160 bits).
const NIXBASE32_ALPHABET: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";

/// Length of the content-hash component of a store path, in base-32
/// characters. Fixed by the Nix store: a 160-bit truncated digest encodes
/// to exactly 32 base-32 symbols.
const HASH_LEN: usize = 32;

/// The store prefix every store object path begins with.
const STORE_PREFIX: &str = "/nix/store/";

/// Why a string failed to parse as a Nix store object path. Carries the
/// offending input so a caller can attach it to a failure record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorePathError {
    /// The path did not begin with `/nix/store/`.
    MissingStorePrefix { input: String },
    /// The store-object component contained a `/` — a subpath into a store
    /// object (e.g. `…-foo/bin/x`), not the store object path itself.
    HasSubpath { input: String },
    /// The component was too short to hold a 32-char hash, a `-`, and a
    /// non-empty name.
    TooShort { input: String },
    /// The first 32 characters were not all in the Nix base-32 alphabet.
    InvalidHash { input: String },
    /// The 32-char hash was not followed by the `-` name separator.
    MissingSeparator { input: String },
    /// The name (the part after `<hash>-`) was empty.
    EmptyName { input: String },
}

impl std::fmt::Display for StorePathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorePathError::MissingStorePrefix { input } => write!(
                f,
                "store path '{input}' does not begin with '{STORE_PREFIX}'"
            ),
            StorePathError::HasSubpath { input } => write!(
                f,
                "store path '{input}' contains a subpath; expected a bare store object path"
            ),
            StorePathError::TooShort { input } => write!(
                f,
                "store path '{input}' is too short to hold a 32-char hash, '-', and a name"
            ),
            StorePathError::InvalidHash { input } => write!(
                f,
                "store path '{input}' has a hash component outside the Nix base-32 alphabet"
            ),
            StorePathError::MissingSeparator { input } => write!(
                f,
                "store path '{input}' hash is not followed by the '-' name separator"
            ),
            StorePathError::EmptyName { input } => {
                write!(f, "store path '{input}' has an empty name component")
            }
        }
    }
}

impl std::error::Error for StorePathError {}

/// A validated Nix store object path: `/nix/store/<hash>-<name>`.
///
/// Constructing a `StorePath` proves the string is a content-addressed
/// store object — a malformed, empty, relative, or `unknown-*`-sentinel
/// string fails to construct. The 32-char hash and the name are sliced once
/// at parse time so consumers never re-`split` the raw string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorePath {
    full: String,
    /// Byte offset where the name begins (after `STORE_PREFIX`, the 32-char
    /// hash, and the `-` separator).
    name_start: usize,
}

impl StorePath {
    /// Parse a string into a validated [`StorePath`].
    ///
    /// Leading/trailing whitespace is trimmed (nix-build stdout carries a
    /// trailing newline). The grammar is exact: `/nix/store/` prefix, then a
    /// 32-character Nix base-32 hash, then `-`, then a non-empty name. The
    /// store-object component must not contain a `/` (a subpath into the
    /// object is rejected — callers validate the object path, not a file
    /// inside it).
    pub fn parse(input: &str) -> Result<Self, StorePathError> {
        let trimmed = input.trim();
        let rest = trimmed.strip_prefix(STORE_PREFIX).ok_or_else(|| {
            StorePathError::MissingStorePrefix {
                input: trimmed.to_string(),
            }
        })?;
        if rest.contains('/') {
            return Err(StorePathError::HasSubpath {
                input: trimmed.to_string(),
            });
        }
        // Need at least the 32-char hash plus one more byte so `split_at`
        // cannot panic and there is something where the separator belongs;
        // the separator and non-empty-name checks below discriminate the
        // exact failure beyond that.
        if rest.len() < HASH_LEN + 1 {
            return Err(StorePathError::TooShort {
                input: trimmed.to_string(),
            });
        }
        let (hash, sep_and_name) = rest.split_at(HASH_LEN);
        if !hash.bytes().all(|b| NIXBASE32_ALPHABET.contains(&b)) {
            return Err(StorePathError::InvalidHash {
                input: trimmed.to_string(),
            });
        }
        let name =
            sep_and_name
                .strip_prefix('-')
                .ok_or_else(|| StorePathError::MissingSeparator {
                    input: trimmed.to_string(),
                })?;
        if name.is_empty() {
            return Err(StorePathError::EmptyName {
                input: trimmed.to_string(),
            });
        }
        let name_start = STORE_PREFIX.len() + HASH_LEN + 1;
        Ok(Self {
            full: trimmed.to_string(),
            name_start,
        })
    }

    /// The full validated store path (whitespace-trimmed). The irreducible
    /// read-back accessor for the named next consumer — passing a validated
    /// path to `attic push` — so the round-trip through this type carries no
    /// silent re-stringification. `allow(dead_code)`: part of the primitive
    /// surface, as with `nix::NixBuildResult::flake_attr` and
    /// `nix::flake_attr_exists`.
    #[allow(dead_code)]
    pub fn as_str(&self) -> &str {
        &self.full
    }

    /// The 32-char content hash component — the hermetic fingerprint this
    /// type exists to expose. `allow(dead_code)`: surfaced for the
    /// content-addressed consumers (closure de-dup, attestation hashing)
    /// the module docstring names; not yet wired at a call site.
    #[allow(dead_code)]
    pub fn hash(&self) -> &str {
        &self.full[STORE_PREFIX.len()..STORE_PREFIX.len() + HASH_LEN]
    }

    /// The name component (everything after `<hash>-`), including any
    /// trailing `.drv`.
    pub fn name(&self) -> &str {
        &self.full[self.name_start..]
    }

    /// Whether this is a derivation path (`…-<name>.drv`) as opposed to a
    /// build output path. `nix path-info --derivation` yields a `.drv`;
    /// a build output does not.
    pub fn is_derivation(&self) -> bool {
        self.name().ends_with(".drv")
    }
}

impl std::fmt::Display for StorePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.full)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real 32-char Nix base-32 hash (the alphabet itself, which is
    /// exactly 32 valid symbols) — used as a realistic fixture so tests
    /// exercise the true hash length rather than a short placeholder.
    const H: &str = "0123456789abcdfghijklmnpqrsvwxyz";

    #[test]
    fn test_parse_output_path() {
        let p = StorePath::parse(&format!("/nix/store/{H}-hello-2.10")).unwrap();
        assert_eq!(p.hash(), H);
        assert_eq!(p.name(), "hello-2.10");
        assert!(!p.is_derivation(), "output path is not a derivation");
    }

    #[test]
    fn test_parse_derivation_path() {
        let p = StorePath::parse(&format!("/nix/store/{H}-mysvc.drv")).unwrap();
        assert_eq!(p.name(), "mysvc.drv");
        assert!(p.is_derivation(), "a .drv name marks a derivation");
    }

    #[test]
    fn test_parse_trims_trailing_newline() {
        // nix-build stdout carries a trailing newline.
        let p = StorePath::parse(&format!("/nix/store/{H}-x\n")).unwrap();
        assert_eq!(p.as_str(), format!("/nix/store/{H}-x"));
    }

    #[test]
    fn test_name_may_contain_hyphens() {
        // The split is hash = first 32 chars, then '-', then the rest —
        // so a name with its own hyphens (the common case) round-trips.
        let p = StorePath::parse(&format!("/nix/store/{H}-foo-bar-1.2.3")).unwrap();
        assert_eq!(p.name(), "foo-bar-1.2.3");
    }

    #[test]
    fn test_empty_is_missing_prefix() {
        assert!(matches!(
            StorePath::parse(""),
            Err(StorePathError::MissingStorePrefix { .. })
        ));
    }

    #[test]
    fn test_relative_path_is_missing_prefix() {
        assert!(matches!(
            StorePath::parse("nix/store/abc-x"),
            Err(StorePathError::MissingStorePrefix { .. })
        ));
    }

    #[test]
    fn test_unknown_sentinel_is_invalid_hash() {
        // The `/nix/store/unknown-{service}.drv` I/O-error fallback the
        // attestation code synthesises is NOT a valid store path: its
        // "hash" component is the literal `unknown-mysvc.drv`'s first 32
        // chars, which are not all base-32. This is the case the old
        // negative-sentinel `starts_with("/nix/store/unknown-")` check
        // special-cased; the positive grammar rejects it by construction.
        let err = StorePath::parse("/nix/store/unknown-mysvc.drv").unwrap_err();
        // "unknown-mysvc.drv" is < 34 chars, so it trips TooShort first.
        assert!(matches!(err, StorePathError::TooShort { .. }));
    }

    #[test]
    fn test_long_non_base32_hash_is_invalid_hash() {
        // 32 chars but containing 'e','o','u','t' (the omitted symbols) —
        // long enough to clear TooShort, so it must trip InvalidHash.
        let bad = "eeeeoooouuuutttteeeeoooouuuutttt"; // 32 chars, all illegal
        assert_eq!(bad.len(), 32);
        let err = StorePath::parse(&format!("/nix/store/{bad}-x")).unwrap_err();
        assert!(matches!(err, StorePathError::InvalidHash { .. }));
    }

    #[test]
    fn test_subpath_is_rejected() {
        let err = StorePath::parse(&format!("/nix/store/{H}-foo/bin/foo")).unwrap_err();
        assert!(matches!(err, StorePathError::HasSubpath { .. }));
    }

    #[test]
    fn test_missing_separator_is_rejected() {
        // 33 chars: a valid 32-char hash followed by a non-'-' byte, so the
        // separator check fires rather than TooShort.
        let err = StorePath::parse(&format!("/nix/store/{H}x")).unwrap_err();
        assert!(matches!(err, StorePathError::MissingSeparator { .. }));
    }

    #[test]
    fn test_empty_name_is_rejected() {
        // 33 chars: a valid 32-char hash, the '-' separator, then nothing.
        let err = StorePath::parse(&format!("/nix/store/{H}-")).unwrap_err();
        assert!(matches!(err, StorePathError::EmptyName { .. }));
    }

    #[test]
    fn test_error_display_names_offending_input() {
        let err = StorePath::parse("/nix/store/unknown-mysvc.drv").unwrap_err();
        assert!(
            err.to_string().contains("unknown-mysvc.drv"),
            "error must name the offending input; got: {err}"
        );
    }
}
