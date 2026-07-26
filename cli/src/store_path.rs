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
    /// type exists to expose. Consumed by [`canonical_closure_fingerprint`]
    /// to reduce a build closure to the content-addressed identity of its
    /// store objects, independent of the volatile metadata `nix path-info`
    /// interleaves with each path.
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

/// Canonical parse-peer for [`StorePath::parse`] via the [`std::str::FromStr`]
/// trait — the Rust idiom for "this type reads back from a string".
///
/// Delegates verbatim to [`StorePath::parse`], so the store-path grammar
/// (`/nix/store/<32-char-base32-hash>-<name>`, no subpath, non-empty name)
/// stays defined at ONE construction surface. Adding a new grammar clause
/// (e.g., a future output-hash prefix or a fixed-output store-path shape)
/// lands in `parse` once, and both the inherent constructor and the trait
/// peer light up in the same commit.
///
/// # Why the trait peer earns its keep
///
/// The inherent [`StorePath::parse`] is the direct constructor; the trait
/// peer opens the same oracle to every downstream context that already
/// speaks [`std::str::FromStr`]:
///
/// - The `str::parse` turbofish (`"/nix/store/…".parse::<StorePath>()`) —
///   the idiomatic Rust surface any reader reaches for first.
/// - Generic bounds (`fn from_string_column<T: FromStr>(s: &str) -> …`) —
///   a downstream CSV / config-loader / attestation-record reader that
///   validates typed columns can name `StorePath` alongside every other
///   `FromStr` typed primitive without a shim.
/// - `serde(try_from = "String")` — a future serde consumer that
///   deserializes store paths from JSON / YAML gets the grammar check
///   through this trait without duplicating the parse call.
/// - `clap(value_parser)` — a future `forge` CLI subcommand that accepts
///   a store path on the argv can bind directly on `StorePath` and let
///   clap route through this trait, so the "malformed store path" error
///   surfaces at argv-parse time rather than deep inside the attestation
///   or attic-push pipeline.
///
/// # Error shape
///
/// `Self::Err = StorePathError`. The typed enum names the exact grammar
/// clause the input violated — `MissingStorePrefix` / `HasSubpath` /
/// `TooShort` / `InvalidHash` / `MissingSeparator` / `EmptyName` — and
/// carries the offending input in each variant, so a caller can attach
/// the failure to a structural record (THEORY §V.4 Phase 1 attestation)
/// without re-parsing the error string.
impl std::str::FromStr for StorePath {
    type Err = StorePathError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// By-reference try-conversion peer for [`StorePath::parse`] via the
/// [`TryFrom<&str>`] trait — the stdlib idiom that pairs with
/// [`std::str::FromStr`] at the try-conversion frontier.
///
/// Delegates verbatim through `<Self as std::str::FromStr>::from_str`, so
/// the store-path grammar stays defined at ONE construction surface — the
/// FromStr peer, which itself delegates to [`StorePath::parse`]. A grammar
/// clause added to `parse` lights up here without a second edit.
///
/// # Why the trait peer earns its keep
///
/// [`std::str::FromStr`] covers the turbofish (`"…".parse::<StorePath>()`)
/// and generic `T: FromStr` bounds. `TryFrom<&str>` covers a disjoint set
/// of downstream idioms that key off `TryFrom` rather than `FromStr`:
///
/// - `#[serde(try_from = "&str")]` — the serde container attribute keys
///   off [`TryFrom`], not [`FromStr`]. A future serde field that borrows
///   the incoming `&str` (no per-field allocation) reaches the store-path
///   grammar check through this impl without a shim.
/// - Generic try-conversion bounds (`fn parse_field<T: for<'a> TryFrom<&'a str>>`)
///   — a validated-input newtype builder or attestation-column reader
///   that types its parse contract as `TryFrom<&str>` rather than
///   `FromStr` can name `StorePath` alongside every other by-reference
///   try-conversion primitive without routing through a shim.
/// - Uniform trait-object surfaces (`&dyn AttestationField` witnesses
///   whose parse contract is stated as `TryFrom<&str>`) — the parallel
///   canonical-label typed sums in this crate already carry the pair
///   (`impl TryFrom<&str> for PerAttemptRegion` at `retry.rs`,
///   `impl TryFrom<&str> for AdmissionTier` at `probe_outcome.rs`,
///   `impl TryFrom<&str> for DigestAlgorithm` at `oci_manifest.rs`);
///   `StorePath` is the store-path primitive counterpart at the same
///   try-conversion frontier.
///
/// # Error shape
///
/// `Self::Error = StorePathError`. The typed grammar-clause enum
/// (`MissingStorePrefix` / `HasSubpath` / `TooShort` / `InvalidHash` /
/// `MissingSeparator` / `EmptyName`) carries through — no widening to
/// [`anyhow::Error`] or `Box<dyn Error>` hides between the by-reference
/// try-conversion surface and the inherent constructor, so a caller can
/// still `match` on the exact clause the input violated at the trait
/// entry point.
impl TryFrom<&str> for StorePath {
    type Error = StorePathError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        <Self as std::str::FromStr>::from_str(s)
    }
}

/// By-value owned-string try-conversion peer for [`StorePath::parse`] via
/// the [`TryFrom<String>`] trait — the by-value counterpart of the
/// [`TryFrom<&str>`] by-reference frontier directly above.
///
/// Delegates through `<Self as std::str::FromStr>::from_str` on the
/// borrowed [`str`] view of the caller-supplied [`String`] (`s.as_str()`),
/// so the store-path grammar stays defined at ONE construction surface —
/// the FromStr peer, which itself delegates to [`StorePath::parse`]. No
/// clone of the input buffer, no divergent grammar: `String::as_str` is a
/// zero-allocation borrow of the owned bytes.
///
/// # Why the trait peer earns its keep
///
/// [`TryFrom<&str>`] covers the by-reference frontier
/// (`#[serde(try_from = "&str")]`, `fn f<T: for<'a> TryFrom<&'a str>>`).
/// [`TryFrom<String>`] covers the disjoint by-value owned-buffer frontier
/// that stdlib and the wider ecosystem key off separately:
///
/// - `#[serde(try_from = "String")]` — the serde container attribute for
///   the owned-buffer case (a deserializer that produced a [`String`],
///   not a borrowed `&str`) keys off [`TryFrom<String>`], not
///   [`TryFrom<&str>`] or [`FromStr`]. A future serde field wrapping a
///   `StorePath` and opting into the owned-buffer `try_from` grammar
///   reaches the store-path check through this impl without a shim.
/// - Generic try-conversion bounds
///   (`fn parse_field<T: TryFrom<String>>`) — a validated-input newtype
///   builder or attestation-column reader whose parse contract is stated
///   as owning the input buffer (rather than borrowing it) can name
///   `StorePath` alongside every other by-value try-conversion primitive
///   without routing through a shim.
/// - Sibling canonical-label typed sums in this crate already carry the
///   pair: `impl TryFrom<String> for PerAttemptRegion` at `retry.rs`,
///   `impl TryFrom<String> for AdmissionTier` at `probe_outcome.rs`,
///   `impl TryFrom<String> for DigestAlgorithm` at `oci_manifest.rs`;
///   `StorePath` is the store-path primitive counterpart at the same
///   by-value try-conversion frontier.
///
/// # Error shape
///
/// `Self::Error = StorePathError`. The typed grammar-clause enum
/// (`MissingStorePrefix` / `HasSubpath` / `TooShort` / `InvalidHash` /
/// `MissingSeparator` / `EmptyName`) carries through from [`FromStr`] —
/// no widening to [`anyhow::Error`] or `Box<dyn Error>` hides between the
/// by-value try-conversion surface and the inherent constructor, so a
/// caller can still `match` on the exact clause the input violated at the
/// trait entry point.
impl TryFrom<String> for StorePath {
    type Error = StorePathError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        <Self as std::str::FromStr>::from_str(s.as_str())
    }
}

/// Borrowed-or-owned UTF-8 try-conversion peer for [`StorePath::parse`] via
/// the [`TryFrom<Cow<'_, str>>`] trait — the borrowed/owned frontier that
/// bridges the [`TryFrom<&str>`] by-reference and [`TryFrom<String>`]
/// by-value peers directly above under a single receiver type.
///
/// Delegates through `<Self as std::str::FromStr>::from_str` on the borrowed
/// [`str`] view of the caller-supplied [`std::borrow::Cow`] (borrowed
/// through [`std::borrow::Cow::as_ref`] from the [`Cow::Borrowed`] arm,
/// dereferenced off the owned [`String`] in the [`Cow::Owned`] arm without
/// cloning), so the store-path grammar stays defined at ONE construction
/// surface — the [`std::str::FromStr`] peer, which itself delegates to
/// [`StorePath::parse`]. No clone of the input buffer on the [`Cow::Owned`]
/// arm, no divergent grammar between the two arms: the impl body pays the
/// by-reference [`std::str::FromStr`] cost at zero allocation on either arm.
///
/// # Why the trait peer earns its keep
///
/// [`TryFrom<&str>`] covers the by-reference frontier
/// (`#[serde(try_from = "&str")]`, `fn f<T: for<'a> TryFrom<&'a str>>`).
/// [`TryFrom<String>`] covers the by-value owned-string frontier
/// (`#[serde(try_from = "String")]`, `fn f<T: TryFrom<String>>`).
/// [`TryFrom<Cow<'_, str>>`] covers the disjoint borrowed-or-owned frontier
/// stdlib and the wider ecosystem key off separately:
///
/// - `#[serde(try_from = "Cow<'_, str>")]` — the serde container attribute
///   for the borrowed-or-owned case (a deserializer that hands its container
///   a [`std::borrow::Cow`] to defer the ownership decision to the
///   underlying [`serde::Deserializer`] and preserve zero-copy where the
///   input allows it) keys off [`TryFrom<Cow<'_, str>>`], not
///   [`TryFrom<&str>`], [`TryFrom<String>`], or [`FromStr`]. A future serde
///   field wrapping a `StorePath` and opting into the borrowed-or-owned
///   `try_from` grammar reaches the store-path check through this impl
///   without a shim.
/// - Generic try-conversion bounds
///   (`fn parse_path<'a, T: TryFrom<Cow<'a, str>>>`) — a validated-input
///   newtype builder or closure-doc field reader whose parse contract is
///   stated at the borrowed-or-owned receiver-shape layer (rather than
///   fixed at borrow or owned) can name `StorePath` alongside every other
///   borrowed-or-owned try-conversion primitive without routing through a
///   shim.
/// - Sibling canonical-string typed primitives in this crate already carry
///   the pair: `impl TryFrom<Cow<'_, str>> for DigestAlgorithm` at
///   `oci_manifest.rs::964`; `StorePath` is the store-path primitive
///   counterpart at the same borrowed-or-owned try-conversion frontier.
///
/// # Error shape
///
/// `Self::Error = StorePathError`. The typed grammar-clause enum
/// (`MissingStorePrefix` / `HasSubpath` / `TooShort` / `InvalidHash` /
/// `MissingSeparator` / `EmptyName`) carries through from [`FromStr`] —
/// no widening to [`anyhow::Error`] or `Box<dyn Error>` hides between the
/// borrowed-or-owned try-conversion surface and the inherent constructor,
/// so a caller can still `match` on the exact clause the input violated at
/// the trait entry point on either [`Cow`] arm.
impl TryFrom<std::borrow::Cow<'_, str>> for StorePath {
    type Error = StorePathError;

    fn try_from(s: std::borrow::Cow<'_, str>) -> Result<Self, Self::Error> {
        <Self as std::str::FromStr>::from_str(s.as_ref())
    }
}

/// Shrunk-owned UTF-8 try-conversion peer for [`StorePath::parse`] via the
/// [`TryFrom<Box<str>>`] trait — the boxed-string frontier that pairs with
/// the [`TryFrom<String>`] by-value peer under a receiver shape that has
/// dropped the [`String`] capacity header so only the UTF-8 payload
/// bytes and the pointer remain.
///
/// Delegates through [`<Self as TryFrom<String>>::try_from`] on the
/// [`String::from`] recovery of the caller-supplied [`Box<str>`], so the
/// store-path grammar stays defined at ONE construction surface — the
/// [`std::str::FromStr`] peer, which itself delegates to
/// [`StorePath::parse`]. [`String::from(Box<str>)`] is a zero-copy
/// ownership transfer: it reuses the boxed slice's allocation as the
/// [`String`] buffer (with `len == capacity`), so the impl body pays no
/// buffer-cloning cost on the way through the by-value peer.
///
/// # Why the trait peer earns its keep
///
/// [`TryFrom<String>`] covers the by-value owned-buffer frontier
/// (`#[serde(try_from = "String")]`, `fn f<T: TryFrom<String>>`).
/// [`TryFrom<Cow<'_, str>>`] covers the borrowed-or-owned frontier
/// (`#[serde(try_from = "Cow<'_, str>")]`,
/// `fn f<'a, T: TryFrom<Cow<'a, str>>>`). [`TryFrom<Box<str>>`] covers the
/// disjoint shrunk-owned frontier stdlib and the wider ecosystem key off
/// separately:
///
/// - `#[serde(try_from = "Box<str>")]` — the serde container attribute for
///   the shrunk-owned case (a deserializer that shrinks its owned UTF-8
///   buffer to `len == capacity` before handing it off, saving the
///   [`String`] capacity header) keys off [`TryFrom<Box<str>>`], not
///   [`TryFrom<String>`], [`TryFrom<&str>`], or [`FromStr`]. A future
///   serde field wrapping a `StorePath` and opting into the shrunk-owned
///   `try_from` grammar reaches the store-path check through this impl
///   without a shim.
/// - Generic try-conversion bounds (`fn parse_field<T: TryFrom<Box<str>>>`)
///   — a validated-input newtype builder or attestation-column reader
///   whose parse contract is stated at the shrunk-owned receiver-shape
///   layer (an owned UTF-8 label without the capacity header, common in
///   memory-tight caches and long-lived tables of parsed labels) can name
///   `StorePath` alongside every other shrunk-owned try-conversion
///   primitive without routing through a shim.
/// - Sibling canonical-string typed primitives in this crate already
///   carry the pair: `impl TryFrom<Box<str>> for DigestAlgorithm` at
///   `oci_manifest.rs::1269`; `StorePath` is the store-path primitive
///   counterpart at the same shrunk-owned try-conversion frontier.
///
/// # Error shape
///
/// `Self::Error = StorePathError`. The typed grammar-clause enum
/// (`MissingStorePrefix` / `HasSubpath` / `TooShort` / `InvalidHash` /
/// `MissingSeparator` / `EmptyName`) carries through from [`FromStr`] —
/// no widening to [`anyhow::Error`] or `Box<dyn Error>` hides between the
/// shrunk-owned try-conversion surface and the inherent constructor, so
/// a caller can still `match` on the exact clause the input violated at
/// the trait entry point.
impl TryFrom<Box<str>> for StorePath {
    type Error = StorePathError;

    fn try_from(boxed: Box<str>) -> Result<Self, Self::Error> {
        <Self as TryFrom<String>>::try_from(String::from(boxed))
    }
}

/// Extract the validated Nix store paths from a `nix path-info --recursive
/// --json` closure document, in document order.
///
/// `nix path-info --json` has emitted two shapes across nix versions: a
/// JSON array of objects each carrying a `"path"` field (older), and a JSON
/// object keyed by the store path (newer). Both are accepted. An entry
/// whose path does not parse as a [`StorePath`] is skipped — the document
/// may carry a non-store entry or be truncated by a partial `path-info`
/// failure, and a fingerprint built from the paths that *are* well-formed
/// is more honest than one taken over the malformed text. A document that
/// is not valid JSON yields no paths.
pub fn parse_closure_paths(closure_info: &str) -> Vec<StorePath> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(closure_info) else {
        return Vec::new();
    };
    let candidates: Vec<&str> = match &value {
        serde_json::Value::Array(items) => items
            .iter()
            .filter_map(|item| item.get("path").and_then(serde_json::Value::as_str))
            .collect(),
        serde_json::Value::Object(map) => map.keys().map(String::as_str).collect(),
        _ => Vec::new(),
    };
    candidates
        .into_iter()
        .filter_map(|s| StorePath::parse(s).ok())
        .collect()
}

/// Canonical, order- and metadata-independent fingerprint of a Nix build
/// closure, derived from the *content hashes* of its store paths.
///
/// `nix path-info --recursive --json` interleaves the content-addressed
/// identity of each store object with volatile metadata —
/// `registrationTime`, `signatures`, `ultimate`, `narSize`, and a path
/// ordering that is not guaranteed stable across nix versions. Hashing the
/// raw document therefore yields a closure fingerprint that drifts run to
/// run even when the closure is byte-identical, defeating the very
/// reproducibility the closure hash exists to attest (THEORY §VI.1:
/// regenerating an artifact from the same inputs must produce a
/// byte-identical result). This reduces the closure to the *set* of its
/// 32-char base-32 content hashes — the hermetic fingerprints
/// [`StorePath::hash`] exposes — deduplicated and lexically sorted, joined
/// one per line. Two builds with the same closure content produce the same
/// fingerprint regardless of metadata or emission order; a closure with no
/// parseable store paths fingerprints to the empty string.
pub fn canonical_closure_fingerprint(closure_info: &str) -> String {
    let paths = parse_closure_paths(closure_info);
    let hashes: std::collections::BTreeSet<&str> = paths.iter().map(StorePath::hash).collect();
    hashes.into_iter().collect::<Vec<_>>().join("\n")
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

    /// A second valid 32-char Nix base-32 hash (a permutation of the
    /// alphabet) so closure fixtures can carry two *distinct* store-object
    /// identities and exercise sorting / de-dup.
    const H2: &str = "zyxwvsrqpnmlkjihgfdcba9876543210";

    #[test]
    fn test_parse_closure_paths_array_shape() {
        // Older nix: a JSON array of objects each carrying a `path` field.
        // A non-store entry and a non-object element are both skipped.
        let doc = format!(
            r#"[{{"path":"/nix/store/{H}-a","narHash":"sha256-x"}},
                {{"path":"/nix/store/{H2}-b.drv","registrationTime":1700000000}},
                {{"path":"not-a-store-path"}},
                "stray-string"]"#
        );
        let paths = parse_closure_paths(&doc);
        assert_eq!(paths.len(), 2, "only the two well-formed store paths parse");
        assert_eq!(paths[0].name(), "a");
        assert_eq!(paths[1].name(), "b.drv");
    }

    #[test]
    fn test_parse_closure_paths_object_shape() {
        // Newer nix: a JSON object keyed by the store path.
        let doc = format!(
            r#"{{"/nix/store/{H}-a": {{"narHash":"sha256-x"}},
                "/nix/store/{H2}-b": {{"narHash":"sha256-y"}}}}"#
        );
        let paths = parse_closure_paths(&doc);
        assert_eq!(paths.len(), 2, "both map keys parse as store paths");
        // The map keys are the store-object identities; the fingerprint is
        // their sorted content hashes regardless of map iteration order.
        assert_eq!(canonical_closure_fingerprint(&doc), format!("{H}\n{H2}"));
    }

    #[test]
    fn test_canonical_closure_fingerprint_is_stable_where_raw_bytes_drift() {
        // Two documents describing the SAME closure content, differing only
        // in path emission order and volatile metadata (registrationTime).
        let doc1 = format!(
            r#"[{{"path":"/nix/store/{H}-a","registrationTime":111}},
                {{"path":"/nix/store/{H2}-b","registrationTime":111}}]"#
        );
        let doc2 = format!(
            r#"[{{"path":"/nix/store/{H2}-b","registrationTime":999}},
                {{"path":"/nix/store/{H}-a","registrationTime":999}}]"#
        );
        // The canonical fingerprint cancels both order and metadata: it is
        // the sorted set of content hashes only.
        assert_eq!(
            canonical_closure_fingerprint(&doc1),
            canonical_closure_fingerprint(&doc2),
            "fingerprint must be order- and metadata-independent"
        );
        // The fingerprint is the lexically-sorted unique hashes joined by
        // newline; H < H2 lexically ('0' < 'z').
        assert_eq!(canonical_closure_fingerprint(&doc1), format!("{H}\n{H2}"));
        // Contrast: the prior raw-byte scheme hashed the document text, and
        // these two equivalent closures are NOT byte-equal — the drift this
        // canonicalization closes.
        assert_ne!(
            doc1, doc2,
            "raw documents differ where the closure does not"
        );
    }

    #[test]
    fn test_canonical_closure_fingerprint_dedups_repeated_paths() {
        // A recursive closure may list the same store object more than once
        // (it is referenced by several parents); the fingerprint is a set.
        let doc = format!(
            r#"[{{"path":"/nix/store/{H}-a"}},
                {{"path":"/nix/store/{H}-a"}},
                {{"path":"/nix/store/{H2}-b"}}]"#
        );
        assert_eq!(canonical_closure_fingerprint(&doc), format!("{H}\n{H2}"));
    }

    /// The [`std::str::FromStr`] trait peer must accept every input the
    /// inherent [`StorePath::parse`] accepts and produce an equal
    /// [`StorePath`] value. Pins the delegation: a future refactor that
    /// severs the trait impl from `Self::parse` (e.g., inlining a stale
    /// grammar clause into `from_str`) would silently drift the two
    /// construction surfaces apart; this test fails first.
    #[test]
    fn test_fromstr_success_agrees_with_inherent_parse() {
        let raw = format!("/nix/store/{H}-hello-2.10");
        let via_trait: StorePath = raw.parse().expect("valid store path parses via trait");
        let via_inherent = StorePath::parse(&raw).expect("valid store path parses inherently");
        assert_eq!(
            via_trait, via_inherent,
            "FromStr must yield the same StorePath value as the inherent constructor"
        );
    }

    /// The [`std::str::FromStr`] trait peer must reject every input the
    /// inherent [`StorePath::parse`] rejects, and must surface the SAME
    /// typed [`StorePathError`] variant carrying the SAME offending input.
    /// Pins that no error-widening shim (`.map_err(anyhow!(...))`,
    /// `Box<dyn Error>` coercion) hides between the two surfaces — the
    /// typed grammar clause the input violated stays legible at the
    /// trait entry point.
    #[test]
    fn test_fromstr_failure_preserves_typed_error_variant() {
        // `unknown-mysvc.drv` is < 34 chars so it trips TooShort under both
        // constructors — the load-bearing shape the attestation gate reads
        // when the pipeline synthesises the I/O-error sentinel.
        let bad = "/nix/store/unknown-mysvc.drv";
        let trait_err = bad
            .parse::<StorePath>()
            .expect_err("malformed store path must fail via trait");
        let inherent_err =
            StorePath::parse(bad).expect_err("malformed store path must fail inherently");
        assert_eq!(
            trait_err, inherent_err,
            "FromStr must surface the same typed error as the inherent constructor"
        );
        assert!(matches!(trait_err, StorePathError::TooShort { .. }));
    }

    /// Round-trip via the turbofish `str::parse` surface — the idiom every
    /// Rust reader reaches for first — must produce a value whose `Display`
    /// re-emits the (trimmed) input verbatim. Pins the `FromStr` /
    /// `Display` peer discipline the store-path grammar rests on: the
    /// parse-round-trip is byte-stable, so a future consumer that
    /// serializes a `StorePath` through `format!("{path}")` and rehydrates
    /// via `str::parse` recovers the same identity.
    #[test]
    fn test_fromstr_display_roundtrip_is_stable() {
        let raw = format!("/nix/store/{H}-foo-bar-1.2.3");
        let path: StorePath = raw.parse().expect("valid store path parses via trait");
        assert_eq!(
            path.to_string(),
            raw,
            "Display must re-emit the trimmed input verbatim"
        );
        let reparsed: StorePath = path
            .to_string()
            .parse()
            .expect("Display output must round-trip through FromStr");
        assert_eq!(reparsed, path, "the round-trip must preserve identity");
    }

    /// The trait peer must also honor the trailing-newline trim that the
    /// inherent constructor applies to nix-build stdout (which carries a
    /// stray `\n`). Pins that a generic `T: FromStr` consumer reading
    /// nix-build stdout through the trait surface does not need to trim
    /// upstream — the grammar owns the trim in one place.
    #[test]
    fn test_fromstr_trims_trailing_newline_like_parse() {
        let raw = format!("/nix/store/{H}-x\n");
        let path: StorePath = raw.parse().expect("trailing newline must be trimmed");
        assert_eq!(path.as_str(), format!("/nix/store/{H}-x"));
    }

    /// [`TryFrom<&str>`] must accept every input the inherent
    /// [`StorePath::parse`] accepts and produce a value equal to the
    /// [`FromStr`] round-trip. Pins the delegation through the FromStr
    /// oracle: a future refactor that severed the trait impl from
    /// `<Self as FromStr>::from_str` (e.g., re-inlining `Self::parse`
    /// with a stale grammar clause) would drift the by-reference
    /// try-conversion surface away from the shared oracle; this test
    /// fails first.
    #[test]
    fn test_try_from_str_success_agrees_with_fromstr() {
        let raw = format!("/nix/store/{H}-hello-2.10");
        let via_try_from = <StorePath as TryFrom<&str>>::try_from(raw.as_str())
            .expect("valid store path parses via TryFrom<&str>");
        let via_fromstr: StorePath = raw.parse().expect("valid store path parses via FromStr");
        assert_eq!(
            via_try_from, via_fromstr,
            "TryFrom<&str> must yield the same StorePath value as FromStr"
        );
    }

    /// [`TryFrom<&str>`] must reject every input the inherent
    /// [`StorePath::parse`] rejects, and must surface the SAME typed
    /// [`StorePathError`] variant carrying the SAME offending input.
    /// Pins that no error-widening shim (`anyhow!(...)`,
    /// `Box<dyn Error>`) hides between the try-conversion surface and
    /// the inherent constructor — the typed grammar clause stays
    /// legible at the trait entry point.
    #[test]
    fn test_try_from_str_failure_preserves_typed_error_variant() {
        // `unknown-mysvc.drv` is < 34 chars so it trips TooShort — the
        // load-bearing shape the attestation gate reads when the
        // pipeline synthesises the I/O-error sentinel.
        let bad = "/nix/store/unknown-mysvc.drv";
        let try_from_err = <StorePath as TryFrom<&str>>::try_from(bad)
            .expect_err("malformed store path must fail via TryFrom<&str>");
        let inherent_err =
            StorePath::parse(bad).expect_err("malformed store path must fail inherently");
        assert_eq!(
            try_from_err, inherent_err,
            "TryFrom<&str> must surface the same typed error as the inherent constructor"
        );
        assert!(matches!(try_from_err, StorePathError::TooShort { .. }));
    }

    /// A generic `fn f<T: for<'a> TryFrom<&'a str>>` consumer must
    /// recover a valid [`StorePath`] through the trait bound. This is
    /// the structural witness that `StorePath` is genuinely usable at
    /// `TryFrom<&str>` call sites — the surface that
    /// `#[serde(try_from = "&str")]` and generic try-conversion
    /// bounds key off. If a future change narrowed the bound (e.g.,
    /// scoped the impl to a lifetime shape the generic surface
    /// couldn't hit), this test fails at compile time.
    #[test]
    fn test_try_from_str_generic_consumer_recovers_identity() {
        fn parse_via_try_from<'a, T>(s: &'a str) -> Result<T, T::Error>
        where
            T: TryFrom<&'a str>,
        {
            T::try_from(s)
        }
        let raw = format!("/nix/store/{H}-foo-bar-1.2.3");
        let path: StorePath =
            parse_via_try_from(&raw).expect("valid store path parses via generic TryFrom bound");
        assert_eq!(path.name(), "foo-bar-1.2.3");
        assert_eq!(path.hash(), H);
        // And the trimming discipline reaches through the generic bound
        // too — a caller does not need to trim upstream.
        let raw_nl = format!("/nix/store/{H}-x\n");
        let trimmed: StorePath = parse_via_try_from(&raw_nl)
            .expect("trailing newline must be trimmed at TryFrom surface");
        assert_eq!(trimmed.as_str(), format!("/nix/store/{H}-x"));
    }

    /// [`TryFrom<String>`] must accept every input the inherent
    /// [`StorePath::parse`] accepts and produce a value equal to the
    /// [`FromStr`] round-trip on the borrowed view of the same buffer.
    /// Pins the delegation through the FromStr oracle: a future refactor
    /// that severed the trait impl from `<Self as FromStr>::from_str`
    /// (e.g., inlined a `Self::parse` call with a stale grammar clause,
    /// or added a spurious `.clone()` that let the two surfaces drift on
    /// whitespace handling) would fail here first.
    #[test]
    fn test_try_from_string_success_agrees_with_fromstr() {
        let raw = format!("/nix/store/{H}-hello-2.10");
        let via_try_from = <StorePath as TryFrom<String>>::try_from(raw.clone())
            .expect("valid store path parses via TryFrom<String>");
        let via_fromstr: StorePath = raw.parse().expect("valid store path parses via FromStr");
        assert_eq!(
            via_try_from, via_fromstr,
            "TryFrom<String> must yield the same StorePath value as FromStr"
        );
        // And a name-with-hyphens case — the load-bearing shape most real
        // store outputs carry — to guard against a future refactor that
        // clones the input on the way in and truncates at the first `-`.
        let raw2 = format!("/nix/store/{H}-foo-bar-1.2.3");
        let via_try_from2 = <StorePath as TryFrom<String>>::try_from(raw2.clone())
            .expect("hyphenated-name store path parses via TryFrom<String>");
        let via_fromstr2: StorePath = raw2
            .parse()
            .expect("hyphenated-name store path parses via FromStr");
        assert_eq!(via_try_from2, via_fromstr2);
        assert_eq!(via_try_from2.name(), "foo-bar-1.2.3");
    }

    /// [`TryFrom<String>`] must reject every input the inherent
    /// [`StorePath::parse`] rejects, and must surface the SAME typed
    /// [`StorePathError`] variant carrying the SAME offending input.
    /// Pins that no error-widening shim (`anyhow!(...)`,
    /// `Box<dyn Error>`) hides between the by-value try-conversion
    /// surface and the inherent constructor — the typed grammar clause
    /// stays legible at the trait entry point even when the caller owns
    /// the input buffer.
    #[test]
    fn test_try_from_string_failure_preserves_typed_error_variant() {
        // Cover every grammar clause once, and cross-check byte-for-byte
        // that the by-value try-conversion surface surfaces the SAME
        // typed error variant (with the SAME offending input in each
        // variant) as the inherent constructor. Pin against a future
        // refactor that silently coerced one variant into another or
        // widened the error to `anyhow::Error`.
        type ExpectVariant = fn(&StorePathError) -> bool;
        let cases: &[(&str, ExpectVariant)] = &[
            ("", |e| {
                matches!(e, StorePathError::MissingStorePrefix { .. })
            }),
            ("nix/store/abc-x", |e| {
                matches!(e, StorePathError::MissingStorePrefix { .. })
            }),
            ("/nix/store/unknown-mysvc.drv", |e| {
                matches!(e, StorePathError::TooShort { .. })
            }),
            ("/nix/store/eeeeoooouuuutttteeeeoooouuuutttt-x", |e| {
                matches!(e, StorePathError::InvalidHash { .. })
            }),
            ("/nix/store/0123456789abcdfghijklmnpqrsvwxyzx", |e| {
                matches!(e, StorePathError::MissingSeparator { .. })
            }),
            ("/nix/store/0123456789abcdfghijklmnpqrsvwxyz-", |e| {
                matches!(e, StorePathError::EmptyName { .. })
            }),
        ];
        for (bad, is_expected_variant) in cases {
            let try_from_err = <StorePath as TryFrom<String>>::try_from((*bad).to_string())
                .expect_err("malformed store path must fail via TryFrom<String>");
            let inherent_err =
                StorePath::parse(bad).expect_err("malformed store path must fail inherently");
            assert_eq!(
                try_from_err, inherent_err,
                "TryFrom<String> must surface the same typed error as the inherent constructor for {bad:?}"
            );
            assert!(
                is_expected_variant(&try_from_err),
                "unexpected error variant for {bad:?}: {try_from_err:?}"
            );
        }
    }

    /// A generic `fn f<T: TryFrom<String>>` consumer must recover a valid
    /// [`StorePath`] through the trait bound. This is the structural
    /// witness that `StorePath` is genuinely usable at
    /// `TryFrom<String>` call sites — the surface that
    /// `#[serde(try_from = "String")]` and generic by-value try-conversion
    /// bounds key off. If a future change narrowed the bound (e.g.,
    /// gated the impl on a lifetime or trait shape the generic surface
    /// couldn't hit), this test fails at compile time.
    #[test]
    fn test_try_from_string_generic_consumer_recovers_identity() {
        fn parse_via_try_from<T>(s: String) -> Result<T, T::Error>
        where
            T: TryFrom<String>,
        {
            T::try_from(s)
        }
        let raw = format!("/nix/store/{H}-foo-bar-1.2.3");
        let path: StorePath = parse_via_try_from(raw.clone())
            .expect("valid store path parses via generic TryFrom<String> bound");
        assert_eq!(path.name(), "foo-bar-1.2.3");
        assert_eq!(path.hash(), H);
        // The trimming discipline reaches through the generic bound too:
        // a caller that owns a nix-build-stdout String does not need to
        // pre-trim before handing it to the generic try-conversion
        // helper — the grammar owns the trim in one place.
        let raw_nl = format!("/nix/store/{H}-x\n");
        let trimmed: StorePath = parse_via_try_from(raw_nl)
            .expect("trailing newline must be trimmed at TryFrom<String> surface");
        assert_eq!(trimmed.as_str(), format!("/nix/store/{H}-x"));
    }

    /// [`TryFrom<Cow<'_, str>>`] must accept every input the inherent
    /// [`StorePath::parse`] accepts on BOTH the [`Cow::Borrowed`] and
    /// [`Cow::Owned`] arms and produce a value equal to the [`FromStr`]
    /// round-trip on the borrowed view of the same buffer. Pins the
    /// delegate-through-[`FromStr`] discipline at the borrowed-or-owned
    /// frontier try-conversion peer: a regression that drifted the impl
    /// body (e.g., pattern-matched the [`Cow`] arms and routed them through
    /// divergent oracles, cloned the [`Cow::Owned`] payload into a fresh
    /// [`String`] and re-parsed through a stale grammar clause, admitted an
    /// empty label on the [`Cow::Borrowed`] arm through a short-circuit)
    /// fails here rather than at every downstream `TryFrom<Cow<'_, str>>`
    /// call site.
    #[test]
    fn test_try_from_cow_str_success_agrees_with_fromstr() {
        use std::borrow::Cow;
        let raw = format!("/nix/store/{H}-hello-2.10");
        let via_borrowed =
            <StorePath as TryFrom<Cow<'_, str>>>::try_from(Cow::Borrowed(raw.as_str()))
                .expect("valid store path parses via TryFrom<Cow::Borrowed>");
        let via_owned = <StorePath as TryFrom<Cow<'_, str>>>::try_from(Cow::Owned(raw.clone()))
            .expect("valid store path parses via TryFrom<Cow::Owned>");
        let via_fromstr: StorePath = raw.parse().expect("valid store path parses via FromStr");
        assert_eq!(
            via_borrowed, via_fromstr,
            "TryFrom<Cow::Borrowed> must yield the same StorePath value as FromStr"
        );
        assert_eq!(
            via_owned, via_fromstr,
            "TryFrom<Cow::Owned> must yield the same StorePath value as FromStr"
        );
        // And a name-with-hyphens case — the load-bearing shape most real
        // store outputs carry — on both arms, guarding against a future
        // refactor that clones on the way in and truncates at the first `-`.
        let raw2 = format!("/nix/store/{H}-foo-bar-1.2.3");
        let via_borrowed2 =
            <StorePath as TryFrom<Cow<'_, str>>>::try_from(Cow::Borrowed(raw2.as_str()))
                .expect("hyphenated-name store path parses via TryFrom<Cow::Borrowed>");
        let via_owned2 = <StorePath as TryFrom<Cow<'_, str>>>::try_from(Cow::Owned(raw2.clone()))
            .expect("hyphenated-name store path parses via TryFrom<Cow::Owned>");
        assert_eq!(via_borrowed2.name(), "foo-bar-1.2.3");
        assert_eq!(via_owned2.name(), "foo-bar-1.2.3");
        assert_eq!(via_borrowed2, via_owned2);
    }

    /// [`TryFrom<Cow<'_, str>>`] must reject every input the inherent
    /// [`StorePath::parse`] rejects on BOTH arms, and must surface the SAME
    /// typed [`StorePathError`] variant carrying the SAME offending input
    /// through both the [`Cow::Borrowed`] and [`Cow::Owned`] arm. Pins that
    /// no error-widening shim (`anyhow!(...)`, `Box<dyn Error>`) hides
    /// between the borrowed-or-owned try-conversion surface and the inherent
    /// constructor — the typed grammar clause stays legible at the trait
    /// entry point on either arm.
    #[test]
    fn test_try_from_cow_str_failure_preserves_typed_error_variant() {
        use std::borrow::Cow;
        // Cover every grammar clause once, and cross-check byte-for-byte
        // that the borrowed-or-owned try-conversion surface surfaces the
        // SAME typed error variant (with the SAME offending input in each
        // variant) as the inherent constructor on BOTH arms. Pin against a
        // future refactor that silently coerced one variant into another,
        // widened the error to `anyhow::Error`, or let the two arms drift.
        type ExpectVariant = fn(&StorePathError) -> bool;
        let cases: &[(&str, ExpectVariant)] = &[
            ("", |e| {
                matches!(e, StorePathError::MissingStorePrefix { .. })
            }),
            ("nix/store/abc-x", |e| {
                matches!(e, StorePathError::MissingStorePrefix { .. })
            }),
            ("/nix/store/unknown-mysvc.drv", |e| {
                matches!(e, StorePathError::TooShort { .. })
            }),
            ("/nix/store/eeeeoooouuuutttteeeeoooouuuutttt-x", |e| {
                matches!(e, StorePathError::InvalidHash { .. })
            }),
            ("/nix/store/0123456789abcdfghijklmnpqrsvwxyzx", |e| {
                matches!(e, StorePathError::MissingSeparator { .. })
            }),
            ("/nix/store/0123456789abcdfghijklmnpqrsvwxyz-", |e| {
                matches!(e, StorePathError::EmptyName { .. })
            }),
        ];
        for (bad, is_expected_variant) in cases {
            let via_borrowed_err =
                <StorePath as TryFrom<Cow<'_, str>>>::try_from(Cow::Borrowed(*bad))
                    .expect_err("malformed store path must fail via TryFrom<Cow::Borrowed>");
            let via_owned_err =
                <StorePath as TryFrom<Cow<'_, str>>>::try_from(Cow::Owned((*bad).to_string()))
                    .expect_err("malformed store path must fail via TryFrom<Cow::Owned>");
            let inherent_err =
                StorePath::parse(bad).expect_err("malformed store path must fail inherently");
            assert_eq!(
                via_borrowed_err, inherent_err,
                "TryFrom<Cow::Borrowed> must surface the same typed error as the inherent constructor for {bad:?}"
            );
            assert_eq!(
                via_owned_err, inherent_err,
                "TryFrom<Cow::Owned> must surface the same typed error as the inherent constructor for {bad:?}"
            );
            assert!(
                is_expected_variant(&via_borrowed_err),
                "unexpected error variant for {bad:?} on Cow::Borrowed arm: {via_borrowed_err:?}"
            );
            assert!(
                is_expected_variant(&via_owned_err),
                "unexpected error variant for {bad:?} on Cow::Owned arm: {via_owned_err:?}"
            );
        }
    }

    /// A generic `fn f<'a, T: TryFrom<Cow<'a, str>>>` consumer must recover
    /// a valid [`StorePath`] through the trait bound on BOTH the
    /// [`Cow::Borrowed`] and [`Cow::Owned`] arm. This is the structural
    /// witness that `StorePath` is genuinely usable at
    /// `TryFrom<Cow<'_, str>>` call sites — the surface that
    /// `#[serde(try_from = "Cow<'_, str>")]` and generic borrowed-or-owned
    /// try-conversion bounds key off. If a future change narrowed the bound
    /// (e.g., bound the [`Cow`] lifetime to `'static` and rejected borrowed
    /// non-static payloads, gated the impl on a lifetime or trait shape the
    /// generic surface couldn't hit), this test fails at compile time.
    #[test]
    fn test_try_from_cow_str_generic_consumer_recovers_identity() {
        use std::borrow::Cow;
        fn parse_via_try_from<'a, T>(s: Cow<'a, str>) -> Result<T, T::Error>
        where
            T: TryFrom<Cow<'a, str>>,
        {
            T::try_from(s)
        }
        let raw = format!("/nix/store/{H}-foo-bar-1.2.3");
        let via_borrowed: StorePath = parse_via_try_from(Cow::Borrowed(raw.as_str()))
            .expect("valid store path parses via generic TryFrom<Cow::Borrowed> bound");
        assert_eq!(via_borrowed.name(), "foo-bar-1.2.3");
        assert_eq!(via_borrowed.hash(), H);
        let via_owned: StorePath = parse_via_try_from(Cow::Owned(raw.clone()))
            .expect("valid store path parses via generic TryFrom<Cow::Owned> bound");
        assert_eq!(via_owned.name(), "foo-bar-1.2.3");
        assert_eq!(via_owned.hash(), H);
        // The trimming discipline reaches through the generic bound on
        // both arms too: a caller that holds a nix-build-stdout Cow does
        // not need to pre-trim before handing it to the generic
        // try-conversion helper — the grammar owns the trim in one place.
        let raw_nl = format!("/nix/store/{H}-x\n");
        let trimmed_borrowed: StorePath = parse_via_try_from(Cow::Borrowed(raw_nl.as_str()))
            .expect("trailing newline must be trimmed at TryFrom<Cow::Borrowed> surface");
        let trimmed_owned: StorePath = parse_via_try_from(Cow::Owned(raw_nl.clone()))
            .expect("trailing newline must be trimmed at TryFrom<Cow::Owned> surface");
        assert_eq!(trimmed_borrowed.as_str(), format!("/nix/store/{H}-x"));
        assert_eq!(trimmed_owned.as_str(), format!("/nix/store/{H}-x"));
    }

    /// [`TryFrom<Box<str>>`] must accept every input the inherent
    /// [`StorePath::parse`] accepts and produce a value equal to the
    /// [`FromStr`] round-trip on the borrowed view of the same buffer.
    /// Pins the delegation through the [`TryFrom<String>`] peer (which
    /// itself routes through the [`FromStr`] oracle): a future refactor
    /// that severed the trait impl from
    /// `<Self as TryFrom<String>>::try_from(String::from(boxed))` (e.g.,
    /// inlined a `Self::parse` call with a stale grammar clause, or
    /// dropped through a shim that cloned the boxed buffer into a fresh
    /// `String` and let the two surfaces drift on whitespace handling)
    /// would fail here first.
    #[test]
    fn test_try_from_box_str_success_agrees_with_fromstr() {
        let raw = format!("/nix/store/{H}-hello-2.10");
        let via_try_from = <StorePath as TryFrom<Box<str>>>::try_from(raw.clone().into_boxed_str())
            .expect("valid store path parses via TryFrom<Box<str>>");
        let via_fromstr: StorePath = raw.parse().expect("valid store path parses via FromStr");
        assert_eq!(
            via_try_from, via_fromstr,
            "TryFrom<Box<str>> must yield the same StorePath value as FromStr"
        );
        // And a name-with-hyphens case — the load-bearing shape most real
        // store outputs carry — to guard against a future refactor that
        // truncates at the first `-` on the way through the boxed peer.
        let raw2 = format!("/nix/store/{H}-foo-bar-1.2.3");
        let via_try_from2 =
            <StorePath as TryFrom<Box<str>>>::try_from(raw2.clone().into_boxed_str())
                .expect("hyphenated-name store path parses via TryFrom<Box<str>>");
        let via_fromstr2: StorePath = raw2
            .parse()
            .expect("hyphenated-name store path parses via FromStr");
        assert_eq!(via_try_from2, via_fromstr2);
        assert_eq!(via_try_from2.name(), "foo-bar-1.2.3");
    }

    /// [`TryFrom<Box<str>>`] must reject every input the inherent
    /// [`StorePath::parse`] rejects, and must surface the SAME typed
    /// [`StorePathError`] variant carrying the SAME offending input.
    /// Pins that no error-widening shim (`anyhow!(...)`,
    /// `Box<dyn Error>`) hides between the shrunk-owned try-conversion
    /// surface and the inherent constructor — the typed grammar clause
    /// stays legible at the trait entry point even when the caller owns
    /// a boxed UTF-8 buffer.
    #[test]
    fn test_try_from_box_str_failure_preserves_typed_error_variant() {
        // Cover every grammar clause once, and cross-check byte-for-byte
        // that the shrunk-owned try-conversion surface surfaces the SAME
        // typed error variant (with the SAME offending input in each
        // variant) as the inherent constructor. Pin against a future
        // refactor that silently coerced one variant into another or
        // widened the error to `anyhow::Error`.
        type ExpectVariant = fn(&StorePathError) -> bool;
        let cases: &[(&str, ExpectVariant)] = &[
            ("", |e| {
                matches!(e, StorePathError::MissingStorePrefix { .. })
            }),
            ("nix/store/abc-x", |e| {
                matches!(e, StorePathError::MissingStorePrefix { .. })
            }),
            ("/nix/store/unknown-mysvc.drv", |e| {
                matches!(e, StorePathError::TooShort { .. })
            }),
            ("/nix/store/eeeeoooouuuutttteeeeoooouuuutttt-x", |e| {
                matches!(e, StorePathError::InvalidHash { .. })
            }),
            ("/nix/store/0123456789abcdfghijklmnpqrsvwxyzx", |e| {
                matches!(e, StorePathError::MissingSeparator { .. })
            }),
            ("/nix/store/0123456789abcdfghijklmnpqrsvwxyz-", |e| {
                matches!(e, StorePathError::EmptyName { .. })
            }),
        ];
        for (bad, is_expected_variant) in cases {
            let try_from_err =
                <StorePath as TryFrom<Box<str>>>::try_from((*bad).to_string().into_boxed_str())
                    .expect_err("malformed store path must fail via TryFrom<Box<str>>");
            let inherent_err =
                StorePath::parse(bad).expect_err("malformed store path must fail inherently");
            assert_eq!(
                try_from_err, inherent_err,
                "TryFrom<Box<str>> must surface the same typed error as the inherent constructor for {bad:?}"
            );
            assert!(
                is_expected_variant(&try_from_err),
                "unexpected error variant for {bad:?}: {try_from_err:?}"
            );
        }
    }

    /// A generic `fn f<T: TryFrom<Box<str>>>` consumer must recover a
    /// valid [`StorePath`] through the trait bound. This is the
    /// structural witness that `StorePath` is genuinely usable at
    /// `TryFrom<Box<str>>` call sites — the surface that
    /// `#[serde(try_from = "Box<str>")]` and generic shrunk-owned
    /// try-conversion bounds key off. If a future change narrowed the
    /// bound (e.g., gated the impl on a lifetime or trait shape the
    /// generic surface couldn't hit), this test fails at compile time.
    #[test]
    fn test_try_from_box_str_generic_consumer_recovers_identity() {
        fn parse_via_try_from<T>(s: Box<str>) -> Result<T, T::Error>
        where
            T: TryFrom<Box<str>>,
        {
            T::try_from(s)
        }
        let raw = format!("/nix/store/{H}-foo-bar-1.2.3");
        let path: StorePath = parse_via_try_from(raw.clone().into_boxed_str())
            .expect("valid store path parses via generic TryFrom<Box<str>> bound");
        assert_eq!(path.name(), "foo-bar-1.2.3");
        assert_eq!(path.hash(), H);
        // The trimming discipline reaches through the generic bound too:
        // a caller that owns a nix-build-stdout Box<str> does not need
        // to pre-trim before handing it to the generic try-conversion
        // helper — the grammar owns the trim in one place.
        let raw_nl = format!("/nix/store/{H}-x\n");
        let trimmed: StorePath = parse_via_try_from(raw_nl.into_boxed_str())
            .expect("trailing newline must be trimmed at TryFrom<Box<str>> surface");
        assert_eq!(trimmed.as_str(), format!("/nix/store/{H}-x"));
    }

    #[test]
    fn test_canonical_closure_fingerprint_empty_for_unparseable() {
        assert_eq!(canonical_closure_fingerprint(""), "");
        assert_eq!(canonical_closure_fingerprint("not json at all"), "");
        // Valid JSON, but no entry is a well-formed store path.
        assert_eq!(
            canonical_closure_fingerprint(r#"[{"path":"/nix/store/short"}]"#),
            ""
        );
    }
}
