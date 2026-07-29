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
    /// The input byte sequence was not valid UTF-8, so the store-path
    /// grammar oracle ([`StorePath::parse`]) could not be reached. Fires at
    /// the byte-slice parse frontier ([`TryFrom<&[u8]> for StorePath`])
    /// before any grammar clause is evaluated. Carries the offending byte
    /// buffer and the [`std::str::Utf8Error`] the decode gate produced so a
    /// caller can attach both to a Phase 1 attestation / telemetry record
    /// (THEORY §V.4) without re-decoding to recover the invalid-sequence
    /// offset. Distinct from the six grammar-clause variants above —
    /// UTF-8 rejection precedes every clause the grammar names, so a
    /// caller pattern-matching on the rejection site can discriminate
    /// "bytes were not text" from "bytes decoded but the text was not a
    /// store path".
    NonUtf8Bytes {
        bytes: Vec<u8>,
        source: std::str::Utf8Error,
    },
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
            StorePathError::NonUtf8Bytes { bytes, source } => write!(
                f,
                "store path bytes '{}' (lossy-decoded) are not valid UTF-8: {source}",
                String::from_utf8_lossy(bytes)
            ),
        }
    }
}

impl std::error::Error for StorePathError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StorePathError::NonUtf8Bytes { source, .. } => Some(source),
            _ => None,
        }
    }
}

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

/// Cross-thread shared-owned UTF-8 try-conversion peer for
/// [`StorePath::parse`] via the [`TryFrom<Arc<str>>`] trait — the atomically
/// refcounted shared-buffer frontier that pairs with the [`TryFrom<Box<str>>`]
/// shrunk-owned peer under a receiver shape whose payload is safe to hand
/// across thread boundaries through [`std::sync::Arc::clone`] rather than
/// buffer-cloned.
///
/// Delegates through `<Self as std::str::FromStr>::from_str` on the borrowed
/// [`str`] view of the caller-supplied [`Arc<str>`] (via
/// [`<std::sync::Arc<str> as AsRef<str>>::as_ref`], a zero-copy borrow of
/// the shared allocation's UTF-8 backing bytes that does NOT touch the
/// atomic refcount header), so the store-path grammar stays defined at ONE
/// construction surface — the [`std::str::FromStr`] peer, which itself
/// delegates to [`StorePath::parse`]. No refcount bump, no buffer clone,
/// no divergent grammar: the impl body pays the by-reference [`FromStr`]
/// cost at zero allocation on the incoming shared handle.
///
/// # Why the trait peer earns its keep
///
/// [`TryFrom<Box<str>>`] covers the shrunk-owned frontier
/// (`#[serde(try_from = "Box<str>")]`, `fn f<T: TryFrom<Box<str>>>`).
/// [`TryFrom<Arc<str>>`] covers the disjoint cross-thread shared-owned
/// frontier stdlib and the wider ecosystem key off separately:
///
/// - `#[serde(try_from = "Arc<str>")]` — the serde container attribute for
///   the shared-owned case (a deserializer that hands out atomically
///   refcounted UTF-8 label buffers so peers hold cheap-clone shared
///   ownership rather than each allocating a copy) keys off
///   [`TryFrom<Arc<str>>`], not [`TryFrom<Box<str>>`], [`TryFrom<String>`],
///   [`TryFrom<&str>`], or [`FromStr`]. A future serde field wrapping a
///   `StorePath` and opting into the cross-thread shared-owned `try_from`
///   grammar reaches the store-path check through this impl without a shim.
/// - Generic try-conversion bounds (`fn parse_field<T: TryFrom<Arc<str>>>`)
///   — a validated-input newtype builder or closure-doc-column reader whose
///   parse contract is stated at the cross-thread shared-owned receiver
///   layer (an atomically refcounted UTF-8 label handed cheaply across
///   worker threads through [`std::sync::Arc::clone`] rather than
///   buffer-cloned per consumer) can name `StorePath` alongside every other
///   cross-thread shared-owned try-conversion primitive without routing
///   through a shim.
/// - A `HashMap<Arc<str>, StorePath>` intern table — a closure-scan or
///   attic-push staging pool that keys a validated store path off its
///   raw-input label buffer and hands the same buffer to sibling readers
///   through [`std::sync::Arc::clone`] — can populate its entries by
///   `try_from`-ing the raw buffer directly through this impl without a
///   `parse::<StorePath>(&*arc)` shim.
/// - Sibling canonical-string typed primitives in this crate already
///   carry the pair: `impl TryFrom<Arc<str>> for DigestAlgorithm` at
///   `oci_manifest.rs::1380`; `StorePath` is the store-path primitive
///   counterpart at the same cross-thread shared-owned try-conversion
///   frontier.
///
/// # Error shape
///
/// `Self::Error = StorePathError`. The typed grammar-clause enum
/// (`MissingStorePrefix` / `HasSubpath` / `TooShort` / `InvalidHash` /
/// `MissingSeparator` / `EmptyName`) carries through from [`FromStr`] —
/// no widening to [`anyhow::Error`] or `Box<dyn Error>` hides between the
/// cross-thread shared-owned try-conversion surface and the inherent
/// constructor, so a caller can still `match` on the exact clause the
/// input violated at the trait entry point.
impl TryFrom<std::sync::Arc<str>> for StorePath {
    type Error = StorePathError;

    fn try_from(shared: std::sync::Arc<str>) -> Result<Self, Self::Error> {
        <Self as std::str::FromStr>::from_str(shared.as_ref())
    }
}

/// Thread-local shared-owned UTF-8 try-conversion peer for
/// [`StorePath::parse`] via the [`TryFrom<Rc<str>>`] trait — the
/// non-atomically refcounted shared-buffer frontier that pairs with the
/// [`TryFrom<Arc<str>>`] cross-thread shared-owned peer directly above
/// under a receiver shape whose payload is cheap-cloned within a single
/// thread through [`std::rc::Rc::clone`] rather than the atomically
/// refcounted [`std::sync::Arc::clone`] used across worker threads.
///
/// Delegates through `<Self as std::str::FromStr>::from_str` on the borrowed
/// [`str`] view of the caller-supplied [`Rc<str>`] (via
/// [`<std::rc::Rc<str> as AsRef<str>>::as_ref`], a zero-copy borrow of
/// the shared allocation's UTF-8 backing bytes that does NOT touch the
/// non-atomic refcount header), so the store-path grammar stays defined at
/// ONE construction surface — the [`std::str::FromStr`] peer, which itself
/// delegates to [`StorePath::parse`]. No refcount bump, no buffer clone,
/// no divergent grammar: the impl body pays the by-reference [`FromStr`]
/// cost at zero allocation on the incoming thread-local shared handle.
///
/// # Why the trait peer earns its keep
///
/// [`TryFrom<Arc<str>>`] covers the cross-thread shared-owned frontier
/// (`#[serde(try_from = "Arc<str>")]`, `fn f<T: TryFrom<Arc<str>>>`).
/// [`TryFrom<Rc<str>>`] covers the disjoint thread-local shared-owned
/// frontier stdlib and the wider ecosystem key off separately:
///
/// - `#[serde(try_from = "Rc<str>")]` — the serde container attribute for
///   the thread-local shared-owned case (a deserializer that hands out
///   non-atomically refcounted UTF-8 label buffers so peers inside a
///   single-thread graph hold cheap-clone shared ownership without paying
///   the atomic-refcount cost of [`std::sync::Arc`]) keys off
///   [`TryFrom<Rc<str>>`], not [`TryFrom<Arc<str>>`], [`TryFrom<Box<str>>`],
///   [`TryFrom<String>`], [`TryFrom<&str>`], or [`FromStr`]. A future
///   serde field wrapping a `StorePath` and opting into the thread-local
///   shared-owned `try_from` grammar reaches the store-path check through
///   this impl without a shim.
/// - Generic try-conversion bounds (`fn parse_field<T: TryFrom<Rc<str>>>`)
///   — a validated-input newtype builder or closure-doc-column reader whose
///   parse contract is stated at the thread-local shared-owned receiver
///   layer (a non-atomically refcounted UTF-8 label handed cheaply among
///   sibling readers on a single thread through [`std::rc::Rc::clone`]
///   rather than [`std::sync::Arc::clone`]) can name `StorePath` alongside
///   every other thread-local shared-owned try-conversion primitive
///   without routing through a shim.
/// - A `HashMap<Rc<str>, StorePath>` single-thread intern table — a
///   closure-scan or attic-push staging pool that keys a validated store
///   path off its raw-input label buffer and hands the same buffer to
///   sibling readers on the same thread through [`std::rc::Rc::clone`] —
///   can populate its entries by `try_from`-ing the raw buffer directly
///   through this impl without a `parse::<StorePath>(&*rc)` shim, and
///   sheds the atomic-refcount cost the [`std::sync::Arc`] peer would pay.
/// - Sibling canonical-string typed primitives in this crate already
///   carry the pair: `impl TryFrom<Rc<str>> for DigestAlgorithm` at
///   `oci_manifest.rs::1519`; `StorePath` is the store-path primitive
///   counterpart at the same thread-local shared-owned try-conversion
///   frontier.
///
/// # Error shape
///
/// `Self::Error = StorePathError`. The typed grammar-clause enum
/// (`MissingStorePrefix` / `HasSubpath` / `TooShort` / `InvalidHash` /
/// `MissingSeparator` / `EmptyName`) carries through from [`FromStr`] —
/// no widening to [`anyhow::Error`] or `Box<dyn Error>` hides between the
/// thread-local shared-owned try-conversion surface and the inherent
/// constructor, so a caller can still `match` on the exact clause the
/// input violated at the trait entry point.
impl TryFrom<std::rc::Rc<str>> for StorePath {
    type Error = StorePathError;

    fn try_from(shared: std::rc::Rc<str>) -> Result<Self, Self::Error> {
        <Self as std::str::FromStr>::from_str(shared.as_ref())
    }
}

/// By-reference byte-slice try-conversion peer for [`StorePath::parse`] via
/// the [`TryFrom<&[u8]>`] trait — the byte-slice frontier that pairs with
/// the six UTF-8 try-conversion peers directly above under a receiver shape
/// whose input has not yet crossed the UTF-8 validation gate.
///
/// Delegates through [`std::str::from_utf8`] then
/// `<Self as std::str::FromStr>::from_str` on the borrowed [`str`] view of
/// the caller-supplied [`&[u8]`], so the store-path grammar stays defined at
/// ONE construction surface — the [`std::str::FromStr`] peer, which itself
/// delegates to [`StorePath::parse`]. A grammar clause added to `parse`
/// lights up at this frontier without a second edit; the UTF-8 decode gate
/// is the one place non-textual input is rejected before the grammar oracle
/// is consulted.
///
/// # Why the trait peer earns its keep
///
/// The six UTF-8 try-conversion peers directly above
/// ([`TryFrom<&str>`], [`TryFrom<String>`], [`TryFrom<Cow<'_, str>>`],
/// [`TryFrom<Box<str>>`], [`TryFrom<Arc<str>>`], [`TryFrom<Rc<str>>`])
/// close the parse frontier at every UTF-8-side receiver shape. This peer
/// closes the disjoint byte-slice frontier stdlib and the wider ecosystem
/// key off separately:
///
/// - [`std::process::Command::output`] hands the parent
///   [`std::process::Output::stdout`] as a [`Vec<u8>`] — the raw
///   nix-frontier surface where forge captures a candidate store path from
///   a spawned child. Every one of the six UTF-8 try-conversion peers above
///   requires the caller to run
///   `std::str::from_utf8(&output.stdout)?.trim().parse::<StorePath>()`
///   (or the four-step [`String::from_utf8_lossy`] variant that silently
///   substitutes replacement characters into a candidate that would then
///   fail the grammar for the wrong reason) at every capture site. This
///   peer routes the same call as
///   `StorePath::try_from(output.stdout.as_slice())` — one composition,
///   both gates carried, the UTF-8 decode failure typed as its own arm.
/// - `#[serde(try_from = "&[u8]")]` — the serde container attribute for
///   the by-reference byte-slice case (a deserializer that borrows a
///   [`&[u8]`] straight off the wire — a bincode / CBOR / MessagePack
///   payload, a rkyv archive, a `serde_bytes` field on a borrowed
///   container) keys off [`TryFrom<&[u8]>`], not [`TryFrom<&str>`],
///   [`TryFrom<String>`], or [`FromStr`]. A future serde field wrapping a
///   `StorePath` and opting into the byte-slice `try_from` grammar
///   reaches the store-path check through this impl without a shim.
/// - Generic try-conversion bounds
///   (`fn parse_bytes_field<T: for<'a> TryFrom<&'a [u8]>>`) — a
///   validated-input newtype builder or attestation-column reader whose
///   parse contract is stated at the byte-slice receiver layer can name
///   [`StorePath`] alongside every other by-reference byte-slice
///   try-conversion primitive without routing through a UTF-8-first shim.
/// - Sibling canonical-label typed sums in this crate already carry the
///   peer: `impl TryFrom<&[u8]> for BumpLevel` at `version.rs:7404`,
///   `impl TryFrom<&[u8]> for PerAttemptRegion` at `retry.rs:3353`,
///   `impl TryFrom<&[u8]> for AdmissionTier` at `probe_outcome.rs:6720`,
///   `impl TryFrom<&[u8]> for DigestAlgorithm` at `oci_manifest.rs:1060`;
///   the byte-slice parse frontier is a four-fold pattern past the
///   three-times-rule threshold (THEORY §VI.1) and [`StorePath`] is the
///   store-path primitive counterpart at the same try-conversion frontier.
///
/// # Two-stage strictness
///
/// The parser is strict at two frontiers, in order:
///
/// 1. Non-UTF-8 byte sequences reject at [`std::str::from_utf8`] with the
///    new typed [`StorePathError::NonUtf8Bytes`] variant, which preserves
///    both the offending byte buffer and the underlying
///    [`std::str::Utf8Error`] under [`std::error::Error::source`]. A
///    caller pattern-matching on the rejection site can discriminate
///    "bytes were not text" from "bytes decoded but the text was not a
///    store path" without a string-diff hack.
/// 2. Valid-UTF-8 byte sequences that decode to a non-store-path string
///    reject at the underlying [`FromStr`] impl with the exact
///    grammar-clause variant the input violated
///    (`MissingStorePrefix` / `HasSubpath` / `TooShort` / `InvalidHash` /
///    `MissingSeparator` / `EmptyName`) — the same canonical-only
///    strictness the UTF-8 peers already carry, now lifted to the
///    byte-slice input layer at ONE composition through
///    [`std::str::from_utf8`].
///
/// # Error shape
///
/// `Self::Error = StorePathError`. The typed grammar-clause enum, extended
/// with the new [`StorePathError::NonUtf8Bytes`] variant for the UTF-8
/// decode gate, carries through — no widening to [`anyhow::Error`] or
/// `Box<dyn Error>` hides between the byte-slice try-conversion surface
/// and the inherent constructor, so a caller can still `match` on the
/// exact rejection site at the trait entry point.
impl TryFrom<&[u8]> for StorePath {
    type Error = StorePathError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let s = std::str::from_utf8(bytes).map_err(|source| StorePathError::NonUtf8Bytes {
            bytes: bytes.to_vec(),
            source,
        })?;
        <Self as std::str::FromStr>::from_str(s)
    }
}

/// By-value owned-buffer byte-slice try-conversion peer for
/// [`StorePath::parse`] via the [`TryFrom<Vec<u8>>`] trait — the
/// owned-input counterpart of the [`TryFrom<&[u8]>`] peer directly above,
/// closing the byte-slice parse frontier at the receiver shape whose
/// caller owns the input allocation.
///
/// Routes through [`String::from_utf8`] — which, on successful UTF-8
/// validation, reuses the same allocation as the returned [`String`]'s
/// backing storage (the standard library documents this as an in-place
/// check, no re-allocation) — then delegates to
/// [`<Self as std::str::FromStr>::from_str`] on the resulting owned
/// [`String`]'s [`str::as_str`] view. The store-path grammar stays
/// defined at ONE construction surface — the [`std::str::FromStr`] peer,
/// which itself delegates to [`StorePath::parse`]. A grammar clause
/// added to `parse` lights up at this frontier without a second edit;
/// the UTF-8 decode gate is the one place non-textual input is rejected
/// before the grammar oracle is consulted.
///
/// On the UTF-8-invalid path the owned [`Vec<u8>`] is recovered through
/// [`std::string::FromUtf8Error::into_bytes`] and threaded into the
/// [`StorePathError::NonUtf8Bytes`] variant verbatim alongside the
/// [`std::str::Utf8Error`] the decode gate produced — a Phase 1
/// attestation / telemetry record (THEORY §V.4) receives both the
/// offending byte buffer and the underlying [`std::str::Utf8Error`]
/// under [`std::error::Error::source`] without a re-decoding to recover
/// the invalid-sequence offset, and without an intermediate
/// [`.to_vec()`] clone the by-reference peer's `bytes.to_vec()` would
/// otherwise force on the owned arm.
///
/// # Why the trait peer earns its keep
///
/// The by-reference [`TryFrom<&[u8]>`] peer directly above closes the
/// byte-slice frontier at the borrowed-input receiver shape. This peer
/// closes the disjoint owned-input receiver shape stdlib and the wider
/// ecosystem key off separately:
///
/// - [`std::process::Command::output`] hands the parent
///   [`std::process::Output::stdout`] as a [`Vec<u8>`] by value. Every
///   downstream consumer holding that owned [`Vec<u8>`] can now write
///   `StorePath::try_from(output.stdout)` — one composition, both
///   gates carried, the UTF-8 decode failure typed as its own arm, the
///   owned allocation consumed at intake without the
///   `output.stdout.as_slice()` bridge the by-reference peer would
///   force.
/// - `#[serde(try_from = "Vec<u8>")]` — the serde container attribute
///   for the by-value owned-byte case (a deserializer that owns a
///   [`Vec<u8>`] straight off the wire — a bincode / CBOR /
///   MessagePack payload materialised into an owned buffer, a rkyv
///   archive that hands its owned bytes to the parse gate, a
///   `serde_bytes` field on an owned container) keys off
///   [`TryFrom<Vec<u8>>`], not [`TryFrom<&[u8]>`] or [`FromStr`]. A
///   future serde field wrapping a [`StorePath`] and opting into the
///   owned-byte-slice `try_from` grammar reaches the store-path check
///   through this impl without a shim.
/// - Generic try-conversion bounds (`fn parse_bytes_field<T:
///   TryFrom<Vec<u8>>>`) — a validated-input newtype builder or
///   attestation-column reader whose parse contract is stated at the
///   owned-byte receiver layer (a [`std::io::Read::read_to_end`]
///   pipeline terminus that hands an owned buffer to a typed parser, a
///   `bytes::Bytes::to_vec` round-trip point at the async HTTP-body /
///   registry-response frontier, a `blake3`/`sha2` pre-hashed-input
///   replay verifier that owns the input buffer to feed both the
///   hasher and the canonical parse) can name [`StorePath`] alongside
///   every other by-value byte-slice try-conversion primitive without
///   routing through a by-reference shim.
/// - Sibling canonical-label typed sums in this crate already carry
///   the peer: `impl TryFrom<Vec<u8>>` for [`crate::version::BumpLevel`]
///   at `version.rs:7534`, for [`crate::retry::PerAttemptRegion`], for
///   [`crate::probe_outcome::AdmissionTier`], and for
///   [`DigestAlgorithm`] at `oci_manifest.rs`. The owned-byte-slice
///   parse frontier is a four-fold pattern past the three-times-rule
///   threshold (THEORY §VI.1); [`StorePath`] is the store-path
///   primitive counterpart at the same try-conversion frontier.
///
/// # Two-stage strictness
///
/// The parser is strict at two frontiers, in order:
///
/// 1. Non-UTF-8 byte sequences reject at [`String::from_utf8`] with the
///    typed [`StorePathError::NonUtf8Bytes`] variant carrying the
///    offending buffer recovered through
///    [`std::string::FromUtf8Error::into_bytes`] verbatim (no clone)
///    and the underlying [`std::str::Utf8Error`] under
///    [`std::error::Error::source`]. A caller pattern-matching on the
///    rejection site can discriminate "bytes were not text" from
///    "bytes decoded but the text was not a store path" without a
///    string-diff hack.
/// 2. Valid-UTF-8 byte sequences that decode to a non-store-path string
///    reject at the underlying [`FromStr`] impl with the exact
///    grammar-clause variant the input violated
///    (`MissingStorePrefix` / `HasSubpath` / `TooShort` / `InvalidHash`
///    / `MissingSeparator` / `EmptyName`) — the same canonical-only
///    strictness the UTF-8 peers and the by-reference byte peer above
///    already carry, now lifted to the owned-byte-slice input layer at
///    ONE composition through [`String::from_utf8`].
///
/// # Error shape
///
/// `Self::Error = StorePathError`. The typed grammar-clause enum carries
/// through — no widening to [`anyhow::Error`] or `Box<dyn Error>` hides
/// between the owned-byte-slice try-conversion surface and the inherent
/// constructor, so a caller can still `match` on the exact rejection
/// site at the trait entry point.
impl TryFrom<Vec<u8>> for StorePath {
    type Error = StorePathError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        match String::from_utf8(bytes) {
            Ok(s) => <Self as std::str::FromStr>::from_str(&s),
            Err(err) => {
                let source = err.utf8_error();
                Err(StorePathError::NonUtf8Bytes {
                    bytes: err.into_bytes(),
                    source,
                })
            }
        }
    }
}

/// Shrunk-owned byte-slice try-conversion peer for [`StorePath::parse`]
/// via the [`TryFrom<Box<[u8]>>`] trait — the byte-slice counterpart of
/// the [`TryFrom<Box<str>>`] shrunk-owned UTF-8 peer above, closing the
/// byte-slice parse frontier at the receiver shape whose caller holds a
/// capacity-shrunk owned byte buffer (`Box<[u8]>`: `len == capacity`, no
/// spare `Vec` capacity header) rather than a general-purpose
/// [`Vec<u8>`].
///
/// Delegates through [`Vec::<u8>::from`] on the caller-supplied
/// [`Box<[u8]>`] — which reuses the same allocation as the returned
/// [`Vec<u8>`]'s backing storage without a re-allocation (the standard
/// library documents `Vec::from(Box<[T]>)` as an O(1) header rewrap:
/// `Box<[T]>` is stored `len == capacity`, so the resulting `Vec` binds
/// the same pointer, length, and capacity, and no element is moved) —
/// then routes into `<Self as TryFrom<Vec<u8>>>::try_from`. The
/// store-path grammar stays defined at ONE construction surface — the
/// [`std::str::FromStr`] peer, which itself delegates to
/// [`StorePath::parse`], reached through the [`TryFrom<Vec<u8>>`] impl
/// that also carries the [`String::from_utf8`] two-stage strictness gate.
/// A grammar clause added to `parse` lights up at this frontier without a
/// second edit; the UTF-8 decode gate is the one place non-textual input
/// is rejected before the grammar oracle is consulted.
///
/// # Why the trait peer earns its keep
///
/// The [`TryFrom<&[u8]>`] and [`TryFrom<Vec<u8>>`] peers directly above
/// close the borrowed and by-value general-owned byte-slice frontiers.
/// [`TryFrom<Box<[u8]>>`] covers the disjoint shrunk-owned byte-slice
/// receiver shape stdlib and the wider ecosystem key off separately:
///
/// - `#[serde(try_from = "Box<[u8]>")]` — the serde container attribute
///   for the shrunk-owned byte case (a deserializer that hands out
///   capacity-shrunk owned byte buffers so peers hold the tightest
///   possible owned allocation without paying the [`Vec<u8>`] capacity
///   header) keys off [`TryFrom<Box<[u8]>>`], not [`TryFrom<Vec<u8>>`],
///   [`TryFrom<&[u8]>`], [`TryFrom<Box<str>>`], or [`FromStr`]. A future
///   serde field wrapping a [`StorePath`] and opting into the
///   shrunk-owned byte `try_from` grammar reaches the store-path check
///   through this impl without a shim.
/// - Generic try-conversion bounds (`fn parse_field<T: TryFrom<Box<[u8]>>>`)
///   — a validated-input newtype builder or attestation-column reader
///   whose parse contract is stated at the shrunk-owned byte receiver
///   layer (a `Vec::<u8>::into_boxed_slice` terminus that hands a
///   capacity-shrunk owned buffer to a typed parser, a `bytes::Bytes`
///   round-trip point at the async HTTP-body / registry-response
///   frontier where the caller has already released the [`Vec<u8>`]'s
///   spare capacity) can name [`StorePath`] alongside every other
///   shrunk-owned byte try-conversion primitive without routing through
///   a `Vec::<u8>::from(boxed)` shim.
/// - The sibling shrunk-owned UTF-8 peer directly above at
///   [`TryFrom<Box<str>>`] closes the UTF-8-string counterpart of this
///   receiver shape; this impl is the byte-slice dual on the same
///   shrunk-owned axis, so the byte-slice frontier is now closed at all
///   three of the string family's owned receiver shapes it needs to
///   match ([`&[u8]`] ↔ [`&str`]; [`Vec<u8>`] ↔ [`String`]; [`Box<[u8]>`]
///   ↔ [`Box<str>`]) at the store-path axis.
///
/// # Two-stage strictness
///
/// The parser is strict at two frontiers, in order, exactly as at the
/// [`TryFrom<Vec<u8>>`] peer above (this impl reaches through it):
///
/// 1. Non-UTF-8 byte sequences reject at [`String::from_utf8`] with the
///    typed [`StorePathError::NonUtf8Bytes`] variant carrying the
///    offending buffer recovered through
///    [`std::string::FromUtf8Error::into_bytes`] verbatim (no clone),
///    routed through the [`Vec<u8>`] the `Box<[u8]>` unwrapped into
///    without re-allocation.
/// 2. Valid-UTF-8 byte sequences that decode to a non-store-path string
///    reject at the underlying [`FromStr`] impl with the exact
///    grammar-clause variant the input violated
///    (`MissingStorePrefix` / `HasSubpath` / `TooShort` / `InvalidHash`
///    / `MissingSeparator` / `EmptyName`).
///
/// # Error shape
///
/// `Self::Error = StorePathError`. The typed grammar-clause enum carries
/// through — no widening to [`anyhow::Error`] or `Box<dyn Error>` hides
/// between the shrunk-owned byte-slice try-conversion surface and the
/// inherent constructor, so a caller can still `match` on the exact
/// rejection site at the trait entry point.
impl TryFrom<Box<[u8]>> for StorePath {
    type Error = StorePathError;

    fn try_from(boxed: Box<[u8]>) -> Result<Self, Self::Error> {
        <Self as TryFrom<Vec<u8>>>::try_from(Vec::<u8>::from(boxed))
    }
}

/// Borrowed-or-owned byte-slice try-conversion peer for [`StorePath::parse`]
/// via the [`TryFrom<std::borrow::Cow<'_, [u8]>>`] trait — the byte-slice
/// counterpart of the [`TryFrom<Cow<'_, str>>`] UTF-8 peer above, closing
/// the byte-slice parse frontier at the receiver shape whose caller does
/// not know at type-checking time whether the input is a borrowed
/// [`&[u8]`] view or an owned [`Vec<u8>`] buffer.
///
/// Arm-matches to the two sibling byte-slice parse peers this impl reaches
/// through: [`std::borrow::Cow::Borrowed`] routes through
/// [`<Self as TryFrom<&[u8]>>::try_from`], and
/// [`std::borrow::Cow::Owned`] routes through
/// [`<Self as TryFrom<Vec<u8>>>::try_from`]. Both peers already carry the
/// [`std::str::from_utf8`] / [`String::from_utf8`] UTF-8 decode gate and
/// the shared [`StorePath::parse`] grammar oracle, so the store-path
/// grammar stays defined at ONE construction surface — the
/// [`std::str::FromStr`] peer, which itself delegates to
/// [`StorePath::parse`], reached through both arms of the [`Cow`] match.
/// A grammar clause added to `parse` lights up at both arms of this
/// frontier without a second edit; the UTF-8 decode gate is the one
/// place non-textual input is rejected before the grammar oracle is
/// consulted, whether the caller held a borrowed or owned byte buffer.
///
/// The arm-match preserves the caller's ownership discipline on both
/// arms: the borrowed arm delegates through the by-reference peer that
/// owns its `bytes.to_vec()` clone on the UTF-8-invalid path (a caller
/// that only ever holds borrowed bytes never pays for an owned
/// allocation on the happy path); the owned arm delegates through the
/// by-value peer that consumes the caller's owned allocation on the
/// happy path through [`String::from_utf8`] and recovers the offending
/// bytes verbatim through [`std::string::FromUtf8Error::into_bytes`] on
/// the UTF-8-invalid path (a caller that already owns the buffer never
/// pays for a second allocation, and never pays a redundant
/// [`.to_vec()`] clone on the rejection). Neither arm widens the
/// receiver-shape decision the caller already made at the input site.
///
/// # Why the trait peer earns its keep
///
/// The [`TryFrom<&[u8]>`] and [`TryFrom<Vec<u8>>`] peers close the
/// borrowed and owned byte-slice frontiers as disjoint receiver shapes.
/// [`TryFrom<Cow<'_, [u8]>>`] covers the borrowed-or-owned frontier
/// stdlib and the wider ecosystem key off separately:
///
/// - `#[serde(try_from = "Cow<'_, [u8]>")]` — the serde container
///   attribute for the borrowed-or-owned byte case (a `zero-copy`
///   deserializer that hands out a borrowed byte slice on the fast
///   path but has to fall back to an owned buffer when the input crosses
///   a `serde` buffer boundary — a `serde_bytes::ByteBuf` field on a
///   flexible container, a `rmp-serde` / `bincode` /
///   `ciborium` decoder whose owned-vs-borrowed choice depends on the
///   underlying reader's contiguity) keys off
///   [`TryFrom<Cow<'_, [u8]>>`], not [`TryFrom<&[u8]>`] or
///   [`TryFrom<Vec<u8>>`]. A future serde field wrapping a
///   [`StorePath`] and opting into the borrowed-or-owned byte
///   `try_from` grammar reaches the store-path check through this impl
///   without a shim.
/// - Generic try-conversion bounds
///   (`fn parse_field<'a, T: TryFrom<Cow<'a, [u8]>>>`) — a
///   validated-input newtype builder or attestation-column reader whose
///   parse contract is stated at the borrowed-or-owned byte receiver
///   layer (an `http-body` collection point whose owned-vs-borrowed
///   discipline depends on whether the frame arrived contiguous, a
///   `bytes::Bytes` → `Cow<[u8]>` bridge at the async
///   registry-response frontier, a canonical-representation-with-copy
///   normaliser that binds its input as `Cow<[u8]>` so the borrowed
///   fast path stays borrowed) can name [`StorePath`] alongside every
///   other borrowed-or-owned byte try-conversion primitive without
///   routing through a per-variant `.into_owned()` shim.
/// - Sibling canonical-label typed sums in this crate already carry the
///   peer: [`impl TryFrom<Cow<'_, [u8]>>`] for
///   [`crate::oci_manifest::DigestAlgorithm`] at
///   `oci_manifest.rs:1979`; [`StorePath`] is the store-path primitive
///   counterpart at the same borrowed-or-owned byte try-conversion
///   frontier.
///
/// # Two-stage strictness
///
/// The parser is strict at two frontiers, in order, on both arms of the
/// [`Cow`] match (this impl reaches through the arm-matched peers):
///
/// 1. Non-UTF-8 byte sequences reject at the UTF-8 decode gate
///    ([`std::str::from_utf8`] on the borrowed arm,
///    [`String::from_utf8`] on the owned arm) with the typed
///    [`StorePathError::NonUtf8Bytes`] variant carrying the offending
///    buffer verbatim and the underlying [`std::str::Utf8Error`] under
///    [`std::error::Error::source`]. Rejection is byte-identical across
///    the two arms on the same input, so a caller pattern-matching on
///    the rejection site reads the same typed error variant with the
///    same offending-bytes payload whether the input was borrowed or
///    owned.
/// 2. Valid-UTF-8 byte sequences that decode to a non-store-path string
///    reject at the underlying [`FromStr`] impl with the exact
///    grammar-clause variant the input violated
///    (`MissingStorePrefix` / `HasSubpath` / `TooShort` / `InvalidHash`
///    / `MissingSeparator` / `EmptyName`).
///
/// # Error shape
///
/// `Self::Error = StorePathError`. The typed grammar-clause enum carries
/// through — no widening to [`anyhow::Error`] or `Box<dyn Error>` hides
/// between the borrowed-or-owned byte try-conversion surface and the
/// inherent constructor, so a caller can still `match` on the exact
/// rejection site at the trait entry point.
impl TryFrom<std::borrow::Cow<'_, [u8]>> for StorePath {
    type Error = StorePathError;

    fn try_from(bytes: std::borrow::Cow<'_, [u8]>) -> Result<Self, Self::Error> {
        match bytes {
            std::borrow::Cow::Borrowed(slice) => <Self as TryFrom<&[u8]>>::try_from(slice),
            std::borrow::Cow::Owned(owned) => <Self as TryFrom<Vec<u8>>>::try_from(owned),
        }
    }
}

/// Cross-thread shared-owned byte-buffer try-conversion peer for
/// [`StorePath::parse`] via the [`TryFrom<Arc<[u8]>>`] trait — the
/// atomically refcounted shared-buffer frontier that pairs with the
/// [`TryFrom<Arc<str>>`] cross-thread shared-owned UTF-8 peer at the
/// disjoint byte-side receiver layer. Where the UTF-8 sibling assumes the
/// text gate has already fired, this peer takes an atomically refcounted
/// buffer whose UTF-8 status is still open — the exact shape carried by a
/// `bytes::Bytes → Arc<[u8]>` bridge, an rkyv / bincode / MessagePack /
/// CBOR wire frame shared across worker threads, or a `Arc<[u8]>` intern
/// table that hands the same buffer to sibling readers without copying.
///
/// Delegates through `<Self as TryFrom<&[u8]>>::try_from` on the borrowed
/// [`[u8]`] view of the caller-supplied [`Arc<[u8]>`] (via
/// [`<std::sync::Arc<[u8]> as AsRef<[u8]>>::as_ref`], a zero-copy borrow
/// of the shared allocation's bytes that does NOT touch the atomic
/// refcount header), so the store-path grammar and the UTF-8 decode gate
/// stay defined at ONE construction surface — the byte-slice
/// [`TryFrom<&[u8]>`] peer, which itself composes [`std::str::from_utf8`]
/// with the [`FromStr`] oracle. No refcount bump, no buffer clone, no
/// divergent decode gate: the impl body pays the by-reference byte-slice
/// try-conversion cost at zero allocation on the incoming shared handle.
///
/// # Why the trait peer earns its keep
///
/// The four byte-side receiver-shape peers directly above
/// ([`TryFrom<&[u8]>`], [`TryFrom<Vec<u8>>`], [`TryFrom<Box<[u8]>>`],
/// [`TryFrom<Cow<'_, [u8]>>`]) close the parse frontier at every
/// non-shared byte receiver shape. This peer closes the disjoint
/// cross-thread shared-owned byte frontier that stdlib and the wider
/// ecosystem key off separately:
///
/// - `#[serde(try_from = "Arc<[u8]>")]` — the serde container attribute
///   for the cross-thread shared-owned byte case (a deserializer that
///   hands out atomically refcounted byte buffers so peers across worker
///   threads hold cheap-clone shared ownership without copying, and
///   without the borrow-lifetime constraint the [`TryFrom<&[u8]>`] peer
///   imposes) keys off [`TryFrom<Arc<[u8]>>`], not [`TryFrom<Arc<str>>`],
///   [`TryFrom<Box<[u8]>>`], [`TryFrom<Vec<u8>>`], or
///   [`TryFrom<&[u8]>`]. A future serde field wrapping a [`StorePath`]
///   and opting into the cross-thread shared-owned byte `try_from`
///   grammar reaches the store-path check through this impl without a
///   shim.
/// - A `bytes::Bytes` → `Arc<[u8]>` bridge at the async
///   registry-response or Attic-fetch frontier: an `http-body` or
///   `hyper::body::Bytes` frame handed across a worker-thread boundary is
///   commonly re-owned as an [`Arc<[u8]>`] so downstream tasks share the
///   same allocation without copying and without the refcount bumps a
///   [`Vec<u8>`] clone would pay. A validated store-path label carried
///   through that channel reaches the parse frontier through this impl
///   without an `Arc::as_ref().to_vec()` copy.
/// - Generic try-conversion bounds
///   (`fn parse_field<T: TryFrom<Arc<[u8]>>>`) — a validated-input
///   newtype builder or attestation-column reader whose parse contract is
///   stated at the cross-thread shared-owned byte receiver layer (an
///   atomically refcounted byte payload handed cheaply among sibling
///   readers on different threads through [`std::sync::Arc::clone`]) can
///   name [`StorePath`] alongside every other cross-thread shared-owned
///   byte try-conversion primitive without routing through a
///   [`Vec<u8>`]-first or [`&[u8]`]-first shim.
/// - A `HashMap<Arc<[u8]>, StorePath>` shared intern table — a
///   closure-scan or attic-push staging pool that keys a validated store
///   path off its raw-byte label buffer and hands the same buffer to
///   sibling readers across worker threads through
///   [`std::sync::Arc::clone`] — can populate its entries by
///   `try_from`-ing the raw shared buffer directly through this impl
///   without an `std::str::from_utf8(&*arc)?.parse::<StorePath>()`
///   two-step, and without paying a fresh [`Vec<u8>`] allocation per
///   entry.
///
/// # Two-stage strictness
///
/// The parser is strict at two frontiers, in order, unchanged from the
/// underlying byte-slice peer:
///
/// 1. Non-UTF-8 byte sequences reject at the UTF-8 decode gate
///    ([`std::str::from_utf8`] inside the delegated [`TryFrom<&[u8]>`]
///    peer) with the typed [`StorePathError::NonUtf8Bytes`] variant
///    carrying the offending buffer verbatim and the underlying
///    [`std::str::Utf8Error`] under [`std::error::Error::source`].
/// 2. Valid-UTF-8 byte sequences that decode to a non-store-path string
///    reject at the underlying [`FromStr`] impl with the exact
///    grammar-clause variant the input violated
///    (`MissingStorePrefix` / `HasSubpath` / `TooShort` / `InvalidHash` /
///    `MissingSeparator` / `EmptyName`).
///
/// # Error shape
///
/// `Self::Error = StorePathError`. The typed grammar-clause enum,
/// extended with the [`StorePathError::NonUtf8Bytes`] variant for the
/// UTF-8 decode gate, carries through — no widening to [`anyhow::Error`]
/// or `Box<dyn Error>` hides between the cross-thread shared-owned byte
/// try-conversion surface and the inherent constructor, so a caller can
/// still `match` on the exact rejection site at the trait entry point
/// even when the caller holds an atomically refcounted byte buffer.
impl TryFrom<std::sync::Arc<[u8]>> for StorePath {
    type Error = StorePathError;

    fn try_from(shared: std::sync::Arc<[u8]>) -> Result<Self, Self::Error> {
        <Self as TryFrom<&[u8]>>::try_from(shared.as_ref())
    }
}

/// Thread-local shared-owned byte-buffer try-conversion peer for
/// [`StorePath::parse`] via the [`TryFrom<Rc<[u8]>>`] trait — the
/// non-atomically refcounted shared-buffer frontier that pairs with the
/// [`TryFrom<Arc<[u8]>>`] cross-thread shared-owned byte peer directly
/// above under a receiver shape whose payload is cheap-cloned within a
/// single thread through [`std::rc::Rc::clone`] rather than the
/// atomically refcounted [`std::sync::Arc::clone`] used across worker
/// threads. Where the UTF-8 sibling [`TryFrom<Rc<str>>`] assumes the
/// text gate has already fired, this peer takes a thread-local
/// refcounted buffer whose UTF-8 status is still open — the exact shape
/// carried by a `HashMap<Rc<[u8]>, StorePath>` single-thread intern
/// table, an Rc-shared byte payload passed among sibling readers on a
/// closure-scan or attic-push staging path, or an rkyv / bincode /
/// MessagePack / CBOR wire frame kept single-threaded to shed the
/// atomic-refcount cost the [`std::sync::Arc<[u8]>`] peer would pay.
///
/// Delegates through `<Self as TryFrom<&[u8]>>::try_from` on the borrowed
/// [`[u8]`] view of the caller-supplied [`Rc<[u8]>`] (via
/// [`<std::rc::Rc<[u8]> as AsRef<[u8]>>::as_ref`], a zero-copy borrow
/// of the shared allocation's bytes that does NOT touch the non-atomic
/// refcount header), so the store-path grammar and the UTF-8 decode
/// gate stay defined at ONE construction surface — the byte-slice
/// [`TryFrom<&[u8]>`] peer, which itself composes [`std::str::from_utf8`]
/// with the [`FromStr`] oracle. No refcount bump, no buffer clone, no
/// divergent decode gate: the impl body pays the by-reference byte-slice
/// try-conversion cost at zero allocation on the incoming thread-local
/// shared handle.
///
/// # Why the trait peer earns its keep
///
/// The five byte-side receiver-shape peers directly above
/// ([`TryFrom<&[u8]>`], [`TryFrom<Vec<u8>>`], [`TryFrom<Box<[u8]>>`],
/// [`TryFrom<Cow<'_, [u8]>>`], [`TryFrom<Arc<[u8]>>`]) close the parse
/// frontier at every non-thread-local-shared byte receiver shape. This
/// peer closes the disjoint thread-local shared-owned byte frontier
/// stdlib and the wider ecosystem key off separately:
///
/// - `#[serde(try_from = "Rc<[u8]>")]` — the serde container attribute
///   for the thread-local shared-owned byte case (a deserializer that
///   hands out non-atomically refcounted byte buffers so peers inside a
///   single-thread graph hold cheap-clone shared ownership without
///   copying and without paying the atomic-refcount cost of
///   [`std::sync::Arc`]) keys off [`TryFrom<Rc<[u8]>>`], not
///   [`TryFrom<Arc<[u8]>>`], [`TryFrom<Rc<str>>`],
///   [`TryFrom<Box<[u8]>>`], [`TryFrom<Vec<u8>>`], or
///   [`TryFrom<&[u8]>`]. A future serde field wrapping a [`StorePath`]
///   and opting into the thread-local shared-owned byte `try_from`
///   grammar reaches the store-path check through this impl without a
///   shim.
/// - A single-thread graph of readers that shares a raw-byte label
///   buffer through [`std::rc::Rc::clone`] — a closure-scan or
///   attic-push staging path kept single-threaded because none of its
///   consumers cross a worker-thread boundary — reaches the parse
///   frontier through this impl without an [`Rc::as_ref().to_vec()`]
///   copy and without lifting the whole payload to [`std::sync::Arc`]
///   solely to satisfy the sibling [`TryFrom<Arc<[u8]>>`] peer's
///   bound.
/// - Generic try-conversion bounds
///   (`fn parse_field<T: TryFrom<Rc<[u8]>>>`) — a validated-input
///   newtype builder or attestation-column reader whose parse contract
///   is stated at the thread-local shared-owned byte receiver layer (a
///   non-atomically refcounted byte payload handed cheaply among
///   sibling readers on a single thread through [`std::rc::Rc::clone`])
///   can name [`StorePath`] alongside every other thread-local
///   shared-owned byte try-conversion primitive without routing through
///   a [`Vec<u8>`]-first, [`&[u8]`]-first, or [`std::sync::Arc<[u8]>`]-first
///   shim.
/// - A `HashMap<Rc<[u8]>, StorePath>` single-thread intern table — a
///   closure-scan or attic-push staging pool that keys a validated
///   store path off its raw-byte label buffer and hands the same buffer
///   to sibling readers on the same thread through
///   [`std::rc::Rc::clone`] — can populate its entries by
///   `try_from`-ing the raw shared buffer directly through this impl
///   without an `std::str::from_utf8(&*rc)?.parse::<StorePath>()`
///   two-step, without paying a fresh [`Vec<u8>`] allocation per entry,
///   and without paying the atomic-refcount cost the sibling
///   [`std::sync::Arc<[u8]>`] peer imposes.
///
/// # Two-stage strictness
///
/// The parser is strict at two frontiers, in order, unchanged from the
/// underlying byte-slice peer:
///
/// 1. Non-UTF-8 byte sequences reject at the UTF-8 decode gate
///    ([`std::str::from_utf8`] inside the delegated [`TryFrom<&[u8]>`]
///    peer) with the typed [`StorePathError::NonUtf8Bytes`] variant
///    carrying the offending buffer verbatim and the underlying
///    [`std::str::Utf8Error`] under [`std::error::Error::source`].
/// 2. Valid-UTF-8 byte sequences that decode to a non-store-path string
///    reject at the underlying [`FromStr`] impl with the exact
///    grammar-clause variant the input violated
///    (`MissingStorePrefix` / `HasSubpath` / `TooShort` / `InvalidHash` /
///    `MissingSeparator` / `EmptyName`).
///
/// # Error shape
///
/// `Self::Error = StorePathError`. The typed grammar-clause enum,
/// extended with the [`StorePathError::NonUtf8Bytes`] variant for the
/// UTF-8 decode gate, carries through — no widening to [`anyhow::Error`]
/// or `Box<dyn Error>` hides between the thread-local shared-owned byte
/// try-conversion surface and the inherent constructor, so a caller can
/// still `match` on the exact rejection site at the trait entry point
/// even when the caller holds a non-atomically refcounted byte buffer.
impl TryFrom<std::rc::Rc<[u8]>> for StorePath {
    type Error = StorePathError;

    fn try_from(shared: std::rc::Rc<[u8]>) -> Result<Self, Self::Error> {
        <Self as TryFrom<&[u8]>>::try_from(shared.as_ref())
    }
}

/// By-reference read-back peer for [`StorePath::as_str`] via the
/// [`AsRef<str>`] trait — the [`std::fmt::Display`] impl above emits the
/// full path into a formatter; this peer exposes the same view directly as
/// a borrowed [`&str`] so consumers can pass a [`StorePath`] anywhere
/// generic [`AsRef<str>`] is accepted without a call-site `.as_str()`
/// shim.
///
/// Delegates verbatim to [`StorePath::as_str`], so the "what does a
/// [`StorePath`] read back as?" question stays defined at ONE accessor
/// surface. A future change to the internal representation (e.g. splitting
/// `full` into `prefix + hash + name` components) lands in `as_str` once,
/// and both the inherent accessor and the trait peer light up in the same
/// commit.
///
/// # Why the trait peer earns its keep
///
/// The inherent [`StorePath::as_str`] is the direct accessor; the trait
/// peer opens the same read-back view to every downstream context that
/// already speaks generic [`AsRef<str>`]:
///
/// - `println!("{}", sp.as_ref() as &str)` and any format-argument sink
///   that binds `impl AsRef<str>` — the [`Display`] impl above covers the
///   format-argument case, but a caller that wants the borrowed [`&str`]
///   *value* (to concatenate, slice, or feed to a third-party API that
///   takes [`AsRef<str>`]) reaches through this peer.
/// - Generic bounds (`fn write_path<S: AsRef<str>>(s: S)`) — a downstream
///   record writer or attestation-column emitter that binds its input
///   contract as [`AsRef<str>`] rather than [`&str`] or `Into<String>`
///   can name [`StorePath`] alongside every other by-reference read-back
///   primitive without a shim.
/// - The [`std::path::Path::new`] constructor, [`std::fs`] operations
///   ([`std::fs::metadata`], [`std::fs::exists`]), and
///   [`std::process::Command`] argument builders (`cmd.arg(sp.as_ref())`)
///   all accept [`AsRef<str>`] or [`AsRef<std::ffi::OsStr>`] at the
///   boundary — the [`&str`] this peer exposes composes with each
///   frontier without a per-site [`.as_str()`] rewrite.
/// - The sibling canonical-label typed sums in this crate already carry
///   the peer: [`AsRef<str>`] `for PerAttemptRegion` at `retry.rs`
///   opens the same read-back frontier for the retry-region label
///   surface; this impl is the store-path primitive counterpart on the
///   same read-back frontier — the by-reference dual of the [`FromStr`]
///   / [`TryFrom<&str>`] construction peers directly above.
///
/// # Zero-cost
///
/// Returns a borrow of the interned [`String`] (`&self.full`) — no
/// allocation, no re-validation, no shift in the string's identity. The
/// [`&str`] this peer exposes has the same lifetime as the borrow of the
/// [`StorePath`], so a caller can bind it in one expression without
/// widening the return to an owned buffer.
impl AsRef<str> for StorePath {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// By-reference filesystem-path read-back peer for [`StorePath::as_str`] via
/// the [`AsRef<std::path::Path>`] trait — the sibling of the [`AsRef<str>`]
/// peer directly above at the filesystem-path frontier, so a consumer bound
/// by `impl AsRef<std::path::Path>` (a [`std::fs::exists`], [`std::fs::metadata`],
/// [`std::fs::symlink_metadata`], [`std::fs::read_link`], or
/// [`std::path::PathBuf::from`] intake site — the boundaries a validated
/// Nix store object path is meant to reach) reads the canonical path view
/// directly from a [`StorePath`] value without a call-site
/// [`std::path::Path::new`]`(sp.as_str())` restatement.
///
/// Delegates through `<Self as AsRef<str>>::as_ref` composed with
/// [`std::path::Path::new`], so the "what does a [`StorePath`] read back as?"
/// question stays defined at ONE accessor surface — the inherent
/// [`StorePath::as_str`] — and the borrowed-view axis routes through it at
/// every frontier peer without a divergent second accessor. A future change
/// to the internal representation lands in [`StorePath::as_str`] once and
/// both the [`AsRef<str>`] peer and this [`AsRef<std::path::Path>`] peer
/// light up in the same commit.
///
/// # Why the trait peer earns its keep
///
/// The [`AsRef<str>`] peer above closes the UTF-8 string frontier
/// (`fn f<S: AsRef<str>>` — record writers, attestation-column emitters,
/// third-party APIs that bind `impl AsRef<str>`). [`AsRef<std::path::Path>`]
/// closes the disjoint filesystem-path frontier the stdlib
/// [`std::fs`] surface and every `impl AsRef<std::path::Path>` boundary key
/// off. A Nix store object path is, by construction, a real path in the
/// local `/nix/store` filesystem: the very consumers this type exists to
/// serve — verifying a build output is on disk before pushing it to Attic,
/// stat-ing a derivation, resolving a symlink from a build result to its
/// output path — key off `impl AsRef<std::path::Path>` rather than
/// `AsRef<str>`:
///
/// - [`std::fs::exists`] / [`std::fs::metadata`] / [`std::fs::symlink_metadata`]
///   — a pre-push liveness check (`fs::exists(&sp)`) or a stat-based
///   size / mtime probe over a validated store object reads directly from a
///   [`StorePath`] value without a per-site `Path::new(sp.as_str())`
///   restatement.
/// - [`std::fs::read_link`] — a `nix-build`-result-follow that reads the
///   symlink target off a `result` link and validates the target as a
///   [`StorePath`] (or dereferences a store-object symlink one step) keys
///   off the filesystem-path frontier at both intake and read-back.
/// - [`std::path::PathBuf::from`] / [`std::path::PathBuf::push`] /
///   [`std::path::PathBuf::join`] — a caller building an owned filesystem
///   path from a validated store object (a downstream tool that composes
///   `sp` with a known-safe subpath at a *separate* site, not this type's
///   canonical shape) reaches through the borrowed-view frontier without
///   the two-step `PathBuf::from(sp.as_str())` restatement.
/// - Sibling canonical-label typed sums in this crate already carry the
///   peer at the same filesystem-path read-back frontier:
///   `impl AsRef<std::path::Path> for BumpLevel` at `version.rs`,
///   `impl AsRef<std::path::Path> for PerAttemptRegion` at `retry.rs`,
///   `impl AsRef<std::path::Path> for AdmissionTier` at `probe_outcome.rs`;
///   [`StorePath`] is the store-path primitive counterpart at the same
///   frontier — the borrowed-view axis of this crate's typed primitives is
///   now closed across the UTF-8 string frontier ([`AsRef<str>`]) AND the
///   filesystem-path frontier (this peer) at the store-path axis.
///
/// # Zero-cost
///
/// Returns a borrow of the interned [`String`] wrapped through
/// [`std::path::Path::new`], which is a zero-cost view transmute
/// ([`std::path::Path`] is an [`std::ffi::OsStr`] newtype and `str: AsRef<OsStr>`
/// on every supported platform). No allocation, no [`std::path::PathBuf`]
/// copy, no re-validation of the store-path grammar — the [`&std::path::Path`]
/// this peer exposes has the same lifetime as the borrow of the [`StorePath`],
/// so a caller can bind it in one expression without widening to
/// [`std::path::PathBuf`].
impl AsRef<std::path::Path> for StorePath {
    fn as_ref(&self) -> &std::path::Path {
        std::path::Path::new(<Self as AsRef<str>>::as_ref(self))
    }
}

/// By-reference OS-string read-back peer for [`StorePath::as_str`] via the
/// [`AsRef<std::ffi::OsStr>`] trait — the sibling of the [`AsRef<str>`] and
/// [`AsRef<std::path::Path>`] peers directly above at the OS-string
/// frontier, so a consumer bound by `impl AsRef<std::ffi::OsStr>` — the
/// input surface every [`std::process::Command::arg`] /
/// [`std::process::Command::args`] / [`std::process::Command::env`] /
/// [`std::process::Command::current_dir`] slot keys off — reads the
/// canonical OS-string view directly from a [`StorePath`] value without a
/// call-site [`std::ffi::OsStr::new`]`(sp.as_str())` restatement.
///
/// Delegates through `<Self as AsRef<str>>::as_ref` composed with
/// [`std::ffi::OsStr::new`], so the "what does a [`StorePath`] read back
/// as?" question stays defined at ONE accessor surface — the inherent
/// [`StorePath::as_str`] — and the borrowed-view axis routes through it at
/// every frontier peer without a divergent second accessor. A future change
/// to the internal representation lands in [`StorePath::as_str`] once and
/// the [`AsRef<str>`] / [`AsRef<std::path::Path>`] / this
/// [`AsRef<std::ffi::OsStr>`] peer light up in the same commit.
///
/// # Why the trait peer earns its keep
///
/// The [`AsRef<str>`] peer closes the UTF-8 string frontier
/// (`fn f<S: AsRef<str>>` — record writers, attestation-column emitters,
/// third-party APIs that bind `impl AsRef<str>`). The
/// [`AsRef<std::path::Path>`] peer closes the filesystem-path frontier the
/// [`std::fs`] surface keys off. [`AsRef<std::ffi::OsStr>`] closes the
/// disjoint OS-string frontier that process-spawn and environment
/// machinery bind: every argument fed to `attic push /nix/store/...`,
/// `nix copy /nix/store/...`, `nix path-info /nix/store/...`, `skopeo copy
/// nix:/nix/store/...`, and every `Command::current_dir(&sp)` slot keys
/// off `impl AsRef<std::ffi::OsStr>` rather than `AsRef<str>` or
/// `AsRef<std::path::Path>`. A validated [`StorePath`] handed to any of
/// those boundaries reaches the process-spawn frontier through the typed
/// primitive without a per-site `OsStr::new(sp.as_str())` restatement:
///
/// - [`std::process::Command::arg`] / [`std::process::Command::args`] — an
///   `attic push` / `nix copy` / `nix path-info` argument slot over a
///   validated store object reads directly from a [`StorePath`] value.
///   These are the exact call sites that motivated the nix-frontier
///   validation gate at [`crate::nix::run_nix_build_typed`]: a value that
///   satisfies [`StorePath::parse`] is by construction safe to hand to
///   the downstream process without a per-consumer re-check.
/// - [`std::process::Command::env`] / [`std::env::set_var`] — a telemetry
///   or reproducibility bridge that surfaces a validated store object as
///   an environment variable value (`FORGE_LAST_BUILD_STORE_PATH=<sp>`)
///   reads through the OS-string frontier without an [`std::ffi::OsString`]
///   copy.
/// - [`std::process::Command::current_dir`] — a caller spawning a
///   sub-process whose CWD is a validated store object subdirectory (a
///   `nix-shell`-alike whose environment is anchored at the store object)
///   reaches the CWD frontier at the OS-string surface every
///   [`std::process::Command`] method keys off.
/// - Sibling canonical-label typed sums in this crate already carry the
///   peer at the same OS-string read-back frontier:
///   `impl AsRef<std::ffi::OsStr> for BumpLevel` at `version.rs`,
///   `impl AsRef<std::ffi::OsStr> for PerAttemptRegion` at `retry.rs`,
///   `impl AsRef<std::ffi::OsStr> for AdmissionTier` at `probe_outcome.rs`;
///   [`StorePath`] is the store-path primitive counterpart at the same
///   frontier — the borrowed-view axis of this crate's typed primitives is
///   now closed across the UTF-8 string frontier ([`AsRef<str>`]), the
///   filesystem-path frontier ([`AsRef<std::path::Path>`]), and the
///   OS-string frontier (this peer) at the store-path axis.
///
/// # Zero-cost
///
/// Returns a borrow of the interned [`String`] wrapped through
/// [`std::ffi::OsStr::new`], which is a zero-cost view transmute at the
/// borrow-view boundary — on Unix, [`std::ffi::OsStr`] is a `[u8]` newtype
/// and every `&str` is a valid `&OsStr`; on Windows, [`std::ffi::OsStr`] is
/// a WTF-8 slice which is a strict superset of UTF-8, so the ASCII store-
/// path payload is a valid `&OsStr` on every supported platform. No
/// allocation, no [`std::ffi::OsString`] copy, no re-validation of the
/// store-path grammar — the [`&std::ffi::OsStr`] this peer exposes has the
/// same lifetime as the borrow of the [`StorePath`], so a caller can bind
/// it in one expression without widening to [`std::ffi::OsString`].
impl AsRef<std::ffi::OsStr> for StorePath {
    fn as_ref(&self) -> &std::ffi::OsStr {
        std::ffi::OsStr::new(<Self as AsRef<str>>::as_ref(self))
    }
}

/// By-reference byte-slice read-back peer for [`StorePath::as_str`] via the
/// [`AsRef<[u8]>`] trait — the sibling of the [`AsRef<str>`],
/// [`AsRef<std::path::Path>`], and [`AsRef<std::ffi::OsStr>`] peers directly
/// above at the byte-slice frontier, so a consumer bound by
/// `impl AsRef<[u8]>` — the input surface every streaming hasher
/// ([`blake3::Hasher::update`], `sha2::Sha256::update`, `blake2::Blake2b::update`),
/// [`std::io::Write::write_all`] sink, [`std::collections::HashMap`]`<Box<[u8]>, _>`
/// key builder, and memchr-driven byte classifier keys off — reads the
/// canonical byte view directly from a [`StorePath`] value without a
/// call-site `sp.as_str().as_bytes()` restatement.
///
/// Delegates through `<Self as AsRef<str>>::as_ref` composed with
/// [`str::as_bytes`], so the "what does a [`StorePath`] read back as?"
/// question stays defined at ONE accessor surface — the inherent
/// [`StorePath::as_str`] — and the borrowed-view axis routes through it at
/// every frontier peer without a divergent second accessor. A future change
/// to the internal representation lands in [`StorePath::as_str`] once and
/// the [`AsRef<str>`] / [`AsRef<std::path::Path>`] / [`AsRef<std::ffi::OsStr>`]
/// / this [`AsRef<[u8]>`] peer light up in the same commit.
///
/// # Why the trait peer earns its keep
///
/// The [`AsRef<str>`] peer closes the UTF-8 string frontier
/// (`fn f<S: AsRef<str>>` — record writers, attestation-column emitters,
/// third-party APIs that bind `impl AsRef<str>`). The
/// [`AsRef<std::path::Path>`] peer closes the filesystem-path frontier the
/// [`std::fs`] surface keys off. The [`AsRef<std::ffi::OsStr>`] peer closes
/// the OS-string frontier the [`std::process::Command`] surface binds.
/// [`AsRef<[u8]>`] closes the disjoint byte-slice frontier that hashing,
/// byte-sink, and byte-keyed-lookup machinery bind: a validated
/// [`StorePath`] handed to any of those boundaries reaches the byte frontier
/// through the typed primitive without a per-site
/// `sp.as_str().as_bytes()` restatement:
///
/// - [`blake3::Hasher::update`] / `sha2::Sha256::update` /
///   `blake2::Blake2b::update` — a caller that folds a validated store path
///   into a build / attestation / closure fingerprint reads directly from a
///   [`StorePath`] value. This is the exact discipline
///   [`canonical_closure_fingerprint`] applies to the *set* of hashes
///   extracted by [`parse_closure_paths`]: the byte-slice frontier is where
///   the hermetic identity of a validated store path meets the hasher, and
///   the peer that carries the identity to it is `AsRef<[u8]>`.
/// - [`std::io::Write::write_all`] — an attestation-column emitter that
///   streams a validated store path to a byte sink (a manifest writer, a
///   provenance-log appender) binds `impl AsRef<[u8]>` at its intake and
///   reads through the peer without a two-step `write_all(sp.as_str().as_bytes())`
///   restatement.
/// - [`std::collections::HashMap`]`<Box<[u8]>, _>::get` — a caller keying a
///   dedup / seen-set / interning table on the raw byte view of a store
///   path (a memchr-shaped byte comparator that outruns UTF-8-aware
///   comparison at the hot path) reaches the byte-slice frontier through
///   the typed primitive at one impl.
/// - Sibling canonical-label typed sums in this crate already carry the
///   peer at the same byte-slice read-back frontier:
///   `impl AsRef<[u8]> for BumpLevel` at `version.rs`,
///   `impl AsRef<[u8]> for PerAttemptRegion` at `retry.rs`,
///   `impl AsRef<[u8]> for AdmissionTier` at `probe_outcome.rs`;
///   [`StorePath`] is the store-path primitive counterpart at the same
///   frontier — the borrowed-view axis of this crate's typed primitives is
///   now closed across the UTF-8 string frontier ([`AsRef<str>`]), the
///   filesystem-path frontier ([`AsRef<std::path::Path>`]), the OS-string
///   frontier ([`AsRef<std::ffi::OsStr>`]), and the byte-slice frontier
///   (this peer) at the store-path axis.
///
/// # Zero-cost
///
/// Returns a borrow of the interned [`String`]'s UTF-8 bytes.
/// [`str::as_bytes`] is a zero-cost view transmute at the borrow-view
/// boundary — no allocation, no [`Vec<u8>`] copy, no re-validation of the
/// store-path grammar. The [`&[u8]`] this peer exposes has the same
/// lifetime as the borrow of the [`StorePath`], so a caller can bind it in
/// one expression without widening to [`Vec<u8>`]. A store-path payload is
/// ASCII by construction (base-32 hash from a fixed 32-char alphabet, plus
/// a name from the store-path name grammar), so [`std::str::from_utf8`]
/// round-trips the bytes losslessly at every valid [`StorePath`] value.
impl AsRef<[u8]> for StorePath {
    fn as_ref(&self) -> &[u8] {
        <Self as AsRef<str>>::as_ref(self).as_bytes()
    }
}

/// Forward-direction borrowed UTF-8 comparison peer — the sibling of the
/// [`AsRef<str>`] read-back peer above, split by intent. A downstream
/// caller who holds a [`StorePath`] and a raw [`str`] (a captured
/// wire-received line, an `attic push` argv slot echo, a
/// nix-build-stdout payload sitting in a `&Cow::Borrowed(s)`) writes
/// `sp == *raw_str` and answers a boolean equality query at the same
/// borrowed UTF-8 frontier the read-back peer covers, without a
/// per-site `sp.as_str() == raw_str` restatement and without an
/// implicit widening to [`String`] to satisfy the standard-library
/// [`PartialEq<str> for String`] surface.
///
/// Delegates through [`StorePath::as_str`] composed with the
/// standard-library [`<str as PartialEq<str>>::eq`] on the borrowed
/// receiver, so the "what canonical bytes does a [`StorePath`] carry?"
/// question stays defined at ONE accessor surface — the inherent
/// [`StorePath::as_str`] — and every comparison surface reads through
/// it. No allocation, no temporary [`String`], no
/// [`std::fmt::Display`] formatter-buffer round trip per call.
///
/// # Why the trait peer earns its keep
///
/// The [`AsRef<str>`] peer (line 1327) closes the *read* frontier
/// (`fn f<S: AsRef<str>>` — record writers, attestation-column
/// emitters, generic borrowed-view consumers). [`PartialEq<str>`]
/// closes the disjoint *comparison* frontier — the surface every
/// wire-check / config-check / round-trip verifier keys off:
///
/// - `assert_eq!(sp, "/nix/store/…")` in a fixture / integration test —
///   reads the canonical bytes of a [`StorePath`] directly against an
///   inline literal without the `assert_eq!(sp.as_str(), "…")`
///   restatement that repeats the accessor name at every assertion.
/// - `wire_line == parsed_store_path` in a stdout-echo verifier that
///   confirms an `attic push` / `nix copy` argv slot round-tripped
///   the exact bytes forge handed it — the reverse-direction sibling
///   below lets the caller pick either receiver at the site.
/// - Generic [`PartialEq`]-bounded consumers
///   (`fn same_label<A, B>(a: A, b: B) -> bool where A: PartialEq<B>`)
///   — a downstream helper that composes a [`StorePath`] with a
///   borrowed [`str`] key can name the bound without a `where` clause
///   naming both `StorePath: AsRef<str>` and a shim
///   `sp.as_str() == raw_str` inline.
/// - Sibling canonical-label typed sums in this crate already carry
///   the same forward-direction peer at the borrowed UTF-8 comparison
///   frontier: `impl PartialEq<str> for BumpLevel` at `version.rs`,
///   `impl PartialEq<str> for PerAttemptRegion` at `retry.rs`,
///   `impl PartialEq<str> for AdmissionTier` at `probe_outcome.rs`,
///   `impl PartialEq<str> for DigestAlgorithm` at `oci_manifest.rs`.
///   [`StorePath`] is the store-path primitive counterpart at the
///   same comparison frontier — the borrowed UTF-8 comparison axis
///   of this crate's typed primitives now spans the ordered label
///   sums AND the validated-path grammar with ONE canonical-view
///   oracle each.
///
/// # Trimming discipline reaches through
///
/// A [`StorePath`] parsed from a newline-terminated buffer holds the
/// *trimmed* canonical bytes ([`StorePath::parse`] applies `trim`
/// before every grammar clause), so the comparison peer sees the
/// trimmed view — `sp == "/nix/store/…-x"` holds for a value parsed
/// from `"/nix/store/…-x\n"`. The comparison peer inherits the
/// discipline the accessor already carries; no per-site
/// `sp.as_str().trim() == …` restatement.
impl PartialEq<str> for StorePath {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

/// Forward-direction borrowed UTF-8 comparison peer through a `&str`
/// argument — the receiver-shape sibling of [`PartialEq<str> for StorePath`]
/// directly above, split by receiver shape so the caller writes
/// `sp == &raw_str_ref` without the explicit deref at every comparison
/// site. The pair together closes the forward-direction 1×2
/// (receiver-shape) surface on the borrowed UTF-8 comparison frontier
/// — the same shape the standard library gives [`String`] through its
/// own [`PartialEq<str> for String`] + [`PartialEq<&str> for String`]
/// pair, and the same shape the sibling canonical-label typed sums
/// already carry.
///
/// Delegates through [`StorePath::as_str`] composed with the standard-
/// library [`<str as PartialEq<str>>::eq`] on the dereffed `&str`
/// argument, so the comparison reads the same canonical bytes as the
/// receiver-shape sibling and the two-impl pair are structurally
/// indistinguishable at the byte-comparison level.
///
/// The reverse-direction pair
/// (`impl PartialEq<StorePath> for str` +
/// `impl PartialEq<StorePath> for &str`) is a natural follow-on that
/// closes the full 2×2 direction × receiver-shape cross-product on
/// this frontier, matching the closure the sibling canonical-label
/// typed sums (`BumpLevel`, `PerAttemptRegion`, `AdmissionTier`,
/// `DigestAlgorithm`) already carry.
impl PartialEq<&str> for StorePath {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

/// Reverse-direction borrowed UTF-8 comparison peer — the sibling of the
/// forward-direction [`PartialEq<str> for StorePath`] pair above, split
/// by direction so the caller can pick either receiver at the comparison
/// site. Together with the forward-direction pair, this closes the full
/// 2×2 (direction × receiver-shape) surface on the borrowed UTF-8
/// comparison frontier of this primitive, matching the standard-library
/// idiom [`String`] carries through its own four-impl closure
/// ([`PartialEq<str> for String`] + [`PartialEq<&str> for String`] +
/// [`PartialEq<String> for str`] + [`PartialEq<String> for &str`]) and
/// the closure the sibling canonical-label typed sums already carry:
///
/// - `impl PartialEq<BumpLevel> for str` at `cli/src/version.rs:9428`,
/// - `impl PartialEq<PerAttemptRegion> for str` at `cli/src/retry.rs:8770`,
/// - `impl PartialEq<AdmissionTier> for str` at `cli/src/probe_outcome.rs:13264`,
/// - `impl PartialEq<DigestAlgorithm> for str` at `cli/src/oci_manifest.rs:3597`.
///
/// A downstream caller holding a raw [`str`] and a [`StorePath`] (a
/// wire-received line from `nix-build` stdout that the caller wants to
/// check against a parsed handle, an inline fixture literal in a
/// caller-side round-trip verifier that writes `"/nix/store/…" == sp`,
/// a generic [`PartialEq`]-bounded consumer parameterised on a
/// [`str`]-like key and a [`StorePath`]-like value) answers the boolean
/// equality query at ONE canonical-view surface — [`StorePath::as_str`]
/// — without a per-site `raw_str == sp.as_str()` restatement and
/// without an implicit widening to [`String`] to satisfy the standard-
/// library [`PartialEq<String> for str`] surface.
///
/// Delegates through [`StorePath::as_str`] composed with the standard-
/// library [`<str as PartialEq<str>>::eq`] on the [`str`] self receiver,
/// so the "what canonical bytes does a [`StorePath`] carry?" question
/// stays defined at ONE accessor surface — the inherent
/// [`StorePath::as_str`] — and every comparison surface (forward-str,
/// forward-&str, reverse-str, reverse-&str) reads through it. No
/// allocation, no temporary [`String`], no [`std::fmt::Display`]
/// formatter-buffer round trip per call.
///
/// The symmetry axiom
/// `<str as PartialEq<StorePath>>::eq(label, &sp)
/// == <StorePath as PartialEq<str>>::eq(&sp, label)` at every
/// (candidate, [`StorePath`]) pair holds by construction: both directions
/// factor through the same `StorePath::as_str` view and the same
/// standard-library [`<str as PartialEq<str>>::eq`] comparison. Pinned
/// at
/// [`tests::test_partial_eq_store_path_symmetric_with_forward_direction`].
///
/// THEORY.md §III typed primitives: the reverse-direction borrowed UTF-8
/// comparison surface is a typed-primitive site on [`StorePath`] itself
/// (one [`PartialEq<StorePath>`] impl on [`str`] routing through
/// [`StorePath::as_str`]), not a per-consumer
/// `label == sp.as_str()` restatement at every downstream site that
/// asks whether a borrowed UTF-8 handle names the same canonical store-
/// path bytes as a [`StorePath`] value. THEORY.md §VI.1 one-oracle: the
/// canonical view is named at one site ([`StorePath::as_str`]), and
/// every borrowed UTF-8 comparison surface — the forward-direction
/// pair above and this reverse-direction pair — reads through the same
/// one-oracle discipline projected onto its own direction × receiver
/// shape.
impl PartialEq<StorePath> for str {
    fn eq(&self, other: &StorePath) -> bool {
        self == other.as_str()
    }
}

/// Reverse-direction borrowed UTF-8 comparison peer through a `&str`
/// receiver — the receiver-shape sibling of
/// [`PartialEq<StorePath> for str`] directly above, split by receiver
/// shape so the caller writes `label_ref == sp` without the explicit
/// `*` deref at every comparison site. The four [`PartialEq`] impls
/// together (forward-str, forward-&str, reverse-str, reverse-&str)
/// close the full 2×2 direction × receiver-shape cross-product on this
/// frontier.
///
/// Delegates through [`StorePath::as_str`] composed with the standard-
/// library [`<str as PartialEq<str>>::eq`] on the dereffed `&str` self
/// receiver, so the comparison reads the same canonical bytes as the
/// receiver-shape sibling and the two-impl pair are structurally
/// indistinguishable at the byte-comparison level. The symmetry axiom
/// `<&str as PartialEq<StorePath>>::eq(&label_ref, &sp)
/// == <StorePath as PartialEq<&str>>::eq(&sp, &label_ref)` holds by
/// construction at every `(label_ref, sp)` pair, pinned at
/// [`tests::test_partial_eq_store_path_symmetric_with_forward_direction`].
impl PartialEq<StorePath> for &str {
    fn eq(&self, other: &StorePath) -> bool {
        *self == other.as_str()
    }
}

/// Forward-direction owned UTF-8 comparison peer — the heap-owned
/// [`String`]-receiver sibling of the borrowed-receiver [`PartialEq<str>`] +
/// [`PartialEq<&str>`] pair above, split by receiver ownership so the caller
/// writes `sp == owned` (a wire-received line captured into a [`String`]
/// buffer, a serde-decoded field arriving as [`String`], a
/// [`std::process::Command`] stdout buffer converted via
/// [`String::from_utf8`]) without an intermediate `sp == owned.as_str()`
/// restatement and without cloning the [`StorePath`]'s canonical bytes into
/// a fresh [`String`] to satisfy a hypothetical
/// [`PartialEq<StorePath> for String`] via the standard library.
///
/// Delegates through [`StorePath::as_str`] composed with
/// [`String::as_str`] and the standard-library
/// [`<str as PartialEq<str>>::eq`], so the "what canonical bytes does a
/// [`StorePath`] carry?" question stays defined at ONE accessor surface —
/// the inherent [`StorePath::as_str`] — and every UTF-8 comparison surface
/// (forward-str, forward-&str, reverse-str, reverse-&str, forward-String,
/// reverse-String) reads through it. Zero allocation, zero temporary
/// [`String`], zero re-validation of the store-path grammar per call.
///
/// Mirrors the sibling canonical-label typed sums' owned-receiver comparison
/// peers at the same one-oracle discipline:
/// - [`impl PartialEq<String> for PerAttemptRegion`] at `cli/src/retry.rs:8910`,
/// - [`impl PartialEq<String> for ContentDigest`] at `cli/src/oci_manifest.rs:6300`.
///
/// The reverse-direction sibling [`impl PartialEq<StorePath> for String`]
/// directly below closes the 2-impl owned-receiver closure so the caller
/// may pick either side of the `==` operator when the comparand is a
/// heap-owned [`String`], matching the standard-library idiom [`String`]
/// carries through its own [`PartialEq<String> for str`] +
/// [`PartialEq<String> for &str`] + [`PartialEq<str> for String`] +
/// [`PartialEq<&str> for String`] closure.
///
/// THEORY.md §III typed primitives: the owned UTF-8 comparison surface is
/// a typed-primitive site on [`StorePath`] itself, not a per-consumer
/// `sp.as_str() == owned.as_str()` restatement at every downstream site
/// that asks whether a [`StorePath`] value names the same canonical bytes
/// as a heap-owned [`String`]. THEORY.md §VI.1 one-oracle: the canonical
/// view is named at one site ([`StorePath::as_str`]) and every comparison
/// receiver × direction × ownership reads through it.
impl PartialEq<String> for StorePath {
    fn eq(&self, other: &String) -> bool {
        self.as_str() == other.as_str()
    }
}

/// Reverse-direction owned UTF-8 comparison peer — the direction sibling
/// of [`impl PartialEq<String> for StorePath`] directly above, split by
/// direction so the caller writes `owned == sp` at the comparison site
/// (a fixture-side assertion `assert_eq!(String::from("/nix/store/…-x"),
/// sp)`, a wire-echo verifier that reads
/// `captured_line == parsed_handle`, a generic [`PartialEq`]-bounded
/// consumer composed on a [`String`] key against a [`StorePath`] value).
/// Together with the forward-direction sibling this closes the 2-impl
/// owned-receiver × direction closure at the same one-oracle discipline
/// the four-impl borrowed-receiver closure above already carries.
///
/// Delegates through [`String::as_str`] composed with [`StorePath::as_str`]
/// and the standard-library [`<str as PartialEq<str>>::eq`], so the
/// symmetry axiom
/// `<String as PartialEq<StorePath>>::eq(&owned, &sp)
/// == <StorePath as PartialEq<String>>::eq(&sp, &owned)` at every
/// (owned, sp) pair holds by construction — both directions factor through
/// the same one-oracle accessor and the same standard-library str
/// equality. Pinned at
/// [`tests::test_partial_eq_string_store_path_symmetric_with_forward_direction`].
///
/// Extends the reverse-direction receiver frontier the borrowed-receiver
/// pair [`impl PartialEq<StorePath> for str`] +
/// [`impl PartialEq<StorePath> for &str`] opened onto the owned-receiver
/// axis, a closure the sibling canonical-label typed sums
/// ([`crate::retry::PerAttemptRegion`],
/// [`crate::oci_manifest::ContentDigest`]) do not yet carry — a natural
/// candidate to replicate at those ladders in a follow-on commit.
///
/// THEORY.md §III typed primitives: the reverse-direction owned UTF-8
/// comparison surface is a typed-primitive site on [`StorePath`] (one
/// [`PartialEq<StorePath>`] impl on [`String`] routing through
/// [`String::as_str`] and [`StorePath::as_str`]), not a per-consumer
/// `owned.as_str() == sp.as_str()` restatement at every downstream
/// comparison site. THEORY.md §VI.1 one-oracle: the canonical view is
/// named at one site ([`StorePath::as_str`]) and every UTF-8 comparison
/// surface — borrowed-str-forward, borrowed-&str-forward,
/// borrowed-str-reverse, borrowed-&str-reverse, owned-String-forward, and
/// this owned-String-reverse — reads through the same one-oracle
/// discipline projected onto its own direction × receiver ownership.
impl PartialEq<StorePath> for String {
    fn eq(&self, other: &StorePath) -> bool {
        self.as_str() == other.as_str()
    }
}

/// Forward-direction borrowed byte-slice comparison peer — the byte-frontier
/// sibling of the [`PartialEq<str>`] / [`PartialEq<&str>`] UTF-8 pair above,
/// split by frontier so a downstream caller who holds a [`StorePath`] and a
/// raw `[u8]` handle (a `nom` / `winnow` byte-slice scrutinee, a captured
/// `Vec<u8>` process-stdout buffer sliced through `[..]`, a
/// [`std::borrow::Cow::Borrowed`] byte-arm of a wire-decode result) writes
/// `sp == *raw_bytes` and answers a boolean equality query at the same
/// borrowed byte-slice frontier the [`AsRef<[u8]>`] read-back peer covers,
/// without a per-site `sp.as_str().as_bytes() == raw_bytes` restatement and
/// without a [`std::str::from_utf8`] round trip on the caller's byte handle
/// to satisfy the UTF-8-side comparison peer.
///
/// Delegates through [`<StorePath as AsRef<[u8]>>::as_ref`] (itself
/// [`StorePath::as_str`] composed with [`str::as_bytes`]) and the
/// standard-library [`<[u8] as PartialEq<[u8]>>::eq`] on the borrowed
/// receiver, so the "what canonical bytes does a [`StorePath`] carry?"
/// question stays defined at ONE accessor surface — the inherent
/// [`StorePath::as_str`] projected onto bytes at the [`AsRef<[u8]>`]
/// surface — and every borrowed byte-slice comparison surface reads
/// through it. Zero allocation, zero temporary buffer, zero re-validation
/// of the store-path grammar per call.
///
/// # Why the trait peer earns its keep
///
/// The [`AsRef<[u8]>`] peer (line 1563) closes the *read* frontier
/// (`fn f<S: AsRef<[u8]>>` — hasher inputs, wire-writer sinks, generic
/// borrowed-byte-view consumers). [`PartialEq<[u8]>`] closes the disjoint
/// *comparison* frontier at the same byte-slice-shape layer — the surface
/// every byte-stream wire-check / cache-index oracle / round-trip
/// verifier keys off:
///
/// - `sp == *captured_bytes` in a stdout-byte-echo verifier that confirms
///   an `attic push` / `nix copy` argv slot round-tripped the exact bytes
///   forge handed it, without the caller allocating a fresh [`String`]
///   from the captured [`Vec<u8>`] to reach the UTF-8-side peer.
/// - `sp == *cache_key_bytes` in a byte-stream cache-index oracle that
///   keys on the store-path bytes without per-comparison UTF-8 conversion.
/// - Generic [`PartialEq`]-bounded consumers
///   (`fn same_bytes<A, B>(a: A, b: B) -> bool where A: PartialEq<B>`) —
///   a downstream helper that composes a [`StorePath`] with a borrowed
///   `[u8]` key can name the bound without a `where` clause naming both
///   `StorePath: AsRef<[u8]>` and a shim
///   `<StorePath as AsRef<[u8]>>::as_ref(&sp) == raw_bytes` inline.
/// - Sibling canonical-label typed sums in this crate already carry the
///   same forward-direction pair at the borrowed byte-slice comparison
///   frontier: [`impl PartialEq<[u8]> for BumpLevel`] at
///   `cli/src/version.rs:9545`, [`impl PartialEq<[u8]> for PerAttemptRegion`]
///   at `cli/src/retry.rs:8989`, [`impl PartialEq<[u8]> for AdmissionTier`]
///   at `cli/src/probe_outcome.rs:13382`, [`impl PartialEq<[u8]> for DigestAlgorithm`]
///   at `cli/src/oci_manifest.rs:3738`. [`StorePath`] is the store-path
///   primitive counterpart at the same comparison frontier — the
///   borrowed byte-slice comparison axis of this crate's typed
///   primitives now spans the ordered label sums AND the validated-path
///   grammar with ONE canonical-view oracle each.
///
/// # Trimming discipline reaches through
///
/// A [`StorePath`] parsed from a newline-terminated buffer holds the
/// *trimmed* canonical bytes ([`StorePath::parse`] applies `trim` before
/// every grammar clause), so the comparison peer sees the trimmed view —
/// `sp == *b"/nix/store/…-x"` holds for a value parsed from
/// `"/nix/store/…-x\n"`. The comparison peer inherits the discipline the
/// accessor already carries; no per-site
/// `sp.as_str().trim().as_bytes() == …` restatement.
///
/// THEORY.md §III typed primitives: the borrowed byte-slice comparison
/// surface is a typed-primitive site on [`StorePath`] itself (one
/// [`PartialEq<[u8]>`] impl on [`StorePath`] routing through
/// [`<StorePath as AsRef<[u8]>>::as_ref`]), not a per-consumer
/// `<StorePath as AsRef<[u8]>>::as_ref(&sp) == raw_bytes` restatement at
/// every downstream site that asks whether a [`StorePath`] value names
/// the same canonical bytes as an already-borrowed `[u8]` handle.
/// THEORY.md §VI.1 one-oracle: the canonical view is named at one site
/// ([`StorePath::as_str`], projected onto bytes through
/// [`str::as_bytes`] at the [`AsRef<[u8]>`] surface), and every borrowed
/// byte-slice surface — the [`AsRef<[u8]>`] borrowed-view sibling, this
/// [`PartialEq<[u8]>`] answering a boolean equality query — reads
/// through the same one-oracle discipline projected onto its own
/// intent × frontier.
impl PartialEq<[u8]> for StorePath {
    fn eq(&self, other: &[u8]) -> bool {
        <Self as AsRef<[u8]>>::as_ref(self) == other
    }
}

/// Forward-direction borrowed byte-slice comparison peer through a `&[u8]`
/// argument — the receiver-shape sibling of [`PartialEq<[u8]> for StorePath`]
/// directly above, split by receiver shape so the caller writes
/// `sp == &raw_bytes_ref` without the explicit deref at every comparison
/// site. The pair together closes the forward-direction 1×2
/// (receiver-shape) surface on the borrowed byte-slice comparison
/// frontier — the same shape the standard library gives [`Vec<u8>`]
/// through its own [`PartialEq<[u8]> for Vec<u8>`] +
/// [`PartialEq<&[u8]> for Vec<u8>`] pair, and the same shape the sibling
/// canonical-label typed sums already carry
/// ([`impl PartialEq<&[u8]> for BumpLevel`] at `cli/src/version.rs:9591`,
/// [`impl PartialEq<&[u8]> for PerAttemptRegion`] at
/// `cli/src/retry.rs:9033`, [`impl PartialEq<&[u8]> for AdmissionTier`]
/// at `cli/src/probe_outcome.rs:13425`,
/// [`impl PartialEq<&[u8]> for DigestAlgorithm`] at
/// `cli/src/oci_manifest.rs:3809`).
///
/// Delegates through [`<StorePath as AsRef<[u8]>>::as_ref`] composed
/// with the standard-library [`<[u8] as PartialEq<[u8]>>::eq`] on the
/// dereffed `&[u8]` argument, so the comparison reads the same canonical
/// bytes as the receiver-shape sibling and the two-impl pair are
/// structurally indistinguishable at the byte-comparison level.
///
/// The reverse-direction pair
/// (`impl PartialEq<StorePath> for [u8]` +
/// `impl PartialEq<StorePath> for &[u8]`) is a natural follow-on that
/// closes the full 2×2 direction × receiver-shape cross-product on this
/// frontier, matching the closure the sibling canonical-label typed
/// sums (`BumpLevel`, `PerAttemptRegion`) already carry across
/// forward × receiver-shape and reverse × receiver-shape.
impl PartialEq<&[u8]> for StorePath {
    fn eq(&self, other: &&[u8]) -> bool {
        <Self as AsRef<[u8]>>::as_ref(self) == *other
    }
}

/// Reverse-direction borrowed byte-slice comparison peer — the sibling of the
/// forward-direction [`PartialEq<[u8]> for StorePath`] pair above, split by
/// direction so the caller can pick either receiver at the comparison site.
/// Together with the forward-direction pair, this closes the full 2×2
/// (direction × receiver-shape) surface on the borrowed byte-slice comparison
/// frontier of this primitive, matching the standard-library idiom [`Vec<u8>`]
/// carries through its own four-impl closure ([`PartialEq<[u8]> for Vec<u8>`],
/// [`PartialEq<&[u8]> for Vec<u8>`], [`PartialEq<Vec<u8>> for [u8]`], and
/// [`PartialEq<Vec<u8>> for &[u8]`]) and the closure the sibling canonical-
/// label typed sums already carry:
///
/// - `impl PartialEq<BumpLevel> for [u8]` at `cli/src/version.rs:9651`,
/// - `impl PartialEq<PerAttemptRegion> for [u8]` at `cli/src/retry.rs:9112`,
/// - `impl PartialEq<AdmissionTier> for [u8]` at `cli/src/probe_outcome.rs:13548`.
///
/// A downstream caller holding a raw `[u8]` handle and a [`StorePath`] (a
/// captured `Vec<u8>` process-stdout buffer sliced through `[..]` that the
/// caller wants to check against a parsed handle, a `nom` / `winnow` byte-
/// slice scrutinee, a byte-stream cache-index oracle keyed on raw bytes) can
/// write `*raw_bytes == sp` at the comparison site without a per-site
/// `raw_bytes == <StorePath as AsRef<[u8]>>::as_ref(&sp)` restatement, and
/// without a [`std::str::from_utf8`] round trip on the caller's byte handle
/// to reach the UTF-8-side [`PartialEq<StorePath> for str`] reverse-direction
/// peer.
///
/// Delegates through [`<StorePath as AsRef<[u8]>>::as_ref`] (itself
/// [`StorePath::as_str`] composed with [`str::as_bytes`]) and the standard-
/// library [`<[u8] as PartialEq<[u8]>>::eq`] on the `[u8]` self receiver, so
/// the "what canonical bytes does a [`StorePath`] carry?" question stays
/// defined at ONE accessor surface — the inherent [`StorePath::as_str`]
/// projected onto bytes at the [`AsRef<[u8]>`] surface — and every borrowed
/// byte-slice comparison surface (forward-`[u8]`, forward-`&[u8]`,
/// reverse-`[u8]`, reverse-`&[u8]`) reads through it. Zero allocation, zero
/// temporary buffer, zero re-validation of the store-path grammar per call.
///
/// The symmetry axiom
/// `<[u8] as PartialEq<StorePath>>::eq(bytes, &sp)
/// == <StorePath as PartialEq<[u8]>>::eq(&sp, bytes)` at every
/// (bytes, [`StorePath`]) pair holds by construction: both directions factor
/// through the same [`AsRef<[u8]>`] one-oracle projection and the same
/// standard-library [`<[u8] as PartialEq<[u8]>>::eq`] comparison. Pinned at
/// [`tests::test_partial_eq_store_path_bytes_symmetric_with_forward_direction`].
///
/// THEORY.md §III typed primitives: the reverse-direction borrowed byte-slice
/// comparison surface is a typed-primitive site on [`StorePath`] itself (one
/// [`PartialEq<StorePath>`] impl on `[u8]` routing through
/// [`<StorePath as AsRef<[u8]>>::as_ref`]), not a per-consumer
/// `raw_bytes == <StorePath as AsRef<[u8]>>::as_ref(&sp)` restatement at
/// every downstream site that asks whether an already-borrowed `[u8]` handle
/// names the same canonical store-path bytes as a [`StorePath`] value.
/// THEORY.md §VI.1 one-oracle: the canonical view is named at one site
/// ([`StorePath::as_str`], projected onto bytes through [`str::as_bytes`] at
/// the [`AsRef<[u8]>`] surface), and every borrowed byte-slice comparison
/// surface — the forward-direction pair above and this reverse-direction
/// pair — reads through the same one-oracle discipline projected onto its
/// own direction × receiver shape.
impl PartialEq<StorePath> for [u8] {
    fn eq(&self, other: &StorePath) -> bool {
        self == <StorePath as AsRef<[u8]>>::as_ref(other)
    }
}

/// Reverse-direction borrowed byte-slice comparison peer through a `&[u8]`
/// receiver — the receiver-shape sibling of
/// [`PartialEq<StorePath> for [u8]`] directly above, split by receiver
/// shape so the caller writes `bytes_ref == sp` without the explicit `*`
/// deref at every comparison site. The four [`PartialEq`] impls together on
/// the byte-slice frontier — forward × receiver-shape (lines 1925 / 1961)
/// and reverse × receiver-shape (directly above and this impl) — close the
/// borrowed byte-slice comparison surface across the full 2×2 cross-product
/// on the [`StorePath`] typed primitive, matching the four-impl closure the
/// sibling canonical-label typed sums already carry on their own byte
/// frontier ([`impl PartialEq<PerAttemptRegion> for &[u8]`] at
/// `cli/src/retry.rs:9162`, [`impl PartialEq<BumpLevel> for &[u8]`] at
/// `cli/src/version.rs:9700`, [`impl PartialEq<AdmissionTier> for &[u8]`] at
/// `cli/src/probe_outcome.rs:13610`).
///
/// Delegates through [`<StorePath as AsRef<[u8]>>::as_ref`] composed with
/// the standard-library [`<[u8] as PartialEq<[u8]>>::eq`] on the dereffed
/// `&[u8]` self receiver, so the comparison reads the same canonical bytes
/// as the receiver-shape sibling and the two-impl reverse-direction pair are
/// structurally indistinguishable at the byte-comparison level. The symmetry
/// axiom
/// `<&[u8] as PartialEq<StorePath>>::eq(&bytes_ref, &sp)
/// == <StorePath as PartialEq<&[u8]>>::eq(&sp, &bytes_ref)` holds by
/// construction at every `(bytes_ref, sp)` pair, pinned at
/// [`tests::test_partial_eq_store_path_bytes_symmetric_with_forward_direction`].
impl PartialEq<StorePath> for &[u8] {
    fn eq(&self, other: &StorePath) -> bool {
        *self == <StorePath as AsRef<[u8]>>::as_ref(other)
    }
}

/// Forward-direction owned byte-vec comparison peer — the byte-frontier
/// sibling of [`impl PartialEq<String> for StorePath`] (line 1794) that
/// closes the owned-receiver axis on the byte frontier: the same
/// forward-direction × owned-receiver corner the owned UTF-8 pair covers
/// on the UTF-8 frontier, split by frontier so a downstream caller who
/// holds a [`StorePath`] and an owned [`Vec<u8>`] handle (a captured
/// process-stdout buffer held by value from a
/// [`std::process::Output::stdout`] read of `nix-build` / `attic push`
/// argv confirmation, an owned wire-decode result from a byte-stream
/// parser that returned a heap-owned buffer, a fixture-side
/// `assert_eq!(sp, "/nix/store/…-x".to_vec())`) writes `sp == owned_bytes`
/// at the comparison site without a per-site `sp.as_str().as_bytes() ==
/// owned_bytes.as_slice()` restatement, without a `[..]` deref to reach
/// the borrowed `[u8]` receiver peer at line 1925, and without a
/// [`String::from_utf8`] round trip on the caller's byte buffer to reach
/// the owned UTF-8-side [`PartialEq<String>`] peer.
///
/// Delegates through [`<StorePath as AsRef<[u8]>>::as_ref`] composed with
/// [`Vec::as_slice`] and the standard-library [`<[u8] as
/// PartialEq<[u8]>>::eq`], so the "what canonical bytes does a
/// [`StorePath`] carry?" question stays defined at ONE accessor surface
/// — the inherent [`StorePath::as_str`] projected onto bytes at the
/// [`AsRef<[u8]>`] surface — and every byte-slice comparison receiver ×
/// direction × ownership reads through it. Zero allocation, zero
/// temporary buffer, zero re-validation of the store-path grammar per
/// call.
///
/// Together with the reverse-direction sibling
/// [`impl PartialEq<StorePath> for Vec<u8>`] directly below, closes the
/// 2-impl owned-byte-vec × direction closure at the same one-oracle
/// discipline the four-impl borrowed byte-slice closure above
/// (`PartialEq<[u8]>` / `PartialEq<&[u8]>` for [`StorePath`] at lines
/// 1925 / 1961; `PartialEq<StorePath>` for `[u8]` / `&[u8]` at lines
/// 2023 / 2054) and the two-impl owned UTF-8 closure at lines 1794 /
/// 1840 already carry on their own receiver × ownership axes. The four
/// receiver × direction × ownership corners on the byte frontier —
/// borrowed forward, borrowed reverse, owned forward, owned reverse —
/// now match the six corners the UTF-8 frontier carries when the &str
/// receiver-shape sibling is counted.
///
/// THEORY.md §III typed primitives: the forward-direction owned byte-vec
/// comparison surface is a typed-primitive site on [`StorePath`] itself
/// (one [`PartialEq<Vec<u8>>`] impl on [`StorePath`] routing through
/// [`<StorePath as AsRef<[u8]>>::as_ref`] and [`Vec::as_slice`]), not a
/// per-consumer `<StorePath as AsRef<[u8]>>::as_ref(&sp) ==
/// owned_bytes.as_slice()` restatement at every downstream site that
/// asks whether a [`StorePath`] value names the same canonical bytes as
/// a heap-owned [`Vec<u8>`]. THEORY.md §VI.1 one-oracle: the canonical
/// view is named at one site ([`StorePath::as_str`], projected onto
/// bytes through [`str::as_bytes`] at the [`AsRef<[u8]>`] surface), and
/// every byte-slice comparison surface — borrowed forward × receiver,
/// borrowed reverse × receiver, and now this owned forward — reads
/// through the same one-oracle discipline projected onto its own
/// direction × receiver ownership.
impl PartialEq<Vec<u8>> for StorePath {
    fn eq(&self, other: &Vec<u8>) -> bool {
        <Self as AsRef<[u8]>>::as_ref(self) == other.as_slice()
    }
}

/// Reverse-direction owned byte-vec comparison peer — the direction
/// sibling of [`impl PartialEq<Vec<u8>> for StorePath`] directly above,
/// split by direction so the caller writes `owned_bytes == sp` at the
/// comparison site (a fixture-side `assert_eq!(vec![…], sp)`, a
/// wire-echo verifier that reads `captured_bytes == parsed_handle` with
/// the captured buffer on the left, a generic [`PartialEq`]-bounded
/// consumer composed on a [`Vec<u8>`] key against a [`StorePath`]
/// value). Together with the forward-direction sibling this closes the
/// 2-impl owned-byte-vec × direction closure at the same one-oracle
/// discipline the four-impl borrowed byte-slice closure already carries.
///
/// Delegates through [`Vec::as_slice`] composed with [`<StorePath as
/// AsRef<[u8]>>::as_ref`] and the standard-library [`<[u8] as
/// PartialEq<[u8]>>::eq`], so the symmetry axiom
/// `<Vec<u8> as PartialEq<StorePath>>::eq(&owned_bytes, &sp)
/// == <StorePath as PartialEq<Vec<u8>>>::eq(&sp, &owned_bytes)` at every
/// (owned_bytes, sp) pair holds by construction — both directions factor
/// through the same [`AsRef<[u8]>`] one-oracle projection and the same
/// standard-library `[u8]` equality. Pinned at
/// [`tests::test_partial_eq_vec_bytes_store_path_symmetric_with_forward_direction`].
///
/// Extends the reverse-direction receiver frontier the borrowed-byte
/// pair [`impl PartialEq<StorePath> for [u8]`] +
/// [`impl PartialEq<StorePath> for &[u8]`] opened onto the owned-byte
/// axis, mirroring the owned-UTF-8 extension the [`impl PartialEq<StorePath>
/// for String`] peer at line 1840 opened onto the UTF-8 frontier.
///
/// THEORY.md §III typed primitives: the reverse-direction owned byte-vec
/// comparison surface is a typed-primitive site on [`StorePath`] (one
/// [`PartialEq<StorePath>`] impl on [`Vec<u8>`] routing through
/// [`Vec::as_slice`] and [`<StorePath as AsRef<[u8]>>::as_ref`]), not a
/// per-consumer `owned_bytes.as_slice() == <StorePath as
/// AsRef<[u8]>>::as_ref(&sp)` restatement at every downstream comparison
/// site. THEORY.md §VI.1 one-oracle: the canonical view is named at one
/// site ([`StorePath::as_str`], projected onto bytes at the
/// [`AsRef<[u8]>`] surface), and every byte-slice comparison surface —
/// borrowed forward × receiver, borrowed reverse × receiver, owned
/// forward, and this owned reverse — reads through the same one-oracle
/// discipline projected onto its own direction × receiver ownership.
impl PartialEq<StorePath> for Vec<u8> {
    fn eq(&self, other: &StorePath) -> bool {
        self.as_slice() == <StorePath as AsRef<[u8]>>::as_ref(other)
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

    /// [`TryFrom<Arc<str>>`] must accept every input the inherent
    /// [`StorePath::parse`] accepts and produce a value equal to the
    /// [`FromStr`] round-trip on the borrowed view of the same buffer.
    /// Pins the delegation through the [`FromStr`] oracle via
    /// [`Arc::as_ref`]: a future refactor that severed the trait impl from
    /// `<Self as FromStr>::from_str(shared.as_ref())` (e.g., inlined a
    /// `Self::parse` call with a stale grammar clause, or cloned the shared
    /// buffer into a fresh `String` and let the two surfaces drift on
    /// whitespace handling) would fail here first.
    #[test]
    fn test_try_from_arc_str_success_agrees_with_fromstr() {
        use std::sync::Arc;
        let raw = format!("/nix/store/{H}-hello-2.10");
        let via_try_from = <StorePath as TryFrom<Arc<str>>>::try_from(Arc::from(raw.as_str()))
            .expect("valid store path parses via TryFrom<Arc<str>>");
        let via_fromstr: StorePath = raw.parse().expect("valid store path parses via FromStr");
        assert_eq!(
            via_try_from, via_fromstr,
            "TryFrom<Arc<str>> must yield the same StorePath value as FromStr"
        );
        // And a name-with-hyphens case — the load-bearing shape most real
        // store outputs carry — to guard against a future refactor that
        // truncates at the first `-` on the way through the shared peer.
        let raw2 = format!("/nix/store/{H}-foo-bar-1.2.3");
        let via_try_from2 = <StorePath as TryFrom<Arc<str>>>::try_from(Arc::from(raw2.as_str()))
            .expect("hyphenated-name store path parses via TryFrom<Arc<str>>");
        let via_fromstr2: StorePath = raw2
            .parse()
            .expect("hyphenated-name store path parses via FromStr");
        assert_eq!(via_try_from2, via_fromstr2);
        assert_eq!(via_try_from2.name(), "foo-bar-1.2.3");
    }

    /// [`TryFrom<Arc<str>>`] must reject every input the inherent
    /// [`StorePath::parse`] rejects, and must surface the SAME typed
    /// [`StorePathError`] variant carrying the SAME offending input.
    /// Pins that no error-widening shim (`anyhow!(...)`,
    /// `Box<dyn Error>`) hides between the cross-thread shared-owned
    /// try-conversion surface and the inherent constructor — the typed
    /// grammar clause stays legible at the trait entry point even when
    /// the caller holds an atomically refcounted UTF-8 buffer.
    #[test]
    fn test_try_from_arc_str_failure_preserves_typed_error_variant() {
        use std::sync::Arc;
        // Cover every grammar clause once, and cross-check byte-for-byte
        // that the shared-owned try-conversion surface surfaces the SAME
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
            let try_from_err = <StorePath as TryFrom<Arc<str>>>::try_from(Arc::from(*bad))
                .expect_err("malformed store path must fail via TryFrom<Arc<str>>");
            let inherent_err =
                StorePath::parse(bad).expect_err("malformed store path must fail inherently");
            assert_eq!(
                try_from_err, inherent_err,
                "TryFrom<Arc<str>> must surface the same typed error as the inherent constructor for {bad:?}"
            );
            assert!(
                is_expected_variant(&try_from_err),
                "unexpected error variant for {bad:?}: {try_from_err:?}"
            );
        }
    }

    /// A generic `fn f<T: TryFrom<Arc<str>>>` consumer must recover a
    /// valid [`StorePath`] through the trait bound. This is the
    /// structural witness that `StorePath` is genuinely usable at
    /// `TryFrom<Arc<str>>` call sites — the surface that
    /// `#[serde(try_from = "Arc<str>")]`, a `HashMap<Arc<str>, StorePath>`
    /// intern-table populate, and generic cross-thread shared-owned
    /// try-conversion bounds key off. If a future change narrowed the
    /// bound (e.g., gated the impl on a lifetime or trait shape the
    /// generic surface couldn't hit), this test fails at compile time.
    #[test]
    fn test_try_from_arc_str_generic_consumer_recovers_identity() {
        use std::sync::Arc;
        fn parse_via_try_from<T>(s: Arc<str>) -> Result<T, T::Error>
        where
            T: TryFrom<Arc<str>>,
        {
            T::try_from(s)
        }
        let raw = format!("/nix/store/{H}-foo-bar-1.2.3");
        let path: StorePath = parse_via_try_from(Arc::from(raw.as_str()))
            .expect("valid store path parses via generic TryFrom<Arc<str>> bound");
        assert_eq!(path.name(), "foo-bar-1.2.3");
        assert_eq!(path.hash(), H);
        // The trimming discipline reaches through the generic bound too:
        // a caller that holds a nix-build-stdout Arc<str> handed across
        // worker threads does not need to pre-trim before handing it to
        // the generic try-conversion helper — the grammar owns the trim
        // in one place.
        let raw_nl = format!("/nix/store/{H}-x\n");
        let trimmed: StorePath = parse_via_try_from(Arc::from(raw_nl.as_str()))
            .expect("trailing newline must be trimmed at TryFrom<Arc<str>> surface");
        assert_eq!(trimmed.as_str(), format!("/nix/store/{H}-x"));
    }

    /// [`TryFrom<Rc<str>>`] must accept every input the inherent
    /// [`StorePath::parse`] accepts and produce a value equal to the
    /// [`FromStr`] round-trip on the borrowed view of the same buffer.
    /// Pins the delegation through the [`FromStr`] oracle via
    /// [`Rc::as_ref`]: a future refactor that severed the trait impl from
    /// `<Self as FromStr>::from_str(shared.as_ref())` (e.g., inlined a
    /// `Self::parse` call with a stale grammar clause, or cloned the shared
    /// buffer into a fresh `String` and let the two surfaces drift on
    /// whitespace handling) would fail here first.
    #[test]
    fn test_try_from_rc_str_success_agrees_with_fromstr() {
        use std::rc::Rc;
        let raw = format!("/nix/store/{H}-hello-2.10");
        let via_try_from = <StorePath as TryFrom<Rc<str>>>::try_from(Rc::from(raw.as_str()))
            .expect("valid store path parses via TryFrom<Rc<str>>");
        let via_fromstr: StorePath = raw.parse().expect("valid store path parses via FromStr");
        assert_eq!(
            via_try_from, via_fromstr,
            "TryFrom<Rc<str>> must yield the same StorePath value as FromStr"
        );
        // And a name-with-hyphens case — the load-bearing shape most real
        // store outputs carry — to guard against a future refactor that
        // truncates at the first `-` on the way through the shared peer.
        let raw2 = format!("/nix/store/{H}-foo-bar-1.2.3");
        let via_try_from2 = <StorePath as TryFrom<Rc<str>>>::try_from(Rc::from(raw2.as_str()))
            .expect("hyphenated-name store path parses via TryFrom<Rc<str>>");
        let via_fromstr2: StorePath = raw2
            .parse()
            .expect("hyphenated-name store path parses via FromStr");
        assert_eq!(via_try_from2, via_fromstr2);
        assert_eq!(via_try_from2.name(), "foo-bar-1.2.3");
    }

    /// [`TryFrom<Rc<str>>`] must reject every input the inherent
    /// [`StorePath::parse`] rejects, and must surface the SAME typed
    /// [`StorePathError`] variant carrying the SAME offending input.
    /// Pins that no error-widening shim (`anyhow!(...)`,
    /// `Box<dyn Error>`) hides between the thread-local shared-owned
    /// try-conversion surface and the inherent constructor — the typed
    /// grammar clause stays legible at the trait entry point even when
    /// the caller holds a non-atomically refcounted UTF-8 buffer.
    #[test]
    fn test_try_from_rc_str_failure_preserves_typed_error_variant() {
        use std::rc::Rc;
        // Cover every grammar clause once, and cross-check byte-for-byte
        // that the thread-local shared-owned try-conversion surface
        // surfaces the SAME typed error variant (with the SAME offending
        // input in each variant) as the inherent constructor. Pin against
        // a future refactor that silently coerced one variant into another
        // or widened the error to `anyhow::Error`.
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
            let try_from_err = <StorePath as TryFrom<Rc<str>>>::try_from(Rc::from(*bad))
                .expect_err("malformed store path must fail via TryFrom<Rc<str>>");
            let inherent_err =
                StorePath::parse(bad).expect_err("malformed store path must fail inherently");
            assert_eq!(
                try_from_err, inherent_err,
                "TryFrom<Rc<str>> must surface the same typed error as the inherent constructor for {bad:?}"
            );
            assert!(
                is_expected_variant(&try_from_err),
                "unexpected error variant for {bad:?}: {try_from_err:?}"
            );
        }
    }

    /// A generic `fn f<T: TryFrom<Rc<str>>>` consumer must recover a
    /// valid [`StorePath`] through the trait bound. This is the
    /// structural witness that `StorePath` is genuinely usable at
    /// `TryFrom<Rc<str>>` call sites — the surface that
    /// `#[serde(try_from = "Rc<str>")]`, a `HashMap<Rc<str>, StorePath>`
    /// single-thread intern-table populate, and generic thread-local
    /// shared-owned try-conversion bounds key off. If a future change
    /// narrowed the bound (e.g., gated the impl on a lifetime or trait
    /// shape the generic surface couldn't hit), this test fails at
    /// compile time.
    #[test]
    fn test_try_from_rc_str_generic_consumer_recovers_identity() {
        use std::rc::Rc;
        fn parse_via_try_from<T>(s: Rc<str>) -> Result<T, T::Error>
        where
            T: TryFrom<Rc<str>>,
        {
            T::try_from(s)
        }
        let raw = format!("/nix/store/{H}-foo-bar-1.2.3");
        let path: StorePath = parse_via_try_from(Rc::from(raw.as_str()))
            .expect("valid store path parses via generic TryFrom<Rc<str>> bound");
        assert_eq!(path.name(), "foo-bar-1.2.3");
        assert_eq!(path.hash(), H);
        // The trimming discipline reaches through the generic bound too:
        // a caller that holds a nix-build-stdout Rc<str> shared among
        // single-thread sibling readers does not need to pre-trim before
        // handing it to the generic try-conversion helper — the grammar
        // owns the trim in one place.
        let raw_nl = format!("/nix/store/{H}-x\n");
        let trimmed: StorePath = parse_via_try_from(Rc::from(raw_nl.as_str()))
            .expect("trailing newline must be trimmed at TryFrom<Rc<str>> surface");
        assert_eq!(trimmed.as_str(), format!("/nix/store/{H}-x"));
    }

    /// The [`TryFrom<&[u8]>`] byte-slice parse peer must agree with the
    /// inherent [`StorePath::parse`] oracle on valid canonical bytes at
    /// both the plain hyphenated-name case and the newline-terminated
    /// trimming case — the trimming discipline reaches through the
    /// byte-slice frontier, so a caller capturing
    /// [`std::process::Output::stdout`] as [`Vec<u8>`] does not need to
    /// pre-trim before handing the [`&[u8]`] to the peer.
    #[test]
    fn test_try_from_bytes_success_agrees_with_fromstr() {
        let raw = format!("/nix/store/{H}-hello-2.10");
        let via_bytes = StorePath::try_from(raw.as_bytes())
            .expect("valid store-path bytes must parse via TryFrom<&[u8]>");
        let via_str: StorePath = raw.parse().unwrap();
        assert_eq!(via_bytes, via_str);
        assert_eq!(via_bytes.hash(), H);
        assert_eq!(via_bytes.name(), "hello-2.10");

        let raw_nl = format!("/nix/store/{H}-x\n");
        let trimmed = StorePath::try_from(raw_nl.as_bytes())
            .expect("trailing newline must be trimmed at TryFrom<&[u8]> surface");
        assert_eq!(trimmed.as_str(), format!("/nix/store/{H}-x"));
    }

    /// A non-UTF-8 byte sequence must reject at the UTF-8 decode gate with
    /// the new [`StorePathError::NonUtf8Bytes`] variant BEFORE any grammar
    /// clause is evaluated. The variant must preserve the offending bytes
    /// and the underlying [`std::str::Utf8Error`] under
    /// [`std::error::Error::source`], so a Phase 1 attestation record
    /// (THEORY §V.4) can attach both to the failure without re-decoding to
    /// recover the invalid-sequence offset.
    #[test]
    fn test_try_from_bytes_rejects_non_utf8_input() {
        use std::error::Error as _;
        // 0xFF is never valid as a UTF-8 leading byte; the buffer starts
        // with a valid store-path prefix so the rejection is proven to
        // fire at the UTF-8 gate, not at the grammar oracle.
        let mut buf: Vec<u8> = b"/nix/store/".to_vec();
        buf.push(0xFF);
        buf.extend_from_slice(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x");
        let err = StorePath::try_from(buf.as_slice())
            .expect_err("non-UTF-8 bytes must reject at TryFrom<&[u8]>");
        match &err {
            StorePathError::NonUtf8Bytes { bytes, source: _ } => {
                assert_eq!(
                    bytes.as_slice(),
                    buf.as_slice(),
                    "the offending bytes must survive verbatim on the failure record"
                );
            }
            other => panic!("expected NonUtf8Bytes, got: {other:?}"),
        }
        // The underlying std::str::Utf8Error must be reachable through the
        // Error::source chain — no re-decoding, no display-string parsing.
        let src = err.source().expect("NonUtf8Bytes must carry a source");
        assert!(
            src.downcast_ref::<std::str::Utf8Error>().is_some(),
            "source must downcast to std::str::Utf8Error, got display: {src}",
        );
        // The Display impl must name the source diagnostic without
        // eliding the offending bytes — the lossy-decoded rendering
        // preserves the surrounding valid bytes for readability.
        let display = err.to_string();
        assert!(
            display.contains("not valid UTF-8"),
            "Display must name the UTF-8 rejection: {display}"
        );
    }

    /// Valid UTF-8 bytes that decode to a non-store-path string must
    /// reject at the underlying [`FromStr`] impl with the exact
    /// grammar-clause variant the input violated — the two-stage
    /// strictness contract: UTF-8 decode gate first, grammar oracle
    /// second. Pins that the byte-slice peer routes rejection through
    /// the one grammar oracle at [`StorePath::parse`] rather than a
    /// divergent second parse path.
    #[test]
    fn test_try_from_bytes_rejects_non_canonical_input() {
        // `/nix/store/short` is valid UTF-8 but too short to hold a 32-
        // char hash — the exact grammar clause `StorePathError::TooShort`
        // discriminates.
        let err = StorePath::try_from(b"/nix/store/short".as_slice())
            .expect_err("non-canonical UTF-8 bytes must reject");
        assert!(
            matches!(err, StorePathError::TooShort { .. }),
            "expected TooShort, got: {err:?}"
        );
        // A relative-path input must fire `MissingStorePrefix`, not
        // `NonUtf8Bytes` — the UTF-8 gate cleared, so the grammar
        // oracle owns the rejection.
        let err = StorePath::try_from(b"relative/path".as_slice())
            .expect_err("relative-path bytes must reject");
        assert!(
            matches!(err, StorePathError::MissingStorePrefix { .. }),
            "expected MissingStorePrefix, got: {err:?}"
        );
    }

    /// A generic `fn f<T: for<'a> TryFrom<&'a [u8]>>` consumer must
    /// accept a borrowed byte slice and recover a validated
    /// [`StorePath`] through the trait bound. This is the structural
    /// witness that [`StorePath`] is genuinely usable at
    /// [`TryFrom<&[u8]>`] call sites — the surface a downstream serde
    /// container attribute (`#[serde(try_from = "&[u8]")]`) or a
    /// process-output capture pipeline reading
    /// [`std::process::Output::stdout`] as [`Vec<u8>`] keys off. If a
    /// future change narrowed the bound or the error type, this test
    /// fails at compile time.
    #[test]
    fn test_try_from_bytes_generic_consumer_recovers_identity() {
        fn parse_via_try_from<'a, T>(bytes: &'a [u8]) -> Result<T, T::Error>
        where
            T: TryFrom<&'a [u8]>,
        {
            T::try_from(bytes)
        }
        let raw = format!("/nix/store/{H}-foo-bar-1.2.3");
        let path: StorePath = parse_via_try_from(raw.as_bytes())
            .expect("valid store-path bytes must parse via generic TryFrom<&[u8]> bound");
        assert_eq!(path.name(), "foo-bar-1.2.3");
        assert_eq!(path.hash(), H);
        // The trimming discipline reaches through the generic bound too:
        // a caller capturing raw stdout bytes does not need to pre-trim
        // before handing them to the generic try-conversion helper — the
        // grammar owns the trim in one place.
        let raw_nl = format!("/nix/store/{H}-x\n");
        let trimmed: StorePath = parse_via_try_from(raw_nl.as_bytes())
            .expect("trailing newline must be trimmed at generic TryFrom<&[u8]> bound");
        assert_eq!(trimmed.as_str(), format!("/nix/store/{H}-x"));
    }

    /// The [`TryFrom<Vec<u8>>`] owned-byte-slice parse peer must agree
    /// with the inherent [`StorePath::parse`] oracle AND with its
    /// by-reference sibling [`TryFrom<&[u8]>`] on valid canonical bytes
    /// at both the plain hyphenated-name case and the newline-terminated
    /// trimming case. The trimming discipline reaches through the
    /// owned-byte frontier, so a caller consuming a
    /// [`std::process::Output::stdout`] [`Vec<u8>`] by value does not
    /// need to pre-trim before handing the [`Vec<u8>`] to the peer.
    /// Pins the delegate-through-[`String::from_utf8`]-then-[`FromStr`]
    /// discipline: parse at [`TryFrom<Vec<u8>>`] tracks parse at both
    /// the sibling [`TryFrom<&[u8]>`] peer and the inherent
    /// [`StorePath::parse`] oracle byte-for-byte at every canonical
    /// input, so a future regression that reroutes the owned-byte arm
    /// away from the shared oracle (an in-place `match` that drifts an
    /// arm's variant assignment, an accepted-label set that widens
    /// beyond the canonical grammar) lights up here rather than
    /// silently at downstream call sites.
    #[test]
    fn test_try_from_vec_bytes_success_agrees_with_fromstr() {
        let raw = format!("/nix/store/{H}-hello-2.10");
        let via_vec = StorePath::try_from(raw.as_bytes().to_vec())
            .expect("valid store-path bytes must parse via TryFrom<Vec<u8>>");
        let via_str: StorePath = raw.parse().unwrap();
        let via_slice = StorePath::try_from(raw.as_bytes())
            .expect("valid store-path bytes must parse via TryFrom<&[u8]>");
        assert_eq!(via_vec, via_str);
        assert_eq!(
            via_vec, via_slice,
            "TryFrom<Vec<u8>> and TryFrom<&[u8]> must agree on canonical bytes"
        );
        assert_eq!(via_vec.hash(), H);
        assert_eq!(via_vec.name(), "hello-2.10");

        let raw_nl = format!("/nix/store/{H}-x\n");
        let trimmed = StorePath::try_from(raw_nl.as_bytes().to_vec())
            .expect("trailing newline must be trimmed at TryFrom<Vec<u8>> surface");
        assert_eq!(trimmed.as_str(), format!("/nix/store/{H}-x"));
        let trimmed_slice = StorePath::try_from(raw_nl.as_bytes())
            .expect("trailing newline must be trimmed at TryFrom<&[u8]> surface");
        assert_eq!(
            trimmed, trimmed_slice,
            "TryFrom<Vec<u8>> and TryFrom<&[u8]> must agree on trimmed canonical bytes"
        );
    }

    /// A non-UTF-8 owned byte sequence must reject at the
    /// [`String::from_utf8`] decode gate with the
    /// [`StorePathError::NonUtf8Bytes`] variant BEFORE any grammar
    /// clause is evaluated. The variant must preserve the offending
    /// bytes recovered through
    /// [`std::string::FromUtf8Error::into_bytes`] verbatim (no
    /// intermediate [`.to_vec()`] clone the by-reference peer's
    /// `bytes.to_vec()` would otherwise force on the owned arm) and the
    /// underlying [`std::str::Utf8Error`] under
    /// [`std::error::Error::source`], so a Phase 1 attestation record
    /// (THEORY §V.4) can attach both to the failure without re-decoding
    /// to recover the invalid-sequence offset.
    #[test]
    fn test_try_from_vec_bytes_rejects_non_utf8_input() {
        use std::error::Error as _;
        // 0xFF is never valid as a UTF-8 leading byte; the buffer starts
        // with a valid store-path prefix so the rejection is proven to
        // fire at the UTF-8 gate, not at the grammar oracle.
        let mut buf: Vec<u8> = b"/nix/store/".to_vec();
        buf.push(0xFF);
        buf.extend_from_slice(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x");
        let expected_bytes = buf.clone();
        let err =
            StorePath::try_from(buf).expect_err("non-UTF-8 bytes must reject at TryFrom<Vec<u8>>");
        match &err {
            StorePathError::NonUtf8Bytes { bytes, source: _ } => {
                assert_eq!(
                    bytes.as_slice(),
                    expected_bytes.as_slice(),
                    "the offending bytes must survive verbatim on the failure record"
                );
            }
            other => panic!("expected NonUtf8Bytes, got: {other:?}"),
        }
        // The underlying std::str::Utf8Error must be reachable through the
        // Error::source chain — no re-decoding, no display-string parsing.
        let src = err.source().expect("NonUtf8Bytes must carry a source");
        assert!(
            src.downcast_ref::<std::str::Utf8Error>().is_some(),
            "source must downcast to std::str::Utf8Error, got display: {src}",
        );
        // The Display impl must name the source diagnostic without
        // eliding the offending bytes.
        let display = err.to_string();
        assert!(
            display.contains("not valid UTF-8"),
            "Display must name the UTF-8 rejection: {display}"
        );
        // Agreement with the by-reference peer: the same rejection must
        // fire at both surfaces so a caller switching from
        // TryFrom<&[u8]> to TryFrom<Vec<u8>> reads the same typed error
        // variant with the same offending-bytes payload.
        let err_slice = StorePath::try_from(expected_bytes.as_slice())
            .expect_err("non-UTF-8 bytes must reject at TryFrom<&[u8]>");
        assert_eq!(
            err, err_slice,
            "TryFrom<Vec<u8>> and TryFrom<&[u8]> must emit byte-identical NonUtf8Bytes rejection"
        );
    }

    /// Valid UTF-8 owned bytes that decode to a non-store-path string
    /// must reject at the underlying [`FromStr`] impl with the exact
    /// grammar-clause variant the input violated — the two-stage
    /// strictness contract: UTF-8 decode gate first, grammar oracle
    /// second. Pins that the owned-byte peer routes rejection through
    /// the one grammar oracle at [`StorePath::parse`] rather than a
    /// divergent second parse path, and that rejection at
    /// [`TryFrom<Vec<u8>>`] tracks rejection at [`TryFrom<&[u8]>`]
    /// variant-for-variant at every reject-set element once UTF-8
    /// validation clears.
    #[test]
    fn test_try_from_vec_bytes_rejects_non_canonical_input() {
        // `/nix/store/short` is valid UTF-8 but too short to hold a 32-
        // char hash — the exact grammar clause `StorePathError::TooShort`
        // discriminates.
        let err = StorePath::try_from(b"/nix/store/short".to_vec())
            .expect_err("non-canonical UTF-8 bytes must reject");
        assert!(
            matches!(err, StorePathError::TooShort { .. }),
            "expected TooShort, got: {err:?}"
        );
        let err_slice = StorePath::try_from(b"/nix/store/short".as_slice())
            .expect_err("non-canonical UTF-8 bytes must reject at TryFrom<&[u8]>");
        assert_eq!(
            err, err_slice,
            "TryFrom<Vec<u8>> and TryFrom<&[u8]> must agree on grammar-clause rejection"
        );

        // A relative-path input must fire `MissingStorePrefix`, not
        // `NonUtf8Bytes` — the UTF-8 gate cleared, so the grammar
        // oracle owns the rejection.
        let err = StorePath::try_from(b"relative/path".to_vec())
            .expect_err("relative-path bytes must reject");
        assert!(
            matches!(err, StorePathError::MissingStorePrefix { .. }),
            "expected MissingStorePrefix, got: {err:?}"
        );
    }

    /// A generic `fn f<T: TryFrom<Vec<u8>>>` consumer must accept an
    /// owned byte buffer and recover a validated [`StorePath`] through
    /// the trait bound. This is the structural witness that
    /// [`StorePath`] is genuinely usable at [`TryFrom<Vec<u8>>`] call
    /// sites — the surface a downstream serde container attribute
    /// (`#[serde(try_from = "Vec<u8>")]`), an
    /// [`std::io::Read::read_to_end`] pipeline terminus that hands an
    /// owned buffer to a typed parser, and a `bytes::Bytes::to_vec`
    /// round-trip point at the async HTTP-body / registry-response
    /// frontier all key off. If a future change narrowed the bound or
    /// the error type, this test fails at compile time.
    #[test]
    fn test_try_from_vec_bytes_generic_consumer_recovers_identity() {
        fn parse_via_try_from<T>(bytes: Vec<u8>) -> Result<T, T::Error>
        where
            T: TryFrom<Vec<u8>>,
        {
            T::try_from(bytes)
        }
        let raw = format!("/nix/store/{H}-foo-bar-1.2.3");
        let path: StorePath = parse_via_try_from(raw.as_bytes().to_vec())
            .expect("valid store-path bytes must parse via generic TryFrom<Vec<u8>> bound");
        assert_eq!(path.name(), "foo-bar-1.2.3");
        assert_eq!(path.hash(), H);
        // The trimming discipline reaches through the generic bound too:
        // a caller consuming a raw stdout Vec<u8> by value does not need
        // to pre-trim before handing it to the generic try-conversion
        // helper — the grammar owns the trim in one place.
        let raw_nl = format!("/nix/store/{H}-x\n");
        let trimmed: StorePath = parse_via_try_from(raw_nl.as_bytes().to_vec())
            .expect("trailing newline must be trimmed at generic TryFrom<Vec<u8>> bound");
        assert_eq!(trimmed.as_str(), format!("/nix/store/{H}-x"));
    }

    /// [`TryFrom<Box<[u8]>>`] must accept every input the inherent
    /// [`StorePath::parse`] accepts and produce a value equal to the
    /// [`FromStr`] round-trip on the borrowed view of the same buffer,
    /// AND cross-agree byte-for-byte with the sibling [`TryFrom<Vec<u8>>`]
    /// and [`TryFrom<&[u8]>`] peers on the same canonical bytes. Pins the
    /// delegation through `<Self as TryFrom<Vec<u8>>>::try_from(Vec::from(boxed))`:
    /// a future refactor that severed the trait impl from the shared
    /// [`Vec<u8>`] entry point (e.g., inlined a `Self::parse` call with a
    /// stale grammar clause, or cloned the boxed byte buffer into a fresh
    /// [`String`] and let the two surfaces drift on whitespace handling)
    /// would fail here first.
    #[test]
    fn test_try_from_box_bytes_success_agrees_with_fromstr() {
        let raw = format!("/nix/store/{H}-hello-2.10");
        let boxed: Box<[u8]> = raw.as_bytes().to_vec().into_boxed_slice();
        let via_box = <StorePath as TryFrom<Box<[u8]>>>::try_from(boxed)
            .expect("valid store-path bytes must parse via TryFrom<Box<[u8]>>");
        let via_str: StorePath = raw.parse().unwrap();
        let via_vec = StorePath::try_from(raw.as_bytes().to_vec())
            .expect("valid store-path bytes must parse via TryFrom<Vec<u8>>");
        let via_slice = StorePath::try_from(raw.as_bytes())
            .expect("valid store-path bytes must parse via TryFrom<&[u8]>");
        assert_eq!(via_box, via_str);
        assert_eq!(
            via_box, via_vec,
            "TryFrom<Box<[u8]>> and TryFrom<Vec<u8>> must agree on canonical bytes"
        );
        assert_eq!(
            via_box, via_slice,
            "TryFrom<Box<[u8]>> and TryFrom<&[u8]> must agree on canonical bytes"
        );
        assert_eq!(via_box.hash(), H);
        assert_eq!(via_box.name(), "hello-2.10");

        let raw_nl = format!("/nix/store/{H}-x\n");
        let boxed_nl: Box<[u8]> = raw_nl.as_bytes().to_vec().into_boxed_slice();
        let trimmed = <StorePath as TryFrom<Box<[u8]>>>::try_from(boxed_nl)
            .expect("trailing newline must be trimmed at TryFrom<Box<[u8]>> surface");
        assert_eq!(trimmed.as_str(), format!("/nix/store/{H}-x"));
        let trimmed_vec = StorePath::try_from(raw_nl.as_bytes().to_vec())
            .expect("trailing newline must be trimmed at TryFrom<Vec<u8>> surface");
        assert_eq!(
            trimmed, trimmed_vec,
            "TryFrom<Box<[u8]>> and TryFrom<Vec<u8>> must agree on trimmed canonical bytes"
        );
    }

    /// A non-UTF-8 [`Box<[u8]>`] must reject at the [`String::from_utf8`]
    /// decode gate reached through the [`TryFrom<Vec<u8>>`] delegation
    /// with the [`StorePathError::NonUtf8Bytes`] variant BEFORE any
    /// grammar clause is evaluated. The rejection must be byte-identical
    /// to the sibling [`TryFrom<Vec<u8>>`] and [`TryFrom<&[u8]>`] peers'
    /// rejection on the same input, so a caller switching between the
    /// three byte receiver shapes reads the same typed error variant with
    /// the same offending-bytes payload — and the source is reachable
    /// through the [`std::error::Error::source`] chain without re-decoding.
    #[test]
    fn test_try_from_box_bytes_rejects_non_utf8_input() {
        use std::error::Error as _;
        // 0xFF is never valid as a UTF-8 leading byte; the buffer starts
        // with a valid store-path prefix so the rejection is proven to
        // fire at the UTF-8 gate, not at the grammar oracle.
        let mut buf: Vec<u8> = b"/nix/store/".to_vec();
        buf.push(0xFF);
        buf.extend_from_slice(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x");
        let expected_bytes = buf.clone();
        let boxed: Box<[u8]> = buf.into_boxed_slice();
        let err = <StorePath as TryFrom<Box<[u8]>>>::try_from(boxed)
            .expect_err("non-UTF-8 bytes must reject at TryFrom<Box<[u8]>>");
        match &err {
            StorePathError::NonUtf8Bytes { bytes, source: _ } => {
                assert_eq!(
                    bytes.as_slice(),
                    expected_bytes.as_slice(),
                    "the offending bytes must survive verbatim on the failure record"
                );
            }
            other => panic!("expected NonUtf8Bytes, got: {other:?}"),
        }
        // The underlying std::str::Utf8Error must be reachable through the
        // Error::source chain — no re-decoding, no display-string parsing.
        let src = err.source().expect("NonUtf8Bytes must carry a source");
        assert!(
            src.downcast_ref::<std::str::Utf8Error>().is_some(),
            "source must downcast to std::str::Utf8Error, got display: {src}",
        );
        // Agreement with the sibling owned-byte and by-reference peers:
        // the same rejection must fire at all three surfaces so a caller
        // switching between them reads the same typed error variant with
        // the same offending-bytes payload.
        let err_vec = StorePath::try_from(expected_bytes.clone())
            .expect_err("non-UTF-8 bytes must reject at TryFrom<Vec<u8>>");
        let err_slice = StorePath::try_from(expected_bytes.as_slice())
            .expect_err("non-UTF-8 bytes must reject at TryFrom<&[u8]>");
        assert_eq!(
            err, err_vec,
            "TryFrom<Box<[u8]>> and TryFrom<Vec<u8>> must emit byte-identical NonUtf8Bytes rejection"
        );
        assert_eq!(
            err, err_slice,
            "TryFrom<Box<[u8]>> and TryFrom<&[u8]> must emit byte-identical NonUtf8Bytes rejection"
        );
    }

    /// Valid UTF-8 boxed bytes that decode to a non-store-path string
    /// must reject at the underlying [`FromStr`] impl with the exact
    /// grammar-clause variant the input violated — the two-stage
    /// strictness contract: UTF-8 decode gate first, grammar oracle
    /// second. Pins that the shrunk-owned-byte peer routes rejection
    /// through the ONE grammar oracle at [`StorePath::parse`] rather
    /// than a divergent second parse path, and that rejection at
    /// [`TryFrom<Box<[u8]>>`] tracks rejection at [`TryFrom<Vec<u8>>`]
    /// and [`TryFrom<&[u8]>`] variant-for-variant at every reject-set
    /// element once UTF-8 validation clears.
    #[test]
    fn test_try_from_box_bytes_rejects_non_canonical_input() {
        // `/nix/store/short` is valid UTF-8 but too short to hold a 32-
        // char hash — the exact grammar clause `StorePathError::TooShort`
        // discriminates.
        let boxed: Box<[u8]> = b"/nix/store/short".to_vec().into_boxed_slice();
        let err = <StorePath as TryFrom<Box<[u8]>>>::try_from(boxed)
            .expect_err("non-canonical UTF-8 bytes must reject at TryFrom<Box<[u8]>>");
        assert!(
            matches!(err, StorePathError::TooShort { .. }),
            "expected TooShort, got: {err:?}"
        );
        let err_vec = StorePath::try_from(b"/nix/store/short".to_vec())
            .expect_err("non-canonical UTF-8 bytes must reject at TryFrom<Vec<u8>>");
        assert_eq!(
            err, err_vec,
            "TryFrom<Box<[u8]>> and TryFrom<Vec<u8>> must agree on grammar-clause rejection"
        );

        // A relative-path input must fire `MissingStorePrefix`, not
        // `NonUtf8Bytes` — the UTF-8 gate cleared, so the grammar
        // oracle owns the rejection.
        let boxed_rel: Box<[u8]> = b"relative/path".to_vec().into_boxed_slice();
        let err = <StorePath as TryFrom<Box<[u8]>>>::try_from(boxed_rel)
            .expect_err("relative-path bytes must reject at TryFrom<Box<[u8]>>");
        assert!(
            matches!(err, StorePathError::MissingStorePrefix { .. }),
            "expected MissingStorePrefix, got: {err:?}"
        );
    }

    /// A generic `fn f<T: TryFrom<Box<[u8]>>>` consumer must accept a
    /// shrunk-owned byte buffer and recover a validated [`StorePath`]
    /// through the trait bound. Structural witness that [`StorePath`] is
    /// genuinely usable at [`TryFrom<Box<[u8]>>`] call sites — the surface
    /// a `#[serde(try_from = "Box<[u8]>")]` container attribute and any
    /// generic shrunk-owned byte try-conversion helper both key off. If a
    /// future change narrowed the bound or the error type, this test
    /// fails at compile time.
    #[test]
    fn test_try_from_box_bytes_generic_consumer_recovers_identity() {
        fn parse_via_try_from<T>(bytes: Box<[u8]>) -> Result<T, T::Error>
        where
            T: TryFrom<Box<[u8]>>,
        {
            T::try_from(bytes)
        }
        let raw = format!("/nix/store/{H}-foo-bar-1.2.3");
        let boxed: Box<[u8]> = raw.as_bytes().to_vec().into_boxed_slice();
        let path: StorePath = parse_via_try_from(boxed)
            .expect("valid store-path bytes must parse via generic TryFrom<Box<[u8]>> bound");
        assert_eq!(path.name(), "foo-bar-1.2.3");
        assert_eq!(path.hash(), H);
        // The trimming discipline reaches through the generic bound too:
        // a caller consuming a `Vec::into_boxed_slice`-terminated buffer
        // does not need to pre-trim before handing it to the generic
        // try-conversion helper — the grammar owns the trim in one place.
        let raw_nl = format!("/nix/store/{H}-x\n");
        let boxed_nl: Box<[u8]> = raw_nl.as_bytes().to_vec().into_boxed_slice();
        let trimmed: StorePath = parse_via_try_from(boxed_nl)
            .expect("trailing newline must be trimmed at generic TryFrom<Box<[u8]>> bound");
        assert_eq!(trimmed.as_str(), format!("/nix/store/{H}-x"));
    }

    /// [`TryFrom<Cow<'_, [u8]>>`] must accept every input the inherent
    /// [`StorePath::parse`] accepts through both the borrowed and owned
    /// arms of the [`std::borrow::Cow`] discriminant, and produce a value
    /// equal to the [`FromStr`] round-trip on the same buffer AND
    /// cross-agree byte-for-byte with the sibling [`TryFrom<&[u8]>`] and
    /// [`TryFrom<Vec<u8>>`] peers on the same canonical bytes. Pins the
    /// arm-match delegation: a future refactor that fused the two arms
    /// into a single `.into_owned()` pre-normalisation (widening the
    /// borrowed fast path onto a redundant owned allocation) or diverged
    /// the two arms onto a stale grammar would fail here first.
    #[test]
    fn test_try_from_cow_bytes_success_agrees_with_fromstr() {
        let raw = format!("/nix/store/{H}-hello-2.10");
        let bytes = raw.as_bytes();
        let via_borrowed = <StorePath as TryFrom<std::borrow::Cow<'_, [u8]>>>::try_from(
            std::borrow::Cow::Borrowed(bytes),
        )
        .expect("valid store-path bytes must parse via TryFrom<Cow::Borrowed>");
        let via_owned = <StorePath as TryFrom<std::borrow::Cow<'_, [u8]>>>::try_from(
            std::borrow::Cow::Owned(bytes.to_vec()),
        )
        .expect("valid store-path bytes must parse via TryFrom<Cow::Owned>");
        let via_str: StorePath = raw.parse().unwrap();
        let via_slice = StorePath::try_from(bytes)
            .expect("valid store-path bytes must parse via TryFrom<&[u8]>");
        let via_vec = StorePath::try_from(bytes.to_vec())
            .expect("valid store-path bytes must parse via TryFrom<Vec<u8>>");
        assert_eq!(via_borrowed, via_str);
        assert_eq!(via_owned, via_str);
        assert_eq!(
            via_borrowed, via_slice,
            "TryFrom<Cow::Borrowed> must agree with TryFrom<&[u8]> on canonical bytes"
        );
        assert_eq!(
            via_owned, via_vec,
            "TryFrom<Cow::Owned> must agree with TryFrom<Vec<u8>> on canonical bytes"
        );
        assert_eq!(via_borrowed, via_owned);
        assert_eq!(via_borrowed.hash(), H);
        assert_eq!(via_borrowed.name(), "hello-2.10");

        // Trimming discipline reaches through both arms of the peer: a
        // newline-terminated buffer parses cleanly whether wrapped
        // borrowed or owned, and both arms produce the trimmed canonical
        // representation.
        let raw_nl = format!("/nix/store/{H}-x\n");
        let trimmed_borrowed = <StorePath as TryFrom<std::borrow::Cow<'_, [u8]>>>::try_from(
            std::borrow::Cow::Borrowed(raw_nl.as_bytes()),
        )
        .expect("trailing newline must be trimmed at TryFrom<Cow::Borrowed> surface");
        let trimmed_owned = <StorePath as TryFrom<std::borrow::Cow<'_, [u8]>>>::try_from(
            std::borrow::Cow::Owned(raw_nl.as_bytes().to_vec()),
        )
        .expect("trailing newline must be trimmed at TryFrom<Cow::Owned> surface");
        assert_eq!(trimmed_borrowed.as_str(), format!("/nix/store/{H}-x"));
        assert_eq!(
            trimmed_borrowed, trimmed_owned,
            "both Cow arms must agree on trimmed canonical bytes"
        );
    }

    /// A non-UTF-8 byte sequence must reject at the UTF-8 decode gate
    /// with the [`StorePathError::NonUtf8Bytes`] variant BEFORE any
    /// grammar clause is evaluated, on both arms of the [`Cow`] match.
    /// The rejection must be byte-identical across the borrowed and
    /// owned arms on the same input, and byte-identical to the sibling
    /// [`TryFrom<&[u8]>`] and [`TryFrom<Vec<u8>>`] peers' rejection on
    /// the same input — a caller switching between the four byte
    /// receiver shapes reads the same typed error variant with the same
    /// offending-bytes payload.
    #[test]
    fn test_try_from_cow_bytes_rejects_non_utf8_input() {
        use std::error::Error as _;
        // 0xFF is never valid as a UTF-8 leading byte; the buffer starts
        // with a valid store-path prefix so the rejection is proven to
        // fire at the UTF-8 gate, not at the grammar oracle.
        let mut buf: Vec<u8> = b"/nix/store/".to_vec();
        buf.push(0xFF);
        buf.extend_from_slice(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x");
        let expected_bytes = buf.clone();

        let err_borrowed = <StorePath as TryFrom<std::borrow::Cow<'_, [u8]>>>::try_from(
            std::borrow::Cow::Borrowed(buf.as_slice()),
        )
        .expect_err("non-UTF-8 bytes must reject at TryFrom<Cow::Borrowed>");
        let err_owned = <StorePath as TryFrom<std::borrow::Cow<'_, [u8]>>>::try_from(
            std::borrow::Cow::Owned(buf.clone()),
        )
        .expect_err("non-UTF-8 bytes must reject at TryFrom<Cow::Owned>");
        for err in [&err_borrowed, &err_owned] {
            match err {
                StorePathError::NonUtf8Bytes { bytes, source: _ } => {
                    assert_eq!(
                        bytes.as_slice(),
                        expected_bytes.as_slice(),
                        "the offending bytes must survive verbatim on the failure record"
                    );
                }
                other => panic!("expected NonUtf8Bytes, got: {other:?}"),
            }
            // The underlying std::str::Utf8Error must be reachable through
            // the Error::source chain — no re-decoding, no display-string
            // parsing.
            let src = err.source().expect("NonUtf8Bytes must carry a source");
            assert!(
                src.downcast_ref::<std::str::Utf8Error>().is_some(),
                "source must downcast to std::str::Utf8Error, got display: {src}",
            );
        }
        assert_eq!(
            err_borrowed, err_owned,
            "both Cow arms must emit byte-identical NonUtf8Bytes rejection on the same input"
        );
        // Agreement with the sibling by-reference and owned-byte peers:
        // the four byte receiver shapes converge on one typed rejection.
        let err_slice = StorePath::try_from(expected_bytes.as_slice())
            .expect_err("non-UTF-8 bytes must reject at TryFrom<&[u8]>");
        let err_vec = StorePath::try_from(expected_bytes.clone())
            .expect_err("non-UTF-8 bytes must reject at TryFrom<Vec<u8>>");
        assert_eq!(
            err_borrowed, err_slice,
            "TryFrom<Cow::Borrowed> and TryFrom<&[u8]> must emit byte-identical NonUtf8Bytes rejection"
        );
        assert_eq!(
            err_owned, err_vec,
            "TryFrom<Cow::Owned> and TryFrom<Vec<u8>> must emit byte-identical NonUtf8Bytes rejection"
        );
    }

    /// Valid UTF-8 bytes that decode to a non-store-path string must
    /// reject at the underlying [`FromStr`] impl with the exact
    /// grammar-clause variant the input violated — the two-stage
    /// strictness contract: UTF-8 decode gate first, grammar oracle
    /// second. Pins that both arms of the [`Cow`] peer route rejection
    /// through the ONE grammar oracle at [`StorePath::parse`] rather
    /// than divergent second parse paths.
    #[test]
    fn test_try_from_cow_bytes_rejects_non_canonical_input() {
        // `/nix/store/short` is valid UTF-8 but too short to hold a 32-
        // char hash — the exact grammar clause `StorePathError::TooShort`
        // discriminates.
        let short: &[u8] = b"/nix/store/short";
        let err_borrowed = <StorePath as TryFrom<std::borrow::Cow<'_, [u8]>>>::try_from(
            std::borrow::Cow::Borrowed(short),
        )
        .expect_err("non-canonical UTF-8 bytes must reject at TryFrom<Cow::Borrowed>");
        let err_owned = <StorePath as TryFrom<std::borrow::Cow<'_, [u8]>>>::try_from(
            std::borrow::Cow::Owned(short.to_vec()),
        )
        .expect_err("non-canonical UTF-8 bytes must reject at TryFrom<Cow::Owned>");
        for err in [&err_borrowed, &err_owned] {
            assert!(
                matches!(err, StorePathError::TooShort { .. }),
                "expected TooShort, got: {err:?}"
            );
        }
        assert_eq!(
            err_borrowed, err_owned,
            "both Cow arms must agree on grammar-clause rejection"
        );
        let err_slice = StorePath::try_from(short)
            .expect_err("non-canonical UTF-8 bytes must reject at TryFrom<&[u8]>");
        assert_eq!(
            err_borrowed, err_slice,
            "TryFrom<Cow::Borrowed> and TryFrom<&[u8]> must agree on grammar-clause rejection"
        );

        // A relative-path input must fire `MissingStorePrefix`, not
        // `NonUtf8Bytes` — the UTF-8 gate cleared, so the grammar
        // oracle owns the rejection.
        let rel: &[u8] = b"relative/path";
        let err_rel = <StorePath as TryFrom<std::borrow::Cow<'_, [u8]>>>::try_from(
            std::borrow::Cow::Borrowed(rel),
        )
        .expect_err("relative-path bytes must reject at TryFrom<Cow::Borrowed>");
        assert!(
            matches!(err_rel, StorePathError::MissingStorePrefix { .. }),
            "expected MissingStorePrefix, got: {err_rel:?}"
        );
    }

    /// A generic `fn f<'a, T: TryFrom<Cow<'a, [u8]>>>` consumer must
    /// accept a borrowed-or-owned byte buffer and recover a validated
    /// [`StorePath`] through the trait bound at both arms. Structural
    /// witness that [`StorePath`] is genuinely usable at
    /// [`TryFrom<Cow<'_, [u8]>>`] call sites — the surface a
    /// `#[serde(try_from = "Cow<'_, [u8]>")]` container attribute and
    /// any generic borrowed-or-owned byte try-conversion helper both
    /// key off. If a future change narrowed the bound or the error
    /// type, this test fails at compile time.
    #[test]
    fn test_try_from_cow_bytes_generic_consumer_recovers_identity() {
        fn parse_via_try_from<'a, T>(bytes: std::borrow::Cow<'a, [u8]>) -> Result<T, T::Error>
        where
            T: TryFrom<std::borrow::Cow<'a, [u8]>>,
        {
            T::try_from(bytes)
        }
        let raw = format!("/nix/store/{H}-foo-bar-1.2.3");
        let path_b: StorePath = parse_via_try_from(std::borrow::Cow::Borrowed(raw.as_bytes()))
            .expect("valid store-path bytes must parse via generic TryFrom<Cow::Borrowed>");
        assert_eq!(path_b.name(), "foo-bar-1.2.3");
        assert_eq!(path_b.hash(), H);
        let path_o: StorePath =
            parse_via_try_from(std::borrow::Cow::Owned(raw.as_bytes().to_vec()))
                .expect("valid store-path bytes must parse via generic TryFrom<Cow::Owned>");
        assert_eq!(path_o, path_b);
        // The trimming discipline reaches through the generic bound on
        // both arms: a caller feeding a newline-terminated buffer wrapped
        // in either [`Cow::Borrowed`] or [`Cow::Owned`] does not need to
        // pre-trim — the grammar owns the trim in one place.
        let raw_nl = format!("/nix/store/{H}-x\n");
        let trimmed_b: StorePath =
            parse_via_try_from(std::borrow::Cow::Borrowed(raw_nl.as_bytes()))
                .expect("trailing newline must be trimmed at generic TryFrom<Cow::Borrowed>");
        let trimmed_o: StorePath =
            parse_via_try_from(std::borrow::Cow::Owned(raw_nl.as_bytes().to_vec()))
                .expect("trailing newline must be trimmed at generic TryFrom<Cow::Owned>");
        assert_eq!(trimmed_b.as_str(), format!("/nix/store/{H}-x"));
        assert_eq!(trimmed_b, trimmed_o);
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

    /// The [`AsRef<str>`] peer must expose the same borrowed view the
    /// inherent [`StorePath::as_str`] gives — pins the delegation so a
    /// future refactor that severed the trait impl from the inherent
    /// accessor (e.g. a copy that re-emitted a stale representation) is
    /// caught here. The trimming discipline reaches through the peer too:
    /// a store path parsed from a newline-terminated buffer reads back
    /// through [`AsRef<str>`] as the trimmed canonical string.
    #[test]
    fn test_asref_str_matches_inherent_as_str() {
        let sp = StorePath::parse(&format!("/nix/store/{H}-hello-2.10")).unwrap();
        let via_asref: &str = sp.as_ref();
        assert_eq!(via_asref, sp.as_str());
        assert_eq!(via_asref, format!("/nix/store/{H}-hello-2.10"));
        // Trimming discipline reaches through the peer: the canonical
        // representation is the trimmed, validated string, not the raw
        // nix-build-stdout buffer.
        let sp_nl = StorePath::parse(&format!("/nix/store/{H}-x\n")).unwrap();
        let via_asref_nl: &str = sp_nl.as_ref();
        assert_eq!(via_asref_nl, format!("/nix/store/{H}-x"));
    }

    /// A generic `fn f<S: AsRef<str>>` consumer must accept a borrowed
    /// [`StorePath`] and recover the canonical string view through the
    /// trait bound. This is the structural witness that [`StorePath`] is
    /// genuinely usable at [`AsRef<str>`] call sites — the surface that
    /// a downstream record writer, attestation-column emitter, or
    /// third-party API binding [`impl AsRef<str>`] keys off. If a future
    /// change narrowed the bound, this test fails at compile time.
    #[test]
    fn test_asref_str_generic_consumer_recovers_canonical_view() {
        fn borrow_as_string<S: AsRef<str>>(s: S) -> String {
            s.as_ref().to_string()
        }
        let sp = StorePath::parse(&format!("/nix/store/{H}-foo-bar-1.2.3")).unwrap();
        assert_eq!(
            borrow_as_string(&sp),
            format!("/nix/store/{H}-foo-bar-1.2.3")
        );
        // The generic bound composes with the Display / FromStr /
        // TryFrom pair: an `AsRef<str>` view of a StorePath re-parses
        // to a StorePath equal to the original — the read-back /
        // parse-back round trip closes at the trait surface.
        let round_tripped: StorePath = borrow_as_string(&sp).parse().unwrap();
        assert_eq!(round_tripped, sp);
    }

    /// The [`AsRef<std::path::Path>`] peer must expose the same borrowed
    /// canonical string view the inherent [`StorePath::as_str`] gives, just
    /// projected onto the filesystem-path frontier through
    /// [`std::path::Path::new`]. Pins the delegation so a future refactor
    /// that severed the trait impl from the inherent accessor (e.g. a copy
    /// that re-emitted a stale or re-computed representation) is caught
    /// here. The trimming discipline reaches through the peer: a store path
    /// parsed from a newline-terminated buffer reads back through
    /// `AsRef<Path>` as the trimmed canonical path.
    #[test]
    fn test_asref_path_matches_inherent_as_str() {
        let sp = StorePath::parse(&format!("/nix/store/{H}-hello-2.10")).unwrap();
        let via_asref: &std::path::Path = sp.as_ref();
        assert_eq!(via_asref, std::path::Path::new(sp.as_str()));
        assert_eq!(
            via_asref,
            std::path::Path::new(&format!("/nix/store/{H}-hello-2.10"))
        );
        // Trimming discipline reaches through the peer.
        let sp_nl = StorePath::parse(&format!("/nix/store/{H}-x\n")).unwrap();
        let via_asref_nl: &std::path::Path = sp_nl.as_ref();
        assert_eq!(
            via_asref_nl,
            std::path::Path::new(&format!("/nix/store/{H}-x"))
        );
    }

    /// A generic `fn f<P: AsRef<std::path::Path>>` consumer must accept a
    /// borrowed [`StorePath`] and recover the canonical filesystem-path
    /// view through the trait bound. This is the structural witness that
    /// [`StorePath`] is genuinely usable at [`std::fs::exists`] /
    /// [`std::fs::metadata`] / [`std::path::PathBuf::from`] call sites —
    /// the surface every `impl AsRef<std::path::Path>` boundary keys off —
    /// without a call-site `Path::new(sp.as_str())` restatement. If a
    /// future change narrowed the bound, this test fails at compile time.
    /// Also pins that [`std::path::Path::to_str`] recovers the canonical
    /// string view (the round trip through the filesystem-path frontier is
    /// UTF-8-lossless on the store-path payload), so a consumer that
    /// crosses back to the string frontier through the peer sees the same
    /// bytes the [`AsRef<str>`] peer would have emitted.
    #[test]
    fn test_asref_path_generic_consumer_recovers_canonical_view() {
        fn borrow_as_pathbuf<P: AsRef<std::path::Path>>(p: P) -> std::path::PathBuf {
            p.as_ref().to_path_buf()
        }
        let sp = StorePath::parse(&format!("/nix/store/{H}-foo-bar-1.2.3")).unwrap();
        let pb = borrow_as_pathbuf(&sp);
        assert_eq!(pb, std::path::PathBuf::from(sp.as_str()));
        // Round-trip through the filesystem-path frontier back to the
        // string frontier recovers the canonical string bytes byte-for-byte
        // (a store path is ASCII by grammar, so `Path::to_str` is
        // guaranteed to yield Some on every supported platform).
        assert_eq!(
            pb.as_path().to_str(),
            Some(format!("/nix/store/{H}-foo-bar-1.2.3").as_str())
        );
    }

    /// The [`AsRef<std::ffi::OsStr>`] peer must expose the same borrowed
    /// canonical string view the inherent [`StorePath::as_str`] gives, just
    /// projected onto the OS-string frontier through
    /// [`std::ffi::OsStr::new`]. Pins the delegation so a future refactor
    /// that severed the trait impl from the inherent accessor (e.g. a copy
    /// that re-emitted a stale or re-computed representation) is caught
    /// here. The trimming discipline reaches through the peer: a store path
    /// parsed from a newline-terminated buffer reads back through
    /// `AsRef<OsStr>` as the trimmed canonical path.
    #[test]
    fn test_asref_osstr_matches_inherent_as_str() {
        let sp = StorePath::parse(&format!("/nix/store/{H}-hello-2.10")).unwrap();
        let via_asref: &std::ffi::OsStr = sp.as_ref();
        assert_eq!(via_asref, std::ffi::OsStr::new(sp.as_str()));
        assert_eq!(
            via_asref,
            std::ffi::OsStr::new(&format!("/nix/store/{H}-hello-2.10"))
        );
        // Trimming discipline reaches through the peer.
        let sp_nl = StorePath::parse(&format!("/nix/store/{H}-x\n")).unwrap();
        let via_asref_nl: &std::ffi::OsStr = sp_nl.as_ref();
        assert_eq!(
            via_asref_nl,
            std::ffi::OsStr::new(&format!("/nix/store/{H}-x"))
        );
    }

    /// A generic `fn f<S: AsRef<std::ffi::OsStr>>` consumer must accept a
    /// borrowed [`StorePath`] and recover the canonical OS-string view
    /// through the trait bound. This is the structural witness that
    /// [`StorePath`] is genuinely usable at [`std::process::Command::arg`] /
    /// [`std::process::Command::args`] / [`std::process::Command::env`] call
    /// sites — the surface every `impl AsRef<std::ffi::OsStr>` boundary
    /// keys off — without a call-site `OsStr::new(sp.as_str())` restatement.
    /// If a future change narrowed the bound, this test fails at compile
    /// time. Also pins that [`std::ffi::OsStr::to_str`] recovers the
    /// canonical string view (the round trip through the OS-string frontier
    /// is UTF-8-lossless on the store-path ASCII payload), so a consumer
    /// that crosses back to the string frontier through the peer sees the
    /// same bytes the [`AsRef<str>`] peer would have emitted.
    #[test]
    fn test_asref_osstr_generic_consumer_recovers_canonical_view() {
        fn borrow_as_osstring<S: AsRef<std::ffi::OsStr>>(s: S) -> std::ffi::OsString {
            s.as_ref().to_os_string()
        }
        let sp = StorePath::parse(&format!("/nix/store/{H}-foo-bar-1.2.3")).unwrap();
        let os = borrow_as_osstring(&sp);
        assert_eq!(os, std::ffi::OsString::from(sp.as_str()));
        // Round-trip through the OS-string frontier back to the string
        // frontier recovers the canonical string bytes byte-for-byte (a
        // store path is ASCII by grammar, so `OsStr::to_str` is guaranteed
        // to yield Some on every supported platform).
        assert_eq!(
            os.as_os_str().to_str(),
            Some(format!("/nix/store/{H}-foo-bar-1.2.3").as_str())
        );
    }

    /// The [`AsRef<std::ffi::OsStr>`] peer must survive an actual
    /// [`std::process::Command::arg`] consumption without a per-site
    /// `OsStr::new(sp.as_str())` restatement — the exact frontier that
    /// motivated the peer (an `attic push /nix/store/...` /
    /// `nix path-info /nix/store/...` / `skopeo copy nix:/nix/store/...`
    /// argument slot). Pins the OS-string round-trip by driving a real
    /// [`std::process::Command`] builder and reading back the recorded
    /// argument list at the [`std::process::Command::get_args`] surface.
    /// If a future regression collapsed the peer to a wider bound (e.g.
    /// only `AsRef<str>`), this test fails at compile time; if the peer
    /// dropped the trimming discipline, the recorded argument would drift
    /// from the canonical [`StorePath::as_str`] view and fail here.
    #[test]
    fn test_asref_osstr_flows_through_command_arg_without_restatement() {
        let sp = StorePath::parse(&format!("/nix/store/{H}-svc-1.2.3\n")).unwrap();
        let mut cmd = std::process::Command::new("/bin/true");
        cmd.arg(&sp);
        let recorded: Vec<&std::ffi::OsStr> = cmd.get_args().collect();
        assert_eq!(recorded.len(), 1, "arg count must be 1");
        assert_eq!(
            recorded[0],
            std::ffi::OsStr::new(sp.as_str()),
            "recorded arg must equal the canonical trimmed store-path view"
        );
        assert_eq!(
            recorded[0],
            std::ffi::OsStr::new(&format!("/nix/store/{H}-svc-1.2.3")),
            "trimming discipline must reach through the OS-string frontier"
        );
    }

    /// The [`AsRef<[u8]>`] peer must expose the same borrowed canonical
    /// string view the inherent [`StorePath::as_str`] gives, just projected
    /// onto the byte-slice frontier through [`str::as_bytes`]. Pins the
    /// delegation so a future refactor that severed the trait impl from the
    /// inherent accessor (e.g. a copy that re-emitted a stale representation,
    /// or an intermediate [`String::into_bytes`] path that discarded the
    /// zero-copy borrow) is caught here. The trimming discipline reaches
    /// through the peer: a store path parsed from a newline-terminated buffer
    /// reads back through `AsRef<[u8]>` as the trimmed canonical path bytes.
    #[test]
    fn test_asref_bytes_matches_inherent_as_str_as_bytes() {
        let sp = StorePath::parse(&format!("/nix/store/{H}-hello-2.10")).unwrap();
        let via_asref: &[u8] = sp.as_ref();
        assert_eq!(via_asref, sp.as_str().as_bytes());
        assert_eq!(via_asref, format!("/nix/store/{H}-hello-2.10").as_bytes());
        // Trimming discipline reaches through the peer.
        let sp_nl = StorePath::parse(&format!("/nix/store/{H}-x\n")).unwrap();
        let via_asref_nl: &[u8] = sp_nl.as_ref();
        assert_eq!(via_asref_nl, format!("/nix/store/{H}-x").as_bytes());
    }

    /// A generic `fn f<S: AsRef<[u8]>>` consumer must accept a borrowed
    /// [`StorePath`] and recover the canonical byte view through the trait
    /// bound. This is the structural witness that [`StorePath`] is genuinely
    /// usable at streaming-hasher `update`, [`std::io::Write::write_all`],
    /// and `HashMap<Box<[u8]>, _>::get` call sites — the surface every
    /// `impl AsRef<[u8]>` boundary keys off — without a call-site
    /// `sp.as_str().as_bytes()` restatement. If a future change narrowed the
    /// bound, this test fails at compile time. Also pins that
    /// [`std::str::from_utf8`] round-trips the byte view back to the
    /// canonical string view (the store-path payload is ASCII by grammar, so
    /// the round trip is UTF-8-lossless on every valid [`StorePath`]), so a
    /// consumer that crosses back to the string frontier through the peer
    /// sees the same bytes the [`AsRef<str>`] peer would have emitted.
    #[test]
    fn test_asref_bytes_generic_consumer_recovers_canonical_view() {
        fn read_bytes<S: AsRef<[u8]>>(s: &S) -> &[u8] {
            s.as_ref()
        }
        let sp = StorePath::parse(&format!("/nix/store/{H}-foo-bar-1.2.3")).unwrap();
        let bytes = read_bytes(&sp);
        assert_eq!(bytes, sp.as_str().as_bytes());
        // Round-trip through the byte frontier back to the string frontier
        // recovers the canonical string bytes byte-for-byte.
        let decoded = std::str::from_utf8(bytes).expect(
            "StorePath byte view is ASCII by grammar and must round-trip through from_utf8",
        );
        assert_eq!(decoded, sp.as_str());
        assert_eq!(decoded, format!("/nix/store/{H}-foo-bar-1.2.3"));
    }

    /// The [`AsRef<[u8]>`] peer must survive an actual
    /// [`blake3::Hasher::update`] consumption without a per-site
    /// `sp.as_str().as_bytes()` restatement — the exact frontier that
    /// motivated the peer (folding a validated store path into a build /
    /// attestation / closure fingerprint). Pins the byte-frontier round trip
    /// by driving a real [`blake3::Hasher`] over the peer and comparing the
    /// resulting digest against the same hasher fed the composed
    /// `sp.as_str().as_bytes()` view: the two digests must match at every
    /// bit, or the peer is drifting from its documented delegation. If a
    /// future regression collapsed the peer to a wider bound (e.g., only
    /// `AsRef<str>`), this test fails at compile time; if the peer dropped
    /// the trimming discipline, the digest over the trimmed and untrimmed
    /// inputs would diverge and fail here.
    #[test]
    fn test_asref_bytes_flows_through_hasher_without_restatement() {
        let sp = StorePath::parse(&format!("/nix/store/{H}-svc-1.2.3\n")).unwrap();
        // Fed through the AsRef<[u8]> peer — the frontier the peer serves.
        let mut via_peer = blake3::Hasher::new();
        via_peer.update(<StorePath as AsRef<[u8]>>::as_ref(&sp));
        let digest_via_peer = via_peer.finalize();
        // Fed through the composed sp.as_str().as_bytes() view — the
        // per-site restatement the peer exists to retire.
        let mut via_composition = blake3::Hasher::new();
        via_composition.update(sp.as_str().as_bytes());
        let digest_via_composition = via_composition.finalize();
        assert_eq!(
            digest_via_peer, digest_via_composition,
            "hasher fed through AsRef<[u8]> must produce the same digest as the composed sp.as_str().as_bytes() view",
        );
        // Trimming discipline reaches through the byte frontier: the
        // canonical trimmed view is what the hasher sees, not the raw
        // nix-build-stdout buffer with its trailing newline.
        let mut via_trimmed_literal = blake3::Hasher::new();
        via_trimmed_literal.update(format!("/nix/store/{H}-svc-1.2.3").as_bytes());
        let digest_via_trimmed_literal = via_trimmed_literal.finalize();
        assert_eq!(
            digest_via_peer, digest_via_trimmed_literal,
            "hasher fed through AsRef<[u8]> must see the trimmed canonical bytes, not the raw newline-terminated buffer",
        );
    }

    /// [`TryFrom<Arc<[u8]>>`] must accept every input the sibling
    /// [`TryFrom<&[u8]>`] peer accepts and produce a value equal to the
    /// [`FromStr`] round-trip on the decoded view of the same buffer.
    /// Pins the delegation through the byte-slice oracle via
    /// [`Arc::as_ref`]: a future refactor that severed the trait impl
    /// from `<Self as TryFrom<&[u8]>>::try_from(shared.as_ref())` (e.g.,
    /// cloned the shared buffer into a fresh [`Vec<u8>`], routed through
    /// [`String::from_utf8`] on an already-decodable buffer, or diverged
    /// the whitespace-trimming discipline from the sibling peer) would
    /// fail here first.
    #[test]
    fn test_try_from_arc_bytes_success_agrees_with_fromstr_and_byte_slice() {
        use std::sync::Arc;
        let raw = format!("/nix/store/{H}-hello-2.10");
        let shared: Arc<[u8]> = Arc::from(raw.as_bytes());
        let via_try_from = <StorePath as TryFrom<Arc<[u8]>>>::try_from(shared.clone())
            .expect("valid store-path bytes must parse via TryFrom<Arc<[u8]>>");
        let via_fromstr: StorePath = raw.parse().expect("valid store path parses via FromStr");
        let via_byte_slice = StorePath::try_from(raw.as_bytes())
            .expect("valid store-path bytes must parse via TryFrom<&[u8]>");
        assert_eq!(
            via_try_from, via_fromstr,
            "TryFrom<Arc<[u8]>> must yield the same StorePath value as FromStr on the decoded view",
        );
        assert_eq!(
            via_try_from, via_byte_slice,
            "TryFrom<Arc<[u8]>> must agree byte-for-byte with the sibling TryFrom<&[u8]> peer on canonical bytes",
        );
        // Cloning the Arc handle must not perturb the parse — the
        // atomic-refcount bump lives in Arc, not in the store-path grammar.
        let cloned = Arc::clone(&shared);
        let via_cloned = <StorePath as TryFrom<Arc<[u8]>>>::try_from(cloned)
            .expect("cloned Arc<[u8]> must parse identically to its origin");
        assert_eq!(via_cloned, via_try_from);
        // Hyphenated-name case guards against a future refactor that
        // truncates at the first `-` on the way through the shared peer.
        let raw2 = format!("/nix/store/{H}-foo-bar-1.2.3");
        let via_try_from2 = <StorePath as TryFrom<Arc<[u8]>>>::try_from(Arc::from(raw2.as_bytes()))
            .expect("hyphenated-name store path parses via TryFrom<Arc<[u8]>>");
        assert_eq!(via_try_from2.name(), "foo-bar-1.2.3");
        assert_eq!(via_try_from2.hash(), H);
        // Trimming discipline reaches through the peer: a newline-terminated
        // buffer parses cleanly and yields the trimmed canonical view.
        let raw_nl = format!("/nix/store/{H}-x\n");
        let trimmed = <StorePath as TryFrom<Arc<[u8]>>>::try_from(Arc::from(raw_nl.as_bytes()))
            .expect("trailing newline must be trimmed at TryFrom<Arc<[u8]>> surface");
        assert_eq!(trimmed.as_str(), format!("/nix/store/{H}-x"));
    }

    /// A non-UTF-8 byte sequence must reject at the UTF-8 decode gate
    /// with the [`StorePathError::NonUtf8Bytes`] variant BEFORE any
    /// grammar clause is evaluated, and the rejection must be
    /// byte-identical to the sibling [`TryFrom<&[u8]>`] peer's rejection
    /// on the same input — a caller switching between the by-reference
    /// byte-slice peer and the cross-thread shared-owned byte peer reads
    /// the same typed error variant with the same offending-bytes
    /// payload.
    #[test]
    fn test_try_from_arc_bytes_rejects_non_utf8_input() {
        use std::error::Error as _;
        use std::sync::Arc;
        // 0xFF is never valid as a UTF-8 leading byte; the buffer starts
        // with a valid store-path prefix so the rejection is proven to
        // fire at the UTF-8 gate, not at the grammar oracle.
        let mut buf: Vec<u8> = b"/nix/store/".to_vec();
        buf.push(0xFF);
        buf.extend_from_slice(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x");
        let expected_bytes = buf.clone();
        let shared: Arc<[u8]> = Arc::from(buf.as_slice());

        let err_shared = <StorePath as TryFrom<Arc<[u8]>>>::try_from(shared)
            .expect_err("non-UTF-8 bytes must reject at TryFrom<Arc<[u8]>>");
        match &err_shared {
            StorePathError::NonUtf8Bytes { bytes, source: _ } => {
                assert_eq!(
                    bytes.as_slice(),
                    expected_bytes.as_slice(),
                    "the offending bytes must survive verbatim on the failure record",
                );
            }
            other => panic!("expected NonUtf8Bytes, got: {other:?}"),
        }
        let src = err_shared
            .source()
            .expect("NonUtf8Bytes must carry a source");
        assert!(
            src.downcast_ref::<std::str::Utf8Error>().is_some(),
            "source must downcast to std::str::Utf8Error, got display: {src}",
        );

        // Agreement with the sibling by-reference byte-slice peer: both
        // shapes converge on one typed rejection.
        let err_slice = StorePath::try_from(expected_bytes.as_slice())
            .expect_err("non-UTF-8 bytes must reject at TryFrom<&[u8]>");
        assert_eq!(
            err_shared, err_slice,
            "TryFrom<Arc<[u8]>> and TryFrom<&[u8]> must emit byte-identical NonUtf8Bytes rejection",
        );
    }

    /// Valid UTF-8 bytes that decode to a non-store-path string must
    /// reject at the underlying [`FromStr`] impl with the exact
    /// grammar-clause variant the input violated — the two-stage
    /// strictness contract: UTF-8 decode gate first, grammar oracle
    /// second. Pins that the cross-thread shared-owned byte peer routes
    /// rejection through the ONE grammar oracle at [`StorePath::parse`]
    /// rather than a divergent second parse path.
    #[test]
    fn test_try_from_arc_bytes_rejects_non_canonical_input() {
        use std::sync::Arc;
        // Cover every grammar clause once, and cross-check byte-for-byte
        // that the shared-owned byte try-conversion surface surfaces the
        // SAME typed error variant (with the SAME offending input in each
        // variant) as the by-reference byte-slice peer.
        type ExpectVariant = fn(&StorePathError) -> bool;
        let cases: &[(&[u8], ExpectVariant)] = &[
            (b"", |e| {
                matches!(e, StorePathError::MissingStorePrefix { .. })
            }),
            (b"nix/store/abc-x", |e| {
                matches!(e, StorePathError::MissingStorePrefix { .. })
            }),
            (b"/nix/store/unknown-mysvc.drv", |e| {
                matches!(e, StorePathError::TooShort { .. })
            }),
            (b"/nix/store/eeeeoooouuuutttteeeeoooouuuutttt-x", |e| {
                matches!(e, StorePathError::InvalidHash { .. })
            }),
            (b"/nix/store/0123456789abcdfghijklmnpqrsvwxyzx", |e| {
                matches!(e, StorePathError::MissingSeparator { .. })
            }),
            (b"/nix/store/0123456789abcdfghijklmnpqrsvwxyz-", |e| {
                matches!(e, StorePathError::EmptyName { .. })
            }),
        ];
        for (bad, is_expected_variant) in cases {
            let shared: Arc<[u8]> = Arc::from(*bad);
            let err_shared = <StorePath as TryFrom<Arc<[u8]>>>::try_from(shared)
                .expect_err("malformed store-path bytes must fail via TryFrom<Arc<[u8]>>");
            let err_slice = StorePath::try_from(*bad)
                .expect_err("malformed store-path bytes must fail via TryFrom<&[u8]>");
            assert_eq!(
                err_shared, err_slice,
                "TryFrom<Arc<[u8]>> must surface the same typed error as the sibling byte-slice peer for {bad:?}",
            );
            assert!(
                is_expected_variant(&err_shared),
                "unexpected error variant for {bad:?}: {err_shared:?}",
            );
        }
    }

    /// A generic `fn f<T: TryFrom<Arc<[u8]>>>` consumer must recover a
    /// valid [`StorePath`] through the trait bound. This is the
    /// structural witness that [`StorePath`] is genuinely usable at
    /// [`TryFrom<Arc<[u8]>>`] call sites — the surface a
    /// `#[serde(try_from = "Arc<[u8]>")]` container attribute, a
    /// `HashMap<Arc<[u8]>, StorePath>` shared intern-table populate, and
    /// a `bytes::Bytes → Arc<[u8]>` async-registry bridge all key off.
    /// If a future change narrowed the bound (e.g., gated the impl on a
    /// lifetime or trait shape the generic surface couldn't hit), this
    /// test fails at compile time.
    #[test]
    fn test_try_from_arc_bytes_generic_consumer_recovers_identity() {
        use std::sync::Arc;
        fn parse_via_try_from<T>(bytes: Arc<[u8]>) -> Result<T, T::Error>
        where
            T: TryFrom<Arc<[u8]>>,
        {
            T::try_from(bytes)
        }
        let raw = format!("/nix/store/{H}-foo-bar-1.2.3");
        let path: StorePath = parse_via_try_from(Arc::from(raw.as_bytes()))
            .expect("valid store-path bytes must parse via generic TryFrom<Arc<[u8]>> bound");
        assert_eq!(path.name(), "foo-bar-1.2.3");
        assert_eq!(path.hash(), H);
        // Trimming discipline reaches through the generic bound: a caller
        // owning a nix-build-stdout Arc<[u8]> handed across worker threads
        // does not need to pre-trim before handing it to the generic
        // try-conversion helper — the grammar owns the trim in one place.
        let raw_nl = format!("/nix/store/{H}-x\n");
        let trimmed: StorePath = parse_via_try_from(Arc::from(raw_nl.as_bytes()))
            .expect("trailing newline must be trimmed at generic TryFrom<Arc<[u8]>>");
        assert_eq!(trimmed.as_str(), format!("/nix/store/{H}-x"));
    }

    /// Valid store-path bytes carried through a thread-local
    /// non-atomically refcounted shared byte buffer must parse via
    /// [`TryFrom<Rc<[u8]>>`], and the parsed value must equal the
    /// [`FromStr`] round-trip on the decoded view of the same bytes and
    /// the sibling [`TryFrom<&[u8]>`] and [`TryFrom<Arc<[u8]>>`] peers'
    /// outputs on the same input. Pins the delegation through the
    /// byte-slice oracle via [`Rc::as_ref`]: a future refactor that
    /// severed the trait impl from
    /// `<Self as TryFrom<&[u8]>>::try_from(shared.as_ref())` (e.g.,
    /// cloned the shared buffer into a fresh [`Vec<u8>`], routed
    /// through [`String::from_utf8`] on an already-decodable buffer,
    /// lifted the payload to [`std::sync::Arc<[u8]>`] to satisfy the
    /// atomically refcounted sibling, or diverged the
    /// whitespace-trimming discipline from the shared peer) would fail
    /// here first.
    #[test]
    fn test_try_from_rc_bytes_success_agrees_with_fromstr_and_byte_slice() {
        use std::rc::Rc;
        use std::sync::Arc;
        let raw = format!("/nix/store/{H}-hello-2.10");
        let shared: Rc<[u8]> = Rc::from(raw.as_bytes());
        let via_try_from = <StorePath as TryFrom<Rc<[u8]>>>::try_from(shared.clone())
            .expect("valid store-path bytes must parse via TryFrom<Rc<[u8]>>");
        let via_fromstr: StorePath = raw.parse().expect("valid store path parses via FromStr");
        let via_byte_slice = StorePath::try_from(raw.as_bytes())
            .expect("valid store-path bytes must parse via TryFrom<&[u8]>");
        let via_arc = <StorePath as TryFrom<Arc<[u8]>>>::try_from(Arc::from(raw.as_bytes()))
            .expect("valid store-path bytes must parse via TryFrom<Arc<[u8]>>");
        assert_eq!(
            via_try_from, via_fromstr,
            "TryFrom<Rc<[u8]>> must yield the same StorePath value as FromStr on the decoded view",
        );
        assert_eq!(
            via_try_from, via_byte_slice,
            "TryFrom<Rc<[u8]>> must agree byte-for-byte with the sibling TryFrom<&[u8]> peer on canonical bytes",
        );
        assert_eq!(
            via_try_from, via_arc,
            "TryFrom<Rc<[u8]>> must agree byte-for-byte with the sibling TryFrom<Arc<[u8]>> peer on canonical bytes",
        );
        // Cloning the Rc handle must not perturb the parse — the
        // non-atomic refcount bump lives in Rc, not in the store-path
        // grammar.
        let cloned = Rc::clone(&shared);
        let via_cloned = <StorePath as TryFrom<Rc<[u8]>>>::try_from(cloned)
            .expect("cloned Rc<[u8]> must parse identically to its origin");
        assert_eq!(via_cloned, via_try_from);
        // Hyphenated-name case guards against a future refactor that
        // truncates at the first `-` on the way through the shared peer.
        let raw2 = format!("/nix/store/{H}-foo-bar-1.2.3");
        let via_try_from2 = <StorePath as TryFrom<Rc<[u8]>>>::try_from(Rc::from(raw2.as_bytes()))
            .expect("hyphenated-name store path parses via TryFrom<Rc<[u8]>>");
        assert_eq!(via_try_from2.name(), "foo-bar-1.2.3");
        assert_eq!(via_try_from2.hash(), H);
        // Trimming discipline reaches through the peer: a newline-terminated
        // buffer parses cleanly and yields the trimmed canonical view.
        let raw_nl = format!("/nix/store/{H}-x\n");
        let trimmed = <StorePath as TryFrom<Rc<[u8]>>>::try_from(Rc::from(raw_nl.as_bytes()))
            .expect("trailing newline must be trimmed at TryFrom<Rc<[u8]>> surface");
        assert_eq!(trimmed.as_str(), format!("/nix/store/{H}-x"));
    }

    /// A non-UTF-8 byte sequence must reject at the UTF-8 decode gate
    /// with the [`StorePathError::NonUtf8Bytes`] variant BEFORE any
    /// grammar clause is evaluated, and the rejection must be
    /// byte-identical to the sibling [`TryFrom<&[u8]>`] peer's rejection
    /// on the same input — a caller switching between the by-reference
    /// byte-slice peer and the thread-local shared-owned byte peer reads
    /// the same typed error variant with the same offending-bytes
    /// payload.
    #[test]
    fn test_try_from_rc_bytes_rejects_non_utf8_input() {
        use std::error::Error as _;
        use std::rc::Rc;
        // 0xFF is never valid as a UTF-8 leading byte; the buffer starts
        // with a valid store-path prefix so the rejection is proven to
        // fire at the UTF-8 gate, not at the grammar oracle.
        let mut buf: Vec<u8> = b"/nix/store/".to_vec();
        buf.push(0xFF);
        buf.extend_from_slice(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x");
        let expected_bytes = buf.clone();
        let shared: Rc<[u8]> = Rc::from(buf.as_slice());

        let err_shared = <StorePath as TryFrom<Rc<[u8]>>>::try_from(shared)
            .expect_err("non-UTF-8 bytes must reject at TryFrom<Rc<[u8]>>");
        match &err_shared {
            StorePathError::NonUtf8Bytes { bytes, source: _ } => {
                assert_eq!(
                    bytes.as_slice(),
                    expected_bytes.as_slice(),
                    "the offending bytes must survive verbatim on the failure record",
                );
            }
            other => panic!("expected NonUtf8Bytes, got: {other:?}"),
        }
        let src = err_shared
            .source()
            .expect("NonUtf8Bytes must carry a source");
        assert!(
            src.downcast_ref::<std::str::Utf8Error>().is_some(),
            "source must downcast to std::str::Utf8Error, got display: {src}",
        );

        // Agreement with the sibling by-reference byte-slice peer: both
        // shapes converge on one typed rejection.
        let err_slice = StorePath::try_from(expected_bytes.as_slice())
            .expect_err("non-UTF-8 bytes must reject at TryFrom<&[u8]>");
        assert_eq!(
            err_shared, err_slice,
            "TryFrom<Rc<[u8]>> and TryFrom<&[u8]> must emit byte-identical NonUtf8Bytes rejection",
        );
    }

    /// Valid UTF-8 bytes that decode to a non-store-path string must
    /// reject at the underlying [`FromStr`] impl with the exact
    /// grammar-clause variant the input violated — the two-stage
    /// strictness contract: UTF-8 decode gate first, grammar oracle
    /// second. Pins that the thread-local shared-owned byte peer routes
    /// rejection through the ONE grammar oracle at [`StorePath::parse`]
    /// rather than a divergent second parse path.
    #[test]
    fn test_try_from_rc_bytes_rejects_non_canonical_input() {
        use std::rc::Rc;
        // Cover every grammar clause once, and cross-check byte-for-byte
        // that the thread-local shared-owned byte try-conversion surface
        // surfaces the SAME typed error variant (with the SAME offending
        // input in each variant) as the by-reference byte-slice peer.
        type ExpectVariant = fn(&StorePathError) -> bool;
        let cases: &[(&[u8], ExpectVariant)] = &[
            (b"", |e| {
                matches!(e, StorePathError::MissingStorePrefix { .. })
            }),
            (b"nix/store/abc-x", |e| {
                matches!(e, StorePathError::MissingStorePrefix { .. })
            }),
            (b"/nix/store/unknown-mysvc.drv", |e| {
                matches!(e, StorePathError::TooShort { .. })
            }),
            (b"/nix/store/eeeeoooouuuutttteeeeoooouuuutttt-x", |e| {
                matches!(e, StorePathError::InvalidHash { .. })
            }),
            (b"/nix/store/0123456789abcdfghijklmnpqrsvwxyzx", |e| {
                matches!(e, StorePathError::MissingSeparator { .. })
            }),
            (b"/nix/store/0123456789abcdfghijklmnpqrsvwxyz-", |e| {
                matches!(e, StorePathError::EmptyName { .. })
            }),
        ];
        for (bad, is_expected_variant) in cases {
            let shared: Rc<[u8]> = Rc::from(*bad);
            let err_shared = <StorePath as TryFrom<Rc<[u8]>>>::try_from(shared)
                .expect_err("malformed store-path bytes must fail via TryFrom<Rc<[u8]>>");
            let err_slice = StorePath::try_from(*bad)
                .expect_err("malformed store-path bytes must fail via TryFrom<&[u8]>");
            assert_eq!(
                err_shared, err_slice,
                "TryFrom<Rc<[u8]>> must surface the same typed error as the sibling byte-slice peer for {bad:?}",
            );
            assert!(
                is_expected_variant(&err_shared),
                "unexpected error variant for {bad:?}: {err_shared:?}",
            );
        }
    }

    /// A generic `fn f<T: TryFrom<Rc<[u8]>>>` consumer must recover a
    /// valid [`StorePath`] through the trait bound. This is the
    /// structural witness that [`StorePath`] is genuinely usable at
    /// [`TryFrom<Rc<[u8]>>`] call sites — the surface a
    /// `#[serde(try_from = "Rc<[u8]>")]` container attribute, a
    /// `HashMap<Rc<[u8]>, StorePath>` single-thread intern-table
    /// populate, and a single-thread graph of readers sharing an
    /// Rc-owned byte payload through [`std::rc::Rc::clone`] all key
    /// off. If a future change narrowed the bound (e.g., gated the
    /// impl on a lifetime or trait shape the generic surface couldn't
    /// hit), this test fails at compile time.
    #[test]
    fn test_try_from_rc_bytes_generic_consumer_recovers_identity() {
        use std::rc::Rc;
        fn parse_via_try_from<T>(bytes: Rc<[u8]>) -> Result<T, T::Error>
        where
            T: TryFrom<Rc<[u8]>>,
        {
            T::try_from(bytes)
        }
        let raw = format!("/nix/store/{H}-foo-bar-1.2.3");
        let path: StorePath = parse_via_try_from(Rc::from(raw.as_bytes()))
            .expect("valid store-path bytes must parse via generic TryFrom<Rc<[u8]>> bound");
        assert_eq!(path.name(), "foo-bar-1.2.3");
        assert_eq!(path.hash(), H);
        // Trimming discipline reaches through the generic bound: a caller
        // owning a nix-build-stdout Rc<[u8]> shared among sibling readers
        // on the same thread does not need to pre-trim before handing it
        // to the generic try-conversion helper — the grammar owns the
        // trim in one place.
        let raw_nl = format!("/nix/store/{H}-x\n");
        let trimmed: StorePath = parse_via_try_from(Rc::from(raw_nl.as_bytes()))
            .expect("trailing newline must be trimmed at generic TryFrom<Rc<[u8]>>");
        assert_eq!(trimmed.as_str(), format!("/nix/store/{H}-x"));
    }

    /// `<StorePath as PartialEq<str>>::eq(&sp, raw)` must agree
    /// byte-for-byte with `sp.as_str() == raw` at every
    /// (canonical-view, candidate) pair. Pins the delegation through
    /// the inherent [`StorePath::as_str`] oracle so a future refactor
    /// that severed the trait impl from the accessor (a hand-rolled
    /// tag-and-slice re-read, a stale representation cache) is caught
    /// here first at the borrowed UTF-8 comparison frontier.
    #[test]
    fn test_partial_eq_str_agrees_with_as_str() {
        let sp = StorePath::parse(&format!("/nix/store/{H}-hello-2.10")).unwrap();
        let candidates = [
            format!("/nix/store/{H}-hello-2.10"),
            format!("/nix/store/{H}-hello-2.11"),
            format!("/nix/store/{H}-x"),
            "/nix/store/short".to_string(),
            String::new(),
            "hello-2.10".to_string(),
        ];
        for candidate in &candidates {
            let via_peer: bool = sp == *candidate.as_str();
            let via_accessor: bool = sp.as_str() == candidate.as_str();
            assert_eq!(
                via_peer, via_accessor,
                "PartialEq<str> peer must agree with sp.as_str() == candidate at {candidate:?}",
            );
        }
    }

    /// The reflexive identity `sp == sp.as_str()` must hold at every
    /// [`StorePath`] value. Pins the accessor's own bytes as a fixed
    /// point of the peer so a future refactor that quietly re-encoded
    /// the canonical view (a trim-drift, an insertion of a
    /// normalization step the accessor does not perform) breaks here
    /// rather than at every downstream comparison site.
    #[test]
    fn test_partial_eq_str_reflexive_at_own_canonical_view() {
        for raw in [
            format!("/nix/store/{H}-hello-2.10"),
            format!("/nix/store/{H}-x"),
            format!("/nix/store/{H}-foo-bar-1.2.3"),
            format!("/nix/store/{H}-svc-1.2.3.drv"),
        ] {
            let sp = StorePath::parse(&raw).unwrap();
            assert!(
                sp == *sp.as_str(),
                "PartialEq<str> must be reflexive at own canonical view for {raw:?}",
            );
        }
    }

    /// The trimming discipline of [`StorePath::parse`] reaches through
    /// the [`PartialEq<str>`] peer — a value parsed from a
    /// newline-terminated buffer compares equal to the *trimmed*
    /// canonical literal, not to the raw newline-terminated buffer.
    /// Pins the invariant that the peer reads the same canonical
    /// bytes the accessor exposes, at the wire-boundary shape the
    /// peer exists to serve.
    #[test]
    fn test_partial_eq_str_trims_through_peer() {
        let sp = StorePath::parse(&format!("/nix/store/{H}-svc-1.2.3\n")).unwrap();
        assert!(sp == *format!("/nix/store/{H}-svc-1.2.3").as_str());
        assert!(!(sp == *format!("/nix/store/{H}-svc-1.2.3\n").as_str()));
    }

    /// `<StorePath as PartialEq<&str>>::eq(&sp, &raw_ref)` — the
    /// receiver-shape sibling of the [`PartialEq<str>`] peer — must
    /// agree byte-for-byte with the receiver-shape sibling at every
    /// (canonical-view, candidate) pair, so a caller may pick either
    /// receiver at the comparison site without the two peers diverging.
    #[test]
    fn test_partial_eq_str_ref_agrees_with_partial_eq_str() {
        let sp = StorePath::parse(&format!("/nix/store/{H}-hello-2.10")).unwrap();
        let candidates = [
            format!("/nix/store/{H}-hello-2.10"),
            format!("/nix/store/{H}-hello-2.11"),
            "/nix/store/short".to_string(),
            String::new(),
        ];
        for candidate in &candidates {
            let raw_ref: &str = candidate.as_str();
            let via_str_ref: bool = sp == raw_ref;
            let via_str: bool = sp == *raw_ref;
            assert_eq!(
                via_str_ref, via_str,
                "PartialEq<&str> receiver-shape peer must agree with PartialEq<str> at {candidate:?}",
            );
        }
    }

    /// A generic `fn f<A, B>(a: A, b: B) -> bool where A: PartialEq<B>`
    /// consumer must accept a borrowed [`StorePath`] against a
    /// borrowed [`str`] and answer through the trait bound. This is
    /// the structural witness that [`StorePath`] is usable at every
    /// downstream generic [`PartialEq`]-bounded comparison site —
    /// the surface a wire-echo verifier or a fixture-comparison
    /// helper keys off — without a per-site
    /// `sp.as_str() == raw` bridge that repeats the accessor name.
    #[test]
    fn test_partial_eq_str_carries_through_generic_consumer() {
        fn eq_through_bound<A, B: ?Sized>(a: &A, b: &B) -> bool
        where
            A: PartialEq<B>,
        {
            a == b
        }
        let sp = StorePath::parse(&format!("/nix/store/{H}-hello-2.10")).unwrap();
        let match_literal = format!("/nix/store/{H}-hello-2.10");
        let miss_literal = format!("/nix/store/{H}-hello-2.11");
        assert!(eq_through_bound::<StorePath, str>(
            &sp,
            match_literal.as_str()
        ));
        assert!(!eq_through_bound::<StorePath, str>(
            &sp,
            miss_literal.as_str()
        ));
    }

    /// `<str as PartialEq<StorePath>>::eq(candidate, &sp)` must agree
    /// byte-for-byte with `candidate == sp.as_str()` at every
    /// (candidate, canonical-view) pair. Pins the delegation through
    /// the inherent [`StorePath::as_str`] oracle on the reverse-
    /// direction [`str`]-receiver peer so a future refactor that
    /// severed the trait impl from the accessor (a hand-rolled
    /// tag-and-slice re-read, a stale representation cache) is caught
    /// here first at the reverse-direction borrowed UTF-8 comparison
    /// frontier — the sibling of
    /// [`test_partial_eq_str_agrees_with_as_str`] on the forward-
    /// direction peer.
    #[test]
    fn test_str_partial_eq_store_path_agrees_with_as_str() {
        let sp = StorePath::parse(&format!("/nix/store/{H}-hello-2.10")).unwrap();
        let candidates = [
            format!("/nix/store/{H}-hello-2.10"),
            format!("/nix/store/{H}-hello-2.11"),
            format!("/nix/store/{H}-x"),
            "/nix/store/short".to_string(),
            String::new(),
            "hello-2.10".to_string(),
        ];
        for candidate in &candidates {
            let via_peer: bool = *candidate.as_str() == sp;
            let via_accessor: bool = candidate.as_str() == sp.as_str();
            assert_eq!(
                via_peer, via_accessor,
                "PartialEq<StorePath> for str peer must agree with candidate == sp.as_str() at {candidate:?}",
            );
        }
    }

    /// The reflexive identity `sp.as_str() == sp` (through the reverse-
    /// direction [`str`]-receiver peer) must hold at every
    /// [`StorePath`] value. Pins the accessor's own bytes as a fixed
    /// point of the peer so a future refactor that quietly re-encoded
    /// the canonical view breaks here rather than at every downstream
    /// comparison site — the reverse-direction sibling of
    /// [`test_partial_eq_str_reflexive_at_own_canonical_view`].
    #[test]
    fn test_str_partial_eq_store_path_reflexive_at_own_canonical_view() {
        for raw in [
            format!("/nix/store/{H}-hello-2.10"),
            format!("/nix/store/{H}-x"),
            format!("/nix/store/{H}-foo-bar-1.2.3"),
            format!("/nix/store/{H}-svc-1.2.3.drv"),
        ] {
            let sp = StorePath::parse(&raw).unwrap();
            assert!(
                *sp.as_str() == sp,
                "PartialEq<StorePath> for str must be reflexive at own canonical view for {raw:?}",
            );
        }
    }

    /// `<&str as PartialEq<StorePath>>::eq(&raw_ref, &sp)` — the
    /// receiver-shape sibling of the [`PartialEq<StorePath> for str`]
    /// peer — must agree byte-for-byte with the receiver-shape sibling
    /// at every (candidate, canonical-view) pair, so a caller may pick
    /// either receiver at the comparison site without the two peers
    /// diverging. Reverse-direction sibling of
    /// [`test_partial_eq_str_ref_agrees_with_partial_eq_str`].
    #[test]
    fn test_str_ref_partial_eq_store_path_agrees_with_partial_eq_store_path() {
        let sp = StorePath::parse(&format!("/nix/store/{H}-hello-2.10")).unwrap();
        let candidates = [
            format!("/nix/store/{H}-hello-2.10"),
            format!("/nix/store/{H}-hello-2.11"),
            "/nix/store/short".to_string(),
            String::new(),
        ];
        for candidate in &candidates {
            let raw_ref: &str = candidate.as_str();
            let via_str_ref: bool = raw_ref == sp;
            let via_str: bool = *raw_ref == sp;
            assert_eq!(
                via_str_ref, via_str,
                "PartialEq<StorePath> for &str receiver-shape peer must agree with PartialEq<StorePath> for str at {candidate:?}",
            );
        }
    }

    /// The trimming discipline of [`StorePath::parse`] reaches through
    /// the reverse-direction [`PartialEq<StorePath> for str`] peer — a
    /// value parsed from a newline-terminated buffer compares equal to
    /// the *trimmed* canonical literal on the reverse-direction side,
    /// not to the raw newline-terminated buffer. Pins the invariant
    /// that the reverse-direction peer reads the same canonical bytes
    /// the accessor exposes, at the wire-boundary shape the peer exists
    /// to serve. Reverse-direction sibling of
    /// [`test_partial_eq_str_trims_through_peer`].
    #[test]
    fn test_str_partial_eq_store_path_trims_through_peer() {
        let sp = StorePath::parse(&format!("/nix/store/{H}-svc-1.2.3\n")).unwrap();
        assert!(*format!("/nix/store/{H}-svc-1.2.3").as_str() == sp);
        assert!(!(*format!("/nix/store/{H}-svc-1.2.3\n").as_str() == sp));
    }

    /// The reverse-direction and forward-direction borrowed UTF-8
    /// comparison surfaces on the [`StorePath`] typed primitive agree
    /// byte-for-byte at every (candidate, [`StorePath`]) pair — the
    /// symmetry axiom
    /// `<str as PartialEq<StorePath>>::eq(candidate, &sp)
    /// == <StorePath as PartialEq<str>>::eq(&sp, candidate)` (and its
    /// `&str`-receiver peer) holds across the canonical × known-bad
    /// candidate grid. Pins the full 2×2 receiver × direction cross-
    /// product closure so a future refactor that diverged one impl
    /// from its symmetric peer breaks this pin at at least one pair
    /// rather than propagating unnoticed through downstream generic
    /// [`PartialEq`]-bounded consumers that thread a [`StorePath`]
    /// through either side of a `==` operator. Structural mirror of
    /// [`crate::probe_outcome::tests::test_partial_eq_admission_tier_symmetric_with_forward_direction`]
    /// (commit c48f819) at the sibling admission-tier label sum and of
    /// [`crate::retry::tests::test_partial_eq_per_attempt_region_symmetric_with_forward_direction`]
    /// (commit 203f63b) at the sibling per-attempt-region ladder.
    #[test]
    fn test_partial_eq_store_path_symmetric_with_forward_direction() {
        let sp = StorePath::parse(&format!("/nix/store/{H}-hello-2.10")).unwrap();
        let candidates = [
            format!("/nix/store/{H}-hello-2.10"),
            format!("/nix/store/{H}-hello-2.11"),
            format!("/nix/store/{H}-x"),
            format!("/nix/store/{H}-svc-1.2.3.drv"),
            "/nix/store/short".to_string(),
            String::new(),
            "hello-2.10".to_string(),
        ];
        for candidate in &candidates {
            let raw: &str = candidate.as_str();
            assert_eq!(
                <str as PartialEq<StorePath>>::eq(raw, &sp),
                <StorePath as PartialEq<str>>::eq(&sp, raw),
                "reverse-str and forward-str PartialEq peers must agree at {candidate:?}",
            );
            let raw_ref: &&str = &raw;
            assert_eq!(
                <&str as PartialEq<StorePath>>::eq(raw_ref, &sp),
                <StorePath as PartialEq<&str>>::eq(&sp, raw_ref),
                "reverse-&str and forward-&str PartialEq peers must agree at {candidate:?}",
            );
        }
    }

    /// `<StorePath as PartialEq<String>>::eq(&sp, &owned)` must agree
    /// byte-for-byte with `sp.as_str() == owned.as_str()` at every
    /// (candidate, canonical-view) pair across the canonical, sibling-
    /// hash, shorter-name, malformed-shortcut, empty, and tail-only
    /// candidate grid. Pins the delegation through the inherent
    /// [`StorePath::as_str`] oracle on the owned-receiver forward-
    /// direction peer, so a future refactor that severed the trait
    /// impl from the accessor (a hand-rolled tag-and-slice re-read,
    /// a stale representation cache, a `Display`-formatter-buffer
    /// detour) is caught here first at the owned UTF-8 comparison
    /// frontier — the owned-receiver sibling of
    /// [`test_partial_eq_str_agrees_with_as_str`] on the borrowed-str
    /// forward-direction peer.
    #[test]
    fn test_partial_eq_string_agrees_with_as_str() {
        let sp = StorePath::parse(&format!("/nix/store/{H}-hello-2.10")).unwrap();
        let candidates = [
            format!("/nix/store/{H}-hello-2.10"),
            format!("/nix/store/{H}-hello-2.11"),
            format!("/nix/store/{H}-x"),
            "/nix/store/short".to_string(),
            String::new(),
            "hello-2.10".to_string(),
        ];
        for candidate in &candidates {
            let owned: String = candidate.clone();
            assert_eq!(
                <StorePath as PartialEq<String>>::eq(&sp, &owned),
                sp.as_str() == owned.as_str(),
                "PartialEq<String> for StorePath must agree with sp.as_str() == owned.as_str() at {candidate:?}",
            );
        }
    }

    /// The reflexive identity
    /// `<StorePath as PartialEq<String>>::eq(&sp, &String::from(sp.as_str()))`
    /// must hold at every [`StorePath`] value — a variant compared
    /// against a heap-owned copy of its own canonical-label emission
    /// always answers true. Pins the accessor's own bytes as a fixed
    /// point of the owned-receiver forward-direction peer so a future
    /// refactor that quietly re-encoded the canonical view breaks here
    /// rather than at every downstream `sp == owned` call site — the
    /// owned-receiver sibling of
    /// [`test_partial_eq_str_reflexive_at_own_canonical_view`].
    #[test]
    fn test_partial_eq_string_reflexive_at_own_canonical_view() {
        for raw in [
            format!("/nix/store/{H}-hello-2.10"),
            format!("/nix/store/{H}-x"),
            format!("/nix/store/{H}-foo-bar-1.2.3"),
            format!("/nix/store/{H}-svc-1.2.3.drv"),
        ] {
            let sp = StorePath::parse(&raw).unwrap();
            let owned: String = String::from(sp.as_str());
            assert!(
                <StorePath as PartialEq<String>>::eq(&sp, &owned),
                "PartialEq<String> for StorePath must be reflexive at own canonical view for {raw:?}",
            );
        }
    }

    /// The trimming discipline of [`StorePath::parse`] reaches through
    /// the owned-receiver forward-direction peer — a value parsed from
    /// a newline-terminated buffer compares equal to a heap-owned copy
    /// of the *trimmed* canonical literal on the owned-receiver side,
    /// not to a heap-owned copy of the raw newline-terminated buffer.
    /// Pins the invariant that the owned-receiver peer reads the same
    /// canonical bytes the accessor exposes, at the wire-boundary
    /// shape the peer exists to serve.
    #[test]
    fn test_partial_eq_string_trims_through_peer() {
        let sp = StorePath::parse(&format!("/nix/store/{H}-svc-1.2.3\n")).unwrap();
        let trimmed: String = format!("/nix/store/{H}-svc-1.2.3");
        let untrimmed: String = format!("/nix/store/{H}-svc-1.2.3\n");
        assert!(<StorePath as PartialEq<String>>::eq(&sp, &trimmed));
        assert!(!<StorePath as PartialEq<String>>::eq(&sp, &untrimmed));
    }

    /// The reverse-direction and forward-direction owned UTF-8
    /// comparison surfaces on the [`StorePath`] typed primitive agree
    /// byte-for-byte at every (owned, [`StorePath`]) pair — the
    /// symmetry axiom
    /// `<String as PartialEq<StorePath>>::eq(&owned, &sp)
    /// == <StorePath as PartialEq<String>>::eq(&sp, &owned)` holds
    /// across the canonical × known-bad candidate grid. Pins the
    /// 2-impl owned-receiver × direction closure so a future refactor
    /// that diverged one impl from its symmetric peer breaks this pin
    /// at at least one pair rather than propagating unnoticed through
    /// downstream generic [`PartialEq`]-bounded consumers that thread
    /// a [`StorePath`] through either side of a `==` operator against
    /// a heap-owned [`String`] key. Structural mirror of
    /// [`test_partial_eq_store_path_symmetric_with_forward_direction`]
    /// on the borrowed-receiver × direction closure.
    #[test]
    fn test_partial_eq_string_store_path_symmetric_with_forward_direction() {
        let sp = StorePath::parse(&format!("/nix/store/{H}-hello-2.10")).unwrap();
        let candidates = [
            format!("/nix/store/{H}-hello-2.10"),
            format!("/nix/store/{H}-hello-2.11"),
            format!("/nix/store/{H}-x"),
            format!("/nix/store/{H}-svc-1.2.3.drv"),
            "/nix/store/short".to_string(),
            String::new(),
            "hello-2.10".to_string(),
        ];
        for candidate in &candidates {
            let owned: String = candidate.clone();
            assert_eq!(
                <String as PartialEq<StorePath>>::eq(&owned, &sp),
                <StorePath as PartialEq<String>>::eq(&sp, &owned),
                "reverse-String and forward-String PartialEq peers must agree at {candidate:?}",
            );
        }
    }

    /// `<StorePath as PartialEq<[u8]>>::eq(&sp, bytes)` must agree
    /// byte-for-byte with `<StorePath as AsRef<[u8]>>::as_ref(&sp) == bytes`
    /// at every (canonical-view, candidate) pair. Pins the delegation
    /// through the [`AsRef<[u8]>`] one-oracle projection so a future
    /// refactor that severed the byte-slice comparison peer from the
    /// borrowed-byte-view accessor (a hand-rolled `as_str().as_bytes()`
    /// re-read, a divergent trimming path) is caught here first at the
    /// forward-direction borrowed byte-slice comparison frontier — the
    /// byte-frontier sibling of
    /// [`test_partial_eq_str_agrees_with_as_str`] on the UTF-8 forward
    /// peer.
    #[test]
    fn test_partial_eq_bytes_agrees_with_as_ref_bytes() {
        let sp = StorePath::parse(&format!("/nix/store/{H}-hello-2.10")).unwrap();
        let candidates: [Vec<u8>; 6] = [
            format!("/nix/store/{H}-hello-2.10").into_bytes(),
            format!("/nix/store/{H}-hello-2.11").into_bytes(),
            format!("/nix/store/{H}-x").into_bytes(),
            b"/nix/store/short".to_vec(),
            Vec::new(),
            b"hello-2.10".to_vec(),
        ];
        for candidate in &candidates {
            let bytes: &[u8] = candidate.as_slice();
            let via_peer: bool = <StorePath as PartialEq<[u8]>>::eq(&sp, bytes);
            let via_accessor: bool = <StorePath as AsRef<[u8]>>::as_ref(&sp) == bytes;
            assert_eq!(
                via_peer, via_accessor,
                "PartialEq<[u8]> peer must agree with as_ref::<[u8]>() == bytes at {candidate:?}",
            );
        }
    }

    /// The reflexive identity
    /// `<StorePath as PartialEq<[u8]>>::eq(&sp, <StorePath as AsRef<[u8]>>::as_ref(&sp))`
    /// must hold at every [`StorePath`] value. Pins the accessor's own
    /// bytes as a fixed point of the byte-slice peer so a future
    /// refactor that quietly re-encoded the canonical byte view breaks
    /// here rather than at every downstream `sp == raw_bytes` call
    /// site — the byte-frontier sibling of
    /// [`test_partial_eq_str_reflexive_at_own_canonical_view`].
    #[test]
    fn test_partial_eq_bytes_reflexive_at_own_canonical_view() {
        for raw in [
            format!("/nix/store/{H}-hello-2.10"),
            format!("/nix/store/{H}-x"),
            format!("/nix/store/{H}-foo-bar-1.2.3"),
            format!("/nix/store/{H}-svc-1.2.3.drv"),
        ] {
            let sp = StorePath::parse(&raw).unwrap();
            let own: &[u8] = <StorePath as AsRef<[u8]>>::as_ref(&sp);
            assert!(
                <StorePath as PartialEq<[u8]>>::eq(&sp, own),
                "PartialEq<[u8]> for StorePath must be reflexive at own canonical view for {raw:?}",
            );
        }
    }

    /// The trimming discipline of [`StorePath::parse`] reaches through
    /// the forward-direction [`PartialEq<[u8]>`] peer — a value parsed
    /// from a newline-terminated buffer compares equal to the *trimmed*
    /// canonical literal as bytes, not to the raw newline-terminated
    /// buffer. Pins the invariant that the byte-slice peer reads the
    /// same canonical bytes the [`AsRef<[u8]>`] accessor exposes, at
    /// the wire-boundary shape the peer exists to serve. Byte-frontier
    /// sibling of [`test_partial_eq_str_trims_through_peer`].
    #[test]
    fn test_partial_eq_bytes_trims_through_peer() {
        let sp = StorePath::parse(&format!("/nix/store/{H}-svc-1.2.3\n")).unwrap();
        let trimmed_bytes = format!("/nix/store/{H}-svc-1.2.3").into_bytes();
        let untrimmed_bytes = format!("/nix/store/{H}-svc-1.2.3\n").into_bytes();
        assert!(<StorePath as PartialEq<[u8]>>::eq(
            &sp,
            trimmed_bytes.as_slice()
        ));
        assert!(!<StorePath as PartialEq<[u8]>>::eq(
            &sp,
            untrimmed_bytes.as_slice()
        ));
    }

    /// `<StorePath as PartialEq<&[u8]>>::eq(&sp, &bytes_ref)` — the
    /// receiver-shape sibling of the [`PartialEq<[u8]>`] peer — must
    /// agree byte-for-byte with the receiver-shape sibling at every
    /// (canonical-view, candidate) pair, so a caller may pick either
    /// receiver at the comparison site without the two peers diverging.
    /// Byte-frontier sibling of
    /// [`test_partial_eq_str_ref_agrees_with_partial_eq_str`].
    #[test]
    fn test_partial_eq_bytes_ref_agrees_with_partial_eq_bytes() {
        let sp = StorePath::parse(&format!("/nix/store/{H}-hello-2.10")).unwrap();
        let candidates: [Vec<u8>; 4] = [
            format!("/nix/store/{H}-hello-2.10").into_bytes(),
            format!("/nix/store/{H}-hello-2.11").into_bytes(),
            b"/nix/store/short".to_vec(),
            Vec::new(),
        ];
        for candidate in &candidates {
            let bytes: &[u8] = candidate.as_slice();
            let via_ref: bool = <StorePath as PartialEq<&[u8]>>::eq(&sp, &bytes);
            let via_val: bool = <StorePath as PartialEq<[u8]>>::eq(&sp, bytes);
            assert_eq!(
                via_ref, via_val,
                "PartialEq<&[u8]> receiver-shape peer must agree with PartialEq<[u8]> at {candidate:?}",
            );
        }
    }

    /// A generic `fn f<A, B>(a: &A, b: &B) -> bool where A: PartialEq<B>`
    /// consumer must accept a borrowed [`StorePath`] against a borrowed
    /// `[u8]` and answer through the trait bound. This is the structural
    /// witness that [`StorePath`] is usable at every downstream generic
    /// [`PartialEq`]-bounded byte-slice comparison site — the surface a
    /// byte-stream wire-echo verifier or a `nom` byte-scrutinee
    /// comparison helper keys off — without a per-site
    /// `<StorePath as AsRef<[u8]>>::as_ref(&sp) == raw_bytes` bridge that
    /// repeats the accessor name.
    #[test]
    fn test_partial_eq_bytes_carries_through_generic_consumer() {
        fn eq_through_bound<A, B: ?Sized>(a: &A, b: &B) -> bool
        where
            A: PartialEq<B>,
        {
            a == b
        }
        let sp = StorePath::parse(&format!("/nix/store/{H}-hello-2.10")).unwrap();
        let match_bytes = format!("/nix/store/{H}-hello-2.10").into_bytes();
        let miss_bytes = format!("/nix/store/{H}-hello-2.11").into_bytes();
        assert!(eq_through_bound::<StorePath, [u8]>(
            &sp,
            match_bytes.as_slice()
        ));
        assert!(!eq_through_bound::<StorePath, [u8]>(
            &sp,
            miss_bytes.as_slice()
        ));
    }

    /// `<[u8] as PartialEq<StorePath>>::eq(bytes, &sp)` must agree
    /// byte-for-byte with `bytes == <StorePath as AsRef<[u8]>>::as_ref(&sp)`
    /// at every (candidate, canonical-view) pair across the canonical,
    /// sibling-hash, shorter-name, malformed-shortcut, empty, tail-only,
    /// and invalid-UTF-8 candidate grid. Pins the delegation through the
    /// [`AsRef<[u8]>`] one-oracle projection on the reverse-direction
    /// borrowed byte-slice peer, so a future refactor that severed the
    /// reverse-direction impl from the accessor (a hand-rolled
    /// `as_str().as_bytes()` re-read, a divergent trimming path, a
    /// stale representation cache) is caught here first at the reverse-
    /// direction borrowed byte-slice comparison frontier — the reverse-
    /// direction byte-frontier sibling of
    /// [`test_str_partial_eq_store_path_agrees_with_as_str`] on the reverse-
    /// direction UTF-8 peer and of [`test_partial_eq_bytes_agrees_with_as_ref_bytes`]
    /// on the forward-direction byte-slice peer.
    #[test]
    fn test_bytes_partial_eq_store_path_agrees_with_as_ref_bytes() {
        let sp = StorePath::parse(&format!("/nix/store/{H}-hello-2.10")).unwrap();
        let candidates: [Vec<u8>; 8] = [
            format!("/nix/store/{H}-hello-2.10").into_bytes(),
            format!("/nix/store/{H}-hello-2.11").into_bytes(),
            format!("/nix/store/{H}-x").into_bytes(),
            format!("/nix/store/{H}-svc-1.2.3.drv").into_bytes(),
            b"/nix/store/short".to_vec(),
            Vec::new(),
            b"hello-2.10".to_vec(),
            vec![0xffu8, 0xfeu8, 0xfdu8],
        ];
        for candidate in &candidates {
            let bytes: &[u8] = candidate.as_slice();
            let via_peer: bool = <[u8] as PartialEq<StorePath>>::eq(bytes, &sp);
            let via_accessor: bool = bytes == <StorePath as AsRef<[u8]>>::as_ref(&sp);
            assert_eq!(
                via_peer, via_accessor,
                "PartialEq<StorePath> for [u8] must agree with bytes == as_ref::<[u8]>() at {candidate:?}",
            );
        }
    }

    /// The reflexive identity
    /// `<[u8] as PartialEq<StorePath>>::eq(<StorePath as AsRef<[u8]>>::as_ref(&sp), &sp)`
    /// must hold at every [`StorePath`] value. Pins the accessor's own
    /// bytes as a fixed point of the reverse-direction `[u8]`-receiver peer
    /// so a future refactor that quietly re-encoded the canonical byte
    /// view breaks here rather than at every downstream `raw_bytes == sp`
    /// call site — the reverse-direction byte-frontier sibling of
    /// [`test_partial_eq_bytes_reflexive_at_own_canonical_view`] and the
    /// byte-frontier sibling of
    /// [`test_str_partial_eq_store_path_reflexive_at_own_canonical_view`].
    #[test]
    fn test_bytes_partial_eq_store_path_reflexive_at_own_canonical_view() {
        for raw in [
            format!("/nix/store/{H}-hello-2.10"),
            format!("/nix/store/{H}-x"),
            format!("/nix/store/{H}-foo-bar-1.2.3"),
            format!("/nix/store/{H}-svc-1.2.3.drv"),
        ] {
            let sp = StorePath::parse(&raw).unwrap();
            let own: &[u8] = <StorePath as AsRef<[u8]>>::as_ref(&sp);
            assert!(
                <[u8] as PartialEq<StorePath>>::eq(own, &sp),
                "PartialEq<StorePath> for [u8] must be reflexive at own canonical view for {raw:?}",
            );
        }
    }

    /// `<&[u8] as PartialEq<StorePath>>::eq(&bytes_ref, &sp)` — the
    /// receiver-shape sibling of the reverse-direction
    /// [`PartialEq<StorePath> for [u8]`] peer — must agree byte-for-byte
    /// with the receiver-shape sibling at every (candidate, canonical-view)
    /// pair, so a caller may pick either receiver at the reverse-direction
    /// comparison site without the two peers diverging. Reverse-direction
    /// byte-frontier sibling of
    /// [`test_partial_eq_bytes_ref_agrees_with_partial_eq_bytes`] on the
    /// forward-direction pair and of
    /// [`test_str_ref_partial_eq_store_path_agrees_with_partial_eq_store_path`]
    /// on the reverse-direction UTF-8 pair.
    #[test]
    fn test_bytes_ref_partial_eq_store_path_agrees_with_bytes_partial_eq_store_path() {
        let sp = StorePath::parse(&format!("/nix/store/{H}-hello-2.10")).unwrap();
        let candidates: [Vec<u8>; 5] = [
            format!("/nix/store/{H}-hello-2.10").into_bytes(),
            format!("/nix/store/{H}-hello-2.11").into_bytes(),
            b"/nix/store/short".to_vec(),
            Vec::new(),
            vec![0xffu8, 0xfeu8, 0xfdu8],
        ];
        for candidate in &candidates {
            let bytes: &[u8] = candidate.as_slice();
            let via_ref: bool = <&[u8] as PartialEq<StorePath>>::eq(&bytes, &sp);
            let via_val: bool = <[u8] as PartialEq<StorePath>>::eq(bytes, &sp);
            assert_eq!(
                via_ref, via_val,
                "PartialEq<StorePath> for &[u8] receiver-shape peer must agree with PartialEq<StorePath> for [u8] at {candidate:?}",
            );
        }
    }

    /// The trimming discipline of [`StorePath::parse`] reaches through the
    /// reverse-direction [`PartialEq<StorePath> for [u8]`] peer — a value
    /// parsed from a newline-terminated buffer compares equal to the
    /// *trimmed* canonical literal as bytes on the reverse-direction side,
    /// not to the raw newline-terminated buffer. Pins the invariant that
    /// the reverse-direction byte-slice peer reads the same canonical
    /// bytes the [`AsRef<[u8]>`] accessor exposes, at the wire-boundary
    /// shape the peer exists to serve. Reverse-direction byte-frontier
    /// sibling of [`test_partial_eq_bytes_trims_through_peer`] on the
    /// forward-direction pair and of
    /// [`test_str_partial_eq_store_path_trims_through_peer`] on the
    /// reverse-direction UTF-8 pair.
    #[test]
    fn test_bytes_partial_eq_store_path_trims_through_peer() {
        let sp = StorePath::parse(&format!("/nix/store/{H}-svc-1.2.3\n")).unwrap();
        let trimmed_bytes = format!("/nix/store/{H}-svc-1.2.3").into_bytes();
        let untrimmed_bytes = format!("/nix/store/{H}-svc-1.2.3\n").into_bytes();
        assert!(<[u8] as PartialEq<StorePath>>::eq(
            trimmed_bytes.as_slice(),
            &sp
        ));
        assert!(!<[u8] as PartialEq<StorePath>>::eq(
            untrimmed_bytes.as_slice(),
            &sp
        ));
    }

    /// The reverse-direction and forward-direction borrowed byte-slice
    /// comparison surfaces on the [`StorePath`] typed primitive agree
    /// byte-for-byte at every (candidate, [`StorePath`]) pair — both
    /// symmetry axioms
    /// `<[u8] as PartialEq<StorePath>>::eq(bytes, &sp)
    /// == <StorePath as PartialEq<[u8]>>::eq(&sp, bytes)` and
    /// `<&[u8] as PartialEq<StorePath>>::eq(&bytes_ref, &sp)
    /// == <StorePath as PartialEq<&[u8]>>::eq(&sp, &bytes_ref)` hold
    /// across the canonical, sibling-hash, shorter-name, empty, tail-only,
    /// and invalid-UTF-8 candidate grid. Pins the full 2×2 receiver ×
    /// direction cross-product closure on the byte-slice frontier at the
    /// [`StorePath`] typed primitive so a future refactor that diverged one
    /// impl from its symmetric peer breaks this pin at at least one pair
    /// rather than propagating unnoticed through downstream generic
    /// [`PartialEq`]-bounded consumers that thread a [`StorePath`] through
    /// either side of a `==` operator at the byte frontier — the byte-
    /// frontier sibling of
    /// [`test_partial_eq_store_path_symmetric_with_forward_direction`] on
    /// the borrowed UTF-8 frontier and structural mirror of
    /// [`crate::retry::tests::test_partial_eq_per_attempt_region_bytes_symmetric_with_forward_direction`]
    /// at the sibling per-attempt-region typed sum.
    #[test]
    fn test_partial_eq_store_path_bytes_symmetric_with_forward_direction() {
        let sp = StorePath::parse(&format!("/nix/store/{H}-hello-2.10")).unwrap();
        let candidates: [Vec<u8>; 8] = [
            format!("/nix/store/{H}-hello-2.10").into_bytes(),
            format!("/nix/store/{H}-hello-2.11").into_bytes(),
            format!("/nix/store/{H}-x").into_bytes(),
            format!("/nix/store/{H}-svc-1.2.3.drv").into_bytes(),
            b"/nix/store/short".to_vec(),
            Vec::new(),
            b"hello-2.10".to_vec(),
            vec![0xffu8, 0xfeu8, 0xfdu8],
        ];
        for candidate in &candidates {
            let bytes: &[u8] = candidate.as_slice();
            assert_eq!(
                <[u8] as PartialEq<StorePath>>::eq(bytes, &sp),
                <StorePath as PartialEq<[u8]>>::eq(&sp, bytes),
                "reverse-direction PartialEq<StorePath> for [u8] must agree with forward-direction PartialEq<[u8]> for StorePath at {candidate:?}",
            );
            assert_eq!(
                <&[u8] as PartialEq<StorePath>>::eq(&bytes, &sp),
                <StorePath as PartialEq<&[u8]>>::eq(&sp, &bytes),
                "reverse-direction PartialEq<StorePath> for &[u8] must agree with forward-direction PartialEq<&[u8]> for StorePath at {candidate:?}",
            );
        }
    }

    /// `<StorePath as PartialEq<Vec<u8>>>::eq(&sp, &owned_bytes)` must
    /// agree byte-for-byte with
    /// `<StorePath as AsRef<[u8]>>::as_ref(&sp) == owned_bytes.as_slice()`
    /// at every (canonical-view, candidate) pair across the canonical,
    /// sibling-hash, shorter-name, `.drv`-suffixed, empty, tail-only,
    /// and invalid-UTF-8 candidate grid. Pins the delegation through the
    /// [`AsRef<[u8]>`] one-oracle projection on the forward-direction
    /// owned byte-vec peer, so a future refactor that severed the peer
    /// from the accessor (a hand-rolled `as_str().as_bytes()` re-read on
    /// the receiver side, a divergent trimming path, a
    /// [`String::from_utf8`] detour through the UTF-8-side owned peer) is
    /// caught here first at the forward-direction owned byte-vec
    /// comparison frontier — the byte-frontier sibling of
    /// [`test_partial_eq_string_agrees_with_as_str`] on the owned UTF-8
    /// forward peer and the owned-receiver sibling of
    /// [`test_partial_eq_bytes_agrees_with_as_ref_bytes`] on the
    /// borrowed byte-slice forward peer.
    #[test]
    fn test_partial_eq_vec_bytes_agrees_with_as_ref_bytes() {
        let sp = StorePath::parse(&format!("/nix/store/{H}-hello-2.10")).unwrap();
        let candidates: [Vec<u8>; 8] = [
            format!("/nix/store/{H}-hello-2.10").into_bytes(),
            format!("/nix/store/{H}-hello-2.11").into_bytes(),
            format!("/nix/store/{H}-x").into_bytes(),
            format!("/nix/store/{H}-svc-1.2.3.drv").into_bytes(),
            b"/nix/store/short".to_vec(),
            Vec::new(),
            b"hello-2.10".to_vec(),
            vec![0xffu8, 0xfeu8, 0xfdu8],
        ];
        for candidate in &candidates {
            let via_peer: bool = <StorePath as PartialEq<Vec<u8>>>::eq(&sp, candidate);
            let via_accessor: bool =
                <StorePath as AsRef<[u8]>>::as_ref(&sp) == candidate.as_slice();
            assert_eq!(
                via_peer, via_accessor,
                "PartialEq<Vec<u8>> for StorePath must agree with as_ref::<[u8]>() == owned.as_slice() at {candidate:?}",
            );
        }
    }

    /// The reflexive identity
    /// `<StorePath as PartialEq<Vec<u8>>>::eq(&sp,
    /// &<StorePath as AsRef<[u8]>>::as_ref(&sp).to_vec())` must hold at
    /// every [`StorePath`] value — a variant compared against a heap-
    /// owned copy of its own canonical byte view always answers true.
    /// Pins the accessor's own bytes as a fixed point of the owned-
    /// receiver forward-direction peer so a future refactor that quietly
    /// re-encoded the canonical byte view breaks here rather than at
    /// every downstream `sp == owned_bytes` call site — the byte-frontier
    /// sibling of [`test_partial_eq_string_reflexive_at_own_canonical_view`]
    /// on the owned UTF-8 forward peer.
    #[test]
    fn test_partial_eq_vec_bytes_reflexive_at_own_canonical_view() {
        for raw in [
            format!("/nix/store/{H}-hello-2.10"),
            format!("/nix/store/{H}-x"),
            format!("/nix/store/{H}-foo-bar-1.2.3"),
            format!("/nix/store/{H}-svc-1.2.3.drv"),
        ] {
            let sp = StorePath::parse(&raw).unwrap();
            let owned_bytes: Vec<u8> = <StorePath as AsRef<[u8]>>::as_ref(&sp).to_vec();
            assert!(
                <StorePath as PartialEq<Vec<u8>>>::eq(&sp, &owned_bytes),
                "PartialEq<Vec<u8>> for StorePath must be reflexive at own canonical view for {raw:?}",
            );
        }
    }

    /// The trimming discipline of [`StorePath::parse`] reaches through the
    /// forward-direction owned byte-vec peer — a value parsed from a
    /// newline-terminated buffer compares equal to a heap-owned copy of
    /// the *trimmed* canonical literal on the owned-byte-vec side, not to
    /// a heap-owned copy of the raw newline-terminated buffer. Pins the
    /// invariant that the owned-byte-vec peer reads the same canonical
    /// bytes the [`AsRef<[u8]>`] accessor exposes, at the wire-boundary
    /// shape the peer exists to serve — the byte-frontier sibling of
    /// [`test_partial_eq_string_trims_through_peer`] on the owned UTF-8
    /// pair and the owned-receiver sibling of
    /// [`test_partial_eq_bytes_trims_through_peer`] on the borrowed
    /// byte-slice pair.
    #[test]
    fn test_partial_eq_vec_bytes_trims_through_peer() {
        let sp = StorePath::parse(&format!("/nix/store/{H}-svc-1.2.3\n")).unwrap();
        let trimmed: Vec<u8> = format!("/nix/store/{H}-svc-1.2.3").into_bytes();
        let untrimmed: Vec<u8> = format!("/nix/store/{H}-svc-1.2.3\n").into_bytes();
        assert!(<StorePath as PartialEq<Vec<u8>>>::eq(&sp, &trimmed));
        assert!(!<StorePath as PartialEq<Vec<u8>>>::eq(&sp, &untrimmed));
    }

    /// The reverse-direction and forward-direction owned byte-vec
    /// comparison surfaces on the [`StorePath`] typed primitive agree
    /// byte-for-byte at every (owned_bytes, [`StorePath`]) pair — the
    /// symmetry axiom
    /// `<Vec<u8> as PartialEq<StorePath>>::eq(&owned_bytes, &sp)
    /// == <StorePath as PartialEq<Vec<u8>>>::eq(&sp, &owned_bytes)` holds
    /// across the canonical, sibling-hash, shorter-name, `.drv`-suffixed,
    /// empty, tail-only, and invalid-UTF-8 candidate grid. Pins the
    /// 2-impl owned-byte-vec × direction closure so a future refactor
    /// that diverged one impl from its symmetric peer breaks this pin at
    /// at least one pair rather than propagating unnoticed through
    /// downstream generic [`PartialEq`]-bounded consumers that thread a
    /// [`StorePath`] through either side of a `==` operator against a
    /// heap-owned [`Vec<u8>`] key. Structural mirror of
    /// [`test_partial_eq_string_store_path_symmetric_with_forward_direction`]
    /// on the owned UTF-8 pair and of
    /// [`test_partial_eq_store_path_bytes_symmetric_with_forward_direction`]
    /// on the borrowed byte-slice pair.
    #[test]
    fn test_partial_eq_vec_bytes_store_path_symmetric_with_forward_direction() {
        let sp = StorePath::parse(&format!("/nix/store/{H}-hello-2.10")).unwrap();
        let candidates: [Vec<u8>; 8] = [
            format!("/nix/store/{H}-hello-2.10").into_bytes(),
            format!("/nix/store/{H}-hello-2.11").into_bytes(),
            format!("/nix/store/{H}-x").into_bytes(),
            format!("/nix/store/{H}-svc-1.2.3.drv").into_bytes(),
            b"/nix/store/short".to_vec(),
            Vec::new(),
            b"hello-2.10".to_vec(),
            vec![0xffu8, 0xfeu8, 0xfdu8],
        ];
        for candidate in &candidates {
            assert_eq!(
                <Vec<u8> as PartialEq<StorePath>>::eq(candidate, &sp),
                <StorePath as PartialEq<Vec<u8>>>::eq(&sp, candidate),
                "reverse-Vec<u8> and forward-Vec<u8> PartialEq peers must agree at {candidate:?}",
            );
        }
    }
}
