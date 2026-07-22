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

    /// The algorithm prefix of the validated digest: `"sha256"` or
    /// `"sha512"`. Read-back accessor so a consumer that pins a policy
    /// on the algorithm at its own attestation boundary (e.g.
    /// [`crate::helm_provenance`]'s sha256-only chart-hash cross-check)
    /// can distinguish arms directly rather than re-splitting the full
    /// string.
    ///
    /// The parse invariant guarantees exactly one `:` separates the
    /// algorithm from the hex body and the algorithm is one of the
    /// values matched in [`Self::parse`], so this returns the unchecked
    /// head slice; the trailing `.unwrap_or_default()` is unreachable
    /// under a valid `ContentDigest`.
    ///
    /// `allow(dead_code)`: part of the primitive read-back surface,
    /// same discipline as [`Self::as_str`].
    #[allow(dead_code)]
    pub fn algorithm(&self) -> &str {
        self.full
            .split_once(':')
            .map(|(algo, _)| algo)
            .unwrap_or_default()
    }

    /// The lowercase-hex body of the validated digest — the payload
    /// after the `<algorithm>:` prefix. Read-back accessor so a
    /// consumer that stores the hex without the algorithm prefix (e.g.
    /// [`crate::helm_provenance::HelmProvenanceOutcome::Verified::signed_chart_hash`],
    /// documented as "no algorithm prefix, lowercase hex") extracts it
    /// off the typed primitive rather than re-parsing.
    ///
    /// Same parse-invariant unreachability as [`Self::algorithm`].
    ///
    /// `allow(dead_code)`: part of the primitive read-back surface,
    /// same discipline as [`Self::as_str`].
    #[allow(dead_code)]
    pub fn hex(&self) -> &str {
        self.full
            .split_once(':')
            .map(|(_, hex)| hex)
            .unwrap_or_default()
    }
}

impl std::fmt::Display for ContentDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.full)
    }
}

/// Parse a [`&str`] into a validated [`ContentDigest`] via the canonical
/// `<algorithm>:<hex>` grammar. Delegates to the inherent
/// [`ContentDigest::parse`] oracle so the grammar is defined at one
/// site and every read surface — `parse`, this `FromStr` impl, the
/// derived `str::parse::<ContentDigest>()` and `T: FromStr` generic
/// bounds — reads through it.
///
/// This is the derived idiom-frontier surface for the
/// [`crate::oci_manifest`] reference-grammar parser family: every other
/// typed primitive in forge's typed-primitive algebra that carries a
/// canonical-label parser (`crate::retry::PerAttemptRegion`,
/// `crate::probe_outcome::AdmissionTier`, `crate::version::BumpLevel`)
/// exposes its parser through both the inherent method AND the
/// [`std::str::FromStr`] trait, so consumers who parse via the
/// `.parse::<T>()` turbofish, thread the type through a
/// `T: FromStr` generic bound, or rehydrate a value through a serde
/// `#[serde(with = "...")]` bridge, all read through the SAME canonical
/// grammar oracle without a per-consumer bridge. Prior to this impl
/// [`ContentDigest`] was the only reference-grammar-family primitive
/// missing the trait surface — its inherent [`ContentDigest::parse`]
/// oracle existed but consumers who wanted to compose it with
/// [`str::parse`] (`"sha256:{hex}".parse::<ContentDigest>()`) or with
/// a [`T: FromStr`] iterator adapter
/// (`strs.iter().filter_map(|s| s.parse::<ContentDigest>().ok())`)
/// could not, and had to fall back to the inherent-method call
/// (`ContentDigest::parse(s).ok()`) at every consumer.
///
/// The [`Err`](std::str::FromStr::Err) type is [`ContentDigestError`] —
/// the same typed error the inherent oracle emits, carrying the same
/// per-failure-mode discriminator (missing separator, unsupported
/// algorithm, invalid hex) so a consumer that pins a per-variant
/// handling policy at its own frontier can distinguish arms directly
/// off the [`Result<ContentDigest, ContentDigestError>`] the impl
/// returns, matching the discipline every other reference-grammar
/// consumer already observes (`crate::helm_provenance::
/// find_tarball_sha256`, `crate::cosign::parse_verify_output`).
///
/// THEORY.md §III.1 typescape: the content-digest reference grammar
/// is a typed primitive on the platform, and its parse frontier is
/// one oracle serving every idiomatic Rust read surface (inherent
/// method, [`FromStr`](std::str::FromStr), `.parse::<T>()`,
/// `T: FromStr` bounds), not a per-consumer restatement of
/// "well-formed `<algorithm>:<hex>`". THEORY.md §VI.1
/// generation over composition: the canonical parse predicate is
/// named at one site ([`ContentDigest::parse`]), the derived read
/// surfaces route through it, and a future refinement to the grammar
/// (widening to `sha384`, tightening the trim behaviour) is a
/// one-site edit at the inherent oracle without a per-consumer
/// cascade.
impl std::str::FromStr for ContentDigest {
    type Err = ContentDigestError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// [`TryFrom<&str>`] for [`ContentDigest`] routes through
/// [`<ContentDigest as std::str::FromStr>::from_str`] so a downstream
/// consumer bound by `impl TryFrom<&str>` (a serde container that opts
/// into `#[serde(try_from = "&str")]` on a wrapper field, a generic
/// try-conversion helper `fn parse_digest<T: for<'a> TryFrom<&'a str,
/// Error = ContentDigestError>>`, a validated-input newtype builder
/// whose canonical parse contract is stated as [`TryFrom<&str>`] rather
/// than [`std::str::FromStr`]) recovers a [`ContentDigest`] value from
/// its canonical `<algorithm>:<hex>` string through the same one-oracle
/// grammar the direct `.parse::<ContentDigest>()` call sites already
/// read.
///
/// The by-reference parse peer of [`std::str::FromStr for ContentDigest`]
/// on the reference-grammar family — same discipline the sibling typed
/// primitives [`crate::retry::PerAttemptRegion`],
/// [`crate::probe_outcome::AdmissionTier`], and
/// [`crate::version::BumpLevel`] already carry (each of them exposes
/// [`std::str::FromStr`] AND [`TryFrom<&str>`], both routing through the
/// shared canonical-label parse oracle) — now extended to the digest
/// reference-grammar family so every canonical-string typed primitive in
/// forge's typed-primitive algebra exposes the SAME two-surface pair
/// (inherent `parse` + [`FromStr`] + [`TryFrom<&str>`], all reading
/// through the ONE [`ContentDigest::parse`] grammar oracle) without
/// exception.
///
/// The [`Err`](std::convert::TryFrom::Error) type is
/// [`ContentDigestError`] — the same typed error [`ContentDigest::parse`]
/// and [`<ContentDigest as std::str::FromStr>::from_str`] emit, carrying
/// the same per-failure-mode discriminator (missing separator,
/// unsupported algorithm, invalid hex) so a consumer that pins a
/// per-variant handling policy at its own frontier can distinguish arms
/// directly off the [`Result<ContentDigest, ContentDigestError>`] the
/// impl returns, matching the discipline every other reference-grammar
/// consumer already observes.
///
/// The natural bridge to the serde `try_from` container attribute
/// (`#[serde(try_from = "&str")]` — which keys off [`TryFrom<&str>`],
/// not [`std::str::FromStr`]) so a downstream config-schema field that
/// wraps a [`ContentDigest`] and wants serde's `try_from` grammar reads
/// through the same one-oracle predicate at zero per-consumer bridge
/// cost. The [`FromStr`](std::str::FromStr) impl carries the load-
/// bearing delegation to [`ContentDigest::parse`]; this [`TryFrom<&str>`]
/// impl delegates through it, so the parse-oracle discipline is
/// preserved end-to-end and a future grammar refinement (widening to
/// `sha384`, tightening the trim behaviour) remains a one-site edit at
/// the inherent [`ContentDigest::parse`] oracle without a per-derived-
/// surface cascade.
///
/// THEORY.md §III.1 typescape: the by-reference try-conversion surface
/// is a typed-primitive site on [`ContentDigest`] itself (one
/// [`TryFrom<&str>`] impl routing through the [`FromStr`] parse oracle),
/// not a per-consumer `.parse::<ContentDigest>()` bridge at every
/// downstream site that types its parse contract as
/// `impl TryFrom<&str>` rather than [`std::str::FromStr`]. THEORY.md
/// §VI.1 one-oracle: the canonical `<algorithm>:<hex>` grammar is named
/// at one site ([`ContentDigest::parse`]), and every parse surface —
/// [`std::str::FromStr`], this [`TryFrom<&str>`], a future
/// [`serde::Deserialize`] impl — reads through it.
impl TryFrom<&str> for ContentDigest {
    type Error = ContentDigestError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        <Self as std::str::FromStr>::from_str(s)
    }
}

/// [`TryFrom<String>`] for [`ContentDigest`] routes through
/// [`<ContentDigest as TryFrom<&str>>::try_from`] so a downstream consumer
/// bound by `impl TryFrom<String>` (a serde container that opts into
/// `#[serde(try_from = "String")]` on a wrapper field, a generic
/// try-conversion helper `fn parse_digest<T: TryFrom<String, Error =
/// ContentDigestError>>`, an owned-input pipeline that consumes
/// `Vec<String>` and produces `Vec<ContentDigest>`) recovers a
/// [`ContentDigest`] value from its canonical `<algorithm>:<hex>` owned
/// string through the same one-oracle grammar the direct
/// `.parse::<ContentDigest>()` call sites already read.
///
/// The by-value peer of [`TryFrom<&str> for ContentDigest`] on the
/// reference-grammar family — a canonical-string typed primitive is
/// parseable both from a borrowed [`&str`] (idiomatic borrow-frontier
/// consumer) AND from an owned [`String`] (idiomatic serde-frontier
/// consumer, where the [`Deserializer`](serde::Deserializer) already
/// produced an owned string and `try_from = "String"` is the container
/// attribute that keys off [`TryFrom<String>`], not [`TryFrom<&str>`]).
/// Prior to this impl a downstream site that received an owned
/// [`String`] (a config-schema field deserialized off a YAML file, a
/// captured registry response the caller already owns) and wanted the
/// typed [`ContentDigest`] had to bridge through [`str`]
/// (`ContentDigest::try_from(owned.as_str())`) at every consumer.
///
/// The [`Err`](std::convert::TryFrom::Error) type is
/// [`ContentDigestError`] — the same typed error every by-reference and
/// by-value parse surface emits, carrying the same per-failure-mode
/// discriminator (missing separator, unsupported algorithm, invalid
/// hex) so a consumer that pins a per-variant handling policy at its
/// own frontier can distinguish arms directly off the
/// [`Result<ContentDigest, ContentDigestError>`] the impl returns.
///
/// The natural bridge to the serde `try_from` container attribute keyed
/// on [`String`] (`#[serde(try_from = "String")]`) — the common shape
/// for a config-schema field whose canonical grammar is a string but
/// whose typed value carries a validating parser. A downstream
/// attestation-record schema that wraps a [`ContentDigest`] and wants
/// serde to hand it an owned [`String`] rather than a borrowed
/// [`&str`] (the default when the schema field is bounded by
/// [`Deserialize`](serde::Deserialize) and the [`Deserializer`] does
/// not implement zero-copy borrow) reads through the same one-oracle
/// predicate at zero per-consumer bridge cost.
///
/// THEORY.md §III.1 typescape: the by-value try-conversion surface is
/// a typed-primitive site on [`ContentDigest`] itself (one
/// [`TryFrom<String>`] impl routing through the [`TryFrom<&str>`]
/// parse oracle), not a per-consumer `owned.as_str()` bridge at every
/// downstream site that types its parse contract as
/// `impl TryFrom<String>` rather than [`TryFrom<&str>`]. THEORY.md
/// §VI.1 one-oracle: the canonical `<algorithm>:<hex>` grammar is
/// named at one site ([`ContentDigest::parse`]), and every parse
/// surface — [`std::str::FromStr`], [`TryFrom<&str>`], this
/// [`TryFrom<String>`] — reads through it.
impl TryFrom<String> for ContentDigest {
    type Error = ContentDigestError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        <Self as TryFrom<&str>>::try_from(s.as_str())
    }
}

/// [`TryFrom<Cow<'_, str>>`] for [`ContentDigest`] routes through
/// [`<ContentDigest as TryFrom<&str>>::try_from`] on the underlying
/// [`str`] view (borrowed from the `Cow::Borrowed` arm, dereferenced
/// off the `String` in the `Cow::Owned` arm) so a downstream consumer
/// bound by `impl TryFrom<Cow<'_, str>>` (a serde-compatible
/// deserializer that hands its container an owned-or-borrowed
/// [`Cow<'_, str>`] to preserve zero-copy where the input allows it, a
/// generic try-conversion helper `fn parse_digest<'a, T: TryFrom<Cow<'a,
/// str>, Error = ContentDigestError>>`, a validated-builder frontier
/// that pins its input type as [`Cow`] to bridge caller-owned and
/// caller-borrowed inputs at zero extra allocation) recovers a
/// [`ContentDigest`] value from its canonical `<algorithm>:<hex>`
/// borrowed-or-owned string through the same one-oracle grammar the
/// direct `.parse::<ContentDigest>()` call sites already read.
///
/// The borrowed/owned-frontier peer of [`TryFrom<&str> for
/// ContentDigest`] and [`TryFrom<String> for ContentDigest`] on the
/// reference-grammar family — a canonical-string typed primitive is
/// parseable from a borrowed [`&str`] (idiomatic borrow-frontier
/// consumer), from an owned [`String`] (idiomatic serde-frontier
/// consumer keyed on `#[serde(try_from = "String")]`), AND from a
/// [`Cow<'_, str>`] (idiomatic borrowed-or-owned frontier consumer
/// keyed on `#[serde(try_from = "Cow<'_, str>")]` or a serde
/// deserializer that emits [`Cow`] to preserve zero-copy for
/// borrowable inputs while still handling owned inputs). Prior to
/// this impl a downstream site that received a [`Cow<'_, str>`] (a
/// serde-derived container whose canonical field type is [`Cow`] to
/// preserve zero-copy, an owned-or-borrowed pipeline that consumes
/// [`Cow`] to defer the ownership decision to its caller) and wanted
/// the typed [`ContentDigest`] had to bridge through [`str`]
/// (`ContentDigest::try_from(cow.as_ref())`) at every consumer.
///
/// The [`Err`](std::convert::TryFrom::Error) type is
/// [`ContentDigestError`] — the same typed error every by-reference
/// and by-value parse surface emits, carrying the same per-failure-
/// mode discriminator (missing separator, unsupported algorithm,
/// invalid hex) so a consumer that pins a per-variant handling policy
/// at its own frontier can distinguish arms directly off the
/// [`Result<ContentDigest, ContentDigestError>`] the impl returns.
///
/// THEORY.md §III.1 typescape: the borrowed/owned-frontier try-
/// conversion surface is a typed-primitive site on [`ContentDigest`]
/// itself (one [`TryFrom<Cow<'_, str>>`] impl routing through the
/// [`TryFrom<&str>`] parse oracle), not a per-consumer
/// `cow.as_ref()` bridge at every downstream site that types its
/// parse contract as `impl TryFrom<Cow<'_, str>>` rather than
/// [`TryFrom<&str>`]. THEORY.md §VI.1 one-oracle: the canonical
/// `<algorithm>:<hex>` grammar is named at one site
/// ([`ContentDigest::parse`]), and every parse surface —
/// [`std::str::FromStr`], [`TryFrom<&str>`], [`TryFrom<String>`],
/// this [`TryFrom<Cow<'_, str>>`] — reads through it.
impl TryFrom<std::borrow::Cow<'_, str>> for ContentDigest {
    type Error = ContentDigestError;

    fn try_from(s: std::borrow::Cow<'_, str>) -> Result<Self, Self::Error> {
        <Self as TryFrom<&str>>::try_from(s.as_ref())
    }
}

/// [`AsRef<str>`] for [`ContentDigest`] routes through
/// [`ContentDigest::as_str`] so a downstream consumer bound by
/// `impl AsRef<str>` (a [`std::path::Path::new`] / [`std::fs::write`]
/// path-segment builder that opens an on-disk cache slot keyed by the
/// full `<algorithm>:<hex>` reference, a [`std::collections::HashSet<&str>`]
/// membership check against a set of expected registry digests, a
/// generic log / tracing attribute setter that keys by
/// [`Into<Cow<'static, str>>`] via the borrowed-view [`AsRef<str>`]
/// coercion, a [`std::process::Command::arg`] slot that pins its input
/// as `impl AsRef<std::ffi::OsStr>` and reads the digest through the
/// blanket [`AsRef<std::ffi::OsStr>`] impl for every `T: AsRef<str>`,
/// a URL-path assembler that appends a validated digest to a registry
/// blob reference under `/v2/<name>/blobs/<digest>`) reads the
/// validated `<algorithm>:<hex>` full string directly off a
/// [`ContentDigest`] value without a per-consumer
/// `digest.as_str()` bridge, without a [`std::fmt::Display`] format-
/// buffer step, and without an intermediate [`String`] allocation.
///
/// The by-reference borrowed-view read peer of the emit surfaces
/// already on the reference-grammar family — [`ContentDigest::as_str`]
/// (inherent) and [`std::fmt::Display for ContentDigest`] both read
/// the same underlying full-digest slice through
/// [`ContentDigest::as_str`]; this [`AsRef<str>`] impl exposes the
/// same slice through the standard-library trait-generic borrowed-
/// view surface the entire std ecosystem already uses
/// (`Path::new`, `Command::arg`, `HashSet::contains`,
/// `HashMap<K: Borrow<str>, _>::get`, `str::eq_ignore_ascii_case`,
/// hasher `update`, formatter `write_str`) so a downstream site that
/// pins its input type as `impl AsRef<str>` recovers the borrowed
/// full-digest slice through the same one-oracle read discipline
/// [`ContentDigest::as_str`] already carries. Structural mirror of
/// [`impl AsRef<std::ffi::CStr> for crate::retry::PerAttemptRegion`],
/// [`impl AsRef<std::ffi::CStr> for crate::probe_outcome::AdmissionTier`],
/// and [`impl AsRef<std::ffi::CStr> for crate::version::BumpLevel`]
/// (commits 307bce0 / e8cbfaf / f6d4f39 — the same borrowed-view lift
/// at the NUL-terminated C-string frontier on the label-axis ordered
/// typed sums, each routing through the shared canonical-label
/// oracle) — now extended to the digest reference-grammar family at
/// the UTF-8 borrowed-view frontier so the parse-oracle-bounded typed
/// primitive [`ContentDigest`] exposes the same trait-generic
/// borrowed-view surface every sibling typed primitive already
/// carries, without exception.
///
/// Zero-cost by construction: the returned `&str` is a borrow off
/// [`ContentDigest::full`] (the trimmed, validated full-digest
/// backing string) via [`ContentDigest::as_str`], so a consumer that
/// borrows the slice reads directly into the value's own storage
/// without a copy, an allocation, or a formatter round-trip through
/// [`std::fmt::Display`]. The identity
/// `digest.as_ref() == digest.as_str()` at every validated
/// [`ContentDigest`] value is pinned by
/// [`tests::test_as_ref_str_matches_as_str`]; the identity carrying
/// through a generic `impl AsRef<str>` consumer is pinned by
/// [`tests::test_as_ref_str_carries_through_generic_consumer`]; the
/// parse-round-trip identity through the borrowed-view surface is
/// pinned by [`tests::test_as_ref_str_parse_round_trip`].
///
/// A future refinement to the inherent [`ContentDigest::parse`]
/// grammar (widening to `sha384`, tightening the trim behaviour) or
/// to the [`ContentDigest::as_str`] read accessor (a canonicalising
/// projection, a case-normalising view) updates the one-oracle site
/// alone and every consumer — cache-slot path builder, registry
/// blob-URL assembler, hasher `update` sink, HashSet membership check
/// — that accepts `impl AsRef<str>` inherits the refined slice
/// automatically with no downstream retyping.
///
/// THEORY.md §III.1 typescape: the borrowed-view UTF-8 read surface
/// is a typed-primitive site on [`ContentDigest`] itself (one
/// [`AsRef<str>`] impl routing through the
/// [`ContentDigest::as_str`] read oracle), not a per-consumer
/// `digest.as_str()` restatement at every downstream site that
/// accepts `impl AsRef<str>`. THEORY.md §VI.1 one-oracle: the
/// validated full-digest slice is named at one site
/// ([`ContentDigest::as_str`], reading through the
/// [`ContentDigest::parse`]-guarded backing string), and every
/// borrowed-view read surface — the inherent
/// [`ContentDigest::as_str`] accessor, the format machinery
/// [`std::fmt::Display`], this [`AsRef<str>`] trait-generic peer —
/// reads through it.
impl AsRef<str> for ContentDigest {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// [`AsRef<[u8]>`] for [`ContentDigest`] routes through
/// [`<ContentDigest as AsRef<str>>::as_ref`] (in turn
/// [`ContentDigest::as_str`]) via [`str::as_bytes`] so a downstream
/// consumer bound by `impl AsRef<[u8]>` (a `blake3::Hasher::update` /
/// `sha2::Digest::update` / `crate::tameshi::Blake3Hash::digest`
/// streaming hasher sink that feeds the validated
/// `<algorithm>:<hex>` bytes into a downstream attestation-chain
/// fingerprint, a [`std::collections::HashSet<&[u8]>`] membership
/// check against a set of expected registry digests keyed on their
/// byte-slice identity, a raw-write output sink
/// (`out.write_all(&digest)`), a `nom` / `winnow` byte-slice parser
/// that treats the digest as a bounded byte token, an
/// `hmac::Mac::update` MAC accumulator that reads its input as
/// bytes) reads the validated `<algorithm>:<hex>` full string
/// directly off a [`ContentDigest`] value as UTF-8 bytes without a
/// per-consumer `digest.as_str().as_bytes()` bridge, without a
/// [`std::fmt::Display`] format-buffer step, and without an
/// intermediate [`String`] / [`Vec<u8>`] allocation.
///
/// The byte-slice borrowed-view read peer of the UTF-8 borrowed-view
/// read surface [`AsRef<str> for ContentDigest`] already on the
/// reference-grammar family — both read the same underlying
/// full-digest slice through [`ContentDigest::as_str`], one exposing
/// it at the UTF-8 frontier (`&str`) and this one at the byte-slice
/// frontier (`&[u8]`) that streaming hashers, MAC accumulators, and
/// raw-write sinks pin their input contract on. Structural mirror
/// of [`impl AsRef<[u8]> for crate::retry::PerAttemptRegion`],
/// [`impl AsRef<[u8]> for crate::probe_outcome::AdmissionTier`],
/// and [`impl AsRef<[u8]> for crate::version::BumpLevel`] — the
/// same borrowed-view lift at the byte-slice frontier the sibling
/// label-axis ordered typed sums already carry, each routing
/// through the shared canonical-label oracle — now extended to the
/// digest reference-grammar family so the parse-oracle-bounded
/// typed primitive [`ContentDigest`] exposes the same trait-generic
/// byte-slice borrowed-view surface every sibling typed primitive
/// already carries, without exception.
///
/// Zero-cost by construction: the returned `&[u8]` is a borrow off
/// the UTF-8 backing string via [`str::as_bytes`], which itself
/// borrows off [`ContentDigest::full`] (the trimmed, validated
/// full-digest backing string) through [`ContentDigest::as_str`],
/// so a consumer that borrows the byte slice reads directly into
/// the value's own storage without a copy, an allocation, or a
/// formatter round-trip. The identity
/// `<ContentDigest as AsRef<[u8]>>::as_ref(&d) ==
/// <ContentDigest as AsRef<str>>::as_ref(&d).as_bytes()` at every
/// validated [`ContentDigest`] value is pinned by
/// [`tests::test_as_ref_bytes_matches_as_ref_str_bytes`]; the
/// identity carrying through a generic `impl AsRef<[u8]>`
/// consumer is pinned by
/// [`tests::test_as_ref_bytes_carries_through_generic_consumer`];
/// the parse-round-trip identity through the byte-slice surface
/// (parsing back via [`std::str::from_utf8`]) is pinned by
/// [`tests::test_as_ref_bytes_parse_round_trip`].
///
/// The validated full-digest bytes are pure lowercase-hex plus
/// `sha256`/`sha512`/`:` — every byte is ASCII by parse invariant,
/// so a byte-slice consumer that treats the input as ASCII (a
/// case-insensitive comparator on the `sha256` prefix, an ASCII
/// hex-digit walker on the `<hex>` body) reads the same
/// canonicalised form the UTF-8 surface exposes with no
/// multibyte-boundary hazard.
///
/// A future refinement to the inherent [`ContentDigest::parse`]
/// grammar (widening to `sha384`, tightening the trim behaviour)
/// or to the [`ContentDigest::as_str`] read accessor (a
/// canonicalising projection, a case-normalising view) updates the
/// one-oracle site alone and every consumer — streaming hasher
/// sink, HashSet-of-bytes membership check, raw-write output sink,
/// MAC accumulator — that accepts `impl AsRef<[u8]>` inherits the
/// refined byte slice automatically with no downstream retyping.
///
/// THEORY.md §III.1 typescape: the borrowed-view byte-slice read
/// surface is a typed-primitive site on [`ContentDigest`] itself
/// (one [`AsRef<[u8]>`] impl routing through the [`AsRef<str>`]
/// and [`ContentDigest::as_str`] read oracle via
/// [`str::as_bytes`]), not a per-consumer
/// `digest.as_str().as_bytes()` restatement at every downstream
/// site that accepts `impl AsRef<[u8]>`. THEORY.md §VI.1
/// one-oracle: the validated full-digest slice is named at one
/// site ([`ContentDigest::as_str`], reading through the
/// [`ContentDigest::parse`]-guarded backing string), and every
/// borrowed-view read surface — the inherent
/// [`ContentDigest::as_str`] accessor, the format machinery
/// [`std::fmt::Display`], the trait-generic UTF-8 peer
/// [`AsRef<str>`], this byte-slice peer [`AsRef<[u8]>`] — reads
/// through it.
impl AsRef<[u8]> for ContentDigest {
    fn as_ref(&self) -> &[u8] {
        <Self as AsRef<str>>::as_ref(self).as_bytes()
    }
}

/// [`From<ContentDigest>`] for [`String`] moves the validated
/// `<algorithm>:<hex>` backing string out of the consumed
/// [`ContentDigest`] value at zero-copy — no allocation, no
/// re-formatting through [`std::fmt::Display`], no
/// `digest.as_str().to_owned()` bridge. A downstream consumer that
/// owns a [`ContentDigest`] and needs to hand it off as an owned
/// [`String`] to a [`std::collections::HashMap<String, _>`] key, a
/// [`Vec<String>`] entry, a [`serde_json::Value::String`] payload,
/// an HTTP header value that pins its input contract as
/// `impl Into<String>` (a `reqwest::header::HeaderValue::from_str`
/// bridge that keys off `String`, an
/// [`http::HeaderValue::from_maybe_shared`] sink), or a config-schema
/// field that owns its digest text (a
/// [`crate::deployment_manifest`] structural field that stores the
/// canonical `<algorithm>:<hex>` form as `String` for downstream
/// serialization) is a one-line `String::from(digest)` /
/// `digest.into()` call, not a per-site `digest.as_str().to_owned()`
/// or `digest.to_string()` bridge that pays a redundant allocation
/// AND a redundant [`std::fmt::Display`] format-buffer round-trip.
///
/// The by-value owned-UTF-8 emit peer of the by-reference
/// borrowed-view read peer [`AsRef<str> for ContentDigest`] (commit
/// 6a321e3): both surfaces read the same underlying validated
/// full-digest slice, one exposing it borrowed at the UTF-8 frontier
/// (`&str`) and this one emitting it owned at the [`String`]
/// frontier that owned-input consumers pin their contract on. The
/// symmetric emit-side sibling of [`TryFrom<String> for
/// ContentDigest`] (commit f175833): the two together close the
/// by-value owned-UTF-8 input+output symmetry on the reference-
/// grammar family — [`TryFrom<String>`] parses a canonical
/// `<algorithm>:<hex>` from an owned [`String`] through the
/// [`ContentDigest::parse`] oracle, this [`From<ContentDigest>`]
/// emits the canonical `<algorithm>:<hex>` as an owned [`String`]
/// through the moved backing string — so a consumer that receives
/// an owned digest string, parses it into a [`ContentDigest`],
/// validates it, and hands it back out as an owned [`String`] at
/// its own downstream boundary reads through the same one-oracle
/// discipline the parse peer already carries with zero per-consumer
/// bridge cost. Structural mirror of [`impl From<crate::retry::
/// PerAttemptRegion> for String`], [`impl
/// From<crate::probe_outcome::AdmissionTier> for String`], and
/// [`impl From<crate::version::BumpLevel> for String`] — the same
/// by-value owned-UTF-8 emit lift the sibling label-axis ordered
/// typed sums already carry, each routing through its shared
/// canonical-label oracle via
/// [`crate::retry::PerAttemptRegion::as_str`] +
/// [`str::to_owned`] — now extended to the digest reference-grammar
/// family through a strictly cheaper move-out projection off the
/// [`ContentDigest`] value's own backing storage.
///
/// Zero-copy by construction: the returned [`String`] is the
/// consumed [`ContentDigest`] value's [`ContentDigest::full`]
/// backing string moved out — no allocation, no clone, no
/// per-consumer buffer growth. Sibling label-axis emit peers
/// (`From<PerAttemptRegion> for String` etc.) allocate a fresh
/// [`String`] because their canonical labels live in a static
/// `'static` slice and the emit peer must copy; the digest family's
/// backing string is a per-value owned [`String`] the impl can move
/// directly, so this peer is strictly cheaper than the sibling
/// analog it structurally mirrors while carrying the same
/// one-oracle read discipline. The identity
/// `String::from(digest.clone()) == digest.as_str()` at every
/// validated [`ContentDigest`] value is pinned by
/// [`tests::test_from_content_digest_string_matches_as_str`]; the
/// identity carrying through a generic `impl Into<String>` consumer
/// is pinned by
/// [`tests::test_from_content_digest_string_carries_through_generic_consumer`];
/// the parse-round-trip identity through the owned-UTF-8 emit
/// surface (parsing the emitted [`String`] back through every
/// canonical parse surface) is pinned by
/// [`tests::test_from_content_digest_string_parse_round_trip`].
///
/// A future refinement to the inherent [`ContentDigest::parse`]
/// grammar (widening to `sha384`, tightening the trim behaviour) or
/// to the [`ContentDigest::as_str`] read accessor (a canonicalising
/// projection) is a one-site edit at the inherent oracle; every
/// consumer bound by `impl Into<String>` inherits the refined
/// canonical form off the moved backing string automatically with
/// no downstream retyping.
///
/// THEORY.md §III.1 typescape: the by-value owned-UTF-8 emit
/// surface is a typed-primitive site on [`ContentDigest`] itself
/// (one [`From<ContentDigest>`] impl moving the
/// [`ContentDigest::parse`]-validated backing string out at
/// zero-copy), not a per-consumer `digest.as_str().to_owned()` or
/// `digest.to_string()` restatement at every downstream site that
/// accepts `impl Into<String>`. THEORY.md §VI.1 one-oracle: the
/// validated full-digest string is named at one site
/// ([`ContentDigest::parse`]-guarded [`ContentDigest::full`]
/// backing), and every emit surface — the borrowed-view read peers
/// [`ContentDigest::as_str`], [`std::fmt::Display`],
/// [`AsRef<str>`], [`AsRef<[u8]>`], this by-value owned-UTF-8 peer
/// [`From<ContentDigest> for String`] — reads through the same
/// backing storage. A future divergence between the moved-out
/// [`String`] and the borrowed `&str` view would fail the new
/// `test_from_content_digest_string_matches_as_str` invariance
/// test.
impl From<ContentDigest> for String {
    fn from(digest: ContentDigest) -> String {
        digest.full
    }
}

/// [`From<ContentDigest>`] for [`Vec<u8>`] moves the validated
/// `<algorithm>:<hex>` backing bytes out of the consumed
/// [`ContentDigest`] value at zero-copy — the impl routes through
/// [`<ContentDigest as From<ContentDigest>>::from`] into [`String`]
/// (which moves [`ContentDigest::full`] out at zero-copy) and then
/// [`String::into_bytes`] (which moves the backing [`Vec<u8>`] out
/// of the [`String`] at zero-copy), so no allocation, no
/// re-formatting through [`std::fmt::Display`], no
/// `digest.as_ref().to_vec()` bridge, no `digest.as_str().as_bytes().
/// to_owned()` chain. A downstream consumer that owns a
/// [`ContentDigest`] and needs to hand it off as an owned
/// [`Vec<u8>`] to a byte-oriented sink (a
/// [`std::collections::HashMap<Vec<u8>, _>`] key insertion, a
/// [`bytes::Bytes::from`] intake, an `http::HeaderValue::from_bytes`
/// / [`http::HeaderValue::from_maybe_shared`] `Vec<u8>` frontier, a
/// `blake3::Hasher` / `sha2::Digest` streaming hasher that consumes
/// its input as an owned byte buffer at a construction boundary, a
/// generic sink bounded by `impl Into<Vec<u8>>`) is a one-line
/// `Vec::<u8>::from(digest)` / `digest.into()` call, not a per-site
/// `digest.as_ref().to_vec()` or `digest.as_str().as_bytes().
/// to_owned()` bridge that pays a redundant allocation.
///
/// The by-value owned-byte-slice emit peer of the by-reference
/// borrowed-view byte-slice read peer [`AsRef<[u8]> for
/// ContentDigest`] (commit fbfb838): both surfaces read the same
/// underlying validated full-digest bytes, one exposing them
/// borrowed at the byte-slice frontier (`&[u8]`) and this one
/// emitting them owned at the [`Vec<u8>`] frontier that
/// owned-byte-buffer consumers pin their contract on. The
/// byte-slice frontier sibling of the by-value owned-UTF-8 emit
/// peer [`From<ContentDigest> for String`] (commit 83313fd): the
/// two together close the by-value owned emit surface across the
/// UTF-8 (`String`) and byte-slice (`Vec<u8>`) frontiers — the
/// UTF-8 peer routes through the moved [`ContentDigest::full`]
/// backing directly, this byte-slice peer chains through the same
/// UTF-8 emit oracle via [`String::into_bytes`] so the two agree
/// byte-for-byte on the canonical form by construction, and a
/// future canonicalising refinement to the [`String`] emit surface
/// propagates to the byte-slice emit surface at zero per-consumer
/// cost.
///
/// Zero-copy by construction: [`String::from(digest)`] moves
/// [`ContentDigest::full`] out at zero-copy, and
/// [`String::into_bytes`] moves the backing [`Vec<u8>`] out of the
/// [`String`] at zero-copy — no allocation, no clone, no
/// per-consumer buffer growth. The identity
/// `Vec::<u8>::from(digest.clone()) ==
/// <ContentDigest as AsRef<[u8]>>::as_ref(&digest)` at every
/// validated [`ContentDigest`] value is pinned by
/// [`tests::test_from_content_digest_vec_u8_matches_as_ref_bytes`];
/// the identity carrying through a generic `impl Into<Vec<u8>>`
/// consumer is pinned by
/// [`tests::test_from_content_digest_vec_u8_carries_through_generic_consumer`];
/// the parse-round-trip identity through the byte-slice emit
/// surface (decoding the emitted [`Vec<u8>`] via
/// [`String::from_utf8`] and parsing back through every canonical
/// parse surface) is pinned by
/// [`tests::test_from_content_digest_vec_u8_parse_round_trip`].
///
/// The emitted bytes are pure lowercase-hex plus
/// `sha256`/`sha512`/`:` — every byte is ASCII by parse invariant,
/// so an owned-byte-buffer consumer that treats the input as ASCII
/// (a `HashMap<Vec<u8>, _>` key whose ordering is byte-lex, a MAC
/// accumulator that reads its owned input as bytes, a
/// content-addressed cache key that hashes the owned byte buffer)
/// stores the same canonical form the byte-slice borrowed-view
/// surface exposes with no multibyte-boundary hazard.
///
/// A future refinement to the inherent [`ContentDigest::parse`]
/// grammar (widening to `sha384`, tightening the trim behaviour) or
/// to the [`From<ContentDigest> for String`] emit oracle (a
/// canonicalising projection at the owned-UTF-8 frontier) is a
/// one-site edit at the inherent / owned-UTF-8 oracle; every
/// consumer bound by `impl Into<Vec<u8>>` inherits the refined
/// canonical byte buffer off the moved backing storage
/// automatically with no downstream retyping.
///
/// THEORY.md §III.1 typescape: the by-value owned-byte-slice emit
/// surface is a typed-primitive site on [`ContentDigest`] itself
/// (one [`From<ContentDigest>`] impl moving the
/// [`ContentDigest::parse`]-validated backing bytes out at
/// zero-copy through the [`From<ContentDigest> for String`] emit
/// oracle), not a per-consumer `digest.as_ref().to_vec()` or
/// `digest.as_str().as_bytes().to_owned()` restatement at every
/// downstream site that accepts `impl Into<Vec<u8>>`.
/// THEORY.md §VI.1 one-oracle: the validated full-digest bytes are
/// named at one site ([`From<ContentDigest> for String`], reading
/// through the moved [`ContentDigest::full`] backing), and every
/// emit surface — the by-value owned-UTF-8 peer
/// [`From<ContentDigest> for String`], this by-value
/// owned-byte-slice peer [`From<ContentDigest> for Vec<u8>`] —
/// reads through it.
impl From<ContentDigest> for Vec<u8> {
    fn from(digest: ContentDigest) -> Vec<u8> {
        String::from(digest).into_bytes()
    }
}

/// [`From<ContentDigest>`] for [`Box<str>`] moves the validated
/// `<algorithm>:<hex>` backing string out of the consumed
/// [`ContentDigest`] value into a heap-owned [`Box<str>`] at exactly
/// the label's length — the impl routes through
/// [`<ContentDigest as From<ContentDigest>>::from`] into [`String`]
/// (which moves [`ContentDigest::full`] out at zero-copy) and then
/// [`String::into_boxed_str`] (which repackages the backing buffer as
/// an immutable [`Box<str>`], shrinking to exact length only when the
/// backing [`String`]'s capacity exceeded its length — for
/// [`ContentDigest`] values the parse-time
/// [`str::to_string`](str::to_string) allocation already sizes to
/// exact length, so the shrink is a no-op in the common case). No
/// re-formatting through [`std::fmt::Display`], no
/// `Box::<str>::from(digest.as_str())` bridge that would copy the
/// backing bytes into a fresh allocation while leaking the consumed
/// [`ContentDigest`]'s owned [`String`], no
/// `digest.as_str().to_owned().into_boxed_str()` chain that would
/// re-parse the owned-string / shrunk-owned discipline at every
/// consumer.
///
/// A downstream consumer that owns a [`ContentDigest`] and needs to
/// hand it off as an immutable heap-owned [`Box<str>`] to an
/// owned-label sink (a [`std::collections::HashMap<Box<str>, _>`] key
/// insertion, a validated-input newtype whose digest field is stored
/// as [`Box<str>`] to shed the [`String`] growth header for a
/// long-lived per-value slot, a `phf`-style keyed-table value slot
/// that owns its label as a boxed slice, a serde container that opts
/// into `#[serde(from = "Box<str>")]` at the shrunk-owned frontier,
/// an `Arc<Manifest>` field where the manifest's digest slot is a
/// [`Box<str>`] chosen for its two-machine-word footprint over the
/// three-word [`String`]) is a one-line
/// `Box::<str>::from(digest)` / `digest.into()` call, not a per-site
/// `Box::<str>::from(digest.as_str())` bridge that pays a redundant
/// allocation nor a `digest.as_str().to_owned().into_boxed_str()`
/// chain that pays the [`String`]-realloc-plus-shrink round trip
/// while re-stating the shrunk-owned discipline.
///
/// The by-value shrunk-owned UTF-8 emit peer of the by-value owned
/// UTF-8 emit peer [`From<ContentDigest> for String`] (commit
/// 83313fd) and the by-value owned byte-slice emit peer
/// [`From<ContentDigest> for Vec<u8>`] (commit e1ea855): all three
/// surfaces move the same validated full-digest bytes out of the
/// consumed [`ContentDigest`], differing only on the owner-shape of
/// the emitted receiver — [`String`] for resizable growth-header
/// owners, [`Vec<u8>`] for byte-oriented sinks, this [`Box<str>`]
/// for immutable heap-owned label slots that trade the [`String`]
/// growth-header word for a two-word slice pointer. All three route
/// through the [`From<ContentDigest> for String`] emit oracle: the
/// [`String`] peer moves [`ContentDigest::full`] directly, the
/// [`Vec<u8>`] peer chains through [`String::into_bytes`], this
/// [`Box<str>`] peer chains through [`String::into_boxed_str`] — the
/// three agree byte-for-byte on the canonical form by construction,
/// and a future canonicalising refinement to the [`String`] emit
/// surface propagates to the shrunk-owned UTF-8 emit surface at zero
/// per-consumer cost.
///
/// Zero-copy in the common case by construction: the parse-time
/// [`str::to_string`] allocation that produces [`ContentDigest::full`]
/// sizes the backing [`String`] to exact length (capacity == length
/// on a fresh `to_string()` of a `&str`), so [`String::into_boxed_str`]
/// repackages the backing buffer as [`Box<str>`] without reallocation.
/// The identity `Box::<str>::from(digest.clone()).as_ref() ==
/// digest.as_str()` at every validated [`ContentDigest`] value is
/// pinned by
/// [`tests::test_from_content_digest_box_str_matches_as_str`]; the
/// identity carrying through a generic `impl Into<Box<str>>` consumer
/// is pinned by
/// [`tests::test_from_content_digest_box_str_carries_through_generic_consumer`];
/// the parse-round-trip identity through the shrunk-owned UTF-8
/// emit surface (parsing back through every canonical parse surface)
/// is pinned by
/// [`tests::test_from_content_digest_box_str_parse_round_trip`].
///
/// A future refinement to the inherent [`ContentDigest::parse`]
/// grammar (widening to `sha384`, tightening the trim behaviour) or
/// to the [`From<ContentDigest> for String`] emit oracle (a
/// canonicalising projection at the owned-UTF-8 frontier) is a
/// one-site edit at the inherent / owned-UTF-8 oracle; every consumer
/// bound by `impl Into<Box<str>>` inherits the refined canonical
/// shrunk-owned label off the moved backing storage automatically
/// with no downstream retyping.
///
/// THEORY.md §III.1 typescape: the by-value shrunk-owned UTF-8 emit
/// surface is a typed-primitive site on [`ContentDigest`] itself
/// (one [`From<ContentDigest>`] impl chaining through the
/// [`From<ContentDigest> for String`] emit oracle via
/// [`String::into_boxed_str`]), not a per-consumer
/// `Box::<str>::from(digest.as_str())` restatement at every
/// downstream site that accepts `impl Into<Box<str>>`.
/// THEORY.md §VI.1 one-oracle: the validated full-digest bytes are
/// named at one site ([`From<ContentDigest> for String`], reading
/// through the moved [`ContentDigest::full`] backing), and every
/// by-value owned emit surface — the by-value owned-UTF-8 peer
/// [`From<ContentDigest> for String`], the by-value owned-byte-slice
/// peer [`From<ContentDigest> for Vec<u8>`], this by-value
/// shrunk-owned UTF-8 peer [`From<ContentDigest> for Box<str>`] —
/// reads through it.
impl From<ContentDigest> for Box<str> {
    fn from(digest: ContentDigest) -> Box<str> {
        String::from(digest).into_boxed_str()
    }
}

/// [`From<ContentDigest>`] for [`std::borrow::Cow<'static, str>`] moves
/// the validated `<algorithm>:<hex>` backing string out of the consumed
/// [`ContentDigest`] value into the [`Cow::Owned`] branch of a
/// `'static`-lifetime [`Cow<'static, str>`] at zero-copy — the impl
/// routes through [`<ContentDigest as From<ContentDigest>>::from`] into
/// [`String`] (which moves [`ContentDigest::full`] out at zero-copy) and
/// wraps the moved [`String`] in [`Cow::Owned`], so no allocation, no
/// re-formatting through [`std::fmt::Display`], no
/// `Cow::Owned(digest.as_str().to_owned())` bridge that would clone the
/// backing bytes while leaking the consumed [`ContentDigest`]'s owned
/// [`String`], no `Cow::Owned(digest.to_string())` chain that would
/// re-run [`std::fmt::Display`] over the already-canonical backing.
///
/// A downstream consumer that owns a [`ContentDigest`] and needs to
/// hand it off to a borrowed/owned-frontier label sink (a
/// `http::HeaderValue::from_str` bridge whose caller types the input
/// contract as `impl Into<Cow<'static, str>>` to interleave `'static`
/// labels with computed [`String`]s, a `tracing::field` recorder that
/// takes `impl Into<Cow<'static, str>>` to hold the label as either a
/// borrowed static or an owned digest, a serde container that opts
/// into `#[serde(from = "Cow<'static, str>")]` at the
/// borrowed/owned-frontier emit surface, a generic sink bounded by
/// `impl Into<Cow<'static, str>>` that accepts either the zero-alloc
/// borrowed branch from a static label or the owned branch from a
/// runtime-parsed digest) is a one-line
/// `Cow::<'static, str>::from(digest)` / `digest.into()` call, not a
/// per-site `Cow::Owned(digest.to_string())` bridge that pays a
/// redundant `Display`-format allocation nor a
/// `Cow::Owned(digest.as_str().to_owned())` chain that clones the
/// already-owned backing.
///
/// The by-value borrowed/owned-frontier emit peer of the by-value
/// owned-UTF-8 emit peer [`From<ContentDigest> for String`] (commit
/// 83313fd), the by-value owned-byte-slice emit peer
/// [`From<ContentDigest> for Vec<u8>`] (commit e1ea855), and the
/// by-value shrunk-owned UTF-8 emit peer
/// [`From<ContentDigest> for Box<str>`] (commit 0e86524): all four
/// surfaces move the same validated full-digest bytes out of the
/// consumed [`ContentDigest`], differing only on the owner-shape of the
/// emitted receiver — [`String`] for resizable growth-header owners,
/// [`Vec<u8>`] for byte-oriented sinks, [`Box<str>`] for immutable
/// heap-owned label slots that trade the [`String`] growth-header word
/// for a two-word slice pointer, this [`Cow<'static, str>`] for
/// borrowed/owned-frontier sinks that accept either the zero-alloc
/// borrowed branch from a `'static` label or the owned branch from a
/// runtime-parsed value. All four route through the
/// [`From<ContentDigest> for String`] emit oracle: the [`String`] peer
/// moves [`ContentDigest::full`] directly, the [`Vec<u8>`] peer chains
/// through [`String::into_bytes`], the [`Box<str>`] peer chains through
/// [`String::into_boxed_str`], this [`Cow<'static, str>`] peer wraps the
/// moved [`String`] in [`Cow::Owned`] — the four agree byte-for-byte on
/// the canonical form by construction, and a future canonicalising
/// refinement to the [`String`] emit surface propagates to the
/// borrowed/owned-frontier emit surface at zero per-consumer cost.
///
/// The borrowed/owned-frontier emit peer of the borrowed/owned-frontier
/// parse peer [`TryFrom<Cow<'_, str>> for ContentDigest`] (commit
/// 3a28035): the parse peer accepts a caller-supplied
/// [`Cow<'_, str>`] and routes it through the one-oracle parser; this
/// emit peer projects a validated [`ContentDigest`] back into a
/// [`Cow<'static, str>`] at the same frontier. Together they close the
/// [`Cow`] frontier at [`ContentDigest`] on both the parse and emit
/// sides so a downstream site that types both its input and its
/// re-emit contract as [`Cow`] (a serde container that opts into
/// `#[serde(try_from = "Cow<'a, str>", into = "Cow<'static, str>")]`,
/// a validated-input newtype builder whose canonical parse AND re-emit
/// contracts are both stated as [`Cow`]) is a one-line bridge through
/// the shared frontier, not a per-consumer restatement of the
/// borrowed/owned discipline at either side.
///
/// The sibling [`Cow<'static, str>`] emit peer at the enum-shaped
/// ordered typed sums [`From<crate::version::BumpLevel> for
/// Cow<'static, str>`], [`From<crate::probe_outcome::AdmissionTier> for
/// Cow<'static, str>`], and [`From<crate::retry::PerAttemptRegion> for
/// Cow<'static, str>`] takes the [`Cow::Borrowed`] branch because their
/// `as_str` oracle returns a `'static` slice off a static label table;
/// this [`ContentDigest`] emit peer takes the [`Cow::Owned`] branch
/// because [`ContentDigest`] owns a runtime-parsed [`String`] with no
/// `'static` backing to borrow — the two branches of [`Cow<'static,
/// str>`] are the load-bearing shapes of the borrowed/owned frontier,
/// and every typed primitive on the platform lands on the branch its
/// oracle backing shape mandates without paying an allocation or a
/// re-parse to shoehorn onto the other.
///
/// Zero-copy by construction: [`String::from(digest)`] moves
/// [`ContentDigest::full`] out at zero-copy, and [`Cow::Owned`] wraps
/// the moved [`String`] without touching its backing buffer — no
/// allocation, no clone, no per-consumer buffer growth. The identity
/// `Cow::<'static, str>::from(digest.clone()) == digest.as_str()` at
/// every validated [`ContentDigest`] value is pinned by
/// [`tests::test_from_content_digest_cow_static_str_matches_as_str`];
/// the identity carrying through a generic
/// `impl Into<Cow<'static, str>>` consumer is pinned by
/// [`tests::test_from_content_digest_cow_static_str_carries_through_generic_consumer`];
/// the parse-round-trip identity through the borrowed/owned-frontier
/// emit surface (parsing back through every canonical parse surface)
/// is pinned by
/// [`tests::test_from_content_digest_cow_static_str_parse_round_trip`];
/// the [`Cow::Owned`]-not-[`Cow::Borrowed`] variant discriminator at
/// the emit boundary (contrasting the enum-shaped siblings that emit
/// [`Cow::Borrowed`]) is pinned by
/// [`tests::test_from_content_digest_cow_static_str_is_owned`].
///
/// A future refinement to the inherent [`ContentDigest::parse`]
/// grammar (widening to `sha384`, tightening the trim behaviour) or
/// to the [`From<ContentDigest> for String`] emit oracle (a
/// canonicalising projection at the owned-UTF-8 frontier) is a
/// one-site edit at the inherent / owned-UTF-8 oracle; every consumer
/// bound by `impl Into<Cow<'static, str>>` inherits the refined
/// canonical borrowed/owned-frontier label off the moved backing
/// storage automatically with no downstream retyping.
///
/// THEORY.md §III.1 typescape: the by-value borrowed/owned-frontier
/// emit surface is a typed-primitive site on [`ContentDigest`] itself
/// (one [`From<ContentDigest>`] impl chaining through the
/// [`From<ContentDigest> for String`] emit oracle via [`Cow::Owned`]),
/// not a per-consumer `Cow::Owned(digest.to_string())` restatement at
/// every downstream site that accepts `impl Into<Cow<'static, str>>`.
/// THEORY.md §VI.1 one-oracle: the validated full-digest bytes are
/// named at one site ([`From<ContentDigest> for String`], reading
/// through the moved [`ContentDigest::full`] backing), and every
/// by-value owned emit surface — the by-value owned-UTF-8 peer
/// [`From<ContentDigest> for String`], the by-value owned-byte-slice
/// peer [`From<ContentDigest> for Vec<u8>`], the by-value shrunk-owned
/// UTF-8 peer [`From<ContentDigest> for Box<str>`], this by-value
/// borrowed/owned-frontier peer
/// [`From<ContentDigest> for Cow<'static, str>`] — reads through it.
impl From<ContentDigest> for std::borrow::Cow<'static, str> {
    fn from(digest: ContentDigest) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Owned(String::from(digest))
    }
}

/// [`From<ContentDigest>`] for [`std::sync::Arc<str>`] moves the validated
/// `<algorithm>:<hex>` backing string out of the consumed [`ContentDigest`]
/// value into an immutable, thread-safe, shared-owned [`Arc<str>`] at
/// exactly the label's length — the impl routes through
/// [`<ContentDigest as From<ContentDigest>>::from`] into [`String`] (which
/// moves [`ContentDigest::full`] out at zero-copy) and then
/// [`std::sync::Arc::<str>::from`] on the moved [`String`] (which
/// repackages the backing buffer as an immutable shared-owned [`Arc<str>`]
/// with a single atomic-refcount header preceding the label bytes). No
/// re-formatting through [`std::fmt::Display`], no
/// `Arc::<str>::from(digest.as_str())` bridge that would copy the backing
/// bytes into a fresh allocation while leaking the consumed
/// [`ContentDigest`]'s owned [`String`], no
/// `digest.to_string().into()` chain that would re-run
/// [`std::fmt::Display`] over the already-canonical backing.
///
/// A downstream consumer that owns a [`ContentDigest`] and needs to hand
/// it off as a cross-thread shared-owned label to an atomic-refcounted sink
/// (a `dashmap::DashMap<Arc<str>, _>` cache key inserted once and cloned
/// across worker threads at `O(1)` [`Arc::clone`] cost, an
/// `Arc<crate::deployment_manifest::...>` structural field whose digest
/// slot is stored as [`Arc<str>`] to share a single label allocation across
/// concurrent readers of the manifest, a `tokio::sync::watch` /
/// `tokio::sync::broadcast` channel that carries an [`Arc<str>`] payload
/// receivers clone atomically without a per-receiver allocation, a
/// long-lived registry-cache entry keyed on a shared-owned digest for
/// zero-copy fanout to `tokio::spawn`ed inspection tasks, a
/// `serde` container that opts into `#[serde(into = "Arc<str>")]` at the
/// shared-owned frontier) is a one-line `Arc::<str>::from(digest)` /
/// `digest.into()` call, not a per-site
/// `Arc::<str>::from(digest.as_str())` bridge that leaks the consumed
/// [`ContentDigest`]'s owned [`String`] nor a
/// `Arc::<str>::from(digest.to_string())` chain that pays a redundant
/// [`Display`]-format allocation on top of the shared-owned repackaging.
///
/// The by-value shared-owned UTF-8 emit peer of the by-value owned-UTF-8
/// emit peer [`From<ContentDigest> for String`] (commit 83313fd), the
/// by-value owned-byte-slice emit peer
/// [`From<ContentDigest> for Vec<u8>`] (commit e1ea855), the by-value
/// shrunk-owned UTF-8 emit peer [`From<ContentDigest> for Box<str>`]
/// (commit 0e86524), and the by-value borrowed/owned-frontier emit peer
/// [`From<ContentDigest> for Cow<'static, str>`] (commit 15b7a05): all
/// five surfaces move the same validated full-digest bytes out of the
/// consumed [`ContentDigest`], differing only on the owner-shape of the
/// emitted receiver — [`String`] for resizable growth-header owners,
/// [`Vec<u8>`] for byte-oriented sinks, [`Box<str>`] for immutable
/// heap-owned label slots that trade the growth-header word for a
/// two-word slice pointer, [`Cow<'static, str>`] for
/// borrowed/owned-frontier sinks, this [`Arc<str>`] for immutable
/// shared-owned label slots that carry a single atomic-refcount header so
/// consumers `Arc::clone` the label across worker threads at atomic-op
/// cost with no per-clone allocation. All five route through the
/// [`From<ContentDigest> for String`] emit oracle: the [`String`] peer
/// moves [`ContentDigest::full`] directly, the [`Vec<u8>`] peer chains
/// through [`String::into_bytes`], the [`Box<str>`] peer chains through
/// [`String::into_boxed_str`], the [`Cow<'static, str>`] peer wraps the
/// moved [`String`] in [`Cow::Owned`], this [`Arc<str>`] peer chains
/// through [`std::sync::Arc::<str>::from`] applied to the moved [`String`]
/// — the five agree byte-for-byte on the canonical form by construction,
/// and a future canonicalising refinement to the [`String`] emit surface
/// propagates to the shared-owned frontier at zero per-consumer cost.
///
/// Structural mirror of [`impl From<crate::retry::PerAttemptRegion> for
/// std::sync::Arc<str>`] on the label-axis ordered typed sums — the same
/// by-value shared-owned UTF-8 emit lift the sibling per-attempt-region
/// primitive already carries, now extended to the digest reference-grammar
/// family so the parse-oracle-bounded typed primitive [`ContentDigest`]
/// exposes the same shared-owned emit surface every sibling typed
/// primitive that has grown a full string-owner emit cross-product
/// already carries.
///
/// Zero-copy on the digest bytes by construction: [`String::from(digest)`]
/// moves [`ContentDigest::full`] out at zero-copy, and
/// [`std::sync::Arc::<str>::from`] on the moved [`String`] performs a
/// single atomic-refcount allocation of exactly `label.len() + refcount
/// header` bytes and copies the label bytes into that allocation once (the
/// [`String`]'s heap buffer cannot itself be repurposed because the
/// [`Arc<str>`] layout requires the atomic-refcount header to precede the
/// str body, and [`String`]'s backing has no such header). This is
/// strictly the minimum cost of shifting from the resizable-growth-header
/// [`String`] shape to the immutable-shared-refcount [`Arc<str>`] shape;
/// no [`std::fmt::Display`] round-trip, no intermediate [`Box<str>`]
/// allocation, no per-consumer bridge cost.
///
/// The identity `<std::sync::Arc<str> as
/// std::ops::Deref>::deref(&std::sync::Arc::<str>::from(digest.clone()))
/// == digest.as_str()` at every validated [`ContentDigest`] value is
/// pinned by [`tests::test_from_content_digest_arc_str_matches_as_str`];
/// the identity carrying through a generic `impl Into<std::sync::Arc<str>>`
/// consumer is pinned by
/// [`tests::test_from_content_digest_arc_str_carries_through_generic_consumer`];
/// the parse-round-trip identity through the shared-owned UTF-8 emit
/// surface (parsing the emitted [`Arc<str>`]'s deref view back through
/// every canonical parse surface) is pinned by
/// [`tests::test_from_content_digest_arc_str_parse_round_trip`]; the
/// cross-thread `Arc::clone` semantic is pinned by
/// [`tests::test_from_content_digest_arc_str_clones_cheaply_across_threads`].
///
/// A future refinement to the inherent [`ContentDigest::parse`] grammar
/// (widening to `sha384`, tightening the trim behaviour) or to the
/// [`From<ContentDigest> for String`] emit oracle (a canonicalising
/// projection at the owned-UTF-8 frontier) is a one-site edit at the
/// inherent / owned-UTF-8 oracle; every consumer bound by
/// `impl Into<std::sync::Arc<str>>` inherits the refined canonical
/// shared-owned label off the moved backing storage automatically with no
/// downstream retyping.
///
/// THEORY.md §III.1 typescape: the by-value shared-owned UTF-8 emit
/// surface is a typed-primitive site on [`ContentDigest`] itself (one
/// [`From<ContentDigest>`] impl chaining through the
/// [`From<ContentDigest> for String`] emit oracle via
/// [`std::sync::Arc::<str>::from`]), not a per-consumer
/// `Arc::<str>::from(digest.as_str())` restatement at every downstream
/// site that accepts `impl Into<std::sync::Arc<str>>`. THEORY.md §VI.1
/// one-oracle: the validated full-digest bytes are named at one site
/// ([`From<ContentDigest> for String`], reading through the moved
/// [`ContentDigest::full`] backing), and every by-value owned emit surface
/// — [`String`], [`Vec<u8>`], [`Box<str>`], [`Cow<'static, str>`], this
/// [`Arc<str>`] — reads through it.
impl From<ContentDigest> for std::sync::Arc<str> {
    fn from(digest: ContentDigest) -> std::sync::Arc<str> {
        std::sync::Arc::<str>::from(String::from(digest))
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

/// Extract the tag component of an OCI / Docker image reference — the
/// `<tag>` in `[registry[:port]/][path/]name:<tag>[@digest]`. Returns
/// [`None`] when the reference is bare (`nginx`), digest-only
/// (`nginx@sha256:…`), or otherwise carries no `:<tag>` after the final
/// path separator; otherwise returns the borrowed tag slice.
///
/// This is the one-oracle site for reading the tag off an image string
/// in forge (theory §III.1 typescape: the reference grammar is a typed
/// primitive on the platform, not a per-call-site restatement; theory
/// §VI.1 generation over composition: `image.split(':').last()`
/// repeated at every consumer is the three-times rule tripped, extract
/// the primitive). Prior call sites hand-rolled `.split(':').last()`
/// which had three failure modes the typed primitive fixes at one site:
///
/// 1. **Digest form.** `nginx@sha256:abcdef…` under the naïve parse
///    returned `abcdef…` (the digest hex) as the "tag". `image_tag`
///    strips the `@digest` suffix first, so a digest-only reference
///    correctly reports no tag rather than a hex string masquerading
///    as one. The dropped digest is recoverable via the peer parser
///    [`image_digest`] — the one canonical site to extract and
///    validate the `@<algo>:<hex>` suffix.
/// 2. **Registry port.** `registry.example.com:5000/name` under the
///    naïve parse returned `5000/name` as the "tag". `image_tag`
///    splits on the last `/` first, so the port colon in the registry
///    prefix cannot be misread as a tag colon.
/// 3. **Bare reference.** `nginx` under the naïve parse returned
///    `nginx` itself as the "tag". `image_tag` returns [`None`] when
///    the name component carries no `:` at all, letting the caller
///    supply an explicit default (`unknown`, `latest`, an error) at
///    its own frontier rather than treating the image name as its own
///    tag.
///
/// Complexity is `O(n)` on a fixed number of `rsplit_once` scans over
/// the reference string; the [`std::iter::Iterator::last`] antipattern
/// (`clippy::double_ended_iterator_last`) it replaces was `O(n)` for
/// the same result but iterated the entire split iterator to reach the
/// tail.
pub fn image_tag(image: &str) -> Option<&str> {
    // Strip the `@digest` suffix if present; the digest is content-
    // addressed identity, not a tag, and its own `:` between algorithm
    // and hex would otherwise confuse the tag scan below.
    let name_and_tag = image.split_once('@').map_or(image, |(head, _)| head);
    // The tag is scoped to the final path component (`image_name[:tag]`);
    // any earlier `:` belongs to a `registry:port/` prefix and must not
    // be read as a tag separator.
    let last_segment = name_and_tag
        .rsplit_once('/')
        .map_or(name_and_tag, |(_, tail)| tail);
    // Empty last segment (`foo/`) has no tag by construction.
    if last_segment.is_empty() {
        return None;
    }
    last_segment.rsplit_once(':').and_then(|(name, tag)| {
        // `name:` (empty tag) is a malformed reference, not a valid
        // empty tag; report no tag rather than surfacing "".
        if name.is_empty() || tag.is_empty() {
            None
        } else {
            Some(tag)
        }
    })
}

/// Display fallback for image references without a parseable tag — the
/// one canonical string surfaced to logs and user-facing output when
/// [`image_tag`] returns [`None`] (a digest-form reference, a bare
/// reference, a port-only registry, a degenerate parse).
///
/// Centralising the sentinel here means the whole crate agrees on
/// which literal a rollout log or a pod-status line writes when the
/// tag can't be read: one `IMAGE_TAG_UNKNOWN` symbol beats five
/// hand-rolled `"unknown"` literals that could drift to `"?"`,
/// `"n/a"`, `""` at any of them. Consumers that log or compare
/// against the sentinel spot it by name (`== oci_manifest::
/// IMAGE_TAG_UNKNOWN`) rather than by magic-string equality.
pub const IMAGE_TAG_UNKNOWN: &str = "unknown";

/// Display-friendly image tag: [`image_tag`] when the reference has a
/// parseable `:<tag>`, [`IMAGE_TAG_UNKNOWN`] otherwise.
///
/// This is the sibling of [`image_tag`] scoped to the log / user-
/// output frontier — a total function that always returns a non-empty
/// [`&str`] safe to interpolate into a status line. Prior call sites
/// hand-rolled `image_tag(image).unwrap_or("unknown")` at five spots
/// (theory §VI.1 three-times rule tripped by more than a factor of
/// one — a `k8s::get_pod_statuses` `PodStatus.image_tag` build and
/// four `flux::wait_for_deployment` / `wait_for_pod` status lines),
/// all baking the literal fallback string into their own scope. Every
/// consumer that reads a tag off a `&str` for display now routes
/// through this one primitive at zero per-site cost, and the sentinel
/// is defined once at the same OCI-adjacent parse frontier the tag
/// itself is read from.
pub fn image_tag_display(image: &str) -> &str {
    image_tag(image).unwrap_or(IMAGE_TAG_UNKNOWN)
}

/// Extract the image reference from a single line of `docker load`
/// output. `docker load` reports each loaded image on its own line under
/// one of two shapes:
///
/// - `Loaded image: <name>:<tag>` — tagged load (tar carried a named
///   image reference).
/// - `Loaded image ID: sha256:<hex>` — untagged load (tar carried only
///   an image ID; the daemon reports the content-addressed identity).
///
/// This primitive returns the trimmed `<ref>` (respectively `<name>:<tag>`
/// or `sha256:<hex>`) for either shape and [`None`] for any other line
/// or for either shape with an empty tail. The tag colon inside the
/// image reference or the digest colon inside the sha256 identity cannot
/// bleed into the parse — the shape's fixed prefix is stripped in one
/// step, so the tail is whatever follows it verbatim.
///
/// The naïve predecessor at `commands/comprehensive_release.rs` was
/// `line.split(':').last().map(str::trim)` on a line that matched
/// `line.contains("Loaded image")`. That parse was semantically wrong
/// on the two real docker-load outputs it had to handle:
///
/// 1. `Loaded image: nginx:latest` — `split(':').last()` returned
///    `"latest"`, dropping the image name entirely. The downstream
///    `docker tag latest <target>` had no local image called
///    `latest:latest` and failed the release step with a misleading
///    "Failed to tag Docker image" error rather than the actual parse
///    bug. Every tagged image (the common case: a Nix-built OCI tar
///    carrying `<service>:<git-sha>`) hit this failure mode.
/// 2. `Loaded image ID: sha256:abcdef…` — `split(':').last()` returned
///    the bare hex `abcdef…`, dropping the `sha256:` algorithm prefix.
///    `docker tag abcdef…` may or may not resolve depending on how
///    docker interprets bare hex; the prefixed form always resolves.
///
/// `docker_load_image_reference` extracts the correct tail in one
/// pattern-scoped step, and the caller composes it as
/// `.lines().find_map(docker_load_image_reference)` — the honesty-
/// preserving replacement for the naïve substring scan.
pub fn docker_load_image_reference(line: &str) -> Option<&str> {
    // `Loaded image ID:` must be checked first: `Loaded image:` is a
    // proper prefix of it up through the space, but not through the `:`
    // (the `ID` word intervenes), so either ordering is correct — this
    // ordering makes the more-specific match explicit.
    line.strip_prefix("Loaded image ID:")
        .or_else(|| line.strip_prefix("Loaded image:"))
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// Split an OCI / Docker image reference into its repository component
/// and its optional `:<tag>`. Returns `(repository, Some(tag))` when the
/// reference carries a parseable tag (per [`image_tag`]'s invariants —
/// registry-port not a tag, `@digest` not a tag, bare reference has no
/// tag), and `(image, None)` otherwise. The returned repository slice is
/// the reference verbatim up to but not including the `:` that separates
/// the last-path-component name from its tag.
///
/// This is the compound sibling of [`image_tag`] at the same OCI-
/// adjacent parse frontier: any consumer that needs both halves of the
/// `<repo>:<tag>` split for display or downstream use now routes through
/// one primitive rather than a per-site `image.rsplit_once(':')` scan
/// that reproduces the same three parse bugs [`image_tag`] closed at
/// its own frontier. Prior call sites hand-rolled
/// `image_str.rsplit_once(':')` at two spots in
/// `commands/status.rs::extract_main_image` and its container-detail
/// peer, both baking the naïve split's three failure modes into the
/// per-site scan:
///
/// 1. **Digest form.** `nginx@sha256:hex` under the naïve split
///    returned `("nginx@sha256", "hex")`, surfacing the digest hex to
///    a `tag` column in the status output as if it were a legitimate
///    tag; the primitive strips `@digest` before the tag scan and
///    reports the whole reference as the repository with `None` as
///    the tag. The dropped digest is recoverable via the peer
///    parser [`image_digest`] — the one canonical site to extract
///    and validate the `@<algo>:<hex>` suffix.
/// 2. **Registry port.** `registry.example.com:5000/nginx` under the
///    naïve split returned `("registry.example.com", "5000/nginx")`,
///    surfacing the path segment to the `tag` column; the primitive
///    scopes the tag scan to the final path component and reports
///    the whole reference with `None` as the tag.
/// 3. **Bare reference.** `nginx` under the naïve split returned
///    `None` from the split itself (no `:`), which the callers handled
///    correctly at the `None` arm; the primitive preserves this
///    behavior verbatim.
///
/// Complexity is `O(n)` on a fixed number of scans over the reference
/// string, matching the direct sibling [`image_tag`] it composes with.
pub fn image_repository_and_tag(image: &str) -> (&str, Option<&str>) {
    // The `@digest` suffix is content-addressed identity, not a tag;
    // strip it so its inner `:` (between `sha256` / `sha512` and the
    // hex body) cannot bleed into the tag scan.
    let before_digest = image.split_once('@').map_or(image, |(head, _)| head);
    // Scope the tag scan to the final path component. Anything before
    // the last `/` is `registry[:port]/path/…` prefix whose `:` (a
    // registry port separator) must not be misread as a tag colon.
    let path_prefix_end = before_digest.rfind('/').map_or(0, |i| i + 1);
    let last_segment = &before_digest[path_prefix_end..];
    // Empty last segment (`foo/`) has no name and therefore no tag by
    // construction.
    if last_segment.is_empty() {
        return (image, None);
    }
    match last_segment.rsplit_once(':') {
        Some((name, tag)) if !name.is_empty() && !tag.is_empty() => {
            // `tag` is a subslice of `image` (it is a tail of
            // `last_segment`, itself a suffix of `before_digest`, itself
            // a prefix of `image`). The repository slice is `image` up
            // to the `:` that starts the tag — offset
            // `path_prefix_end + name.len()`.
            let repo_end = path_prefix_end + name.len();
            (&image[..repo_end], Some(tag))
        }
        _ => (image, None),
    }
}

/// Extract the content-addressed digest of an OCI / Docker image
/// reference — the `@<algo>:<hex>` suffix in
/// `[registry[:port]/][path/]name[:<tag>]@<algo>:<hex>`. Returns
/// [`Some`] with a validated [`ContentDigest`] when the reference
/// carries a well-formed `@<algo>:<hex>` suffix; returns [`None`] when
/// the reference is bare (`nginx`), tagged-only (`nginx:v1`), carries
/// no repository component before the `@` (`@sha256:hex`), or carries
/// an `@` suffix that does not parse as a canonical registry digest
/// (unsupported algorithm, wrong hex length, non-lowercase-hex byte).
///
/// This is the third peer of the reference-grammar parser family
/// (theory §III.1 typescape: the reference grammar is a typed primitive
/// on the platform, not a per-call-site restatement), alongside
/// [`image_tag`] (extract the `<tag>` fragment) and
/// [`image_repository_and_tag`] (split the `<repository>` and `<tag>`
/// fragments). The full canonical reference grammar is
/// `[registry[:port]/][path/]name[:<tag>][@<algo>:<hex>]`; the two tag
/// parsers strip the `@digest` suffix (a digest is content-addressed
/// identity, not a tag) and this primitive is the one canonical site
/// to recover it. Together the three parsers cover every fragment of
/// the reference grammar without loss, so a consumer that needs any
/// combination of repository / tag / digest routes through the
/// primitives rather than hand-rolling a `split_once('@')` scan that
/// forgets to validate the tail.
///
/// The returned digest is validated by [`ContentDigest::parse`] — the
/// same algorithm / length / lowercase-hex checks that gate every
/// digest entering the [`canonical_manifest_fingerprint`] — so a caller
/// receives a value it can trust as a real content-addressed identity
/// without re-parsing. A malformed `@<garbage>` suffix is discarded at
/// the extraction frontier rather than allowed to escape into a caller
/// that would compare, log, or pin against a bad digest.
///
/// Complexity is `O(n)` on a single [`str::split_once`] scan plus the
/// fixed [`ContentDigest::parse`] validation.
pub fn image_digest(image: &str) -> Option<ContentDigest> {
    let (head, digest_str) = image.split_once('@')?;
    // A `@digest` suffix with no repository component before it
    // (`@sha256:hex`) is malformed as an image reference; report no
    // digest so the frontier does not admit a headless reference into
    // the typed algebra.
    if head.is_empty() {
        return None;
    }
    ContentDigest::parse(digest_str).ok()
}

/// Compose an OCI / Docker image reference from a repository slice and a
/// tag, returning the canonical `<repository>:<tag>` shape as an owned
/// `String`.
///
/// This is the compositional inverse of [`image_repository_and_tag`]:
/// for every tag-free repository slice `r`
/// (`image_repository_and_tag(r) == (r, None)`) and every non-empty
/// tag `t`, feeding both halves through the composer and back through
/// the parser recovers the original pair —
/// `image_repository_and_tag(&image_reference(r, t)) == (r, Some(t))`.
/// The roundtrip law is asserted in
/// `test_image_reference_roundtrips_with_image_repository_and_tag`
/// across every non-degenerate input shape the parser handles
/// (bare name, path prefix, registry, registry with port), so future
/// changes to either half that break the pair are caught by the test
/// suite rather than at a distant call site.
///
/// This is the one canonical site in the crate for building a
/// `<repository>:<tag>` reference from its two halves. Prior call sites
/// hand-rolled `format!("{}:{}", registry, tag)` at 20+ spots across
/// `commands/attestation.rs`, `commands/migrations.rs`,
/// `commands/product_release.rs`, `commands/rust_service.rs`, and
/// peers — each independently reproducing the same trivial `format!`
/// shape and each independently at risk of drifting to a subtly wrong
/// separator (`format!("{}::{}", …)`, `format!("{}/{}", …)`), of
/// reordering the halves, or of double-tagging a repository slice that
/// already carries its own tag. The one-oracle-site route closes the
/// class of composition drift by construction (theory §III.1 typescape:
/// the composition of the reference grammar is a typed primitive, not
/// a per-call-site restatement; §VI.1 generation over composition:
/// hand-rolled `format!` composition repeated at every consumer is the
/// three-times rule tripped, extract the primitive).
///
/// Under `debug_assertions`, the primitive checks its caller invariants:
///
/// - `repository` is non-empty.
/// - `tag` is non-empty.
/// - `repository` does not itself already carry a tag — i.e.,
///   [`image_repository_and_tag`] reports the whole slice as the
///   repository with `None` as the tag. A repository slice that already
///   carries its own tag (`nginx:latest` passed as `repository`) would
///   produce a double-tagged malformed reference (`nginx:latest:new`).
///
/// The checks are debug-only so a call site whose repository slice is
/// derived from a validated config source pays no release-mode cost.
/// The typical caller shape is
/// `image_reference(deploy_config.registry_url(), &tag_suffix)` — a
/// registry URL rendered from typed configuration and a tag suffix
/// derived from a git SHA, both bare by construction.
pub fn image_reference(repository: &str, tag: &str) -> String {
    debug_assert!(
        !repository.is_empty(),
        "image_reference: repository must be non-empty"
    );
    debug_assert!(!tag.is_empty(), "image_reference: tag must be non-empty");
    debug_assert!(
        image_repository_and_tag(repository).1.is_none(),
        "image_reference: repository '{repository}' already carries a tag; \
         composing '{repository}:{tag}' would produce a double-tagged reference"
    );
    format!("{repository}:{tag}")
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

    /// The `algorithm()` accessor recovers the algorithm prefix off a
    /// validated digest for both supported algorithms. A consumer that
    /// pins a per-algorithm policy at its own attestation boundary can
    /// distinguish arms without re-splitting the full string.
    #[test]
    fn test_content_digest_algorithm_accessor() {
        let sha256 = ContentDigest::parse(&format!("sha256:{D1}")).unwrap();
        assert_eq!(sha256.algorithm(), "sha256");
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let sha512 = ContentDigest::parse(&format!("sha512:{hex512}")).unwrap();
        assert_eq!(sha512.algorithm(), "sha512");
    }

    /// The `hex()` accessor recovers the lowercase-hex body off a
    /// validated digest for both supported algorithms. Round-trips
    /// with the input hex on the two canonical algorithms, so a
    /// consumer that persists the hex without the algorithm prefix
    /// (e.g. `helm_provenance::HelmProvenanceOutcome::Verified::
    /// signed_chart_hash`) extracts it off the typed primitive.
    #[test]
    fn test_content_digest_hex_accessor() {
        let sha256 = ContentDigest::parse(&format!("sha256:{D1}")).unwrap();
        assert_eq!(sha256.hex(), D1);
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let sha512 = ContentDigest::parse(&format!("sha512:{hex512}")).unwrap();
        assert_eq!(sha512.hex(), hex512);
    }

    /// `algorithm()` + `hex()` compose back to the full digest string,
    /// so the two accessors are the exact inverse of the internal
    /// `<algorithm>:<hex>` shape. Pinning the round-trip closes the
    /// class of drift where a future consumer joins accessor outputs
    /// and finds them disagreeing with `as_str()`.
    #[test]
    fn test_content_digest_accessors_compose_to_full_string() {
        let d = ContentDigest::parse(&format!("  sha256:{D1}\n")).unwrap();
        assert_eq!(format!("{}:{}", d.algorithm(), d.hex()), d.as_str());
    }

    /// `str::parse::<ContentDigest>()` succeeds on a well-formed sha256
    /// digest and yields the same validated value as the inherent
    /// [`ContentDigest::parse`] oracle. Pins the derived
    /// [`std::str::FromStr`] surface for the primary registry algorithm.
    #[test]
    fn test_from_str_parses_sha256_digest() {
        let raw = format!("sha256:{D1}");
        let via_from_str: ContentDigest = raw.parse().unwrap();
        let via_inherent = ContentDigest::parse(&raw).unwrap();
        assert_eq!(via_from_str, via_inherent);
        assert_eq!(via_from_str.as_str(), raw);
    }

    /// `str::parse::<ContentDigest>()` succeeds on a well-formed sha512
    /// digest. Pins the derived surface for the second supported
    /// algorithm so a future consumer that turbofishes a sha512-signed
    /// receipt through the trait reads the same grammar the inherent
    /// oracle enforces.
    #[test]
    fn test_from_str_parses_sha512_digest() {
        let hex = "f".repeat(SHA512_HEX_LEN);
        let raw = format!("sha512:{hex}");
        let via_from_str: ContentDigest = raw.parse().unwrap();
        assert_eq!(via_from_str.algorithm(), "sha512");
        assert_eq!(via_from_str.hex(), hex);
    }

    /// The [`std::str::FromStr`] impl inherits the inherent oracle's
    /// edge-whitespace trim: a captured registry response with a
    /// trailing newline still parses via `.parse::<ContentDigest>()`.
    /// Pins the derived surface's trim behaviour to the inherent
    /// oracle's so a downstream consumer switching from
    /// `ContentDigest::parse(s.trim()).ok()` to
    /// `s.parse::<ContentDigest>().ok()` reads byte-identical results.
    #[test]
    fn test_from_str_trims_edge_whitespace() {
        let raw = format!("  sha256:{D1}\n");
        let via_from_str: ContentDigest = raw.parse().unwrap();
        assert_eq!(via_from_str.as_str(), format!("sha256:{D1}"));
    }

    /// The [`std::str::FromStr`] impl emits the SAME
    /// [`ContentDigestError`] variant as the inherent oracle at each
    /// canonical failure mode (missing separator, unsupported
    /// algorithm, invalid hex — length wrong, uppercase, non-hex byte).
    /// Pins the "one grammar oracle serves both entry points" invariant
    /// so a future refactor that inlined a divergent grammar into
    /// [`std::str::FromStr`] (e.g., trimmed only via `str::trim_start`,
    /// or accepted uppercase hex) is caught by the test suite.
    #[test]
    fn test_from_str_matches_inherent_parse_on_every_error_mode() {
        let cases = [
            "sha256abc",                              // missing separator
            &format!("md5:{D1}"),                     // unsupported algorithm
            &format!("sha256:{}", &D1[..60]),         // wrong hex length
            &format!("sha256:{}", D1.to_uppercase()), // uppercase hex
            &format!("sha256:{}g", &D1[..63]),        // non-hex byte
        ];
        for raw in cases {
            let via_from_str = raw.parse::<ContentDigest>().unwrap_err();
            let via_inherent = ContentDigest::parse(raw).unwrap_err();
            assert_eq!(
                via_from_str, via_inherent,
                "from_str and inherent parse must emit the same error variant \
                 for '{raw}'; got from_str={via_from_str:?} vs inherent={via_inherent:?}"
            );
        }
    }

    /// The [`std::str::FromStr`] impl composes with
    /// [`Iterator::filter_map`] and the `T: FromStr` bound —
    /// `strs.iter().filter_map(|s| s.parse::<ContentDigest>().ok())`
    /// yields exactly the well-formed digests, in input order, with
    /// malformed entries silently dropped. The compositional
    /// motivation for landing the trait: prior to this impl the
    /// idiomatic Rust filter-parse over an iterator of digest strings
    /// had to fall back to the inherent-method call at every consumer;
    /// after this impl the turbofish composes directly.
    #[test]
    fn test_from_str_composes_with_iterator_filter_map() {
        let good_1 = format!("sha256:{D1}");
        let good_2 = format!("sha256:{D2}");
        let mixed = [
            good_1.as_str(),                        // valid sha256
            "sha256abc",                            // missing separator — dropped
            good_2.as_str(),                        // valid sha256
            "md5:0123456789abcdef0123456789abcdef", // unsupported algorithm — dropped
        ];
        let parsed: Vec<ContentDigest> = mixed
            .iter()
            .filter_map(|s| s.parse::<ContentDigest>().ok())
            .collect();
        assert_eq!(
            parsed.iter().map(ContentDigest::as_str).collect::<Vec<_>>(),
            vec![good_1.as_str(), good_2.as_str()],
            "filter_map through the FromStr surface must drop malformed entries and \
             preserve input order for well-formed ones"
        );
    }

    /// Round-trip: `str::parse::<ContentDigest>()` on a valid digest
    /// followed by [`ContentDigest::as_str`] recovers the trimmed input
    /// verbatim. Pins the emit-then-parse identity through the derived
    /// [`std::str::FromStr`] entry point so a future consumer that
    /// stamps a digest into an attestation record via `d.to_string()`
    /// and rehydrates it via `s.parse::<ContentDigest>()` (a
    /// [`Display`](std::fmt::Display) + [`FromStr`](std::str::FromStr)
    /// round trip) reads back the same typed value.
    #[test]
    fn test_from_str_roundtrips_via_display() {
        let d1: ContentDigest = format!("sha256:{D1}").parse().unwrap();
        let d2: ContentDigest = d1.to_string().parse().unwrap();
        assert_eq!(d1, d2);
    }

    /// [`TryFrom<&str>`] succeeds on a well-formed sha256 digest and
    /// yields the same validated value as the inherent
    /// [`ContentDigest::parse`] oracle and the [`std::str::FromStr`]
    /// derived surface. Pins the by-reference try-conversion surface for
    /// the primary registry algorithm.
    #[test]
    fn test_try_from_str_parses_sha256_digest() {
        let raw = format!("sha256:{D1}");
        let via_try_from = ContentDigest::try_from(raw.as_str()).unwrap();
        let via_inherent = ContentDigest::parse(&raw).unwrap();
        assert_eq!(via_try_from, via_inherent);
        assert_eq!(via_try_from.as_str(), raw);
    }

    /// [`TryFrom<&str>`] succeeds on a well-formed sha512 digest. Pins
    /// the derived surface for the second supported algorithm so a
    /// downstream consumer bound by `impl TryFrom<&str>` that receives a
    /// sha512-signed receipt reads the same grammar the inherent oracle
    /// enforces.
    #[test]
    fn test_try_from_str_parses_sha512_digest() {
        let hex = "f".repeat(SHA512_HEX_LEN);
        let raw = format!("sha512:{hex}");
        let via_try_from = ContentDigest::try_from(raw.as_str()).unwrap();
        assert_eq!(via_try_from.algorithm(), "sha512");
        assert_eq!(via_try_from.hex(), hex);
    }

    /// The [`TryFrom<&str>`] impl inherits the inherent oracle's
    /// edge-whitespace trim: a captured registry response with leading /
    /// trailing whitespace still parses via `ContentDigest::try_from`.
    /// Pins the by-reference try-conversion surface's trim behaviour to
    /// the inherent oracle's so a downstream consumer switching from
    /// `ContentDigest::parse(s.trim()).ok()` to
    /// `ContentDigest::try_from(s).ok()` reads byte-identical results.
    #[test]
    fn test_try_from_str_trims_edge_whitespace() {
        let raw = format!("  sha256:{D1}\n");
        let via_try_from = ContentDigest::try_from(raw.as_str()).unwrap();
        assert_eq!(via_try_from.as_str(), format!("sha256:{D1}"));
    }

    /// The [`TryFrom<&str>`] impl emits the SAME [`ContentDigestError`]
    /// variant as the inherent oracle at each canonical failure mode
    /// (missing separator, unsupported algorithm, invalid hex — length
    /// wrong, uppercase, non-hex byte). Pins the "one grammar oracle
    /// serves every idiomatic Rust parse entry point" invariant so a
    /// future refactor that inlined a divergent grammar into
    /// [`TryFrom<&str>`] is caught by the test suite.
    #[test]
    fn test_try_from_str_matches_inherent_parse_on_every_error_mode() {
        let cases = [
            "sha256abc",                              // missing separator
            &format!("md5:{D1}"),                     // unsupported algorithm
            &format!("sha256:{}", &D1[..60]),         // wrong hex length
            &format!("sha256:{}", D1.to_uppercase()), // uppercase hex
            &format!("sha256:{}g", &D1[..63]),        // non-hex byte
        ];
        for raw in cases {
            let via_try_from = ContentDigest::try_from(raw).unwrap_err();
            let via_inherent = ContentDigest::parse(raw).unwrap_err();
            assert_eq!(
                via_try_from, via_inherent,
                "try_from and inherent parse must emit the same error variant \
                 for '{raw}'; got try_from={via_try_from:?} vs inherent={via_inherent:?}"
            );
        }
    }

    /// The [`TryFrom<&str>`] impl and the [`std::str::FromStr`] impl
    /// resolve to the SAME [`Result<ContentDigest, ContentDigestError>`]
    /// on every well-formed digest and every canonical failure mode.
    /// Pins the "both by-reference parse surfaces route through the
    /// single [`ContentDigest::parse`] oracle" invariant so a future
    /// divergence between the two derived surfaces (one accepting inputs
    /// the other rejects, or emitting a different error variant) is
    /// caught by the test suite.
    #[test]
    fn test_try_from_str_agrees_with_from_str() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let ok_cases = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha512:{hex512}"),
            format!("  sha256:{D3}\n"),
        ];
        for raw in ok_cases {
            let via_try_from = ContentDigest::try_from(raw.as_str());
            let via_from_str: Result<ContentDigest, _> = raw.parse();
            assert_eq!(via_try_from, via_from_str);
        }
        let err_cases = [
            "sha256abc",                              // missing separator
            &format!("md5:{D1}"),                     // unsupported algorithm
            &format!("sha256:{}", &D1[..60]),         // wrong hex length
            &format!("sha256:{}", D1.to_uppercase()), // uppercase hex
            &format!("sha256:{}g", &D1[..63]),        // non-hex byte
        ];
        for raw in err_cases {
            let via_try_from = ContentDigest::try_from(raw);
            let via_from_str: Result<ContentDigest, _> = raw.parse();
            assert_eq!(via_try_from, via_from_str);
        }
    }

    /// The [`TryFrom<&str>`] impl composes with a generic
    /// try-conversion helper bounded by `for<'a> TryFrom<&'a str, Error
    /// = ContentDigestError>` — the compositional motivation for
    /// landing the trait separately from [`std::str::FromStr`]. Pins the
    /// generic-consumer surface so a downstream site that types its
    /// parse contract as [`TryFrom<&str>`] (a serde `try_from` wrapper,
    /// a validated-input builder helper) recovers the same typed value
    /// the inherent oracle produces.
    #[test]
    fn test_try_from_str_carries_through_generic_consumer() {
        fn parse_via_try_from<T: for<'a> TryFrom<&'a str, Error = ContentDigestError>>(
            s: &str,
        ) -> Result<T, ContentDigestError> {
            T::try_from(s)
        }
        let raw = format!("sha256:{D1}");
        let d: ContentDigest = parse_via_try_from(&raw).unwrap();
        assert_eq!(d.as_str(), raw);
        let err = parse_via_try_from::<ContentDigest>("sha256abc").unwrap_err();
        assert!(matches!(err, ContentDigestError::MissingSeparator { .. }));
    }

    /// [`TryFrom<String>`] succeeds on a well-formed sha256 digest and
    /// yields the same validated value as the inherent oracle. The
    /// by-value parse surface is the idiomatic serde-frontier peer of
    /// the by-reference [`TryFrom<&str>`] surface — the container
    /// attribute `#[serde(try_from = "String")]` keys off this impl,
    /// not [`TryFrom<&str>`].
    #[test]
    fn test_try_from_string_parses_sha256_digest() {
        let raw = format!("sha256:{D1}");
        let d = ContentDigest::try_from(raw.clone()).unwrap();
        assert_eq!(d.as_str(), raw);
        assert_eq!(d.algorithm(), "sha256");
        assert_eq!(d.hex(), D1);
        let inherent = ContentDigest::parse(&raw).unwrap();
        assert_eq!(d, inherent);
    }

    /// [`TryFrom<String>`] succeeds on a well-formed sha512 digest —
    /// the second supported algorithm at the digest reference-grammar
    /// family. Pins the impl across both algorithms so a widening to
    /// `sha384` at the inherent oracle is caught by an existing test.
    #[test]
    fn test_try_from_string_parses_sha512_digest() {
        let hex = "f".repeat(SHA512_HEX_LEN);
        let raw = format!("sha512:{hex}");
        let d = ContentDigest::try_from(raw.clone()).unwrap();
        assert_eq!(d.as_str(), raw);
        assert_eq!(d.algorithm(), "sha512");
        assert_eq!(d.hex(), hex);
    }

    /// [`TryFrom<String>`] inherits the inherent oracle's edge-
    /// whitespace trim so a serde-deserialized YAML string carrying a
    /// stray newline still parses. Pins the trim invariant across the
    /// by-value derived surface.
    #[test]
    fn test_try_from_string_trims_edge_whitespace() {
        let raw = format!("  sha256:{D1}\n").to_string();
        let d = ContentDigest::try_from(raw).unwrap();
        assert_eq!(d.as_str(), format!("sha256:{D1}"));
        assert_eq!(d.algorithm(), "sha256");
        assert_eq!(d.hex(), D1);
    }

    /// [`TryFrom<String>`] agrees with the inherent oracle on every
    /// canonical failure mode (missing separator, unsupported
    /// algorithm, wrong hex length, uppercase hex, non-hex byte). Pins
    /// the "one grammar oracle serves every by-value parse entry point"
    /// invariant. A future refactor that inlined a divergent grammar
    /// into [`TryFrom<String>`] (accepted uppercase hex, trimmed only
    /// via [`str::trim_start`]) fails this test.
    #[test]
    fn test_try_from_string_matches_inherent_parse_on_every_error_mode() {
        let err_cases = [
            "sha256abc123".to_string(), // missing separator
            format!("md5:{D1}"),        // unsupported algorithm
            format!("sha1:0123456789abcdef0123456789abcdef01234567"), // unsupported algorithm
            format!("sha256:{}", &D1[..60]), // wrong hex length
            format!("sha256:{}", D1.to_uppercase()), // uppercase hex
            format!("sha256:{}g", &D1[..63]), // non-hex byte
        ];
        for raw in err_cases {
            let via_try_from = ContentDigest::try_from(raw.clone());
            let via_inherent = ContentDigest::parse(&raw);
            assert_eq!(
                via_try_from, via_inherent,
                "TryFrom<String> and inherent parse must agree on '{raw}'",
            );
            assert!(via_try_from.is_err());
        }
    }

    /// [`TryFrom<String>`] and [`TryFrom<&str>`] resolve to the SAME
    /// [`Result<ContentDigest, ContentDigestError>`] across every
    /// well-formed digest AND every canonical failure mode. Pins the
    /// "both by-reference and by-value try-conversion surfaces read
    /// through the same canonical grammar oracle" invariant so a
    /// future divergence between the two derived surfaces (one
    /// accepting inputs the other rejects, or emitting a different
    /// error variant) fails this test.
    #[test]
    fn test_try_from_string_agrees_with_try_from_str() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let ok_cases = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha512:{hex512}"),
            format!("  sha256:{D3}\n"),
        ];
        for raw in ok_cases {
            let via_owned = ContentDigest::try_from(raw.clone());
            let via_borrowed = ContentDigest::try_from(raw.as_str());
            assert_eq!(via_owned, via_borrowed);
        }
        let err_cases = [
            "sha256abc".to_string(),
            format!("md5:{D1}"),
            format!("sha256:{}", &D1[..60]),
            format!("sha256:{}", D1.to_uppercase()),
            format!("sha256:{}g", &D1[..63]),
        ];
        for raw in err_cases {
            let via_owned = ContentDigest::try_from(raw.clone());
            let via_borrowed = ContentDigest::try_from(raw.as_str());
            assert_eq!(via_owned, via_borrowed);
        }
    }

    /// The [`TryFrom<String>`] impl composes with a generic
    /// try-conversion helper bounded by `TryFrom<String, Error =
    /// ContentDigestError>` — the compositional motivation for landing
    /// the trait separately from [`TryFrom<&str>`]. Pins the by-value
    /// generic-consumer surface so a downstream site that types its
    /// parse contract as [`TryFrom<String>`] (a serde `try_from =
    /// "String"` wrapper, an owned-input validated builder) recovers
    /// the same typed value the inherent oracle produces.
    #[test]
    fn test_try_from_string_carries_through_generic_consumer() {
        fn parse_via_try_from<T: TryFrom<String, Error = ContentDigestError>>(
            s: String,
        ) -> Result<T, ContentDigestError> {
            T::try_from(s)
        }
        let raw = format!("sha256:{D1}");
        let d: ContentDigest = parse_via_try_from(raw.clone()).unwrap();
        assert_eq!(d.as_str(), raw);
        let err = parse_via_try_from::<ContentDigest>("sha256abc".to_string()).unwrap_err();
        assert!(matches!(err, ContentDigestError::MissingSeparator { .. }));
    }

    /// [`TryFrom<Cow<'_, str>>`] succeeds on a well-formed sha256
    /// digest handed in via the borrowed arm — the zero-copy path a
    /// serde deserializer takes when the input allows it. Pins the
    /// primary algorithm on the borrowed arm of the derived surface.
    #[test]
    fn test_try_from_cow_str_borrowed_parses_sha256_digest() {
        let raw = format!("sha256:{D1}");
        let cow: std::borrow::Cow<'_, str> = std::borrow::Cow::Borrowed(raw.as_str());
        let d = ContentDigest::try_from(cow).unwrap();
        assert_eq!(d.as_str(), raw);
        assert_eq!(d.algorithm(), "sha256");
        assert_eq!(d.hex(), D1);
        let inherent = ContentDigest::parse(&raw).unwrap();
        assert_eq!(d, inherent);
    }

    /// [`TryFrom<Cow<'_, str>>`] succeeds on a well-formed sha256
    /// digest handed in via the owned arm — the fallback path a
    /// serde deserializer takes when zero-copy is unavailable
    /// (escaped strings, differing lifetimes). Pins the primary
    /// algorithm on the owned arm of the derived surface.
    #[test]
    fn test_try_from_cow_str_owned_parses_sha256_digest() {
        let raw = format!("sha256:{D1}");
        let cow: std::borrow::Cow<'_, str> = std::borrow::Cow::Owned(raw.clone());
        let d = ContentDigest::try_from(cow).unwrap();
        assert_eq!(d.as_str(), raw);
        assert_eq!(d.algorithm(), "sha256");
        assert_eq!(d.hex(), D1);
    }

    /// [`TryFrom<Cow<'_, str>>`] succeeds on a well-formed sha512
    /// digest across both `Cow` arms. Pins the second supported
    /// algorithm so a widening at the inherent oracle is caught by
    /// an existing test on this derived surface.
    #[test]
    fn test_try_from_cow_str_parses_sha512_digest_both_arms() {
        let hex = "f".repeat(SHA512_HEX_LEN);
        let raw = format!("sha512:{hex}");
        let via_borrowed =
            ContentDigest::try_from(std::borrow::Cow::Borrowed(raw.as_str())).unwrap();
        let via_owned =
            ContentDigest::try_from(std::borrow::Cow::<'_, str>::Owned(raw.clone())).unwrap();
        assert_eq!(via_borrowed, via_owned);
        assert_eq!(via_borrowed.algorithm(), "sha512");
        assert_eq!(via_borrowed.hex(), hex);
    }

    /// [`TryFrom<Cow<'_, str>>`] inherits the inherent oracle's
    /// edge-whitespace trim on both arms so a serde-deserialized
    /// YAML string carrying a stray newline still parses whether
    /// the deserializer emits it borrowed or owned.
    #[test]
    fn test_try_from_cow_str_trims_edge_whitespace_both_arms() {
        let raw = format!("  sha256:{D1}\n");
        let expected = format!("sha256:{D1}");
        let via_borrowed =
            ContentDigest::try_from(std::borrow::Cow::Borrowed(raw.as_str())).unwrap();
        let via_owned = ContentDigest::try_from(std::borrow::Cow::<'_, str>::Owned(raw)).unwrap();
        assert_eq!(via_borrowed.as_str(), expected);
        assert_eq!(via_owned.as_str(), expected);
    }

    /// [`TryFrom<Cow<'_, str>>`] agrees with the inherent oracle on
    /// every canonical failure mode across both arms. Pins the
    /// "one grammar oracle serves every borrowed-or-owned parse entry
    /// point" invariant. A future refactor that inlined a divergent
    /// grammar into [`TryFrom<Cow<'_, str>>`] fails this test.
    #[test]
    fn test_try_from_cow_str_matches_inherent_parse_on_every_error_mode() {
        let err_cases = [
            "sha256abc123".to_string(),
            format!("md5:{D1}"),
            format!("sha1:0123456789abcdef0123456789abcdef01234567"),
            format!("sha256:{}", &D1[..60]),
            format!("sha256:{}", D1.to_uppercase()),
            format!("sha256:{}g", &D1[..63]),
        ];
        for raw in err_cases {
            let via_borrowed = ContentDigest::try_from(std::borrow::Cow::Borrowed(raw.as_str()));
            let via_owned =
                ContentDigest::try_from(std::borrow::Cow::<'_, str>::Owned(raw.clone()));
            let via_inherent = ContentDigest::parse(&raw);
            assert_eq!(
                via_borrowed, via_inherent,
                "TryFrom<Cow::Borrowed> and inherent parse must agree on '{raw}'",
            );
            assert_eq!(
                via_owned, via_inherent,
                "TryFrom<Cow::Owned> and inherent parse must agree on '{raw}'",
            );
            assert!(via_borrowed.is_err());
        }
    }

    /// [`TryFrom<Cow<'_, str>>`] and [`TryFrom<&str>`] resolve to the
    /// SAME [`Result<ContentDigest, ContentDigestError>`] across every
    /// well-formed digest AND every canonical failure mode on both
    /// `Cow` arms. Pins the "borrowed, owned, and cow parse surfaces
    /// all read through the same canonical grammar oracle" invariant
    /// so a future divergence between the derived surfaces fails this
    /// test.
    #[test]
    fn test_try_from_cow_str_agrees_with_try_from_str_both_arms() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let ok_cases = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha512:{hex512}"),
            format!("  sha256:{D3}\n"),
        ];
        for raw in ok_cases {
            let via_borrowed = ContentDigest::try_from(std::borrow::Cow::Borrowed(raw.as_str()));
            let via_owned =
                ContentDigest::try_from(std::borrow::Cow::<'_, str>::Owned(raw.clone()));
            let via_ref = ContentDigest::try_from(raw.as_str());
            assert_eq!(via_borrowed, via_ref);
            assert_eq!(via_owned, via_ref);
        }
    }

    /// The [`TryFrom<Cow<'_, str>>`] impl composes with a generic
    /// try-conversion helper bounded by `for<'a> TryFrom<Cow<'a, str>,
    /// Error = ContentDigestError>` — the compositional motivation
    /// for landing the trait separately from [`TryFrom<&str>`] /
    /// [`TryFrom<String>`]. Pins the borrowed/owned-frontier
    /// generic-consumer surface so a downstream site that types its
    /// parse contract as [`TryFrom<Cow<'_, str>>`] (a serde
    /// `try_from = "Cow<'_, str>"` wrapper, a caller-agnostic
    /// validated builder) recovers the same typed value the inherent
    /// oracle produces on both arms.
    #[test]
    fn test_try_from_cow_str_carries_through_generic_consumer() {
        fn parse_via_try_from<'a, T>(s: std::borrow::Cow<'a, str>) -> Result<T, ContentDigestError>
        where
            T: TryFrom<std::borrow::Cow<'a, str>, Error = ContentDigestError>,
        {
            T::try_from(s)
        }
        let raw = format!("sha256:{D1}");
        let borrowed: std::borrow::Cow<'_, str> = std::borrow::Cow::Borrowed(raw.as_str());
        let d: ContentDigest = parse_via_try_from(borrowed).unwrap();
        assert_eq!(d.as_str(), raw);
        let owned: std::borrow::Cow<'_, str> = std::borrow::Cow::Owned(raw.clone());
        let d2: ContentDigest = parse_via_try_from(owned).unwrap();
        assert_eq!(d2, d);
        let err = parse_via_try_from::<ContentDigest>(std::borrow::Cow::Borrowed("sha256abc"))
            .unwrap_err();
        assert!(matches!(err, ContentDigestError::MissingSeparator { .. }));
    }

    /// [`AsRef::as_ref`] yields the same borrowed slice the inherent
    /// [`ContentDigest::as_str`] accessor yields on every validated
    /// digest. Pins the "borrowed-view read surface routes through
    /// [`ContentDigest::as_str`]" invariant: a future refactor that
    /// inlined a divergent read into the [`AsRef<str>`] impl fails
    /// this test.
    #[test]
    fn test_as_ref_str_matches_as_str() {
        let raw = format!("sha256:{D1}");
        let d = ContentDigest::parse(&raw).unwrap();
        let via_as_ref: &str = <ContentDigest as AsRef<str>>::as_ref(&d);
        assert_eq!(via_as_ref, d.as_str());
        assert_eq!(via_as_ref, raw);
    }

    /// [`AsRef<str>::as_ref`] yields the full `<algorithm>:<hex>` slice
    /// for a sha256 digest — the same string the inherent read
    /// accessor and the [`std::fmt::Display`] formatter emit. Pins the
    /// primary registry algorithm on the borrowed-view surface.
    #[test]
    fn test_as_ref_str_sha256_full_digest() {
        let raw = format!("sha256:{D1}");
        let d = ContentDigest::parse(&raw).unwrap();
        let borrowed: &str = d.as_ref();
        assert_eq!(borrowed, raw);
        assert!(borrowed.starts_with("sha256:"));
        assert_eq!(&borrowed[7..], D1);
    }

    /// [`AsRef<str>::as_ref`] yields the full `<algorithm>:<hex>` slice
    /// for a sha512 digest. Pins the second supported algorithm on the
    /// borrowed-view surface so a widening at the inherent oracle is
    /// caught by an existing test on this derived surface.
    #[test]
    fn test_as_ref_str_sha512_full_digest() {
        let hex = "f".repeat(SHA512_HEX_LEN);
        let raw = format!("sha512:{hex}");
        let d = ContentDigest::parse(&raw).unwrap();
        let borrowed: &str = d.as_ref();
        assert_eq!(borrowed, raw);
        assert!(borrowed.starts_with("sha512:"));
        assert_eq!(&borrowed[7..], hex);
    }

    /// [`AsRef<str>::as_ref`] reads the trimmed backing slice on an
    /// input the inherent oracle whitespace-trimmed at parse time —
    /// the borrowed-view surface exposes the canonical trimmed value,
    /// not the caller's stray-whitespace raw input. Pins the trim
    /// discipline carrying through the derived read surface.
    #[test]
    fn test_as_ref_str_after_whitespace_trim() {
        let raw = format!("  sha256:{D1}\n");
        let expected = format!("sha256:{D1}");
        let d = ContentDigest::parse(&raw).unwrap();
        let borrowed: &str = d.as_ref();
        assert_eq!(borrowed, expected);
        // The borrowed slice does NOT retain the caller's leading /
        // trailing whitespace — the canonical trimmed form is what the
        // derived surface exposes.
        assert!(!borrowed.starts_with(' '));
        assert!(!borrowed.ends_with('\n'));
    }

    /// [`AsRef<str>::as_ref`] and [`std::fmt::Display`]'s formatter
    /// output read the same underlying slice — the borrowed-view
    /// trait-generic peer and the format-machinery emission surface
    /// both route through [`ContentDigest::as_str`]. Pins the "one
    /// read oracle serves both the trait-generic borrowed-view and
    /// the format-machinery emission" invariant so a future
    /// divergence between the two surfaces fails this test.
    #[test]
    fn test_as_ref_str_matches_display() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let cases = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        for raw in cases {
            let d = ContentDigest::parse(&raw).unwrap();
            let via_as_ref: &str = d.as_ref();
            let via_display = d.to_string();
            assert_eq!(
                via_as_ref, via_display,
                "AsRef<str> and Display must read the same underlying \
                 slice on '{raw}'",
            );
        }
    }

    /// The [`AsRef<str>`] impl composes with a generic borrowed-view
    /// helper bounded by `impl AsRef<str>` — the compositional
    /// motivation for landing the trait separately from the inherent
    /// [`ContentDigest::as_str`] accessor. Pins the trait-generic
    /// consumer surface: a downstream site that types its input
    /// contract as `impl AsRef<str>` (a path-segment assembler, a
    /// HashSet membership check, a hasher `update` sink, a URL-path
    /// builder) recovers the same borrowed full-digest slice a
    /// direct `.as_str()` call would.
    #[test]
    fn test_as_ref_str_carries_through_generic_consumer() {
        fn first_char_of<T: AsRef<str>>(t: T) -> char {
            t.as_ref().chars().next().unwrap()
        }
        fn full_length_of<T: AsRef<str>>(t: T) -> usize {
            t.as_ref().len()
        }
        fn equals<T: AsRef<str>>(t: T, expected: &str) -> bool {
            t.as_ref() == expected
        }
        let raw = format!("sha256:{D1}");
        let d = ContentDigest::parse(&raw).unwrap();
        assert_eq!(first_char_of(&d), 's');
        assert_eq!(full_length_of(&d), raw.len());
        assert!(equals(&d, &raw));
        // The generic bound must accept ContentDigest by value AND by
        // borrow — both routes must yield the same slice.
        assert_eq!(full_length_of(d.clone()), raw.len());
        assert!(equals(d, &raw));
    }

    /// A validated digest's [`AsRef<str>`] slice round-trips through
    /// the inherent [`ContentDigest::parse`] oracle back to the same
    /// validated [`ContentDigest`] value. Pins the "borrowed-view
    /// read surface exposes exactly the canonical form the inherent
    /// oracle accepts" invariant so a future canonicalising
    /// refinement to [`ContentDigest::as_str`] that broke round-trip
    /// via [`AsRef<str>`] fails this test.
    #[test]
    fn test_as_ref_str_parse_round_trip() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let cases = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        for raw in cases {
            let d = ContentDigest::parse(&raw).unwrap();
            let borrowed: &str = d.as_ref();
            let round_tripped = ContentDigest::parse(borrowed).unwrap();
            assert_eq!(round_tripped, d);
            // Composed with the trait-generic parse peer: parsing the
            // AsRef<str> slice through TryFrom<&str> and FromStr must
            // yield the same value.
            let via_try_from = ContentDigest::try_from(borrowed).unwrap();
            let via_from_str: ContentDigest = borrowed.parse().unwrap();
            assert_eq!(via_try_from, d);
            assert_eq!(via_from_str, d);
        }
    }

    /// [`AsRef<[u8]>::as_ref`] yields exactly the same bytes as
    /// `<ContentDigest as AsRef<str>>::as_ref(&d).as_bytes()` at
    /// every validated digest — the byte-slice borrowed-view peer
    /// routes through the same one-oracle read discipline the UTF-8
    /// borrowed-view peer already carries, just projected onto its
    /// own frontier. Pins the "byte-slice surface routes through
    /// AsRef<str> ⇒ as_str ⇒ full backing string" invariant: a
    /// future refactor that inlined a divergent read into the
    /// [`AsRef<[u8]>`] impl fails this test.
    #[test]
    fn test_as_ref_bytes_matches_as_ref_str_bytes() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let cases = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        for raw in cases {
            let d = ContentDigest::parse(&raw).unwrap();
            let via_bytes: &[u8] = <ContentDigest as AsRef<[u8]>>::as_ref(&d);
            let via_str: &str = <ContentDigest as AsRef<str>>::as_ref(&d);
            assert_eq!(via_bytes, via_str.as_bytes());
            assert_eq!(via_bytes, d.as_str().as_bytes());
            assert_eq!(via_bytes, raw.as_bytes());
        }
    }

    /// [`AsRef<[u8]>::as_ref`] yields the full `<algorithm>:<hex>`
    /// byte slice for a sha256 digest, and every byte is ASCII
    /// (lowercase-hex / `sha256` / `:`) so a downstream ASCII
    /// consumer reads the canonical byte stream directly. Pins the
    /// primary registry algorithm on the byte-slice surface.
    #[test]
    fn test_as_ref_bytes_sha256_full_digest() {
        let raw = format!("sha256:{D1}");
        let d = ContentDigest::parse(&raw).unwrap();
        let borrowed: &[u8] = d.as_ref();
        assert_eq!(borrowed, raw.as_bytes());
        assert!(borrowed.starts_with(b"sha256:"));
        assert_eq!(&borrowed[7..], D1.as_bytes());
        assert!(borrowed.iter().all(|b| b.is_ascii()));
    }

    /// [`AsRef<[u8]>::as_ref`] yields the full `<algorithm>:<hex>`
    /// byte slice for a sha512 digest. Pins the second supported
    /// algorithm on the byte-slice surface so a widening at the
    /// inherent oracle is caught by an existing test on this
    /// derived surface.
    #[test]
    fn test_as_ref_bytes_sha512_full_digest() {
        let hex = "f".repeat(SHA512_HEX_LEN);
        let raw = format!("sha512:{hex}");
        let d = ContentDigest::parse(&raw).unwrap();
        let borrowed: &[u8] = d.as_ref();
        assert_eq!(borrowed, raw.as_bytes());
        assert!(borrowed.starts_with(b"sha512:"));
        assert_eq!(&borrowed[7..], hex.as_bytes());
        assert!(borrowed.iter().all(|b| b.is_ascii()));
    }

    /// [`AsRef<[u8]>::as_ref`] reads the trimmed backing bytes on
    /// an input the inherent oracle whitespace-trimmed at parse
    /// time — the byte-slice surface exposes the canonical trimmed
    /// value, not the caller's stray-whitespace raw input. Pins
    /// the trim discipline carrying through the byte-slice
    /// borrowed-view surface.
    #[test]
    fn test_as_ref_bytes_after_whitespace_trim() {
        let raw = format!("  sha256:{D1}\n");
        let expected = format!("sha256:{D1}");
        let d = ContentDigest::parse(&raw).unwrap();
        let borrowed: &[u8] = d.as_ref();
        assert_eq!(borrowed, expected.as_bytes());
        assert!(!borrowed.starts_with(b" "));
        assert!(!borrowed.ends_with(b"\n"));
    }

    /// The [`AsRef<[u8]>`] impl composes with a generic byte-slice
    /// helper bounded by `impl AsRef<[u8]>` — the compositional
    /// motivation for landing the trait separately from the
    /// inherent [`ContentDigest::as_str`] accessor. Pins the
    /// trait-generic consumer surface: a downstream site that
    /// types its input contract as `impl AsRef<[u8]>` (a streaming
    /// hasher `update` sink, a raw-write output sink, an
    /// hmac-mac accumulator, a byte-slice HashSet membership
    /// check) recovers the same borrowed full-digest byte slice a
    /// direct `.as_str().as_bytes()` chain would. Both by-value and
    /// by-borrow entry to the generic helper resolve to the same
    /// slice.
    #[test]
    fn test_as_ref_bytes_carries_through_generic_consumer() {
        fn first_byte_of<T: AsRef<[u8]>>(t: T) -> u8 {
            *t.as_ref().first().unwrap()
        }
        fn byte_length_of<T: AsRef<[u8]>>(t: T) -> usize {
            t.as_ref().len()
        }
        fn byte_eq<T: AsRef<[u8]>>(t: T, expected: &[u8]) -> bool {
            t.as_ref() == expected
        }
        // Simulate the load-bearing sink shape (streaming hasher):
        // fold `T: AsRef<[u8]>` bytes into an accumulator.
        fn sum_of_bytes<T: AsRef<[u8]>>(t: T) -> u64 {
            t.as_ref().iter().map(|b| u64::from(*b)).sum()
        }
        let raw = format!("sha256:{D1}");
        let d = ContentDigest::parse(&raw).unwrap();
        assert_eq!(first_byte_of(&d), b's');
        assert_eq!(byte_length_of(&d), raw.len());
        assert!(byte_eq(&d, raw.as_bytes()));
        assert_eq!(sum_of_bytes(&d), sum_of_bytes(raw.as_bytes()));
        // The generic bound must accept ContentDigest by value AND
        // by borrow — both routes must yield the same slice.
        assert_eq!(byte_length_of(d.clone()), raw.len());
        assert!(byte_eq(d, raw.as_bytes()));
    }

    /// A validated digest's [`AsRef<[u8]>`] slice round-trips
    /// through [`std::str::from_utf8`] and then the inherent
    /// [`ContentDigest::parse`] oracle back to the same validated
    /// [`ContentDigest`] value. Pins the "byte-slice surface
    /// exposes exactly the canonical UTF-8 form the inherent
    /// oracle accepts" invariant so a future canonicalising
    /// refinement to [`ContentDigest::as_str`] that broke
    /// round-trip via [`AsRef<[u8]>`] fails this test. Composed
    /// with the trait-generic parse peer chain
    /// ([`TryFrom<&str>`], [`FromStr`](std::str::FromStr)) so a
    /// consumer that receives the byte slice, decodes UTF-8, and
    /// parses back through any read surface recovers the same
    /// value.
    #[test]
    fn test_as_ref_bytes_parse_round_trip() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let cases = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        for raw in cases {
            let d = ContentDigest::parse(&raw).unwrap();
            let borrowed: &[u8] = d.as_ref();
            let decoded = std::str::from_utf8(borrowed).unwrap();
            let round_tripped = ContentDigest::parse(decoded).unwrap();
            assert_eq!(round_tripped, d);
            let via_try_from = ContentDigest::try_from(decoded).unwrap();
            let via_from_str: ContentDigest = decoded.parse().unwrap();
            assert_eq!(via_try_from, d);
            assert_eq!(via_from_str, d);
        }
    }

    /// The by-value owned-UTF-8 emit surface
    /// [`From<ContentDigest> for String`] moves the same validated
    /// full-digest bytes that the borrowed-view surfaces
    /// [`ContentDigest::as_str`] and [`AsRef<str>`] read. Pins the
    /// "emit peer routes through the same one-oracle backing string
    /// the read peers project" invariant across the sha256 / sha512
    /// algorithm grid — a future divergence between the moved-out
    /// [`String`] and the borrowed `&str` view fails this test.
    #[test]
    fn test_from_content_digest_string_matches_as_str() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let cases = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        for raw in cases {
            let d = ContentDigest::parse(&raw).unwrap();
            let borrowed_as_str = d.as_str().to_owned();
            let borrowed_as_ref: String = <ContentDigest as AsRef<str>>::as_ref(&d).to_owned();
            let via_display = format!("{d}");
            let emitted: String = String::from(d);
            assert_eq!(emitted, borrowed_as_str);
            assert_eq!(emitted, borrowed_as_ref);
            assert_eq!(emitted, via_display);
            assert_eq!(emitted, raw);
        }
    }

    /// [`From<ContentDigest> for String`] emits the full
    /// `<algorithm>:<hex>` slice for a sha256 digest. Pins the
    /// primary registry algorithm on the by-value owned-UTF-8 emit
    /// surface — the emitted [`String`] is byte-identical to the
    /// input the inherent oracle accepted.
    #[test]
    fn test_from_content_digest_string_sha256_full_digest() {
        let raw = format!("sha256:{D1}");
        let d = ContentDigest::parse(&raw).unwrap();
        let emitted: String = d.into();
        assert_eq!(emitted, raw);
        assert!(emitted.starts_with("sha256:"));
        assert_eq!(&emitted[7..], D1);
    }

    /// [`From<ContentDigest> for String`] emits the full
    /// `<algorithm>:<hex>` slice for a sha512 digest. Pins the
    /// second supported algorithm on the by-value owned-UTF-8 emit
    /// surface so a widening at the inherent oracle is caught by an
    /// existing test on this derived surface.
    #[test]
    fn test_from_content_digest_string_sha512_full_digest() {
        let hex = "f".repeat(SHA512_HEX_LEN);
        let raw = format!("sha512:{hex}");
        let d = ContentDigest::parse(&raw).unwrap();
        let emitted: String = d.into();
        assert_eq!(emitted, raw);
        assert!(emitted.starts_with("sha512:"));
        assert_eq!(&emitted[7..], hex);
    }

    /// [`From<ContentDigest> for String`] emits the trimmed canonical
    /// form on an input the inherent oracle whitespace-trimmed at
    /// parse time — the emit surface projects the canonical trimmed
    /// value, not the caller's stray-whitespace raw input. Pins the
    /// trim discipline carrying through the by-value owned-UTF-8
    /// emit surface.
    #[test]
    fn test_from_content_digest_string_after_whitespace_trim() {
        let raw = format!("  sha256:{D1}\n");
        let expected = format!("sha256:{D1}");
        let d = ContentDigest::parse(&raw).unwrap();
        let emitted: String = d.into();
        assert_eq!(emitted, expected);
        assert!(!emitted.starts_with(' '));
        assert!(!emitted.ends_with('\n'));
    }

    /// The [`From<ContentDigest> for String`] impl composes with a
    /// generic owned-string helper bounded by `impl Into<String>` —
    /// the compositional motivation for landing the trait separately
    /// from the borrowed-view [`AsRef<str>`] read peer. Pins the
    /// trait-generic consumer surface: a downstream site that types
    /// its input contract as `impl Into<String>`
    /// (a `HashMap<String, _>::insert` key, a
    /// [`http::HeaderValue::from_maybe_shared`] intake, a
    /// [`serde_json::Value::String`] constructor sink, a config-schema
    /// setter that owns its digest text) recovers the same validated
    /// full-digest [`String`] a direct `digest.as_str().to_owned()`
    /// chain would, at zero-copy off the moved backing storage.
    #[test]
    fn test_from_content_digest_string_carries_through_generic_consumer() {
        fn first_char_of<T: Into<String>>(t: T) -> char {
            let s: String = t.into();
            s.chars().next().unwrap()
        }
        fn length_of<T: Into<String>>(t: T) -> usize {
            let s: String = t.into();
            s.len()
        }
        fn owned_eq<T: Into<String>>(t: T, expected: &str) -> bool {
            let s: String = t.into();
            s == expected
        }
        let raw = format!("sha256:{D1}");
        let d1 = ContentDigest::parse(&raw).unwrap();
        let d2 = d1.clone();
        let d3 = d1.clone();
        assert_eq!(first_char_of(d1), 's');
        assert_eq!(length_of(d2), raw.len());
        assert!(owned_eq(d3, &raw));
    }

    /// A validated digest's [`From<ContentDigest> for String`]
    /// output round-trips through the full parse-surface set —
    /// inherent [`ContentDigest::parse`], [`TryFrom<&str>`],
    /// [`FromStr`](std::str::FromStr), [`TryFrom<String>`],
    /// [`TryFrom<Cow<'_, str>>`] — back to the same validated
    /// [`ContentDigest`] value. Pins the "emit surface projects
    /// exactly the canonical form every parse surface accepts"
    /// invariant so a future canonicalising refinement to the
    /// backing string that broke round-trip via the owned-UTF-8
    /// emit peer fails this test.
    #[test]
    fn test_from_content_digest_string_parse_round_trip() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let cases = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        for raw in cases {
            let original = ContentDigest::parse(&raw).unwrap();
            let emitted: String = String::from(original.clone());
            let via_parse = ContentDigest::parse(&emitted).unwrap();
            let via_try_from_str = ContentDigest::try_from(emitted.as_str()).unwrap();
            let via_from_str: ContentDigest = emitted.parse().unwrap();
            let via_try_from_string = ContentDigest::try_from(emitted.clone()).unwrap();
            let via_try_from_cow =
                ContentDigest::try_from(std::borrow::Cow::Owned(emitted.clone())).unwrap();
            assert_eq!(via_parse, original);
            assert_eq!(via_try_from_str, original);
            assert_eq!(via_from_str, original);
            assert_eq!(via_try_from_string, original);
            assert_eq!(via_try_from_cow, original);
        }
    }

    /// The by-value owned-byte-slice emit surface
    /// [`From<ContentDigest> for Vec<u8>`] moves the same validated
    /// full-digest bytes that the borrowed-view surface
    /// [`AsRef<[u8]> for ContentDigest`] reads and that the
    /// by-value owned-UTF-8 emit peer [`From<ContentDigest> for
    /// String`] emits (as UTF-8 bytes). Pins the "byte-slice emit
    /// peer routes through the same one-oracle backing bytes the
    /// borrowed-view byte-slice peer projects, chained through the
    /// UTF-8 emit oracle via [`String::into_bytes`]" invariant
    /// across the sha256 / sha512 algorithm grid — a future
    /// divergence between the moved-out [`Vec<u8>`] and the
    /// borrowed `&[u8]` view fails this test.
    #[test]
    fn test_from_content_digest_vec_u8_matches_as_ref_bytes() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let cases = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        for raw in cases {
            let d = ContentDigest::parse(&raw).unwrap();
            let borrowed_as_ref: Vec<u8> = <ContentDigest as AsRef<[u8]>>::as_ref(&d).to_vec();
            let via_str_bytes: Vec<u8> = d.as_str().as_bytes().to_vec();
            let via_string_emit: Vec<u8> = String::from(d.clone()).into_bytes();
            let emitted: Vec<u8> = Vec::<u8>::from(d);
            assert_eq!(emitted, borrowed_as_ref);
            assert_eq!(emitted, via_str_bytes);
            assert_eq!(emitted, via_string_emit);
            assert_eq!(emitted, raw.as_bytes());
        }
    }

    /// [`From<ContentDigest> for Vec<u8>`] emits the full
    /// `<algorithm>:<hex>` byte slice for a sha256 digest. Pins the
    /// primary registry algorithm on the by-value owned-byte-slice
    /// emit surface — the emitted [`Vec<u8>`] is byte-identical to
    /// the input the inherent oracle accepted, and every emitted
    /// byte is ASCII by parse invariant.
    #[test]
    fn test_from_content_digest_vec_u8_sha256_full_digest() {
        let raw = format!("sha256:{D1}");
        let d = ContentDigest::parse(&raw).unwrap();
        let emitted: Vec<u8> = d.into();
        assert_eq!(emitted, raw.as_bytes());
        assert!(emitted.starts_with(b"sha256:"));
        assert_eq!(&emitted[7..], D1.as_bytes());
        assert!(emitted.iter().all(|b| b.is_ascii()));
    }

    /// [`From<ContentDigest> for Vec<u8>`] emits the full
    /// `<algorithm>:<hex>` byte slice for a sha512 digest. Pins the
    /// second supported algorithm on the by-value owned-byte-slice
    /// emit surface so a widening at the inherent oracle is caught
    /// by an existing test on this derived surface.
    #[test]
    fn test_from_content_digest_vec_u8_sha512_full_digest() {
        let hex = "f".repeat(SHA512_HEX_LEN);
        let raw = format!("sha512:{hex}");
        let d = ContentDigest::parse(&raw).unwrap();
        let emitted: Vec<u8> = d.into();
        assert_eq!(emitted, raw.as_bytes());
        assert!(emitted.starts_with(b"sha512:"));
        assert_eq!(&emitted[7..], hex.as_bytes());
        assert!(emitted.iter().all(|b| b.is_ascii()));
    }

    /// [`From<ContentDigest> for Vec<u8>`] emits the trimmed
    /// canonical bytes on an input the inherent oracle
    /// whitespace-trimmed at parse time — the emit surface projects
    /// the canonical trimmed byte buffer, not the caller's
    /// stray-whitespace raw input. Pins the trim discipline
    /// carrying through the by-value owned-byte-slice emit surface.
    #[test]
    fn test_from_content_digest_vec_u8_after_whitespace_trim() {
        let raw = format!("  sha256:{D1}\n");
        let expected = format!("sha256:{D1}");
        let d = ContentDigest::parse(&raw).unwrap();
        let emitted: Vec<u8> = d.into();
        assert_eq!(emitted, expected.as_bytes());
        assert!(!emitted.starts_with(b" "));
        assert!(!emitted.ends_with(b"\n"));
    }

    /// The [`From<ContentDigest> for Vec<u8>`] impl composes with a
    /// generic owned-byte-buffer helper bounded by `impl
    /// Into<Vec<u8>>` — the compositional motivation for landing
    /// the trait separately from the borrowed-view [`AsRef<[u8]>`]
    /// read peer. Pins the trait-generic consumer surface: a
    /// downstream site that types its input contract as
    /// `impl Into<Vec<u8>>` (a `HashMap<Vec<u8>, _>::insert` key, a
    /// [`bytes::Bytes::from`] intake, an
    /// `http::HeaderValue::from_bytes` `Vec<u8>` frontier, a
    /// streaming-hasher owned-buffer construction sink) recovers
    /// the same validated full-digest bytes a direct
    /// `digest.as_ref().to_vec()` chain would, at zero-copy off the
    /// moved backing storage.
    #[test]
    fn test_from_content_digest_vec_u8_carries_through_generic_consumer() {
        fn first_byte_of<T: Into<Vec<u8>>>(t: T) -> u8 {
            let v: Vec<u8> = t.into();
            *v.first().unwrap()
        }
        fn byte_length_of<T: Into<Vec<u8>>>(t: T) -> usize {
            let v: Vec<u8> = t.into();
            v.len()
        }
        fn owned_bytes_eq<T: Into<Vec<u8>>>(t: T, expected: &[u8]) -> bool {
            let v: Vec<u8> = t.into();
            v == expected
        }
        let raw = format!("sha256:{D1}");
        let d1 = ContentDigest::parse(&raw).unwrap();
        let d2 = d1.clone();
        let d3 = d1.clone();
        assert_eq!(first_byte_of(d1), b's');
        assert_eq!(byte_length_of(d2), raw.len());
        assert!(owned_bytes_eq(d3, raw.as_bytes()));
    }

    /// A validated digest's [`From<ContentDigest> for Vec<u8>`]
    /// output round-trips through [`String::from_utf8`] and then
    /// the full parse-surface set — inherent
    /// [`ContentDigest::parse`], [`TryFrom<&str>`],
    /// [`FromStr`](std::str::FromStr), [`TryFrom<String>`],
    /// [`TryFrom<Cow<'_, str>>`] — back to the same validated
    /// [`ContentDigest`] value. Pins the "byte-slice emit surface
    /// projects exactly the canonical UTF-8 form every parse
    /// surface accepts" invariant so a future canonicalising
    /// refinement to the backing bytes that broke round-trip via
    /// the owned-byte-slice emit peer fails this test.
    #[test]
    fn test_from_content_digest_vec_u8_parse_round_trip() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let cases = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        for raw in cases {
            let original = ContentDigest::parse(&raw).unwrap();
            let emitted: Vec<u8> = Vec::<u8>::from(original.clone());
            let decoded = String::from_utf8(emitted).unwrap();
            let via_parse = ContentDigest::parse(&decoded).unwrap();
            let via_try_from_str = ContentDigest::try_from(decoded.as_str()).unwrap();
            let via_from_str: ContentDigest = decoded.parse().unwrap();
            let via_try_from_string = ContentDigest::try_from(decoded.clone()).unwrap();
            let via_try_from_cow =
                ContentDigest::try_from(std::borrow::Cow::Owned(decoded.clone())).unwrap();
            assert_eq!(via_parse, original);
            assert_eq!(via_try_from_str, original);
            assert_eq!(via_from_str, original);
            assert_eq!(via_try_from_string, original);
            assert_eq!(via_try_from_cow, original);
        }
    }

    /// The by-value shrunk-owned UTF-8 emit surface
    /// [`From<ContentDigest> for Box<str>`] moves the same validated
    /// full-digest bytes that the borrowed-view surface
    /// [`ContentDigest::as_str`] reads and that the by-value
    /// owned-UTF-8 emit peer [`From<ContentDigest> for String`]
    /// emits, chained through [`String::into_boxed_str`]. Pins the
    /// "shrunk-owned UTF-8 emit peer routes through the same
    /// one-oracle backing string the owned-UTF-8 emit peer projects"
    /// invariant across the sha256 / sha512 algorithm grid — a
    /// future divergence between the moved-out [`Box<str>`] and the
    /// borrowed `&str` view fails this test.
    #[test]
    fn test_from_content_digest_box_str_matches_as_str() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let cases = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        for raw in cases {
            let d = ContentDigest::parse(&raw).unwrap();
            let borrowed_as_str = d.as_str().to_owned();
            let via_display = format!("{d}");
            let emitted: Box<str> = Box::<str>::from(d);
            assert_eq!(emitted.as_ref(), borrowed_as_str.as_str());
            assert_eq!(emitted.as_ref(), via_display.as_str());
            assert_eq!(&*emitted, raw.as_str());
        }
    }

    /// [`From<ContentDigest> for Box<str>`] emits the full
    /// `<algorithm>:<hex>` slice for a sha256 digest. Pins the
    /// primary registry algorithm on the by-value shrunk-owned UTF-8
    /// emit surface — the emitted [`Box<str>`] is byte-identical to
    /// the input the inherent oracle accepted.
    #[test]
    fn test_from_content_digest_box_str_sha256_full_digest() {
        let raw = format!("sha256:{D1}");
        let d = ContentDigest::parse(&raw).unwrap();
        let emitted: Box<str> = d.into();
        assert_eq!(&*emitted, raw.as_str());
        assert!(emitted.starts_with("sha256:"));
        assert_eq!(&emitted[7..], D1);
    }

    /// [`From<ContentDigest> for Box<str>`] emits the full
    /// `<algorithm>:<hex>` slice for a sha512 digest. Pins the
    /// second supported algorithm on the by-value shrunk-owned UTF-8
    /// emit surface so a widening at the inherent oracle is caught
    /// by an existing test on this derived surface.
    #[test]
    fn test_from_content_digest_box_str_sha512_full_digest() {
        let hex = "f".repeat(SHA512_HEX_LEN);
        let raw = format!("sha512:{hex}");
        let d = ContentDigest::parse(&raw).unwrap();
        let emitted: Box<str> = d.into();
        assert_eq!(&*emitted, raw.as_str());
        assert!(emitted.starts_with("sha512:"));
        assert_eq!(&emitted[7..], hex.as_str());
    }

    /// [`From<ContentDigest> for Box<str>`] emits the trimmed
    /// canonical form on an input the inherent oracle
    /// whitespace-trimmed at parse time — the emit surface projects
    /// the canonical trimmed value, not the caller's stray-whitespace
    /// raw input. Pins the trim discipline carrying through the
    /// by-value shrunk-owned UTF-8 emit surface.
    #[test]
    fn test_from_content_digest_box_str_after_whitespace_trim() {
        let raw = format!("  sha256:{D1}\n");
        let expected = format!("sha256:{D1}");
        let d = ContentDigest::parse(&raw).unwrap();
        let emitted: Box<str> = d.into();
        assert_eq!(&*emitted, expected.as_str());
        assert!(!emitted.starts_with(' '));
        assert!(!emitted.ends_with('\n'));
    }

    /// The [`From<ContentDigest> for Box<str>`] impl composes with a
    /// generic shrunk-owned label helper bounded by
    /// `impl Into<Box<str>>` — the compositional motivation for
    /// landing the trait separately from the borrowed-view
    /// [`AsRef<str>`] read peer and the owned-string
    /// [`From<ContentDigest> for String`] emit peer. Pins the
    /// trait-generic consumer surface: a downstream site that types
    /// its input contract as `impl Into<Box<str>>`
    /// (a [`std::collections::HashMap<Box<str>, _>`] key insertion, a
    /// validated-input newtype whose digest field is stored as
    /// [`Box<str>`] to shed the [`String`] growth header, a
    /// `phf`-style keyed-table value slot that owns its label as a
    /// boxed slice) recovers the same validated full-digest
    /// [`Box<str>`] a direct
    /// `digest.as_str().to_owned().into_boxed_str()` chain would, at
    /// no allocation beyond the parse-time backing off the moved
    /// storage.
    #[test]
    fn test_from_content_digest_box_str_carries_through_generic_consumer() {
        fn first_char_of<T: Into<Box<str>>>(t: T) -> char {
            let b: Box<str> = t.into();
            b.chars().next().unwrap()
        }
        fn length_of<T: Into<Box<str>>>(t: T) -> usize {
            let b: Box<str> = t.into();
            b.len()
        }
        fn boxed_eq<T: Into<Box<str>>>(t: T, expected: &str) -> bool {
            let b: Box<str> = t.into();
            &*b == expected
        }
        let raw = format!("sha256:{D1}");
        let d1 = ContentDigest::parse(&raw).unwrap();
        let d2 = d1.clone();
        let d3 = d1.clone();
        assert_eq!(first_char_of(d1), 's');
        assert_eq!(length_of(d2), raw.len());
        assert!(boxed_eq(d3, &raw));
    }

    /// A validated digest's [`From<ContentDigest> for Box<str>`]
    /// output round-trips through the full parse-surface set —
    /// inherent [`ContentDigest::parse`], [`TryFrom<&str>`],
    /// [`FromStr`](std::str::FromStr), [`TryFrom<String>`],
    /// [`TryFrom<Cow<'_, str>>`] — back to the same validated
    /// [`ContentDigest`] value. Pins the "shrunk-owned UTF-8 emit
    /// surface projects exactly the canonical form every parse
    /// surface accepts" invariant so a future canonicalising
    /// refinement to the backing string that broke round-trip via
    /// the shrunk-owned UTF-8 emit peer fails this test.
    #[test]
    fn test_from_content_digest_box_str_parse_round_trip() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let cases = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        for raw in cases {
            let original = ContentDigest::parse(&raw).unwrap();
            let emitted: Box<str> = Box::<str>::from(original.clone());
            let via_parse = ContentDigest::parse(&emitted).unwrap();
            let via_try_from_str = ContentDigest::try_from(&*emitted).unwrap();
            let via_from_str: ContentDigest = emitted.parse().unwrap();
            let via_try_from_string =
                ContentDigest::try_from(String::from(emitted.clone())).unwrap();
            let via_try_from_cow =
                ContentDigest::try_from(std::borrow::Cow::Owned(String::from(emitted))).unwrap();
            assert_eq!(via_parse, original);
            assert_eq!(via_try_from_str, original);
            assert_eq!(via_from_str, original);
            assert_eq!(via_try_from_string, original);
            assert_eq!(via_try_from_cow, original);
        }
    }

    /// [`From<ContentDigest> for Cow<'static, str>`] emits the same
    /// canonical `<algorithm>:<hex>` slice every borrowed-view read
    /// surface exposes. Pins the borrowed/owned-frontier emit peer to
    /// the [`ContentDigest::as_str`] one-oracle read surface at every
    /// supported algorithm, so a widening at the inherent oracle is
    /// caught by an existing test on this derived surface.
    #[test]
    fn test_from_content_digest_cow_static_str_matches_as_str() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let cases = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        for raw in cases {
            let d = ContentDigest::parse(&raw).unwrap();
            let borrowed_as_str = d.as_str().to_owned();
            let via_display = format!("{d}");
            let emitted: std::borrow::Cow<'static, str> = std::borrow::Cow::<'static, str>::from(d);
            assert_eq!(emitted.as_ref(), borrowed_as_str.as_str());
            assert_eq!(emitted.as_ref(), via_display.as_str());
            assert_eq!(&*emitted, raw.as_str());
        }
    }

    /// [`From<ContentDigest> for Cow<'static, str>`] emits the full
    /// `<algorithm>:<hex>` slice for a sha256 digest. Pins the primary
    /// registry algorithm on the by-value borrowed/owned-frontier emit
    /// surface — the emitted [`Cow<'static, str>`] is byte-identical to
    /// the input the inherent oracle accepted.
    #[test]
    fn test_from_content_digest_cow_static_str_sha256_full_digest() {
        let raw = format!("sha256:{D1}");
        let d = ContentDigest::parse(&raw).unwrap();
        let emitted: std::borrow::Cow<'static, str> = d.into();
        assert_eq!(&*emitted, raw.as_str());
        assert!(emitted.starts_with("sha256:"));
        assert_eq!(&emitted[7..], D1);
    }

    /// [`From<ContentDigest> for Cow<'static, str>`] emits the full
    /// `<algorithm>:<hex>` slice for a sha512 digest. Pins the second
    /// supported algorithm on the by-value borrowed/owned-frontier emit
    /// surface so a widening at the inherent oracle is caught by an
    /// existing test on this derived surface.
    #[test]
    fn test_from_content_digest_cow_static_str_sha512_full_digest() {
        let hex = "f".repeat(SHA512_HEX_LEN);
        let raw = format!("sha512:{hex}");
        let d = ContentDigest::parse(&raw).unwrap();
        let emitted: std::borrow::Cow<'static, str> = d.into();
        assert_eq!(&*emitted, raw.as_str());
        assert!(emitted.starts_with("sha512:"));
        assert_eq!(&emitted[7..], hex.as_str());
    }

    /// [`From<ContentDigest> for Cow<'static, str>`] emits the trimmed
    /// canonical form on an input the inherent oracle whitespace-trimmed
    /// at parse time — the emit surface projects the canonical trimmed
    /// value, not the caller's stray-whitespace raw input. Pins the trim
    /// discipline carrying through the by-value borrowed/owned-frontier
    /// emit surface.
    #[test]
    fn test_from_content_digest_cow_static_str_after_whitespace_trim() {
        let raw = format!("  sha256:{D1}\n");
        let expected = format!("sha256:{D1}");
        let d = ContentDigest::parse(&raw).unwrap();
        let emitted: std::borrow::Cow<'static, str> = d.into();
        assert_eq!(&*emitted, expected.as_str());
        assert!(!emitted.starts_with(' '));
        assert!(!emitted.ends_with('\n'));
    }

    /// The [`From<ContentDigest> for Cow<'static, str>`] impl composes
    /// with a generic borrowed/owned-frontier label helper bounded by
    /// `impl Into<Cow<'static, str>>` — the compositional motivation for
    /// landing the trait separately from the owned-string
    /// [`From<ContentDigest> for String`] and shrunk-owned
    /// [`From<ContentDigest> for Box<str>`] emit peers. Pins the
    /// trait-generic consumer surface: a downstream site that types its
    /// input contract as `impl Into<Cow<'static, str>>` (a
    /// `tracing::field` recorder that interleaves `'static` labels with
    /// runtime-parsed digests in the same sink, a serde container that
    /// opts into `#[serde(from = "Cow<'static, str>")]` at the
    /// borrowed/owned-frontier emit surface, an
    /// `http::HeaderValue`-adjacent bridge that types its label input
    /// as [`Cow<'static, str>`] to elide the allocation on the borrowed
    /// branch) recovers the same validated full-digest [`Cow<'static,
    /// str>`] a direct `Cow::Owned(digest.as_str().to_owned())` chain
    /// would, at no allocation beyond the parse-time backing off the
    /// moved storage.
    #[test]
    fn test_from_content_digest_cow_static_str_carries_through_generic_consumer() {
        fn first_char_of<T: Into<std::borrow::Cow<'static, str>>>(t: T) -> char {
            let c: std::borrow::Cow<'static, str> = t.into();
            c.chars().next().unwrap()
        }
        fn length_of<T: Into<std::borrow::Cow<'static, str>>>(t: T) -> usize {
            let c: std::borrow::Cow<'static, str> = t.into();
            c.len()
        }
        fn cow_eq<T: Into<std::borrow::Cow<'static, str>>>(t: T, expected: &str) -> bool {
            let c: std::borrow::Cow<'static, str> = t.into();
            &*c == expected
        }
        let raw = format!("sha256:{D1}");
        let d1 = ContentDigest::parse(&raw).unwrap();
        let d2 = d1.clone();
        let d3 = d1.clone();
        assert_eq!(first_char_of(d1), 's');
        assert_eq!(length_of(d2), raw.len());
        assert!(cow_eq(d3, &raw));
    }

    /// A validated digest's [`From<ContentDigest> for Cow<'static, str>`]
    /// output round-trips through the full parse-surface set —
    /// inherent [`ContentDigest::parse`], [`TryFrom<&str>`],
    /// [`FromStr`](std::str::FromStr), [`TryFrom<String>`],
    /// [`TryFrom<Cow<'_, str>>`] — back to the same validated
    /// [`ContentDigest`] value. Pins the "borrowed/owned-frontier emit
    /// surface projects exactly the canonical form every parse surface
    /// accepts" invariant so a future canonicalising refinement to the
    /// backing string that broke round-trip via the
    /// borrowed/owned-frontier emit peer fails this test.
    #[test]
    fn test_from_content_digest_cow_static_str_parse_round_trip() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let cases = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        for raw in cases {
            let original = ContentDigest::parse(&raw).unwrap();
            let emitted: std::borrow::Cow<'static, str> =
                std::borrow::Cow::<'static, str>::from(original.clone());
            let via_parse = ContentDigest::parse(emitted.as_ref()).unwrap();
            let via_try_from_str = ContentDigest::try_from(emitted.as_ref()).unwrap();
            let via_from_str: ContentDigest = emitted.parse().unwrap();
            let via_try_from_string = ContentDigest::try_from(emitted.to_string()).unwrap();
            let via_try_from_cow = ContentDigest::try_from(emitted).unwrap();
            assert_eq!(via_parse, original);
            assert_eq!(via_try_from_str, original);
            assert_eq!(via_from_str, original);
            assert_eq!(via_try_from_string, original);
            assert_eq!(via_try_from_cow, original);
        }
    }

    /// [`From<ContentDigest> for Cow<'static, str>`] takes the
    /// [`Cow::Owned`] branch — the load-bearing choice given
    /// [`ContentDigest`] holds a runtime-parsed [`String`] with no
    /// `'static` backing to borrow. Contrasts the enum-shaped sibling
    /// [`Cow<'static, str>`] emit peers on [`crate::version::BumpLevel`],
    /// [`crate::probe_outcome::AdmissionTier`], and
    /// [`crate::retry::PerAttemptRegion`] — each of which lands on
    /// [`Cow::Borrowed`] because their `as_str` oracle returns a
    /// `'static` slice off a static label table — and pins the branch
    /// discriminator so a future refactor that accidentally boxed the
    /// digest through [`Cow::Borrowed`] on a leaked buffer (or that
    /// re-formatted through [`std::fmt::Display`] into an owned string
    /// to shoehorn onto the borrowed branch) fails this test.
    #[test]
    fn test_from_content_digest_cow_static_str_is_owned() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let cases = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        for raw in cases {
            let d = ContentDigest::parse(&raw).unwrap();
            let emitted: std::borrow::Cow<'static, str> = d.into();
            assert!(
                matches!(emitted, std::borrow::Cow::Owned(_)),
                "ContentDigest owns its backing String; Cow<'static, str> emit peer must \
                 wrap the moved backing in Cow::Owned, not Cow::Borrowed"
            );
        }
    }

    /// The by-value shared-owned UTF-8 emit surface
    /// [`From<ContentDigest> for std::sync::Arc<str>`] emits the same
    /// canonical `<algorithm>:<hex>` slice every borrowed-view read surface
    /// exposes. Pins the shared-owned frontier emit peer to the
    /// [`ContentDigest::as_str`] one-oracle read surface at every supported
    /// algorithm, so a widening at the inherent oracle is caught by an
    /// existing test on this derived surface.
    #[test]
    fn test_from_content_digest_arc_str_matches_as_str() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let cases = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        for raw in cases {
            let d = ContentDigest::parse(&raw).unwrap();
            let borrowed_as_str = d.as_str().to_owned();
            let via_display = format!("{d}");
            let emitted: std::sync::Arc<str> = std::sync::Arc::<str>::from(d);
            assert_eq!(&*emitted, borrowed_as_str.as_str());
            assert_eq!(&*emitted, via_display.as_str());
            assert_eq!(&*emitted, raw.as_str());
        }
    }

    /// [`From<ContentDigest> for std::sync::Arc<str>`] emits the full
    /// `<algorithm>:<hex>` slice for a sha256 digest. Pins the primary
    /// registry algorithm on the by-value shared-owned UTF-8 emit surface —
    /// the emitted [`Arc<str>`] is byte-identical to the input the inherent
    /// oracle accepted.
    #[test]
    fn test_from_content_digest_arc_str_sha256_full_digest() {
        let raw = format!("sha256:{D1}");
        let d = ContentDigest::parse(&raw).unwrap();
        let emitted: std::sync::Arc<str> = d.into();
        assert_eq!(&*emitted, raw.as_str());
        assert!(emitted.starts_with("sha256:"));
        assert_eq!(&emitted[7..], D1);
    }

    /// [`From<ContentDigest> for std::sync::Arc<str>`] emits the full
    /// `<algorithm>:<hex>` slice for a sha512 digest. Pins the second
    /// supported algorithm on the by-value shared-owned UTF-8 emit surface
    /// so a widening at the inherent oracle is caught by an existing test
    /// on this derived surface.
    #[test]
    fn test_from_content_digest_arc_str_sha512_full_digest() {
        let hex = "f".repeat(SHA512_HEX_LEN);
        let raw = format!("sha512:{hex}");
        let d = ContentDigest::parse(&raw).unwrap();
        let emitted: std::sync::Arc<str> = d.into();
        assert_eq!(&*emitted, raw.as_str());
        assert!(emitted.starts_with("sha512:"));
        assert_eq!(&emitted[7..], hex.as_str());
    }

    /// [`From<ContentDigest> for std::sync::Arc<str>`] emits the trimmed
    /// canonical form on an input the inherent oracle whitespace-trimmed at
    /// parse time — the emit surface projects the canonical trimmed value,
    /// not the caller's stray-whitespace raw input. Pins the trim discipline
    /// carrying through the by-value shared-owned UTF-8 emit surface.
    #[test]
    fn test_from_content_digest_arc_str_after_whitespace_trim() {
        let raw = format!("  sha256:{D1}\n");
        let expected = format!("sha256:{D1}");
        let d = ContentDigest::parse(&raw).unwrap();
        let emitted: std::sync::Arc<str> = d.into();
        assert_eq!(&*emitted, expected.as_str());
        assert!(!emitted.starts_with(' '));
        assert!(!emitted.ends_with('\n'));
    }

    /// The [`From<ContentDigest> for std::sync::Arc<str>`] impl composes
    /// with a generic shared-owned-label helper bounded by
    /// `impl Into<std::sync::Arc<str>>` — the compositional motivation for
    /// landing the trait separately from the owned-string
    /// [`From<ContentDigest> for String`] and shrunk-owned
    /// [`From<ContentDigest> for Box<str>`] emit peers. Pins the
    /// trait-generic consumer surface: a downstream site that types its
    /// input contract as `impl Into<Arc<str>>` (a
    /// `dashmap::DashMap<Arc<str>, _>` cache key inserter, a
    /// `tokio::sync::broadcast` sender that carries an `Arc<str>` payload
    /// across worker threads at `O(1)` `Arc::clone` cost, a
    /// `serde` container opting into `#[serde(into = "Arc<str>")]` at the
    /// shared-owned frontier) recovers the same validated full-digest
    /// [`Arc<str>`] a direct `Arc::<str>::from(digest.as_str())` call
    /// would, at exactly the shared-owned repackaging cost off the moved
    /// backing storage.
    #[test]
    fn test_from_content_digest_arc_str_carries_through_generic_consumer() {
        fn first_char_of<T: Into<std::sync::Arc<str>>>(t: T) -> char {
            let a: std::sync::Arc<str> = t.into();
            a.chars().next().unwrap()
        }
        fn length_of<T: Into<std::sync::Arc<str>>>(t: T) -> usize {
            let a: std::sync::Arc<str> = t.into();
            a.len()
        }
        fn arc_eq<T: Into<std::sync::Arc<str>>>(t: T, expected: &str) -> bool {
            let a: std::sync::Arc<str> = t.into();
            &*a == expected
        }
        let raw = format!("sha256:{D1}");
        let d1 = ContentDigest::parse(&raw).unwrap();
        let d2 = d1.clone();
        let d3 = d1.clone();
        assert_eq!(first_char_of(d1), 's');
        assert_eq!(length_of(d2), raw.len());
        assert!(arc_eq(d3, &raw));
    }

    /// A validated digest's [`From<ContentDigest> for std::sync::Arc<str>`]
    /// output round-trips through the full parse-surface set — inherent
    /// [`ContentDigest::parse`], [`TryFrom<&str>`],
    /// [`FromStr`](std::str::FromStr), [`TryFrom<String>`],
    /// [`TryFrom<Cow<'_, str>>`] — back to the same validated
    /// [`ContentDigest`] value. Pins the "shared-owned emit surface
    /// projects exactly the canonical form every parse surface accepts"
    /// invariant so a future canonicalising refinement to the backing
    /// string that broke round-trip via the shared-owned UTF-8 emit peer
    /// fails this test.
    #[test]
    fn test_from_content_digest_arc_str_parse_round_trip() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let cases = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        for raw in cases {
            let original = ContentDigest::parse(&raw).unwrap();
            let emitted: std::sync::Arc<str> = std::sync::Arc::<str>::from(original.clone());
            let via_parse = ContentDigest::parse(&emitted).unwrap();
            let via_try_from_str = ContentDigest::try_from(&*emitted).unwrap();
            let via_from_str: ContentDigest = emitted.parse().unwrap();
            let via_try_from_string = ContentDigest::try_from(emitted.to_string()).unwrap();
            let via_try_from_cow =
                ContentDigest::try_from(std::borrow::Cow::Borrowed(&*emitted)).unwrap();
            assert_eq!(via_parse, original);
            assert_eq!(via_try_from_str, original);
            assert_eq!(via_from_str, original);
            assert_eq!(via_try_from_string, original);
            assert_eq!(via_try_from_cow, original);
        }
    }

    /// [`From<ContentDigest> for std::sync::Arc<str>`] emits an
    /// [`Arc<str>`] whose [`Arc::clone`] returns a second handle onto the
    /// same shared allocation — the load-bearing property of the
    /// shared-owned frontier that a downstream cross-thread cache slot
    /// (`dashmap::DashMap<Arc<str>, _>`, `tokio::sync::broadcast` payload)
    /// relies on to fan a single label allocation across worker threads at
    /// atomic-refcount cost. Pins the shared-allocation identity so a
    /// future refactor that accidentally re-allocated on
    /// [`Arc::clone`] (a rebox through `to_string().into()` in the emit
    /// path, a per-clone `Arc::<str>::from(&*self)` chain) fails this
    /// test.
    #[test]
    fn test_from_content_digest_arc_str_clones_cheaply_across_threads() {
        let raw = format!("sha256:{D1}");
        let d = ContentDigest::parse(&raw).unwrap();
        let emitted: std::sync::Arc<str> = d.into();
        let cloned = std::sync::Arc::clone(&emitted);
        assert!(
            std::sync::Arc::ptr_eq(&emitted, &cloned),
            "Arc::clone on the emitted Arc<str> must return a handle onto the same shared \
             allocation, not a fresh allocation of the label bytes"
        );
        assert_eq!(&*cloned, raw.as_str());
        assert_eq!(std::sync::Arc::strong_count(&emitted), 2);
        let handoff = std::sync::Arc::clone(&emitted);
        let joined = std::thread::spawn(move || handoff.to_string())
            .join()
            .unwrap();
        assert_eq!(joined, raw);
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

    /// The canonical `name:tag` shape (with and without a registry
    /// prefix and with and without a path prefix) reports the tag
    /// after the final `/` and the final `:`.
    #[test]
    fn test_image_tag_extracts_canonical_tag() {
        assert_eq!(image_tag("nginx:latest"), Some("latest"));
        assert_eq!(image_tag("library/nginx:1.25"), Some("1.25"));
        assert_eq!(image_tag("docker.io/library/nginx:1.25"), Some("1.25"));
        assert_eq!(image_tag("ghcr.io/pleme-io/forge:v0.42.0"), Some("v0.42.0"));
    }

    /// A bare reference (no `:` after the final path separator) has
    /// no tag; report [`None`] rather than the image name itself,
    /// which the naïve `image.split(':').last()` predecessor returned.
    #[test]
    fn test_image_tag_bare_reference_has_no_tag() {
        assert_eq!(image_tag("nginx"), None);
        assert_eq!(image_tag("library/nginx"), None);
        assert_eq!(image_tag("docker.io/library/nginx"), None);
    }

    /// A `registry:port/name` prefix embeds a `:` in the registry
    /// segment; the tag scan is scoped to the final path component,
    /// so the port colon is not misread as a tag colon (the failure
    /// mode of the `.split(':').last()` predecessor for names with
    /// no tag but with a port-bearing registry).
    #[test]
    fn test_image_tag_registry_port_is_not_a_tag() {
        assert_eq!(image_tag("registry.example.com:5000/nginx"), None);
        assert_eq!(image_tag("registry.example.com:5000/library/nginx"), None);
        assert_eq!(image_tag("registry.example.com:5000/nginx:v1"), Some("v1"));
        assert_eq!(
            image_tag("registry.example.com:5000/library/nginx:v1"),
            Some("v1")
        );
    }

    /// A digest-form reference (`name@sha256:hex`) is content-
    /// addressed identity, not a tag; report [`None`] rather than
    /// the digest hex, which the naïve `image.split(':').last()`
    /// predecessor returned as if it were a tag.
    #[test]
    fn test_image_tag_digest_form_has_no_tag() {
        assert_eq!(image_tag(&format!("nginx@sha256:{D1}")), None);
        assert_eq!(image_tag(&format!("library/nginx@sha256:{D1}")), None);
        assert_eq!(
            image_tag(&format!(
                "registry.example.com:5000/library/nginx@sha256:{D1}"
            )),
            None
        );
    }

    /// A `name:tag@digest` reference carries both a tag and a
    /// digest; the tag survives the digest strip and is reported.
    #[test]
    fn test_image_tag_tag_and_digest_reports_tag() {
        assert_eq!(
            image_tag(&format!("nginx:latest@sha256:{D1}")),
            Some("latest")
        );
        assert_eq!(
            image_tag(&format!(
                "registry.example.com:5000/library/nginx:1.25@sha256:{D1}"
            )),
            Some("1.25")
        );
    }

    /// Degenerate and malformed inputs — empty string, trailing
    /// separators, empty tag after a `:`, empty name before a `:` —
    /// all report [`None`] rather than an empty tag slice; the
    /// call-site fallback (`unwrap_or("unknown")`, `ok_or(...)`)
    /// then decides how the "no tag" case renders.
    #[test]
    fn test_image_tag_degenerate_inputs_have_no_tag() {
        assert_eq!(image_tag(""), None);
        assert_eq!(image_tag("nginx:"), None);
        assert_eq!(image_tag(":latest"), None);
        assert_eq!(image_tag("nginx/"), None);
        assert_eq!(image_tag("/nginx"), None);
    }

    /// [`image_tag_display`] returns the parsed tag for every input
    /// [`image_tag`] does; the display sibling is a pure widening from
    /// [`Option<&str>`] to `&str` on the `Some` branch.
    #[test]
    fn test_image_tag_display_returns_parsed_tag_when_present() {
        assert_eq!(image_tag_display("nginx:latest"), "latest");
        assert_eq!(
            image_tag_display("ghcr.io/pleme-io/forge:v0.42.0"),
            "v0.42.0"
        );
        assert_eq!(
            image_tag_display("registry.example.com:5000/library/nginx:1.25"),
            "1.25"
        );
    }

    /// Every input that makes [`image_tag`] return [`None`] — bare,
    /// port-only, digest-form, degenerate — routes to the shared
    /// [`IMAGE_TAG_UNKNOWN`] sentinel via [`image_tag_display`].
    #[test]
    fn test_image_tag_display_falls_back_to_sentinel() {
        assert_eq!(image_tag_display(""), IMAGE_TAG_UNKNOWN);
        assert_eq!(image_tag_display("nginx"), IMAGE_TAG_UNKNOWN);
        assert_eq!(
            image_tag_display("registry.example.com:5000/library/nginx"),
            IMAGE_TAG_UNKNOWN
        );
        assert_eq!(
            image_tag_display(&format!("nginx@sha256:{D1}")),
            IMAGE_TAG_UNKNOWN
        );
        assert_eq!(image_tag_display("nginx:"), IMAGE_TAG_UNKNOWN);
        assert_eq!(image_tag_display(":latest"), IMAGE_TAG_UNKNOWN);
    }

    /// The sentinel is a non-empty display string safe to interpolate
    /// into any user-facing log line — a rollout status line that
    /// substituted an empty string here would produce
    /// "Current tag: , waiting for SHA …" and lose the reader.
    #[test]
    fn test_image_tag_unknown_is_a_non_empty_display_string() {
        assert!(!IMAGE_TAG_UNKNOWN.is_empty());
        assert_eq!(IMAGE_TAG_UNKNOWN, "unknown");
    }

    /// Regression pin for the five call sites this primitive replaces:
    /// [`image_tag_display`] must be observationally identical to the
    /// prior hand-rolled `image_tag(input).unwrap_or("unknown")` on
    /// every input the crate had in production. Reverting the impl to
    /// something that changed the sentinel spelling (e.g. `""`, `"?"`,
    /// `"n/a"`) would fail this test, catching the drift the
    /// centralised primitive is here to prevent.
    #[test]
    fn test_image_tag_display_matches_prior_unwrap_or_unknown_pattern() {
        let inputs = [
            "nginx:latest",
            "ghcr.io/pleme-io/forge:v0.42.0",
            "registry.example.com:5000/library/nginx:1.25",
            "",
            "nginx",
            "registry.example.com:5000/library/nginx",
            "nginx:",
            ":latest",
            "nginx/",
        ];
        for input in inputs {
            let predecessor = image_tag(input).unwrap_or("unknown");
            assert_eq!(
                image_tag_display(input),
                predecessor,
                "image_tag_display drifted from the pre-extraction \
                 `image_tag(image).unwrap_or(\"unknown\")` shape on input {input:?}"
            );
        }
    }

    /// The canonical `Loaded image: <ref>` shape (tagged load) reports
    /// the full `<name>:<tag>` reference verbatim — the tag colon
    /// inside the reference is preserved, not eaten by a naïve
    /// `split(':').last()` scan.
    #[test]
    fn test_docker_load_image_reference_tagged_load() {
        assert_eq!(
            docker_load_image_reference("Loaded image: nginx:latest"),
            Some("nginx:latest")
        );
        assert_eq!(
            docker_load_image_reference("Loaded image: myservice:abc1234"),
            Some("myservice:abc1234")
        );
        assert_eq!(
            docker_load_image_reference("Loaded image: ghcr.io/pleme-io/forge:v0.42.0"),
            Some("ghcr.io/pleme-io/forge:v0.42.0")
        );
        // Registry with port + tag: two colons inside the reference,
        // both preserved.
        assert_eq!(
            docker_load_image_reference(
                "Loaded image: registry.example.com:5000/library/nginx:1.25"
            ),
            Some("registry.example.com:5000/library/nginx:1.25")
        );
    }

    /// The `Loaded image ID: <id>` shape (untagged load) reports the
    /// full content-addressed identity verbatim, with the `sha256:`
    /// algorithm prefix intact.
    #[test]
    fn test_docker_load_image_reference_untagged_load() {
        let id = format!("sha256:{D1}");
        assert_eq!(
            docker_load_image_reference(&format!("Loaded image ID: {id}")),
            Some(id.as_str())
        );
    }

    /// Whitespace around the reference is trimmed; the tail is always
    /// the reference alone with no stray leading space (which the
    /// downstream `docker tag` would otherwise reject).
    #[test]
    fn test_docker_load_image_reference_trims_surrounding_whitespace() {
        assert_eq!(
            docker_load_image_reference("Loaded image:   nginx:latest   "),
            Some("nginx:latest")
        );
        assert_eq!(
            docker_load_image_reference("Loaded image ID:\tsha256:abc\n"),
            Some("sha256:abc")
        );
    }

    /// Lines that do not carry a `Loaded image[:| ID:]` prefix — status
    /// lines, warnings, unrelated stdout, empty lines — report [`None`]
    /// so `.lines().find_map(...)` skips them without confusing an
    /// arbitrary substring for an image reference.
    #[test]
    fn test_docker_load_image_reference_rejects_non_load_lines() {
        assert_eq!(docker_load_image_reference(""), None);
        assert_eq!(docker_load_image_reference("Loading layer"), None);
        assert_eq!(
            docker_load_image_reference("The image loaded was: nginx:latest"),
            None
        );
        // The `Loaded image` phrase in the middle of a line (not as a
        // prefix) is not a load record; skip it.
        assert_eq!(
            docker_load_image_reference("Note: Loaded image: nginx:latest"),
            None
        );
    }

    /// An empty tail after either prefix reports [`None`] rather than
    /// an empty reference; the downstream `docker tag ""` would
    /// otherwise fail with an opaque error.
    #[test]
    fn test_docker_load_image_reference_empty_tail_is_none() {
        assert_eq!(docker_load_image_reference("Loaded image:"), None);
        assert_eq!(docker_load_image_reference("Loaded image:   "), None);
        assert_eq!(docker_load_image_reference("Loaded image ID:"), None);
        assert_eq!(docker_load_image_reference("Loaded image ID:  \t "), None);
    }

    /// The naïve `line.split(':').last().map(str::trim)` predecessor
    /// returned the wrong tail on both real docker-load shapes; this
    /// test pins the exact strings the primitive rescues from that
    /// bug. Reverting `docker_load_image_reference` to the predecessor
    /// (`line.split(':').last().map(str::trim)` applied to a
    /// prefix-matched line) would fail every assertion here.
    #[test]
    fn test_docker_load_image_reference_regression_pins() {
        // Tagged load — predecessor returned "latest", losing "nginx:".
        assert_eq!(
            docker_load_image_reference("Loaded image: nginx:latest"),
            Some("nginx:latest")
        );
        // Registry+port+tag — predecessor returned "1.25", losing the
        // registry, port, and image name.
        assert_eq!(
            docker_load_image_reference(
                "Loaded image: registry.example.com:5000/library/nginx:1.25"
            ),
            Some("registry.example.com:5000/library/nginx:1.25")
        );
        // Untagged load — predecessor returned bare hex, losing the
        // "sha256:" algorithm prefix docker requires as an image ID.
        let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(
            docker_load_image_reference(&format!("Loaded image ID: sha256:{hex}")),
            Some(format!("sha256:{hex}").as_str())
        );
    }

    /// End-to-end shape: a multi-line `docker load` stdout stream
    /// scanned with `.lines().find_map(docker_load_image_reference)`
    /// yields the first loaded image reference and skips unrelated
    /// status lines, mirroring the caller's composition at
    /// `commands/comprehensive_release.rs`.
    #[test]
    fn test_docker_load_image_reference_scans_multiline_stdout() {
        let stdout = "Loading layer [==================================================>]\n\
                      Loaded image: myservice:abc1234\n\
                      Loaded image: myservice-worker:abc1234\n";
        let first = stdout.lines().find_map(docker_load_image_reference);
        assert_eq!(first, Some("myservice:abc1234"));
    }

    /// The canonical `<repo>:<tag>` shape reports the repository up to
    /// but not including the tag colon and the tag after it. Registry
    /// prefix and path prefix are carried into the repository slice
    /// verbatim.
    #[test]
    fn test_image_repository_and_tag_extracts_canonical_split() {
        assert_eq!(
            image_repository_and_tag("nginx:latest"),
            ("nginx", Some("latest"))
        );
        assert_eq!(
            image_repository_and_tag("library/nginx:1.25"),
            ("library/nginx", Some("1.25"))
        );
        assert_eq!(
            image_repository_and_tag("docker.io/library/nginx:1.25"),
            ("docker.io/library/nginx", Some("1.25"))
        );
        assert_eq!(
            image_repository_and_tag("ghcr.io/pleme-io/forge:v0.42.0"),
            ("ghcr.io/pleme-io/forge", Some("v0.42.0"))
        );
    }

    /// A bare reference (no `:` after the final path separator) reports
    /// the whole input as the repository and `None` as the tag; the
    /// naïve `image.rsplit_once(':')` predecessor also returned `None`
    /// on the split for a bare reference, so this axis is unchanged.
    #[test]
    fn test_image_repository_and_tag_bare_reference_has_no_tag() {
        assert_eq!(image_repository_and_tag("nginx"), ("nginx", None));
        assert_eq!(
            image_repository_and_tag("library/nginx"),
            ("library/nginx", None)
        );
        assert_eq!(
            image_repository_and_tag("docker.io/library/nginx"),
            ("docker.io/library/nginx", None)
        );
    }

    /// A `registry:port/name` reference embeds a `:` in the registry
    /// segment; the primitive scopes the tag scan to the final path
    /// component and reports the whole reference as the repository with
    /// `None` as the tag. The naïve `rsplit_once(':')` predecessor
    /// returned `("registry.example.com", "5000/nginx")` on this input,
    /// surfacing a path segment as if it were a tag — the primitive
    /// closes that bug at one site.
    #[test]
    fn test_image_repository_and_tag_registry_port_is_not_a_tag() {
        assert_eq!(
            image_repository_and_tag("registry.example.com:5000/nginx"),
            ("registry.example.com:5000/nginx", None)
        );
        assert_eq!(
            image_repository_and_tag("registry.example.com:5000/library/nginx"),
            ("registry.example.com:5000/library/nginx", None)
        );
        assert_eq!(
            image_repository_and_tag("registry.example.com:5000/nginx:v1"),
            ("registry.example.com:5000/nginx", Some("v1"))
        );
        assert_eq!(
            image_repository_and_tag("registry.example.com:5000/library/nginx:v1"),
            ("registry.example.com:5000/library/nginx", Some("v1"))
        );
    }

    /// A digest-form reference (`name@sha256:hex`) is content-
    /// addressed identity, not a tag; the primitive reports the whole
    /// reference as the repository with `None` as the tag. The naïve
    /// `rsplit_once(':')` predecessor returned `("nginx@sha256", "hex")`
    /// on this input, surfacing the digest hex as if it were a tag —
    /// the primitive closes that bug at one site.
    #[test]
    fn test_image_repository_and_tag_digest_form_has_no_tag() {
        assert_eq!(
            image_repository_and_tag(&format!("nginx@sha256:{D1}")),
            (format!("nginx@sha256:{D1}").as_str(), None)
        );
        assert_eq!(
            image_repository_and_tag(&format!("library/nginx@sha256:{D1}")),
            (format!("library/nginx@sha256:{D1}").as_str(), None)
        );
        assert_eq!(
            image_repository_and_tag(&format!(
                "registry.example.com:5000/library/nginx@sha256:{D1}"
            )),
            (
                format!("registry.example.com:5000/library/nginx@sha256:{D1}").as_str(),
                None,
            )
        );
    }

    /// Degenerate and malformed inputs — empty string, trailing
    /// separators, empty tag after a `:`, empty name before a `:` —
    /// all report the whole input as the repository with `None` as the
    /// tag; the primitive never surfaces an empty tag slice.
    #[test]
    fn test_image_repository_and_tag_degenerate_inputs_have_no_tag() {
        assert_eq!(image_repository_and_tag(""), ("", None));
        assert_eq!(image_repository_and_tag("nginx:"), ("nginx:", None));
        assert_eq!(image_repository_and_tag(":latest"), (":latest", None));
        assert_eq!(image_repository_and_tag("nginx/"), ("nginx/", None));
        assert_eq!(image_repository_and_tag("/nginx"), ("/nginx", None));
    }

    /// The repository half agrees with the tag half — on every input
    /// where the primitive reports `Some(tag)`, the reported repository
    /// slice concatenated with `":"` and the tag reconstructs the
    /// original reference (modulo any `@digest` suffix, which the
    /// primitive does not carry into the repository slice when a tag
    /// is present — the tag/digest split is not roundtrippable through
    /// the two-tuple return by design, matching the semantic of the
    /// sibling [`image_tag`] which strips `@digest` before its scan).
    #[test]
    fn test_image_repository_and_tag_roundtrip_when_no_digest() {
        let cases = [
            "nginx:latest",
            "library/nginx:1.25",
            "docker.io/library/nginx:1.25",
            "ghcr.io/pleme-io/forge:v0.42.0",
            "registry.example.com:5000/nginx:v1",
            "registry.example.com:5000/library/nginx:v1",
        ];
        for input in cases {
            let (repo, tag) = image_repository_and_tag(input);
            let tag = tag.expect("case must have a parseable tag");
            assert_eq!(
                format!("{repo}:{tag}"),
                input,
                "repository+':'+tag must reconstruct the original reference"
            );
        }
    }

    /// [`image_reference`] composes a `<repository>:<tag>` reference
    /// verbatim from its two halves — the canonical bare-registry +
    /// tag-suffix shape used at every non-`commands/status.rs` build /
    /// push / cosign call site in the crate.
    #[test]
    fn test_image_reference_composes_canonical_shape() {
        assert_eq!(image_reference("nginx", "latest"), "nginx:latest");
        assert_eq!(
            image_reference("library/nginx", "1.25"),
            "library/nginx:1.25"
        );
        assert_eq!(
            image_reference("ghcr.io/pleme-io/forge", "v0.42.0"),
            "ghcr.io/pleme-io/forge:v0.42.0"
        );
    }

    /// A `registry:port/name` repository slice carries its own `:`
    /// (the port colon) but not its own tag — [`image_repository_and_tag`]
    /// reports the whole slice as the repository with `None` as the tag.
    /// [`image_reference`] must accept such a slice under its
    /// debug-mode `already carries a tag` check and compose the
    /// `<repository>:<tag>` shape correctly.
    #[test]
    fn test_image_reference_preserves_registry_port_repository_slice() {
        assert_eq!(
            image_reference("registry.example.com:5000/nginx", "v1"),
            "registry.example.com:5000/nginx:v1"
        );
        assert_eq!(
            image_reference("registry.example.com:5000/library/nginx", "v1"),
            "registry.example.com:5000/library/nginx:v1"
        );
    }

    /// The load-bearing algebra law: on every non-degenerate
    /// `(repository, tag)` pair the [`image_repository_and_tag`] parser
    /// handles, feeding the halves through [`image_reference`] and
    /// back through the parser recovers the original pair verbatim.
    /// This is the property that makes the composer the honest
    /// inverse of the parser (theory §III.1 typescape: the compose /
    /// parse pair widens the typed algebra so future canonicalisation
    /// on either half must uphold the roundtrip or fail this test).
    #[test]
    fn test_image_reference_roundtrips_with_image_repository_and_tag() {
        let cases = [
            ("nginx", "latest"),
            ("library/nginx", "1.25"),
            ("docker.io/library/nginx", "1.25"),
            ("ghcr.io/pleme-io/forge", "v0.42.0"),
            ("registry.example.com:5000/nginx", "v1"),
            ("registry.example.com:5000/library/nginx", "v1"),
        ];
        for (repo, tag) in cases {
            let composed = image_reference(repo, tag);
            let parsed = image_repository_and_tag(&composed);
            assert_eq!(
                parsed,
                (repo, Some(tag)),
                "image_reference / image_repository_and_tag roundtrip must be identity on \
                 non-degenerate (repository, tag) pairs; broke on ({repo:?}, {tag:?}) → \
                 composed = {composed:?}, reparsed = {parsed:?}"
            );
        }
    }

    /// Regression pin for the call sites this primitive replaces:
    /// [`image_reference`] must be observationally identical to the
    /// prior hand-rolled `format!("{}:{}", repository, tag)` shape on
    /// every `(repository, tag)` input the crate had in production.
    /// Reverting the impl to something that changed the separator
    /// (e.g. `"/"`, `"::"`) or the order (`format!("{}:{}", tag,
    /// repository)`) would fail this test, catching the drift the
    /// centralised primitive is here to prevent.
    ///
    /// The fixture set spans the full crate-wide call-site surface,
    /// not the six initial migrations alone: the central
    /// `infrastructure/registry.rs` push/manifest helpers, the
    /// `commands/image_release.rs` regctl orchestrator, the
    /// `commands/nix_builder.rs` / `commands/kenshi_agent.rs` YAML
    /// rewriters, the `commands/crossplane.rs` xpkg push, the
    /// `commands/rollback.rs` display line, the `domain/migration.rs`
    /// `MigrationConfig::image_ref` accessor, and the initial
    /// `commands/attestation.rs` / `commands/migrations.rs` /
    /// `commands/product_release.rs` / `commands/rust_service.rs`
    /// sites. Reverting any of them to `format!("{}:{}", …)` would
    /// still parse-and-produce the same string, but the drift-risk
    /// this primitive closes (separator, order, double-tag) applies
    /// per site; the fixture spans them all so a schema-level
    /// regression on `image_reference` is caught at one place.
    #[test]
    fn test_image_reference_matches_prior_format_shape() {
        let inputs = [
            // `commands/attestation.rs`: cosign_image_ref
            ("ghcr.io/pleme-io/forge", "sig-tag"),
            // `commands/migrations.rs`: image for the k8s migration job
            ("ghcr.io/pleme-io/forge/myproduct-api", "amd64-abc1234"),
            // `commands/product_release.rs`: full_tag for `docker tag`
            ("ghcr.io/pleme-io/forge/myproduct-worker", "sha-deadbeef"),
            // `commands/rust_service.rs`: full_tag, image_tag,
            // expected_image
            ("ghcr.io/pleme-io/forge/api", "arm64-latest"),
            ("ghcr.io/pleme-io/forge/api", "linux-latest"),
            ("registry.example.com:5000/library/nginx", "v1.2.3"),
            // `infrastructure/registry.rs::push_tags`,
            // `push_multiarch` (arch tag / arch-latest),
            // `create_manifest_index`: registry + tag both bound at
            // the call site.
            ("ghcr.io/pleme-io/forge/api", "amd64-abc1234"),
            ("ghcr.io/pleme-io/forge/api", "arm64-abc1234"),
            ("ghcr.io/pleme-io/forge/api", "amd64-latest"),
            ("ghcr.io/pleme-io/forge/api", "arm64-latest"),
            ("ghcr.io/pleme-io/forge/api", "latest"),
            // `infrastructure/registry.rs::push_multiarch`: the arch-
            // suffix composed tag routes through the primitive as
            // `image_reference(registry, &format!("{arch}-{suffix}"))`.
            ("ghcr.io/pleme-io/forge/api", "amd64-abc1234"),
            // `commands/image_release.rs::tags_pushed` and its regctl
            // `index create` targets.
            ("ghcr.io/pleme-io/forge/api", "abc1234"),
            ("ghcr.io/pleme-io/forge/api", "latest"),
            // `commands/nix_builder.rs`,
            // `commands/kenshi_agent.rs`: registry+new_tag on YAML
            // rewrite.
            ("ghcr.io/pleme-io/forge/nix-builder", "amd64-abc1234"),
            ("ghcr.io/pleme-io/forge/kenshi-agent", "amd64-abc1234"),
            // `commands/crossplane.rs::function_release` /
            // `configuration_release`: package_ref (trimmed of any
            // trailing `/`) + tag.
            ("ghcr.io/pleme-io/forge/xpkg-fn-foo", "v0.1.0"),
            // `commands/rollback.rs::verify_rollback_candidates`:
            // registry_url + `amd64-{previous_tag}`.
            ("ghcr.io/pleme-io/forge/api", "amd64-prevsha"),
            // `domain/migration.rs::MigrationConfig::image_ref`.
            ("ghcr.io/org/project/myproduct-api", "amd64-abc1234"),
        ];
        for (repo, tag) in inputs {
            let predecessor = format!("{}:{}", repo, tag);
            assert_eq!(
                image_reference(repo, tag),
                predecessor,
                "image_reference drifted from the pre-extraction \
                 `format!(\"{{}}:{{}}\", repository, tag)` shape on input ({repo:?}, {tag:?})"
            );
        }
    }

    /// Regression pin for the two `commands/status.rs` call sites this
    /// primitive replaces: on the three input shapes the naïve
    /// `image_str.rsplit_once(':')` predecessor got wrong, the primitive
    /// must report a repository/tag pair that agrees with [`image_tag`]
    /// (never surfaces the digest hex or a path segment as a tag).
    /// Reverting the impl to plain `image.rsplit_once(':')` would fail
    /// every assertion here.
    #[test]
    fn test_image_repository_and_tag_regression_pins() {
        // Registry port: naïve predecessor returned
        // ("registry.example.com", "5000/nginx"); primitive returns
        // (whole ref, None).
        let (repo, tag) = image_repository_and_tag("registry.example.com:5000/nginx");
        assert_eq!(repo, "registry.example.com:5000/nginx");
        assert_eq!(tag, None);
        assert_eq!(tag, image_tag("registry.example.com:5000/nginx"));

        // Digest form: naïve predecessor returned ("nginx@sha256", "hex");
        // primitive returns (whole ref, None).
        let input = format!("nginx@sha256:{D1}");
        let (repo, tag) = image_repository_and_tag(&input);
        assert_eq!(repo, input.as_str());
        assert_eq!(tag, None);
        assert_eq!(tag, image_tag(&input));

        // Canonical tagged shape (baseline): both predecessor and
        // primitive agree.
        let (repo, tag) = image_repository_and_tag("nginx:latest");
        assert_eq!(repo, "nginx");
        assert_eq!(tag, Some("latest"));
        assert_eq!(tag, image_tag("nginx:latest"));
    }

    /// The canonical `name@sha256:hex` shape reports the parsed
    /// [`ContentDigest`] for every input the naïve tag parsers
    /// silently discard. Registry prefix and path prefix do not
    /// affect the digest scan — the `split_once('@')` reaches the
    /// digest suffix regardless of what came before it.
    #[test]
    fn test_image_digest_extracts_canonical_digest() {
        let expected = ContentDigest::parse(&format!("sha256:{D1}")).unwrap();
        assert_eq!(
            image_digest(&format!("nginx@sha256:{D1}")),
            Some(expected.clone())
        );
        assert_eq!(
            image_digest(&format!("library/nginx@sha256:{D1}")),
            Some(expected.clone())
        );
        assert_eq!(
            image_digest(&format!("docker.io/library/nginx@sha256:{D1}")),
            Some(expected.clone())
        );
        assert_eq!(
            image_digest(&format!(
                "registry.example.com:5000/library/nginx@sha256:{D1}"
            )),
            Some(expected)
        );
    }

    /// A `name:tag@digest` reference carries both a tag and a digest;
    /// [`image_digest`] reports the digest, sibling [`image_tag`]
    /// reports the tag, and they never confuse the two halves.
    #[test]
    fn test_image_digest_with_tag_and_digest_reports_digest() {
        let expected = ContentDigest::parse(&format!("sha256:{D1}")).unwrap();
        assert_eq!(
            image_digest(&format!("nginx:latest@sha256:{D1}")),
            Some(expected.clone())
        );
        assert_eq!(
            image_digest(&format!(
                "registry.example.com:5000/library/nginx:1.25@sha256:{D1}"
            )),
            Some(expected)
        );
        // The tag parser sibling still reports the tag verbatim on
        // the same input — the two halves are independent extractors.
        assert_eq!(
            image_tag(&format!("nginx:latest@sha256:{D1}")),
            Some("latest")
        );
    }

    /// [`image_digest`] validates the digest tail via
    /// [`ContentDigest::parse`], so `sha512` references also parse.
    #[test]
    fn test_image_digest_supports_sha512() {
        let hex = "f".repeat(SHA512_HEX_LEN);
        let expected = ContentDigest::parse(&format!("sha512:{hex}")).unwrap();
        assert_eq!(image_digest(&format!("nginx@sha512:{hex}")), Some(expected));
    }

    /// A bare reference or tagged-only reference carries no `@`; the
    /// primitive reports [`None`] without consulting
    /// [`ContentDigest::parse`].
    #[test]
    fn test_image_digest_reports_none_when_no_at_suffix() {
        assert_eq!(image_digest(""), None);
        assert_eq!(image_digest("nginx"), None);
        assert_eq!(image_digest("library/nginx"), None);
        assert_eq!(image_digest("nginx:latest"), None);
        assert_eq!(image_digest("ghcr.io/pleme-io/forge:v0.42.0"), None);
        assert_eq!(image_digest("registry.example.com:5000/nginx"), None);
        assert_eq!(image_digest("registry.example.com:5000/nginx:v1"), None);
    }

    /// A malformed `@<garbage>` suffix — unsupported algorithm, wrong
    /// hex length, non-lowercase-hex byte, or empty tail — is
    /// discarded at the extraction frontier. The primitive does not
    /// admit an unvalidated digest string into the typed algebra
    /// (theory §III.1 typescape: the digest is a proof-carrying value,
    /// not a slice; theory §V.1 knowable platform: a malformed digest
    /// entering `verify_image_digest_matches` at a distant call site
    /// would silently succeed a string compare on garbage — the
    /// validated `ContentDigest` return type closes that class of
    /// failure at the frontier).
    #[test]
    fn test_image_digest_rejects_malformed_digest_suffix() {
        // Empty tail after `@`: `ContentDigest::parse("")` reports
        // MissingSeparator.
        assert_eq!(image_digest("nginx@"), None);
        // Unsupported algorithm.
        assert_eq!(image_digest(&format!("nginx@md5:{D1}")), None);
        assert_eq!(
            image_digest("nginx@sha1:0123456789abcdef0123456789abcdef01234567"),
            None
        );
        // Wrong hex length for sha256.
        assert_eq!(image_digest(&format!("nginx@sha256:{}", &D1[..60])), None);
        // Uppercase hex — registries emit lowercase.
        assert_eq!(
            image_digest(&format!("nginx@sha256:{}", D1.to_uppercase())),
            None
        );
        // Non-hex byte in the body.
        assert_eq!(image_digest(&format!("nginx@sha256:{}g", &D1[..63])), None);
        // No colon separator inside the tail.
        assert_eq!(image_digest("nginx@sha256abc"), None);
    }

    /// A `@<algo>:<hex>` suffix with no repository component before
    /// the `@` is malformed as an image reference; the primitive
    /// reports [`None`] rather than admitting a headless reference
    /// into the algebra.
    #[test]
    fn test_image_digest_requires_repository_before_at() {
        assert_eq!(image_digest(&format!("@sha256:{D1}")), None);
    }

    /// The load-bearing three-parser coverage law: the reference
    /// grammar `[registry[:port]/][path/]name[:<tag>][@<algo>:<hex>]`
    /// has three fragments after the repository — tag, digest, and
    /// the repository itself — and the parser family covers all of
    /// them without loss. On every non-degenerate input carrying a
    /// tag AND a digest, feeding the input through
    /// [`image_repository_and_tag`] and [`image_digest`] recovers
    /// the (repository, tag, digest) triple; the tag parsers strip
    /// the digest, and the digest parser is agnostic to whether a
    /// tag is present. Future changes to any of the three parsers
    /// that break the independent-extractor invariant are caught by
    /// this test rather than at a distant call site.
    #[test]
    fn test_reference_grammar_parsers_cover_all_fragments() {
        let cases = [
            // (input, expected_repo, expected_tag, expected_digest_body)
            (format!("nginx:latest@sha256:{D1}"), "nginx", "latest", D1),
            (
                format!("library/nginx:1.25@sha256:{D2}"),
                "library/nginx",
                "1.25",
                D2,
            ),
            (
                format!("ghcr.io/pleme-io/forge:v0.42.0@sha256:{D3}"),
                "ghcr.io/pleme-io/forge",
                "v0.42.0",
                D3,
            ),
            (
                format!("registry.example.com:5000/library/nginx:v1@sha256:{D1}"),
                "registry.example.com:5000/library/nginx",
                "v1",
                D1,
            ),
        ];
        for (input, expected_repo, expected_tag, expected_digest_body) in cases {
            let (repo, tag) = image_repository_and_tag(&input);
            let digest = image_digest(&input);
            let expected_digest = ContentDigest::parse(&format!("sha256:{expected_digest_body}"))
                .expect("digest fixture must parse");
            assert_eq!(
                repo, expected_repo,
                "image_repository_and_tag repo mismatch on {input:?}"
            );
            assert_eq!(
                tag,
                Some(expected_tag),
                "image_repository_and_tag tag mismatch on {input:?}"
            );
            assert_eq!(
                digest,
                Some(expected_digest),
                "image_digest mismatch on {input:?}"
            );
        }
    }

    /// The three-parser family agrees on the "no-digest" case: every
    /// input `image_repository_and_tag` handles without a digest
    /// suffix ([`image_repository_and_tag`] returns `(_, _)` and
    /// [`image_digest`] returns [`None`]) — the tag parser is unaware
    /// the digest parser exists, and vice versa. Reverting
    /// [`image_digest`] to also handle tags (or leaking the tag
    /// scan into the digest parser) would fail this test.
    #[test]
    fn test_image_digest_none_when_reference_carries_no_digest() {
        let cases = [
            "nginx",
            "library/nginx",
            "docker.io/library/nginx",
            "nginx:latest",
            "library/nginx:1.25",
            "ghcr.io/pleme-io/forge:v0.42.0",
            "registry.example.com:5000/library/nginx",
            "registry.example.com:5000/library/nginx:v1",
        ];
        for input in cases {
            assert_eq!(
                image_digest(input),
                None,
                "image_digest must report None on tag-only / bare reference {input:?}"
            );
        }
    }
}
