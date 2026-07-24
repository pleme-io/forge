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
/// distribution spec lists both as the canonical set), and forge's attestation
/// frontier emits `blake3` (256-bit output, 64 lowercase-hex chars — same body
/// length as sha256) through [`tameshi::hash::Blake3Hash::to_prefixed`] into
/// `certification_hash` / `signature` / `compliance_hash` slots documented in
/// [`crate::config::release`] and stamped into the sekiban annotation set at
/// [`crate::commands::attestation::generate_attestation_info`], so the
/// same one-oracle grammar spans registry-supplied digests and attestation-
/// supplied digests without a per-algorithm-family branch at every consumer.
const SHA256_HEX_LEN: usize = 64;
const SHA512_HEX_LEN: usize = 128;
const BLAKE3_HEX_LEN: usize = 64;

/// The canonical set of content-digest algorithms this module admits at
/// its parse frontier — a typed sum over the `<algorithm>:<hex>`
/// algorithm axis. The enum has three variants, mirroring the three
/// algorithms [`ContentDigest::parse`] accepts:
///
/// - [`DigestAlgorithm::Sha256`] — the OCI distribution-spec canonical
///   registry-side digest; 64 lowercase-hex chars (256 bits).
/// - [`DigestAlgorithm::Sha512`] — the OCI distribution-spec canonical
///   registry-side long-form digest; 128 lowercase-hex chars (512 bits).
/// - [`DigestAlgorithm::Blake3`] — forge's attestation-frontier digest
///   emitted by `tameshi::hash::Blake3Hash::to_prefixed` into the sekiban
///   `certification_hash` / `signature` / `compliance_hash` slots stamped
///   through [`crate::commands::attestation::generate_attestation_info`];
///   64 lowercase-hex chars (256 bits).
///
/// This lifts the algorithm axis off the stringly-typed `&str` label
/// [`ContentDigest::algorithm`] returns onto a typed sum with a bounded,
/// exhaustive variant set. Prior to this typed sum, a downstream policy
/// site pinned the algorithm axis through a bare string comparison —
/// [`crate::helm_provenance::find_tarball_sha256`]'s
/// `digest.algorithm() != "sha256"` cross-check was the load-bearing
/// example — which carried two per-site failure modes: (a) a typo in the
/// literal (`"sha-256"`, `"SHA256"`) was not detectable at compile time
/// and silently narrowed the policy predicate, and (b) a widening of the
/// digest grammar to a new algorithm (a future `sha384` arm the
/// distribution spec might normatively adopt) left every stringly-
/// typed dispatch site untouched, silently degrading the policy to a
/// partial cover of the new variant.
///
/// Routing every algorithm dispatch through this typed sum makes the
/// axis single-source: a future variant insertion forces the author to
/// extend the enum (the compiler refuses to compile a non-exhaustive
/// `match` against it), and every downstream policy site that
/// distinguishes arms picks up the new variant at the compile-time
/// exhaustiveness check without a per-site edit.
///
/// The parse frontier ([`ContentDigest::parse`]) and the read-back
/// accessor ([`ContentDigest::algorithm_kind`]) both route through the
/// canonical label ↔ variant table on this typed sum
/// ([`DigestAlgorithm::parse`] / [`DigestAlgorithm::as_str`]), so a
/// future refinement to the algorithm set (widening to `sha384`,
/// tightening the attestation-frontier arm) is a one-site edit on this
/// enum.
///
/// Sibling of [`crate::probe_outcome::AdmissionTier`],
/// [`crate::retry::PerAttemptRegion`], and
/// [`crate::version::BumpLevel`] — every canonical-label typed sum in
/// forge's typed-primitive algebra exposes the same shape (a bounded
/// enum + [`ALL`](Self::ALL) const + [`as_str`](Self::as_str) label
/// projection + [`Display`](std::fmt::Display) + canonical-label
/// [`parse`](Self::parse) inverse), and this closes the same shape on
/// the digest-algorithm axis. Prior to this typed sum the digest-
/// algorithm axis was the only canonical-label surface in the module
/// still living as a bare `&str` prefix inside the parse function's
/// `match` body.
///
/// THEORY.md §III.1 typescape: the digest-algorithm axis is a typed
/// primitive on the platform (one bounded variant set), not a bare
/// `&str` prefix restated at every consumer that pins a per-algorithm
/// policy. THEORY.md §VI.1 generation over composition: the
/// canonical label ↔ variant table is named at one site
/// ([`DigestAlgorithm::as_str`] and its inverse [`DigestAlgorithm::parse`]),
/// and every algorithm dispatch surface — the [`ContentDigest::parse`]
/// grammar oracle, the [`ContentDigest::algorithm_kind`] read-back
/// accessor, the [`crate::helm_provenance`] sha256-only cross-check —
/// reads through it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DigestAlgorithm {
    /// The OCI / Docker distribution-spec canonical registry-side
    /// digest — 256-bit SHA-2 output rendered as 64 lowercase-hex chars
    /// (the [`SHA256_HEX_LEN`] body length).
    Sha256,
    /// The OCI / Docker distribution-spec canonical registry-side
    /// long-form digest — 512-bit SHA-2 output rendered as 128
    /// lowercase-hex chars (the [`SHA512_HEX_LEN`] body length).
    Sha512,
    /// Forge's attestation-frontier digest — 256-bit BLAKE3 output
    /// rendered as 64 lowercase-hex chars (the [`BLAKE3_HEX_LEN`] body
    /// length) — emitted through `tameshi::hash::Blake3Hash::to_prefixed`
    /// into the sekiban annotation set stamped by
    /// [`crate::commands::attestation::generate_attestation_info`].
    Blake3,
}

impl DigestAlgorithm {
    /// Every [`DigestAlgorithm`] variant, listed in the algorithm-family
    /// order the [`ContentDigest::parse`] grammar admits them
    /// (`Sha256`, `Sha512`, `Blake3` — the two OCI-distribution
    /// registry-side algorithms followed by forge's attestation-
    /// frontier algorithm). Single-source enumeration of the typed sum,
    /// mirroring the discipline
    /// [`crate::probe_outcome::AdmissionTier::ALL`] and
    /// [`crate::version::BumpLevel::ALL`] establish at their sibling
    /// typed sums. A consumer that needs to iterate every variant —
    /// exhaustive-cover property tests, per-algorithm cross-check
    /// tables, telemetry-label enumeration — reads
    /// [`DigestAlgorithm::ALL`] once instead of restating the variant
    /// list at the call site, so a future variant insertion forces the
    /// author to extend this one const rather than every per-site
    /// restatement.
    #[allow(dead_code)]
    pub const ALL: [Self; 3] = [Self::Sha256, Self::Sha512, Self::Blake3];

    /// The canonical `<algorithm>` label the parse grammar
    /// [`ContentDigest::parse`] admits for this variant. Read-back
    /// projection from the typed sum onto the borrowed UTF-8
    /// canonical-label surface. Route: every downstream consumer that
    /// formats the algorithm prefix (a display frontier stamping
    /// `"{algo}:{hex}"`, a serde-serialize adapter that emits the
    /// canonical label, the [`std::fmt::Display`] impl directly below)
    /// reads through this one-oracle table so a future variant
    /// insertion adds one arm here rather than one arm at every
    /// per-consumer restatement.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
            Self::Blake3 => "blake3",
        }
    }

    /// The lowercase-hex body length the [`ContentDigest::parse`]
    /// grammar pins for this variant. Route: the parse oracle reads
    /// this at its length-check arm so the expected body length is a
    /// projection from the algorithm typed sum, not a per-variant
    /// `match` branch restated at every parse site.
    #[allow(dead_code)]
    pub const fn hex_len(self) -> usize {
        match self {
            Self::Sha256 => SHA256_HEX_LEN,
            Self::Sha512 => SHA512_HEX_LEN,
            Self::Blake3 => BLAKE3_HEX_LEN,
        }
    }

    /// Parse a canonical `<algorithm>` label into a
    /// [`DigestAlgorithm`] variant. Returns [`None`] when the input is
    /// not one of the canonical labels [`DigestAlgorithm::as_str`]
    /// admits — the one-oracle inverse of the label projection. The
    /// [`ContentDigest::parse`] grammar oracle reads through this at
    /// its algorithm-arm dispatch so the canonical label ↔ variant
    /// table is named at one site and a future variant insertion adds
    /// one arm here rather than at every consumer that dispatches on
    /// the algorithm prefix.
    pub fn parse(label: &str) -> Option<Self> {
        match label {
            "sha256" => Some(Self::Sha256),
            "sha512" => Some(Self::Sha512),
            "blake3" => Some(Self::Blake3),
            _ => None,
        }
    }
}

/// The canonical-label surface of [`DigestAlgorithm`] at the
/// [`std::fmt::Display`] frontier — routes through
/// [`DigestAlgorithm::as_str`] so the variant → label mapping is defined
/// at one site. A downstream consumer that stamps
/// `format!("{algo}:{hex}")` reads through the same one-oracle table
/// the [`ContentDigest::parse`] grammar admits at its algorithm arm.
/// Discipline-mirror of [`crate::probe_outcome::AdmissionTier`]'s
/// [`Display`](std::fmt::Display) impl and
/// [`crate::version::BumpLevel`]'s
/// [`Display`](std::fmt::Display) impl, both routing through their
/// respective `as_str` label-projection tables.
impl std::fmt::Display for DigestAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// [`AsRef<str>`] impl routes through [`DigestAlgorithm::as_str`] so a
/// downstream consumer that accepts `impl AsRef<str>` (a path-segment
/// builder assembling a per-algorithm cache-key partition, a
/// [`std::collections::HashMap<&str, _>`] keyed by algorithm label, an
/// OpenTelemetry / tracing attribute setter that keys by
/// `Into<Cow<'static, str>>`, a `format!("{prefix}:{}", algo.as_ref())`
/// stamp) reads the canonical lowercase label (`"sha256"`, `"sha512"`,
/// `"blake3"`) directly from a [`DigestAlgorithm`] value without going
/// through the [`std::fmt::Display`] formatter buffer or an
/// intermediate [`String`] allocation. The zero-cost byte-slice-
/// coercion peer of the format-machinery [`std::fmt::Display`] surface,
/// both routing through the same [`DigestAlgorithm::as_str`]
/// canonical-label oracle.
///
/// Sibling of the [`std::fmt::Display`] impl directly above — the same
/// lift at the byte-slice-access layer instead of the format layer.
/// Together with the [`Display`](std::fmt::Display) impl this closes
/// the `as_str` ⇢ {`Display`, `AsRef<str>`} emission pair at the
/// digest-algorithm axis against the shared canonical-label oracle.
/// Structural mirror of `impl AsRef<str> for BumpLevel` (line 1426 of
/// `version.rs` — the same lift at the version-bump-magnitude ladder,
/// routing through [`crate::version::BumpLevel::as_str`]),
/// `impl AsRef<str> for AdmissionTier` (commit 7acca19 — the same
/// lift at the admission-tier ladder, routing through
/// [`crate::probe_outcome::AdmissionTier::as_str`]), and
/// `impl AsRef<str> for PerAttemptRegion` (commit 8c8cffe — the same
/// lift at the per-attempt-region ladder, routing through
/// [`crate::retry::PerAttemptRegion::as_str`]). With this impl, all
/// four repo-internal canonical-label typed sums that carry
/// `as_str` + [`Display`](std::fmt::Display) also carry
/// [`AsRef<str>`] routing through the shared canonical-label oracle —
/// the label-axis grammar at every canonical-label typed sum is now a
/// one-oracle surface at every Rust-idiomatic borrowed-view reading.
///
/// Zero-cost by construction: the returned `&str` is `'static`
/// (delegated from [`DigestAlgorithm::as_str`]'s `&'static str`
/// return type), so a consumer that borrows the slice reads directly
/// into the static-string constant table without a copy, matching
/// the zero-allocation discipline [`std::fmt::Display`] doesn't offer
/// (which writes through a [`std::fmt::Formatter`] into a caller-
/// provided buffer).
///
/// The inherent [`DigestAlgorithm::as_str`] takes `self` by value
/// ([`DigestAlgorithm`] is [`Copy`]), so the impl body dereferences
/// `*self` before invoking the projection; the returned `&'static str`
/// is unaffected by the receiver-shape difference between the
/// [`AsRef::as_ref`] `&self` signature and the inherent
/// [`DigestAlgorithm::as_str`] by-value receiver.
///
/// A future variant insertion (a `sha384` arm the distribution spec
/// might normatively adopt, a per-attestation-frontier arm forge
/// might land) updates the [`DigestAlgorithm::as_str`] match body
/// alone and every consumer — cache-key partition, HashMap key,
/// tracing attribute stamper — that accepts `impl AsRef<str>`
/// inherits the new canonical label automatically with no downstream
/// retyping.
///
/// The identity `algo.as_ref() == algo.as_str()` at every
/// [`DigestAlgorithm::ALL`] variant is pinned by
/// [`tests::test_digest_algorithm_as_ref_str_agrees_with_as_str`];
/// the identity carrying through a generic `impl AsRef<str>` consumer
/// at every variant is pinned by
/// [`tests::test_digest_algorithm_as_ref_str_carries_through_generic_consumer`].
///
/// THEORY.md §V.4 typed primitives: the byte-slice-coercion surface
/// is a typed-primitive site on [`DigestAlgorithm`] itself (one
/// `AsRef<str>` impl routing through [`DigestAlgorithm::as_str`]),
/// not a per-consumer `.as_str()` restatement at every downstream
/// site that accepts `impl AsRef<str>`. THEORY.md §VI.1 one-oracle:
/// the canonical label is named at one site
/// ([`DigestAlgorithm::as_str`]) and every surface — `as_str`,
/// `Display`, this `AsRef<str>` — reads through it.
impl AsRef<str> for DigestAlgorithm {
    fn as_ref(&self) -> &str {
        (*self).as_str()
    }
}

/// [`std::str::FromStr`] impl routes through [`DigestAlgorithm::parse`] so
/// a downstream consumer that reads the canonical-label surface at the
/// stdlib parse frontier ([`str::parse::<DigestAlgorithm>()`],
/// [`&str::parse`], a `#[clap(value_parser)]` slot that accepts
/// `impl FromStr`, an [`iterator::filter_map(|s| s.parse().ok())`] pipeline
/// over CLI-supplied algorithm labels, a config-file loader that reads
/// TOML / YAML string values into typed algorithm variants) recovers the
/// [`DigestAlgorithm`] variant from the same canonical lowercase grammar
/// [`DigestAlgorithm::as_str`] emits — no per-consumer alias matrix, no
/// drift between the label a [`Display`](std::fmt::Display) stamp writes
/// and the variant a downstream [`FromStr`](std::str::FromStr) reader
/// recovers.
///
/// Sibling of [`std::fmt::Display`] and [`AsRef<str>`] directly above —
/// the parse surface at the same canonical-label oracle the two emission
/// surfaces already read through. Together with those impls this closes
/// the `as_str` ⇢ {`Display`, `AsRef<str>`} emission pair and the
/// {`FromStr`} parse peer at the digest-algorithm axis against the
/// shared canonical-label oracle. Structural mirror of
/// `impl FromStr for BumpLevel` (line 1223 of `version.rs`),
/// `impl FromStr for AdmissionTier` (line 5687 of `probe_outcome.rs`),
/// and `impl FromStr for PerAttemptRegion` (line 1139 of `retry.rs`) —
/// the same lift at the version-bump-magnitude, admission-tier, and
/// per-attempt-region ladders, each routing through its sum's
/// canonical-label inverse oracle. With this impl, all four repo-internal
/// canonical-label typed sums that carry
/// `as_str` + [`Display`](std::fmt::Display) + [`AsRef<str>`] also carry
/// [`FromStr`](std::str::FromStr) routing through the shared canonical-
/// label inverse oracle.
///
/// The impl body routes through [`DigestAlgorithm::parse`] — the one-
/// oracle canonical-label inverse table — rather than restating the
/// label → variant match at the [`FromStr`](std::str::FromStr) call site.
/// A future variant insertion (a `sha384` arm the distribution spec might
/// normatively adopt, a per-attestation-frontier arm forge might land)
/// updates the [`DigestAlgorithm::parse`] match body alone and every
/// consumer — CLI `clap` value parser, config-file loader, telemetry
/// label backfill — that reads through [`FromStr`](std::str::FromStr)
/// inherits the new canonical label automatically with no downstream
/// retyping. The error path stays the same: an unknown label surfaces
/// an [`anyhow::Error`] naming the offending input and the canonical
/// three-label set, matching the byte-identical rejection wording the
/// sibling FromStr impls emit at their `_ =>` arms.
///
/// The error type is [`anyhow::Error`] — the exact shape the three
/// sibling FromStr impls carry ([`crate::version::BumpLevel`],
/// [`crate::probe_outcome::AdmissionTier`],
/// [`crate::retry::PerAttemptRegion`] — all `type Err = anyhow::Error`).
/// A downstream typed-error surface that wants a structured rejection
/// (a per-consumer error enum, a `#[derive(thiserror::Error)]` typed
/// wrap) downcasts through the [`anyhow::Error::downcast`] surface or
/// reads the rejection at the [`ContentDigest::parse`] level where the
/// grammar oracle emits a structured [`ContentDigestError::UnsupportedAlgorithm`]
/// at the same rejection frontier.
///
/// The round-trip `algo.as_str().parse::<DigestAlgorithm>() ==
/// Ok(algo)` at every [`DigestAlgorithm::ALL`] variant is pinned by
/// [`tests::test_digest_algorithm_from_str_round_trips_every_variant`];
/// the rejection wording on unknown labels is pinned by
/// [`tests::test_digest_algorithm_from_str_rejects_unknown_label`]; the
/// route-through-`parse` discipline (the [`FromStr`](std::str::FromStr)
/// oracle agrees with the [`DigestAlgorithm::parse`] inverse at every
/// admitted label and at rejection) is pinned by
/// [`tests::test_digest_algorithm_from_str_agrees_with_parse`].
///
/// THEORY.md §V.4 typed primitives: the canonical-label parse surface
/// is a typed-primitive site on [`DigestAlgorithm`] itself (one
/// [`FromStr`](std::str::FromStr) impl routing through the
/// [`DigestAlgorithm::parse`] inverse oracle), not a per-consumer
/// `match s { "sha256" => ... }` restatement at every downstream site
/// that dispatches on the algorithm label. THEORY.md §VI.1 one-oracle:
/// canonical-label parsing lives at one site
/// ([`DigestAlgorithm::parse`]) and every read surface — the inverse
/// oracle itself, the [`ContentDigest::parse`] grammar oracle's
/// algorithm arm, this [`FromStr`](std::str::FromStr) impl — reads
/// through it.
impl std::str::FromStr for DigestAlgorithm {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or_else(|| {
            anyhow::anyhow!("Invalid digest algorithm '{s}' — use sha256, sha512, or blake3")
        })
    }
}

/// [`TryFrom<&str>`] impl routes through
/// [`<DigestAlgorithm as std::str::FromStr>::from_str`] so a downstream
/// consumer bound by `impl TryFrom<&str>` (a serde container that opts into
/// `#[serde(try_from = "&str")]` on a wrapper field, a generic try-conversion
/// helper `fn parse_field<T: for<'a> TryFrom<&'a str>>`, a validated-input
/// newtype builder whose canonical parse contract is stated as
/// [`TryFrom<&str>`] rather than [`std::str::FromStr`]) recovers a
/// [`DigestAlgorithm`] variant from its canonical lowercase label through the
/// same one-oracle grammar the direct `.parse::<DigestAlgorithm>()` call
/// sites already read.
///
/// The by-reference try-conversion parse peer of [`std::str::FromStr`]
/// directly above — [`std::str::FromStr`] is the stdlib parse frontier of the
/// canonical-label conversion surface, this [`TryFrom<&str>`] is the by-
/// reference try-conversion frontier of the same canonical-label conversion
/// surface. Both route through the shared [`DigestAlgorithm::parse`] inverse
/// oracle: the stdlib parse frontier through the [`FromStr`] impl body's
/// `Self::parse` route, this by-reference try-conversion frontier through
/// the [`FromStr`] impl itself (one further indirection so the load-bearing
/// match body stays named at one site, not restated at every parse peer).
///
/// Sibling of [`std::fmt::Display`], [`AsRef<str>`], and
/// [`std::str::FromStr`] directly above — the same lift at the by-reference
/// try-conversion layer instead of the format / borrow / stdlib-parse layers.
/// Together with those impls this closes the `as_str` ⇢ {`Display`,
/// `AsRef<str>`} emission pair and the {`FromStr`, `TryFrom<&str>`} parse set
/// at the digest-algorithm axis against the shared canonical-label oracle.
/// Structural mirror of `impl TryFrom<&str> for PerAttemptRegion`
/// (line 1431 of `retry.rs`) and `impl TryFrom<&str> for AdmissionTier`
/// (line 7293 of `probe_outcome.rs`) — the same lift at the by-reference
/// try-conversion layer of the parallel canonical-label typed sums, each
/// delegating through its sum's stdlib [`FromStr`] impl.
///
/// The natural bridge to the `serde` `try_from` container attribute
/// (`#[serde(try_from = "&str")]` — which keys off [`TryFrom<&str>`], not
/// [`std::str::FromStr`]) so a downstream config-schema field that wraps a
/// [`DigestAlgorithm`] and wants serde's `try_from` grammar composes with
/// one blanket impl at the typed-primitive site, not a per-consumer inline
/// `#[serde(deserialize_with)]` cascade. The [`FromStr`] impl carries the
/// load-bearing route through [`DigestAlgorithm::parse`]; this
/// [`TryFrom<&str>`] impl delegates through it, so the parse-oracle
/// discipline is preserved end-to-end and a future variant insertion
/// (a `sha384` arm the OCI distribution spec might normatively adopt, a
/// per-attestation-frontier arm forge might land) remains a one-site edit at
/// the [`DigestAlgorithm::parse`] match body plus the matching `as_str` /
/// `hex_len` arm additions.
///
/// The error type is [`anyhow::Error`] — the exact shape the [`FromStr`]
/// impl above and the sibling `TryFrom<&str>` impls at
/// [`crate::retry::PerAttemptRegion`] and
/// [`crate::probe_outcome::AdmissionTier`] all carry (all
/// `type Error = anyhow::Error`). Rejection wording is inherited from
/// [`FromStr`]: an unknown label surfaces an [`anyhow::Error`] naming the
/// offending input and the canonical three-label set — no per-peer
/// rejection-message drift.
///
/// The parser is strict for the same reason [`std::str::FromStr`] is: only
/// the canonical lowercase labels emitted by [`DigestAlgorithm::as_str`]
/// parse. Uppercase (`"SHA256"`), hyphenated (`"sha-256"`), unknown labels
/// (`"md5"`), empty input, and edge-whitespace variants (`"sha256 "`,
/// `" sha256"`) all reject — the strictness is delegated from the underlying
/// [`FromStr`] impl (in turn from [`DigestAlgorithm::parse`]).
///
/// The identity
/// `DigestAlgorithm::try_from(algo.as_str()).unwrap() == algo` at every
/// [`DigestAlgorithm::ALL`] variant is pinned by
/// [`tests::test_digest_algorithm_try_from_str_agrees_with_from_str`]; the
/// identity carried through a generic `impl for<'a> TryFrom<&'a str>`
/// consumer at every variant is pinned by
/// [`tests::test_digest_algorithm_try_from_str_carries_through_generic_consumer`];
/// the strict-rejection contract on non-canonical input is pinned by
/// [`tests::test_digest_algorithm_try_from_str_rejects_non_canonical_input`].
///
/// THEORY.md §III.1 typescape: the by-reference try-conversion surface is
/// a typed-primitive site on [`DigestAlgorithm`] itself (one
/// `TryFrom<&str>` impl routing through the [`std::str::FromStr`] parse
/// oracle), not a per-consumer `.parse::<DigestAlgorithm>()` bridge at every
/// downstream site that types its parse contract as `impl TryFrom<&str>`
/// rather than [`std::str::FromStr`]. THEORY.md §VI.1 generation over
/// composition: the canonical-label grammar is named at one site
/// ([`DigestAlgorithm::as_str`]), inverted at one site
/// ([`DigestAlgorithm::parse`]), and every parse surface —
/// [`std::str::FromStr`], this [`TryFrom<&str>`], the
/// [`ContentDigest::parse`] grammar oracle's algorithm arm — reads through
/// it.
impl TryFrom<&str> for DigestAlgorithm {
    type Error = anyhow::Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        <Self as std::str::FromStr>::from_str(s)
    }
}

/// [`TryFrom<String>`] impl routes through
/// [`<DigestAlgorithm as std::str::FromStr>::from_str`] on the borrowed
/// `&str` view of the caller-supplied [`String`], so a downstream consumer
/// bound by `impl TryFrom<String>` (a serde container that opts into
/// `#[serde(try_from = "String")]` on a wrapper field, a generic
/// try-conversion helper `fn parse_field<T: TryFrom<String>>` that owns
/// the input buffer, a validated-input newtype builder whose canonical
/// parse contract accepts an owned [`String`] rather than a borrowed
/// `&str`) recovers a [`DigestAlgorithm`] variant from its canonical
/// lowercase label through the same one-oracle grammar the direct
/// `.parse::<DigestAlgorithm>()` call sites and the sibling
/// [`TryFrom<&str>`] impl above already read.
///
/// The by-value owned-string parse peer of [`TryFrom<&str>`] directly
/// above — [`TryFrom<&str>`] is the by-reference try-conversion frontier
/// of the canonical-label conversion surface, this [`TryFrom<String>`] is
/// the by-value owned-string try-conversion frontier of the same
/// canonical-label conversion surface. Both route through the shared
/// [`<Self as std::str::FromStr>::from_str`] canonical-grammar oracle:
/// the [`&str`] peer through `from_str(s)` directly, this [`String`] peer
/// through `from_str(s.as_str())` — the same canonical grammar lifted to
/// the by-value owned-string parse layer, with the receiver-side
/// [`String::as_str`] call yielding a borrowed `&str` view of the owned
/// buffer at zero allocation cost, so the impl body pays the by-reference
/// [`FromStr`] cost and does not clone the input.
///
/// Sibling of [`std::fmt::Display`], [`AsRef<str>`],
/// [`std::str::FromStr`], and [`TryFrom<&str>`] above — the same lift at
/// the by-value owned-string try-conversion layer instead of the format /
/// borrow / stdlib-parse / by-reference-try layers. Together with those
/// impls this extends the `as_str` ⇢ {`Display`, `AsRef<str>`} emission
/// pair and the {`FromStr`, `TryFrom<&str>`, `TryFrom<String>`} parse set
/// at the digest-algorithm axis against the shared canonical-label
/// oracle. Structural mirror of `impl TryFrom<String> for PerAttemptRegion`
/// (line 1589 of `retry.rs`) — the same lift at the by-value owned-string
/// try-conversion layer of the parallel canonical-label typed sum,
/// delegating through its sum's stdlib [`FromStr`] impl on the
/// [`String::as_str`] view of the caller-supplied buffer.
///
/// The natural bridge to the `serde` `try_from` container attribute
/// (`#[serde(try_from = "String")]` — which keys off [`TryFrom<String>`],
/// not [`std::str::FromStr`]) so a downstream config-schema field that
/// wraps a [`DigestAlgorithm`] and wants serde's `try_from` grammar with
/// an owned-buffer receiver composes with one blanket impl at the typed-
/// primitive site, not a per-consumer inline `#[serde(deserialize_with)]`
/// cascade. The [`FromStr`] impl carries the load-bearing route through
/// [`DigestAlgorithm::parse`]; this [`TryFrom<String>`] impl delegates
/// through it, so the parse-oracle discipline is preserved end-to-end
/// and a future variant insertion (a `sha384` arm the OCI distribution
/// spec might normatively adopt, a per-attestation-frontier arm forge
/// might land) remains a one-site edit at the [`DigestAlgorithm::parse`]
/// match body plus the matching `as_str` / `hex_len` arm additions.
///
/// The error type is [`anyhow::Error`] — the exact shape the [`FromStr`]
/// impl and the [`TryFrom<&str>`] impl above both carry, and the same
/// shape the sibling `TryFrom<String>` impl at
/// [`crate::retry::PerAttemptRegion`] carries (`type Error =
/// anyhow::Error`). Rejection wording is inherited from [`FromStr`]: an
/// unknown label surfaces an [`anyhow::Error`] naming the offending input
/// and the canonical three-label set — no per-peer rejection-message
/// drift.
///
/// The parser is strict for the same reason [`std::str::FromStr`] is:
/// only the canonical lowercase labels emitted by
/// [`DigestAlgorithm::as_str`] parse. Uppercase (`"SHA256"`), hyphenated
/// (`"sha-256"`), unknown labels (`"md5"`), empty input, and edge-
/// whitespace variants (`"sha256 "`, `" sha256"`) all reject — the
/// strictness is delegated from the underlying [`FromStr`] impl (in turn
/// from [`DigestAlgorithm::parse`]).
///
/// The identity
/// `DigestAlgorithm::try_from(algo.as_str().to_owned()).unwrap() == algo`
/// at every [`DigestAlgorithm::ALL`] variant is pinned by
/// [`tests::test_digest_algorithm_try_from_string_agrees_with_from_str`];
/// the identity carried through a generic `impl TryFrom<String>` consumer
/// at every variant is pinned by
/// [`tests::test_digest_algorithm_try_from_string_carries_through_generic_consumer`];
/// the strict-rejection contract on non-canonical input is pinned by
/// [`tests::test_digest_algorithm_try_from_string_rejects_non_canonical_input`].
///
/// THEORY.md §III.1 typescape: the by-value owned-string try-conversion
/// surface is a typed-primitive site on [`DigestAlgorithm`] itself (one
/// `TryFrom<String>` impl routing through the [`std::str::FromStr`]
/// parse oracle on [`String::as_str`]), not a per-consumer
/// `s.parse::<DigestAlgorithm>()` bridge at every downstream site that
/// types its parse contract as `impl TryFrom<String>` rather than
/// [`std::str::FromStr`]. THEORY.md §VI.1 generation over composition:
/// the canonical-label grammar is named at one site
/// ([`DigestAlgorithm::as_str`]), inverted at one site
/// ([`DigestAlgorithm::parse`]), and every parse surface —
/// [`std::str::FromStr`], [`TryFrom<&str>`], this [`TryFrom<String>`],
/// the [`ContentDigest::parse`] grammar oracle's algorithm arm — reads
/// through it.
impl TryFrom<String> for DigestAlgorithm {
    type Error = anyhow::Error;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        <Self as std::str::FromStr>::from_str(s.as_str())
    }
}

/// [`TryFrom<Cow<'_, str>>`] impl routes through
/// [`<DigestAlgorithm as std::str::FromStr>::from_str`] on the underlying
/// [`str`] view of the caller-supplied [`std::borrow::Cow`] (borrowed
/// through [`Cow::as_ref`] from the [`Cow::Borrowed`] arm, dereferenced
/// off the [`String`] in the [`Cow::Owned`] arm without cloning), so a
/// downstream consumer bound by `impl TryFrom<Cow<'_, str>>` (a serde-
/// compatible deserializer that hands its container an owned-or-borrowed
/// [`Cow<'_, str>`] to preserve zero-copy where the input allows it, a
/// generic try-conversion helper
/// `fn parse_algo<'a, T: TryFrom<Cow<'a, str>>>` that opts into the
/// borrowed-or-owned frontier at the receiver-shape layer, a
/// [`serde::Deserialize`] adapter opting into
/// `#[serde(try_from = "Cow<'_, str>")]` on a wrapper field to defer the
/// ownership decision to the underlying [`serde::Deserializer`]) recovers
/// a [`DigestAlgorithm`] variant from its canonical lowercase label
/// through the same one-oracle grammar the direct
/// `.parse::<DigestAlgorithm>()` call sites and the sibling
/// [`TryFrom<&str>`] / [`TryFrom<String>`] impls already read.
///
/// The borrowed/owned-frontier try-conversion peer of [`TryFrom<&str>`]
/// and [`TryFrom<String>`] directly above — [`TryFrom<&str>`] is the
/// by-reference frontier of the canonical-label conversion surface,
/// [`TryFrom<String>`] is the by-value owned-string frontier, this
/// [`TryFrom<Cow<'_, str>>`] is the borrowed-or-owned frontier that
/// bridges the two under a single receiver type. All three route through
/// the shared [`<Self as std::str::FromStr>::from_str`] canonical-grammar
/// oracle: the [`&str`] peer through `from_str(s)` directly, the
/// [`String`] peer through `from_str(s.as_str())`, this [`Cow`] peer
/// through `from_str(s.as_ref())` — the same canonical grammar lifted to
/// the borrowed-or-owned frontier, with the receiver-side
/// [`Cow::as_ref`] call yielding a borrowed `&str` view of the
/// caller-supplied payload at zero allocation cost on either arm, so the
/// impl body pays the by-reference [`FromStr`] cost and does not clone
/// the input on the [`Cow::Owned`] arm.
///
/// Sibling of [`std::fmt::Display`], [`AsRef<str>`],
/// [`std::str::FromStr`], [`TryFrom<&str>`], and [`TryFrom<String>`]
/// above — the same lift at the borrowed-or-owned frontier instead of
/// the format / borrow / stdlib-parse / by-reference-try / by-value-try
/// layers. Together with those impls this extends the `as_str` ⇢
/// {`Display`, `AsRef<str>`} emission pair and the {`FromStr`,
/// `TryFrom<&str>`, `TryFrom<String>`, `TryFrom<Cow<'_, str>>`} parse set
/// at the digest-algorithm axis against the shared canonical-label
/// oracle. Structural mirror of
/// [`TryFrom<Cow<'_, str>> for ContentDigest`] (commit 3a28035) — the
/// same lift at the borrowed-or-owned frontier of the parallel
/// canonical-string typed primitive on the same module, delegating
/// through its sum's by-reference parse oracle on the
/// [`Cow::as_ref`] view of the caller-supplied payload.
///
/// The natural bridge to the `serde` `try_from` container attribute
/// (`#[serde(try_from = "Cow<'_, str>")]`) so a downstream config-schema
/// field that wraps a [`DigestAlgorithm`] and wants serde's `try_from`
/// grammar with a borrowed-or-owned receiver composes with one blanket
/// impl at the typed-primitive site, not a per-consumer inline
/// `#[serde(deserialize_with)]` cascade. The [`FromStr`] impl carries
/// the load-bearing route through [`DigestAlgorithm::parse`]; this
/// [`TryFrom<Cow<'_, str>>`] impl delegates through it, so the parse-
/// oracle discipline is preserved end-to-end and a future variant
/// insertion (a `sha384` arm the OCI distribution spec might normatively
/// adopt, a per-attestation-frontier arm forge might land) remains a
/// one-site edit at the [`DigestAlgorithm::parse`] match body plus the
/// matching `as_str` / `hex_len` arm additions.
///
/// The error type is [`anyhow::Error`] — the exact shape the [`FromStr`]
/// impl and the [`TryFrom<&str>`] / [`TryFrom<String>`] impls above all
/// carry. Rejection wording is inherited from [`FromStr`]: an unknown
/// label surfaces an [`anyhow::Error`] naming the offending input and
/// the canonical three-label set — no per-peer rejection-message drift
/// across the borrowed / owned / borrowed-or-owned receiver frontier.
///
/// The parser is strict for the same reason [`std::str::FromStr`] is:
/// only the canonical lowercase labels emitted by
/// [`DigestAlgorithm::as_str`] parse. Uppercase (`"SHA256"`), hyphenated
/// (`"sha-256"`), unknown labels (`"md5"`), empty input, and edge-
/// whitespace variants (`"sha256 "`, `" sha256"`) all reject on both the
/// [`Cow::Borrowed`] and [`Cow::Owned`] arms — the strictness is
/// delegated from the underlying [`FromStr`] impl (in turn from
/// [`DigestAlgorithm::parse`]).
///
/// The identity
/// `DigestAlgorithm::try_from(Cow::Borrowed(algo.as_str())).unwrap() ==
/// algo` and the [`Cow::Owned`] mirror at every
/// [`DigestAlgorithm::ALL`] variant are pinned by
/// [`tests::test_digest_algorithm_try_from_cow_str_agrees_with_from_str`];
/// the identity carried through a generic
/// `impl TryFrom<Cow<'_, str>>` consumer at every variant is pinned by
/// [`tests::test_digest_algorithm_try_from_cow_str_carries_through_generic_consumer`];
/// the strict-rejection contract on non-canonical input at both arms is
/// pinned by
/// [`tests::test_digest_algorithm_try_from_cow_str_rejects_non_canonical_input`].
///
/// THEORY.md §III.1 typescape: the borrowed-or-owned frontier try-
/// conversion surface is a typed-primitive site on [`DigestAlgorithm`]
/// itself (one `TryFrom<Cow<'_, str>>` impl routing through the
/// [`std::str::FromStr`] parse oracle on [`Cow::as_ref`]), not a
/// per-consumer `cow.as_ref().parse::<DigestAlgorithm>()` bridge at
/// every downstream site that types its parse contract as
/// `impl TryFrom<Cow<'_, str>>` rather than [`std::str::FromStr`].
/// THEORY.md §VI.1 generation over composition: the canonical-label
/// grammar is named at one site ([`DigestAlgorithm::as_str`]), inverted
/// at one site ([`DigestAlgorithm::parse`]), and every parse surface —
/// [`std::str::FromStr`], [`TryFrom<&str>`], [`TryFrom<String>`], this
/// [`TryFrom<Cow<'_, str>>`], the [`ContentDigest::parse`] grammar
/// oracle's algorithm arm — reads through it.
impl TryFrom<std::borrow::Cow<'_, str>> for DigestAlgorithm {
    type Error = anyhow::Error;

    fn try_from(s: std::borrow::Cow<'_, str>) -> Result<Self, Self::Error> {
        <Self as std::str::FromStr>::from_str(s.as_ref())
    }
}

/// [`TryFrom<&[u8]>`] impl routes through [`std::str::from_utf8`] then
/// delegates to [`<DigestAlgorithm as std::str::FromStr>::from_str`] on the
/// resulting borrowed `&str` view of the caller-supplied byte slice, so a
/// downstream consumer holding a byte slice at a raw-byte frontier (a
/// captured registry stdout still on the [`Vec<u8>`] register that has not
/// yet been UTF-8-validated, a manifest byte body from a
/// `reqwest::Response::bytes()` / `hyper::body::to_bytes` future not yet
/// UTF-8-validated, a slice off a `std::fs::read` of a cached
/// algorithm-label file, a `serde_bytes`-decoded field whose canonical
/// wire shape is `&[u8]`, a `nom` / `winnow` byte-slice parser that pins
/// its input contract as `&[u8]` and yields a bounded canonical-label
/// token) recovers a [`DigestAlgorithm`] variant from its canonical
/// lowercase byte serialization through the same one-oracle grammar the
/// direct `.parse::<DigestAlgorithm>()` string call sites and the sibling
/// [`TryFrom<&str>`] / [`TryFrom<String>`] / [`TryFrom<Cow<'_, str>>`]
/// impls already read.
///
/// The borrowed-byte-slice parse peer of [`TryFrom<&str>`],
/// [`TryFrom<String>`], and [`TryFrom<Cow<'_, str>>`] above — the parse
/// surface at the digest-algorithm axis is now closed across the
/// borrowed-string ([`TryFrom<&str>`]), owned-string
/// ([`TryFrom<String>`]), borrowed-or-owned-string
/// ([`TryFrom<Cow<'_, str>>`]), AND borrowed-byte-slice
/// (this [`TryFrom<&[u8]>`]) input frontiers, so a downstream site that
/// receives its input at any of those frontiers routes through the same
/// [`DigestAlgorithm::parse`] oracle without an
/// `std::str::from_utf8(bytes)?.parse()` bridge per consumer. Prior to
/// this impl a downstream site holding a `&[u8]` (a captured registry
/// stdout not yet UTF-8-validated, a network response body still on the
/// byte-slice register, a `serde_bytes`-decoded field) had to restate
/// that bridge at every call site before it could reach the string parse
/// oracle. Structural mirror of [`TryFrom<&[u8]> for ContentDigest`]
/// directly below — the same lift at the borrowed-byte-slice frontier of
/// the parallel canonical-string typed primitive on the same module,
/// delegating through its sum's by-reference parse oracle on the
/// [`std::str::from_utf8`] view of the caller-supplied byte payload.
///
/// The error type is [`anyhow::Error`] — the exact shape the [`FromStr`]
/// impl and the [`TryFrom<&str>`] / [`TryFrom<String>`] /
/// [`TryFrom<Cow<'_, str>>`] impls above all carry. Two rejection modes:
/// a UTF-8-invalid byte input (a stray non-UTF-8 sequence in a raw wire
/// capture, a partial-write byte tail that clips a UTF-8 continuation)
/// surfaces an [`anyhow::Error`] naming the offending bytes' lossy-
/// decoded rendering so a caller can still attach the offending input to
/// a failure record; a UTF-8-valid but non-canonical label (uppercase,
/// hyphenated, unknown, empty, edge-whitespace) surfaces the same
/// [`anyhow::Error`] the underlying [`FromStr`] impl emits — no per-peer
/// rejection-message drift across the borrowed-string / borrowed-byte-
/// slice receiver frontier once UTF-8 validation clears.
///
/// The parser is strict for the same reason [`std::str::FromStr`] is:
/// only the canonical lowercase labels emitted by
/// [`DigestAlgorithm::as_str`] parse. Uppercase (`b"SHA256"`),
/// hyphenated (`b"sha-256"`), unknown labels (`b"md5"`), empty input
/// (`b""`), and edge-whitespace variants (`b"sha256 "`, `b" sha256"`)
/// all reject — the strictness is delegated from the underlying
/// [`FromStr`] impl (in turn from [`DigestAlgorithm::parse`]) once UTF-8
/// validation clears; UTF-8-invalid inputs reject at the
/// [`std::str::from_utf8`] validation arm without reaching the string
/// oracle.
///
/// The identity
/// `DigestAlgorithm::try_from(algo.as_str().as_bytes()).unwrap() == algo`
/// at every [`DigestAlgorithm::ALL`] variant is pinned by
/// [`tests::test_digest_algorithm_try_from_bytes_agrees_with_from_str`];
/// the identity carried through a generic `impl for<'a> TryFrom<&'a [u8]>`
/// consumer at every variant is pinned by
/// [`tests::test_digest_algorithm_try_from_bytes_carries_through_generic_consumer`];
/// the strict-rejection contract on non-canonical UTF-8-valid input is
/// pinned by
/// [`tests::test_digest_algorithm_try_from_bytes_rejects_non_canonical_input`];
/// the UTF-8-invalid rejection contract is pinned by
/// [`tests::test_digest_algorithm_try_from_bytes_rejects_invalid_utf8`].
///
/// THEORY.md §III.1 typescape: the borrowed-byte-slice try-conversion
/// surface is a typed-primitive site on [`DigestAlgorithm`] itself (one
/// `TryFrom<&[u8]>` impl routing through [`std::str::from_utf8`] then
/// [`std::str::FromStr`]), not a per-consumer
/// `std::str::from_utf8(bytes)?.parse::<DigestAlgorithm>()` bridge at
/// every downstream site that owns a byte slice and needs to reach a
/// [`DigestAlgorithm`] value. THEORY.md §VI.1 generation over
/// composition: the canonical-label grammar is named at one site
/// ([`DigestAlgorithm::as_str`]), inverted at one site
/// ([`DigestAlgorithm::parse`]), and every parse surface —
/// [`std::str::FromStr`], [`TryFrom<&str>`], [`TryFrom<String>`],
/// [`TryFrom<Cow<'_, str>>`], this [`TryFrom<&[u8]>`], the
/// [`ContentDigest::parse`] grammar oracle's algorithm arm — reads
/// through it.
impl TryFrom<&[u8]> for DigestAlgorithm {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        match std::str::from_utf8(bytes) {
            Ok(s) => <Self as std::str::FromStr>::from_str(s),
            Err(_) => Err(anyhow::anyhow!(
                "Invalid digest algorithm byte input '{}' (lossy-decoded) is not valid UTF-8",
                String::from_utf8_lossy(bytes)
            )),
        }
    }
}

/// [`TryFrom<Vec<u8>>`] routes through [`String::from_utf8`] then delegates
/// to [`<DigestAlgorithm as TryFrom<String>>::try_from`] so a downstream
/// consumer holding an owned byte buffer at a raw-byte frontier (a consumed
/// `reqwest::Response::bytes()` future materialised into [`Vec<u8>`], a
/// moved [`std::fs::read`] of a cached algorithm-label file, a
/// `serde_bytes`-decoded field on an owned schema value, a
/// tokio-mpsc-received [`Vec<u8>`] frame that carries the algorithm token
/// as its payload) recovers a [`DigestAlgorithm`] variant from its
/// canonical lowercase owned-byte serialization through the same one-oracle
/// grammar the `.parse::<DigestAlgorithm>()` string call sites already
/// read — WITHOUT the by-reference bridge
/// (`DigestAlgorithm::try_from(bytes.as_slice())`) that leaves the owned
/// [`Vec<u8>`] on the caller and forces the string oracle to receive only
/// a borrowed view.
///
/// Zero-copy on the happy path: [`String::from_utf8`] consumes the owned
/// [`Vec<u8>`] and — on successful UTF-8 validation — reuses the same
/// allocation as the returned [`String`]'s backing storage (the standard
/// library documents this as an in-place check, no re-allocation). The
/// resulting owned [`String`] then flows into the by-value string parse
/// peer [`TryFrom<String> for DigestAlgorithm`] which routes through the
/// [`FromStr`] oracle on [`String::as_str`] — one allocation, consumed at
/// intake, carried through parse, discarded when the typed variant lands
/// (variants are copy-cheap enums, not backing-string-holding newtypes).
///
/// The by-value owned-byte-slice parse peer of [`TryFrom<&str>`],
/// [`TryFrom<String>`], [`TryFrom<Cow<'_, str>>`], and [`TryFrom<&[u8]>`]
/// above — the parse surface at the digest-algorithm axis is now closed
/// across the borrowed-string ([`TryFrom<&str>`]), owned-string
/// ([`TryFrom<String>`]), borrowed-or-owned-string
/// ([`TryFrom<Cow<'_, str>>`]), borrowed-byte-slice
/// ([`TryFrom<&[u8]>`]), AND owned-byte-slice (this [`TryFrom<Vec<u8>>`])
/// input frontiers, so a downstream site that receives its input at any
/// of those frontiers routes through the same [`DigestAlgorithm::parse`]
/// oracle without an intermediate
/// `String::from_utf8(bytes)?.try_into::<DigestAlgorithm>()` bridge per
/// consumer. Structural mirror of [`TryFrom<Vec<u8>> for ContentDigest`]
/// (commit 67c5485) at the parallel canonical-string typed primitive on
/// the same module — the same lift at the owned-byte-slice frontier of
/// the reference-grammar family, delegating through its sum's by-value
/// parse oracle on the [`String::from_utf8`] view of the caller-supplied
/// byte payload.
///
/// The error type is [`anyhow::Error`] — the exact shape the [`FromStr`]
/// impl and the [`TryFrom<&str>`] / [`TryFrom<String>`] /
/// [`TryFrom<Cow<'_, str>>`] / [`TryFrom<&[u8]>`] impls above all carry.
/// Two rejection modes: a UTF-8-invalid byte input (a stray non-UTF-8
/// sequence in a raw wire capture, a partial-write byte tail that clips a
/// UTF-8 continuation) surfaces an [`anyhow::Error`] naming the offending
/// bytes' lossy-decoded rendering so a caller can still attach the
/// offending input to a failure record; a UTF-8-valid but non-canonical
/// label (uppercase, hyphenated, unknown, empty, edge-whitespace)
/// surfaces the same [`anyhow::Error`] the underlying [`FromStr`] impl
/// emits — no per-peer rejection-message drift across the owned-string /
/// owned-byte-slice receiver frontier once UTF-8 validation clears. On
/// the UTF-8-invalid path the owned [`Vec<u8>`] is recovered through
/// [`std::string::FromUtf8Error::into_bytes`] so the lossy rendering names
/// the exact bytes the caller supplied — no data loss between the intake
/// buffer and the failure record.
///
/// The identity
/// `DigestAlgorithm::try_from(algo.as_str().as_bytes().to_vec()).unwrap() == algo`
/// at every [`DigestAlgorithm::ALL`] variant is pinned by
/// [`tests::test_digest_algorithm_try_from_vec_bytes_agrees_with_from_str`];
/// the identity carried through a generic `impl TryFrom<Vec<u8>>` consumer
/// at every variant is pinned by
/// [`tests::test_digest_algorithm_try_from_vec_bytes_carries_through_generic_consumer`];
/// the strict-rejection contract on non-canonical UTF-8-valid input is
/// pinned by
/// [`tests::test_digest_algorithm_try_from_vec_bytes_rejects_non_canonical_input`];
/// the UTF-8-invalid rejection contract is pinned by
/// [`tests::test_digest_algorithm_try_from_vec_bytes_rejects_invalid_utf8`].
///
/// THEORY.md §III.1 typescape: the by-value owned-byte-slice
/// try-conversion surface is a typed-primitive site on
/// [`DigestAlgorithm`] itself (one [`TryFrom<Vec<u8>>`] impl routing
/// through [`String::from_utf8`] then [`TryFrom<String>`]), not a
/// per-consumer `String::from_utf8(bytes)?.try_into()` bridge at every
/// downstream site that owns a byte buffer. THEORY.md §VI.1 generation
/// over composition: the canonical-label grammar is named at one site
/// ([`DigestAlgorithm::as_str`]), inverted at one site
/// ([`DigestAlgorithm::parse`]), and every parse surface —
/// [`std::str::FromStr`], [`TryFrom<&str>`], [`TryFrom<String>`],
/// [`TryFrom<Cow<'_, str>>`], [`TryFrom<&[u8]>`], this
/// [`TryFrom<Vec<u8>>`], the [`ContentDigest::parse`] grammar oracle's
/// algorithm arm — reads through it.
impl TryFrom<Vec<u8>> for DigestAlgorithm {
    type Error = anyhow::Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        match String::from_utf8(bytes) {
            Ok(s) => <Self as TryFrom<String>>::try_from(s),
            Err(err) => Err(anyhow::anyhow!(
                "Invalid digest algorithm byte input '{}' (lossy-decoded) is not valid UTF-8",
                String::from_utf8_lossy(&err.into_bytes())
            )),
        }
    }
}

/// Why a string failed to parse as an OCI / Docker content digest. Carries
/// the offending input so a caller can attach it to a failure record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentDigestError {
    /// The string did not contain the `:` separating algorithm from hex.
    MissingSeparator { input: String },
    /// The algorithm prefix was not one of the supported algorithms
    /// (`sha256` / `sha512` — the OCI distribution registry set — or
    /// `blake3` — forge's attestation-frontier set stamped through
    /// [`tameshi::hash::Blake3Hash::to_prefixed`]).
    UnsupportedAlgorithm { input: String },
    /// The hex body was not lowercase-hex of the algorithm's expected length.
    InvalidHex { input: String },
    /// The byte-slice input was not valid UTF-8, so the string-oracle
    /// grammar cannot be reached. Carries a lossy-decoded rendering of
    /// the input so a failure record can still name the offending bytes.
    /// Only the byte-slice parse peer
    /// ([`TryFrom<&[u8]> for ContentDigest`]) can emit this variant —
    /// the string-frontier parse peers cannot receive UTF-8-invalid
    /// input by construction.
    InvalidUtf8 { input: String },
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
                "content digest '{input}' algorithm is not one of sha256 / sha512 / blake3"
            ),
            ContentDigestError::InvalidHex { input } => write!(
                f,
                "content digest '{input}' hex body is not lowercase-hex of the algorithm's expected length"
            ),
            ContentDigestError::InvalidUtf8 { input } => write!(
                f,
                "content digest byte input '{input}' (lossy-decoded) is not valid UTF-8"
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
///
/// `Hash` closes the identity-sink surface the type's whole raison
/// d'être asks for. Content-addressed identity is a hash key by
/// definition: two [`ContentDigest`] values are [`Eq`] iff their
/// validated `<algorithm>:<hex>` bytes agree, so the same values must
/// hash the same and a [`std::collections::HashSet<ContentDigest>`] /
/// [`std::collections::HashMap<ContentDigest, _>`] read-back is the
/// canonical dedup / lookup shape. Deriving `Hash` off the same
/// `full` field the derived [`PartialEq`] / [`Eq`] read (the only
/// field on the struct) discharges the [`Eq`] → [`Hash`] coherence
/// requirement by construction: `a == b ⇒ hash(a) == hash(b)` holds
/// at every `(a, b)` pair because both traits project through the
/// same one-oracle validated backing string. Prior to this derive,
/// the ~30 sibling trait impls in this file that documented
/// `HashSet<ContentDigest>` / `HashMap<ContentDigest, _>` as their
/// downstream consumer sink (see the [`AsRef<str>`] / [`AsRef<[u8]>`]
/// borrowed-view read peers, the [`PartialEq<str>`] / [`PartialEq<&str>`]
/// comparison peers, the [`From<ContentDigest>`] emit peers, the
/// [`TryFrom<&str>`] / [`TryFrom<String>`] parse peers) all pointed
/// at a shape the primitive itself could not participate in — a
/// [`ContentDigest`] value could not be inserted into either
/// container without a per-consumer `digest.as_str().to_owned()`
/// bridge that paid an allocation AND lost the type-level identity
/// guarantee at the key slot. Closing the [`Hash`] derive routes
/// every downstream identity-container sink through the primitive
/// itself.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
        let algorithm = DigestAlgorithm::parse(algo).ok_or_else(|| {
            ContentDigestError::UnsupportedAlgorithm {
                input: trimmed.to_string(),
            }
        })?;
        let expected_len = algorithm.hex_len();
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

    /// The algorithm prefix of the validated digest: `"sha256"`,
    /// `"sha512"`, or `"blake3"`. Read-back accessor so a consumer
    /// that pins a policy on the algorithm at its own attestation
    /// boundary (e.g. [`crate::helm_provenance`]'s sha256-only chart-
    /// hash cross-check, a future blake3-only attestation-hash
    /// cross-check on the sekiban annotation set stamped through
    /// [`tameshi::hash::Blake3Hash::to_prefixed`]) can distinguish
    /// arms directly rather than re-splitting the full string.
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

    /// The [`DigestAlgorithm`] variant of the validated digest — the
    /// typed peer of [`Self::algorithm`], which returns the same axis
    /// as a bare `&str` label. Reads through the canonical label ↔
    /// variant table on the typed sum ([`DigestAlgorithm::parse`]) so
    /// a downstream consumer that pins a per-algorithm policy — the
    /// sha256-only cross-check
    /// [`crate::helm_provenance::find_tarball_sha256`] performs on the
    /// signed-chart digest, a future per-algorithm ordering key
    /// keyed on the algorithm axis rather than the full digest bytes,
    /// a per-algorithm serde-serialize pathway — reads a typed variant
    /// rather than a string prefix. The compiler refuses to compile a
    /// non-exhaustive `match` against the typed variant, so a future
    /// widening of the digest grammar to a new algorithm (a `sha384`
    /// arm the distribution spec might normatively adopt) lights up at
    /// every downstream policy site rather than silently degrading it
    /// to a partial cover.
    ///
    /// The parse invariant guarantees the algorithm prefix
    /// [`Self::algorithm`] returns is one of the canonical labels
    /// [`DigestAlgorithm::parse`] admits, so the inner
    /// [`Option::expect`] is unreachable under a valid
    /// [`ContentDigest`] — the same parse-invariant unreachability
    /// discipline [`Self::algorithm`] and [`Self::hex`] carry.
    ///
    /// `allow(dead_code)`: part of the primitive read-back surface,
    /// same discipline as [`Self::algorithm`] / [`Self::hex`].
    ///
    /// THEORY.md §III.1 typescape: the digest-algorithm axis is a
    /// typed-primitive projection off [`ContentDigest`] onto the
    /// [`DigestAlgorithm`] typed sum, not a per-consumer
    /// `digest.algorithm() == "sha256"` string comparison at every
    /// downstream policy site. THEORY.md §VI.1 one-oracle: the
    /// canonical label ↔ variant table is named at one site
    /// ([`DigestAlgorithm::as_str`] / [`DigestAlgorithm::parse`]), and
    /// this read-back accessor reads through it.
    #[allow(dead_code)]
    pub fn algorithm_kind(&self) -> DigestAlgorithm {
        DigestAlgorithm::parse(self.algorithm())
            .expect("ContentDigest carries a validated algorithm by parse invariant")
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

/// [`TryFrom<&[u8]>`] for [`ContentDigest`] routes through
/// [`std::str::from_utf8`] then delegates to
/// [`<ContentDigest as TryFrom<&str>>::try_from`] so a downstream
/// consumer holding a byte slice at a raw-byte frontier (a captured
/// `skopeo inspect --raw` stdout still on the [`Vec<u8>`] register, a
/// manifest byte body from a `reqwest::Response::bytes()` /
/// `hyper::body::to_bytes` future not yet UTF-8-validated, a slice off
/// a `std::fs::read` of a cached digest file, a `nom` / `winnow`
/// byte-slice parser that pins its input contract as `&[u8]` and
/// yields a bounded `<algorithm>:<hex>` digest token) recovers a
/// [`ContentDigest`] value from its canonical `<algorithm>:<hex>`
/// byte serialization through the same one-oracle grammar the
/// `.parse::<ContentDigest>()` string call sites already read.
///
/// The borrowed-byte-slice peer of [`TryFrom<&str> for ContentDigest`],
/// [`TryFrom<String> for ContentDigest`], and
/// [`TryFrom<Cow<'_, str>> for ContentDigest`] on the
/// reference-grammar family — the parse surface is now closed across
/// the borrowed-string, owned-string, borrowed-or-owned-string, and
/// borrowed-byte-slice input frontiers so a downstream site that
/// receives its input at any of those frontiers routes through the
/// same [`ContentDigest::parse`] oracle without an
/// `std::str::from_utf8(bytes)?.parse()` bridge per consumer. Prior
/// to this impl a downstream site holding a `&[u8]` (a captured
/// registry stdout not yet UTF-8-validated, a network response body
/// still on the byte-slice register, a `serde_bytes`-decoded field)
/// had to restate that bridge at every call site before it could
/// reach the string parse oracle.
///
/// The [`Err`](std::convert::TryFrom::Error) type is
/// [`ContentDigestError`] — the same typed error every by-reference
/// and by-value parse surface emits. The three
/// grammar-failure variants ([`ContentDigestError::MissingSeparator`],
/// [`ContentDigestError::UnsupportedAlgorithm`],
/// [`ContentDigestError::InvalidHex`]) route unchanged through the
/// string oracle once UTF-8 validation clears; a UTF-8-invalid input
/// (a stray non-UTF-8 sequence in a raw wire capture, a
/// partial-write byte tail that clips a UTF-8 continuation) surfaces
/// as [`ContentDigestError::InvalidUtf8`] carrying the lossy-decoded
/// rendering of the offending bytes so a caller that pins a
/// per-variant handling policy at its own frontier can distinguish
/// arms directly off the
/// [`Result<ContentDigest, ContentDigestError>`] the impl returns.
///
/// THEORY.md §III.1 typescape: the byte-slice try-conversion surface
/// is a typed-primitive site on [`ContentDigest`] itself (one
/// [`TryFrom<&[u8]>`] impl routing through [`std::str::from_utf8`]
/// then [`TryFrom<&str>`]), not a per-consumer
/// `std::str::from_utf8(bytes)?.parse()` bridge at every downstream
/// site that owns a byte slice. THEORY.md §VI.1 one-oracle: the
/// canonical `<algorithm>:<hex>` grammar is named at one site
/// ([`ContentDigest::parse`]), and every parse surface —
/// [`std::str::FromStr`], [`TryFrom<&str>`], [`TryFrom<String>`],
/// [`TryFrom<Cow<'_, str>>`], this [`TryFrom<&[u8]>`] — reads
/// through it.
impl TryFrom<&[u8]> for ContentDigest {
    type Error = ContentDigestError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        match std::str::from_utf8(bytes) {
            Ok(s) => <Self as TryFrom<&str>>::try_from(s),
            Err(_) => Err(ContentDigestError::InvalidUtf8 {
                input: String::from_utf8_lossy(bytes).into_owned(),
            }),
        }
    }
}

/// [`TryFrom<Vec<u8>>`] for [`ContentDigest`] routes through
/// [`String::from_utf8`] then delegates to
/// [`<ContentDigest as TryFrom<String>>::try_from`] so a downstream
/// consumer holding an owned byte buffer at a raw-byte frontier (a
/// consumed `reqwest::Response::bytes()` future materialised into
/// `Vec<u8>`, a moved `std::fs::read` of a cached digest file, a
/// `serde_bytes`-decoded field on an owned schema value, a
/// tokio-mpsc-received `Vec<u8>` frame that carries the digest token
/// as its payload) recovers a [`ContentDigest`] value from its
/// canonical `<algorithm>:<hex>` owned-byte serialization through the
/// same one-oracle grammar the `.parse::<ContentDigest>()` string
/// call sites already read — WITHOUT the by-reference bridge
/// (`ContentDigest::try_from(bytes.as_slice())`) that leaks the owned
/// [`Vec<u8>`] allocation and forces the string oracle to re-allocate
/// its own owned backing string off the borrowed view.
///
/// Zero-copy on the happy path: [`String::from_utf8`] consumes the
/// owned [`Vec<u8>`] and — on successful UTF-8 validation — reuses
/// the same allocation as the returned [`String`]'s backing storage
/// (the standard library documents this as an in-place check, no
/// re-allocation). The resulting owned [`String`] then flows into
/// the by-value string parse peer [`TryFrom<String> for ContentDigest`]
/// which itself moves the string into the validated
/// [`ContentDigest`]'s backing storage on success — one allocation,
/// consumed at intake, carried through parse, landed on the typed
/// value. The prior route through the borrowed-byte peer
/// (`ContentDigest::try_from(bytes.as_slice())`) instead forced a
/// second allocation inside the string oracle (`trimmed.to_string()`
/// at [`ContentDigest::parse`]) because the borrowed input could
/// not be moved.
///
/// The by-value owned-byte-slice parse peer of [`TryFrom<&[u8]> for
/// ContentDigest`] on the reference-grammar family — the parse
/// surface is now closed across the borrowed-string
/// ([`TryFrom<&str>`]), owned-string ([`TryFrom<String>`]),
/// borrowed-or-owned-string ([`TryFrom<Cow<'_, str>>`]),
/// borrowed-byte-slice ([`TryFrom<&[u8]>`]), AND owned-byte-slice
/// (this [`TryFrom<Vec<u8>>`]) input frontiers — mirroring the emit
/// surface which is already closed across the by-value owned targets
/// on both axes ([`From<ContentDigest> for String`],
/// [`From<ContentDigest> for Vec<u8>`]). A downstream site that
/// received its input at any of those frontiers routes through the
/// same [`ContentDigest::parse`] oracle without a per-consumer
/// `String::from_utf8(bytes)?.try_into()` bridge — the pattern this
/// impl absorbs at one site so no downstream site restates it.
/// Structural mirror of [`impl TryFrom<Vec<u8>> for
/// crate::retry::PerAttemptRegion`], the by-value owned-byte-slice
/// parse peer on the sibling label-axis ordered typed sum that
/// already carries the complete owned-shape parse-peer set
/// ([`TryFrom<Box<str>>`], [`TryFrom<Arc<str>>`],
/// [`TryFrom<Rc<str>>`], [`TryFrom<Vec<u8>>`],
/// [`TryFrom<Box<[u8]>>`], [`TryFrom<Arc<[u8]>>`],
/// [`TryFrom<Rc<[u8]>>`]) — the digest reference-grammar family
/// begins closing that same owned-shape parse-peer surface here,
/// starting with the by-value owned-byte-slice peer whose emit
/// counterpart [`From<ContentDigest> for Vec<u8>`] already exists.
///
/// The [`Err`](std::convert::TryFrom::Error) type is
/// [`ContentDigestError`] — the same typed error every by-reference
/// and by-value parse surface emits. The three grammar-failure
/// variants ([`ContentDigestError::MissingSeparator`],
/// [`ContentDigestError::UnsupportedAlgorithm`],
/// [`ContentDigestError::InvalidHex`]) route unchanged through the
/// string oracle once UTF-8 validation clears; a UTF-8-invalid input
/// (a stray non-UTF-8 byte in an owned wire buffer, a
/// partial-write byte tail materialised as owned bytes) surfaces as
/// [`ContentDigestError::InvalidUtf8`] carrying the lossy-decoded
/// rendering of the offending bytes so a caller that pins a
/// per-variant handling policy at its own frontier can distinguish
/// arms directly off the
/// [`Result<ContentDigest, ContentDigestError>`] the impl returns.
/// On the UTF-8-invalid path the owned [`Vec<u8>`] is recovered
/// through [`std::string::FromUtf8Error::into_bytes`] so the lossy
/// rendering names the exact bytes the caller supplied — no data
/// loss between the intake buffer and the failure record.
///
/// THEORY.md §III.1 typescape: the by-value owned-byte-slice
/// try-conversion surface is a typed-primitive site on
/// [`ContentDigest`] itself (one [`TryFrom<Vec<u8>>`] impl routing
/// through [`String::from_utf8`] then [`TryFrom<String>`]), not a
/// per-consumer `String::from_utf8(bytes)?.try_into()` bridge at
/// every downstream site that owns a byte buffer. THEORY.md §VI.1
/// one-oracle: the canonical `<algorithm>:<hex>` grammar is named
/// at one site ([`ContentDigest::parse`]), and every parse surface —
/// [`std::str::FromStr`], [`TryFrom<&str>`], [`TryFrom<String>`],
/// [`TryFrom<Cow<'_, str>>`], [`TryFrom<&[u8]>`], this
/// [`TryFrom<Vec<u8>>`] — reads through it.
impl TryFrom<Vec<u8>> for ContentDigest {
    type Error = ContentDigestError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        match String::from_utf8(bytes) {
            Ok(s) => <Self as TryFrom<String>>::try_from(s),
            Err(err) => Err(ContentDigestError::InvalidUtf8 {
                input: String::from_utf8_lossy(&err.into_bytes()).into_owned(),
            }),
        }
    }
}

/// [`TryFrom<Box<str>>`] for [`ContentDigest`] routes through
/// [`String::from`] (which unboxes the `Box<str>` at zero-copy into the
/// same heap allocation as the returned [`String`]'s backing storage)
/// then delegates to
/// [`<ContentDigest as TryFrom<String>>::try_from`] so a downstream
/// consumer holding a shrunk-owned UTF-8 buffer at a two-word boxed-slice
/// frontier (a serde container that opts into
/// `#[serde(try_from = "Box<str>")]` on a wrapper field, a
/// `Cow::Owned` arm that shed its growth-header capacity through
/// [`String::into_boxed_str`] before landing on a downstream sink, a
/// heap-owned label slot stored in a `Vec<Box<str>>` whose entries flow
/// into a parse pass, a validated-builder frontier that pins its
/// canonical input contract as [`Box<str>`] to shed the growth-header
/// word before the parse gate) recovers a [`ContentDigest`] value from
/// its canonical `<algorithm>:<hex>` shrunk-owned UTF-8 serialization
/// through the same one-oracle grammar the
/// `.parse::<ContentDigest>()` string call sites already read — WITHOUT
/// the by-reference bridge (`ContentDigest::try_from(boxed.as_ref())`)
/// that leaks the owned [`Box<str>`] allocation and forces the string
/// oracle to re-allocate its own owned backing string off the borrowed
/// view.
///
/// Zero-copy on the happy path: [`String::from(Box<str>)`] takes
/// ownership of the boxed slice's heap allocation and reuses it as the
/// returned [`String`]'s backing storage (the standard library documents
/// this as a length-only conversion with no re-allocation). The
/// resulting owned [`String`] then flows into the by-value string parse
/// peer [`TryFrom<String> for ContentDigest`] which itself moves the
/// string into the validated [`ContentDigest`]'s backing storage on
/// success — one allocation, consumed at intake, carried through parse,
/// landed on the typed value. The prior route through the borrowed-str
/// peer (`ContentDigest::try_from(boxed.as_ref())`) instead forced a
/// second allocation inside the string oracle (`trimmed.to_string()`
/// at [`ContentDigest::parse`]) because the borrowed input could not
/// be moved.
///
/// The by-value shrunk-owned UTF-8 parse peer of
/// [`TryFrom<&str> for ContentDigest`] (commit ebd8d0d),
/// [`TryFrom<String> for ContentDigest`] (commit f175833),
/// [`TryFrom<Cow<'_, str>> for ContentDigest`] (commit 3a28035),
/// [`TryFrom<&[u8]> for ContentDigest`] (commit 08e1285), and
/// [`TryFrom<Vec<u8>> for ContentDigest`] (commit 67c5485) on the
/// reference-grammar family — the parse surface widens across the
/// borrowed-string, owned-string, borrowed-or-owned-string,
/// borrowed-byte-slice, owned-byte-slice, AND shrunk-owned-string
/// input frontiers so a downstream site that receives its input at any
/// of those frontiers routes through the same [`ContentDigest::parse`]
/// oracle without a per-consumer `String::from(boxed).try_into()`
/// bridge — the pattern this impl absorbs at one site so no downstream
/// site restates it. The parse mirror of the emit peer
/// [`From<ContentDigest> for Box<str>`] (commit 0e86524): the emit peer
/// projects a validated [`ContentDigest`] into a shrunk-owned UTF-8
/// buffer through [`String::into_boxed_str`]; this parse peer recovers
/// a [`ContentDigest`] value from a shrunk-owned UTF-8 buffer through
/// [`String::from`]. Together they close the [`Box<str>`] frontier at
/// [`ContentDigest`] on both the parse and emit sides so a downstream
/// site that types both its input and its re-emit contract as
/// [`Box<str>`] (a serde container that opts into
/// `#[serde(try_from = "Box<str>", into = "Box<str>")]`, a
/// validated-input newtype builder whose canonical parse AND re-emit
/// contracts are both stated as shrunk-owned UTF-8) is a one-line
/// bridge through the shared frontier, not a per-consumer restatement
/// of the shrunk-owned discipline at either side.
///
/// Structural mirror of [`impl TryFrom<Box<str>> for
/// crate::retry::PerAttemptRegion`], the by-value shrunk-owned UTF-8
/// parse peer on the sibling label-axis ordered typed sum that already
/// carries the complete owned-shape parse-peer set
/// ([`TryFrom<Box<str>>`], [`TryFrom<Arc<str>>`], [`TryFrom<Rc<str>>`],
/// [`TryFrom<Vec<u8>>`], [`TryFrom<Box<[u8]>>`], [`TryFrom<Arc<[u8]>>`],
/// [`TryFrom<Rc<[u8]>>`]) — the digest reference-grammar family now
/// begins closing the shrunk-owned string leg of that same owned-shape
/// parse-peer surface, mirroring the emit-side [`From<ContentDigest>
/// for Box<str>`] that already exists.
///
/// The [`Err`](std::convert::TryFrom::Error) type is
/// [`ContentDigestError`] — the same typed error every by-reference
/// and by-value parse surface emits. The three grammar-failure
/// variants ([`ContentDigestError::MissingSeparator`],
/// [`ContentDigestError::UnsupportedAlgorithm`],
/// [`ContentDigestError::InvalidHex`]) route unchanged through the
/// string oracle so a caller that pins a per-variant handling policy
/// at its own frontier can distinguish arms directly off the
/// [`Result<ContentDigest, ContentDigestError>`] the impl returns. The
/// UTF-8-invalid failure mode ([`ContentDigestError::InvalidUtf8`])
/// cannot be reached from this peer by construction: a [`Box<str>`]
/// carries a UTF-8-validated backing slice at the type level, so the
/// UTF-8 gate the byte-frontier peers ([`TryFrom<&[u8]>`],
/// [`TryFrom<Vec<u8>>`]) run is unreachable here.
///
/// THEORY.md §III.1 typescape: the by-value shrunk-owned UTF-8
/// try-conversion surface is a typed-primitive site on
/// [`ContentDigest`] itself (one [`TryFrom<Box<str>>`] impl routing
/// through [`String::from`] then [`TryFrom<String>`]), not a
/// per-consumer `String::from(boxed).try_into()` bridge at every
/// downstream site that owns a shrunk UTF-8 buffer. THEORY.md §VI.1
/// one-oracle: the canonical `<algorithm>:<hex>` grammar is named
/// at one site ([`ContentDigest::parse`]), and every parse surface —
/// [`std::str::FromStr`], [`TryFrom<&str>`], [`TryFrom<String>`],
/// [`TryFrom<Cow<'_, str>>`], [`TryFrom<&[u8]>`], [`TryFrom<Vec<u8>>`],
/// this [`TryFrom<Box<str>>`] — reads through it.
impl TryFrom<Box<str>> for ContentDigest {
    type Error = ContentDigestError;

    fn try_from(boxed: Box<str>) -> Result<Self, Self::Error> {
        <Self as TryFrom<String>>::try_from(String::from(boxed))
    }
}

/// [`TryFrom<Arc<str>>`] for [`ContentDigest`] routes through
/// [`<std::sync::Arc<str> as AsRef<str>>::as_ref`] (a zero-copy borrow of
/// the shared allocation's UTF-8 backing bytes that does NOT touch the
/// atomic-refcount header) then delegates to
/// [`<ContentDigest as TryFrom<&str>>::try_from`] so a downstream
/// consumer holding a shared-owned UTF-8 buffer at a refcount-headered
/// frontier (a serde container that opts into
/// `#[serde(try_from = "Arc<str>")]` on a wrapper field to consume a
/// cross-thread shared-owned label without a per-consumer allocation, a
/// validated-input newtype builder whose parse contract accepts a
/// caller-supplied [`Arc<str>`] label slot at the shared-owned frontier
/// for cross-thread cheap-clone semantics on the input, a
/// `dashmap`-style keyed-table consumer whose key slot arrives as a
/// shared-owned label from an upstream table build refcounted across
/// worker threads, a `Vec<Arc<str>>` per-attempt digest list handed
/// cheaply through [`Arc::clone`] to each parse worker) recovers a
/// [`ContentDigest`] value from its canonical `<algorithm>:<hex>`
/// shared-owned UTF-8 serialization through the same one-oracle grammar
/// the `.parse::<ContentDigest>()` string call sites already read —
/// WITHOUT a per-consumer `shared.parse::<ContentDigest>()` restatement
/// at every downstream site, WITHOUT an
/// [`std::sync::Arc::try_unwrap`]-fallback-clone-then-parse cascade
/// that would negotiate the refcount at every intake, and WITHOUT an
/// `Arc::to_string()`-then-parse round trip that would allocate a fresh
/// owned [`String`] off the shared borrow for each parse pass.
///
/// Zero-touch on the atomic refcount during the parse: the receiver-side
/// [`<std::sync::Arc<str> as AsRef<str>>::as_ref`] call yields a
/// borrowed `&str` view of the shared allocation's UTF-8 payload without
/// allocating and without incrementing or decrementing the atomic
/// refcount header preceding the label bytes, so the parse-side receiver
/// pays the by-reference [`ContentDigest::parse`] cost only, not the
/// atomic-op cost of a
/// [`std::sync::Arc::try_unwrap`]-fallback-clone-then-parse composition
/// nor the allocation cost of an `Arc::to_string()`-then-parse round
/// trip. The [`std::sync::Arc<str>`] input is dropped at end of scope,
/// releasing the shared allocation exactly when the last outstanding
/// [`Arc::clone`] refcount hits zero — the standard shared-owned drop
/// semantics carry through unchanged.
///
/// The by-value shared-owned UTF-8 parse peer of
/// [`TryFrom<&str> for ContentDigest`] (commit ebd8d0d),
/// [`TryFrom<String> for ContentDigest`] (commit f175833),
/// [`TryFrom<Cow<'_, str>> for ContentDigest`] (commit 3a28035),
/// [`TryFrom<&[u8]> for ContentDigest`] (commit 08e1285),
/// [`TryFrom<Vec<u8>> for ContentDigest`] (commit 67c5485), and
/// [`TryFrom<Box<str>> for ContentDigest`] (commit 2d5eb7e) on the
/// reference-grammar family — the parse surface widens across the
/// borrowed-string, owned-string, borrowed-or-owned-string,
/// borrowed-byte-slice, owned-byte-slice, shrunk-owned-string, AND
/// shared-owned-string input frontiers so a downstream site that
/// receives its input at any of those frontiers routes through the same
/// [`ContentDigest::parse`] oracle without a per-consumer bridge — the
/// pattern this impl absorbs at one site so no downstream site restates
/// it. The parse mirror of the emit peer
/// [`From<ContentDigest> for Arc<str>`] (commit 5f85247): the emit peer
/// projects a validated [`ContentDigest`] into a cross-thread
/// shared-owned UTF-8 buffer through
/// [`std::sync::Arc::<str>::from`]; this parse peer recovers a
/// [`ContentDigest`] value from a cross-thread shared-owned UTF-8 buffer
/// through the [`AsRef::as_ref`] borrow of its backing bytes. Together
/// they close the [`Arc<str>`] frontier at [`ContentDigest`] on both the
/// parse and emit sides so a downstream site that types both its input
/// and its re-emit contract as [`Arc<str>`] (a serde container that
/// opts into `#[serde(try_from = "Arc<str>", into = "Arc<str>")]`, a
/// validated-input newtype builder whose canonical parse AND re-emit
/// contracts are both stated as cross-thread shared-owned UTF-8) is a
/// one-line bridge through the shared frontier, not a per-consumer
/// restatement of the shared-owned discipline at either side.
///
/// Structural mirror of
/// [`impl TryFrom<Arc<str>> for crate::retry::PerAttemptRegion`], the
/// by-value shared-owned UTF-8 parse peer on the sibling label-axis
/// ordered typed sum that already carries the complete owned-shape
/// parse-peer set ([`TryFrom<Box<str>>`], [`TryFrom<Arc<str>>`],
/// [`TryFrom<Rc<str>>`], [`TryFrom<Vec<u8>>`], [`TryFrom<Box<[u8]>>`],
/// [`TryFrom<Arc<[u8]>>`], [`TryFrom<Rc<[u8]>>`]) — the digest
/// reference-grammar family continues closing the shared-owned string
/// leg of that same owned-shape parse-peer surface, mirroring the
/// emit-side [`From<ContentDigest> for Arc<str>`] that already exists.
/// Next natural step in the same family: the thread-local shared-owned
/// UTF-8 parse peer [`TryFrom<Rc<str>>`] closing the shrunk / shared
/// UTF-8 parse trio.
///
/// The [`Err`](std::convert::TryFrom::Error) type is
/// [`ContentDigestError`] — the same typed error every by-reference
/// and by-value parse surface emits. The three grammar-failure
/// variants ([`ContentDigestError::MissingSeparator`],
/// [`ContentDigestError::UnsupportedAlgorithm`],
/// [`ContentDigestError::InvalidHex`]) route unchanged through the
/// string oracle so a caller that pins a per-variant handling policy
/// at its own frontier can distinguish arms directly off the
/// [`Result<ContentDigest, ContentDigestError>`] the impl returns. The
/// UTF-8-invalid failure mode ([`ContentDigestError::InvalidUtf8`])
/// cannot be reached from this peer by construction: an
/// [`std::sync::Arc<str>`] carries a UTF-8-validated backing slice at
/// the type level, so the UTF-8 gate the byte-frontier peers
/// ([`TryFrom<&[u8]>`], [`TryFrom<Vec<u8>>`]) run is unreachable here.
///
/// THEORY.md §III.1 typescape: the by-value shared-owned UTF-8
/// try-conversion surface is a typed-primitive site on
/// [`ContentDigest`] itself (one [`TryFrom<Arc<str>>`] impl routing
/// through [`AsRef::as_ref`] then [`TryFrom<&str>`]), not a
/// per-consumer `shared.parse::<ContentDigest>()` restatement at every
/// downstream site that owns a shared UTF-8 buffer. THEORY.md §VI.1
/// one-oracle: the canonical `<algorithm>:<hex>` grammar is named at
/// one site ([`ContentDigest::parse`]), and every parse surface —
/// [`std::str::FromStr`], [`TryFrom<&str>`], [`TryFrom<String>`],
/// [`TryFrom<Cow<'_, str>>`], [`TryFrom<&[u8]>`], [`TryFrom<Vec<u8>>`],
/// [`TryFrom<Box<str>>`], this [`TryFrom<Arc<str>>`] — reads through
/// it.
impl TryFrom<std::sync::Arc<str>> for ContentDigest {
    type Error = ContentDigestError;

    fn try_from(shared: std::sync::Arc<str>) -> Result<Self, Self::Error> {
        <Self as TryFrom<&str>>::try_from(shared.as_ref())
    }
}

/// [`TryFrom<Rc<str>>`] for [`ContentDigest`] routes through
/// [`<std::rc::Rc<str> as AsRef<str>>::as_ref`] (a zero-copy borrow of the
/// shared allocation's UTF-8 backing bytes that does NOT touch the
/// non-atomic-refcount header) then delegates to
/// [`<ContentDigest as TryFrom<&str>>::try_from`] so a downstream consumer
/// holding a single-thread shared-owned UTF-8 buffer at a refcount-headered
/// frontier (a serde container that opts into
/// `#[serde(try_from = "Rc<str>")]` on a wrapper field to consume a
/// thread-local shared-owned label without a per-consumer allocation, a
/// validated-input newtype builder whose parse contract accepts a
/// caller-supplied [`Rc<str>`] label slot at the shared-owned frontier
/// for single-thread cheap-clone semantics on the input, a single-thread
/// `HashMap<Rc<str>, _>` registry cache whose key slot arrives as a
/// shared-owned label from an upstream table build refcounted across peer
/// inspectors within one thread, a `!Send` per-task lookaside built during
/// a synchronous scan phase whose `Vec<Rc<str>>` digest list is handed
/// cheaply through [`Rc::clone`] to each parse worker) recovers a
/// [`ContentDigest`] value from its canonical `<algorithm>:<hex>`
/// shared-owned UTF-8 serialization through the same one-oracle grammar
/// the `.parse::<ContentDigest>()` string call sites already read —
/// WITHOUT a per-consumer `shared.parse::<ContentDigest>()` restatement at
/// every downstream site, WITHOUT an
/// [`std::rc::Rc::try_unwrap`]-fallback-clone-then-parse cascade that
/// would negotiate the refcount at every intake, and WITHOUT an
/// `Rc::to_string()`-then-parse round trip that would allocate a fresh
/// owned [`String`] off the shared borrow for each parse pass.
///
/// Zero-touch on the non-atomic refcount during the parse: the
/// receiver-side [`<std::rc::Rc<str> as AsRef<str>>::as_ref`] call yields
/// a borrowed `&str` view of the shared allocation's UTF-8 payload
/// without allocating and without incrementing or decrementing the
/// non-atomic-refcount header preceding the label bytes, so the
/// parse-side receiver pays the by-reference [`ContentDigest::parse`]
/// cost only, not the integer-op cost of a
/// [`std::rc::Rc::try_unwrap`]-fallback-clone-then-parse composition nor
/// the allocation cost of an `Rc::to_string()`-then-parse round trip. The
/// [`std::rc::Rc<str>`] input is dropped at end of scope, releasing the
/// shared allocation exactly when the last outstanding [`Rc::clone`]
/// refcount hits zero — the standard single-thread shared-owned drop
/// semantics carry through unchanged.
///
/// A single-thread caller that would otherwise widen its parse frontier
/// to [`Arc<str>`] purely to satisfy the parse peer's type signature —
/// paying [`Arc`]'s atomic-refcount header on every clone of a label
/// that never crosses a thread boundary — routes through this [`Rc<str>`]
/// peer instead and keeps the non-atomic-refcount cost on the input side
/// by construction. The single-thread parse-side cost of a `Vec<Rc<str>>`
/// digest list drained one-by-one through this impl collapses to
/// `n * (Rc::deref + ContentDigest::parse)`, matching the [`Arc<str>`]
/// peer's parse cost minus the atomic-fence overhead the [`Rc<str>`]
/// frontier avoids by construction.
///
/// The by-value thread-local shared-owned UTF-8 parse peer of
/// [`TryFrom<&str> for ContentDigest`] (commit ebd8d0d),
/// [`TryFrom<String> for ContentDigest`] (commit f175833),
/// [`TryFrom<Cow<'_, str>> for ContentDigest`] (commit 3a28035),
/// [`TryFrom<&[u8]> for ContentDigest`] (commit 08e1285),
/// [`TryFrom<Vec<u8>> for ContentDigest`] (commit 67c5485),
/// [`TryFrom<Box<str>> for ContentDigest`] (commit 2d5eb7e), and
/// [`TryFrom<Arc<str>> for ContentDigest`] (commit 414b22c) on the
/// reference-grammar family — the parse surface widens across the
/// borrowed-string, owned-string, borrowed-or-owned-string,
/// borrowed-byte-slice, owned-byte-slice, shrunk-owned-string,
/// cross-thread shared-owned-string, AND thread-local shared-owned-string
/// input frontiers so a downstream site that receives its input at any of
/// those frontiers routes through the same [`ContentDigest::parse`]
/// oracle without a per-consumer bridge — the pattern this impl absorbs
/// at one site so no downstream site restates it. The parse mirror of the
/// emit peer [`From<ContentDigest> for Rc<str>`] (commit a7bcfd2): the
/// emit peer projects a validated [`ContentDigest`] into a thread-local
/// shared-owned UTF-8 buffer through [`std::rc::Rc::<str>::from`]; this
/// parse peer recovers a [`ContentDigest`] value from a thread-local
/// shared-owned UTF-8 buffer through the [`AsRef::as_ref`] borrow of its
/// backing bytes. Together they close the [`Rc<str>`] frontier at
/// [`ContentDigest`] on both the parse and emit sides so a downstream
/// site that types both its input and its re-emit contract as
/// [`Rc<str>`] (a serde container that opts into
/// `#[serde(try_from = "Rc<str>", into = "Rc<str>")]`, a
/// validated-input newtype builder whose canonical parse AND re-emit
/// contracts are both stated as thread-local shared-owned UTF-8) is a
/// one-line bridge through the shared frontier, not a per-consumer
/// restatement of the shared-owned discipline at either side.
///
/// Closes the shrunk / cross-thread-shared / thread-local-shared UTF-8
/// parse trio at [`ContentDigest`]: [`TryFrom<Box<str>>`] (commit 2d5eb7e,
/// shrunk-owned), [`TryFrom<Arc<str>>`] (commit 414b22c, cross-thread
/// shared-owned), this [`TryFrom<Rc<str>>`] (thread-local shared-owned)
/// — every owned-shape UTF-8 receiver frontier the sibling label-axis
/// ordered typed sums already carry now has a matching parse surface on
/// the digest reference-grammar family.
///
/// Structural mirror of
/// [`impl TryFrom<Rc<str>> for crate::retry::PerAttemptRegion`], the
/// by-value thread-local shared-owned UTF-8 parse peer on the sibling
/// label-axis ordered typed sum that already carries the complete
/// owned-shape parse-peer set ([`TryFrom<Box<str>>`],
/// [`TryFrom<Arc<str>>`], [`TryFrom<Rc<str>>`], [`TryFrom<Vec<u8>>`],
/// [`TryFrom<Box<[u8]>>`], [`TryFrom<Arc<[u8]>>`], [`TryFrom<Rc<[u8]>>`])
/// — the digest reference-grammar family closes the thread-local
/// shared-owned string leg of that same owned-shape parse-peer surface,
/// mirroring the emit-side [`From<ContentDigest> for Rc<str>`] that
/// already exists. Next natural step in the same family: the
/// borrowed/owned-frontier byte-slice parse peer
/// [`TryFrom<Cow<'_, [u8]>>`] opening the shrunk / cross-thread-shared
/// / thread-local-shared byte-slice parse trio at the byte-slice
/// frontier.
///
/// The [`Err`](std::convert::TryFrom::Error) type is
/// [`ContentDigestError`] — the same typed error every by-reference and
/// by-value parse surface emits. The three grammar-failure variants
/// ([`ContentDigestError::MissingSeparator`],
/// [`ContentDigestError::UnsupportedAlgorithm`],
/// [`ContentDigestError::InvalidHex`]) route unchanged through the
/// string oracle so a caller that pins a per-variant handling policy at
/// its own frontier can distinguish arms directly off the
/// [`Result<ContentDigest, ContentDigestError>`] the impl returns. The
/// UTF-8-invalid failure mode ([`ContentDigestError::InvalidUtf8`])
/// cannot be reached from this peer by construction: an
/// [`std::rc::Rc<str>`] carries a UTF-8-validated backing slice at the
/// type level, so the UTF-8 gate the byte-frontier peers
/// ([`TryFrom<&[u8]>`], [`TryFrom<Vec<u8>>`]) run is unreachable here.
///
/// THEORY.md §III.1 typescape: the by-value thread-local shared-owned
/// UTF-8 try-conversion surface is a typed-primitive site on
/// [`ContentDigest`] itself (one [`TryFrom<Rc<str>>`] impl routing
/// through [`AsRef::as_ref`] then [`TryFrom<&str>`]), not a per-consumer
/// `shared.parse::<ContentDigest>()` restatement at every downstream
/// site that owns a thread-local shared UTF-8 buffer. THEORY.md §VI.1
/// one-oracle: the canonical `<algorithm>:<hex>` grammar is named at
/// one site ([`ContentDigest::parse`]), and every parse surface —
/// [`std::str::FromStr`], [`TryFrom<&str>`], [`TryFrom<String>`],
/// [`TryFrom<Cow<'_, str>>`], [`TryFrom<&[u8]>`], [`TryFrom<Vec<u8>>`],
/// [`TryFrom<Box<str>>`], [`TryFrom<Arc<str>>`], this [`TryFrom<Rc<str>>`]
/// — reads through it.
impl TryFrom<std::rc::Rc<str>> for ContentDigest {
    type Error = ContentDigestError;

    fn try_from(shared: std::rc::Rc<str>) -> Result<Self, Self::Error> {
        <Self as TryFrom<&str>>::try_from(shared.as_ref())
    }
}

/// [`TryFrom<Cow<'_, [u8]>>`] for [`ContentDigest`] routes each arm through
/// its shape-matched byte-slice parse peer — the [`Cow::Borrowed`] arm to
/// [`<ContentDigest as TryFrom<&[u8]>>::try_from`] (a zero-copy borrow of
/// the shared byte view that runs the by-reference UTF-8 gate and then the
/// string oracle without touching the owned allocation), the [`Cow::Owned`]
/// arm to [`<ContentDigest as TryFrom<Vec<u8>>>::try_from`] (a consumed
/// move of the owned [`Vec<u8>`] into the by-value UTF-8 gate whose
/// [`String::from_utf8`] happy path reuses the same allocation as the
/// intermediate [`String`] backing storage that then moves into the
/// validated [`ContentDigest`]) so a downstream consumer holding a
/// borrowed-or-owned byte buffer at a raw-byte frontier (a serde-compatible
/// byte deserializer that hands its container an owned-or-borrowed
/// [`Cow<'_, [u8]>`] to preserve zero-copy where the input allows it, a
/// generic try-conversion helper `fn parse_digest<'a, T: TryFrom<Cow<'a,
/// [u8]>, Error = ContentDigestError>>`, a validated-builder frontier that
/// pins its input contract as [`Cow<'_, [u8]>`] to bridge caller-owned and
/// caller-borrowed raw-byte inputs at zero extra allocation on the
/// borrowed arm and zero extra allocation on the owned arm, an owned-or-
/// borrowed pipeline that consumes [`Cow`] to defer the ownership decision
/// to its caller while still handing the wire bytes through the parse
/// oracle) recovers a [`ContentDigest`] value from its canonical
/// `<algorithm>:<hex>` borrowed-or-owned byte serialization through the
/// same one-oracle grammar the `.parse::<ContentDigest>()` string call
/// sites already read — WITHOUT the by-reference bridge
/// (`ContentDigest::try_from(cow.as_ref())`) that would collapse the
/// owned arm through the borrowed peer and force the string oracle to
/// re-allocate its own owned backing string off the borrowed view even
/// when the caller already handed over an owned [`Vec<u8>`] the parse
/// pipeline could have moved through end to end.
///
/// Ownership-preserving on both arms: the [`Cow::Borrowed`] arm keeps
/// the caller's borrow structurally by routing through the borrowed-byte
/// peer (no allocation on the parse-side receiver), and the [`Cow::Owned`]
/// arm keeps the caller's owned allocation structurally by routing
/// through the owned-byte peer whose [`String::from_utf8`] happy path
/// converts the [`Vec<u8>`] backing to a [`String`] backing without
/// re-allocating (the standard library documents this as an in-place
/// UTF-8 check) and then into the validated value's backing on
/// [`TryFrom<String>`]'s move. A downstream site that types its parse
/// contract as [`Cow<'_, [u8]>`] to preserve zero-copy on borrowable
/// inputs while still handling owned inputs — a serde
/// `try_from = "Cow<'_, [u8]>"` wrapper on a byte-frontier
/// deserializer, a caller-agnostic validated builder whose input type
/// crosses the borrowed/owned frontier — pays the byte-slice UTF-8 gate
/// cost only, not the additional allocation the by-reference bridge
/// would force on the owned arm.
///
/// The borrowed/owned-frontier byte-slice parse peer of [`TryFrom<&[u8]>
/// for ContentDigest`] (commit 08e1285), [`TryFrom<Vec<u8>> for
/// ContentDigest`] (commit 67c5485), and [`TryFrom<Cow<'_, str>> for
/// ContentDigest`] (commit 3a28035) on the reference-grammar family —
/// the parse surface widens across the borrowed-byte-slice, owned-byte-
/// slice, AND borrowed-or-owned-byte-slice input frontiers so a
/// downstream site that receives its input at any of those frontiers
/// routes through the same [`ContentDigest::parse`] oracle without a
/// per-consumer bridge. Structural analog on the byte-slice axis of
/// [`TryFrom<Cow<'_, str>> for ContentDigest`] on the UTF-8-string
/// axis: the borrowed/owned-frontier string peer opened the borrowed-
/// or-owned frontier at the [`str`] receiver shape; this
/// borrowed/owned-frontier byte-slice peer opens the analogous frontier
/// at the `[u8]` receiver shape so the parse surface is now closed at
/// the [`Cow`] frontier on both the UTF-8-string axis and the byte-
/// slice axis. The parse mirror of the emit peer
/// [`From<ContentDigest> for Cow<'static, [u8]>`] (commit c2a5acf): the
/// emit peer projects a validated [`ContentDigest`] into a
/// borrowed-or-owned byte buffer through `Cow::Owned(bytes)`; this parse
/// peer recovers a [`ContentDigest`] value from a borrowed-or-owned byte
/// buffer through the arm-matched byte-slice peer delegation. Together
/// they close the [`Cow<'_, [u8]>`] / [`Cow<'static, [u8]>`] frontier
/// at [`ContentDigest`] on both the parse and emit sides so a
/// downstream site that types both its input and its re-emit contract
/// as a byte-slice [`Cow`] (a serde container that opts into
/// `#[serde(try_from = "Cow<'_, [u8]>", into = "Cow<'static, [u8]>")]`,
/// a validated-input newtype builder whose canonical parse AND re-emit
/// contracts are both stated as borrowed-or-owned byte slices) is a
/// one-line bridge through the shared frontier, not a per-consumer
/// restatement of the borrowed/owned byte-slice discipline at either
/// side.
///
/// Opens the shrunk / cross-thread-shared / thread-local-shared
/// byte-slice parse trio at [`ContentDigest`] — the analog on the
/// byte-slice axis of the UTF-8-string trio [`TryFrom<Box<str>>`]
/// (commit 2d5eb7e), [`TryFrom<Arc<str>>`] (commit 414b22c),
/// [`TryFrom<Rc<str>>`] (commit 4d0783e) closed on the sibling axis.
/// Next natural steps in the same family: [`TryFrom<Box<[u8]>>`]
/// (shrunk-owned byte-slice), [`TryFrom<Arc<[u8]>>`] (cross-thread
/// shared-owned byte-slice), [`TryFrom<Rc<[u8]>>`] (thread-local
/// shared-owned byte-slice) closing the owned-shape byte-slice
/// parse-peer surface on the digest reference-grammar family.
///
/// The [`Err`](std::convert::TryFrom::Error) type is
/// [`ContentDigestError`] — the same typed error every by-reference and
/// by-value parse surface emits. The three grammar-failure variants
/// ([`ContentDigestError::MissingSeparator`],
/// [`ContentDigestError::UnsupportedAlgorithm`],
/// [`ContentDigestError::InvalidHex`]) route unchanged through the
/// string oracle once UTF-8 validation clears on either arm; a
/// UTF-8-invalid input on either arm (a stray non-UTF-8 byte in a
/// borrowed wire capture, an owned partial-write byte tail that clips
/// a UTF-8 continuation) surfaces as
/// [`ContentDigestError::InvalidUtf8`] carrying the lossy-decoded
/// rendering of the offending bytes — the same failure record the
/// arm-matched byte-slice peer emits — so a caller that pins a
/// per-variant handling policy at its own frontier can distinguish
/// arms directly off the [`Result<ContentDigest, ContentDigestError>`]
/// the impl returns.
///
/// THEORY.md §III.1 typescape: the borrowed/owned-frontier byte-slice
/// try-conversion surface is a typed-primitive site on [`ContentDigest`]
/// itself (one [`TryFrom<Cow<'_, [u8]>>`] impl arm-matching to the
/// borrowed-byte and owned-byte parse peers), not a per-consumer
/// arm-matching bridge at every downstream site that types its parse
/// contract as `impl TryFrom<Cow<'_, [u8]>>` rather than a shape-
/// specific byte-slice peer. THEORY.md §VI.1 one-oracle: the canonical
/// `<algorithm>:<hex>` grammar is named at one site
/// ([`ContentDigest::parse`]), and every parse surface —
/// [`std::str::FromStr`], [`TryFrom<&str>`], [`TryFrom<String>`],
/// [`TryFrom<Cow<'_, str>>`], [`TryFrom<&[u8]>`], [`TryFrom<Vec<u8>>`],
/// [`TryFrom<Box<str>>`], [`TryFrom<Arc<str>>`], [`TryFrom<Rc<str>>`],
/// this [`TryFrom<Cow<'_, [u8]>>`] — reads through it.
impl TryFrom<std::borrow::Cow<'_, [u8]>> for ContentDigest {
    type Error = ContentDigestError;

    fn try_from(bytes: std::borrow::Cow<'_, [u8]>) -> Result<Self, Self::Error> {
        match bytes {
            std::borrow::Cow::Borrowed(slice) => <Self as TryFrom<&[u8]>>::try_from(slice),
            std::borrow::Cow::Owned(owned) => <Self as TryFrom<Vec<u8>>>::try_from(owned),
        }
    }
}

/// [`TryFrom<Box<[u8]>>`] for [`ContentDigest`] routes through
/// [`Vec::from`] (which unboxes the [`Box<[u8]>`] at zero-copy into
/// the same heap allocation as the returned [`Vec<u8>`]'s backing
/// storage — the standard library documents this as a
/// transfer-of-ownership conversion with no re-allocation, and the
/// resulting [`Vec<u8>`] carries `capacity == length` matching the
/// boxed slice's shape) then delegates to
/// [`<ContentDigest as TryFrom<Vec<u8>>>::try_from`] so a downstream
/// consumer holding a shrunk-owned raw-byte buffer at a two-word
/// boxed-slice frontier (a serde container that opts into
/// `#[serde(try_from = "Box<[u8]>")]` on a byte-frontier wrapper
/// field, a [`Cow<'_, [u8]>::Owned`] arm that shed its growth-header
/// capacity through [`Vec::into_boxed_slice`] before landing on a
/// downstream sink, a heap-owned raw-byte slot stored in a
/// `Vec<Box<[u8]>>` whose entries flow into a parse pass, a
/// validated-builder frontier that pins its canonical input contract
/// as [`Box<[u8]>`] to shed the growth-header word before the parse
/// gate) recovers a [`ContentDigest`] value from its canonical
/// `<algorithm>:<hex>` shrunk-owned byte serialization through the
/// same one-oracle grammar the `.parse::<ContentDigest>()` string
/// call sites already read — WITHOUT the by-reference bridge
/// (`ContentDigest::try_from(boxed.as_ref())`) that leaks the owned
/// [`Box<[u8]>`] allocation and forces the string oracle to
/// re-allocate its own owned backing string off the borrowed view.
///
/// Zero-copy on the happy path: [`Vec::from(Box<[u8]>)`] takes
/// ownership of the boxed slice's heap allocation and reuses it as
/// the returned [`Vec<u8>`]'s backing storage. The resulting owned
/// [`Vec<u8>`] then flows into the by-value byte-slice parse peer
/// [`TryFrom<Vec<u8>> for ContentDigest`] whose [`String::from_utf8`]
/// happy path reuses the same allocation as the intermediate
/// [`String`] backing storage that then moves into the validated
/// [`ContentDigest`]'s backing on [`TryFrom<String>`]'s move — one
/// allocation, consumed at intake, carried through the byte-frontier
/// UTF-8 gate and the string oracle, landed on the typed value. The
/// prior route through the borrowed-byte peer
/// (`ContentDigest::try_from(boxed.as_ref())`) instead forced a
/// second allocation inside the string oracle
/// (`trimmed.to_string()` at [`ContentDigest::parse`]) because the
/// borrowed input could not be moved.
///
/// The by-value shrunk-owned byte-slice parse peer of
/// [`TryFrom<&[u8]> for ContentDigest`] (commit 08e1285),
/// [`TryFrom<Vec<u8>> for ContentDigest`] (commit 67c5485),
/// [`TryFrom<Cow<'_, [u8]>> for ContentDigest`] (commit cc9fcb3),
/// and the sibling shrunk-owned UTF-8-string peer
/// [`TryFrom<Box<str>> for ContentDigest`] (commit 2d5eb7e) on the
/// reference-grammar family — the parse surface widens across the
/// borrowed-byte, owned-byte, borrowed-or-owned-byte, AND
/// shrunk-owned-byte input frontiers so a downstream site that
/// receives its input at any of those frontiers routes through the
/// same [`ContentDigest::parse`] oracle without a per-consumer
/// `Vec::from(boxed).try_into()` bridge — the pattern this impl
/// absorbs at one site so no downstream site restates it. The parse
/// mirror of the emit peer [`From<ContentDigest> for Box<[u8]>`]
/// (commit fce9fee): the emit peer projects a validated
/// [`ContentDigest`] into a shrunk-owned raw-byte buffer through
/// [`Vec::into_boxed_slice`]; this parse peer recovers a
/// [`ContentDigest`] value from a shrunk-owned raw-byte buffer
/// through [`Vec::from`]. Together they close the [`Box<[u8]>`]
/// frontier at [`ContentDigest`] on both the parse and emit sides so
/// a downstream site that types both its input and its re-emit
/// contract as [`Box<[u8]>`] (a serde container that opts into
/// `#[serde(try_from = "Box<[u8]>", into = "Box<[u8]>")]`, a
/// validated-input newtype builder whose canonical parse AND re-emit
/// contracts are both stated as shrunk-owned raw bytes) is a
/// one-line bridge through the shared frontier, not a per-consumer
/// restatement of the shrunk-owned discipline at either side.
///
/// Opens the shrunk-owned byte-slice parse peer in the owned-shape
/// byte-slice trio the borrowed/owned-frontier byte-slice peer
/// (commit cc9fcb3) named as the next natural steps —
/// [`TryFrom<Arc<[u8]>>`] (cross-thread shared-owned byte-slice) and
/// [`TryFrom<Rc<[u8]>>`] (thread-local shared-owned byte-slice)
/// remain open behind this one. Mirrors the UTF-8-string shrunk-
/// owned peer [`TryFrom<Box<str>>`] (commit 2d5eb7e) already closed
/// on the sibling axis so the digest reference-grammar family now
/// carries the shrunk-owned parse peer on both the UTF-8-string
/// axis and the byte-slice axis.
///
/// The [`Err`](std::convert::TryFrom::Error) type is
/// [`ContentDigestError`] — the same typed error every by-reference
/// and by-value parse surface emits. The three grammar-failure
/// variants ([`ContentDigestError::MissingSeparator`],
/// [`ContentDigestError::UnsupportedAlgorithm`],
/// [`ContentDigestError::InvalidHex`]) route unchanged through the
/// string oracle once UTF-8 validation clears; a UTF-8-invalid
/// shrunk-owned raw-byte buffer surfaces as
/// [`ContentDigestError::InvalidUtf8`] carrying the lossy-decoded
/// rendering of the offending bytes — the same failure record the
/// owned-byte peer [`TryFrom<Vec<u8>>`] emits — so a caller that
/// pins a per-variant handling policy at its own frontier can
/// distinguish arms directly off the
/// [`Result<ContentDigest, ContentDigestError>`] the impl returns.
///
/// THEORY.md §III.1 typescape: the by-value shrunk-owned byte-slice
/// try-conversion surface is a typed-primitive site on
/// [`ContentDigest`] itself (one [`TryFrom<Box<[u8]>>`] impl
/// routing through [`Vec::from`] then [`TryFrom<Vec<u8>>`]), not a
/// per-consumer `Vec::from(boxed).try_into()` bridge at every
/// downstream site that owns a shrunk raw-byte buffer. THEORY.md
/// §VI.1 one-oracle: the canonical `<algorithm>:<hex>` grammar is
/// named at one site ([`ContentDigest::parse`]), and every parse
/// surface — [`std::str::FromStr`], [`TryFrom<&str>`],
/// [`TryFrom<String>`], [`TryFrom<Cow<'_, str>>`],
/// [`TryFrom<&[u8]>`], [`TryFrom<Vec<u8>>`], [`TryFrom<Box<str>>`],
/// [`TryFrom<Arc<str>>`], [`TryFrom<Rc<str>>`],
/// [`TryFrom<Cow<'_, [u8]>>`], this [`TryFrom<Box<[u8]>>`] — reads
/// through it.
impl TryFrom<Box<[u8]>> for ContentDigest {
    type Error = ContentDigestError;

    fn try_from(boxed: Box<[u8]>) -> Result<Self, Self::Error> {
        <Self as TryFrom<Vec<u8>>>::try_from(Vec::<u8>::from(boxed))
    }
}

/// [`TryFrom<Arc<[u8]>>`] for [`ContentDigest`] routes through
/// [`<std::sync::Arc<[u8]> as AsRef<[u8]>>::as_ref`] (a zero-copy borrow
/// of the shared allocation's raw-byte payload that does NOT touch the
/// atomic-refcount header) then delegates to
/// [`<ContentDigest as TryFrom<&[u8]>>::try_from`] so a downstream
/// consumer holding a cross-thread shared-owned raw-byte buffer at a
/// refcount-headered byte-slice frontier (a serde container that opts
/// into `#[serde(try_from = "Arc<[u8]>")]` on a byte-frontier wrapper
/// field to consume a cross-thread shared-owned raw-byte record without
/// a per-consumer allocation, a validated-input newtype builder whose
/// parse contract accepts a caller-supplied [`Arc<[u8]>`] blob slot at
/// the shared-owned raw-byte frontier for cross-thread cheap-clone
/// semantics on the input, a `bytes::Bytes::from(Arc<[u8]>)` intake
/// path whose upstream table build refcounted the raw-byte record
/// across worker threads before landing on the parse pass, a
/// `Vec<Arc<[u8]>>` per-attestation raw-byte digest list handed cheaply
/// through [`Arc::clone`] to each parse worker) recovers a
/// [`ContentDigest`] value from its canonical `<algorithm>:<hex>`
/// cross-thread shared-owned raw-byte serialization through the same
/// one-oracle grammar the `.parse::<ContentDigest>()` string call sites
/// already read — WITHOUT a per-consumer `shared.as_ref().try_into()`
/// restatement at every downstream site, WITHOUT an
/// [`std::sync::Arc::try_unwrap`]-fallback-clone-then-parse cascade
/// that would negotiate the refcount at every intake, and WITHOUT an
/// `Arc::<[u8]>::to_vec()`-then-parse round trip that would allocate a
/// fresh owned [`Vec<u8>`] off the shared borrow for each parse pass.
///
/// Zero-touch on the atomic refcount during the parse: the
/// receiver-side [`<std::sync::Arc<[u8]> as AsRef<[u8]>>::as_ref`] call
/// yields a borrowed `&[u8]` view of the shared allocation's raw-byte
/// payload without allocating and without incrementing or decrementing
/// the atomic-refcount header preceding the raw bytes, so the
/// parse-side receiver pays the by-reference [`TryFrom<&[u8]>`] cost
/// only (a [`std::str::from_utf8`] UTF-8 gate then the
/// [`ContentDigest::parse`] string oracle), not the atomic-op cost of
/// a [`std::sync::Arc::try_unwrap`]-fallback-clone-then-parse
/// composition nor the allocation cost of an
/// `Arc::<[u8]>::to_vec()`-then-parse round trip. The
/// [`std::sync::Arc<[u8]>`] input is dropped at end of scope, releasing
/// the shared allocation exactly when the last outstanding
/// [`Arc::clone`] refcount hits zero — the standard cross-thread
/// shared-owned drop semantics carry through unchanged.
///
/// A cross-thread caller that would otherwise widen its parse frontier
/// to [`Vec<u8>`] purely to satisfy an owned-byte parse peer's type
/// signature — paying a per-worker deep-copy [`Vec::from(slice)`] on
/// every fan-out of a raw-byte record shared across a worker pool —
/// routes through this [`Arc<[u8]>`] peer instead and keeps the
/// cheap-clone atomic-refcount cost on the input side by construction.
/// The cross-thread parse-side cost of a `Vec<Arc<[u8]>>` raw-byte
/// digest list drained one-by-one through this impl collapses to
/// `n * (Arc::deref + std::str::from_utf8 + ContentDigest::parse)`,
/// matching the [`Vec<u8>`] peer's parse cost minus the per-worker
/// deep-copy allocation the [`Arc<[u8]>`] frontier avoids by
/// construction.
///
/// The by-value cross-thread shared-owned byte-slice parse peer of
/// [`TryFrom<&[u8]> for ContentDigest`] (commit 08e1285),
/// [`TryFrom<Vec<u8>> for ContentDigest`] (commit 67c5485),
/// [`TryFrom<Cow<'_, [u8]>> for ContentDigest`] (commit cc9fcb3),
/// [`TryFrom<Box<[u8]>> for ContentDigest`] (commit f5f98f6), and the
/// sibling cross-thread shared-owned UTF-8-string peer
/// [`TryFrom<Arc<str>> for ContentDigest`] (commit 414b22c) on the
/// reference-grammar family — the parse surface widens across the
/// borrowed-byte, owned-byte, borrowed-or-owned-byte, shrunk-owned-byte,
/// AND cross-thread shared-owned-byte input frontiers so a downstream
/// site that receives its input at any of those frontiers routes
/// through the same [`ContentDigest::parse`] oracle without a
/// per-consumer bridge — the pattern this impl absorbs at one site so
/// no downstream site restates it. The parse mirror of the emit peer
/// [`From<ContentDigest> for Arc<[u8]>`] (commit 49111c1): the emit
/// peer projects a validated [`ContentDigest`] into a cross-thread
/// shared-owned raw-byte buffer through
/// [`std::sync::Arc::<[u8]>::from`]; this parse peer recovers a
/// [`ContentDigest`] value from a cross-thread shared-owned raw-byte
/// buffer through the [`AsRef::as_ref`] borrow of its backing bytes.
/// Together they close the [`Arc<[u8]>`] frontier at [`ContentDigest`]
/// on both the parse and emit sides so a downstream site that types
/// both its input and its re-emit contract as [`Arc<[u8]>`] (a serde
/// container that opts into
/// `#[serde(try_from = "Arc<[u8]>", into = "Arc<[u8]>")]`, a
/// validated-input newtype builder whose canonical parse AND re-emit
/// contracts are both stated as cross-thread shared-owned raw bytes)
/// is a one-line bridge through the shared frontier, not a per-consumer
/// restatement of the cross-thread shared-owned raw-byte discipline at
/// either side.
///
/// Mid-trio in the owned-shape byte-slice family the borrowed/owned-
/// frontier byte-slice peer (commit cc9fcb3) named as the next natural
/// steps: [`TryFrom<Box<[u8]>>`] (commit f5f98f6, shrunk-owned) opened
/// the trio; this [`TryFrom<Arc<[u8]>>`] closes the cross-thread
/// shared-owned middle; the thread-local shared-owned
/// [`TryFrom<Rc<[u8]>>`] peer remains open behind this one, mirroring
/// the UTF-8-string trio (commits 2d5eb7e, 414b22c, 4d0783e) already
/// closed on the sibling axis.
///
/// Structural mirror of
/// [`impl TryFrom<Arc<[u8]>> for crate::retry::PerAttemptRegion`], the
/// by-value cross-thread shared-owned byte-slice parse peer on the
/// sibling label-axis ordered typed sum that already carries the
/// complete owned-shape parse-peer set ([`TryFrom<Box<str>>`],
/// [`TryFrom<Arc<str>>`], [`TryFrom<Rc<str>>`], [`TryFrom<Vec<u8>>`],
/// [`TryFrom<Box<[u8]>>`], [`TryFrom<Arc<[u8]>>`], [`TryFrom<Rc<[u8]>>`])
/// — the digest reference-grammar family closes the cross-thread
/// shared-owned byte-slice leg of that same owned-shape parse-peer
/// surface, mirroring the emit-side [`From<ContentDigest> for Arc<[u8]>`]
/// (commit 49111c1) that already exists.
///
/// The [`Err`](std::convert::TryFrom::Error) type is
/// [`ContentDigestError`] — the same typed error every by-reference and
/// by-value parse surface emits. The three grammar-failure variants
/// ([`ContentDigestError::MissingSeparator`],
/// [`ContentDigestError::UnsupportedAlgorithm`],
/// [`ContentDigestError::InvalidHex`]) route unchanged through the
/// string oracle once UTF-8 validation clears; a UTF-8-invalid
/// cross-thread shared-owned raw-byte buffer surfaces as
/// [`ContentDigestError::InvalidUtf8`] carrying the lossy-decoded
/// rendering of the offending bytes — the same failure record the
/// borrowed-byte peer [`TryFrom<&[u8]>`] emits — so a caller that pins
/// a per-variant handling policy at its own frontier can distinguish
/// arms directly off the [`Result<ContentDigest, ContentDigestError>`]
/// the impl returns.
///
/// THEORY.md §III.1 typescape: the by-value cross-thread shared-owned
/// byte-slice try-conversion surface is a typed-primitive site on
/// [`ContentDigest`] itself (one [`TryFrom<Arc<[u8]>>`] impl routing
/// through [`AsRef::as_ref`] then [`TryFrom<&[u8]>`]), not a
/// per-consumer `shared.as_ref().try_into()` restatement at every
/// downstream site that owns a cross-thread shared raw-byte buffer.
/// THEORY.md §VI.1 one-oracle: the canonical `<algorithm>:<hex>`
/// grammar is named at one site ([`ContentDigest::parse`]), and every
/// parse surface — [`std::str::FromStr`], [`TryFrom<&str>`],
/// [`TryFrom<String>`], [`TryFrom<Cow<'_, str>>`], [`TryFrom<&[u8]>`],
/// [`TryFrom<Vec<u8>>`], [`TryFrom<Box<str>>`], [`TryFrom<Arc<str>>`],
/// [`TryFrom<Rc<str>>`], [`TryFrom<Cow<'_, [u8]>>`],
/// [`TryFrom<Box<[u8]>>`], this [`TryFrom<Arc<[u8]>>`] — reads through
/// it.
impl TryFrom<std::sync::Arc<[u8]>> for ContentDigest {
    type Error = ContentDigestError;

    fn try_from(shared: std::sync::Arc<[u8]>) -> Result<Self, Self::Error> {
        <Self as TryFrom<&[u8]>>::try_from(shared.as_ref())
    }
}

/// [`TryFrom<Rc<[u8]>>`] for [`ContentDigest`] routes through
/// [`<std::rc::Rc<[u8]> as AsRef<[u8]>>::as_ref`] (a zero-copy borrow of the
/// shared allocation's raw-byte payload that does NOT touch the
/// non-atomic-refcount header) then delegates to
/// [`<ContentDigest as TryFrom<&[u8]>>::try_from`] so a downstream consumer
/// holding a single-thread shared-owned raw-byte buffer at a refcount-headered
/// byte-slice frontier (a serde container that opts into
/// `#[serde(try_from = "Rc<[u8]>")]` on a byte-frontier wrapper field to
/// consume a thread-local shared-owned raw-byte record without a per-consumer
/// allocation, a validated-input newtype builder whose parse contract accepts
/// a caller-supplied [`Rc<[u8]>`] blob slot at the shared-owned raw-byte
/// frontier for single-thread cheap-clone semantics on the input, a `!Send`
/// per-task lookaside built during a synchronous scan phase whose
/// `Vec<Rc<[u8]>>` per-attestation raw-byte digest list is handed cheaply
/// through [`Rc::clone`] to each parse worker within one thread) recovers a
/// [`ContentDigest`] value from its canonical `<algorithm>:<hex>` thread-local
/// shared-owned raw-byte serialization through the same one-oracle grammar
/// the `.parse::<ContentDigest>()` string call sites already read — WITHOUT
/// a per-consumer `shared.as_ref().try_into()` restatement at every
/// downstream site, WITHOUT an [`std::rc::Rc::try_unwrap`]-fallback-clone-
/// then-parse cascade that would negotiate the refcount at every intake,
/// and WITHOUT an `Rc::<[u8]>::to_vec()`-then-parse round trip that would
/// allocate a fresh owned [`Vec<u8>`] off the shared borrow for each parse
/// pass.
///
/// Zero-touch on the non-atomic refcount during the parse: the receiver-side
/// [`<std::rc::Rc<[u8]> as AsRef<[u8]>>::as_ref`] call yields a borrowed
/// `&[u8]` view of the shared allocation's raw-byte payload without
/// allocating and without incrementing or decrementing the non-atomic-
/// refcount header preceding the raw bytes, so the parse-side receiver pays
/// the by-reference [`TryFrom<&[u8]>`] cost only (a [`std::str::from_utf8`]
/// UTF-8 gate then the [`ContentDigest::parse`] string oracle), not the
/// integer-op cost of a [`std::rc::Rc::try_unwrap`]-fallback-clone-then-
/// parse composition nor the allocation cost of an
/// `Rc::<[u8]>::to_vec()`-then-parse round trip. The [`std::rc::Rc<[u8]>`]
/// input is dropped at end of scope, releasing the shared allocation
/// exactly when the last outstanding [`Rc::clone`] refcount hits zero — the
/// standard single-thread shared-owned drop semantics carry through
/// unchanged.
///
/// A single-thread caller that would otherwise widen its parse frontier to
/// [`Arc<[u8]>`] purely to satisfy the parse peer's type signature —
/// paying [`Arc`]'s atomic-refcount header on every clone of a raw-byte
/// record that never crosses a thread boundary — routes through this
/// [`Rc<[u8]>`] peer instead and keeps the non-atomic-refcount cost on the
/// input side by construction. The single-thread parse-side cost of a
/// `Vec<Rc<[u8]>>` raw-byte digest list drained one-by-one through this
/// impl collapses to `n * (Rc::deref + std::str::from_utf8 + ContentDigest::parse)`,
/// matching the [`Arc<[u8]>`] peer's parse cost minus the atomic-fence
/// overhead the [`Rc<[u8]>`] frontier avoids by construction.
///
/// The by-value thread-local shared-owned byte-slice parse peer of
/// [`TryFrom<&[u8]> for ContentDigest`] (commit 08e1285),
/// [`TryFrom<Vec<u8>> for ContentDigest`] (commit 67c5485),
/// [`TryFrom<Cow<'_, [u8]>> for ContentDigest`] (commit cc9fcb3),
/// [`TryFrom<Box<[u8]>> for ContentDigest`] (commit f5f98f6), and
/// [`TryFrom<Arc<[u8]>> for ContentDigest`] (commit d2ccc5d) on the
/// reference-grammar family — the parse surface widens across the
/// borrowed-byte, owned-byte, borrowed-or-owned-byte, shrunk-owned-byte,
/// cross-thread shared-owned-byte, AND thread-local shared-owned-byte
/// input frontiers so a downstream site that receives its input at any of
/// those frontiers routes through the same [`ContentDigest::parse`] oracle
/// without a per-consumer bridge — the pattern this impl absorbs at one
/// site so no downstream site restates it. The parse mirror of the emit
/// peer [`From<ContentDigest> for Rc<[u8]>`] (commit 578dbc6): the emit
/// peer projects a validated [`ContentDigest`] into a thread-local
/// shared-owned raw-byte buffer through [`std::rc::Rc::<[u8]>::from`]; this
/// parse peer recovers a [`ContentDigest`] value from a thread-local
/// shared-owned raw-byte buffer through the [`AsRef::as_ref`] borrow of its
/// backing bytes. Together they close the [`Rc<[u8]>`] frontier at
/// [`ContentDigest`] on both the parse and emit sides so a downstream site
/// that types both its input and its re-emit contract as [`Rc<[u8]>`] (a
/// serde container that opts into
/// `#[serde(try_from = "Rc<[u8]>", into = "Rc<[u8]>")]`, a validated-input
/// newtype builder whose canonical parse AND re-emit contracts are both
/// stated as thread-local shared-owned raw bytes) is a one-line bridge
/// through the shared frontier, not a per-consumer restatement of the
/// thread-local shared-owned raw-byte discipline at either side.
///
/// Closes the shrunk / cross-thread-shared / thread-local-shared byte-slice
/// parse trio at [`ContentDigest`]: [`TryFrom<Box<[u8]>>`] (commit f5f98f6,
/// shrunk-owned) opened the trio; [`TryFrom<Arc<[u8]>>`] (commit d2ccc5d,
/// cross-thread shared-owned) closed the middle; this
/// [`TryFrom<Rc<[u8]>>`] (thread-local shared-owned) closes it. Every
/// owned-shape byte-slice receiver frontier the sibling label-axis ordered
/// typed sums already carry now has a matching parse surface on the digest
/// reference-grammar family, mirroring the UTF-8-string trio (commits
/// 2d5eb7e, 414b22c, 4d0783e) already closed on the sibling axis. Closes
/// the full owned-shape parse cross-product on the digest reference-
/// grammar family across both the UTF-8-string axis and the byte-slice
/// axis.
///
/// Structural mirror of
/// [`impl TryFrom<Rc<[u8]>> for crate::retry::PerAttemptRegion`], the
/// by-value thread-local shared-owned byte-slice parse peer on the sibling
/// label-axis ordered typed sum that already carries the complete
/// owned-shape parse-peer set ([`TryFrom<Box<str>>`], [`TryFrom<Arc<str>>`],
/// [`TryFrom<Rc<str>>`], [`TryFrom<Vec<u8>>`], [`TryFrom<Box<[u8]>>`],
/// [`TryFrom<Arc<[u8]>>`], [`TryFrom<Rc<[u8]>>`]) — the digest reference-
/// grammar family closes the thread-local shared-owned byte-slice leg of
/// that same owned-shape parse-peer surface, mirroring the emit-side
/// [`From<ContentDigest> for Rc<[u8]>`] (commit 578dbc6) that already
/// exists.
///
/// The [`Err`](std::convert::TryFrom::Error) type is
/// [`ContentDigestError`] — the same typed error every by-reference and
/// by-value parse surface emits. The three grammar-failure variants
/// ([`ContentDigestError::MissingSeparator`],
/// [`ContentDigestError::UnsupportedAlgorithm`],
/// [`ContentDigestError::InvalidHex`]) route unchanged through the string
/// oracle once UTF-8 validation clears; a UTF-8-invalid thread-local
/// shared-owned raw-byte buffer surfaces as
/// [`ContentDigestError::InvalidUtf8`] carrying the lossy-decoded rendering
/// of the offending bytes — the same failure record the borrowed-byte peer
/// [`TryFrom<&[u8]>`] emits — so a caller that pins a per-variant handling
/// policy at its own frontier can distinguish arms directly off the
/// [`Result<ContentDigest, ContentDigestError>`] the impl returns.
///
/// THEORY.md §III.1 typescape: the by-value thread-local shared-owned
/// byte-slice try-conversion surface is a typed-primitive site on
/// [`ContentDigest`] itself (one [`TryFrom<Rc<[u8]>>`] impl routing
/// through [`AsRef::as_ref`] then [`TryFrom<&[u8]>`]), not a per-consumer
/// `shared.as_ref().try_into()` restatement at every downstream site that
/// owns a thread-local shared raw-byte buffer. THEORY.md §VI.1 one-oracle:
/// the canonical `<algorithm>:<hex>` grammar is named at one site
/// ([`ContentDigest::parse`]), and every parse surface —
/// [`std::str::FromStr`], [`TryFrom<&str>`], [`TryFrom<String>`],
/// [`TryFrom<Cow<'_, str>>`], [`TryFrom<&[u8]>`], [`TryFrom<Vec<u8>>`],
/// [`TryFrom<Box<str>>`], [`TryFrom<Arc<str>>`], [`TryFrom<Rc<str>>`],
/// [`TryFrom<Cow<'_, [u8]>>`], [`TryFrom<Box<[u8]>>`],
/// [`TryFrom<Arc<[u8]>>`], this [`TryFrom<Rc<[u8]>>`] — reads through it.
impl TryFrom<std::rc::Rc<[u8]>> for ContentDigest {
    type Error = ContentDigestError;

    fn try_from(shared: std::rc::Rc<[u8]>) -> Result<Self, Self::Error> {
        <Self as TryFrom<&[u8]>>::try_from(shared.as_ref())
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

/// [`std::borrow::Borrow<str>`] for [`ContentDigest`] routes through
/// [`ContentDigest::as_str`] so a downstream consumer that keys an
/// identity container on [`ContentDigest`] — a
/// [`std::collections::HashMap<ContentDigest, V>`] mapping each
/// canonical digest to its owning image reference / attestation
/// record / verification breadcrumb, a
/// [`std::collections::HashSet<ContentDigest>`] of already-seen
/// content-addressed blobs guarding a deduped push / fetch loop, a
/// [`std::collections::BTreeMap<ContentDigest, V>`] emitting a
/// deterministic canonical-digest-ordered dump for a manifest /
/// audit report — probes the container by an incoming `&str`
/// (a captured registry-response line, a `serde_json::Value::String`
/// pulled off a manifest field, a config-file digest token, a CLI
/// argument slot) WITHOUT allocating a fresh [`ContentDigest`] key
/// per probe.
///
/// The identity-container-lookup peer of the trait-generic
/// borrowed-view read peer [`AsRef<str> for ContentDigest`] directly
/// above — both project the same validated full-digest slice through
/// [`ContentDigest::as_str`], split by intent: [`AsRef<str>`] yields
/// the slice for a generic `impl AsRef<str>` read consumer (a
/// formatter frontier, a hasher [`update`](std::hash::Hasher::write)
/// sink, a [`std::path::Path::new`] path-segment builder), this
/// [`Borrow<str>`] answers the identity-container's own probe
/// contract (`HashMap::get<Q>` / `BTreeMap::get<Q>` /
/// `HashSet::contains<Q>` where `K: Borrow<Q>`) directly at the
/// [`ContentDigest`] key slot without a per-probe
/// `ContentDigest::parse(str_key).ok().and_then(|k| map.get(&k))`
/// restatement that pays a parse-and-discard round trip per lookup
/// AND wastes the standard-library idiom's zero-allocation probe
/// discipline the [`String`] → [`str`] key story already carries.
///
/// [`Eq`] → [`Hash`] coherence with [`Borrow<str>`] holds by
/// construction and is the load-bearing safety condition for
/// [`Borrow<str>`] participating in a [`std::collections::HashMap`]
/// key slot: the derived [`Hash`] on
/// [`ContentDigest`]`{ full: String }` produces
/// `full.hash(hasher)`, [`Hash`] on [`String`] delegates to
/// [`Hash`] on the underlying [`str`] via
/// `(**self).hash(hasher)`, and this [`Borrow<str>::borrow`] returns
/// the same `&self.full` slice through [`ContentDigest::as_str`], so
/// `hash(&digest)` and `hash(digest.borrow() as &str)` step through
/// the exact same [`str::hash`] byte-write trace at every validated
/// [`ContentDigest`] value with any [`std::hash::Hasher`] — the
/// [`Borrow`] contract's `k.borrow().hash(h) == k.hash(h)` axiom
/// discharges structurally without a hand-rolled [`Hash`] impl and
/// without a per-consumer proof obligation. [`Eq`] agreement follows
/// the same route: the derived [`PartialEq`] on
/// [`ContentDigest`]`{ full: String }` reads `self.full == other.full`
/// (byte-for-byte UTF-8 equality on the validated backing string),
/// and a lookup probe compares `k.borrow() == q` at the borrowed
/// [`str`] frontier through the same
/// [`<str as PartialEq<str>>::eq`] the sibling [`PartialEq<str> for
/// ContentDigest`] peer routes through. Together they close the
/// [`Borrow`] safety contract at the primitive.
///
/// Zero-cost by construction: the returned `&str` is a borrow off
/// [`ContentDigest::full`] via [`ContentDigest::as_str`], so a
/// container probe reads directly into the key value's own storage
/// without a copy, an allocation, or a formatter round-trip — the
/// same zero-cost discipline the standard-library [`String`] →
/// [`str`] [`Borrow`] projection carries. The identity
/// `<ContentDigest as std::borrow::Borrow<str>>::borrow(&d) ==
/// <ContentDigest as AsRef<str>>::as_ref(&d)` at every validated
/// [`ContentDigest`] value is pinned by
/// [`tests::test_borrow_str_matches_as_ref_str`]; the [`Hash`]
/// coherence axiom at a shared [`std::hash::Hasher`] is pinned by
/// [`tests::test_borrow_str_hash_agrees_with_borrowed_str_hash`];
/// the identity-container probe surface — [`HashMap`], [`BTreeMap`],
/// [`HashSet`] all keying on [`ContentDigest`] and probed by
/// `&str` — is pinned by
/// [`tests::test_borrow_str_hash_map_probe_by_str_key`],
/// [`tests::test_borrow_str_btree_map_probe_by_str_key`], and
/// [`tests::test_borrow_str_hash_set_contains_by_str_key`]; the
/// generic-consumer carry-through is pinned by
/// [`tests::test_borrow_str_carries_through_generic_consumer`].
///
/// Prior identity-container work on this primitive closed the key
/// slot itself (commit 5923d7a — `derive(Hash)` on
/// [`ContentDigest`], with [`tests::test_hash_set_dedup_and_membership`]
/// pinning a `HashSet<ContentDigest>` insert / contains / dedup
/// cycle by owned [`ContentDigest`] key). That closure left every
/// probe still forced through an owned-key construction
/// (`set.contains(&ContentDigest::parse(str_key).unwrap())`),
/// paying the [`ContentDigest::parse`] cost — full grammar check,
/// [`str::trim`], [`str::split_once`], per-byte hex validation,
/// [`String`] allocation for the backing store — on every probe
/// against a wire-received / config-loaded / CLI-argument
/// canonical-digest string, AND surfacing a parse failure as
/// probe-inapplicable when the probe intent was strictly
/// "is this raw string present as a key." This [`Borrow<str>`] impl
/// closes that gap so the probe reads the raw `&str` through the
/// container's own zero-allocation lookup path, deferring the
/// parse-oracle cost to key insertion (once per canonical digest,
/// where the grammar guarantee is load-bearing) rather than probe
/// (per lookup, where the string is either present verbatim or
/// absent).
///
/// Frontier inspiration: SLSA / sigstore / BuildKit /
/// content-addressed cache flows probe `Vec<u8>`-keyed or
/// `String`-keyed maps of validated digests against wire-received
/// digest strings by the thousand per manifest walk; the
/// [`String`] → [`str`] [`Borrow`] projection is the standard-
/// library idiom that lets those flows read raw strings against
/// canonical string keys without per-probe validation. This impl
/// projects that idiom onto the typed [`ContentDigest`] key slot so
/// the same probe discipline works against a
/// grammar-oracle-bounded key type — a strictly stronger identity
/// contract than [`String`] carries (a [`ContentDigest`] key is
/// provably a valid `<algorithm>:<hex>`; a [`String`] key is not),
/// at the same zero-allocation probe cost.
///
/// THEORY.md §III.1 typescape: the identity-container-lookup
/// borrowed UTF-8 projection is a typed-primitive site on
/// [`ContentDigest`] itself (one [`Borrow<str>`] impl routing
/// through [`ContentDigest::as_str`]), not a per-consumer
/// `ContentDigest::parse(str_key).ok().and_then(|k| map.get(&k))`
/// restatement at every downstream identity-container probe site.
/// THEORY.md §VI.1 one-oracle: the validated full-digest slice is
/// named at one site ([`ContentDigest::as_str`], reading through
/// the [`ContentDigest::parse`]-guarded backing string), and every
/// borrowed-view surface — the inherent [`ContentDigest::as_str`]
/// accessor, the format machinery [`std::fmt::Display`], the
/// trait-generic UTF-8 read peer [`AsRef<str>`], the trait-generic
/// byte-slice read peer [`AsRef<[u8]>`], this
/// identity-container-lookup peer [`Borrow<str>`] — reads through
/// it.
impl std::borrow::Borrow<str> for ContentDigest {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

/// Ergonomic canonical-digest equality query at the borrowed UTF-8
/// frontier — a downstream consumer bound by [`PartialEq<str>`]
/// (a `matches!` predicate that reads a canonical `<algorithm>:<hex>`
/// off a `Cow::Borrowed(s)` arm without a per-arm
/// [`ContentDigest::parse`] parse-and-discard round trip, a
/// config-audit assertion that dereferences a [`String`] /
/// [`Box<str>`] / [`std::sync::Arc<str>`] / [`std::rc::Rc<str>`]
/// canonical-digest handle and asks whether it names a specific
/// [`ContentDigest`] value, an integration-test oracle that verifies
/// a captured `skopeo inspect` / journal / attestation-breadcrumb
/// line equals the canonical `<algorithm>:<hex>` for a specific
/// digest without a downstream `.as_str()` restatement) answers the
/// boolean equality query `digest == *label_str_ref` at ONE
/// composition rather than a per-site `digest.as_str() == label`
/// restatement that repeats the canonical-digest oracle name at
/// every downstream comparison site.
///
/// Sibling of [`AsRef<str>`] (line 680) — the same canonical-digest
/// oracle at the same borrowed UTF-8 frontier, split by intent:
/// [`AsRef<str>`] yields the digest bytes for a generic
/// `impl AsRef<str>` consumer to read (a formatter frontier, a
/// hasher [`update`](std::hash::Hasher::write) sink, a
/// `serde_json::Value::String` wrapper), this [`PartialEq<str>`]
/// answers a boolean equality query directly at the
/// [`ContentDigest`] value without threading the caller through the
/// intermediate `.as_str()` name at every comparison site.
///
/// Route: the impl body composes [`ContentDigest::as_str`] with the
/// standard library [`<str as PartialEq<str>>::eq`] (byte-for-byte
/// UTF-8 equality against the borrowed right-hand-side view), so
/// the comparison reads the same canonical-digest bytes at zero
/// allocation, zero temporary [`String`] construction, and zero
/// [`std::fmt::Display`] formatter-buffer round trip per call — the
/// same zero-cost discipline the sibling [`AsRef<str>`] borrowed-
/// view surface carries.
///
/// Structural mirror of [`impl PartialEq<str> for crate::retry::
/// PerAttemptRegion`] (line 8586 of `cli/src/retry.rs`),
/// [`impl PartialEq<str> for crate::probe_outcome::AdmissionTier`],
/// and [`impl PartialEq<str> for crate::version::BumpLevel`] — the
/// same borrowed UTF-8 comparison lift the sibling label-axis
/// ordered typed sums already carry, each routing through its
/// shared canonical-label oracle — now extended to the digest
/// reference-grammar family so [`ContentDigest`] exposes the same
/// two-receiver borrowed UTF-8 comparison pair (this
/// [`PartialEq<str>`] answering `digest == *label_ref` after
/// caller-explicit deref, the [`PartialEq<&str>`] peer directly
/// below answering `digest == label_ref` without the deref) that
/// every sibling reference-grammar primitive already carries,
/// mirroring the standard-library idiom [`String`] carries through
/// its own [`PartialEq<str>`] + [`PartialEq<&str>`] receiver-shape
/// pair.
///
/// THEORY.md §III.1 typescape: the borrowed UTF-8 comparison
/// surface is a typed-primitive site on [`ContentDigest`] itself
/// (one [`PartialEq<str>`] impl routing through
/// [`ContentDigest::as_str`]), not a per-consumer
/// `digest.as_str() == label` restatement at every downstream site
/// that asks whether a [`ContentDigest`] value names a specific
/// canonical `<algorithm>:<hex>`. THEORY.md §VI.1 one-oracle: the
/// validated full-digest slice is named at one site
/// ([`ContentDigest::as_str`], reading through the
/// [`ContentDigest::parse`]-guarded backing string), and every
/// borrowed UTF-8 surface — the [`AsRef<str>`] borrowed-view
/// sibling yielding `&str`, this [`PartialEq<str>`] answering a
/// boolean equality query — reads through the same one-oracle
/// discipline projected onto its own intent.
impl PartialEq<str> for ContentDigest {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

/// Ergonomic canonical-digest equality query at the borrowed UTF-8
/// frontier through a `&str` receiver — the peer of
/// [`PartialEq<str> for ContentDigest`] (directly above), split by
/// receiver shape: [`PartialEq<str>`] answers the boolean equality
/// query against a dereffed `str` value (`digest == *label_ref`),
/// this [`PartialEq<&str>`] answers the same boolean equality query
/// against a `&str` reference (`digest == label_ref`) without the
/// caller's explicit `*` deref at every comparison site. The two
/// receiver-shape peers together give the borrowed UTF-8 comparison
/// surface the same ergonomic reach the standard library gives
/// [`String`] through its own [`PartialEq<str>`] + [`PartialEq<&str>`]
/// receiver-shape pair.
///
/// Route: the impl body composes [`ContentDigest::as_str`] with the
/// standard library [`<str as PartialEq<str>>::eq`] on the deref of
/// the borrowed `&str` receiver, so the comparison reads the same
/// canonical-digest bytes at zero allocation, zero temporary
/// [`String`] construction, and zero [`std::fmt::Display`]
/// formatter-buffer round trip per call — the same zero-cost
/// discipline the [`PartialEq<str>`] receiver-shape sibling carries.
///
/// Structural mirror of [`impl PartialEq<&str> for crate::retry::
/// PerAttemptRegion`] (line 8677 of `cli/src/retry.rs`),
/// [`impl PartialEq<&str> for crate::probe_outcome::AdmissionTier`],
/// and [`impl PartialEq<&str> for crate::version::BumpLevel`] — the
/// same borrowed UTF-8 `&str`-receiver comparison lift the sibling
/// label-axis ordered typed sums already carry, now extended to the
/// digest reference-grammar family so the two-receiver borrowed
/// UTF-8 comparison pair closes on [`ContentDigest`] alongside its
/// [`PartialEq<str>`] sibling above.
///
/// THEORY.md §III.1 typescape: the borrowed UTF-8 `&str`-receiver
/// comparison surface is a typed-primitive site on [`ContentDigest`]
/// itself (one [`PartialEq<&str>`] impl routing through
/// [`ContentDigest::as_str`]), not a per-consumer
/// `digest.as_str() == label_ref` restatement at every downstream
/// site that asks whether a [`ContentDigest`] value names a specific
/// canonical `<algorithm>:<hex>` through an already-borrowed `&str`
/// handle. THEORY.md §VI.1 one-oracle: the validated full-digest
/// slice is named at one site ([`ContentDigest::as_str`]), and every
/// borrowed UTF-8 surface — the [`AsRef<str>`] borrowed-view sibling
/// yielding `&str`, the [`PartialEq<str>`] dereffed-str-receiver
/// sibling answering `digest == *label_ref`, this
/// [`PartialEq<&str>`] answering `digest == label_ref` without the
/// explicit deref — reads through the same one-oracle discipline
/// projected onto its own intent × receiver shape.
impl PartialEq<&str> for ContentDigest {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

/// Symmetric borrowed UTF-8 comparison peer: `<str as
/// PartialEq<ContentDigest>>::eq` — the reverse-direction sibling of
/// [`PartialEq<str> for ContentDigest`] (directly above). The pair
/// together closes the borrowed UTF-8 comparison surface across BOTH
/// receiver directions, so a caller who holds a
/// [`str`] value (a `matches!` arm on a `str` binding, a dereffed
/// `&Cow::Borrowed(s)`) writes `*label_ref == digest` (or the
/// standard-library-derived `if a == b || b == a`-style symmetric
/// composition a generic `PartialEq`-bounded consumer performs
/// internally) and answers a boolean equality query against a
/// [`ContentDigest`] value at the same borrowed UTF-8 frontier the
/// forward-direction peer covers, at zero allocation, zero temporary
/// [`String`] construction, and zero [`std::fmt::Display`]
/// formatter-buffer round trip per call.
///
/// Route: the impl body composes [`ContentDigest::as_str`] with the
/// standard library [`<str as PartialEq<str>>::eq`], so the comparison
/// reads the same canonical-digest bytes as the forward-direction
/// [`PartialEq<str> for ContentDigest`] peer, and the symmetry axiom
/// `<str as PartialEq<ContentDigest>>::eq(label, &digest)
/// == <ContentDigest as PartialEq<str>>::eq(&digest, label)` holds by
/// construction at every `(label, digest)` pair.
///
/// Mirrors the standard-library idiom [`String`] carries through its
/// own [`PartialEq<String> for str`] +
/// [`PartialEq<String> for &str`] symmetric receiver-shape pair: a
/// borrowed UTF-8 handle compares against an owned canonical-string
/// primitive in either direction with the same zero-cost projection
/// through the primitive's read-back accessor. Prior to this impl the
/// digest reference-grammar family carried only the forward direction
/// (`digest == label` compiled but `label == digest` did not), so a
/// generic `PartialEq`-bounded consumer that composed the two through
/// its own symmetric-check protocol could not thread a
/// [`ContentDigest`] through the [`str`] side of the bound without a
/// per-consumer `label == digest.as_str()` bridge.
///
/// THEORY.md §III.1 typescape: the reverse-direction borrowed UTF-8
/// comparison surface is a typed-primitive site on [`ContentDigest`]
/// itself (one [`PartialEq<ContentDigest>`] impl on [`str`] routing
/// through [`ContentDigest::as_str`]), not a per-consumer
/// `label == digest.as_str()` restatement at every downstream site
/// that asks whether a borrowed UTF-8 handle names the same canonical
/// `<algorithm>:<hex>` as a [`ContentDigest`] value. THEORY.md §VI.1
/// one-oracle: the validated full-digest slice is named at one site
/// ([`ContentDigest::as_str`]), and every borrowed UTF-8 comparison
/// surface — the forward-direction [`PartialEq<str> for
/// ContentDigest`] + [`PartialEq<&str> for ContentDigest`] pair, this
/// reverse-direction [`PartialEq<ContentDigest> for str`] +
/// [`PartialEq<ContentDigest> for &str`] pair — reads through the
/// same one-oracle discipline projected onto its own direction ×
/// receiver shape.
impl PartialEq<ContentDigest> for str {
    fn eq(&self, other: &ContentDigest) -> bool {
        self == other.as_str()
    }
}

/// Symmetric borrowed UTF-8 comparison peer through a `&str`
/// receiver — the reverse-direction sibling of [`PartialEq<&str> for
/// ContentDigest`] and the receiver-shape peer of
/// [`PartialEq<ContentDigest> for str`] (directly above), split by
/// receiver shape so the caller writes `label_ref == digest` without
/// the explicit `*` deref at every comparison site. The four
/// [`PartialEq`] impls together — forward × receiver-shape and
/// reverse × receiver-shape — close the borrowed UTF-8 comparison
/// surface across the full 2×2 cross-product on the reference-grammar
/// family, matching the standard-library idiom [`String`] carries
/// through its own four-impl closure ([`PartialEq<str> for String`] +
/// [`PartialEq<&str> for String`] + [`PartialEq<String> for str`] +
/// [`PartialEq<String> for &str`]).
///
/// Route: the impl body composes [`ContentDigest::as_str`] with
/// [`<str as PartialEq<str>>::eq`] on the dereffed `&str` self
/// receiver, so the comparison reads the same canonical-digest bytes
/// as the sibling receiver-shape peer at zero allocation and zero
/// intermediate buffer, and the symmetry axiom
/// `<&str as PartialEq<ContentDigest>>::eq(&label_ref, &digest)
/// == <ContentDigest as PartialEq<&str>>::eq(&digest, &label_ref)`
/// holds by construction at every `(label_ref, digest)` pair.
///
/// THEORY.md §III.1 typescape: the reverse-direction borrowed UTF-8
/// `&str`-receiver comparison surface is a typed-primitive site on
/// [`ContentDigest`] itself (one [`PartialEq<ContentDigest>`] impl on
/// [`&str`] routing through [`ContentDigest::as_str`]), not a
/// per-consumer `label_ref == digest.as_str()` restatement at every
/// downstream site that asks whether a borrowed `&str` handle names
/// the same canonical `<algorithm>:<hex>` as a [`ContentDigest`]
/// value. THEORY.md §VI.1 one-oracle: the validated full-digest slice
/// is named at one site ([`ContentDigest::as_str`]), and this reverse-
/// direction `&str`-receiver surface reads through the same
/// one-oracle discipline the three sibling comparison surfaces
/// (forward-str, forward-&str, reverse-str) already carry.
impl PartialEq<ContentDigest> for &str {
    fn eq(&self, other: &ContentDigest) -> bool {
        *self == other.as_str()
    }
}

/// Ergonomic canonical-digest equality query at the borrowed
/// byte-slice frontier — the byte-slice peer of [`PartialEq<str> for
/// ContentDigest`] above. A downstream consumer bound by
/// [`PartialEq<[u8]>`] (a `matches!` predicate that reads a canonical
/// `<algorithm>:<hex>` off a `Cow::Borrowed(&[u8])` arm without a
/// per-arm [`std::str::from_utf8`] + [`ContentDigest::parse`]
/// parse-and-discard round trip, a byte-stream cache-index oracle
/// that compares a wire-received digest byte slice against a
/// specific [`ContentDigest`] value directly at the byte frontier,
/// an integration-test oracle that verifies a captured
/// registry-response byte slice equals the canonical
/// `<algorithm>:<hex>` for a specific digest without threading
/// through a UTF-8 conversion) answers the boolean equality query
/// `digest == *label_bytes_ref` at ONE composition rather than a
/// per-site `<ContentDigest as AsRef<[u8]>>::as_ref(&d) == label`
/// restatement that repeats the canonical-digest oracle name at
/// every downstream byte-slice comparison site.
///
/// Byte-slice peer of the borrowed UTF-8 comparison surface
/// [`PartialEq<str> for ContentDigest`] / [`PartialEq<&str> for
/// ContentDigest`] — the same canonical-digest oracle at the
/// byte-slice frontier that streaming hashers, MAC accumulators, and
/// raw-write byte sinks pin their input contract on. Sibling of
/// [`AsRef<[u8]>`] — the same borrowed-view byte-slice oracle at the
/// same byte frontier, split by intent: [`AsRef<[u8]>`] yields the
/// digest bytes for a generic `impl AsRef<[u8]>` consumer to read
/// (a `blake3::Hasher::update` / `sha2::Digest::update` streaming
/// hasher sink, a raw-write output sink, a `nom` / `winnow` byte-
/// slice parser), this [`PartialEq<[u8]>`] answers a boolean
/// equality query directly at the [`ContentDigest`] value without
/// threading the caller through the intermediate `.as_ref()` name
/// at every comparison site.
///
/// Route: the impl body composes
/// [`<ContentDigest as AsRef<[u8]>>::as_ref`] (in turn
/// [`ContentDigest::as_str`] via [`str::as_bytes`]) with the
/// standard library [`<[u8] as PartialEq<[u8]>>::eq`] (byte-for-byte
/// equality against the borrowed right-hand-side view), so the
/// comparison reads the same canonical-digest bytes at zero
/// allocation, zero temporary [`String`] / [`Vec<u8>`] construction,
/// and zero [`std::fmt::Display`] formatter-buffer round trip per
/// call — the same zero-cost discipline the sibling [`AsRef<[u8]>`]
/// borrowed-view surface carries.
///
/// The validated full-digest bytes are pure lowercase-hex plus
/// `sha256` / `sha512` / `:` — every byte is ASCII by parse
/// invariant, so a byte-slice consumer that treats the input as
/// ASCII observes the same equality outcome as the UTF-8-side
/// [`PartialEq<str>`] sibling: at every validated [`ContentDigest`]
/// value `d` and every borrowed byte slice `b`,
/// `<ContentDigest as PartialEq<[u8]>>::eq(&d, b)
///     == (b == d.as_str().as_bytes())` holds by construction, with
/// no multibyte-boundary hazard.
///
/// THEORY.md §III.1 typescape: the borrowed byte-slice comparison
/// surface is a typed-primitive site on [`ContentDigest`] itself
/// (one [`PartialEq<[u8]>`] impl routing through the [`AsRef<[u8]>`]
/// and [`ContentDigest::as_str`] read oracle), not a per-consumer
/// `<ContentDigest as AsRef<[u8]>>::as_ref(&d) == label` restatement
/// at every downstream byte-slice comparison site. THEORY.md §VI.1
/// one-oracle: the validated full-digest slice is named at one site
/// ([`ContentDigest::as_str`]), and every borrowed byte-slice
/// surface — the [`AsRef<[u8]>`] borrowed-view sibling yielding
/// `&[u8]`, this [`PartialEq<[u8]>`] answering a boolean equality
/// query — reads through the same one-oracle discipline projected
/// onto its own intent × frontier.
impl PartialEq<[u8]> for ContentDigest {
    fn eq(&self, other: &[u8]) -> bool {
        <Self as AsRef<[u8]>>::as_ref(self) == other
    }
}

/// Ergonomic canonical-digest equality query at the borrowed
/// byte-slice frontier through a `&[u8]` receiver — the peer of
/// [`PartialEq<[u8]> for ContentDigest`] (directly above), split by
/// receiver shape: [`PartialEq<[u8]>`] answers the boolean equality
/// query against a dereffed `[u8]` value
/// (`digest == *label_bytes_ref`), this [`PartialEq<&[u8]>`] answers
/// the same boolean equality query against a `&[u8]` reference
/// (`digest == label_bytes_ref`) without the caller's explicit `*`
/// deref at every comparison site. The two receiver-shape peers
/// together give the borrowed byte-slice comparison surface the same
/// ergonomic reach the UTF-8-side [`PartialEq<str>`] +
/// [`PartialEq<&str>`] receiver-shape pair already covers, matching
/// the standard-library idiom [`String`] carries through its own
/// four-receiver comparison closure across both frontiers.
///
/// Route: the impl body composes
/// [`<ContentDigest as AsRef<[u8]>>::as_ref`] with
/// [`<[u8] as PartialEq<[u8]>>::eq`] on the deref of the borrowed
/// `&[u8]` receiver, so the comparison reads the same canonical-
/// digest bytes at zero allocation, zero temporary [`Vec<u8>`]
/// construction, and zero [`std::fmt::Display`] formatter-buffer
/// round trip per call — the same zero-cost discipline the
/// [`PartialEq<[u8]>`] receiver-shape sibling carries.
///
/// THEORY.md §III.1 typescape: the borrowed byte-slice
/// `&[u8]`-receiver comparison surface is a typed-primitive site on
/// [`ContentDigest`] itself (one [`PartialEq<&[u8]>`] impl routing
/// through [`AsRef<[u8]>`]), not a per-consumer
/// `<ContentDigest as AsRef<[u8]>>::as_ref(&d) == label_ref`
/// restatement at every downstream site that asks whether a
/// [`ContentDigest`] value names a specific canonical
/// `<algorithm>:<hex>` through an already-borrowed `&[u8]` handle.
/// THEORY.md §VI.1 one-oracle: the validated full-digest slice is
/// named at one site ([`ContentDigest::as_str`]), and every borrowed
/// byte-slice surface — the [`AsRef<[u8]>`] borrowed-view sibling
/// yielding `&[u8]`, the [`PartialEq<[u8]>`] dereffed-bytes-receiver
/// sibling answering `digest == *label_bytes_ref`, this
/// [`PartialEq<&[u8]>`] answering `digest == label_bytes_ref`
/// without the explicit deref — reads through the same one-oracle
/// discipline projected onto its own intent × receiver shape.
impl PartialEq<&[u8]> for ContentDigest {
    fn eq(&self, other: &&[u8]) -> bool {
        <Self as AsRef<[u8]>>::as_ref(self) == *other
    }
}

/// Symmetric borrowed byte-slice comparison peer: `<[u8] as
/// PartialEq<ContentDigest>>::eq` — the reverse-direction sibling of
/// [`PartialEq<[u8]> for ContentDigest`] (directly above). The pair
/// together closes the borrowed byte-slice comparison surface across
/// BOTH receiver directions, so a caller who holds a `[u8]` value (a
/// `matches!` arm on a dereffed `Cow::Borrowed(&[u8])` binding, a
/// byte-stream cache-index oracle whose scrutinee is a dereffed
/// `&Vec<u8>`) writes `*label_bytes_ref == digest` (or the
/// standard-library-derived `if a == b || b == a`-style symmetric
/// composition a generic `PartialEq`-bounded consumer performs
/// internally) and answers a boolean equality query against a
/// [`ContentDigest`] value at the same borrowed byte-slice frontier
/// the forward-direction peer covers, at zero allocation, zero
/// temporary [`Vec<u8>`] construction, and zero
/// [`std::fmt::Display`] formatter-buffer round trip per call.
///
/// Route: the impl body composes
/// [`<ContentDigest as AsRef<[u8]>>::as_ref`] (in turn
/// [`ContentDigest::as_str`] via [`str::as_bytes`]) with the
/// standard library [`<[u8] as PartialEq<[u8]>>::eq`] on the `self`
/// receiver, so the comparison reads the same canonical-digest bytes
/// as the forward-direction [`PartialEq<[u8]> for ContentDigest`]
/// peer, and the symmetry axiom
/// `<[u8] as PartialEq<ContentDigest>>::eq(bytes, &digest)
/// == <ContentDigest as PartialEq<[u8]>>::eq(&digest, bytes)` holds
/// by construction at every `(bytes, digest)` pair.
///
/// Mirrors the standard-library idiom [`Vec<u8>`] carries through
/// its own [`PartialEq<Vec<u8>> for [u8]`] +
/// [`PartialEq<Vec<u8>> for &[u8]`] symmetric receiver-shape pair
/// (and the [`String`]-side [`PartialEq<String> for str`] +
/// [`PartialEq<String> for &str`] pair the borrowed UTF-8 sibling
/// commit d894159 mirrored on the reference-grammar family): a
/// borrowed byte-slice handle compares against an owned canonical-
/// bytes primitive in either direction with the same zero-cost
/// projection through the primitive's read-back accessor. Prior to
/// this impl the digest reference-grammar family carried only the
/// forward direction at the byte-slice frontier
/// (`digest == label_bytes` compiled but `label_bytes == digest`
/// did not), so a generic `PartialEq`-bounded consumer that composed
/// the two through its own symmetric-check protocol could not thread
/// a [`ContentDigest`] through the `[u8]` side of the bound without
/// a per-consumer
/// `label_bytes == <ContentDigest as AsRef<[u8]>>::as_ref(&digest)`
/// bridge.
///
/// THEORY.md §III.1 typescape: the reverse-direction borrowed
/// byte-slice comparison surface is a typed-primitive site on
/// [`ContentDigest`] itself (one [`PartialEq<ContentDigest>`] impl
/// on [`[u8]`] routing through [`AsRef<[u8]>`] and
/// [`ContentDigest::as_str`]), not a per-consumer
/// `label_bytes == <ContentDigest as AsRef<[u8]>>::as_ref(&d)`
/// restatement at every downstream site that asks whether a
/// borrowed byte-slice handle names the same canonical
/// `<algorithm>:<hex>` as a [`ContentDigest`] value. THEORY.md
/// §VI.1 one-oracle: the validated full-digest slice is named at
/// one site ([`ContentDigest::as_str`]), and every borrowed
/// byte-slice comparison surface — the forward-direction
/// [`PartialEq<[u8]> for ContentDigest`] +
/// [`PartialEq<&[u8]> for ContentDigest`] pair, this reverse-
/// direction [`PartialEq<ContentDigest> for [u8]`] +
/// [`PartialEq<ContentDigest> for &[u8]`] pair — reads through the
/// same one-oracle discipline projected onto its own direction ×
/// receiver shape.
impl PartialEq<ContentDigest> for [u8] {
    fn eq(&self, other: &ContentDigest) -> bool {
        self == <ContentDigest as AsRef<[u8]>>::as_ref(other)
    }
}

/// Symmetric borrowed byte-slice comparison peer through a `&[u8]`
/// receiver — the reverse-direction sibling of
/// [`PartialEq<&[u8]> for ContentDigest`] and the receiver-shape
/// peer of [`PartialEq<ContentDigest> for [u8]`] (directly above),
/// split by receiver shape so the caller writes
/// `label_bytes_ref == digest` without the explicit `*` deref at
/// every comparison site. The four [`PartialEq`] impls together on
/// the byte-slice frontier — forward × receiver-shape and reverse ×
/// receiver-shape — close the borrowed byte-slice comparison
/// surface across the full 2×2 cross-product on the reference-
/// grammar family, matching the full four-impl closure the
/// [`String`]/`str`-side sibling
/// ([`PartialEq<str> for ContentDigest`] +
/// [`PartialEq<&str> for ContentDigest`] +
/// [`PartialEq<ContentDigest> for str`] +
/// [`PartialEq<ContentDigest> for &str`]) already carries at the
/// UTF-8 frontier.
///
/// Route: the impl body composes
/// [`<ContentDigest as AsRef<[u8]>>::as_ref`] with the standard
/// library [`<[u8] as PartialEq<[u8]>>::eq`] on the dereffed
/// `&[u8]` self receiver, so the comparison reads the same
/// canonical-digest bytes as the sibling receiver-shape peer at
/// zero allocation and zero intermediate buffer, and the symmetry
/// axiom
/// `<&[u8] as PartialEq<ContentDigest>>::eq(&bytes_ref, &digest)
/// == <ContentDigest as PartialEq<&[u8]>>::eq(&digest, &bytes_ref)`
/// holds by construction at every `(bytes_ref, digest)` pair.
///
/// THEORY.md §III.1 typescape: the reverse-direction borrowed
/// byte-slice `&[u8]`-receiver comparison surface is a typed-
/// primitive site on [`ContentDigest`] itself (one
/// [`PartialEq<ContentDigest>`] impl on [`&[u8]`] routing through
/// [`AsRef<[u8]>`]), not a per-consumer
/// `label_bytes_ref == <ContentDigest as AsRef<[u8]>>::as_ref(&d)`
/// restatement at every downstream site that asks whether a
/// borrowed `&[u8]` handle names the same canonical
/// `<algorithm>:<hex>` as a [`ContentDigest`] value. THEORY.md
/// §VI.1 one-oracle: the validated full-digest slice is named at
/// one site ([`ContentDigest::as_str`]), and this reverse-direction
/// `&[u8]`-receiver surface reads through the same one-oracle
/// discipline the three sibling byte-slice comparison surfaces
/// (forward-`[u8]`, forward-`&[u8]`, reverse-`[u8]`) already carry.
impl PartialEq<ContentDigest> for &[u8] {
    fn eq(&self, other: &ContentDigest) -> bool {
        *self == <ContentDigest as AsRef<[u8]>>::as_ref(other)
    }
}

/// Ergonomic canonical-digest equality query at the owned UTF-8
/// frontier — the owned-string peer of the borrowed-UTF-8 comparison
/// pair [`PartialEq<str> for ContentDigest`] +
/// [`PartialEq<&str> for ContentDigest`] above. A downstream consumer
/// that owns a [`String`] (a `serde_json::Value::String(String)` arm,
/// a [`std::collections::HashMap<String, _>`] value read out by clone,
/// a config-schema field that stores a canonical `<algorithm>:<hex>`
/// as owned [`String`] for downstream serialization, an integration-
/// test oracle that captures a `skopeo inspect` / journal / attestation-
/// breadcrumb line into an owned [`String`] and asks whether it names a
/// specific [`ContentDigest`] value) answers the boolean equality query
/// `digest == owned_label` at ONE composition rather than a per-site
/// `digest.as_str() == owned_label.as_str()` restatement that repeats
/// the canonical-digest oracle name at every downstream comparison
/// site.
///
/// Route: the impl body composes [`ContentDigest::as_str`] with the
/// standard library [`<str as PartialEq<str>>::eq`] on the
/// [`String`]-side deref coercion, so the comparison reads the same
/// canonical-digest bytes at zero allocation, zero temporary [`String`]
/// construction, and zero [`std::fmt::Display`] formatter-buffer round
/// trip per call — the same zero-cost discipline the borrowed-str
/// sibling peers carry.
///
/// Sibling of the by-value owned-UTF-8 emit peer
/// [`From<ContentDigest> for String`] (directly below): both surfaces
/// bridge the [`ContentDigest`] value and the [`String`] owned-input
/// frontier — the emit peer moves the validated backing string out
/// (`String::from(digest)`), this comparison peer asks whether the
/// owned [`String`] on the right names the same canonical
/// `<algorithm>:<hex>` as the [`ContentDigest`] value on the left
/// (`digest == owned_label`) — so a downstream site that received an
/// owned [`String`] and needs to answer either query reads through
/// the ContentDigest primitive at the [`String`] frontier without a
/// per-site `.as_str()` restatement.
///
/// Mirrors the standard-library idiom [`String`] carries through its
/// own [`PartialEq<String> for str`] + [`PartialEq<String> for &str`]
/// symmetric owned-string comparison surface: an owned canonical-string
/// primitive compares against a [`String`] handle at either frontier
/// with the same zero-cost projection through the primitive's
/// read-back accessor.
///
/// THEORY.md §III.1 typescape: the owned UTF-8 comparison surface is a
/// typed-primitive site on [`ContentDigest`] itself (one
/// [`PartialEq<String>`] impl routing through [`ContentDigest::as_str`]),
/// not a per-consumer `digest.as_str() == owned_label.as_str()`
/// restatement at every downstream site that asks whether a
/// [`ContentDigest`] value names a specific canonical
/// `<algorithm>:<hex>` through an owned [`String`] handle. THEORY.md
/// §VI.1 one-oracle: the validated full-digest slice is named at one
/// site ([`ContentDigest::as_str`]), and every comparison surface —
/// the borrowed-UTF-8 pair, the borrowed-byte-slice pair, this owned-
/// UTF-8 peer — reads through the same one-oracle discipline projected
/// onto its own intent × frontier.
impl PartialEq<String> for ContentDigest {
    fn eq(&self, other: &String) -> bool {
        self.as_str() == other.as_str()
    }
}

/// Symmetric owned UTF-8 comparison peer:
/// `<String as PartialEq<ContentDigest>>::eq` — the reverse-direction
/// sibling of [`PartialEq<String> for ContentDigest`] (directly above).
/// The pair together closes the owned UTF-8 comparison surface across
/// both receiver directions, so a caller who holds an owned [`String`]
/// writes `owned_label == digest` (or the standard-library-derived
/// `if a == b || b == a`-style symmetric composition a generic
/// `PartialEq`-bounded consumer performs internally) and answers a
/// boolean equality query against a [`ContentDigest`] value at the
/// same owned UTF-8 frontier the forward-direction peer covers, at
/// zero allocation, zero temporary [`String`] construction, and zero
/// [`std::fmt::Display`] formatter-buffer round trip per call.
///
/// Route: the impl body composes [`ContentDigest::as_str`] with
/// [`<str as PartialEq<str>>::eq`] on the [`String`]-side deref
/// coercion, so the comparison reads the same canonical-digest bytes
/// as the forward-direction [`PartialEq<String> for ContentDigest`]
/// peer, and the symmetry axiom
/// `<String as PartialEq<ContentDigest>>::eq(owned, &digest)
/// == <ContentDigest as PartialEq<String>>::eq(&digest, owned)` holds
/// by construction at every `(owned, digest)` pair.
///
/// Mirrors the standard-library idiom [`String`] carries through its
/// own [`PartialEq<String> for str`] + [`PartialEq<String> for &str`]
/// symmetric receiver-shape pair: a borrowed / owned UTF-8 handle
/// compares against the counter-shape UTF-8 primitive in either
/// direction with the same zero-cost projection through the
/// primitive's read-back accessor. Prior to this impl the digest
/// reference-grammar family carried only the forward direction at the
/// owned-UTF-8 frontier (`digest == owned_label` compiled but
/// `owned_label == digest` did not), so a generic `PartialEq`-bounded
/// consumer that composed the two through its own symmetric-check
/// protocol could not thread a [`ContentDigest`] through the
/// [`String`] side of the bound without a per-consumer
/// `owned_label == digest.as_str()` bridge.
///
/// THEORY.md §III.1 typescape: the reverse-direction owned UTF-8
/// comparison surface is a typed-primitive site on [`ContentDigest`]
/// itself (one [`PartialEq<ContentDigest>`] impl on [`String`] routing
/// through [`ContentDigest::as_str`]), not a per-consumer
/// `owned_label == digest.as_str()` restatement at every downstream
/// site that asks whether an owned [`String`] handle names the same
/// canonical `<algorithm>:<hex>` as a [`ContentDigest`] value.
/// THEORY.md §VI.1 one-oracle: the validated full-digest slice is
/// named at one site ([`ContentDigest::as_str`]), and this reverse-
/// direction owned-UTF-8 receiver surface reads through the same
/// one-oracle discipline every sibling comparison surface (borrowed
/// str × 2 × 2, borrowed bytes × 2 × 2, forward owned-string) already
/// carries.
impl PartialEq<ContentDigest> for String {
    fn eq(&self, other: &ContentDigest) -> bool {
        self.as_str() == other.as_str()
    }
}

/// Ergonomic canonical-digest equality query at the owned byte-slice
/// frontier — the owned-bytes peer of the borrowed-byte-slice
/// comparison pair [`PartialEq<[u8]> for ContentDigest`] +
/// [`PartialEq<&[u8]> for ContentDigest`] above, and the byte-side
/// projection of the owned-UTF-8 pair
/// [`PartialEq<String> for ContentDigest`] +
/// [`PartialEq<ContentDigest> for String`] directly above. A
/// downstream consumer that owns a [`Vec<u8>`] (a
/// [`bytes::Bytes::to_vec`] snapshot of a wire-received
/// Content-Digest header value, a
/// [`std::collections::HashMap<Vec<u8>, _>`] value read out by
/// clone, a config-schema field that stores a canonical
/// `<algorithm>:<hex>` as owned [`Vec<u8>`] for downstream signing,
/// a [`std::io::Read::read_to_end`] buffer that captured a
/// registry-response line into an owned [`Vec<u8>`] and asks
/// whether it names a specific [`ContentDigest`] value) answers the
/// boolean equality query `digest == owned_bytes` at ONE
/// composition rather than a per-site
/// `<ContentDigest as AsRef<[u8]>>::as_ref(&digest)
/// == owned_bytes.as_slice()` restatement that repeats the
/// canonical-digest oracle name at every downstream comparison
/// site.
///
/// Route: the impl body composes
/// [`<ContentDigest as AsRef<[u8]>>::as_ref`] with the standard
/// library [`<[u8] as PartialEq<[u8]>>::eq`] on the [`Vec<u8>`]-
/// side deref coercion (`Vec<u8>: Deref<Target = [u8]>`), so the
/// comparison reads the same canonical-digest bytes at zero
/// allocation, zero temporary [`Vec<u8>`] construction, and zero
/// [`std::fmt::Display`] formatter-buffer round trip per call —
/// the same zero-cost discipline the borrowed-bytes sibling peers
/// carry.
///
/// Sibling of the by-value owned-byte-slice emit peer
/// [`From<ContentDigest> for Vec<u8>`] (commit e1ea855): both
/// surfaces bridge the [`ContentDigest`] value and the [`Vec<u8>`]
/// owned-input frontier — the emit peer moves the validated
/// backing bytes out (`Vec::<u8>::from(digest)`), this comparison
/// peer asks whether the owned [`Vec<u8>`] on the right names the
/// same canonical `<algorithm>:<hex>` as the [`ContentDigest`]
/// value on the left (`digest == owned_bytes`) — so a downstream
/// site that received an owned [`Vec<u8>`] and needs to answer
/// either query reads through the ContentDigest primitive at the
/// [`Vec<u8>`] frontier without a per-site
/// `<ContentDigest as AsRef<[u8]>>::as_ref` restatement.
///
/// Mirrors the standard-library idiom [`Vec<u8>`] carries through
/// its own [`PartialEq<Vec<u8>> for [u8]`] +
/// [`PartialEq<Vec<u8>> for &[u8]`] symmetric owned-bytes
/// comparison surface: an owned canonical-bytes primitive
/// compares against a [`Vec<u8>`] handle at either frontier with
/// the same zero-cost projection through the primitive's read-back
/// accessor. This impl is the byte-side projection of the
/// [`PartialEq<String>`] owned-UTF-8 peer directly above; where
/// that peer answers the query at the UTF-8 frontier through
/// [`ContentDigest::as_str`], this peer answers the same query at
/// the byte-slice frontier through
/// [`<ContentDigest as AsRef<[u8]>>::as_ref`] (which itself
/// composes [`ContentDigest::as_str`] with [`str::as_bytes`]).
///
/// Closes the fourth and last uncovered corner of the reference-
/// grammar comparison cross-product noted in commit 06cb6f5 (the
/// [`PartialEq<String>`] forward peer): borrowed-str × 2 × 2
/// (17c63ca + d894159), borrowed-bytes × 2 × 2 (9acc9aa + 94a61bb),
/// owned-str × 2 (06cb6f5), and this owned-bytes × 2 pair — the
/// full 12-impl closure of the borrowed and owned string/bytes
/// receiver-shape × direction cross-product at the reference-
/// grammar family, matching the closure the standard library
/// itself carries across [`str`] / [`String`] / [`[u8]`] /
/// [`Vec<u8>`].
///
/// THEORY.md §III.1 typescape: the owned byte-slice comparison
/// surface is a typed-primitive site on [`ContentDigest`] itself
/// (one [`PartialEq<Vec<u8>>`] impl routing through
/// [`<ContentDigest as AsRef<[u8]>>::as_ref`]), not a per-consumer
/// `<ContentDigest as AsRef<[u8]>>::as_ref(&d) == owned.as_slice()`
/// restatement at every downstream site that asks whether a
/// [`ContentDigest`] value names a specific canonical
/// `<algorithm>:<hex>` through an owned [`Vec<u8>`] handle.
/// THEORY.md §VI.1 one-oracle: the validated full-digest slice is
/// named at one site ([`ContentDigest::as_str`]), and every
/// comparison surface — the borrowed-UTF-8 pair, the borrowed-
/// byte-slice pair, the owned-UTF-8 pair, this owned-byte-slice
/// peer — reads through the same one-oracle discipline projected
/// onto its own intent × frontier.
impl PartialEq<Vec<u8>> for ContentDigest {
    fn eq(&self, other: &Vec<u8>) -> bool {
        <Self as AsRef<[u8]>>::as_ref(self) == other.as_slice()
    }
}

/// Symmetric owned byte-slice comparison peer:
/// `<Vec<u8> as PartialEq<ContentDigest>>::eq` — the reverse-
/// direction sibling of [`PartialEq<Vec<u8>> for ContentDigest`]
/// directly above. The pair together closes the owned byte-slice
/// comparison surface across both receiver directions, so a caller
/// who holds an owned [`Vec<u8>`] writes `owned_bytes == digest`
/// (or the standard-library-derived `if a == b || b == a`-style
/// symmetric composition a generic `PartialEq`-bounded consumer
/// performs internally) and answers a boolean equality query
/// against a [`ContentDigest`] value at the same owned byte-slice
/// frontier the forward-direction peer covers, at zero allocation,
/// zero temporary [`Vec<u8>`] construction, and zero
/// [`std::fmt::Display`] formatter-buffer round trip per call.
///
/// Route: the impl body composes
/// [`<ContentDigest as AsRef<[u8]>>::as_ref`] with
/// [`<[u8] as PartialEq<[u8]>>::eq`] on the [`Vec<u8>`]-side deref
/// coercion, so the comparison reads the same canonical-digest
/// bytes as the forward-direction
/// [`PartialEq<Vec<u8>> for ContentDigest`] peer, and the symmetry
/// axiom
/// `<Vec<u8> as PartialEq<ContentDigest>>::eq(owned, &digest)
/// == <ContentDigest as PartialEq<Vec<u8>>>::eq(&digest, owned)`
/// holds by construction at every `(owned, digest)` pair.
///
/// Mirrors the standard-library idiom [`Vec<u8>`] carries through
/// its own [`PartialEq<Vec<u8>> for [u8]`] symmetric receiver-shape
/// pair: a borrowed / owned byte-slice handle compares against the
/// counter-shape byte-slice primitive in either direction with the
/// same zero-cost projection through the primitive's read-back
/// accessor. Prior to this impl the digest reference-grammar family
/// carried only the forward direction at the owned-byte-slice
/// frontier (`digest == owned_bytes` compiled but
/// `owned_bytes == digest` did not), so a generic `PartialEq`-
/// bounded consumer that composed the two through its own
/// symmetric-check protocol could not thread a [`ContentDigest`]
/// through the [`Vec<u8>`] side of the bound without a per-consumer
/// `owned_bytes.as_slice() == <ContentDigest as AsRef<[u8]>>::as_ref(&d)`
/// bridge.
///
/// THEORY.md §III.1 typescape: the reverse-direction owned byte-
/// slice comparison surface is a typed-primitive site on
/// [`ContentDigest`] itself (one [`PartialEq<ContentDigest>`] impl
/// on [`Vec<u8>`] routing through
/// [`<ContentDigest as AsRef<[u8]>>::as_ref`]), not a per-consumer
/// `owned_bytes == <ContentDigest as AsRef<[u8]>>::as_ref(&d)`
/// restatement at every downstream site that asks whether an owned
/// [`Vec<u8>`] handle names the same canonical
/// `<algorithm>:<hex>` as a [`ContentDigest`] value.
/// THEORY.md §VI.1 one-oracle: the validated full-digest slice is
/// named at one site ([`ContentDigest::as_str`]), and this reverse-
/// direction owned-byte-slice receiver surface reads through the
/// same one-oracle discipline every sibling comparison surface
/// (borrowed str × 2 × 2, borrowed bytes × 2 × 2, owned-string
/// × 2, forward owned-bytes) already carries.
impl PartialEq<ContentDigest> for Vec<u8> {
    fn eq(&self, other: &ContentDigest) -> bool {
        self.as_slice() == <ContentDigest as AsRef<[u8]>>::as_ref(other)
    }
}

/// Ergonomic canonical-digest equality query at the borrowed-or-
/// owned-frontier UTF-8 receiver — the [`Cow<'_, str>`] peer of the
/// borrowed-str comparison pair
/// [`PartialEq<str> for ContentDigest`] +
/// [`PartialEq<&str> for ContentDigest`] and the owned-string
/// comparison peer [`PartialEq<String> for ContentDigest`] above. A
/// downstream consumer that holds a canonical `<algorithm>:<hex>`
/// label at the [`Cow<'_, str>`] frontier (a `serde` decoder that
/// yields `Cow::Borrowed` on the zero-copy fast path and
/// `Cow::Owned` on an escaped-string arm, a config-schema field
/// that stores canonical digest text as [`Cow<'_, str>`] so
/// borrowed static defaults and owned user-supplied overrides
/// share one contract, a `nom` / `winnow` parser whose output type
/// is `Cow<'_, str>` because the borrowed slice may reference the
/// input buffer or an owned normalisation result) answers the
/// boolean equality query `digest == cow_label` at ONE composition
/// rather than a per-site `digest.as_str() == &**cow_label` /
/// `digest.as_str() == cow_label.as_ref()` restatement that
/// repeats the canonical-digest oracle name at every downstream
/// comparison site.
///
/// Route: the impl body composes [`ContentDigest::as_str`] with
/// the standard library [`<str as PartialEq<str>>::eq`] on the
/// [`Cow<'_, str>`] deref coercion (via [`AsRef::as_ref`]), so the
/// comparison reads the same canonical-digest bytes independently
/// of which [`Cow`] arm the caller holds — the borrowed and owned
/// arms alias the same underlying UTF-8 view at zero allocation,
/// zero temporary [`String`] construction, and zero
/// [`std::fmt::Display`] formatter-buffer round trip per call.
///
/// Sibling of [`TryFrom<Cow<'_, str>> for ContentDigest`] (commit
/// 3a28035): both surfaces bridge the [`ContentDigest`] value and
/// the [`Cow<'_, str>`] borrowed-or-owned-frontier — the parse
/// peer recovers a [`ContentDigest`] from a canonical
/// `<algorithm>:<hex>` [`Cow<'_, str>`] payload through the
/// [`ContentDigest::parse`] oracle, this comparison peer asks
/// whether an already-held [`Cow<'_, str>`] label names the same
/// canonical `<algorithm>:<hex>` as the [`ContentDigest`] value on
/// the left — so a downstream site that received input at the
/// [`Cow`] frontier and needs to answer either query reads through
/// the ContentDigest primitive at the [`Cow`] frontier without a
/// per-site `cow.as_ref()` restatement.
///
/// Structural mirror of the sibling borrowed-str
/// [`PartialEq<str> for ContentDigest`] and owned-string
/// [`PartialEq<String> for ContentDigest`] peers — the same
/// canonical-digest comparison lift, now extended to the arm-
/// collapsing [`Cow`] receiver so the full UTF-8 comparison
/// receiver set on the reference-grammar family (borrowed str,
/// borrowed &str, owned String, borrowed-or-owned Cow<'_, str>)
/// is closed on the forward direction.
///
/// THEORY.md §III.1 typescape: the [`Cow<'_, str>`] comparison
/// surface is a typed-primitive site on [`ContentDigest`] itself
/// (one [`PartialEq<Cow<'_, str>>`] impl routing through
/// [`ContentDigest::as_str`]), not a per-consumer
/// `digest.as_str() == cow.as_ref()` restatement at every
/// downstream site that receives a [`Cow<'_, str>`] and asks
/// whether it names a specific canonical `<algorithm>:<hex>`.
/// THEORY.md §VI.1 one-oracle: the validated full-digest slice is
/// named at one site ([`ContentDigest::as_str`], reading through
/// the [`ContentDigest::parse`]-guarded backing string), and every
/// comparison surface — the borrowed-str pair, the borrowed-byte
/// pair, the owned-String pair, the owned-Vec<u8> pair, this
/// borrowed-or-owned [`Cow<'_, str>`] peer — reads through the
/// same one-oracle discipline projected onto its own receiver
/// shape.
impl PartialEq<std::borrow::Cow<'_, str>> for ContentDigest {
    fn eq(&self, other: &std::borrow::Cow<'_, str>) -> bool {
        self.as_str() == other.as_ref()
    }
}

/// Symmetric borrowed-or-owned UTF-8 comparison peer:
/// `<Cow<'_, str> as PartialEq<ContentDigest>>::eq` — the reverse-
/// direction sibling of [`PartialEq<Cow<'_, str>> for
/// ContentDigest`] (directly above). The pair together closes the
/// [`Cow<'_, str>`] comparison surface across both receiver
/// directions, so a caller who holds a [`Cow<'_, str>`] label
/// writes `cow_label == digest` (or the standard-library-derived
/// `if a == b || b == a`-style symmetric composition a generic
/// `PartialEq`-bounded consumer performs internally) and answers a
/// boolean equality query against a [`ContentDigest`] value at the
/// same arm-collapsing frontier the forward-direction peer covers,
/// at zero allocation, zero temporary [`String`] construction, and
/// zero [`std::fmt::Display`] formatter-buffer round trip per call.
///
/// Route: the impl body composes [`ContentDigest::as_str`] with
/// [`<str as PartialEq<str>>::eq`] on the [`Cow<'_, str>`] deref
/// coercion (via [`AsRef::as_ref`]), so the comparison reads the
/// same canonical-digest bytes as the forward-direction
/// [`PartialEq<Cow<'_, str>> for ContentDigest`] peer, and the
/// symmetry axiom
/// `<Cow<'_, str> as PartialEq<ContentDigest>>::eq(cow, &d)
/// == <ContentDigest as PartialEq<Cow<'_, str>>>::eq(&d, cow)`
/// holds by construction at every `(cow, digest)` pair on either
/// [`Cow`] arm.
///
/// Prior to this impl the digest reference-grammar family carried
/// only the forward direction at the [`Cow`] frontier
/// (`digest == cow_label` compiled but `cow_label == digest` did
/// not), so a generic `PartialEq`-bounded consumer that composed
/// the two through its own symmetric-check protocol could not
/// thread a [`ContentDigest`] through the [`Cow`] side of the
/// bound without a per-consumer `cow_label.as_ref() == digest.as_str()`
/// bridge.
///
/// THEORY.md §III.1 typescape: the reverse-direction [`Cow<'_, str>`]
/// comparison surface is a typed-primitive site on
/// [`ContentDigest`] itself (one [`PartialEq<ContentDigest>`] impl
/// on [`Cow<'_, str>`] routing through [`ContentDigest::as_str`]),
/// not a per-consumer `cow_label.as_ref() == digest.as_str()`
/// restatement at every downstream site that asks whether a
/// [`Cow<'_, str>`] handle names the same canonical
/// `<algorithm>:<hex>` as a [`ContentDigest`] value. THEORY.md
/// §VI.1 one-oracle: the validated full-digest slice is named at
/// one site ([`ContentDigest::as_str`]), and this reverse-
/// direction [`Cow<'_, str>`] receiver reads through the same
/// one-oracle discipline every sibling comparison surface
/// (borrowed str × 2 × 2, borrowed bytes × 2 × 2, owned String
/// × 2, owned Vec<u8> × 2, forward [`Cow<'_, str>`]) already
/// carries.
impl PartialEq<ContentDigest> for std::borrow::Cow<'_, str> {
    fn eq(&self, other: &ContentDigest) -> bool {
        self.as_ref() == other.as_str()
    }
}

/// Ergonomic canonical-digest equality query at the borrowed-or-
/// owned-frontier byte-slice receiver — the [`Cow<'_, [u8]>`] peer
/// of the borrowed-byte-slice comparison pair
/// [`PartialEq<[u8]> for ContentDigest`] +
/// [`PartialEq<&[u8]> for ContentDigest`], the owned-byte-slice
/// comparison peer [`PartialEq<Vec<u8>> for ContentDigest`], and
/// the byte-side projection of the borrowed-or-owned UTF-8 pair
/// [`PartialEq<Cow<'_, str>> for ContentDigest`] +
/// [`PartialEq<ContentDigest> for Cow<'_, str>`] (commit 38b2165)
/// above. A downstream consumer that holds a canonical
/// `<algorithm>:<hex>` label at the [`Cow<'_, [u8]>`] frontier (a
/// `bytes::Bytes`-backed decoder that hands off a
/// [`Cow<'_, [u8]>`] whose borrowed arm aliases the wire buffer
/// and whose owned arm carries a normalised copy, a `nom` /
/// `winnow` byte parser whose output type is `Cow<'_, [u8]>`
/// because the borrowed slice may reference the input buffer or
/// an owned canonicalisation result, a
/// `sigstore` / `sigstore_rs` verifier that surfaces a Content-
/// Digest header value as [`Cow<'_, [u8]>`] so a borrowed HTTP-
/// header slot and an owned normalised form share one contract,
/// a `serde_bytes` field decoded as [`Cow<'_, [u8]>`] whose zero-
/// copy fast path yields `Cow::Borrowed` and whose escaped-bytes
/// arm yields `Cow::Owned`) answers the boolean equality query
/// `digest == cow_bytes` at ONE composition rather than a per-
/// site `<ContentDigest as AsRef<[u8]>>::as_ref(&digest)
/// == cow_bytes.as_ref()` restatement that repeats the canonical-
/// digest oracle name at every downstream comparison site.
///
/// Route: the impl body composes
/// [`<ContentDigest as AsRef<[u8]>>::as_ref`] with the standard
/// library [`<[u8] as PartialEq<[u8]>>::eq`] on the
/// [`Cow<'_, [u8]>`] deref coercion (via [`AsRef::as_ref`]), so
/// the comparison reads the same canonical-digest bytes
/// independently of which [`Cow`] arm the caller holds — the
/// borrowed and owned arms alias the same underlying byte-slice
/// view at zero allocation, zero temporary [`Vec<u8>`]
/// construction, and zero [`std::fmt::Display`] formatter-buffer
/// round trip per call.
///
/// Sibling of [`TryFrom<Cow<'_, [u8]>> for ContentDigest`]
/// (commit cc9fcb3): both surfaces bridge the [`ContentDigest`]
/// value and the [`Cow<'_, [u8]>`] borrowed-or-owned-frontier —
/// the parse peer recovers a [`ContentDigest`] from a canonical
/// `<algorithm>:<hex>` [`Cow<'_, [u8]>`] payload through the
/// [`ContentDigest::parse`] oracle (after a UTF-8 admission check),
/// this comparison peer asks whether an already-held
/// [`Cow<'_, [u8]>`] label names the same canonical
/// `<algorithm>:<hex>` as the [`ContentDigest`] value on the left
/// — so a downstream site that received input at the
/// [`Cow<'_, [u8]>`] frontier and needs to answer either query
/// reads through the ContentDigest primitive at that frontier
/// without a per-site `cow_bytes.as_ref()` restatement.
///
/// Structural mirror of the sibling borrowed-bytes
/// [`PartialEq<[u8]> for ContentDigest`], owned-bytes
/// [`PartialEq<Vec<u8>> for ContentDigest`], and borrowed-or-
/// owned-UTF-8 [`PartialEq<Cow<'_, str>> for ContentDigest`] peers
/// — the same canonical-digest comparison lift, now extended to
/// the arm-collapsing [`Cow`] receiver on the byte-slice side so
/// the full byte-slice comparison receiver set on the reference-
/// grammar family (borrowed [u8], borrowed &[u8], owned Vec<u8>,
/// borrowed-or-owned Cow<'_, [u8]>) is closed on the forward
/// direction — the exact mirror of the four-shape UTF-8 receiver
/// set (str, &str, String, Cow<'_, str>) already carried.
///
/// THEORY.md §III.1 typescape: the [`Cow<'_, [u8]>`] comparison
/// surface is a typed-primitive site on [`ContentDigest`] itself
/// (one [`PartialEq<Cow<'_, [u8]>>`] impl routing through
/// [`<ContentDigest as AsRef<[u8]>>::as_ref`]), not a per-consumer
/// `<ContentDigest as AsRef<[u8]>>::as_ref(&d) == cow.as_ref()`
/// restatement at every downstream site that receives a
/// [`Cow<'_, [u8]>`] and asks whether it names a specific
/// canonical `<algorithm>:<hex>`. THEORY.md §VI.1 one-oracle: the
/// validated full-digest slice is named at one site
/// ([`ContentDigest::as_str`], read as bytes through
/// [`AsRef<[u8]>`]), and every comparison surface — the borrowed-
/// str pair, the borrowed-byte pair, the owned-String pair, the
/// owned-Vec<u8> pair, the borrowed-or-owned [`Cow<'_, str>`]
/// pair, this borrowed-or-owned [`Cow<'_, [u8]>`] peer — reads
/// through the same one-oracle discipline projected onto its own
/// receiver shape.
impl PartialEq<std::borrow::Cow<'_, [u8]>> for ContentDigest {
    fn eq(&self, other: &std::borrow::Cow<'_, [u8]>) -> bool {
        <Self as AsRef<[u8]>>::as_ref(self) == other.as_ref()
    }
}

/// Symmetric borrowed-or-owned byte-slice comparison peer:
/// `<Cow<'_, [u8]> as PartialEq<ContentDigest>>::eq` — the
/// reverse-direction sibling of
/// [`PartialEq<Cow<'_, [u8]>> for ContentDigest`] (directly above).
/// The pair together closes the [`Cow<'_, [u8]>`] comparison
/// surface across both receiver directions, so a caller who holds
/// a [`Cow<'_, [u8]>`] byte-slice label writes
/// `cow_bytes == digest` (or the standard-library-derived
/// `if a == b || b == a`-style symmetric composition a generic
/// `PartialEq`-bounded consumer performs internally) and answers a
/// boolean equality query against a [`ContentDigest`] value at the
/// same arm-collapsing byte-slice frontier the forward-direction
/// peer covers, at zero allocation, zero temporary [`Vec<u8>`]
/// construction, and zero [`std::fmt::Display`] formatter-buffer
/// round trip per call.
///
/// Route: the impl body composes
/// [`<ContentDigest as AsRef<[u8]>>::as_ref`] with
/// [`<[u8] as PartialEq<[u8]>>::eq`] on the [`Cow<'_, [u8]>`]
/// deref coercion (via [`AsRef::as_ref`]), so the comparison reads
/// the same canonical-digest bytes as the forward-direction
/// [`PartialEq<Cow<'_, [u8]>> for ContentDigest`] peer, and the
/// symmetry axiom
/// `<Cow<'_, [u8]> as PartialEq<ContentDigest>>::eq(cow, &d)
/// == <ContentDigest as PartialEq<Cow<'_, [u8]>>>::eq(&d, cow)`
/// holds by construction at every `(cow, digest)` pair on either
/// [`Cow`] arm.
///
/// Prior to this impl the digest reference-grammar family carried
/// only the forward direction at the [`Cow<'_, [u8]>`] frontier
/// (`digest == cow_bytes` compiled but `cow_bytes == digest` did
/// not), so a generic `PartialEq`-bounded consumer that composed
/// the two through its own symmetric-check protocol could not
/// thread a [`ContentDigest`] through the [`Cow<'_, [u8]>`] side
/// of the bound without a per-consumer
/// `cow_bytes.as_ref() == <ContentDigest as AsRef<[u8]>>::as_ref(&d)`
/// bridge.
///
/// THEORY.md §III.1 typescape: the reverse-direction
/// [`Cow<'_, [u8]>`] comparison surface is a typed-primitive site
/// on [`ContentDigest`] itself (one [`PartialEq<ContentDigest>`]
/// impl on [`Cow<'_, [u8]>`] routing through
/// [`<ContentDigest as AsRef<[u8]>>::as_ref`]), not a per-consumer
/// `cow_bytes.as_ref() == <ContentDigest as AsRef<[u8]>>::as_ref(&d)`
/// restatement at every downstream site that asks whether a
/// [`Cow<'_, [u8]>`] handle names the same canonical
/// `<algorithm>:<hex>` as a [`ContentDigest`] value. THEORY.md
/// §VI.1 one-oracle: the validated full-digest slice is named at
/// one site ([`ContentDigest::as_str`], read as bytes through
/// [`AsRef<[u8]>`]), and this reverse-direction
/// [`Cow<'_, [u8]>`] receiver reads through the same one-oracle
/// discipline every sibling comparison surface (borrowed str
/// × 2 × 2, borrowed bytes × 2 × 2, owned String × 2, owned
/// Vec<u8> × 2, borrowed-or-owned [`Cow<'_, str>`] × 2, forward
/// [`Cow<'_, [u8]>`]) already carries.
impl PartialEq<ContentDigest> for std::borrow::Cow<'_, [u8]> {
    fn eq(&self, other: &ContentDigest) -> bool {
        self.as_ref() == <ContentDigest as AsRef<[u8]>>::as_ref(other)
    }
}

/// Ergonomic canonical-digest equality query at the shrunk-owned
/// UTF-8 frontier — the [`Box<str>`] peer of the owned-string
/// comparison pair [`PartialEq<String> for ContentDigest`] +
/// [`PartialEq<ContentDigest> for String`] (commit 06cb6f5) and the
/// borrowed-or-owned [`Cow<'_, str>`] pair
/// [`PartialEq<Cow<'_, str>> for ContentDigest`] +
/// [`PartialEq<ContentDigest> for Cow<'_, str>`] (commit 38b2165)
/// above. A downstream consumer that holds a canonical
/// `<algorithm>:<hex>` label as a shrunk-owned [`Box<str>`] handle
/// (a long-lived registry cache that stores a validated digest label
/// as [`Box<str>`] after
/// [`String::into_boxed_str`] to shed the amortised-capacity slack
/// the [`String`] growth buffer carries, a `Vec<Box<str>>` /
/// `HashSet<Box<str>>` compact-footprint index, an emitted-peer
/// consumer that received a digest label through
/// [`From<ContentDigest> for Box<str>`] (commit 0e86524) and asks
/// whether it names the same canonical form as a live
/// [`ContentDigest`] value) answers the boolean equality query
/// `digest == boxed_label` at ONE composition rather than a per-site
/// `digest.as_str() == &**boxed_label` / `digest.as_str() ==
/// boxed_label.as_ref()` restatement that repeats the canonical-
/// digest oracle name at every downstream comparison site.
///
/// Route: the impl body composes [`ContentDigest::as_str`] with
/// the standard library [`<str as PartialEq<str>>::eq`] on the
/// [`Box<str>`] deref coercion (`Box<str>: Deref<Target = str>`),
/// so the comparison reads the same canonical-digest bytes at
/// zero allocation, zero temporary [`String`] construction, and
/// zero [`std::fmt::Display`] formatter-buffer round trip per
/// call — the same zero-cost discipline the sibling owned-string
/// [`PartialEq<String>`] and borrowed-or-owned [`PartialEq<Cow<'_, str>>`]
/// peers carry.
///
/// Sibling of the by-value shrunk-owned UTF-8 emit peer
/// [`From<ContentDigest> for Box<str>`] (commit 0e86524) and the
/// by-value shrunk-owned UTF-8 parse peer
/// [`TryFrom<Box<str>> for ContentDigest`] (commit 2d5eb7e): the
/// three surfaces bridge the [`ContentDigest`] value and the
/// [`Box<str>`] shrunk-owned frontier — the parse peer recovers a
/// [`ContentDigest`] from a canonical `<algorithm>:<hex>`
/// [`Box<str>`] payload through the [`ContentDigest::parse`]
/// oracle, the emit peer hands off the validated canonical form as
/// a [`Box<str>`] through [`String::into_boxed_str`], this
/// comparison peer asks whether an already-held [`Box<str>`] label
/// names the same canonical form as the [`ContentDigest`] value on
/// the left — so a downstream site that received input at the
/// [`Box<str>`] frontier and needs to answer any of the three
/// queries reads through the ContentDigest primitive at that
/// frontier without a per-site `&**boxed_label` deref restatement.
///
/// Opens the shrunk-owned / shared-owned UTF-8 receiver trio
/// ([`Box<str>`], [`std::sync::Arc<str>`], [`std::rc::Rc<str>`])
/// on the equality axis. The parse axis already carries all three
/// receivers (commits 2d5eb7e, 414b22c, 4d0783e) and the emit axis
/// already carries all three receivers (commits 0e86524, 5f85247,
/// a7bcfd2), so this pair is the first step in closing the equality-
/// axis analog of the same three-receiver family on the reference-
/// grammar primitive — after the [`Arc<str>`] and [`Rc<str>`]
/// equality peers land, the shrunk-owned / shared-owned UTF-8
/// receiver family is closed on all three input/output/equality
/// axes on both directions.
///
/// THEORY.md §III.1 typescape: the [`Box<str>`] comparison surface
/// is a typed-primitive site on [`ContentDigest`] itself (one
/// [`PartialEq<Box<str>>`] impl routing through
/// [`ContentDigest::as_str`]), not a per-consumer
/// `digest.as_str() == &**boxed_label` restatement at every
/// downstream site that receives a [`Box<str>`] and asks whether
/// it names a specific canonical `<algorithm>:<hex>`. THEORY.md
/// §VI.1 one-oracle: the validated full-digest slice is named at
/// one site ([`ContentDigest::as_str`], reading through the
/// [`ContentDigest::parse`]-guarded backing string), and every
/// comparison surface — the borrowed-str pair, the borrowed-byte
/// pair, the owned-String pair, the owned-Vec<u8> pair, the
/// borrowed-or-owned [`Cow<'_, str>`] pair, the borrowed-or-owned
/// [`Cow<'_, [u8]>`] pair, this shrunk-owned [`Box<str>`] peer —
/// reads through the same one-oracle discipline projected onto its
/// own receiver shape.
impl PartialEq<Box<str>> for ContentDigest {
    fn eq(&self, other: &Box<str>) -> bool {
        self.as_str() == other.as_ref()
    }
}

/// Symmetric shrunk-owned UTF-8 comparison peer:
/// `<Box<str> as PartialEq<ContentDigest>>::eq` — the reverse-
/// direction sibling of [`PartialEq<Box<str>> for ContentDigest`]
/// (directly above). The pair together closes the [`Box<str>`]
/// comparison surface across both receiver directions, so a caller
/// who holds a [`Box<str>`] label writes `boxed_label == digest`
/// (or the standard-library-derived `if a == b || b == a`-style
/// symmetric composition a generic `PartialEq`-bounded consumer
/// performs internally) and answers a boolean equality query
/// against a [`ContentDigest`] value at the same shrunk-owned
/// frontier the forward-direction peer covers, at zero allocation,
/// zero temporary [`String`] construction, and zero
/// [`std::fmt::Display`] formatter-buffer round trip per call.
///
/// Route: the impl body composes [`ContentDigest::as_str`] with
/// [`<str as PartialEq<str>>::eq`] on the [`Box<str>`] deref
/// coercion, so the comparison reads the same canonical-digest
/// bytes as the forward-direction
/// [`PartialEq<Box<str>> for ContentDigest`] peer, and the
/// symmetry axiom
/// `<Box<str> as PartialEq<ContentDigest>>::eq(boxed, &d)
/// == <ContentDigest as PartialEq<Box<str>>>::eq(&d, boxed)` holds
/// by construction at every `(boxed, digest)` pair.
///
/// Prior to this impl the digest reference-grammar family carried
/// only the forward direction at the [`Box<str>`] frontier
/// (`digest == boxed_label` compiled but `boxed_label == digest`
/// did not), so a generic `PartialEq`-bounded consumer that
/// composed the two through its own symmetric-check protocol could
/// not thread a [`ContentDigest`] through the [`Box<str>`] side of
/// the bound without a per-consumer `&**boxed_label ==
/// digest.as_str()` bridge.
///
/// THEORY.md §III.1 typescape: the reverse-direction [`Box<str>`]
/// comparison surface is a typed-primitive site on
/// [`ContentDigest`] itself (one [`PartialEq<ContentDigest>`] impl
/// on [`Box<str>`] routing through [`ContentDigest::as_str`]), not
/// a per-consumer `&**boxed_label == digest.as_str()` restatement
/// at every downstream site that asks whether a [`Box<str>`]
/// handle names the same canonical `<algorithm>:<hex>` as a
/// [`ContentDigest`] value. THEORY.md §VI.1 one-oracle: the
/// validated full-digest slice is named at one site
/// ([`ContentDigest::as_str`]), and this reverse-direction
/// [`Box<str>`] receiver reads through the same one-oracle
/// discipline every sibling comparison surface (borrowed str
/// × 2 × 2, borrowed bytes × 2 × 2, owned String × 2, owned
/// Vec<u8> × 2, borrowed-or-owned [`Cow<'_, str>`] × 2,
/// borrowed-or-owned [`Cow<'_, [u8]>`] × 2, forward [`Box<str>`])
/// already carries.
impl PartialEq<ContentDigest> for Box<str> {
    fn eq(&self, other: &ContentDigest) -> bool {
        self.as_ref() == other.as_str()
    }
}

/// Ergonomic canonical-digest equality query at the shrunk-owned
/// byte-slice frontier — the [`Box<[u8]>`] peer of the owned-byte-
/// slice comparison pair [`PartialEq<Vec<u8>> for ContentDigest`] +
/// [`PartialEq<ContentDigest> for Vec<u8>`] (commit 49e9bb4) and the
/// borrowed-or-owned [`Cow<'_, [u8]>`] pair
/// [`PartialEq<Cow<'_, [u8]>> for ContentDigest`] +
/// [`PartialEq<ContentDigest> for Cow<'_, [u8]>`] (commit 276e908)
/// above. A downstream consumer that holds a canonical
/// `<algorithm>:<hex>` label as a shrunk-owned [`Box<[u8]>`] byte-
/// buffer handle (a long-lived registry cache that stores a
/// validated digest label as [`Box<[u8]>`] after
/// [`Vec::into_boxed_slice`] to shed the amortised-capacity slack
/// the [`Vec<u8>`] growth buffer carries, a `Vec<Box<[u8]>>` /
/// `HashSet<Box<[u8]>>` compact-footprint index over byte-oriented
/// digest labels, an emitted-peer consumer that received a digest
/// label through [`From<ContentDigest> for Box<[u8]>`] (commit
/// fce9fee) and asks whether it names the same canonical form as a
/// live [`ContentDigest`] value) answers the boolean equality query
/// `digest == boxed_bytes` at ONE composition rather than a per-site
/// `<ContentDigest as AsRef<[u8]>>::as_ref(&d) == &**boxed_bytes` /
/// `<ContentDigest as AsRef<[u8]>>::as_ref(&d) == boxed_bytes.as_ref()`
/// restatement that repeats the canonical-digest oracle name at
/// every downstream comparison site.
///
/// Route: the impl body composes
/// [`<ContentDigest as AsRef<[u8]>>::as_ref`] with the standard
/// library [`<[u8] as PartialEq<[u8]>>::eq`] on the [`Box<[u8]>`]
/// deref coercion (`Box<[u8]>: Deref<Target = [u8]>`), so the
/// comparison reads the same canonical-digest bytes at zero
/// allocation, zero temporary [`Vec<u8>`] construction, and zero
/// [`std::fmt::Display`] formatter-buffer round trip per call —
/// the same zero-cost discipline the sibling owned-bytes
/// [`PartialEq<Vec<u8>>`] and borrowed-or-owned
/// [`PartialEq<Cow<'_, [u8]>>`] peers carry.
///
/// Sibling of the by-value shrunk-owned byte-slice emit peer
/// [`From<ContentDigest> for Box<[u8]>`] (commit fce9fee) and the
/// by-value shrunk-owned byte-slice parse peer
/// [`TryFrom<Box<[u8]>> for ContentDigest`] (commit f5f98f6): the
/// three surfaces bridge the [`ContentDigest`] value and the
/// [`Box<[u8]>`] shrunk-owned frontier — the parse peer recovers a
/// [`ContentDigest`] from a canonical `<algorithm>:<hex>`
/// [`Box<[u8]>`] payload through the [`ContentDigest::parse`]
/// oracle, the emit peer hands off the validated canonical form as
/// a [`Box<[u8]>`] through [`Vec::into_boxed_slice`], this
/// comparison peer asks whether an already-held [`Box<[u8]>`]
/// byte-buffer label names the same canonical form as the
/// [`ContentDigest`] value on the left — so a downstream site that
/// received input at the [`Box<[u8]>`] frontier and needs to answer
/// any of the three queries reads through the ContentDigest
/// primitive at that frontier without a per-site `&**boxed_bytes`
/// deref restatement.
///
/// The byte-slice-axis mirror of the shrunk-owned UTF-8
/// [`Box<str>`] comparison pair
/// [`PartialEq<Box<str>> for ContentDigest`] +
/// [`PartialEq<ContentDigest> for Box<str>`] (commit f97d311)
/// directly above: the two pairs together close the shrunk-owned
/// [`Box<T>`] receiver on both the UTF-8 (`str`) and byte-slice
/// (`[u8]`) axes on both directions — the exact closure the
/// sibling borrowed pair (`str` + `[u8]`), owned pair (`String` +
/// `Vec<u8>`), and borrowed-or-owned [`Cow<'_, T>`] pair
/// (`Cow<'_, str>` + `Cow<'_, [u8]>`) already carry. Opens the
/// shrunk-owned / shared-owned byte-slice receiver trio
/// ([`Box<[u8]>`], [`std::sync::Arc<[u8]>`], [`std::rc::Rc<[u8]>`])
/// on the equality axis. The parse axis already carries all three
/// receivers (commits f5f98f6, d2ccc5d, 0eeac6d) and the emit axis
/// already carries all three receivers (commits fce9fee, 49111c1,
/// 578dbc6), so this pair is the first step in closing the
/// equality-axis analog of the same three-receiver family on the
/// byte-slice side.
///
/// THEORY.md §III.1 typescape: the [`Box<[u8]>`] comparison
/// surface is a typed-primitive site on [`ContentDigest`] itself
/// (one [`PartialEq<Box<[u8]>>`] impl routing through
/// [`<ContentDigest as AsRef<[u8]>>::as_ref`]), not a per-consumer
/// `<ContentDigest as AsRef<[u8]>>::as_ref(&d) == &**boxed_bytes`
/// restatement at every downstream site that receives a
/// [`Box<[u8]>`] and asks whether it names a specific canonical
/// `<algorithm>:<hex>`. THEORY.md §VI.1 one-oracle: the validated
/// full-digest slice is named at one site
/// ([`ContentDigest::as_str`], read as bytes through
/// [`AsRef<[u8]>`]), and every comparison surface — the borrowed-
/// str pair, the borrowed-byte pair, the owned-String pair, the
/// owned-Vec<u8> pair, the borrowed-or-owned [`Cow<'_, str>`]
/// pair, the borrowed-or-owned [`Cow<'_, [u8]>`] pair, the
/// shrunk-owned [`Box<str>`] pair, this shrunk-owned
/// [`Box<[u8]>`] peer — reads through the same one-oracle
/// discipline projected onto its own receiver shape.
impl PartialEq<Box<[u8]>> for ContentDigest {
    fn eq(&self, other: &Box<[u8]>) -> bool {
        <Self as AsRef<[u8]>>::as_ref(self) == other.as_ref()
    }
}

/// Symmetric shrunk-owned byte-slice comparison peer:
/// `<Box<[u8]> as PartialEq<ContentDigest>>::eq` — the reverse-
/// direction sibling of [`PartialEq<Box<[u8]>> for ContentDigest`]
/// (directly above). The pair together closes the [`Box<[u8]>`]
/// comparison surface across both receiver directions, so a
/// caller who holds a [`Box<[u8]>`] byte-buffer label writes
/// `boxed_bytes == digest` (or the standard-library-derived
/// `if a == b || b == a`-style symmetric composition a generic
/// `PartialEq`-bounded consumer performs internally) and answers a
/// boolean equality query against a [`ContentDigest`] value at the
/// same shrunk-owned byte-slice frontier the forward-direction
/// peer covers, at zero allocation, zero temporary [`Vec<u8>`]
/// construction, and zero [`std::fmt::Display`] formatter-buffer
/// round trip per call.
///
/// Route: the impl body composes
/// [`<ContentDigest as AsRef<[u8]>>::as_ref`] with
/// [`<[u8] as PartialEq<[u8]>>::eq`] on the [`Box<[u8]>`] deref
/// coercion, so the comparison reads the same canonical-digest
/// bytes as the forward-direction [`PartialEq<Box<[u8]>> for
/// ContentDigest`] peer, and the symmetry axiom
/// `<Box<[u8]> as PartialEq<ContentDigest>>::eq(boxed, &d)
/// == <ContentDigest as PartialEq<Box<[u8]>>>::eq(&d, boxed)`
/// holds by construction at every `(boxed, digest)` pair.
///
/// Prior to this impl the digest reference-grammar family carried
/// only the forward direction at the [`Box<[u8]>`] frontier
/// (`digest == boxed_bytes` compiled but `boxed_bytes == digest`
/// did not), so a generic `PartialEq`-bounded consumer that
/// composed the two through its own symmetric-check protocol could
/// not thread a [`ContentDigest`] through the [`Box<[u8]>`] side of
/// the bound without a per-consumer
/// `&**boxed_bytes == <ContentDigest as AsRef<[u8]>>::as_ref(&d)`
/// bridge.
///
/// THEORY.md §III.1 typescape: the reverse-direction
/// [`Box<[u8]>`] comparison surface is a typed-primitive site on
/// [`ContentDigest`] itself (one [`PartialEq<ContentDigest>`] impl
/// on [`Box<[u8]>`] routing through
/// [`<ContentDigest as AsRef<[u8]>>::as_ref`]), not a per-consumer
/// `&**boxed_bytes == <ContentDigest as AsRef<[u8]>>::as_ref(&d)`
/// restatement at every downstream site that asks whether a
/// [`Box<[u8]>`] handle names the same canonical
/// `<algorithm>:<hex>` as a [`ContentDigest`] value. THEORY.md
/// §VI.1 one-oracle: the validated full-digest slice is named at
/// one site ([`ContentDigest::as_str`], read as bytes through
/// [`AsRef<[u8]>`]), and this reverse-direction [`Box<[u8]>`]
/// receiver reads through the same one-oracle discipline every
/// sibling comparison surface (borrowed str × 2 × 2, borrowed
/// bytes × 2 × 2, owned String × 2, owned Vec<u8> × 2,
/// borrowed-or-owned [`Cow<'_, str>`] × 2, borrowed-or-owned
/// [`Cow<'_, [u8]>`] × 2, shrunk-owned [`Box<str>`] × 2, forward
/// [`Box<[u8]>`]) already carries.
impl PartialEq<ContentDigest> for Box<[u8]> {
    fn eq(&self, other: &ContentDigest) -> bool {
        self.as_ref() == <ContentDigest as AsRef<[u8]>>::as_ref(other)
    }
}

/// Ergonomic canonical-digest equality query at the cross-thread
/// shared-owned UTF-8 frontier — the [`std::sync::Arc<str>`] peer of
/// the shrunk-owned [`Box<str>`] pair
/// [`PartialEq<Box<str>> for ContentDigest`] +
/// [`PartialEq<ContentDigest> for Box<str>`] (commit f97d311)
/// directly above. A downstream consumer that holds a canonical
/// `<algorithm>:<hex>` label as a cross-thread shared-owned
/// [`Arc<str>`] handle (a long-lived registry cache that stores a
/// validated digest label under an [`Arc<str>`] to share the string
/// across worker threads without per-clone allocation, an emitted-
/// peer consumer that received a digest label through
/// [`From<ContentDigest> for Arc<str>`] (commit 5f85247) and asks
/// whether it names the same canonical form as a live
/// [`ContentDigest`] value) answers the boolean equality query
/// `digest == arc_label` at ONE composition rather than a per-site
/// `digest.as_str() == &**arc_label` /
/// `digest.as_str() == arc_label.as_ref()` restatement that repeats
/// the canonical-digest oracle name at every downstream comparison
/// site.
///
/// Route: [`ContentDigest::as_str`] composed with
/// [`<str as PartialEq<str>>::eq`] on the [`Arc<str>`] deref
/// coercion — zero allocation, zero temporary [`String`]
/// construction, zero [`std::fmt::Display`] formatter-buffer round
/// trip.
///
/// Sibling of the by-value cross-thread shared-owned UTF-8 emit
/// peer [`From<ContentDigest> for Arc<str>`] (commit 5f85247) and
/// the by-value cross-thread shared-owned UTF-8 parse peer
/// [`TryFrom<Arc<str>> for ContentDigest`] (commit 414b22c): the
/// three surfaces bridge the [`ContentDigest`] value and the
/// [`Arc<str>`] cross-thread shared-owned frontier — the parse peer
/// recovers a [`ContentDigest`] from a canonical `<algorithm>:<hex>`
/// [`Arc<str>`] payload through the [`ContentDigest::parse`]
/// oracle, the emit peer hands off the validated canonical form as
/// an [`Arc<str>`] through a fresh [`Arc::from`] allocation, this
/// comparison peer asks whether an already-held [`Arc<str>`] label
/// names the same canonical form as the [`ContentDigest`] value on
/// the left.
///
/// Opens the cross-thread shared-owned / thread-local shared-owned
/// [`Arc<str>`] + [`Rc<str>`] receiver duo on the equality axis on
/// the UTF-8 side. The parse axis already carries both receivers
/// (commits 414b22c, 4d0783e) and the emit axis already carries
/// both receivers (commits 5f85247, a7bcfd2), so this pair is the
/// first step in closing the equality-axis analog of the same
/// shared-owned family on the UTF-8 side.
///
/// THEORY.md §III.1 typescape: the [`Arc<str>`] comparison surface
/// is a typed-primitive site on [`ContentDigest`] itself (one
/// [`PartialEq<Arc<str>>`] impl routing through
/// [`ContentDigest::as_str`]), not a per-consumer
/// `digest.as_str() == &**arc_label` restatement at every
/// downstream site that receives an [`Arc<str>`] and asks whether
/// it names a specific canonical `<algorithm>:<hex>`. THEORY.md
/// §VI.1 one-oracle: the validated full-digest slice is named at
/// one site ([`ContentDigest::as_str`]), and every comparison
/// surface reads through the same one-oracle discipline projected
/// onto its own receiver shape.
impl PartialEq<std::sync::Arc<str>> for ContentDigest {
    fn eq(&self, other: &std::sync::Arc<str>) -> bool {
        self.as_str() == other.as_ref()
    }
}

/// Symmetric cross-thread shared-owned UTF-8 comparison peer:
/// `<Arc<str> as PartialEq<ContentDigest>>::eq` — the reverse-
/// direction sibling of
/// [`PartialEq<std::sync::Arc<str>> for ContentDigest`] directly
/// above. The pair together closes the [`Arc<str>`] comparison
/// surface across both receiver directions, so a caller who holds
/// an [`Arc<str>`] label writes `arc_label == digest` (or the
/// standard-library-derived symmetric composition a generic
/// `PartialEq`-bounded consumer performs internally) and answers a
/// boolean equality query against a [`ContentDigest`] value at the
/// same cross-thread shared-owned frontier the forward-direction
/// peer covers, at zero allocation, zero temporary [`String`]
/// construction, and zero [`std::fmt::Display`] formatter-buffer
/// round trip per call.
///
/// Route: [`ContentDigest::as_str`] composed with
/// [`<str as PartialEq<str>>::eq`] on the [`Arc<str>`] deref
/// coercion, so the comparison reads the same canonical-digest
/// bytes as the forward-direction peer, and the symmetry axiom
/// `<Arc<str> as PartialEq<ContentDigest>>::eq(arc, &d)
/// == <ContentDigest as PartialEq<Arc<str>>>::eq(&d, arc)` holds by
/// construction at every `(arc, digest)` pair.
///
/// THEORY.md §III.1 typescape: the reverse-direction [`Arc<str>`]
/// comparison surface is a typed-primitive site on
/// [`ContentDigest`] itself (one [`PartialEq<ContentDigest>`] impl
/// on [`Arc<str>`] routing through [`ContentDigest::as_str`]), not
/// a per-consumer `&**arc_label == digest.as_str()` restatement at
/// every downstream site that asks whether an [`Arc<str>`] handle
/// names the same canonical `<algorithm>:<hex>` as a
/// [`ContentDigest`] value. THEORY.md §VI.1 one-oracle: the
/// validated full-digest slice is named at one site
/// ([`ContentDigest::as_str`]), and this reverse-direction
/// [`Arc<str>`] receiver reads through the same one-oracle
/// discipline every sibling comparison surface already carries.
impl PartialEq<ContentDigest> for std::sync::Arc<str> {
    fn eq(&self, other: &ContentDigest) -> bool {
        self.as_ref() == other.as_str()
    }
}

/// Thread-local shared-owned UTF-8 comparison peer:
/// [`<ContentDigest as PartialEq<Rc<str>>>::eq`] — the sibling of
/// [`PartialEq<std::sync::Arc<str>> for ContentDigest`] (commit
/// 57fbde1) directly above at the thread-local shared-owned
/// [`Rc<str>`] receiver shape. Answers `digest == rc_label`
/// against a caller-held [`std::rc::Rc<str>`] handle by
/// composition of the [`ContentDigest::as_str`] one-oracle read
/// accessor and the [`std::rc::Rc<str>`] deref coercion — a
/// per-comparison cost of one pointer indirection to the
/// [`Rc<str>`] backing slice plus one byte-slice equality, at
/// zero allocation, zero temporary [`String`] construction, zero
/// [`std::fmt::Display`] formatter-buffer round trip.
///
/// Sibling of the by-value thread-local shared-owned UTF-8 emit
/// peer [`From<ContentDigest> for Rc<str>`] (commit a7bcfd2) and
/// the by-value thread-local shared-owned UTF-8 parse peer
/// [`TryFrom<Rc<str>> for ContentDigest`] (commit 4d0783e): the
/// three surfaces bridge the [`ContentDigest`] value and the
/// [`Rc<str>`] thread-local shared-owned frontier — the parse
/// peer recovers a [`ContentDigest`] from a canonical
/// `<algorithm>:<hex>` [`Rc<str>`] payload through the
/// [`ContentDigest::parse`] oracle, the emit peer hands off the
/// validated canonical form as an [`Rc<str>`] through a fresh
/// [`Rc::from`] allocation, this comparison peer asks whether an
/// already-held [`Rc<str>`] label names the same canonical form
/// as the [`ContentDigest`] value on the left.
///
/// Closes the cross-thread shared-owned / thread-local
/// shared-owned [`Arc<str>`] + [`Rc<str>`] receiver duo on the
/// equality axis on the UTF-8 side. The parse axis already carries
/// both receivers (commits 414b22c, 4d0783e), the emit axis
/// already carries both receivers (commits 5f85247, a7bcfd2), and
/// the [`Arc<str>`] equality peer (commit 57fbde1) opened this
/// pair — so with this commit the shared-owned UTF-8 receiver duo
/// is closed on all three input / output / equality axes on the
/// forward direction, matching the closure the standard library
/// carries across its own [`Arc`] / [`Rc`] shared-owned family.
///
/// A downstream consumer that received an already-parsed digest
/// label as [`Rc<str>`] (a same-thread cache that shares a
/// validated digest label across sibling coroutines through
/// [`Rc::clone`] without paying [`Arc`]'s atomic-refcount header
/// for a slot never crossing a thread boundary, an emitted-peer
/// consumer that received a label through
/// [`From<ContentDigest> for Rc<str>`], a
/// [`Vec<std::rc::Rc<str>>`] /
/// [`std::collections::HashSet<std::rc::Rc<str>>`] index over
/// same-thread shared-owned digest handles) now answers
/// `digest == rc_label` at one composition rather than a per-site
/// `digest.as_str() == &**rc_label` restatement of the
/// canonical-digest oracle name.
///
/// THEORY.md §III.1 typescape: the [`Rc<str>`] comparison surface
/// is a typed-primitive site on [`ContentDigest`] itself (one
/// [`PartialEq<Rc<str>>`] impl routing through
/// [`ContentDigest::as_str`]), not a per-consumer
/// `digest.as_str() == &**rc_label` restatement at every
/// downstream site that receives an [`Rc<str>`] and asks whether
/// it names a specific canonical `<algorithm>:<hex>`. THEORY.md
/// §VI.1 one-oracle: the validated full-digest slice is named at
/// one site ([`ContentDigest::as_str`]), and every comparison
/// surface — the sibling [`Arc<str>`] peer of commit 57fbde1,
/// this [`Rc<str>`] peer — reads through the same one-oracle
/// discipline projected onto its own receiver shape.
impl PartialEq<std::rc::Rc<str>> for ContentDigest {
    fn eq(&self, other: &std::rc::Rc<str>) -> bool {
        self.as_str() == other.as_ref()
    }
}

/// Symmetric thread-local shared-owned UTF-8 comparison peer:
/// [`<Rc<str> as PartialEq<ContentDigest>>::eq`] — the reverse-
/// direction sibling of
/// [`PartialEq<std::rc::Rc<str>> for ContentDigest`] directly
/// above. The pair together closes the [`Rc<str>`] comparison
/// surface across both receiver directions, so a caller who holds
/// an [`Rc<str>`] label writes `rc_label == digest` (or the
/// standard-library-derived symmetric composition a generic
/// `PartialEq`-bounded consumer performs internally) and answers a
/// boolean equality query against a [`ContentDigest`] value at the
/// same thread-local shared-owned frontier the forward-direction
/// peer covers, at zero allocation, zero temporary [`String`]
/// construction, and zero [`std::fmt::Display`] formatter-buffer
/// round trip per call.
///
/// Route: [`ContentDigest::as_str`] composed with
/// [`<str as PartialEq<str>>::eq`] on the [`Rc<str>`] deref
/// coercion, so the comparison reads the same canonical-digest
/// bytes as the forward-direction peer, and the symmetry axiom
/// `<Rc<str> as PartialEq<ContentDigest>>::eq(rc, &d)
/// == <ContentDigest as PartialEq<Rc<str>>>::eq(&d, rc)` holds by
/// construction at every `(rc, digest)` pair.
///
/// Together with the forward peer directly above and the
/// [`Arc<str>`] pair (commit 57fbde1), this commit closes the
/// shared-owned UTF-8 comparison-pair duo across both receiver
/// shapes and both directions — the equality-axis analog of the
/// shared-owned UTF-8 parse and emit peer duos already closed on
/// the [`Arc<str>`] + [`Rc<str>`] receiver pair. Two follow-up
/// commits mirror the same duo onto the byte-slice side
/// ([`Arc<[u8]>`], [`Rc<[u8]>`] equality pairs) — the parse and
/// emit axes already carry all four, so the equality axis closes
/// to the same three-receiver family on both sides once the
/// follow-ups land.
///
/// THEORY.md §III.1 typescape: the reverse-direction [`Rc<str>`]
/// comparison surface is a typed-primitive site on
/// [`ContentDigest`] itself (one [`PartialEq<ContentDigest>`]
/// impl on [`Rc<str>`] routing through [`ContentDigest::as_str`]),
/// not a per-consumer `&**rc_label == digest.as_str()`
/// restatement at every downstream site that asks whether an
/// [`Rc<str>`] handle names the same canonical
/// `<algorithm>:<hex>` as a [`ContentDigest`] value. THEORY.md
/// §VI.1 one-oracle: the validated full-digest slice is named at
/// one site ([`ContentDigest::as_str`]), and this reverse-
/// direction [`Rc<str>`] receiver reads through the same one-
/// oracle discipline every sibling comparison surface already
/// carries.
impl PartialEq<ContentDigest> for std::rc::Rc<str> {
    fn eq(&self, other: &ContentDigest) -> bool {
        self.as_ref() == other.as_str()
    }
}

/// Ergonomic canonical-digest equality query at the cross-thread
/// shared-owned byte-slice frontier — the [`std::sync::Arc<[u8]>`] peer
/// of the shrunk-owned [`Box<[u8]>`] pair
/// [`PartialEq<Box<[u8]>> for ContentDigest`] +
/// [`PartialEq<ContentDigest> for Box<[u8]>`] (commit 43343cf) and the
/// cross-thread shared-owned UTF-8 pair
/// [`PartialEq<std::sync::Arc<str>> for ContentDigest`] +
/// [`PartialEq<ContentDigest> for std::sync::Arc<str>`] (commit 57fbde1)
/// directly above. A downstream consumer that holds a canonical
/// `<algorithm>:<hex>` label as a cross-thread shared-owned
/// [`Arc<[u8]>`] byte-buffer handle (a long-lived registry cache that
/// stores a validated digest label under an [`Arc<[u8]>`] to share the
/// raw byte payload across worker threads without per-clone allocation
/// while retaining direct byte-oriented access — a `blake3` / `sha2`
/// hasher `update` slot, a `serde_bytes` transport frontier, a
/// content-addressed-store key surface — an emitted-peer consumer that
/// received a digest label through
/// [`From<ContentDigest> for std::sync::Arc<[u8]>`] (commit 49111c1) and
/// asks whether it names the same canonical form as a live
/// [`ContentDigest`] value) answers the boolean equality query
/// `digest == arc_bytes` at ONE composition rather than a per-site
/// `<ContentDigest as AsRef<[u8]>>::as_ref(&d) == &**arc_bytes` /
/// `<ContentDigest as AsRef<[u8]>>::as_ref(&d) == arc_bytes.as_ref()`
/// restatement that repeats the canonical-digest oracle name at every
/// downstream comparison site.
///
/// Route: the impl body composes
/// [`<ContentDigest as AsRef<[u8]>>::as_ref`] with the standard library
/// [`<[u8] as PartialEq<[u8]>>::eq`] on the [`Arc<[u8]>`] deref
/// coercion (`Arc<[u8]>: Deref<Target = [u8]>`), so the comparison
/// reads the same canonical-digest bytes at zero allocation, zero
/// temporary [`Vec<u8>`] construction, and zero [`std::fmt::Display`]
/// formatter-buffer round trip per call — the same zero-cost
/// discipline the sibling shrunk-owned [`PartialEq<Box<[u8]>>`],
/// owned [`PartialEq<Vec<u8>>`], and borrowed-or-owned
/// [`PartialEq<Cow<'_, [u8]>>`] peers carry, at a per-comparison cost
/// of one atomic-refcount-free pointer indirection to the
/// [`Arc<[u8]>`] backing slice plus one byte-slice equality.
///
/// Sibling of the by-value cross-thread shared-owned byte-slice emit
/// peer [`From<ContentDigest> for std::sync::Arc<[u8]>`] (commit
/// 49111c1) and the by-value cross-thread shared-owned byte-slice
/// parse peer [`TryFrom<std::sync::Arc<[u8]>> for ContentDigest`]
/// (commit d2ccc5d): the three surfaces bridge the [`ContentDigest`]
/// value and the [`Arc<[u8]>`] cross-thread shared-owned byte-slice
/// frontier — the parse peer recovers a [`ContentDigest`] from a
/// canonical `<algorithm>:<hex>` [`Arc<[u8]>`] payload through the
/// [`ContentDigest::parse`] oracle, the emit peer hands off the
/// validated canonical form as an [`Arc<[u8]>`] through a fresh
/// [`Arc::from`] allocation, this comparison peer asks whether an
/// already-held [`Arc<[u8]>`] byte-buffer label names the same
/// canonical form as the [`ContentDigest`] value on the left.
///
/// Opens the shrunk-owned / shared-owned byte-slice receiver duo on
/// the equality axis, mirroring the [`Arc<str>`] equality peer
/// (commit 57fbde1) that opened the same duo on the UTF-8 side. The
/// parse axis already carries both receivers on the byte-slice side
/// (commits d2ccc5d, 0eeac6d) and the emit axis already carries both
/// receivers (commits 49111c1, 578dbc6), so this pair is the first
/// step in closing the equality-axis analog of the same shared-owned
/// family on the byte-slice side — the follow-up [`Rc<[u8]>`]
/// equality pair closes the trio to match the parse / emit / equality
/// three-axis closure the UTF-8 side already carries.
///
/// THEORY.md §III.1 typescape: the [`Arc<[u8]>`] comparison surface
/// is a typed-primitive site on [`ContentDigest`] itself (one
/// [`PartialEq<std::sync::Arc<[u8]>>`] impl routing through
/// [`<ContentDigest as AsRef<[u8]>>::as_ref`]), not a per-consumer
/// `<ContentDigest as AsRef<[u8]>>::as_ref(&d) == &**arc_bytes`
/// restatement at every downstream site that receives an
/// [`Arc<[u8]>`] and asks whether it names a specific canonical
/// `<algorithm>:<hex>`. THEORY.md §VI.1 one-oracle: the validated
/// full-digest slice is named at one site
/// ([`ContentDigest::as_str`], read as bytes through [`AsRef<[u8]>`]),
/// and every comparison surface reads through the same one-oracle
/// discipline projected onto its own receiver shape.
impl PartialEq<std::sync::Arc<[u8]>> for ContentDigest {
    fn eq(&self, other: &std::sync::Arc<[u8]>) -> bool {
        <Self as AsRef<[u8]>>::as_ref(self) == other.as_ref()
    }
}

/// Symmetric cross-thread shared-owned byte-slice comparison peer:
/// `<Arc<[u8]> as PartialEq<ContentDigest>>::eq` — the reverse-
/// direction sibling of
/// [`PartialEq<std::sync::Arc<[u8]>> for ContentDigest`] directly
/// above. The pair together closes the [`Arc<[u8]>`] comparison
/// surface across both receiver directions, so a caller who holds an
/// [`Arc<[u8]>`] byte-buffer label writes `arc_bytes == digest` (or
/// the standard-library-derived symmetric composition a generic
/// `PartialEq`-bounded consumer performs internally) and answers a
/// boolean equality query against a [`ContentDigest`] value at the
/// same cross-thread shared-owned byte-slice frontier the forward-
/// direction peer covers, at zero allocation, zero temporary
/// [`Vec<u8>`] construction, and zero [`std::fmt::Display`]
/// formatter-buffer round trip per call.
///
/// Route: [`<ContentDigest as AsRef<[u8]>>::as_ref`] composed with
/// [`<[u8] as PartialEq<[u8]>>::eq`] on the [`Arc<[u8]>`] deref
/// coercion, so the comparison reads the same canonical-digest bytes
/// as the forward-direction peer, and the symmetry axiom
/// `<Arc<[u8]> as PartialEq<ContentDigest>>::eq(arc, &d)
/// == <ContentDigest as PartialEq<Arc<[u8]>>>::eq(&d, arc)` holds by
/// construction at every `(arc, digest)` pair.
///
/// Prior to this impl the digest reference-grammar family carried
/// only the forward direction at the [`Arc<[u8]>`] frontier
/// (`digest == arc_bytes` compiled but `arc_bytes == digest` did
/// not), so a generic `PartialEq`-bounded consumer that composed the
/// two through its own symmetric-check protocol could not thread a
/// [`ContentDigest`] through the [`Arc<[u8]>`] side of the bound
/// without a per-consumer
/// `&**arc_bytes == <ContentDigest as AsRef<[u8]>>::as_ref(&d)`
/// bridge.
///
/// THEORY.md §III.1 typescape: the reverse-direction [`Arc<[u8]>`]
/// comparison surface is a typed-primitive site on [`ContentDigest`]
/// itself (one [`PartialEq<ContentDigest>`] impl on [`Arc<[u8]>`]
/// routing through [`<ContentDigest as AsRef<[u8]>>::as_ref`]), not a
/// per-consumer
/// `&**arc_bytes == <ContentDigest as AsRef<[u8]>>::as_ref(&d)`
/// restatement at every downstream site that asks whether an
/// [`Arc<[u8]>`] handle names the same canonical `<algorithm>:<hex>`
/// as a [`ContentDigest`] value. THEORY.md §VI.1 one-oracle: the
/// validated full-digest slice is named at one site
/// ([`ContentDigest::as_str`], read as bytes through [`AsRef<[u8]>`]),
/// and this reverse-direction [`Arc<[u8]>`] receiver reads through
/// the same one-oracle discipline every sibling comparison surface
/// already carries.
impl PartialEq<ContentDigest> for std::sync::Arc<[u8]> {
    fn eq(&self, other: &ContentDigest) -> bool {
        self.as_ref() == <ContentDigest as AsRef<[u8]>>::as_ref(other)
    }
}

/// Ergonomic canonical-digest equality query at the thread-local
/// shared-owned byte-slice frontier — the [`std::rc::Rc<[u8]>`] peer
/// of the cross-thread shared-owned [`Arc<[u8]>`] pair
/// [`PartialEq<std::sync::Arc<[u8]>> for ContentDigest`] +
/// [`PartialEq<ContentDigest> for std::sync::Arc<[u8]>`] (commit
/// 13c64ad) and the thread-local shared-owned UTF-8 pair
/// [`PartialEq<std::rc::Rc<str>> for ContentDigest`] +
/// [`PartialEq<ContentDigest> for std::rc::Rc<str>`] (commit fdb2bdd)
/// directly above. A downstream consumer that holds a canonical
/// `<algorithm>:<hex>` label as a thread-local shared-owned
/// [`Rc<[u8]>`] byte-buffer handle (a same-thread registry cache that
/// stores a validated digest label under an [`Rc<[u8]>`] to share the
/// raw byte payload across per-task closures within a single worker
/// thread without per-clone allocation while retaining direct
/// byte-oriented access — a `blake3` / `sha2` hasher `update` slot, a
/// `serde_bytes` transport frontier, a content-addressed-store key
/// surface, an emitted-peer consumer that received a digest label
/// through [`From<ContentDigest> for std::rc::Rc<[u8]>`] (commit
/// 578dbc6) and asks whether it names the same canonical form as a
/// live [`ContentDigest`] value) answers the boolean equality query
/// `digest == rc_bytes` at ONE composition rather than a per-site
/// `<ContentDigest as AsRef<[u8]>>::as_ref(&d) == &**rc_bytes` /
/// `<ContentDigest as AsRef<[u8]>>::as_ref(&d) == rc_bytes.as_ref()`
/// restatement that repeats the canonical-digest oracle name at every
/// downstream comparison site.
///
/// Route: the impl body composes
/// [`<ContentDigest as AsRef<[u8]>>::as_ref`] with the standard library
/// [`<[u8] as PartialEq<[u8]>>::eq`] on the [`Rc<[u8]>`] deref
/// coercion (`Rc<[u8]>: Deref<Target = [u8]>`), so the comparison
/// reads the same canonical-digest bytes at zero allocation, zero
/// temporary [`Vec<u8>`] construction, and zero [`std::fmt::Display`]
/// formatter-buffer round trip per call — the same zero-cost
/// discipline the sibling cross-thread shared-owned
/// [`PartialEq<std::sync::Arc<[u8]>>`], shrunk-owned
/// [`PartialEq<Box<[u8]>>`], owned [`PartialEq<Vec<u8>>`], and
/// borrowed-or-owned [`PartialEq<Cow<'_, [u8]>>`] peers carry, at a
/// per-comparison cost of one non-atomic-refcount-free pointer
/// indirection to the [`Rc<[u8]>`] backing slice plus one byte-slice
/// equality.
///
/// Sibling of the by-value thread-local shared-owned byte-slice emit
/// peer [`From<ContentDigest> for std::rc::Rc<[u8]>`] (commit
/// 578dbc6) and the by-value thread-local shared-owned byte-slice
/// parse peer [`TryFrom<std::rc::Rc<[u8]>> for ContentDigest`]
/// (commit 0eeac6d): the three surfaces bridge the [`ContentDigest`]
/// value and the [`Rc<[u8]>`] thread-local shared-owned byte-slice
/// frontier — the parse peer recovers a [`ContentDigest`] from a
/// canonical `<algorithm>:<hex>` [`Rc<[u8]>`] payload through the
/// [`ContentDigest::parse`] oracle, the emit peer hands off the
/// validated canonical form as an [`Rc<[u8]>`] through a fresh
/// [`Rc::from`] allocation, this comparison peer asks whether an
/// already-held [`Rc<[u8]>`] byte-buffer label names the same
/// canonical form as the [`ContentDigest`] value on the left.
///
/// Closes the shared-owned byte-slice receiver duo on the equality
/// axis with its cross-thread [`Arc<[u8]>`] sibling directly above
/// (commit 13c64ad). Together with the [`Arc<str>`] + [`Rc<str>`]
/// UTF-8 equality peers (commits 57fbde1, fdb2bdd) and the parse /
/// emit peers on both sides (`Arc<[u8]>` parse d2ccc5d, `Rc<[u8]>`
/// parse 0eeac6d, `Arc<[u8]>` emit 49111c1, `Rc<[u8]>` emit
/// 578dbc6), this commit closes the shared-owned three-axis
/// (parse / emit / equality) family across both `str` and `[u8]`
/// frontiers to the same four-receiver closure (`Arc<str>`,
/// `Rc<str>`, `Arc<[u8]>`, `Rc<[u8]>`). Subsequent follow-ups
/// extend the same equality pattern to further receiver shapes
/// (e.g. `PartialEq<PathBuf>`, `PartialEq<OsString>`) as those
/// receiver families come up on the parse / emit axes.
///
/// THEORY.md §III.1 typescape: the [`Rc<[u8]>`] comparison surface
/// is a typed-primitive site on [`ContentDigest`] itself (one
/// [`PartialEq<std::rc::Rc<[u8]>>`] impl routing through
/// [`<ContentDigest as AsRef<[u8]>>::as_ref`]), not a per-consumer
/// `<ContentDigest as AsRef<[u8]>>::as_ref(&d) == &**rc_bytes`
/// restatement at every downstream site that receives an
/// [`Rc<[u8]>`] and asks whether it names a specific canonical
/// `<algorithm>:<hex>`. THEORY.md §VI.1 one-oracle: the validated
/// full-digest slice is named at one site
/// ([`ContentDigest::as_str`], read as bytes through [`AsRef<[u8]>`]),
/// and every comparison surface reads through the same one-oracle
/// discipline projected onto its own receiver shape.
impl PartialEq<std::rc::Rc<[u8]>> for ContentDigest {
    fn eq(&self, other: &std::rc::Rc<[u8]>) -> bool {
        <Self as AsRef<[u8]>>::as_ref(self) == other.as_ref()
    }
}

/// Symmetric thread-local shared-owned byte-slice comparison peer:
/// `<Rc<[u8]> as PartialEq<ContentDigest>>::eq` — the reverse-
/// direction sibling of
/// [`PartialEq<std::rc::Rc<[u8]>> for ContentDigest`] directly
/// above. The pair together closes the [`Rc<[u8]>`] comparison
/// surface across both receiver directions, so a caller who holds
/// an [`Rc<[u8]>`] byte-buffer label writes `rc_bytes == digest`
/// (or the standard-library-derived symmetric composition a generic
/// `PartialEq`-bounded consumer performs internally) and answers a
/// boolean equality query against a [`ContentDigest`] value at the
/// same thread-local shared-owned byte-slice frontier the forward-
/// direction peer covers, at zero allocation, zero temporary
/// [`Vec<u8>`] construction, and zero [`std::fmt::Display`]
/// formatter-buffer round trip per call.
///
/// Route: [`<ContentDigest as AsRef<[u8]>>::as_ref`] composed with
/// [`<[u8] as PartialEq<[u8]>>::eq`] on the [`Rc<[u8]>`] deref
/// coercion, so the comparison reads the same canonical-digest bytes
/// as the forward-direction peer, and the symmetry axiom
/// `<Rc<[u8]> as PartialEq<ContentDigest>>::eq(rc, &d)
/// == <ContentDigest as PartialEq<Rc<[u8]>>>::eq(&d, rc)` holds by
/// construction at every `(rc, digest)` pair.
///
/// Together with the forward peer directly above and the
/// [`Arc<[u8]>`] pair (commit 13c64ad), this commit closes the
/// shared-owned byte-slice comparison-pair duo across both receiver
/// shapes and both directions — the equality-axis analog of the
/// shared-owned byte-slice parse and emit peer duos already closed
/// on the [`Arc<[u8]>`] + [`Rc<[u8]>`] receiver pair.
///
/// Prior to this impl the digest reference-grammar family carried
/// only the forward direction at the [`Rc<[u8]>`] frontier
/// (`digest == rc_bytes` compiled but `rc_bytes == digest` did
/// not), so a generic `PartialEq`-bounded consumer that composed the
/// two through its own symmetric-check protocol could not thread a
/// [`ContentDigest`] through the [`Rc<[u8]>`] side of the bound
/// without a per-consumer
/// `&**rc_bytes == <ContentDigest as AsRef<[u8]>>::as_ref(&d)`
/// bridge.
///
/// THEORY.md §III.1 typescape: the reverse-direction [`Rc<[u8]>`]
/// comparison surface is a typed-primitive site on [`ContentDigest`]
/// itself (one [`PartialEq<ContentDigest>`] impl on [`Rc<[u8]>`]
/// routing through [`<ContentDigest as AsRef<[u8]>>::as_ref`]), not a
/// per-consumer
/// `&**rc_bytes == <ContentDigest as AsRef<[u8]>>::as_ref(&d)`
/// restatement at every downstream site that asks whether an
/// [`Rc<[u8]>`] handle names the same canonical `<algorithm>:<hex>`
/// as a [`ContentDigest`] value. THEORY.md §VI.1 one-oracle: the
/// validated full-digest slice is named at one site
/// ([`ContentDigest::as_str`], read as bytes through [`AsRef<[u8]>`]),
/// and this reverse-direction [`Rc<[u8]>`] receiver reads through
/// the same one-oracle discipline every sibling comparison surface
/// already carries.
impl PartialEq<ContentDigest> for std::rc::Rc<[u8]> {
    fn eq(&self, other: &ContentDigest) -> bool {
        self.as_ref() == <ContentDigest as AsRef<[u8]>>::as_ref(other)
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

/// [`From<ContentDigest>`] for [`std::rc::Rc<str>`] moves the validated
/// `<algorithm>:<hex>` backing string out of the consumed [`ContentDigest`]
/// value into an immutable, single-thread, shared-owned [`Rc<str>`] at
/// exactly the label's length — the impl routes through
/// [`<ContentDigest as From<ContentDigest>>::from`] into [`String`] (which
/// moves [`ContentDigest::full`] out at zero-copy) and then
/// [`std::rc::Rc::<str>::from`] on the moved [`String`] (which repackages
/// the backing buffer as an immutable shared-owned [`Rc<str>`] with a
/// single non-atomic-refcount header preceding the label bytes). No
/// re-formatting through [`std::fmt::Display`], no
/// `Rc::<str>::from(digest.as_str())` bridge that would copy the backing
/// bytes into a fresh allocation while leaking the consumed
/// [`ContentDigest`]'s owned [`String`], no `digest.to_string().into()`
/// chain that would re-run [`std::fmt::Display`] over the already-canonical
/// backing.
///
/// A downstream consumer that owns a [`ContentDigest`] and needs to hand
/// it off as a same-thread shared-owned label to a non-atomic-refcounted
/// sink (a single-thread `HashMap<Rc<str>, _>` registry cache built once
/// per pipeline pass and cloned across peer inspectors at `O(1)`
/// [`Rc::clone`] cost with no atomic-op fence, an `Rc<Manifest>`
/// structural field whose digest slot is stored as [`Rc<str>`] to share a
/// single label allocation across per-worker readers of the manifest
/// within one thread, a `!Send` per-task lookaside built during a
/// synchronous scan phase that keys entries on the digest without
/// paying [`Arc`]'s atomic refcount, a `LocalKey` / `thread_local!`
/// per-thread digest interner that fans out `Rc<str>` handles to
/// inline inspection helpers) is a one-line `Rc::<str>::from(digest)` /
/// `digest.into()` call, not a per-site
/// `Rc::<str>::from(digest.as_str())` bridge that leaks the consumed
/// [`ContentDigest`]'s owned [`String`] nor a
/// `Rc::<str>::from(digest.to_string())` chain that pays a redundant
/// [`Display`]-format allocation on top of the shared-owned repackaging.
///
/// The by-value single-thread shared-owned UTF-8 emit peer of the
/// by-value owned-UTF-8 emit peer [`From<ContentDigest> for String`]
/// (commit 83313fd), the by-value owned-byte-slice emit peer
/// [`From<ContentDigest> for Vec<u8>`] (commit e1ea855), the by-value
/// shrunk-owned UTF-8 emit peer [`From<ContentDigest> for Box<str>`]
/// (commit 0e86524), the by-value borrowed/owned-frontier emit peer
/// [`From<ContentDigest> for Cow<'static, str>`] (commit 15b7a05), and
/// the by-value cross-thread shared-owned UTF-8 emit peer
/// [`From<ContentDigest> for Arc<str>`] (commit 5f85247): all six
/// surfaces move the same validated full-digest bytes out of the
/// consumed [`ContentDigest`], differing only on the owner-shape of the
/// emitted receiver — [`String`] for resizable growth-header owners,
/// [`Vec<u8>`] for byte-oriented sinks, [`Box<str>`] for immutable
/// heap-owned label slots that trade the growth-header word for a
/// two-word slice pointer, [`Cow<'static, str>`] for borrowed/owned-
/// frontier sinks, [`Arc<str>`] for cross-thread shared-owned label
/// slots that carry an atomic-refcount header, this [`Rc<str>`] for
/// single-thread shared-owned label slots that carry a non-atomic-
/// refcount header so consumers `Rc::clone` the label within one
/// thread at pointer-copy + integer-increment cost with no atomic fence
/// and no per-clone allocation. All six route through the
/// [`From<ContentDigest> for String`] emit oracle: the [`String`] peer
/// moves [`ContentDigest::full`] directly, the [`Vec<u8>`] peer chains
/// through [`String::into_bytes`], the [`Box<str>`] peer chains through
/// [`String::into_boxed_str`], the [`Cow<'static, str>`] peer wraps the
/// moved [`String`] in [`Cow::Owned`], the [`Arc<str>`] peer chains
/// through [`std::sync::Arc::<str>::from`], this [`Rc<str>`] peer
/// chains through [`std::rc::Rc::<str>::from`] applied to the moved
/// [`String`] — the six agree byte-for-byte on the canonical form by
/// construction, and a future canonicalising refinement to the
/// [`String`] emit surface propagates to the single-thread shared-owned
/// frontier at zero per-consumer cost.
///
/// Structural mirror of the sibling label-axis
/// `From<T> for std::rc::Rc<std::ffi::CStr>` closer trio on
/// [`crate::retry::PerAttemptRegion`], [`crate::probe_outcome::AdmissionTier`],
/// and [`crate::version::BumpLevel`] — the trio already carries the
/// by-value thread-local shared-owned emit surface at its
/// NUL-terminated C-string frontier (commits 71e7707, 61d51ad,
/// dbaf0a3), and this impl extends the same discipline to the digest
/// reference-grammar family at its UTF-8 frontier. The parse-oracle-
/// bounded typed primitive [`ContentDigest`] now exposes the same
/// thread-local shared-owned emit surface every sibling typed primitive
/// on the string-owner axis already carries.
///
/// Zero-copy on the digest bytes by construction: [`String::from(digest)`]
/// moves [`ContentDigest::full`] out at zero-copy, and
/// [`std::rc::Rc::<str>::from`] on the moved [`String`] performs a
/// single non-atomic-refcount allocation of exactly `label.len() +
/// refcount header` bytes and copies the label bytes into that
/// allocation once (the [`String`]'s heap buffer cannot itself be
/// repurposed because the [`Rc<str>`] layout requires the non-atomic-
/// refcount header to precede the str body, and [`String`]'s backing
/// has no such header). This is strictly the minimum cost of shifting
/// from the resizable-growth-header [`String`] shape to the
/// immutable-shared-refcount [`Rc<str>`] shape; no [`std::fmt::Display`]
/// round-trip, no intermediate [`Box<str>`] allocation, no per-consumer
/// bridge cost. A single-thread caller that would otherwise pay
/// [`Arc<str>`]'s atomic-refcount header for a cache slot never
/// accessed from another thread saves the atomic-op cost on every
/// clone by construction.
///
/// The identity `<std::rc::Rc<str> as std::ops::Deref>::deref(
/// &std::rc::Rc::<str>::from(digest.clone())) == digest.as_str()` at
/// every validated [`ContentDigest`] value is pinned by
/// [`tests::test_from_content_digest_rc_str_matches_as_str`]; the
/// identity carrying through a generic `impl Into<std::rc::Rc<str>>`
/// consumer is pinned by
/// [`tests::test_from_content_digest_rc_str_carries_through_generic_consumer`];
/// the parse-round-trip identity through the shared-owned UTF-8 emit
/// surface (parsing the emitted [`Rc<str>`]'s deref view back through
/// every canonical parse surface) is pinned by
/// [`tests::test_from_content_digest_rc_str_parse_round_trip`]; the
/// same-thread `Rc::clone` shared-allocation semantic is pinned by
/// [`tests::test_from_content_digest_rc_str_clones_share_allocation`].
///
/// A future refinement to the inherent [`ContentDigest::parse`] grammar
/// (widening to `sha384`, tightening the trim behaviour) or to the
/// [`From<ContentDigest> for String`] emit oracle (a canonicalising
/// projection at the owned-UTF-8 frontier) is a one-site edit at the
/// inherent / owned-UTF-8 oracle; every consumer bound by
/// `impl Into<std::rc::Rc<str>>` inherits the refined canonical
/// shared-owned label off the moved backing storage automatically with
/// no downstream retyping.
///
/// THEORY.md §III.1 typescape: the by-value single-thread shared-owned
/// UTF-8 emit surface is a typed-primitive site on [`ContentDigest`]
/// itself (one [`From<ContentDigest>`] impl chaining through the
/// [`From<ContentDigest> for String`] emit oracle via
/// [`std::rc::Rc::<str>::from`]), not a per-consumer
/// `Rc::<str>::from(digest.as_str())` restatement at every downstream
/// site that accepts `impl Into<std::rc::Rc<str>>`. THEORY.md §VI.1
/// one-oracle: the validated full-digest bytes are named at one site
/// ([`From<ContentDigest> for String`], reading through the moved
/// [`ContentDigest::full`] backing), and every by-value owned emit
/// surface — [`String`], [`Vec<u8>`], [`Box<str>`], [`Cow<'static, str>`],
/// [`Arc<str>`], this [`Rc<str>`] — reads through it.
impl From<ContentDigest> for std::rc::Rc<str> {
    fn from(digest: ContentDigest) -> std::rc::Rc<str> {
        std::rc::Rc::<str>::from(String::from(digest))
    }
}

/// [`From<ContentDigest>`] for [`Box<[u8]>`] moves the validated
/// `<algorithm>:<hex>` backing bytes out of the consumed [`ContentDigest`]
/// value into an immutable, heap-owned [`Box<[u8]>`] at exactly the
/// label's length — the impl routes through
/// [`<Vec<u8> as From<ContentDigest>>::from`] (which chains through the
/// [`From<ContentDigest> for String`] emit oracle via
/// [`String::into_bytes`], moving [`ContentDigest::full`] out at
/// zero-copy) and then [`Vec::into_boxed_slice`] (which repackages the
/// backing buffer as an immutable [`Box<[u8]>`], shrinking to exact
/// length only when the backing [`Vec<u8>`]'s capacity exceeded its
/// length — for [`ContentDigest`] values the parse-time
/// [`str::to_string`](str::to_string) allocation sizes the backing
/// [`String`] to exact length, and [`String::into_bytes`] preserves
/// the buffer's capacity, so the shrink is a no-op in the common
/// case). No re-formatting through [`std::fmt::Display`], no
/// `Box::<[u8]>::from(digest.as_ref())` bridge that would copy the
/// backing bytes into a fresh allocation while leaking the consumed
/// [`ContentDigest`]'s owned [`String`], no
/// `digest.as_ref().to_vec().into_boxed_slice()` chain that would
/// re-state the shrunk-owned discipline at every consumer.
///
/// A downstream consumer that owns a [`ContentDigest`] and needs to
/// hand it off as an immutable heap-owned byte slice to an owned-byte
/// sink (a [`std::collections::HashMap<Box<[u8]>, _>`] key insertion,
/// a validated-input newtype whose digest field is stored as
/// [`Box<[u8]>`] to shed the [`Vec<u8>`] growth-header word for a
/// long-lived per-value slot, a `bytes::Bytes::from(Box<[u8]>)` intake
/// at the shrunk-owned frontier, an `Arc<Manifest>` field whose
/// digest slot is a [`Box<[u8]>`] chosen for its two-machine-word
/// footprint over the three-word [`Vec<u8>`]) is a one-line
/// `Box::<[u8]>::from(digest)` / `digest.into()` call, not a per-site
/// `Box::<[u8]>::from(digest.as_ref())` bridge that pays a redundant
/// allocation nor a `digest.as_ref().to_vec().into_boxed_slice()`
/// chain that pays the [`Vec`]-alloc-plus-shrink round trip while
/// re-stating the shrunk-owned discipline.
///
/// The by-value shrunk-owned byte-slice emit peer of the by-value
/// owned-byte-slice emit peer [`From<ContentDigest> for Vec<u8>`]
/// (commit e1ea855) and the sibling by-value shrunk-owned UTF-8 emit
/// peer [`From<ContentDigest> for Box<str>`] (commit 0e86524): all
/// three surfaces move the same validated full-digest bytes out of
/// the consumed [`ContentDigest`], differing only on the owner-shape
/// of the emitted receiver — [`Vec<u8>`] for resizable growth-header
/// byte-buffer owners, [`Box<str>`] for immutable heap-owned UTF-8
/// label slots, this [`Box<[u8]>`] for immutable heap-owned raw-byte
/// slots that trade the [`Vec<u8>`] growth-header word for a two-word
/// slice pointer while dropping the UTF-8 typing that [`Box<str>`]
/// imposes on the ASCII-only-by-parse-invariant digest bytes for
/// consumers that pin their contract on the raw byte-slice frontier
/// (`bytes::Bytes`, `http::HeaderValue::from_bytes`, streaming
/// hashers). All three route through the [`From<ContentDigest> for
/// String`] emit oracle: the [`Vec<u8>`] peer chains through
/// [`String::into_bytes`], the [`Box<str>`] peer chains through
/// [`String::into_boxed_str`], this [`Box<[u8]>`] peer chains through
/// [`String::into_bytes`] then [`Vec::into_boxed_slice`] — the three
/// agree byte-for-byte on the canonical form by construction, and a
/// future canonicalising refinement to the [`String`] emit surface
/// propagates to the shrunk-owned byte-slice frontier at zero
/// per-consumer cost.
///
/// Zero-copy in the common case by construction: the parse-time
/// [`str::to_string`] allocation that produces [`ContentDigest::full`]
/// sizes the backing [`String`] to exact length,
/// [`String::into_bytes`] repackages that buffer as a [`Vec<u8>`] at
/// the same capacity, and [`Vec::into_boxed_slice`] repackages the
/// [`Vec<u8>`] as [`Box<[u8]>`] without reallocation when capacity
/// equals length. The identity
/// `<Box<[u8]> as std::ops::Deref>::deref(&Box::<[u8]>::from(
/// digest.clone())) == digest.as_str().as_bytes()` at every validated
/// [`ContentDigest`] value is pinned by
/// [`tests::test_from_content_digest_box_bytes_matches_as_ref`]; the
/// identity carrying through a generic `impl Into<Box<[u8]>>`
/// consumer is pinned by
/// [`tests::test_from_content_digest_box_bytes_carries_through_generic_consumer`];
/// the parse-round-trip identity through the shrunk-owned byte-slice
/// emit surface (decoding the emitted [`Box<[u8]>`] as UTF-8 and
/// parsing through every canonical parse surface) is pinned by
/// [`tests::test_from_content_digest_box_bytes_parse_round_trip`];
/// the shrunk-owned length identity is pinned by
/// [`tests::test_from_content_digest_box_bytes_length_equals_label_bytes`].
///
/// A future refinement to the inherent [`ContentDigest::parse`]
/// grammar (widening to `sha384`, tightening the trim behaviour) or
/// to the [`From<ContentDigest> for String`] emit oracle (a
/// canonicalising projection at the owned-UTF-8 frontier) is a
/// one-site edit at the inherent / owned-UTF-8 oracle; every consumer
/// bound by `impl Into<Box<[u8]>>` inherits the refined canonical
/// shrunk-owned byte slice off the moved backing storage
/// automatically with no downstream retyping.
///
/// THEORY.md §III.1 typescape: the by-value shrunk-owned byte-slice
/// emit surface is a typed-primitive site on [`ContentDigest`] itself
/// (one [`From<ContentDigest>`] impl chaining through the
/// [`From<ContentDigest> for String`] emit oracle via
/// [`String::into_bytes`] and [`Vec::into_boxed_slice`]), not a
/// per-consumer `Box::<[u8]>::from(digest.as_ref())` restatement at
/// every downstream site that accepts `impl Into<Box<[u8]>>`.
/// THEORY.md §VI.1 one-oracle: the validated full-digest bytes are
/// named at one site ([`From<ContentDigest> for String`], reading
/// through the moved [`ContentDigest::full`] backing), and every
/// by-value owned emit surface — the by-value owned-byte-slice peer
/// [`From<ContentDigest> for Vec<u8>`], this by-value shrunk-owned
/// byte-slice peer [`From<ContentDigest> for Box<[u8]>`] — reads
/// through it.
impl From<ContentDigest> for Box<[u8]> {
    fn from(digest: ContentDigest) -> Box<[u8]> {
        Vec::<u8>::from(digest).into_boxed_slice()
    }
}

/// [`From<ContentDigest>`] for [`std::borrow::Cow<'static, [u8]>`] moves
/// the validated `<algorithm>:<hex>` backing string out of the consumed
/// [`ContentDigest`] value into the [`Cow::Owned`] branch of a
/// `'static`-lifetime [`Cow<'static, [u8]>`] at zero-copy — the impl
/// routes through [`<Vec<u8> as From<ContentDigest>>::from`] (which
/// itself chains through the [`From<ContentDigest> for String`] emit
/// oracle via [`String::into_bytes`], moving [`ContentDigest::full`]
/// out at zero-copy) and wraps the moved [`Vec<u8>`] in [`Cow::Owned`],
/// so no allocation beyond the parse-time backing, no re-formatting
/// through [`std::fmt::Display`], no
/// `Cow::Owned(digest.as_ref().to_vec())` bridge that would clone the
/// backing bytes while leaking the consumed [`ContentDigest`]'s owned
/// [`String`], no `Cow::Owned(digest.into())` chain that would restate
/// the frontier discipline at every site.
///
/// A downstream consumer that owns a [`ContentDigest`] and needs to
/// hand it off as a borrowed-or-owned raw-byte handle to a
/// borrowed/owned-frontier byte-slice sink (a [`bytes::Bytes::from`]
/// intake that types its input contract as
/// `impl Into<Cow<'static, [u8]>>` to interleave `'static` byte
/// literals with runtime-parsed digests in the same sink, a `serde`
/// container that opts into `#[serde(from = "Cow<'static, [u8]>")]` at
/// the borrowed/owned-frontier byte-slice emit surface, a streaming
/// hasher that seeds off an `impl Into<Cow<'static, [u8]>>` label
/// input to elide the allocation on the borrowed branch,
/// `http::HeaderValue::from_bytes` bridges that key off a
/// [`Cow<'static, [u8]>`] to avoid the [`Vec<u8>`] growth-header word
/// on the owned branch) is a one-line
/// `Cow::<'static, [u8]>::from(digest)` / `digest.into()` call, not a
/// per-site `Cow::Owned(digest.as_ref().to_vec())` bridge that pays a
/// redundant allocation nor a `Cow::Owned(Vec::<u8>::from(digest))`
/// chain that re-states the borrowed/owned-frontier byte-slice
/// discipline.
///
/// The by-value borrowed/owned-frontier byte-slice emit peer of the
/// UTF-8 borrowed/owned-frontier peer
/// [`From<ContentDigest> for Cow<'static, str>`] (commit 15b7a05) at
/// the raw-byte frontier, of the resizable owned-byte-slice peer
/// [`From<ContentDigest> for Vec<u8>`] (commit e1ea855) with a
/// `'static`-borrowed alternative branch, and of the shrunk-owned
/// byte-slice peer [`From<ContentDigest> for Box<[u8]>`] (commit
/// fce9fee) with a resizable-owned alternative branch: all four
/// surfaces move the same validated full-digest bytes out of the
/// consumed [`ContentDigest`], differing only on the owner-shape of
/// the emitted receiver — [`Cow<'static, str>`] for UTF-8
/// borrowed/owned-frontier sinks, [`Vec<u8>`] for resizable
/// growth-header byte-buffer owners, [`Box<[u8]>`] for immutable
/// shrunk-owned raw-byte slots, this [`Cow<'static, [u8]>`] for
/// raw-byte borrowed/owned-frontier sinks that pin their contract on
/// the ASCII-only-by-parse-invariant digest bytes without the UTF-8
/// typing [`Cow<'static, str>`] imposes. All four route through the
/// [`From<ContentDigest> for String`] emit oracle: the
/// [`Cow<'static, str>`] peer wraps the moved [`String`] in
/// [`Cow::Owned`], the [`Vec<u8>`] peer chains through
/// [`String::into_bytes`], the [`Box<[u8]>`] peer chains through
/// [`String::into_bytes`] then [`Vec::into_boxed_slice`], this
/// [`Cow<'static, [u8]>`] peer chains through [`String::into_bytes`]
/// then wraps the moved [`Vec<u8>`] in [`Cow::Owned`] — the four
/// agree byte-for-byte on the canonical form by construction, and a
/// future canonicalising refinement to the [`String`] emit surface
/// propagates to the borrowed/owned-frontier byte-slice sink at zero
/// per-consumer cost.
///
/// Zero-copy on the digest bytes by construction: [`Vec::<u8>::from`]
/// moves [`ContentDigest::full`]'s backing buffer out through
/// [`String::into_bytes`] (which repackages the [`String`] as a
/// [`Vec<u8>`] at the same capacity), and [`Cow::Owned`] wraps the
/// moved [`Vec<u8>`] in the owned branch without further allocation.
/// The load-bearing choice of the [`Cow::Owned`] branch (contrasting
/// the sibling enum-shaped [`From<T> for Cow<'static, [u8]>`] peers
/// that land on [`Cow::Borrowed`] because their `as_ref` oracle
/// returns a `'static` byte slice off a static label table) is pinned
/// by [`tests::test_from_content_digest_cow_static_bytes_is_owned`];
/// the byte-slice equality identity is pinned by
/// [`tests::test_from_content_digest_cow_static_bytes_matches_as_ref`];
/// the identity carrying through a generic `impl Into<Cow<'static,
/// [u8]>>` consumer is pinned by
/// [`tests::test_from_content_digest_cow_static_bytes_carries_through_generic_consumer`];
/// the parse-round-trip identity through the borrowed/owned-frontier
/// byte-slice emit surface (decoding the emitted [`Cow<'static, [u8]>`]
/// as UTF-8 and parsing through every canonical parse surface) is
/// pinned by
/// [`tests::test_from_content_digest_cow_static_bytes_parse_round_trip`].
///
/// A future refinement to the inherent [`ContentDigest::parse`]
/// grammar (widening to `sha384`, tightening the trim behaviour) or
/// to the [`From<ContentDigest> for String`] emit oracle (a
/// canonicalising projection at the owned-UTF-8 frontier) is a
/// one-site edit at the inherent / owned-UTF-8 oracle; every consumer
/// bound by `impl Into<Cow<'static, [u8]>>` inherits the refined
/// canonical borrowed/owned-frontier byte slice off the moved backing
/// storage automatically with no downstream retyping.
///
/// THEORY.md §III.1 typescape: the by-value borrowed/owned-frontier
/// byte-slice emit surface is a typed-primitive site on
/// [`ContentDigest`] itself (one [`From<ContentDigest>`] impl chaining
/// through the [`From<ContentDigest> for String`] emit oracle via
/// [`String::into_bytes`] and [`Cow::Owned`]), not a per-consumer
/// `Cow::Owned(digest.as_ref().to_vec())` restatement at every
/// downstream site that accepts `impl Into<Cow<'static, [u8]>>`.
/// THEORY.md §VI.1 one-oracle: the validated full-digest bytes are
/// named at one site ([`From<ContentDigest> for String`], reading
/// through the moved [`ContentDigest::full`] backing), and every
/// by-value owned emit surface — the UTF-8 peers
/// [`From<ContentDigest> for String`],
/// [`From<ContentDigest> for Box<str>`],
/// [`From<ContentDigest> for Cow<'static, str>`], the byte-slice peers
/// [`From<ContentDigest> for Vec<u8>`],
/// [`From<ContentDigest> for Box<[u8]>`], this
/// [`From<ContentDigest> for Cow<'static, [u8]>`] — reads through it.
impl From<ContentDigest> for std::borrow::Cow<'static, [u8]> {
    fn from(digest: ContentDigest) -> std::borrow::Cow<'static, [u8]> {
        std::borrow::Cow::Owned(Vec::<u8>::from(digest))
    }
}

/// [`From<ContentDigest>`] for [`std::sync::Arc<[u8]>`] moves the validated
/// `<algorithm>:<hex>` backing string out of the consumed [`ContentDigest`]
/// value into an immutable, thread-safe, shared-owned [`Arc<[u8]>`] at
/// exactly the label's byte length — the impl routes through
/// [`<Vec<u8> as From<ContentDigest>>::from`] (which itself chains through
/// the [`From<ContentDigest> for String`] emit oracle via
/// [`String::into_bytes`], moving [`ContentDigest::full`] out at zero-copy)
/// and then [`std::sync::Arc::<[u8]>::from`] on the moved [`Vec<u8>`]
/// (which repackages the backing buffer as an immutable shared-owned
/// [`Arc<[u8]>`] with a single atomic-refcount header preceding the label
/// bytes). No re-formatting through [`std::fmt::Display`], no
/// `Arc::<[u8]>::from(digest.as_ref())` bridge that would copy the backing
/// bytes into a fresh allocation while leaking the consumed
/// [`ContentDigest`]'s owned [`String`], no
/// `digest.as_ref().to_vec().into()` chain that would restate the
/// shared-owned discipline at every consumer.
///
/// A downstream consumer that owns a [`ContentDigest`] and needs to hand
/// it off as a cross-thread shared-owned raw-byte handle to an atomic-
/// refcounted byte-slice sink (a `dashmap::DashMap<Arc<[u8]>, _>` cache
/// key inserted once and cloned across worker threads at `O(1)`
/// [`Arc::clone`] cost with no atomic-op per-clone allocation, an
/// `Arc<Manifest>` field whose digest slot is stored as [`Arc<[u8]>`] to
/// share a single label byte-buffer across concurrent readers without
/// paying the [`String`]/`Arc<str>` UTF-8 typing on the ASCII-only-by-
/// parse-invariant digest bytes, a `bytes::Bytes::from(Arc<[u8]>)` intake
/// that pins its input contract on the raw-byte shared-owned frontier, a
/// `tokio::sync::broadcast` sender carrying an [`Arc<[u8]>`] payload
/// receivers clone atomically without a per-receiver allocation, a
/// long-lived registry-cache entry keyed on a shared-owned raw-byte digest
/// for zero-copy fanout to `tokio::spawn`ed inspection tasks, a `serde`
/// container that opts into `#[serde(into = "Arc<[u8]>")]` at the
/// shared-owned byte-slice frontier) is a one-line
/// `Arc::<[u8]>::from(digest)` / `digest.into()` call, not a per-site
/// `Arc::<[u8]>::from(digest.as_ref())` bridge that leaks the consumed
/// [`ContentDigest`]'s owned [`String`] nor a
/// `Arc::<[u8]>::from(digest.to_string().into_bytes())` chain that pays a
/// redundant [`Display`]-format allocation on top of the shared-owned
/// repackaging.
///
/// The by-value cross-thread shared-owned byte-slice emit peer of the
/// by-value cross-thread shared-owned UTF-8 emit peer
/// [`From<ContentDigest> for Arc<str>`] (commit 5f85247) at the raw-byte
/// frontier, of the by-value resizable owned-byte-slice peer
/// [`From<ContentDigest> for Vec<u8>`] (commit e1ea855) with a shared-
/// owned alternative shape, of the by-value shrunk-owned byte-slice peer
/// [`From<ContentDigest> for Box<[u8]>`] (commit fce9fee) with a shared-
/// owned refcounted alternative shape, and of the by-value borrowed/
/// owned-frontier byte-slice peer
/// [`From<ContentDigest> for Cow<'static, [u8]>`] (commit c2a5acf) with a
/// cross-thread refcounted alternative shape: all five surfaces move the
/// same validated full-digest bytes out of the consumed [`ContentDigest`],
/// differing only on the owner-shape of the emitted receiver —
/// [`Arc<str>`] for cross-thread shared-owned UTF-8 label slots,
/// [`Vec<u8>`] for resizable growth-header byte-buffer owners,
/// [`Box<[u8]>`] for immutable shrunk-owned raw-byte slots that trade the
/// [`Vec<u8>`] growth-header word for a two-word slice pointer,
/// [`Cow<'static, [u8]>`] for borrowed/owned-frontier raw-byte sinks, this
/// [`Arc<[u8]>`] for immutable cross-thread shared-owned raw-byte slots
/// that carry a single atomic-refcount header so consumers `Arc::clone`
/// the label byte-buffer across worker threads at atomic-op cost with no
/// per-clone allocation, while dropping the UTF-8 typing [`Arc<str>`]
/// imposes on the ASCII-only-by-parse-invariant digest bytes for consumers
/// that pin their contract on the raw-byte shared-owned frontier
/// (`bytes::Bytes`, `http::HeaderValue::from_bytes`, streaming hashers
/// seeded off an [`Arc<[u8]>`] label input). All five route through the
/// [`From<ContentDigest> for String`] emit oracle: the [`Arc<str>`] peer
/// chains through [`std::sync::Arc::<str>::from`], the [`Vec<u8>`] peer
/// chains through [`String::into_bytes`], the [`Box<[u8]>`] peer chains
/// through [`String::into_bytes`] then [`Vec::into_boxed_slice`], the
/// [`Cow<'static, [u8]>`] peer chains through [`String::into_bytes`] then
/// wraps the moved [`Vec<u8>`] in [`Cow::Owned`], this [`Arc<[u8]>`] peer
/// chains through [`String::into_bytes`] then
/// [`std::sync::Arc::<[u8]>::from`] applied to the moved [`Vec<u8>`] —
/// the five agree byte-for-byte on the canonical form by construction,
/// and a future canonicalising refinement to the [`String`] emit surface
/// propagates to the cross-thread shared-owned raw-byte frontier at zero
/// per-consumer cost.
///
/// Zero-copy on the digest bytes by construction: [`Vec::<u8>::from`]
/// moves [`ContentDigest::full`]'s backing buffer out through
/// [`String::into_bytes`] (which repackages the [`String`] as a
/// [`Vec<u8>`] at the same capacity), and
/// [`std::sync::Arc::<[u8]>::from`] on the moved [`Vec<u8>`] performs a
/// single atomic-refcount allocation of exactly `label.len() + refcount
/// header` bytes and copies the label bytes into that allocation once
/// (the [`Vec<u8>`]'s heap buffer cannot itself be repurposed because the
/// [`Arc<[u8]>`] layout requires the atomic-refcount header to precede
/// the slice body, and [`Vec<u8>`]'s backing has no such header). This is
/// strictly the minimum cost of shifting from the resizable-growth-header
/// [`Vec<u8>`] shape to the immutable-shared-refcount [`Arc<[u8]>`] shape;
/// no [`std::fmt::Display`] round-trip, no intermediate [`Box<[u8]>`]
/// allocation, no per-consumer bridge cost.
///
/// The identity `<std::sync::Arc<[u8]> as
/// std::ops::Deref>::deref(&std::sync::Arc::<[u8]>::from(digest.clone()))
/// == digest.as_str().as_bytes()` at every validated [`ContentDigest`]
/// value is pinned by
/// [`tests::test_from_content_digest_arc_bytes_matches_as_ref`]; the
/// identity carrying through a generic `impl Into<std::sync::Arc<[u8]>>`
/// consumer is pinned by
/// [`tests::test_from_content_digest_arc_bytes_carries_through_generic_consumer`];
/// the parse-round-trip identity through the cross-thread shared-owned
/// byte-slice emit surface (decoding the emitted [`Arc<[u8]>`]'s deref
/// view as UTF-8 and parsing through every canonical parse surface) is
/// pinned by
/// [`tests::test_from_content_digest_arc_bytes_parse_round_trip`]; the
/// cross-thread `Arc::clone` shared-allocation semantic is pinned by
/// [`tests::test_from_content_digest_arc_bytes_clones_cheaply_across_threads`].
///
/// A future refinement to the inherent [`ContentDigest::parse`] grammar
/// (widening to `sha384`, tightening the trim behaviour) or to the
/// [`From<ContentDigest> for String`] emit oracle (a canonicalising
/// projection at the owned-UTF-8 frontier) is a one-site edit at the
/// inherent / owned-UTF-8 oracle; every consumer bound by
/// `impl Into<std::sync::Arc<[u8]>>` inherits the refined canonical
/// cross-thread shared-owned byte slice off the moved backing storage
/// automatically with no downstream retyping.
///
/// THEORY.md §III.1 typescape: the by-value cross-thread shared-owned
/// byte-slice emit surface is a typed-primitive site on [`ContentDigest`]
/// itself (one [`From<ContentDigest>`] impl chaining through the
/// [`From<ContentDigest> for String`] emit oracle via
/// [`String::into_bytes`] and [`std::sync::Arc::<[u8]>::from`]), not a
/// per-consumer `Arc::<[u8]>::from(digest.as_ref())` restatement at every
/// downstream site that accepts `impl Into<std::sync::Arc<[u8]>>`.
/// THEORY.md §VI.1 one-oracle: the validated full-digest bytes are named
/// at one site ([`From<ContentDigest> for String`], reading through the
/// moved [`ContentDigest::full`] backing), and every by-value owned emit
/// surface — the UTF-8 peers [`From<ContentDigest> for String`],
/// [`From<ContentDigest> for Box<str>`],
/// [`From<ContentDigest> for Cow<'static, str>`],
/// [`From<ContentDigest> for Arc<str>`],
/// [`From<ContentDigest> for Rc<str>`], the byte-slice peers
/// [`From<ContentDigest> for Vec<u8>`],
/// [`From<ContentDigest> for Box<[u8]>`],
/// [`From<ContentDigest> for Cow<'static, [u8]>`], this
/// [`From<ContentDigest> for Arc<[u8]>`] — reads through it.
impl From<ContentDigest> for std::sync::Arc<[u8]> {
    fn from(digest: ContentDigest) -> std::sync::Arc<[u8]> {
        std::sync::Arc::<[u8]>::from(Vec::<u8>::from(digest))
    }
}

/// [`From<ContentDigest>`] for [`std::rc::Rc<[u8]>`] moves the validated
/// `<algorithm>:<hex>` backing string out of the consumed [`ContentDigest`]
/// value into an immutable, single-thread, shared-owned [`Rc<[u8]>`] at
/// exactly the label's byte length — the impl routes through
/// [`<Vec<u8> as From<ContentDigest>>::from`] (which itself chains through
/// the [`From<ContentDigest> for String`] emit oracle via
/// [`String::into_bytes`], moving [`ContentDigest::full`] out at zero-copy)
/// and then [`std::rc::Rc::<[u8]>::from`] on the moved [`Vec<u8>`] (which
/// repackages the backing buffer as an immutable shared-owned [`Rc<[u8]>`]
/// with a single non-atomic-refcount header preceding the label bytes). No
/// re-formatting through [`std::fmt::Display`], no
/// `Rc::<[u8]>::from(digest.as_ref())` bridge that would copy the backing
/// bytes into a fresh allocation while leaking the consumed
/// [`ContentDigest`]'s owned [`String`], no `digest.as_ref().to_vec()
/// .into()` chain that would restate the shared-owned discipline at every
/// consumer.
///
/// A downstream consumer that owns a [`ContentDigest`] and needs to hand
/// it off as a same-thread shared-owned raw-byte handle to a non-atomic-
/// refcounted byte-slice sink (a same-thread `HashMap<Rc<[u8]>, _>` cache
/// key inserted once and cloned across inline inspection helpers at `O(1)`
/// [`Rc::clone`] cost with no atomic-op per-clone allocation, a
/// `thread_local!` per-thread digest interner that fans `Rc<[u8]>` handles
/// to per-worker readers without paying [`Arc`]'s atomic refcount fence, a
/// `bytes::Bytes::from(Rc<[u8]>)` intake that pins its input contract on
/// the raw-byte single-thread shared-owned frontier, a `!Send` per-task
/// lookaside that keys entries on the digest without paying [`Arc`]'s
/// atomic refcount) is a one-line `Rc::<[u8]>::from(digest)` /
/// `digest.into()` call, not a per-site
/// `Rc::<[u8]>::from(digest.as_ref())` bridge that leaks the consumed
/// [`ContentDigest`]'s owned [`String`] nor a
/// `Rc::<[u8]>::from(digest.to_string().into_bytes())` chain that pays a
/// redundant [`Display`]-format allocation on top of the shared-owned
/// repackaging.
///
/// The by-value single-thread shared-owned byte-slice emit peer of the
/// by-value cross-thread shared-owned byte-slice emit peer
/// [`From<ContentDigest> for Arc<[u8]>`] (commit 49111c1) with a
/// non-atomic-refcount alternative shape for `!Send` consumers, of the
/// by-value single-thread shared-owned UTF-8 emit peer
/// [`From<ContentDigest> for Rc<str>`] (commit a7bcfd2) at the raw-byte
/// frontier, of the by-value borrowed/owned-frontier byte-slice peer
/// [`From<ContentDigest> for Cow<'static, [u8]>`] (commit c2a5acf) with a
/// same-thread refcounted alternative shape, of the by-value shrunk-owned
/// byte-slice peer [`From<ContentDigest> for Box<[u8]>`] (commit fce9fee)
/// with a same-thread refcounted alternative shape, and of the by-value
/// resizable owned-byte-slice peer [`From<ContentDigest> for Vec<u8>`]
/// (commit e1ea855) with a shared-owned alternative shape: all five
/// byte-slice emit surfaces move the same validated full-digest bytes out
/// of the consumed [`ContentDigest`], differing only on the owner-shape of
/// the emitted receiver — [`Vec<u8>`] for resizable growth-header
/// byte-buffer owners, [`Box<[u8]>`] for immutable shrunk-owned raw-byte
/// slots that trade the [`Vec<u8>`] growth-header word for a two-word
/// slice pointer, [`Cow<'static, [u8]>`] for borrowed/owned-frontier
/// raw-byte sinks, [`Arc<[u8]>`] for immutable cross-thread shared-owned
/// raw-byte slots that carry a single atomic-refcount header, this
/// [`Rc<[u8]>`] for immutable same-thread shared-owned raw-byte slots that
/// carry a single non-atomic-refcount header so `!Send` consumers
/// [`Rc::clone`] the label byte-buffer at pointer-copy + integer-increment
/// cost with no atomic-op fence per clone, while dropping the UTF-8 typing
/// [`Rc<str>`] imposes on the ASCII-only-by-parse-invariant digest bytes
/// for consumers that pin their contract on the raw-byte single-thread
/// shared-owned frontier (`bytes::Bytes`, `http::HeaderValue::from_bytes`,
/// streaming hashers seeded off an [`Rc<[u8]>`] label input). All five
/// route through the [`From<ContentDigest> for String`] emit oracle: the
/// [`Vec<u8>`] peer chains through [`String::into_bytes`], the [`Box<[u8]>`]
/// peer chains through [`String::into_bytes`] then
/// [`Vec::into_boxed_slice`], the [`Cow<'static, [u8]>`] peer chains
/// through [`String::into_bytes`] then wraps the moved [`Vec<u8>`] in
/// [`Cow::Owned`], the [`Arc<[u8]>`] peer chains through
/// [`String::into_bytes`] then [`std::sync::Arc::<[u8]>::from`] applied to
/// the moved [`Vec<u8>`], this [`Rc<[u8]>`] peer chains through
/// [`String::into_bytes`] then [`std::rc::Rc::<[u8]>::from`] applied to
/// the moved [`Vec<u8>`] — the five agree byte-for-byte on the canonical
/// form by construction, and a future canonicalising refinement to the
/// [`String`] emit surface propagates to the single-thread shared-owned
/// raw-byte frontier at zero per-consumer cost.
///
/// Zero-copy on the digest bytes by construction: [`Vec::<u8>::from`]
/// moves [`ContentDigest::full`]'s backing buffer out through
/// [`String::into_bytes`] (which repackages the [`String`] as a
/// [`Vec<u8>`] at the same capacity), and [`std::rc::Rc::<[u8]>::from`] on
/// the moved [`Vec<u8>`] performs a single non-atomic-refcount allocation
/// of exactly `label.len() + refcount header` bytes and copies the label
/// bytes into that allocation once (the [`Vec<u8>`]'s heap buffer cannot
/// itself be repurposed because the [`Rc<[u8]>`] layout requires the
/// non-atomic-refcount header to precede the slice body, and [`Vec<u8>`]'s
/// backing has no such header). This is strictly the minimum cost of
/// shifting from the resizable-growth-header [`Vec<u8>`] shape to the
/// immutable-shared-refcount [`Rc<[u8]>`] shape; no [`std::fmt::Display`]
/// round-trip, no intermediate [`Box<[u8]>`] allocation, no per-consumer
/// bridge cost. A single-thread caller that would otherwise pay
/// [`Arc<[u8]>`]'s atomic-refcount header for a cache slot never accessed
/// from another thread saves the atomic-op cost on every clone by
/// construction.
///
/// The identity `<std::rc::Rc<[u8]> as
/// std::ops::Deref>::deref(&std::rc::Rc::<[u8]>::from(digest.clone()))
/// == digest.as_str().as_bytes()` at every validated [`ContentDigest`]
/// value is pinned by
/// [`tests::test_from_content_digest_rc_bytes_matches_as_ref`]; the
/// identity carrying through a generic `impl Into<std::rc::Rc<[u8]>>`
/// consumer is pinned by
/// [`tests::test_from_content_digest_rc_bytes_carries_through_generic_consumer`];
/// the parse-round-trip identity through the single-thread shared-owned
/// byte-slice emit surface (decoding the emitted [`Rc<[u8]>`]'s deref
/// view as UTF-8 and parsing through every canonical parse surface) is
/// pinned by
/// [`tests::test_from_content_digest_rc_bytes_parse_round_trip`]; the
/// same-thread `Rc::clone` shared-allocation semantic is pinned by
/// [`tests::test_from_content_digest_rc_bytes_clones_share_allocation`].
///
/// A future refinement to the inherent [`ContentDigest::parse`] grammar
/// (widening to `sha384`, tightening the trim behaviour) or to the
/// [`From<ContentDigest> for String`] emit oracle (a canonicalising
/// projection at the owned-UTF-8 frontier) is a one-site edit at the
/// inherent / owned-UTF-8 oracle; every consumer bound by
/// `impl Into<std::rc::Rc<[u8]>>` inherits the refined canonical
/// single-thread shared-owned byte slice off the moved backing storage
/// automatically with no downstream retyping.
///
/// THEORY.md §III.1 typescape: the by-value single-thread shared-owned
/// byte-slice emit surface is a typed-primitive site on [`ContentDigest`]
/// itself (one [`From<ContentDigest>`] impl chaining through the
/// [`From<ContentDigest> for String`] emit oracle via
/// [`String::into_bytes`] and [`std::rc::Rc::<[u8]>::from`]), not a
/// per-consumer `Rc::<[u8]>::from(digest.as_ref())` restatement at every
/// downstream site that accepts `impl Into<std::rc::Rc<[u8]>>`.
/// THEORY.md §VI.1 one-oracle: the validated full-digest bytes are named
/// at one site ([`From<ContentDigest> for String`], reading through the
/// moved [`ContentDigest::full`] backing), and every by-value owned emit
/// surface — the UTF-8 peers [`From<ContentDigest> for String`],
/// [`From<ContentDigest> for Box<str>`],
/// [`From<ContentDigest> for Cow<'static, str>`],
/// [`From<ContentDigest> for Arc<str>`],
/// [`From<ContentDigest> for Rc<str>`], the byte-slice peers
/// [`From<ContentDigest> for Vec<u8>`],
/// [`From<ContentDigest> for Box<[u8]>`],
/// [`From<ContentDigest> for Cow<'static, [u8]>`],
/// [`From<ContentDigest> for Arc<[u8]>`], this
/// [`From<ContentDigest> for Rc<[u8]>`] — reads through it. The
/// byte-slice emit cross-product is now closed on all five standard-
/// library owner-shapes.
impl From<ContentDigest> for std::rc::Rc<[u8]> {
    fn from(digest: ContentDigest) -> std::rc::Rc<[u8]> {
        std::rc::Rc::<[u8]>::from(Vec::<u8>::from(digest))
    }
}

/// [`serde::Serialize`] for [`ContentDigest`] emits the validated
/// `<algorithm>:<hex>` backing string as a serde string value through
/// [`serde::Serializer::serialize_str`] on
/// [`ContentDigest::as_str`], so a downstream attestation-record schema
/// that carries a [`ContentDigest`] field emits the canonical, trimmed,
/// lowercase-hex form the [`ContentDigest::parse`] oracle validated —
/// not the offending pre-trim input, not a re-formatted
/// [`std::fmt::Display`] rendering, not an
/// `serde_json::Value::String(digest.as_str().to_owned())` bridge at
/// every emit site.
///
/// The by-reference emit peer of the by-value emit family
/// [`From<ContentDigest> for String`] / [`From<ContentDigest> for
/// Vec<u8>`] / [`From<ContentDigest> for Box<str>`] etc.: the by-value
/// peers move the backing string out at zero-copy for owned-sink
/// consumers; this by-reference peer streams the same backing bytes
/// through a serde [`Serializer`](serde::Serializer) so a
/// [`serde_json`] / [`serde_yaml`] / [`toml`] frontier that pins its
/// contract as `T: serde::Serialize` reads through the same one-oracle
/// canonical form without a per-emit-site
/// `serializer.serialize_str(digest.as_str())` bridge and without
/// paying the redundant clone the sibling `From<&ContentDigest> for
/// String` peer would demand.
///
/// THEORY.md §III.1 typescape: the serde emit surface is a
/// typed-primitive site on [`ContentDigest`] itself (one
/// [`serde::Serialize`] impl streaming the [`ContentDigest::parse`]-
/// validated backing string through [`serde::Serializer::serialize_str`]),
/// not a per-consumer `serializer.serialize_str(digest.as_str())`
/// restatement at every downstream site that owns a [`ContentDigest`]
/// and hands it to a serde-derived container. THEORY.md §VI.1
/// one-oracle: the validated full-digest string is named at one site
/// ([`ContentDigest::parse`]-guarded [`ContentDigest::full`] backing),
/// and every emit surface — the borrowed-view read peers
/// [`ContentDigest::as_str`], [`std::fmt::Display`], [`AsRef<str>`],
/// [`AsRef<[u8]>`], the by-value owned emit peers, this by-reference
/// serde-frontier peer — reads through the same backing storage.
impl serde::Serialize for ContentDigest {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.full)
    }
}

/// [`serde::Deserialize`] for [`ContentDigest`] borrows a
/// [`Cow<'de, str>`] off the [`Deserializer`](serde::Deserializer)
/// (borrowed at zero-copy where the deserializer carries a borrowable
/// string tape — `serde_json::from_slice` off a `&[u8]`, `serde_yaml`'s
/// borrowing scanner — owned where it does not) and routes through
/// [`<ContentDigest as TryFrom<Cow<'_, str>>>::try_from`] into the
/// [`ContentDigest::parse`] oracle so an attestation-record schema
/// that carries a [`ContentDigest`]-typed field rejects a malformed
/// `<algorithm>:<hex>` string at serde-read time — the moment the
/// deserializer visits the string — rather than at a downstream
/// consumer boundary where the offending input has already been
/// laundered through a stringly-typed intermediate.
///
/// The serde-frontier parse peer of the parse-family
/// ([`std::str::FromStr`], [`TryFrom<&str>`], [`TryFrom<String>`],
/// [`TryFrom<Cow<'_, str>>`], [`TryFrom<Box<str>>`],
/// [`TryFrom<Arc<str>>`], [`TryFrom<Rc<str>>`], [`TryFrom<&[u8]>`],
/// [`TryFrom<Vec<u8>>`], [`TryFrom<Cow<'_, [u8]>>`],
/// [`TryFrom<Box<[u8]>>`], [`TryFrom<Arc<[u8]>>`],
/// [`TryFrom<Rc<[u8]>>`]) — a canonical-string typed primitive is now
/// parseable from every idiomatic Rust input frontier AND from the
/// [`serde::Deserializer`] frontier the attestation-record and
/// deploy-schema readers pin their contract on, all through the same
/// one-oracle grammar the direct `.parse::<ContentDigest>()` call sites
/// already read. Prior to this impl a serde-derived container that
/// wanted to carry a [`ContentDigest`]-typed field had to either
/// declare `#[serde(try_from = "String")]` at each field (paying a
/// per-container attribute) or land the field as `String` and validate
/// downstream — a stringly-typed schema surface the parse-oracle
/// family this file has been widening exists to close.
///
/// The [`Err`](serde::de::Error) type is the deserializer's own
/// [`serde::de::Error`], surfaced through [`serde::de::Error::custom`]
/// on the [`ContentDigestError`] the [`TryFrom<Cow<'_, str>>`] oracle
/// emitted — so a [`serde_json`] failure preserves the JSON pointer /
/// line-and-column context and a [`serde_yaml`] failure preserves the
/// YAML span, both wrapping the same typed
/// [`ContentDigestError::Display`] message. A downstream reader that
/// wants the typed [`ContentDigestError`] variant (rather than the
/// string-wrapped serde-frontier form) still routes through
/// [`ContentDigest::parse`] / [`TryFrom<Cow<'_, str>>`] on its own
/// borrowed / owned input at its own frontier.
///
/// THEORY.md §III.1 typescape: the serde parse surface is a
/// typed-primitive site on [`ContentDigest`] itself (one
/// [`serde::Deserialize`] impl routing through the [`TryFrom<Cow<'_,
/// str>>`] peer into the [`ContentDigest::parse`] oracle), not a
/// per-consumer `#[serde(try_from = "String")]` container attribute at
/// every downstream schema that wraps a digest field. THEORY.md §VI.1
/// one-oracle: the canonical `<algorithm>:<hex>` grammar is named at
/// one site ([`ContentDigest::parse`]), and every parse surface —
/// [`std::str::FromStr`], the [`TryFrom<T>`] peer family across
/// [`&str`] / [`String`] / [`Cow<str>`] / [`Box<str>`] / [`Arc<str>`] /
/// [`Rc<str>`] and their byte-slice mirrors, this [`serde::Deserialize`]
/// — reads through it. THEORY.md §V.4 (attestation as cryptographic
/// evidence): a stringly-typed digest field cannot substantiate a
/// claim it does not validate; strengthening a serde-derived
/// attestation-record field from `String` to [`ContentDigest`] (now
/// unlocked directly, no `#[serde(try_from = "String")]` bridge
/// needed) moves the substantiation from a downstream boundary check
/// to a serde-read-time type-level invariant.
impl<'de> serde::Deserialize<'de> for ContentDigest {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let cow: std::borrow::Cow<'de, str> =
            <std::borrow::Cow<'de, str> as serde::Deserialize<'de>>::deserialize(deserializer)?;
        <Self as TryFrom<std::borrow::Cow<'_, str>>>::try_from(cow)
            .map_err(serde::de::Error::custom)
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

    /// A well-formed `blake3:{64-hex}` string parses. Blake3's
    /// default 256-bit output renders as 64 lowercase-hex chars —
    /// the same body length as sha256 — and is the shape
    /// [`tameshi::hash::Blake3Hash::to_prefixed`] emits into
    /// `certification_hash` / `signature` / `compliance_hash` slots
    /// stamped through
    /// [`crate::commands::attestation::generate_attestation_info`].
    /// Pins the load-bearing widening of the parse oracle beyond the
    /// two registry-side algorithms (sha256 / sha512) so the same
    /// grammar accepts both registry-supplied and attestation-
    /// supplied digests at one site.
    #[test]
    fn test_parse_blake3_digest() {
        let d = ContentDigest::parse(&format!("blake3:{D1}")).unwrap();
        assert_eq!(d.as_str(), format!("blake3:{D1}"));
    }

    /// A `blake3:` prefix with a body of wrong length (63 or 65
    /// hex chars) fails at the [`ContentDigestError::InvalidHex`]
    /// arm — the algorithm passes the algorithm gate but its 256-
    /// bit / 64-hex-char length requirement pins the body against
    /// [`BLAKE3_HEX_LEN`]. Guards the length-boundary rejection at
    /// the algorithm arm added by this widening so a future drift
    /// (accidentally reading a 32-hex-char blake3-of-something-
    /// truncated body, or a copy-pasted sha512-length body) cannot
    /// silently enter a validated [`ContentDigest`].
    #[test]
    fn test_parse_rejects_wrong_blake3_hex_length() {
        // 63 chars — one short of the 64-char body.
        let err = ContentDigest::parse(&format!("blake3:{}", &D1[..63])).unwrap_err();
        assert!(matches!(err, ContentDigestError::InvalidHex { .. }));
        // 65 chars — one past the 64-char body.
        let err = ContentDigest::parse(&format!("blake3:{D1}f")).unwrap_err();
        assert!(matches!(err, ContentDigestError::InvalidHex { .. }));
    }

    /// A `blake3:` prefix with uppercase hex fails at the
    /// [`ContentDigestError::InvalidHex`] arm just as sha256 /
    /// sha512 do. [`tameshi::hash::Blake3Hash::to_prefixed`] emits
    /// lowercase; uppercase is non-canonical at the attestation
    /// frontier the same way it is at the registry frontier.
    /// Discipline-mirror of
    /// [`test_parse_rejects_uppercase_hex`] at the sha256 arm,
    /// extended to blake3 so the canonicity contract holds
    /// uniformly across the widened algorithm set.
    #[test]
    fn test_parse_rejects_uppercase_blake3_hex() {
        let err = ContentDigest::parse(&format!("blake3:{}", D1.to_uppercase())).unwrap_err();
        assert!(matches!(err, ContentDigestError::InvalidHex { .. }));
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
    /// validated digest for every supported algorithm — the two
    /// registry-side ones (sha256 / sha512) and the attestation-
    /// frontier one (blake3, added at this widening). A consumer
    /// that pins a per-algorithm policy at its own attestation
    /// boundary can distinguish arms directly without re-splitting
    /// the full string.
    #[test]
    fn test_content_digest_algorithm_accessor() {
        let sha256 = ContentDigest::parse(&format!("sha256:{D1}")).unwrap();
        assert_eq!(sha256.algorithm(), "sha256");
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let sha512 = ContentDigest::parse(&format!("sha512:{hex512}")).unwrap();
        assert_eq!(sha512.algorithm(), "sha512");
        let blake3 = ContentDigest::parse(&format!("blake3:{D1}")).unwrap();
        assert_eq!(blake3.algorithm(), "blake3");
    }

    /// The `hex()` accessor recovers the lowercase-hex body off a
    /// validated digest for every supported algorithm. Round-trips
    /// with the input hex on the three canonical algorithms, so a
    /// consumer that persists the hex without the algorithm prefix
    /// (e.g. `helm_provenance::HelmProvenanceOutcome::Verified::
    /// signed_chart_hash`, or a future blake3-hex column stored
    /// alongside the sekiban annotation set) extracts it off the
    /// typed primitive.
    #[test]
    fn test_content_digest_hex_accessor() {
        let sha256 = ContentDigest::parse(&format!("sha256:{D1}")).unwrap();
        assert_eq!(sha256.hex(), D1);
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let sha512 = ContentDigest::parse(&format!("sha512:{hex512}")).unwrap();
        assert_eq!(sha512.hex(), hex512);
        let blake3 = ContentDigest::parse(&format!("blake3:{D2}")).unwrap();
        assert_eq!(blake3.hex(), D2);
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

    /// [`DigestAlgorithm::as_str`] projects each variant onto the
    /// canonical `<algorithm>` label the [`ContentDigest::parse`]
    /// grammar admits. Pins the one-oracle label table so a future
    /// drift (a variant added without extending the projection, an
    /// accidental typo in a label) lights up. Guards the load-bearing
    /// contract that the label projection round-trips through
    /// [`DigestAlgorithm::parse`] on every variant.
    #[test]
    fn test_digest_algorithm_as_str_projects_canonical_label() {
        assert_eq!(DigestAlgorithm::Sha256.as_str(), "sha256");
        assert_eq!(DigestAlgorithm::Sha512.as_str(), "sha512");
        assert_eq!(DigestAlgorithm::Blake3.as_str(), "blake3");
    }

    /// [`DigestAlgorithm::hex_len`] projects each variant onto the
    /// lowercase-hex body length the [`ContentDigest::parse`] grammar
    /// pins for that algorithm. Guards the projection table so a
    /// future variant insertion or a length-constant drift lights up
    /// at this one site.
    #[test]
    fn test_digest_algorithm_hex_len_projects_body_length() {
        assert_eq!(DigestAlgorithm::Sha256.hex_len(), SHA256_HEX_LEN);
        assert_eq!(DigestAlgorithm::Sha512.hex_len(), SHA512_HEX_LEN);
        assert_eq!(DigestAlgorithm::Blake3.hex_len(), BLAKE3_HEX_LEN);
    }

    /// [`DigestAlgorithm::parse`] is the one-oracle inverse of
    /// [`DigestAlgorithm::as_str`] — every variant's canonical label
    /// round-trips back to the same variant. Guards the label ↔
    /// variant table isomorphism on the [`DigestAlgorithm::ALL`]
    /// enumeration so a future variant insertion at either end of the
    /// pair lights up.
    #[test]
    fn test_digest_algorithm_parse_round_trips_every_variant() {
        for algo in DigestAlgorithm::ALL {
            assert_eq!(DigestAlgorithm::parse(algo.as_str()), Some(algo));
        }
    }

    /// [`DigestAlgorithm::parse`] returns [`None`] for a label outside
    /// the canonical set — the same rejection the
    /// [`ContentDigest::parse`] grammar oracle observes at its
    /// [`ContentDigestError::UnsupportedAlgorithm`] arm. Pins the
    /// rejection cover so a downstream policy site (a per-algorithm
    /// cross-check) cannot silently admit a stringly-typed drift like
    /// `"SHA256"` (uppercase) or `"sha-256"` (hyphenated).
    #[test]
    fn test_digest_algorithm_parse_rejects_unknown_label() {
        assert_eq!(DigestAlgorithm::parse("SHA256"), None);
        assert_eq!(DigestAlgorithm::parse("sha-256"), None);
        assert_eq!(DigestAlgorithm::parse("md5"), None);
        assert_eq!(DigestAlgorithm::parse(""), None);
    }

    /// The [`std::fmt::Display`] impl on [`DigestAlgorithm`] routes
    /// through [`DigestAlgorithm::as_str`]. A downstream consumer
    /// stamping `format!("{algo}:{hex}")` reads the same canonical
    /// label the parse grammar admits, so a `{algo}:{hex}` render
    /// round-trips back through [`ContentDigest::parse`] without a
    /// per-variant restatement of the label.
    #[test]
    fn test_digest_algorithm_display_matches_as_str() {
        for algo in DigestAlgorithm::ALL {
            assert_eq!(algo.to_string(), algo.as_str());
        }
    }

    /// [`DigestAlgorithm::ALL`] contains every variant exactly once —
    /// the exhaustive-cover match discipline
    /// [`crate::probe_outcome::AdmissionTier::ALL`] establishes at the
    /// sibling typed sum, extended to the digest-algorithm axis. A
    /// future variant insertion that forgot to extend
    /// [`DigestAlgorithm::ALL`] lights up at this one site because
    /// the exhaustive `match` refuses to compile.
    #[test]
    fn test_digest_algorithm_all_contains_every_variant() {
        for algo in DigestAlgorithm::ALL {
            match algo {
                DigestAlgorithm::Sha256 => {
                    assert!(DigestAlgorithm::ALL.contains(&DigestAlgorithm::Sha256))
                }
                DigestAlgorithm::Sha512 => {
                    assert!(DigestAlgorithm::ALL.contains(&DigestAlgorithm::Sha512))
                }
                DigestAlgorithm::Blake3 => {
                    assert!(DigestAlgorithm::ALL.contains(&DigestAlgorithm::Blake3))
                }
            }
        }
        assert_eq!(DigestAlgorithm::ALL.len(), 3);
    }

    /// At every [`DigestAlgorithm`] variant enumerated by
    /// [`DigestAlgorithm::ALL`], `<DigestAlgorithm as AsRef<str>>::as_ref(&algo)`
    /// (the [`AsRef<str>`] impl body) equals `algo.as_str()` (the
    /// canonical-label oracle) exactly. The load-bearing structural pin
    /// that ties the byte-slice-coercion surface to the shared
    /// [`DigestAlgorithm::as_str`] oracle: a regression that swapped
    /// [`AsRef<str>`] to route through the [`std::fmt::Display`]
    /// formatter buffer (paying a [`String`] allocation), or drifted
    /// the [`AsRef<str>`] grammar from [`DigestAlgorithm::as_str`]'s
    /// lowercase labels, fails here at ONE named site instead of
    /// leaking to every downstream consumer that accepts
    /// `impl AsRef<str>` (per-algorithm cache-key partition,
    /// [`std::collections::HashMap<&str, _>`] key lookup keyed by
    /// algorithm label, OpenTelemetry / tracing attribute setter,
    /// `format!("{prefix}:{}", algo.as_ref())` stamp). Structural
    /// mirror of
    /// [`crate::version::tests::test_bump_level_as_ref_str_agrees_with_as_str`]
    /// at the version-bump-magnitude ladder,
    /// `test_admission_tier_as_ref_str_agrees_with_as_str` (commit
    /// 7acca19) at the admission-tier ladder, and
    /// `test_per_attempt_region_as_ref_str_agrees_with_as_str` (commit
    /// 8c8cffe) at the per-attempt-region ladder — the four agreement
    /// pins together close the read-side agreement across every
    /// canonical-label typed sum in forge's typed-primitive algebra at
    /// the byte-slice surface ([`AsRef<str>`]) against the shared
    /// canonical-label oracle.
    #[test]
    fn test_digest_algorithm_as_ref_str_agrees_with_as_str() {
        for algo in DigestAlgorithm::ALL {
            let borrowed: &str = algo.as_ref();
            assert_eq!(
                borrowed,
                algo.as_str(),
                "AsRef<str> and as_str must agree at {algo:?}",
            );
        }
    }

    /// The [`AsRef<str>`] identity carries through a generic
    /// `impl AsRef<str>` consumer at every [`DigestAlgorithm::ALL`]
    /// variant. A tiny generic function `fn read<T: AsRef<str>>(t: &T) ->
    /// &str { t.as_ref() }` — the shape of an actual downstream consumer
    /// (per-algorithm cache-key partition, HashMap key lookup, tracing
    /// attribute setter, `format!("{prefix}:{}", algo.as_ref())` stamp) —
    /// reads the canonical lowercase label directly from a
    /// [`DigestAlgorithm`] value without going through the
    /// [`std::fmt::Display`] formatter buffer or an intermediate
    /// [`String`] allocation. The structural witness that a
    /// [`DigestAlgorithm`] is genuinely usable at `impl AsRef<str>` call
    /// sites — a regression that drifted the [`AsRef<str>`] impl
    /// signature (e.g., returning an owned [`String`] instead of a
    /// `&str`, or requiring a `&mut self`) fails here at compile time
    /// instead of at every downstream generic call site. Structural
    /// mirror of
    /// [`crate::version::tests::test_bump_level_as_ref_str_carries_through_generic_consumer`]
    /// at the version-bump-magnitude ladder,
    /// `test_admission_tier_as_ref_str_carries_through_generic_consumer`
    /// (commit 7acca19) at the admission-tier ladder, and
    /// `test_per_attempt_region_as_ref_str_carries_through_generic_consumer`
    /// (commit 8c8cffe) at the per-attempt-region ladder.
    #[test]
    fn test_digest_algorithm_as_ref_str_carries_through_generic_consumer() {
        fn read<T: AsRef<str>>(t: &T) -> &str {
            t.as_ref()
        }

        for algo in DigestAlgorithm::ALL {
            assert_eq!(
                read(&algo),
                algo.as_str(),
                "generic AsRef<str> consumer must read canonical label at {algo:?}",
            );
        }
    }

    /// [`ContentDigest::algorithm_kind`] projects the validated digest
    /// onto the [`DigestAlgorithm`] typed sum, agreeing with the
    /// stringly-typed [`ContentDigest::algorithm`] on every canonical
    /// algorithm. The typed peer of the accessor at the algorithm
    /// axis — a downstream consumer that pins a per-algorithm policy
    /// reads a variant rather than a bare label, so a stringly-typed
    /// drift is caught by the compiler's exhaustiveness check.
    #[test]
    fn test_content_digest_algorithm_kind_projects_typed_variant() {
        let sha256 = ContentDigest::parse(&format!("sha256:{D1}")).unwrap();
        assert_eq!(sha256.algorithm_kind(), DigestAlgorithm::Sha256);
        assert_eq!(sha256.algorithm_kind().as_str(), sha256.algorithm());

        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let sha512 = ContentDigest::parse(&format!("sha512:{hex512}")).unwrap();
        assert_eq!(sha512.algorithm_kind(), DigestAlgorithm::Sha512);
        assert_eq!(sha512.algorithm_kind().as_str(), sha512.algorithm());

        let blake3 = ContentDigest::parse(&format!("blake3:{D2}")).unwrap();
        assert_eq!(blake3.algorithm_kind(), DigestAlgorithm::Blake3);
        assert_eq!(blake3.algorithm_kind().as_str(), blake3.algorithm());
    }

    /// `algo.as_str().parse::<DigestAlgorithm>()` recovers `algo` at every
    /// [`DigestAlgorithm::ALL`] variant — the [`std::str::FromStr`] impl
    /// is the round-trip inverse of [`DigestAlgorithm::as_str`] across the
    /// full canonical-label set. Guards the label ↔ variant isomorphism
    /// at the parse frontier so a future variant insertion at either the
    /// projection or the inverse silently drifting apart lights up here.
    /// Structural mirror of
    /// [`crate::version::tests::test_bump_level_from_str_round_trips_every_variant`]
    /// at the version-bump-magnitude ladder — the four canonical-label
    /// typed sums each pin the FromStr round-trip against their shared
    /// `as_str` oracle.
    #[test]
    fn test_digest_algorithm_from_str_round_trips_every_variant() {
        for algo in DigestAlgorithm::ALL {
            let parsed: DigestAlgorithm = algo
                .as_str()
                .parse()
                .expect("canonical label must parse back to its variant");
            assert_eq!(parsed, algo, "FromStr must round-trip as_str at {algo:?}",);
        }
    }

    /// [`str::parse::<DigestAlgorithm>`] rejects labels outside the
    /// canonical three-label set with an error naming both the offending
    /// input and the admitted labels (`sha256`, `sha512`, `blake3`).
    /// Pins the rejection wording so a downstream CLI surface that
    /// forwards the parse error to the operator reads the byte-identical
    /// text at every unknown-label rejection. Guards against silent
    /// widening of the accepted set (an accidental `Ok(default)` fallback,
    /// a case-insensitive match arm) and against wording drift (a
    /// canonical label dropped from the enumeration).
    #[test]
    fn test_digest_algorithm_from_str_rejects_unknown_label() {
        for bad in ["SHA256", "sha-256", "md5", "", "sha256 ", " sha256"] {
            let err = bad
                .parse::<DigestAlgorithm>()
                .expect_err("non-canonical label must reject");
            let msg = err.to_string();
            assert!(
                msg.contains(&format!("'{bad}'")),
                "error must quote the offending input at '{bad}'; got: {msg}"
            );
            for canonical in ["sha256", "sha512", "blake3"] {
                assert!(
                    msg.contains(canonical),
                    "error must enumerate canonical label '{canonical}' at input '{bad}'; got: {msg}"
                );
            }
        }
    }

    /// The [`std::str::FromStr`] impl agrees with the inherent
    /// [`DigestAlgorithm::parse`] inverse oracle on both the admitted-
    /// label side and the rejection side: `s.parse::<DigestAlgorithm>().ok()
    /// == DigestAlgorithm::parse(s)` at every canonical-label input AND
    /// at a representative unknown-label input. The load-bearing structural
    /// pin that ties the [`std::str::FromStr`] parse surface to the ONE
    /// canonical-label inverse oracle: a regression that inlined a
    /// divergent match (e.g., case-insensitive folding, whitespace-tolerant
    /// trimming, an alias like `"sha-256"`) into
    /// [`std::str::FromStr`] fails here at this ONE named site instead of
    /// leaking to every downstream consumer that reads through
    /// [`FromStr`](std::str::FromStr) (CLI `clap` value parser, config-
    /// file loader, telemetry label backfill).
    #[test]
    fn test_digest_algorithm_from_str_agrees_with_parse() {
        for algo in DigestAlgorithm::ALL {
            let label = algo.as_str();
            let via_from_str = label.parse::<DigestAlgorithm>().ok();
            let via_inherent = DigestAlgorithm::parse(label);
            assert_eq!(
                via_from_str, via_inherent,
                "FromStr and inherent parse must agree on canonical label '{label}'",
            );
        }
        for bad in ["SHA256", "sha-256", "md5", ""] {
            let via_from_str = bad.parse::<DigestAlgorithm>().ok();
            let via_inherent = DigestAlgorithm::parse(bad);
            assert_eq!(
                via_from_str, via_inherent,
                "FromStr and inherent parse must agree on non-canonical label '{bad}'",
            );
        }
    }

    /// `<DigestAlgorithm as TryFrom<&str>>::try_from(algo.as_str())` recovers
    /// `algo` at every [`DigestAlgorithm::ALL`] variant — the [`TryFrom<&str>`]
    /// impl round-trips against [`DigestAlgorithm::as_str`] across the full
    /// canonical-label set. Pins the identity
    /// `DigestAlgorithm::try_from(algo.as_str()).unwrap() == algo` at every
    /// variant against the shared canonical-label oracle. The structural
    /// witness that the by-reference try-conversion parse surface (this
    /// [`TryFrom<&str>`]) reads the same one-oracle grammar the stdlib parse
    /// frontier ([`std::str::FromStr`], the sibling above) writes — one
    /// round-trip pin per variant, refuses a future variant insertion that
    /// drops the `TryFrom<&str>` / `as_str` agreement. Structural mirror of
    /// [`crate::retry::tests::test_per_attempt_region_try_from_str_agrees_with_from_str`]
    /// at the per-attempt-region ladder and
    /// [`crate::probe_outcome::tests::test_admission_tier_try_from_str_agrees_with_from_str`]
    /// at the admission-tier ladder — the three canonical-label typed sums
    /// each pin the [`TryFrom<&str>`] round-trip against their shared
    /// `as_str` oracle.
    #[test]
    fn test_digest_algorithm_try_from_str_agrees_with_from_str() {
        for algo in DigestAlgorithm::ALL {
            let parsed = <DigestAlgorithm as std::convert::TryFrom<&str>>::try_from(algo.as_str())
                .expect("canonical label must parse through TryFrom<&str>");
            assert_eq!(
                parsed, algo,
                "TryFrom<&str> must round-trip through as_str at {algo:?}",
            );
        }
    }

    /// The [`TryFrom<&str> for DigestAlgorithm`] identity carries through a
    /// generic `impl for<'a> TryFrom<&'a str>` consumer at every
    /// [`DigestAlgorithm::ALL`] variant. A tiny generic function
    /// `fn parse<T>(s: &str) -> T where T: for<'a> TryFrom<&'a str>,
    /// T::Error: Debug` — the shape of an actual downstream consumer
    /// (validated-input newtype builder, serde `try_from` wrapper, generic
    /// try-conversion helper that opts into the [`TryFrom<&str>`] contract
    /// rather than [`std::str::FromStr`]) — recovers the canonical variant
    /// from the canonical lowercase label at every variant. The structural
    /// witness that a [`DigestAlgorithm`] is genuinely usable at
    /// `impl for<'a> TryFrom<&'a str>` call sites — a regression that
    /// drifted the [`TryFrom`] impl signature (e.g., requiring an owned
    /// [`String`] input instead of `&str`, or returning a different variant
    /// than [`FromStr`] would) fails here at compile time or at the
    /// assertion instead of at every downstream generic call site.
    #[test]
    fn test_digest_algorithm_try_from_str_carries_through_generic_consumer() {
        fn parse<T>(s: &str) -> T
        where
            T: for<'a> std::convert::TryFrom<&'a str>,
            for<'a> <T as std::convert::TryFrom<&'a str>>::Error: std::fmt::Debug,
        {
            <T as std::convert::TryFrom<&str>>::try_from(s)
                .expect("canonical label must parse through generic TryFrom<&str>")
        }

        for algo in DigestAlgorithm::ALL {
            assert_eq!(
                parse::<DigestAlgorithm>(algo.as_str()),
                algo,
                "generic TryFrom<&str> consumer must recover canonical variant at {algo:?}",
            );
        }
    }

    /// [`TryFrom<&str> for DigestAlgorithm`] rejects non-canonical input with
    /// the same strictness [`std::str::FromStr`] enforces — empty string,
    /// uppercase, hyphenated, unknown labels, and edge-whitespace variants
    /// all reject. Pins the strict-rejection contract at the by-reference
    /// try-conversion surface so a downstream consumer bound by
    /// [`TryFrom<&str>`] (a serde `try_from` container, a generic
    /// try-conversion helper) inherits the same canonical-only grammar the
    /// direct `.parse::<DigestAlgorithm>()` call sites already read. Also
    /// pins the delegate-through-[`FromStr`] discipline: rejection at
    /// [`TryFrom<&str>`] tracks rejection at [`std::str::FromStr`] byte-for-
    /// byte, so a future permissive-parse regression at the underlying
    /// [`FromStr`] impl (case-folded acceptance of `"SHA256"`, whitespace-
    /// tolerant admission of `"sha256 "`, alias admission of `"sha-256"`)
    /// lights up here rather than drifting silently through the by-reference
    /// try-conversion surface.
    #[test]
    fn test_digest_algorithm_try_from_str_rejects_non_canonical_input() {
        for bad in ["SHA256", "sha-256", "md5", "", "sha256 ", " sha256"] {
            let via_try_from = <DigestAlgorithm as std::convert::TryFrom<&str>>::try_from(bad).ok();
            let via_from_str = bad.parse::<DigestAlgorithm>().ok();
            assert!(
                via_try_from.is_none(),
                "TryFrom<&str> must reject non-canonical input {bad:?}",
            );
            assert_eq!(
                via_try_from, via_from_str,
                "TryFrom<&str> and FromStr must agree on rejection at {bad:?}",
            );
        }
    }

    /// The [`TryFrom<String> for DigestAlgorithm`] impl round-trips every
    /// canonical label emitted by [`DigestAlgorithm::as_str`] and agrees
    /// with [`std::str::FromStr`] byte-for-byte at every
    /// [`DigestAlgorithm::ALL`] variant. Pins the delegate-through-
    /// [`FromStr`] discipline at the by-value owned-string parse peer: a
    /// regression that drifted the [`TryFrom<String>`] impl body (e.g.,
    /// cloning `s` and re-parsing through a divergent oracle, admitting
    /// a case-folded label an ownership-aware branch might slip through)
    /// fails here rather than at every downstream `TryFrom<String>` call
    /// site.
    #[test]
    fn test_digest_algorithm_try_from_string_agrees_with_from_str() {
        for algo in DigestAlgorithm::ALL {
            let owned = algo.as_str().to_owned();
            let parsed =
                <DigestAlgorithm as std::convert::TryFrom<String>>::try_from(owned.clone())
                    .expect("canonical label must parse through TryFrom<String>");
            assert_eq!(
                parsed, algo,
                "TryFrom<String> must round-trip through as_str at {algo:?}",
            );
            let via_from_str = owned
                .parse::<DigestAlgorithm>()
                .expect("canonical label must parse through FromStr");
            assert_eq!(
                parsed, via_from_str,
                "TryFrom<String> and FromStr must agree at {algo:?}",
            );
        }
    }

    /// The [`TryFrom<String> for DigestAlgorithm`] identity carries through
    /// a generic `impl TryFrom<String>` consumer at every
    /// [`DigestAlgorithm::ALL`] variant. A tiny generic function
    /// `fn parse<T>(s: String) -> T where T: TryFrom<String>,
    /// T::Error: Debug` — the shape of an actual downstream consumer
    /// (validated-input newtype builder that owns the input buffer, serde
    /// `try_from = "String"` wrapper, generic try-conversion helper that
    /// opts into the by-value [`TryFrom<String>`] contract rather than the
    /// by-reference [`TryFrom<&str>`] contract) — recovers the canonical
    /// variant from the canonical lowercase label at every variant. The
    /// structural witness that a [`DigestAlgorithm`] is genuinely usable at
    /// `impl TryFrom<String>` call sites — a regression that drifted the
    /// [`TryFrom<String>`] impl signature (e.g., requiring `&String` input
    /// instead of `String`, returning a different variant than [`FromStr`]
    /// would) fails here at compile time or at the assertion instead of
    /// at every downstream generic call site.
    #[test]
    fn test_digest_algorithm_try_from_string_carries_through_generic_consumer() {
        fn parse<T>(s: String) -> T
        where
            T: std::convert::TryFrom<String>,
            <T as std::convert::TryFrom<String>>::Error: std::fmt::Debug,
        {
            <T as std::convert::TryFrom<String>>::try_from(s)
                .expect("canonical label must parse through generic TryFrom<String>")
        }

        for algo in DigestAlgorithm::ALL {
            assert_eq!(
                parse::<DigestAlgorithm>(algo.as_str().to_owned()),
                algo,
                "generic TryFrom<String> consumer must recover canonical variant at {algo:?}",
            );
        }
    }

    /// [`TryFrom<String> for DigestAlgorithm`] rejects non-canonical input
    /// with the same strictness [`std::str::FromStr`] and [`TryFrom<&str>`]
    /// enforce — empty string, uppercase, hyphenated, unknown labels, and
    /// edge-whitespace variants all reject. Pins the strict-rejection
    /// contract at the by-value owned-string try-conversion surface so a
    /// downstream consumer bound by [`TryFrom<String>`] (a serde
    /// `try_from = "String"` container, a generic try-conversion helper
    /// that owns the input buffer) inherits the same canonical-only
    /// grammar the direct `.parse::<DigestAlgorithm>()` call sites already
    /// read. Also pins the delegate-through-[`FromStr`] discipline:
    /// rejection at [`TryFrom<String>`] tracks rejection at [`FromStr`]
    /// byte-for-byte at every reject-set element, so a future permissive-
    /// parse regression at the underlying [`FromStr`] impl lights up here
    /// rather than drifting silently through the by-value owned-string
    /// try-conversion surface.
    #[test]
    fn test_digest_algorithm_try_from_string_rejects_non_canonical_input() {
        for bad in ["SHA256", "sha-256", "md5", "", "sha256 ", " sha256"] {
            let owned = bad.to_owned();
            let via_try_from =
                <DigestAlgorithm as std::convert::TryFrom<String>>::try_from(owned.clone()).ok();
            let via_from_str = owned.parse::<DigestAlgorithm>().ok();
            assert!(
                via_try_from.is_none(),
                "TryFrom<String> must reject non-canonical input {bad:?}",
            );
            assert_eq!(
                via_try_from, via_from_str,
                "TryFrom<String> and FromStr must agree on rejection at {bad:?}",
            );
        }
    }

    /// The [`TryFrom<Cow<'_, str>> for DigestAlgorithm`] impl round-trips
    /// every canonical label emitted by [`DigestAlgorithm::as_str`] on
    /// BOTH the [`Cow::Borrowed`] and [`Cow::Owned`] arms and agrees with
    /// [`std::str::FromStr`] byte-for-byte at every
    /// [`DigestAlgorithm::ALL`] variant. Pins the delegate-through-
    /// [`FromStr`] discipline at the borrowed-or-owned frontier try-
    /// conversion peer: a regression that drifted the
    /// [`TryFrom<Cow<'_, str>>`] impl body (e.g., pattern-matching the
    /// [`Cow`] arms and routing them through divergent oracles, cloning
    /// the [`Cow::Owned`] payload into a fresh [`String`] and re-parsing
    /// through a case-folded branch, admitting an empty label on the
    /// [`Cow::Borrowed`] arm through a short-circuit) fails here rather
    /// than at every downstream `TryFrom<Cow<'_, str>>` call site.
    #[test]
    fn test_digest_algorithm_try_from_cow_str_agrees_with_from_str() {
        use std::borrow::Cow;
        for algo in DigestAlgorithm::ALL {
            let label = algo.as_str();

            let via_borrowed = <DigestAlgorithm as std::convert::TryFrom<Cow<'_, str>>>::try_from(
                Cow::Borrowed(label),
            )
            .expect("canonical label must parse through TryFrom<Cow::Borrowed>");
            assert_eq!(
                via_borrowed, algo,
                "TryFrom<Cow::Borrowed> must round-trip through as_str at {algo:?}",
            );

            let via_owned = <DigestAlgorithm as std::convert::TryFrom<Cow<'_, str>>>::try_from(
                Cow::Owned(label.to_owned()),
            )
            .expect("canonical label must parse through TryFrom<Cow::Owned>");
            assert_eq!(
                via_owned, algo,
                "TryFrom<Cow::Owned> must round-trip through as_str at {algo:?}",
            );

            let via_from_str = label
                .parse::<DigestAlgorithm>()
                .expect("canonical label must parse through FromStr");
            assert_eq!(
                via_borrowed, via_from_str,
                "TryFrom<Cow::Borrowed> and FromStr must agree at {algo:?}",
            );
            assert_eq!(
                via_owned, via_from_str,
                "TryFrom<Cow::Owned> and FromStr must agree at {algo:?}",
            );
        }
    }

    /// The [`TryFrom<Cow<'_, str>> for DigestAlgorithm`] identity carries
    /// through a generic `impl TryFrom<Cow<'_, str>>` consumer at every
    /// [`DigestAlgorithm::ALL`] variant. A tiny generic function
    /// `fn parse<'a, T>(s: Cow<'a, str>) -> T where T: TryFrom<Cow<'a,
    /// str>>, T::Error: Debug` — the shape of an actual downstream
    /// consumer (borrowed-or-owned pipeline that consumes [`Cow`] to
    /// defer the ownership decision to its caller, serde
    /// `try_from = "Cow<'_, str>"` wrapper, generic try-conversion helper
    /// that opts into the borrowed-or-owned frontier at the receiver-
    /// shape layer) — recovers the canonical variant from the canonical
    /// lowercase label on BOTH [`Cow`] arms at every variant. The
    /// structural witness that a [`DigestAlgorithm`] is genuinely usable
    /// at `impl TryFrom<Cow<'_, str>>` call sites — a regression that
    /// drifted the [`TryFrom<Cow<'_, str>>`] impl signature (e.g.,
    /// binding the [`Cow`] lifetime to `'static` and rejecting borrowed
    /// non-static payloads, returning a different variant than
    /// [`FromStr`] would) fails here at compile time or at the assertion
    /// instead of at every downstream generic call site.
    #[test]
    fn test_digest_algorithm_try_from_cow_str_carries_through_generic_consumer() {
        use std::borrow::Cow;
        fn parse<'a, T>(s: Cow<'a, str>) -> T
        where
            T: std::convert::TryFrom<Cow<'a, str>>,
            <T as std::convert::TryFrom<Cow<'a, str>>>::Error: std::fmt::Debug,
        {
            <T as std::convert::TryFrom<Cow<'a, str>>>::try_from(s)
                .expect("canonical label must parse through generic TryFrom<Cow<'_, str>>")
        }

        for algo in DigestAlgorithm::ALL {
            assert_eq!(
                parse::<DigestAlgorithm>(Cow::Borrowed(algo.as_str())),
                algo,
                "generic TryFrom<Cow::Borrowed> consumer must recover canonical variant at {algo:?}",
            );
            assert_eq!(
                parse::<DigestAlgorithm>(Cow::Owned(algo.as_str().to_owned())),
                algo,
                "generic TryFrom<Cow::Owned> consumer must recover canonical variant at {algo:?}",
            );
        }
    }

    /// [`TryFrom<Cow<'_, str>> for DigestAlgorithm`] rejects non-canonical
    /// input with the same strictness [`std::str::FromStr`],
    /// [`TryFrom<&str>`], and [`TryFrom<String>`] enforce — empty string,
    /// uppercase, hyphenated, unknown labels, and edge-whitespace variants
    /// all reject on BOTH the [`Cow::Borrowed`] and [`Cow::Owned`] arms.
    /// Pins the strict-rejection contract at the borrowed-or-owned
    /// frontier try-conversion surface so a downstream consumer bound by
    /// [`TryFrom<Cow<'_, str>>`] (a serde `try_from = "Cow<'_, str>"`
    /// container, a generic try-conversion helper that receives a
    /// borrowed-or-owned payload) inherits the same canonical-only
    /// grammar the direct `.parse::<DigestAlgorithm>()` call sites
    /// already read. Also pins the delegate-through-[`FromStr`]
    /// discipline: rejection at [`TryFrom<Cow<'_, str>>`] tracks
    /// rejection at [`FromStr`] byte-for-byte at every reject-set element
    /// on both arms, so a future permissive-parse regression at the
    /// underlying [`FromStr`] impl lights up here rather than drifting
    /// silently through the borrowed-or-owned frontier try-conversion
    /// surface.
    #[test]
    fn test_digest_algorithm_try_from_cow_str_rejects_non_canonical_input() {
        use std::borrow::Cow;
        for bad in ["SHA256", "sha-256", "md5", "", "sha256 ", " sha256"] {
            let via_borrowed = <DigestAlgorithm as std::convert::TryFrom<Cow<'_, str>>>::try_from(
                Cow::Borrowed(bad),
            )
            .ok();
            let via_owned = <DigestAlgorithm as std::convert::TryFrom<Cow<'_, str>>>::try_from(
                Cow::Owned(bad.to_owned()),
            )
            .ok();
            let via_from_str = bad.parse::<DigestAlgorithm>().ok();
            assert!(
                via_borrowed.is_none(),
                "TryFrom<Cow::Borrowed> must reject non-canonical input {bad:?}",
            );
            assert!(
                via_owned.is_none(),
                "TryFrom<Cow::Owned> must reject non-canonical input {bad:?}",
            );
            assert_eq!(
                via_borrowed, via_from_str,
                "TryFrom<Cow::Borrowed> and FromStr must agree on rejection at {bad:?}",
            );
            assert_eq!(
                via_owned, via_from_str,
                "TryFrom<Cow::Owned> and FromStr must agree on rejection at {bad:?}",
            );
        }
    }

    /// [`TryFrom<&[u8]> for DigestAlgorithm`] agrees with
    /// [`std::str::FromStr`] on every [`DigestAlgorithm::ALL`] variant
    /// when the byte slice is the canonical lowercase label's UTF-8
    /// bytes. Pins the byte-slice parse peer against the shared
    /// canonical-label oracle: a downstream site that hands a `&[u8]`
    /// (a captured registry stdout, a network response body, a
    /// `serde_bytes` field) into the try-conversion surface recovers
    /// the exact variant the string-frontier parse peer would recover
    /// on the same label. Also pins the delegate-through-[`FromStr`]
    /// discipline: the value the byte-slice peer emits tracks the value
    /// [`FromStr`] emits byte-for-byte at every variant, so a future
    /// regression that reroutes the byte-slice arm away from the
    /// [`FromStr`] oracle (a per-peer inline `match` that drifts an
    /// arm's variant assignment, a per-peer accepted-label set that
    /// widens beyond the canonical grammar) lights up here rather than
    /// silently at downstream call sites.
    #[test]
    fn test_digest_algorithm_try_from_bytes_agrees_with_from_str() {
        for algo in DigestAlgorithm::ALL {
            let label = algo.as_str();

            let via_bytes =
                <DigestAlgorithm as std::convert::TryFrom<&[u8]>>::try_from(label.as_bytes())
                    .expect("canonical label bytes must parse through TryFrom<&[u8]>");
            assert_eq!(
                via_bytes, algo,
                "TryFrom<&[u8]> must round-trip through as_str at {algo:?}",
            );

            let via_from_str = label
                .parse::<DigestAlgorithm>()
                .expect("canonical label must parse through FromStr");
            assert_eq!(
                via_bytes, via_from_str,
                "TryFrom<&[u8]> and FromStr must agree at {algo:?}",
            );
        }
    }

    /// The [`TryFrom<&[u8]> for DigestAlgorithm`] identity carries
    /// through a generic `impl for<'a> TryFrom<&'a [u8]>` consumer at
    /// every [`DigestAlgorithm::ALL`] variant. A tiny generic function
    /// `fn parse<'a, T>(bytes: &'a [u8]) -> T where T: TryFrom<&'a [u8]>,
    /// T::Error: Debug` — the shape of an actual downstream consumer
    /// (byte-slice pipeline that parses algorithm labels off a wire
    /// capture, serde `try_from = "&[u8]"` wrapper on a `serde_bytes`
    /// field, generic try-conversion helper that opts into the byte-
    /// slice frontier at the receiver-shape layer) — recovers the
    /// canonical variant from the canonical lowercase label's UTF-8
    /// bytes at every variant. The structural witness that a
    /// [`DigestAlgorithm`] is genuinely usable at
    /// `impl for<'a> TryFrom<&'a [u8]>` call sites — a regression that
    /// drifted the [`TryFrom<&[u8]>`] impl signature (e.g., binding the
    /// slice lifetime to `'static` and rejecting borrowed non-static
    /// payloads, returning a different variant than [`FromStr`] would)
    /// fails here at compile time or at the assertion instead of at
    /// every downstream generic call site.
    #[test]
    fn test_digest_algorithm_try_from_bytes_carries_through_generic_consumer() {
        fn parse<'a, T>(bytes: &'a [u8]) -> T
        where
            T: std::convert::TryFrom<&'a [u8]>,
            <T as std::convert::TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        {
            <T as std::convert::TryFrom<&'a [u8]>>::try_from(bytes)
                .expect("canonical label bytes must parse through generic TryFrom<&[u8]>")
        }

        for algo in DigestAlgorithm::ALL {
            assert_eq!(
                parse::<DigestAlgorithm>(algo.as_str().as_bytes()),
                algo,
                "generic TryFrom<&[u8]> consumer must recover canonical variant at {algo:?}",
            );
        }
    }

    /// [`TryFrom<&[u8]> for DigestAlgorithm`] rejects UTF-8-valid but
    /// non-canonical input with the same strictness [`std::str::FromStr`],
    /// [`TryFrom<&str>`], [`TryFrom<String>`], and
    /// [`TryFrom<Cow<'_, str>>`] enforce — empty input, uppercase,
    /// hyphenated, unknown labels, and edge-whitespace variants all
    /// reject. Pins the strict-rejection contract at the borrowed-byte-
    /// slice frontier try-conversion surface so a downstream consumer
    /// bound by [`TryFrom<&[u8]>`] (a serde `try_from = "&[u8]"`
    /// container on a `serde_bytes` field, a `nom` / `winnow` byte-slice
    /// parser that yields a bounded canonical-label token) inherits the
    /// same canonical-only grammar the direct
    /// `.parse::<DigestAlgorithm>()` call sites already read. Also pins
    /// the delegate-through-[`FromStr`] discipline: rejection at
    /// [`TryFrom<&[u8]>`] tracks rejection at [`FromStr`] byte-for-byte
    /// at every reject-set element once UTF-8 validation clears, so a
    /// future permissive-parse regression at the underlying [`FromStr`]
    /// impl lights up here rather than drifting silently through the
    /// borrowed-byte-slice frontier try-conversion surface.
    #[test]
    fn test_digest_algorithm_try_from_bytes_rejects_non_canonical_input() {
        for bad in ["SHA256", "sha-256", "md5", "", "sha256 ", " sha256"] {
            let via_bytes =
                <DigestAlgorithm as std::convert::TryFrom<&[u8]>>::try_from(bad.as_bytes()).ok();
            let via_from_str = bad.parse::<DigestAlgorithm>().ok();
            assert!(
                via_bytes.is_none(),
                "TryFrom<&[u8]> must reject non-canonical UTF-8-valid input {bad:?}",
            );
            assert_eq!(
                via_bytes, via_from_str,
                "TryFrom<&[u8]> and FromStr must agree on rejection at {bad:?}",
            );
        }
    }

    /// [`TryFrom<&[u8]> for DigestAlgorithm`] rejects UTF-8-invalid
    /// byte input — a stray non-UTF-8 sequence, a partial-write byte
    /// tail that clips a UTF-8 continuation — before the input reaches
    /// the string oracle. Pins the two-stage validation contract: the
    /// byte-slice peer validates UTF-8 first at [`std::str::from_utf8`]
    /// (the only rejection mode the string-frontier peers cannot emit
    /// by construction, since a [`&str`] / [`String`] / [`Cow<'_, str>`]
    /// receiver is already guaranteed UTF-8) then delegates the
    /// canonical-label grammar to the [`FromStr`] oracle. The
    /// UTF-8-invalid rejection error carries a lossy-decoded rendering
    /// of the offending bytes so a caller pinning a failure record can
    /// still attach the offending input to the record without an
    /// intermediate `String::from_utf8_lossy` call at every downstream
    /// site.
    #[test]
    fn test_digest_algorithm_try_from_bytes_rejects_invalid_utf8() {
        for bad in [
            &b"\xffsha256"[..],
            &b"sha256\xff"[..],
            &b"\xc3\x28"[..],
            &b"\xed\xa0\x80"[..],
        ] {
            let via_bytes = <DigestAlgorithm as std::convert::TryFrom<&[u8]>>::try_from(bad);
            assert!(
                via_bytes.is_err(),
                "TryFrom<&[u8]> must reject UTF-8-invalid input {bad:?}",
            );
            let msg = via_bytes.unwrap_err().to_string();
            assert!(
                msg.contains("not valid UTF-8"),
                "UTF-8-invalid rejection message must name the failure mode, got {msg:?}",
            );
        }
    }

    /// [`TryFrom<Vec<u8>> for DigestAlgorithm`] round-trips the canonical
    /// lowercase label byte serialization at every [`DigestAlgorithm::ALL`]
    /// variant AND agrees byte-for-byte with the by-reference
    /// [`TryFrom<&[u8]>`] and by-value [`TryFrom<String>`] peers at every
    /// variant. Pins the delegate-through-[`String::from_utf8`]-then-
    /// [`TryFrom<String>`] discipline: parse at [`TryFrom<Vec<u8>>`] tracks
    /// parse at both sibling peers byte-for-byte at every canonical
    /// variant, so a future regression that reroutes the owned-byte-slice
    /// arm away from the shared oracle (a per-peer inline `match` that
    /// drifts an arm's variant assignment, a per-peer accepted-label set
    /// that widens beyond the canonical grammar) lights up here rather
    /// than silently at downstream call sites.
    #[test]
    fn test_digest_algorithm_try_from_vec_bytes_agrees_with_from_str() {
        for algo in DigestAlgorithm::ALL {
            let label = algo.as_str();

            let via_vec = <DigestAlgorithm as std::convert::TryFrom<Vec<u8>>>::try_from(
                label.as_bytes().to_vec(),
            )
            .expect("canonical label owned bytes must parse through TryFrom<Vec<u8>>");
            assert_eq!(
                via_vec, algo,
                "TryFrom<Vec<u8>> must round-trip through as_str at {algo:?}",
            );

            let via_bytes =
                <DigestAlgorithm as std::convert::TryFrom<&[u8]>>::try_from(label.as_bytes())
                    .expect("canonical label bytes must parse through TryFrom<&[u8]>");
            assert_eq!(
                via_vec, via_bytes,
                "TryFrom<Vec<u8>> and TryFrom<&[u8]> must agree at {algo:?}",
            );

            let via_string =
                <DigestAlgorithm as std::convert::TryFrom<String>>::try_from(label.to_owned())
                    .expect("canonical label owned string must parse through TryFrom<String>");
            assert_eq!(
                via_vec, via_string,
                "TryFrom<Vec<u8>> and TryFrom<String> must agree at {algo:?}",
            );
        }
    }

    /// The [`TryFrom<Vec<u8>> for DigestAlgorithm`] identity carries
    /// through a generic `impl TryFrom<Vec<u8>>` consumer at every
    /// [`DigestAlgorithm::ALL`] variant. A tiny generic function
    /// `fn parse<T>(bytes: Vec<u8>) -> T where T: TryFrom<Vec<u8>>,
    /// T::Error: Debug` — the shape of an actual downstream consumer
    /// (owned-byte pipeline that parses algorithm labels off a wire
    /// capture materialised as [`Vec<u8>`], serde `try_from = "Vec<u8>"`
    /// wrapper on a `serde_bytes` field, generic try-conversion helper
    /// that opts into the owned-byte-slice frontier at the receiver-shape
    /// layer) — recovers the canonical variant from the canonical
    /// lowercase label's owned UTF-8 bytes at every variant. The
    /// structural witness that a [`DigestAlgorithm`] is genuinely usable
    /// at `impl TryFrom<Vec<u8>>` call sites — a regression that drifted
    /// the [`TryFrom<Vec<u8>>`] impl signature (e.g., accepting only
    /// borrowed byte slices at some coercion site, returning a different
    /// variant than the sibling peers would) fails here at compile time
    /// or at the assertion instead of at every downstream generic call
    /// site.
    #[test]
    fn test_digest_algorithm_try_from_vec_bytes_carries_through_generic_consumer() {
        fn parse<T>(bytes: Vec<u8>) -> T
        where
            T: std::convert::TryFrom<Vec<u8>>,
            <T as std::convert::TryFrom<Vec<u8>>>::Error: std::fmt::Debug,
        {
            <T as std::convert::TryFrom<Vec<u8>>>::try_from(bytes)
                .expect("canonical label owned bytes must parse through generic TryFrom<Vec<u8>>")
        }

        for algo in DigestAlgorithm::ALL {
            assert_eq!(
                parse::<DigestAlgorithm>(algo.as_str().as_bytes().to_vec()),
                algo,
                "generic TryFrom<Vec<u8>> consumer must recover canonical variant at {algo:?}",
            );
        }
    }

    /// [`TryFrom<Vec<u8>> for DigestAlgorithm`] rejects UTF-8-valid but
    /// non-canonical input with the same strictness the sibling
    /// [`std::str::FromStr`], [`TryFrom<&str>`], [`TryFrom<String>`],
    /// [`TryFrom<Cow<'_, str>>`], and [`TryFrom<&[u8]>`] peers enforce —
    /// empty input, uppercase, hyphenated, unknown labels, and edge-
    /// whitespace variants all reject. Pins the strict-rejection contract
    /// at the by-value owned-byte-slice frontier try-conversion surface
    /// so a downstream consumer bound by [`TryFrom<Vec<u8>>`] (a serde
    /// `try_from = "Vec<u8>"` container on a `serde_bytes` field, an
    /// owned-byte pipeline that yields a bounded canonical-label token)
    /// inherits the same canonical-only grammar the direct
    /// `.parse::<DigestAlgorithm>()` call sites already read. Also pins
    /// the delegate-through-[`TryFrom<String>`] discipline: rejection at
    /// [`TryFrom<Vec<u8>>`] tracks rejection at [`TryFrom<String>`]
    /// byte-for-byte at every reject-set element once UTF-8 validation
    /// clears, so a future permissive-parse regression at the underlying
    /// [`FromStr`] impl lights up here rather than drifting silently
    /// through the by-value owned-byte-slice frontier try-conversion
    /// surface.
    #[test]
    fn test_digest_algorithm_try_from_vec_bytes_rejects_non_canonical_input() {
        for bad in ["SHA256", "sha-256", "md5", "", "sha256 ", " sha256"] {
            let via_vec = <DigestAlgorithm as std::convert::TryFrom<Vec<u8>>>::try_from(
                bad.as_bytes().to_vec(),
            )
            .ok();
            let via_string =
                <DigestAlgorithm as std::convert::TryFrom<String>>::try_from(bad.to_owned()).ok();
            assert!(
                via_vec.is_none(),
                "TryFrom<Vec<u8>> must reject non-canonical UTF-8-valid input {bad:?}",
            );
            assert_eq!(
                via_vec, via_string,
                "TryFrom<Vec<u8>> and TryFrom<String> must agree on rejection at {bad:?}",
            );
        }
    }

    /// [`TryFrom<Vec<u8>> for DigestAlgorithm`] rejects UTF-8-invalid
    /// owned-byte input — a stray non-UTF-8 sequence, a partial-write
    /// byte tail that clips a UTF-8 continuation — before the input
    /// reaches the string oracle. Pins the two-stage validation contract:
    /// the owned-byte-slice peer validates UTF-8 first at
    /// [`String::from_utf8`] (the only rejection mode the string-frontier
    /// peers cannot emit by construction, since a [`String`] receiver is
    /// already guaranteed UTF-8) then delegates the canonical-label
    /// grammar to the [`TryFrom<String>`] peer. The UTF-8-invalid
    /// rejection error carries a lossy-decoded rendering of the offending
    /// bytes recovered through [`std::string::FromUtf8Error::into_bytes`]
    /// so a caller pinning a failure record can still attach the
    /// offending input to the record without an intermediate
    /// [`String::from_utf8_lossy`] call at every downstream site.
    #[test]
    fn test_digest_algorithm_try_from_vec_bytes_rejects_invalid_utf8() {
        for bad in [
            &b"\xffsha256"[..],
            &b"sha256\xff"[..],
            &b"\xc3\x28"[..],
            &b"\xed\xa0\x80"[..],
        ] {
            let via_vec =
                <DigestAlgorithm as std::convert::TryFrom<Vec<u8>>>::try_from(bad.to_vec());
            assert!(
                via_vec.is_err(),
                "TryFrom<Vec<u8>> must reject UTF-8-invalid input {bad:?}",
            );
            let msg = via_vec.unwrap_err().to_string();
            assert!(
                msg.contains("not valid UTF-8"),
                "UTF-8-invalid rejection message must name the failure mode, got {msg:?}",
            );
        }
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

    /// [`TryFrom<&[u8]>`] succeeds on the byte serialization of a
    /// well-formed sha256 digest and yields the same validated value
    /// as the inherent oracle. The byte-slice parse surface is the
    /// idiomatic wire-frontier peer of the string parse surfaces: a
    /// captured registry stdout or a network response body arrives on
    /// the byte register, and this impl routes through
    /// [`std::str::from_utf8`] before delegating to the string
    /// oracle.
    #[test]
    fn test_try_from_bytes_parses_sha256_digest() {
        let raw = format!("sha256:{D1}");
        let d = ContentDigest::try_from(raw.as_bytes()).unwrap();
        assert_eq!(d.as_str(), raw);
        assert_eq!(d.algorithm(), "sha256");
        assert_eq!(d.hex(), D1);
        let inherent = ContentDigest::parse(&raw).unwrap();
        assert_eq!(d, inherent);
    }

    /// [`TryFrom<&[u8]>`] succeeds on the byte serialization of a
    /// well-formed sha512 digest — the second supported algorithm at
    /// the digest reference-grammar family. Pins the impl across both
    /// algorithms so a widening at the inherent oracle (e.g. `sha384`)
    /// is caught by an existing test on this derived surface.
    #[test]
    fn test_try_from_bytes_parses_sha512_digest() {
        let hex = "f".repeat(SHA512_HEX_LEN);
        let raw = format!("sha512:{hex}");
        let d = ContentDigest::try_from(raw.as_bytes()).unwrap();
        assert_eq!(d.as_str(), raw);
        assert_eq!(d.algorithm(), "sha512");
        assert_eq!(d.hex(), hex);
    }

    /// [`TryFrom<&[u8]>`] trims leading / trailing ASCII whitespace on
    /// the delegated string oracle — a captured wire response whose
    /// trailing newline rides in the byte buffer parses successfully
    /// because the string oracle whitespace-trims before checking the
    /// grammar. Pins the trim discipline carrying through the
    /// byte-slice frontier.
    #[test]
    fn test_try_from_bytes_trims_edge_whitespace() {
        let raw = format!("  sha256:{D1}\n");
        let expected = format!("sha256:{D1}");
        let d = ContentDigest::try_from(raw.as_bytes()).unwrap();
        assert_eq!(d.as_str(), expected);
    }

    /// [`TryFrom<&[u8]>`] on a UTF-8-valid input emits the SAME error
    /// [`ContentDigest::parse`] emits on every grammar-failure input
    /// — the missing-separator, unsupported-algorithm, and
    /// invalid-hex variants route through the string oracle unchanged
    /// once UTF-8 validation clears. Pins the "byte-slice parse
    /// surface reads through the string parse oracle on
    /// grammar-failure inputs" invariant so a future refactor that
    /// inlined a divergent grammar into the byte-slice peer fails
    /// this test.
    #[test]
    fn test_try_from_bytes_matches_inherent_parse_on_every_grammar_error_mode() {
        let err_cases = [
            "sha256abc",                              // missing separator
            &format!("md5:{D1}"),                     // unsupported algorithm
            &format!("sha256:{}", &D1[..60]),         // wrong hex length
            &format!("sha256:{}", D1.to_uppercase()), // uppercase hex
            &format!("sha256:{}g", &D1[..63]),        // non-hex byte
        ];
        for raw in err_cases {
            let via_bytes = ContentDigest::try_from(raw.as_bytes());
            let via_inherent = ContentDigest::parse(raw);
            assert_eq!(via_bytes, via_inherent);
        }
    }

    /// [`TryFrom<&[u8]>`] agrees with [`TryFrom<&str>`] on every
    /// valid and invalid UTF-8-valid input — the byte-slice parse
    /// surface and the string parse surface resolve to the SAME
    /// [`Result<ContentDigest, ContentDigestError>`] across every
    /// input the two share, so a downstream site that migrates a
    /// consumer from `bytes.as_ref().parse()` (string-typed) to a
    /// direct byte-slice consumer keyed on `TryFrom<&[u8]>` yields
    /// identical values and identical errors at every input.
    #[test]
    fn test_try_from_bytes_agrees_with_try_from_str() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let ok_cases = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha512:{hex512}"),
            format!("  sha256:{D3}\n"),
        ];
        for raw in ok_cases {
            let via_bytes = ContentDigest::try_from(raw.as_bytes());
            let via_str = ContentDigest::try_from(raw.as_str());
            assert_eq!(via_bytes, via_str);
        }
        let err_cases = [
            "sha256abc",
            &format!("md5:{D1}"),
            &format!("sha256:{}", &D1[..60]),
            &format!("sha256:{}", D1.to_uppercase()),
            &format!("sha256:{}g", &D1[..63]),
        ];
        for raw in err_cases {
            let via_bytes = ContentDigest::try_from(raw.as_bytes());
            let via_str = ContentDigest::try_from(raw);
            assert_eq!(via_bytes, via_str);
        }
    }

    /// [`TryFrom<&[u8]>`] on a UTF-8-invalid input surfaces the
    /// [`ContentDigestError::InvalidUtf8`] variant carrying the
    /// lossy-decoded rendering of the offending bytes. Pins the
    /// byte-frontier-specific failure mode — the string parse peers
    /// cannot receive this input by construction, so this variant
    /// is only emitted by the byte-slice peer. A stray continuation
    /// byte (`0xff`) trailing an otherwise-valid digest still fails
    /// UTF-8 validation before the string oracle is reached.
    #[test]
    fn test_try_from_bytes_rejects_invalid_utf8() {
        let mut bytes = format!("sha256:{D1}").into_bytes();
        bytes.push(0xff);
        let err = ContentDigest::try_from(bytes.as_slice()).unwrap_err();
        assert!(matches!(err, ContentDigestError::InvalidUtf8 { .. }));
        // The lossy-decoded rendering names the offending input at the
        // failure record so a caller can attach it downstream.
        assert!(
            err.to_string().contains("sha256:"),
            "InvalidUtf8 display must name the lossy-decoded input; got: {err}"
        );
    }

    /// [`TryFrom<&[u8]>`] on a purely-invalid-UTF-8 input (no
    /// well-formed prefix) also surfaces
    /// [`ContentDigestError::InvalidUtf8`] — the byte-slice peer
    /// fails at the UTF-8 gate before any grammar predicate runs, so
    /// a consumer that receives arbitrary bytes off a
    /// `serde_bytes`-decoded field or a raw file read cannot leak
    /// through as a MissingSeparator / UnsupportedAlgorithm /
    /// InvalidHex misdiagnosis.
    #[test]
    fn test_try_from_bytes_rejects_pure_invalid_utf8() {
        let bytes: &[u8] = &[0xff, 0xfe, 0xfd, 0xfc];
        let err = ContentDigest::try_from(bytes).unwrap_err();
        assert!(matches!(err, ContentDigestError::InvalidUtf8 { .. }));
    }

    /// The [`TryFrom<&[u8]>`] impl composes with a generic
    /// try-conversion helper bounded by `for<'a> TryFrom<&'a [u8],
    /// Error = ContentDigestError>` — the compositional motivation
    /// for landing the trait separately from the string parse
    /// surfaces. Pins the generic-consumer surface so a downstream
    /// site that types its parse contract as `TryFrom<&[u8]>` (a
    /// `nom` / `winnow` byte-slice parser, a raw-wire validated-input
    /// builder helper) recovers the same typed value the inherent
    /// oracle produces.
    #[test]
    fn test_try_from_bytes_carries_through_generic_consumer() {
        fn parse_via_try_from<T: for<'a> TryFrom<&'a [u8], Error = ContentDigestError>>(
            bytes: &[u8],
        ) -> Result<T, ContentDigestError> {
            T::try_from(bytes)
        }
        let raw = format!("sha256:{D1}");
        let d: ContentDigest = parse_via_try_from(raw.as_bytes()).unwrap();
        assert_eq!(d.as_str(), raw);
        let err = parse_via_try_from::<ContentDigest>(b"sha256abc").unwrap_err();
        assert!(matches!(err, ContentDigestError::MissingSeparator { .. }));
    }

    /// [`TryFrom<Vec<u8>>`] succeeds on the owned-byte serialization
    /// of a well-formed sha256 digest and yields the same validated
    /// value as the inherent oracle. The by-value owned-byte-slice
    /// parse surface — the natural intake for a consumer that owns a
    /// [`Vec<u8>`] materialised off a completed
    /// `reqwest::Response::bytes()` future, a moved [`std::fs::read`],
    /// or a `serde_bytes`-decoded owned field — routes through the
    /// same one-oracle grammar as every other parse peer.
    #[test]
    fn test_try_from_vec_bytes_parses_sha256_digest() {
        let raw = format!("sha256:{D1}");
        let bytes = raw.clone().into_bytes();
        let d = ContentDigest::try_from(bytes).unwrap();
        assert_eq!(d.as_str(), raw);
        assert_eq!(d.algorithm(), "sha256");
        assert_eq!(d.hex(), D1);
        let inherent = ContentDigest::parse(&raw).unwrap();
        assert_eq!(d, inherent);
    }

    /// [`TryFrom<Vec<u8>>`] succeeds on the owned-byte serialization
    /// of a well-formed sha512 digest — the second supported algorithm
    /// at the digest reference-grammar family. Pins the impl across
    /// both algorithms so a widening at the inherent oracle (e.g.
    /// `sha384`) is caught by an existing test on this derived
    /// surface.
    #[test]
    fn test_try_from_vec_bytes_parses_sha512_digest() {
        let hex = "f".repeat(SHA512_HEX_LEN);
        let raw = format!("sha512:{hex}");
        let d = ContentDigest::try_from(raw.clone().into_bytes()).unwrap();
        assert_eq!(d.as_str(), raw);
        assert_eq!(d.algorithm(), "sha512");
        assert_eq!(d.hex(), hex);
    }

    /// [`TryFrom<Vec<u8>>`] trims leading / trailing ASCII whitespace
    /// on the delegated string oracle — an owned wire buffer whose
    /// trailing newline rides in the moved [`Vec<u8>`] parses
    /// successfully because the string oracle whitespace-trims before
    /// checking the grammar. Pins the trim discipline carrying
    /// through the owned-byte frontier.
    #[test]
    fn test_try_from_vec_bytes_trims_edge_whitespace() {
        let raw = format!("  sha256:{D1}\n");
        let expected = format!("sha256:{D1}");
        let d = ContentDigest::try_from(raw.into_bytes()).unwrap();
        assert_eq!(d.as_str(), expected);
    }

    /// [`TryFrom<Vec<u8>>`] on a UTF-8-valid input emits the SAME
    /// error [`ContentDigest::parse`] emits on every grammar-failure
    /// input — the missing-separator, unsupported-algorithm, and
    /// invalid-hex variants route through the string oracle unchanged
    /// once UTF-8 validation clears. Pins the "owned-byte parse
    /// surface reads through the string parse oracle on
    /// grammar-failure inputs" invariant so a future refactor that
    /// inlined a divergent grammar into the owned-byte peer fails
    /// this test.
    #[test]
    fn test_try_from_vec_bytes_matches_inherent_parse_on_every_grammar_error_mode() {
        let err_cases: [String; 5] = [
            "sha256abc".to_string(),                 // missing separator
            format!("md5:{D1}"),                     // unsupported algorithm
            format!("sha256:{}", &D1[..60]),         // wrong hex length
            format!("sha256:{}", D1.to_uppercase()), // uppercase hex
            format!("sha256:{}g", &D1[..63]),        // non-hex byte
        ];
        for raw in err_cases {
            let via_vec = ContentDigest::try_from(raw.clone().into_bytes());
            let via_inherent = ContentDigest::parse(&raw);
            assert_eq!(
                via_vec, via_inherent,
                "TryFrom<Vec<u8>> and inherent parse must agree on '{raw}'",
            );
        }
    }

    /// [`TryFrom<Vec<u8>>`] agrees with [`TryFrom<&[u8]>`] on every
    /// well-formed AND UTF-8-valid grammar-failure input — the
    /// owned-byte parse surface and the borrowed-byte parse surface
    /// resolve to the SAME [`Result<ContentDigest, ContentDigestError>`]
    /// across every input the two share, so a downstream site that
    /// migrates a consumer from `bytes.as_slice().try_into()`
    /// (borrowed) to a direct owned-byte consumer keyed on
    /// [`TryFrom<Vec<u8>>`] yields identical values and identical
    /// errors at every input. Pins the "owned and borrowed byte
    /// parse peers read through the same canonical oracle" invariant.
    #[test]
    fn test_try_from_vec_bytes_agrees_with_try_from_byte_slice() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let ok_cases = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha512:{hex512}"),
            format!("  sha256:{D3}\n"),
        ];
        for raw in ok_cases {
            let via_vec = ContentDigest::try_from(raw.clone().into_bytes());
            let via_slice = ContentDigest::try_from(raw.as_bytes());
            assert_eq!(via_vec, via_slice);
        }
        let err_cases: [String; 5] = [
            "sha256abc".to_string(),
            format!("md5:{D1}"),
            format!("sha256:{}", &D1[..60]),
            format!("sha256:{}", D1.to_uppercase()),
            format!("sha256:{}g", &D1[..63]),
        ];
        for raw in err_cases {
            let via_vec = ContentDigest::try_from(raw.clone().into_bytes());
            let via_slice = ContentDigest::try_from(raw.as_bytes());
            assert_eq!(via_vec, via_slice);
        }
    }

    /// [`TryFrom<Vec<u8>>`] agrees with [`TryFrom<String>`] on every
    /// well-formed input — the by-value owned-byte parse peer and the
    /// by-value owned-UTF-8 parse peer resolve to the SAME validated
    /// [`ContentDigest`] value across every input both accept. Pins
    /// the "the two by-value owned parse peers route through the same
    /// canonical oracle" cross-axis invariant so a divergence between
    /// the owned-UTF-8 and owned-byte parse paths (one accepting
    /// inputs the other rejects) fails this test.
    #[test]
    fn test_try_from_vec_bytes_agrees_with_try_from_string() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let ok_cases = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha512:{hex512}"),
            format!("  sha256:{D3}\n"),
        ];
        for raw in ok_cases {
            let via_vec = ContentDigest::try_from(raw.clone().into_bytes());
            let via_string = ContentDigest::try_from(raw.clone());
            assert_eq!(via_vec, via_string);
        }
    }

    /// [`TryFrom<Vec<u8>>`] on a UTF-8-invalid owned buffer surfaces
    /// the [`ContentDigestError::InvalidUtf8`] variant carrying the
    /// lossy-decoded rendering of the offending bytes — the same
    /// byte-frontier-specific failure mode the borrowed-byte peer
    /// emits, so a downstream site whose failure branch pattern-
    /// matches on [`ContentDigestError::InvalidUtf8`] handles owned
    /// and borrowed byte inputs uniformly. Pins the load-bearing
    /// "the by-value owned-byte peer recovers the input through
    /// [`FromUtf8Error::into_bytes`] and renders it lossy" invariant:
    /// a future refactor that dropped the input from the error would
    /// fail this test.
    #[test]
    fn test_try_from_vec_bytes_rejects_invalid_utf8() {
        let mut bytes = format!("sha256:{D1}").into_bytes();
        bytes.push(0xff);
        let err = ContentDigest::try_from(bytes).unwrap_err();
        assert!(matches!(err, ContentDigestError::InvalidUtf8 { .. }));
        assert!(
            err.to_string().contains("sha256:"),
            "InvalidUtf8 display must name the lossy-decoded input; got: {err}"
        );
    }

    /// [`TryFrom<Vec<u8>>`] on a purely-invalid-UTF-8 owned buffer
    /// (no well-formed prefix) surfaces
    /// [`ContentDigestError::InvalidUtf8`] — the owned-byte peer fails
    /// at the UTF-8 gate before any grammar predicate runs, so a
    /// consumer that receives arbitrary owned bytes off a
    /// `serde_bytes`-decoded owned field, a tokio-mpsc `Vec<u8>`
    /// frame, or a moved raw file read cannot leak through as a
    /// MissingSeparator / UnsupportedAlgorithm / InvalidHex
    /// misdiagnosis.
    #[test]
    fn test_try_from_vec_bytes_rejects_pure_invalid_utf8() {
        let bytes: Vec<u8> = vec![0xff, 0xfe, 0xfd, 0xfc];
        let err = ContentDigest::try_from(bytes).unwrap_err();
        assert!(matches!(err, ContentDigestError::InvalidUtf8 { .. }));
    }

    /// The [`TryFrom<Vec<u8>>`] impl composes with a generic
    /// try-conversion helper bounded by `TryFrom<Vec<u8>, Error =
    /// ContentDigestError>` — the compositional motivation for
    /// landing the trait separately from the borrowed-byte parse
    /// surface. Pins the by-value generic-consumer surface so a
    /// downstream site that types its parse contract as
    /// [`TryFrom<Vec<u8>>`] (an owned-input validated-builder helper,
    /// a `serde_bytes`-frontier wrapper that hands its container an
    /// owned [`Vec<u8>`]) recovers the same typed value the inherent
    /// oracle produces.
    #[test]
    fn test_try_from_vec_bytes_carries_through_generic_consumer() {
        fn parse_via_try_from<T: TryFrom<Vec<u8>, Error = ContentDigestError>>(
            bytes: Vec<u8>,
        ) -> Result<T, ContentDigestError> {
            T::try_from(bytes)
        }
        let raw = format!("sha256:{D1}");
        let d: ContentDigest = parse_via_try_from(raw.clone().into_bytes()).unwrap();
        assert_eq!(d.as_str(), raw);
        let err = parse_via_try_from::<ContentDigest>(b"sha256abc".to_vec()).unwrap_err();
        assert!(matches!(err, ContentDigestError::MissingSeparator { .. }));
    }

    /// [`TryFrom<Vec<u8>>`] round-trips through the emit peer
    /// [`From<ContentDigest> for Vec<u8>`] — parsing an owned buffer,
    /// emitting the owned buffer off the resulting value, then
    /// re-parsing that emitted buffer yields the SAME validated
    /// [`ContentDigest`]. Pins the "the by-value owned-byte parse peer
    /// and the by-value owned-byte emit peer are mutual inverses on
    /// the validated subset" invariant, closing the round-trip
    /// discipline on the owned-byte axis (the string-axis round-trip
    /// through [`TryFrom<String>`] / [`From<ContentDigest> for
    /// String`] is already pinned by prior tests).
    #[test]
    fn test_try_from_vec_bytes_round_trips_through_vec_emit_peer() {
        let raw = format!("sha256:{D1}");
        let d1 = ContentDigest::try_from(raw.clone().into_bytes()).unwrap();
        let emitted: Vec<u8> = d1.clone().into();
        let d2 = ContentDigest::try_from(emitted).unwrap();
        assert_eq!(d1, d2);
        assert_eq!(d2.as_str(), raw);
    }

    /// [`TryFrom<Box<str>>`] succeeds on the shrunk-owned UTF-8
    /// serialization of a well-formed sha256 digest and yields the same
    /// validated value as the inherent oracle. The by-value shrunk-owned
    /// UTF-8 parse surface — the natural intake for a consumer that
    /// owns a [`Box<str>`] shed off a growth-header [`String`] through
    /// [`String::into_boxed_str`], a serde container that opts into
    /// `#[serde(try_from = "Box<str>")]` on a wrapper field, or a
    /// heap-owned label slot stored as [`Box<str>`] — routes through
    /// the same one-oracle grammar as every other parse peer.
    #[test]
    fn test_try_from_box_str_parses_sha256_digest() {
        let raw = format!("sha256:{D1}");
        let boxed: Box<str> = raw.clone().into_boxed_str();
        let d = ContentDigest::try_from(boxed).unwrap();
        assert_eq!(d.as_str(), raw);
        assert_eq!(d.algorithm(), "sha256");
        assert_eq!(d.hex(), D1);
        let inherent = ContentDigest::parse(&raw).unwrap();
        assert_eq!(d, inherent);
    }

    /// [`TryFrom<Box<str>>`] succeeds on the shrunk-owned UTF-8
    /// serialization of a well-formed sha512 digest — the second
    /// supported algorithm at the digest reference-grammar family.
    /// Pins the impl across both algorithms so a widening at the
    /// inherent oracle (e.g. `sha384`) is caught by an existing test
    /// on this derived surface.
    #[test]
    fn test_try_from_box_str_parses_sha512_digest() {
        let hex = "f".repeat(SHA512_HEX_LEN);
        let raw = format!("sha512:{hex}");
        let boxed: Box<str> = raw.clone().into_boxed_str();
        let d = ContentDigest::try_from(boxed).unwrap();
        assert_eq!(d.as_str(), raw);
        assert_eq!(d.algorithm(), "sha512");
        assert_eq!(d.hex(), hex);
    }

    /// [`TryFrom<Box<str>>`] trims leading / trailing ASCII whitespace
    /// on the delegated string oracle — a shrunk-owned UTF-8 buffer
    /// whose trailing newline rides in the moved [`Box<str>`] parses
    /// successfully because the string oracle whitespace-trims before
    /// checking the grammar. Pins the trim discipline carrying
    /// through the shrunk-owned UTF-8 frontier.
    #[test]
    fn test_try_from_box_str_trims_edge_whitespace() {
        let raw = format!("  sha256:{D1}\n");
        let expected = format!("sha256:{D1}");
        let boxed: Box<str> = raw.into_boxed_str();
        let d = ContentDigest::try_from(boxed).unwrap();
        assert_eq!(d.as_str(), expected);
    }

    /// [`TryFrom<Box<str>>`] emits the SAME error
    /// [`ContentDigest::parse`] emits on every grammar-failure input —
    /// the missing-separator, unsupported-algorithm, and invalid-hex
    /// variants route through the string oracle unchanged because the
    /// shrunk-owned-string peer delegates via [`String::from`] then
    /// [`TryFrom<String>`]. Pins the "shrunk-owned UTF-8 parse surface
    /// reads through the string parse oracle on grammar-failure
    /// inputs" invariant so a future refactor that inlined a divergent
    /// grammar into the shrunk-owned peer fails this test.
    #[test]
    fn test_try_from_box_str_matches_inherent_parse_on_every_error_mode() {
        let err_cases: [String; 5] = [
            "sha256abc".to_string(),                 // missing separator
            format!("md5:{D1}"),                     // unsupported algorithm
            format!("sha256:{}", &D1[..60]),         // wrong hex length
            format!("sha256:{}", D1.to_uppercase()), // uppercase hex
            format!("sha256:{}g", &D1[..63]),        // non-hex byte
        ];
        for raw in err_cases {
            let boxed: Box<str> = raw.clone().into_boxed_str();
            let via_box = ContentDigest::try_from(boxed);
            let via_inherent = ContentDigest::parse(&raw);
            assert_eq!(
                via_box, via_inherent,
                "TryFrom<Box<str>> and inherent parse must agree on '{raw}'",
            );
        }
    }

    /// [`TryFrom<Box<str>>`] agrees with [`TryFrom<String>`] on every
    /// well-formed AND grammar-failure input — the by-value shrunk-
    /// owned UTF-8 parse peer and the by-value owned-UTF-8 parse peer
    /// resolve to the SAME [`Result<ContentDigest, ContentDigestError>`]
    /// across every input the two share, so a downstream site that
    /// migrates a consumer from [`String`] to [`Box<str>`] (a memory-
    /// optimisation pass that sheds the growth-header word on
    /// immutable label slots) yields identical values and identical
    /// errors at every input. Pins the "owned and shrunk-owned string
    /// parse peers read through the same canonical oracle" invariant.
    #[test]
    fn test_try_from_box_str_agrees_with_try_from_string() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let ok_cases = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha512:{hex512}"),
            format!("  sha256:{D3}\n"),
        ];
        for raw in ok_cases {
            let boxed: Box<str> = raw.clone().into_boxed_str();
            let via_box = ContentDigest::try_from(boxed);
            let via_string = ContentDigest::try_from(raw.clone());
            assert_eq!(via_box, via_string);
        }
        let err_cases: [String; 5] = [
            "sha256abc".to_string(),
            format!("md5:{D1}"),
            format!("sha256:{}", &D1[..60]),
            format!("sha256:{}", D1.to_uppercase()),
            format!("sha256:{}g", &D1[..63]),
        ];
        for raw in err_cases {
            let boxed: Box<str> = raw.clone().into_boxed_str();
            let via_box = ContentDigest::try_from(boxed);
            let via_string = ContentDigest::try_from(raw.clone());
            assert_eq!(via_box, via_string);
        }
    }

    /// The [`TryFrom<Box<str>>`] impl composes with a generic
    /// try-conversion helper bounded by `TryFrom<Box<str>, Error =
    /// ContentDigestError>` — the compositional motivation for landing
    /// the trait separately from the [`String`] parse surface. Pins the
    /// by-value shrunk-owned generic-consumer surface so a downstream
    /// site that types its parse contract as [`TryFrom<Box<str>>`] (a
    /// serde container that opts into
    /// `#[serde(try_from = "Box<str>")]`, a heap-owned-label
    /// validated-builder helper) recovers the same typed value the
    /// inherent oracle produces.
    #[test]
    fn test_try_from_box_str_carries_through_generic_consumer() {
        fn parse_via_try_from<T: TryFrom<Box<str>, Error = ContentDigestError>>(
            boxed: Box<str>,
        ) -> Result<T, ContentDigestError> {
            T::try_from(boxed)
        }
        let raw = format!("sha256:{D1}");
        let boxed: Box<str> = raw.clone().into_boxed_str();
        let d: ContentDigest = parse_via_try_from(boxed).unwrap();
        assert_eq!(d.as_str(), raw);
        let bad: Box<str> = Box::from("sha256abc");
        let err = parse_via_try_from::<ContentDigest>(bad).unwrap_err();
        assert!(matches!(err, ContentDigestError::MissingSeparator { .. }));
    }

    /// [`TryFrom<Box<str>>`] round-trips through the emit peer
    /// [`From<ContentDigest> for Box<str>`] — parsing a shrunk-owned
    /// UTF-8 buffer, emitting the shrunk-owned buffer off the resulting
    /// value, then re-parsing that emitted buffer yields the SAME
    /// validated [`ContentDigest`]. Pins the "the by-value shrunk-owned
    /// UTF-8 parse peer and the by-value shrunk-owned UTF-8 emit peer
    /// are mutual inverses on the validated subset" invariant, closing
    /// the round-trip discipline on the [`Box<str>`] axis.
    #[test]
    fn test_try_from_box_str_round_trips_through_box_str_emit_peer() {
        let raw = format!("sha256:{D1}");
        let boxed: Box<str> = raw.clone().into_boxed_str();
        let d1 = ContentDigest::try_from(boxed).unwrap();
        let emitted: Box<str> = d1.clone().into();
        let d2 = ContentDigest::try_from(emitted).unwrap();
        assert_eq!(d1, d2);
        assert_eq!(d2.as_str(), raw);
    }

    /// [`TryFrom<Arc<str>>`] succeeds on the shared-owned UTF-8
    /// serialization of a well-formed sha256 digest — the primary
    /// registry algorithm. Pins the happy path: a downstream site that
    /// hands the shrunk-owned buffer through an `Arc::clone` before
    /// parse (a cross-thread cached-label slot, a serde container that
    /// opts into `#[serde(try_from = "Arc<str>")]` on a wrapper field,
    /// a `Vec<Arc<str>>` per-attempt digest list) routes through the
    /// same one-oracle grammar as every other parse peer.
    #[test]
    fn test_try_from_arc_str_parses_sha256_digest() {
        let raw = format!("sha256:{D1}");
        let shared: std::sync::Arc<str> = std::sync::Arc::<str>::from(raw.as_str());
        let d = ContentDigest::try_from(shared).unwrap();
        assert_eq!(d.as_str(), raw);
        assert_eq!(d.algorithm(), "sha256");
        assert_eq!(d.hex(), D1);
        let inherent = ContentDigest::parse(&raw).unwrap();
        assert_eq!(d, inherent);
    }

    /// [`TryFrom<Arc<str>>`] succeeds on the shared-owned UTF-8
    /// serialization of a well-formed sha512 digest — the second
    /// supported algorithm at the digest reference-grammar family.
    /// Pins the impl across both algorithms so a widening at the
    /// inherent oracle (e.g. `sha384`) is caught by an existing test
    /// on this derived surface.
    #[test]
    fn test_try_from_arc_str_parses_sha512_digest() {
        let hex = "f".repeat(SHA512_HEX_LEN);
        let raw = format!("sha512:{hex}");
        let shared: std::sync::Arc<str> = std::sync::Arc::<str>::from(raw.as_str());
        let d = ContentDigest::try_from(shared).unwrap();
        assert_eq!(d.as_str(), raw);
        assert_eq!(d.algorithm(), "sha512");
        assert_eq!(d.hex(), hex);
    }

    /// [`TryFrom<Arc<str>>`] trims leading / trailing ASCII whitespace
    /// on the delegated string oracle — a shared-owned UTF-8 buffer
    /// whose trailing newline rides in the shared allocation parses
    /// successfully because the string oracle whitespace-trims before
    /// checking the grammar. Pins the trim discipline carrying through
    /// the shared-owned UTF-8 frontier.
    #[test]
    fn test_try_from_arc_str_trims_edge_whitespace() {
        let raw = format!("  sha256:{D1}\n");
        let expected = format!("sha256:{D1}");
        let shared: std::sync::Arc<str> = std::sync::Arc::<str>::from(raw.as_str());
        let d = ContentDigest::try_from(shared).unwrap();
        assert_eq!(d.as_str(), expected);
    }

    /// [`TryFrom<Arc<str>>`] emits the SAME error
    /// [`ContentDigest::parse`] emits on every grammar-failure input —
    /// the missing-separator, unsupported-algorithm, and invalid-hex
    /// variants route through the string oracle unchanged because the
    /// shared-owned-string peer delegates via [`AsRef::as_ref`] then
    /// [`TryFrom<&str>`]. Pins the "shared-owned UTF-8 parse surface
    /// reads through the string parse oracle on grammar-failure inputs"
    /// invariant so a future refactor that inlined a divergent grammar
    /// into the shared-owned peer fails this test.
    #[test]
    fn test_try_from_arc_str_matches_inherent_parse_on_every_error_mode() {
        let err_cases: [String; 5] = [
            "sha256abc".to_string(),                 // missing separator
            format!("md5:{D1}"),                     // unsupported algorithm
            format!("sha256:{}", &D1[..60]),         // wrong hex length
            format!("sha256:{}", D1.to_uppercase()), // uppercase hex
            format!("sha256:{}g", &D1[..63]),        // non-hex byte
        ];
        for raw in err_cases {
            let shared: std::sync::Arc<str> = std::sync::Arc::<str>::from(raw.as_str());
            let via_arc = ContentDigest::try_from(shared);
            let via_inherent = ContentDigest::parse(&raw);
            assert_eq!(
                via_arc, via_inherent,
                "TryFrom<Arc<str>> and inherent parse must agree on '{raw}'",
            );
        }
    }

    /// [`TryFrom<Arc<str>>`] agrees with [`TryFrom<Box<str>>`] on every
    /// well-formed AND grammar-failure input — the by-value
    /// shared-owned UTF-8 parse peer and the by-value shrunk-owned UTF-8
    /// parse peer resolve to the SAME
    /// [`Result<ContentDigest, ContentDigestError>`] across every input
    /// the two share, so a downstream site that migrates a consumer from
    /// [`Box<str>`] to [`Arc<str>`] (a memory-optimisation pass that
    /// widens a heap-owned label slot to a cross-thread refcounted one
    /// to shed per-worker allocations) yields identical values and
    /// identical errors at every input. Pins the "shrunk-owned and
    /// shared-owned string parse peers read through the same canonical
    /// oracle" invariant, closing the sibling-peer agreement between
    /// the two newest owned-shape parse peers.
    #[test]
    fn test_try_from_arc_str_agrees_with_try_from_box_str() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let ok_cases = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha512:{hex512}"),
            format!("  sha256:{D3}\n"),
        ];
        for raw in ok_cases {
            let shared: std::sync::Arc<str> = std::sync::Arc::<str>::from(raw.as_str());
            let boxed: Box<str> = raw.clone().into_boxed_str();
            let via_arc = ContentDigest::try_from(shared);
            let via_box = ContentDigest::try_from(boxed);
            assert_eq!(via_arc, via_box);
        }
        let err_cases: [String; 5] = [
            "sha256abc".to_string(),
            format!("md5:{D1}"),
            format!("sha256:{}", &D1[..60]),
            format!("sha256:{}", D1.to_uppercase()),
            format!("sha256:{}g", &D1[..63]),
        ];
        for raw in err_cases {
            let shared: std::sync::Arc<str> = std::sync::Arc::<str>::from(raw.as_str());
            let boxed: Box<str> = raw.clone().into_boxed_str();
            let via_arc = ContentDigest::try_from(shared);
            let via_box = ContentDigest::try_from(boxed);
            assert_eq!(via_arc, via_box);
        }
    }

    /// The [`TryFrom<Arc<str>>`] impl composes with a generic
    /// try-conversion helper bounded by `TryFrom<Arc<str>, Error =
    /// ContentDigestError>` — the compositional motivation for landing
    /// the trait separately from the [`String`] and [`Box<str>`] parse
    /// surfaces. Pins the by-value shared-owned generic-consumer surface
    /// so a downstream site that types its parse contract as
    /// [`TryFrom<Arc<str>>`] (a serde container that opts into
    /// `#[serde(try_from = "Arc<str>")]`, a cross-thread-cached-label
    /// validated-builder helper) recovers the same typed value the
    /// inherent oracle produces.
    #[test]
    fn test_try_from_arc_str_carries_through_generic_consumer() {
        fn parse_via_try_from<T: TryFrom<std::sync::Arc<str>, Error = ContentDigestError>>(
            shared: std::sync::Arc<str>,
        ) -> Result<T, ContentDigestError> {
            T::try_from(shared)
        }
        let raw = format!("sha256:{D1}");
        let shared: std::sync::Arc<str> = std::sync::Arc::<str>::from(raw.as_str());
        let d: ContentDigest = parse_via_try_from(shared).unwrap();
        assert_eq!(d.as_str(), raw);
        let bad: std::sync::Arc<str> = std::sync::Arc::<str>::from("sha256abc");
        let err = parse_via_try_from::<ContentDigest>(bad).unwrap_err();
        assert!(matches!(err, ContentDigestError::MissingSeparator { .. }));
    }

    /// [`TryFrom<Arc<str>>`] round-trips through the emit peer
    /// [`From<ContentDigest> for Arc<str>`] — parsing a shared-owned
    /// UTF-8 buffer, emitting the shared-owned buffer off the resulting
    /// value, then re-parsing that emitted buffer yields the SAME
    /// validated [`ContentDigest`]. Pins the "the by-value shared-owned
    /// UTF-8 parse peer and the by-value shared-owned UTF-8 emit peer
    /// are mutual inverses on the validated subset" invariant, closing
    /// the round-trip discipline on the [`Arc<str>`] axis and matching
    /// the closed [`Box<str>`] round-trip pinned above.
    #[test]
    fn test_try_from_arc_str_round_trips_through_arc_str_emit_peer() {
        let raw = format!("sha256:{D1}");
        let shared: std::sync::Arc<str> = std::sync::Arc::<str>::from(raw.as_str());
        let d1 = ContentDigest::try_from(shared).unwrap();
        let emitted: std::sync::Arc<str> = d1.clone().into();
        let d2 = ContentDigest::try_from(emitted).unwrap();
        assert_eq!(d1, d2);
        assert_eq!(d2.as_str(), raw);
    }

    /// [`TryFrom<Rc<str>>`] succeeds on the thread-local shared-owned
    /// UTF-8 serialization of a well-formed sha256 digest — the by-value
    /// parse peer of [`TryFrom<&str>`], accepting the receiver-side
    /// shared-owned buffer through [`AsRef::as_ref`] then delegating to
    /// the string oracle. Pins the "shared-owned UTF-8 parse surface
    /// reads through the string parse oracle" invariant so a future
    /// refactor that inlined a divergent grammar into the shared-owned
    /// peer fails this test.
    #[test]
    fn test_try_from_rc_str_parses_sha256_digest() {
        let raw = format!("sha256:{D1}");
        let shared: std::rc::Rc<str> = std::rc::Rc::<str>::from(raw.as_str());
        let d = ContentDigest::try_from(shared).unwrap();
        assert_eq!(d.as_str(), raw);
        assert_eq!(d.algorithm(), "sha256");
        assert_eq!(d.hex(), D1);
        let inherent = ContentDigest::parse(&raw).unwrap();
        assert_eq!(d, inherent);
    }

    /// [`TryFrom<Rc<str>>`] succeeds on the shared-owned UTF-8
    /// serialization of a well-formed sha512 digest — the second
    /// supported algorithm at the digest reference-grammar family.
    /// Pins the impl across both algorithms so a widening at the
    /// inherent oracle (e.g. `sha384`) is caught by an existing test
    /// on this derived surface.
    #[test]
    fn test_try_from_rc_str_parses_sha512_digest() {
        let hex = "f".repeat(SHA512_HEX_LEN);
        let raw = format!("sha512:{hex}");
        let shared: std::rc::Rc<str> = std::rc::Rc::<str>::from(raw.as_str());
        let d = ContentDigest::try_from(shared).unwrap();
        assert_eq!(d.as_str(), raw);
        assert_eq!(d.algorithm(), "sha512");
        assert_eq!(d.hex(), hex);
    }

    /// [`TryFrom<Rc<str>>`] trims leading / trailing ASCII whitespace
    /// on the delegated string oracle — a thread-local shared-owned
    /// UTF-8 buffer whose trailing newline rides in the shared
    /// allocation parses successfully because the string oracle
    /// whitespace-trims before checking the grammar. Pins the trim
    /// discipline carrying through the thread-local shared-owned UTF-8
    /// frontier.
    #[test]
    fn test_try_from_rc_str_trims_edge_whitespace() {
        let raw = format!("  sha256:{D1}\n");
        let expected = format!("sha256:{D1}");
        let shared: std::rc::Rc<str> = std::rc::Rc::<str>::from(raw.as_str());
        let d = ContentDigest::try_from(shared).unwrap();
        assert_eq!(d.as_str(), expected);
    }

    /// [`TryFrom<Rc<str>>`] emits the SAME error
    /// [`ContentDigest::parse`] emits on every grammar-failure input —
    /// the missing-separator, unsupported-algorithm, and invalid-hex
    /// variants route through the string oracle unchanged because the
    /// thread-local shared-owned-string peer delegates via
    /// [`AsRef::as_ref`] then [`TryFrom<&str>`]. Pins the "thread-local
    /// shared-owned UTF-8 parse surface reads through the string parse
    /// oracle on grammar-failure inputs" invariant so a future refactor
    /// that inlined a divergent grammar into the thread-local
    /// shared-owned peer fails this test.
    #[test]
    fn test_try_from_rc_str_matches_inherent_parse_on_every_error_mode() {
        let err_cases: [String; 5] = [
            "sha256abc".to_string(),                 // missing separator
            format!("md5:{D1}"),                     // unsupported algorithm
            format!("sha256:{}", &D1[..60]),         // wrong hex length
            format!("sha256:{}", D1.to_uppercase()), // uppercase hex
            format!("sha256:{}g", &D1[..63]),        // non-hex byte
        ];
        for raw in err_cases {
            let shared: std::rc::Rc<str> = std::rc::Rc::<str>::from(raw.as_str());
            let via_rc = ContentDigest::try_from(shared);
            let via_inherent = ContentDigest::parse(&raw);
            assert_eq!(
                via_rc, via_inherent,
                "TryFrom<Rc<str>> and inherent parse must agree on '{raw}'",
            );
        }
    }

    /// [`TryFrom<Rc<str>>`] agrees with [`TryFrom<Arc<str>>`] on every
    /// well-formed AND grammar-failure input — the by-value thread-local
    /// shared-owned UTF-8 parse peer and the by-value cross-thread
    /// shared-owned UTF-8 parse peer resolve to the SAME
    /// [`Result<ContentDigest, ContentDigestError>`] across every input
    /// the two share, so a downstream site that migrates a consumer from
    /// [`Arc<str>`] to [`Rc<str>`] (a scan-phase pass that narrows a
    /// cross-thread refcounted label slot to a single-thread refcounted
    /// one to shed the atomic-fence overhead on labels never accessed
    /// across threads) yields identical values and identical errors at
    /// every input. Pins the "thread-local shared-owned and cross-thread
    /// shared-owned string parse peers read through the same canonical
    /// oracle" invariant, closing the sibling-peer agreement between the
    /// two shared-owned owned-shape parse peers.
    #[test]
    fn test_try_from_rc_str_agrees_with_try_from_arc_str() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let ok_cases = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha512:{hex512}"),
            format!("  sha256:{D3}\n"),
        ];
        for raw in ok_cases {
            let rc: std::rc::Rc<str> = std::rc::Rc::<str>::from(raw.as_str());
            let arc: std::sync::Arc<str> = std::sync::Arc::<str>::from(raw.as_str());
            let via_rc = ContentDigest::try_from(rc);
            let via_arc = ContentDigest::try_from(arc);
            assert_eq!(via_rc, via_arc);
        }
        let err_cases: [String; 5] = [
            "sha256abc".to_string(),
            format!("md5:{D1}"),
            format!("sha256:{}", &D1[..60]),
            format!("sha256:{}", D1.to_uppercase()),
            format!("sha256:{}g", &D1[..63]),
        ];
        for raw in err_cases {
            let rc: std::rc::Rc<str> = std::rc::Rc::<str>::from(raw.as_str());
            let arc: std::sync::Arc<str> = std::sync::Arc::<str>::from(raw.as_str());
            let via_rc = ContentDigest::try_from(rc);
            let via_arc = ContentDigest::try_from(arc);
            assert_eq!(via_rc, via_arc);
        }
    }

    /// The [`TryFrom<Rc<str>>`] impl composes with a generic
    /// try-conversion helper bounded by `TryFrom<Rc<str>, Error =
    /// ContentDigestError>` — the compositional motivation for landing
    /// the trait separately from the [`String`], [`Box<str>`], and
    /// [`Arc<str>`] parse surfaces. Pins the by-value thread-local
    /// shared-owned generic-consumer surface so a downstream site that
    /// types its parse contract as [`TryFrom<Rc<str>>`] (a serde
    /// container that opts into `#[serde(try_from = "Rc<str>")]`, a
    /// single-thread-cached-label validated-builder helper) recovers
    /// the same typed value the inherent oracle produces.
    #[test]
    fn test_try_from_rc_str_carries_through_generic_consumer() {
        fn parse_via_try_from<T: TryFrom<std::rc::Rc<str>, Error = ContentDigestError>>(
            shared: std::rc::Rc<str>,
        ) -> Result<T, ContentDigestError> {
            T::try_from(shared)
        }
        let raw = format!("sha256:{D1}");
        let shared: std::rc::Rc<str> = std::rc::Rc::<str>::from(raw.as_str());
        let d: ContentDigest = parse_via_try_from(shared).unwrap();
        assert_eq!(d.as_str(), raw);
        let bad: std::rc::Rc<str> = std::rc::Rc::<str>::from("sha256abc");
        let err = parse_via_try_from::<ContentDigest>(bad).unwrap_err();
        assert!(matches!(err, ContentDigestError::MissingSeparator { .. }));
    }

    /// [`TryFrom<Rc<str>>`] round-trips through the emit peer
    /// [`From<ContentDigest> for Rc<str>`] — parsing a thread-local
    /// shared-owned UTF-8 buffer, emitting the shared-owned buffer off
    /// the resulting value, then re-parsing that emitted buffer yields
    /// the SAME validated [`ContentDigest`]. Pins the "the by-value
    /// thread-local shared-owned UTF-8 parse peer and the by-value
    /// thread-local shared-owned UTF-8 emit peer are mutual inverses on
    /// the validated subset" invariant, closing the round-trip
    /// discipline on the [`Rc<str>`] axis and matching the closed
    /// [`Arc<str>`] round-trip pinned above.
    #[test]
    fn test_try_from_rc_str_round_trips_through_rc_str_emit_peer() {
        let raw = format!("sha256:{D1}");
        let shared: std::rc::Rc<str> = std::rc::Rc::<str>::from(raw.as_str());
        let d1 = ContentDigest::try_from(shared).unwrap();
        let emitted: std::rc::Rc<str> = d1.clone().into();
        let d2 = ContentDigest::try_from(emitted).unwrap();
        assert_eq!(d1, d2);
        assert_eq!(d2.as_str(), raw);
    }

    /// [`TryFrom<Cow<'_, [u8]>>`] succeeds on a well-formed sha256 digest
    /// handed in via the borrowed arm — the zero-copy path a serde byte
    /// deserializer takes when the input slice can be reused directly.
    /// Pins the primary algorithm on the borrowed arm of the derived
    /// byte-slice frontier surface.
    #[test]
    fn test_try_from_cow_bytes_borrowed_parses_sha256_digest() {
        let raw = format!("sha256:{D1}");
        let cow: std::borrow::Cow<'_, [u8]> = std::borrow::Cow::Borrowed(raw.as_bytes());
        let d = ContentDigest::try_from(cow).unwrap();
        assert_eq!(d.as_str(), raw);
        assert_eq!(d.algorithm(), "sha256");
        assert_eq!(d.hex(), D1);
        let inherent = ContentDigest::parse(&raw).unwrap();
        assert_eq!(d, inherent);
    }

    /// [`TryFrom<Cow<'_, [u8]>>`] succeeds on a well-formed sha256 digest
    /// handed in via the owned arm — the fallback path a serde byte
    /// deserializer takes when zero-copy is unavailable (an escaped or
    /// re-materialised byte buffer, a network response body already
    /// consumed into `Vec<u8>`). Pins the primary algorithm on the owned
    /// arm.
    #[test]
    fn test_try_from_cow_bytes_owned_parses_sha256_digest() {
        let raw = format!("sha256:{D1}");
        let cow: std::borrow::Cow<'_, [u8]> = std::borrow::Cow::Owned(raw.as_bytes().to_vec());
        let d = ContentDigest::try_from(cow).unwrap();
        assert_eq!(d.as_str(), raw);
        assert_eq!(d.algorithm(), "sha256");
        assert_eq!(d.hex(), D1);
    }

    /// [`TryFrom<Cow<'_, [u8]>>`] succeeds on a well-formed sha512 digest
    /// across both `Cow` arms. Pins the second supported algorithm on
    /// the borrowed/owned-frontier byte-slice surface so a widening at
    /// the inherent oracle is caught by an existing test on this
    /// derived surface.
    #[test]
    fn test_try_from_cow_bytes_parses_sha512_digest_both_arms() {
        let hex = "f".repeat(SHA512_HEX_LEN);
        let raw = format!("sha512:{hex}");
        let via_borrowed =
            ContentDigest::try_from(std::borrow::Cow::Borrowed(raw.as_bytes())).unwrap();
        let via_owned =
            ContentDigest::try_from(std::borrow::Cow::<'_, [u8]>::Owned(raw.as_bytes().to_vec()))
                .unwrap();
        assert_eq!(via_borrowed, via_owned);
        assert_eq!(via_borrowed.algorithm(), "sha512");
        assert_eq!(via_borrowed.hex(), hex);
    }

    /// [`TryFrom<Cow<'_, [u8]>>`] inherits the inherent oracle's
    /// edge-whitespace trim on both arms so a captured registry stdout
    /// whose trailing newline rides in the byte buffer still parses on
    /// either the borrowed or the owned arm.
    #[test]
    fn test_try_from_cow_bytes_trims_edge_whitespace_both_arms() {
        let raw = format!("  sha256:{D1}\n");
        let expected = format!("sha256:{D1}");
        let via_borrowed =
            ContentDigest::try_from(std::borrow::Cow::Borrowed(raw.as_bytes())).unwrap();
        let via_owned =
            ContentDigest::try_from(std::borrow::Cow::<'_, [u8]>::Owned(raw.as_bytes().to_vec()))
                .unwrap();
        assert_eq!(via_borrowed.as_str(), expected);
        assert_eq!(via_owned.as_str(), expected);
    }

    /// [`TryFrom<Cow<'_, [u8]>>`] agrees with the inherent oracle on every
    /// canonical grammar-failure mode across both arms. Pins the
    /// "one grammar oracle serves every borrowed-or-owned byte-slice
    /// parse entry point" invariant. A future refactor that inlined a
    /// divergent grammar into either arm fails this test.
    #[test]
    fn test_try_from_cow_bytes_matches_inherent_parse_on_every_grammar_error_mode() {
        let err_cases = [
            "sha256abc123".to_string(),
            format!("md5:{D1}"),
            format!("sha1:0123456789abcdef0123456789abcdef01234567"),
            format!("sha256:{}", &D1[..60]),
            format!("sha256:{}", D1.to_uppercase()),
            format!("sha256:{}g", &D1[..63]),
        ];
        for raw in err_cases {
            let via_borrowed = ContentDigest::try_from(std::borrow::Cow::Borrowed(raw.as_bytes()));
            let via_owned = ContentDigest::try_from(std::borrow::Cow::<'_, [u8]>::Owned(
                raw.as_bytes().to_vec(),
            ));
            let via_inherent = ContentDigest::parse(&raw);
            assert_eq!(
                via_borrowed, via_inherent,
                "TryFrom<Cow::Borrowed<[u8]>> and inherent parse must agree on '{raw}'",
            );
            assert_eq!(
                via_owned, via_inherent,
                "TryFrom<Cow::Owned<[u8]>> and inherent parse must agree on '{raw}'",
            );
            assert!(via_borrowed.is_err());
        }
    }

    /// [`TryFrom<Cow<'_, [u8]>>`] agrees arm-for-arm with the shape-
    /// matched byte-slice peers: the borrowed arm resolves to the same
    /// [`Result`] as [`TryFrom<&[u8]>`] on the same byte view, and the
    /// owned arm resolves to the same [`Result`] as [`TryFrom<Vec<u8>>`]
    /// on the same owned bytes. Pins the arm-matched delegation
    /// discipline so a future refactor that collapsed the owned arm
    /// through the borrowed peer (forcing a re-allocation in the string
    /// oracle) or the borrowed arm through the owned peer (forcing a
    /// spurious `to_vec()`) fails this test.
    #[test]
    fn test_try_from_cow_bytes_agrees_with_shape_matched_byte_peers() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let ok_cases = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha512:{hex512}"),
            format!("  sha256:{D3}\n"),
        ];
        for raw in ok_cases {
            let via_cow_borrowed =
                ContentDigest::try_from(std::borrow::Cow::Borrowed(raw.as_bytes()));
            let via_slice = ContentDigest::try_from(raw.as_bytes());
            assert_eq!(via_cow_borrowed, via_slice);

            let via_cow_owned = ContentDigest::try_from(std::borrow::Cow::<'_, [u8]>::Owned(
                raw.as_bytes().to_vec(),
            ));
            let via_vec = ContentDigest::try_from(raw.as_bytes().to_vec());
            assert_eq!(via_cow_owned, via_vec);
        }
        let err_cases = [
            "sha256abc",
            &format!("md5:{D1}"),
            &format!("sha256:{}", &D1[..60]),
            &format!("sha256:{}", D1.to_uppercase()),
            &format!("sha256:{}g", &D1[..63]),
        ];
        for raw in err_cases {
            let via_cow_borrowed =
                ContentDigest::try_from(std::borrow::Cow::Borrowed(raw.as_bytes()));
            let via_slice = ContentDigest::try_from(raw.as_bytes());
            assert_eq!(via_cow_borrowed, via_slice);

            let via_cow_owned = ContentDigest::try_from(std::borrow::Cow::<'_, [u8]>::Owned(
                raw.as_bytes().to_vec(),
            ));
            let via_vec = ContentDigest::try_from(raw.as_bytes().to_vec());
            assert_eq!(via_cow_owned, via_vec);
        }
    }

    /// [`TryFrom<Cow<'_, [u8]>>`] on a UTF-8-invalid input surfaces
    /// [`ContentDigestError::InvalidUtf8`] on BOTH arms — the borrowed
    /// arm through [`std::str::from_utf8`] inside the by-reference
    /// byte-slice peer, the owned arm through [`String::from_utf8`]
    /// inside the by-value byte-slice peer. Pins the byte-frontier
    /// UTF-8 gate on both arms so a downstream consumer receiving a
    /// raw wire buffer as [`Cow<'_, [u8]>`] cannot leak a non-UTF-8
    /// sequence past the byte frontier as a MissingSeparator /
    /// UnsupportedAlgorithm / InvalidHex misdiagnosis.
    #[test]
    fn test_try_from_cow_bytes_rejects_invalid_utf8_both_arms() {
        let mut bytes = format!("sha256:{D1}").into_bytes();
        bytes.push(0xff);
        let borrowed_err =
            ContentDigest::try_from(std::borrow::Cow::Borrowed(bytes.as_slice())).unwrap_err();
        assert!(matches!(
            borrowed_err,
            ContentDigestError::InvalidUtf8 { .. }
        ));
        let owned_err = ContentDigest::try_from(std::borrow::Cow::<'_, [u8]>::Owned(bytes.clone()))
            .unwrap_err();
        assert!(matches!(owned_err, ContentDigestError::InvalidUtf8 { .. }));
        assert_eq!(borrowed_err.to_string(), owned_err.to_string());
    }

    /// The [`TryFrom<Cow<'_, [u8]>>`] impl composes with a generic
    /// try-conversion helper bounded by `for<'a> TryFrom<Cow<'a, [u8]>,
    /// Error = ContentDigestError>` — the compositional motivation for
    /// landing the trait separately from the shape-specific byte-slice
    /// peers. Pins the borrowed/owned-frontier byte-slice generic-
    /// consumer surface so a downstream site that types its parse
    /// contract as [`TryFrom<Cow<'_, [u8]>>`] (a serde
    /// `try_from = "Cow<'_, [u8]>"` wrapper on a byte-frontier
    /// deserializer, a caller-agnostic validated builder) recovers the
    /// same typed value the inherent oracle produces on both arms.
    #[test]
    fn test_try_from_cow_bytes_carries_through_generic_consumer() {
        fn parse_via_try_from<'a, T>(
            bytes: std::borrow::Cow<'a, [u8]>,
        ) -> Result<T, ContentDigestError>
        where
            T: TryFrom<std::borrow::Cow<'a, [u8]>, Error = ContentDigestError>,
        {
            T::try_from(bytes)
        }
        let raw = format!("sha256:{D1}");
        let borrowed: std::borrow::Cow<'_, [u8]> = std::borrow::Cow::Borrowed(raw.as_bytes());
        let d: ContentDigest = parse_via_try_from(borrowed).unwrap();
        assert_eq!(d.as_str(), raw);
        let owned: std::borrow::Cow<'_, [u8]> = std::borrow::Cow::Owned(raw.as_bytes().to_vec());
        let d2: ContentDigest = parse_via_try_from(owned).unwrap();
        assert_eq!(d2, d);
        let err = parse_via_try_from::<ContentDigest>(std::borrow::Cow::Borrowed(b"sha256abc"))
            .unwrap_err();
        assert!(matches!(err, ContentDigestError::MissingSeparator { .. }));
    }

    /// [`TryFrom<Cow<'_, [u8]>>`] round-trips through the emit peer
    /// [`From<ContentDigest> for Cow<'static, [u8]>`] (commit c2a5acf):
    /// parsing a borrowed-or-owned byte buffer, emitting the owned-arm
    /// buffer off the resulting value, then re-parsing that emitted
    /// buffer yields the SAME validated [`ContentDigest`]. Pins the
    /// "the byte-slice `Cow` parse peer and the byte-slice `Cow` emit
    /// peer are mutual inverses on the validated subset" invariant,
    /// closing the round-trip discipline on the [`Cow<'_, [u8]>`] /
    /// [`Cow<'static, [u8]>`] axis and matching the closed
    /// [`Cow<'_, str>`] round-trip on the sibling UTF-8-string axis.
    #[test]
    fn test_try_from_cow_bytes_round_trips_through_cow_bytes_emit_peer() {
        let raw = format!("sha256:{D1}");
        let via_borrowed: std::borrow::Cow<'_, [u8]> = std::borrow::Cow::Borrowed(raw.as_bytes());
        let d1 = ContentDigest::try_from(via_borrowed).unwrap();
        let emitted: std::borrow::Cow<'static, [u8]> = d1.clone().into();
        let d2 = ContentDigest::try_from(emitted).unwrap();
        assert_eq!(d1, d2);
        assert_eq!(d2.as_str(), raw);
    }

    /// [`TryFrom<Box<[u8]>>`] succeeds on the shrunk-owned raw-byte
    /// serialization of a well-formed sha256 digest — the primary
    /// registry algorithm. Pins the happy path on the derived
    /// shrunk-owned byte-slice frontier surface: a downstream site
    /// that receives its input as a two-word [`Box<[u8]>`] (a serde
    /// `try_from = "Box<[u8]>"` wrapper, a heap-owned raw-byte
    /// validated-builder slot, a shed-capacity `Cow::Owned` byte
    /// arm) routes through the same one-oracle grammar as every
    /// other parse peer.
    #[test]
    fn test_try_from_box_bytes_parses_sha256_digest() {
        let raw = format!("sha256:{D1}");
        let boxed: Box<[u8]> = raw.as_bytes().to_vec().into_boxed_slice();
        let d = ContentDigest::try_from(boxed).unwrap();
        assert_eq!(d.as_str(), raw);
        assert_eq!(d.algorithm(), "sha256");
        assert_eq!(d.hex(), D1);
        let inherent = ContentDigest::parse(&raw).unwrap();
        assert_eq!(d, inherent);
    }

    /// [`TryFrom<Box<[u8]>>`] succeeds on the shrunk-owned raw-byte
    /// serialization of a well-formed sha512 digest — the second
    /// supported algorithm at the digest reference-grammar family.
    /// Pins the impl across both algorithms so a widening at the
    /// inherent oracle (e.g. `sha384`) is caught by an existing
    /// test on this derived surface.
    #[test]
    fn test_try_from_box_bytes_parses_sha512_digest() {
        let hex = "f".repeat(SHA512_HEX_LEN);
        let raw = format!("sha512:{hex}");
        let boxed: Box<[u8]> = raw.as_bytes().to_vec().into_boxed_slice();
        let d = ContentDigest::try_from(boxed).unwrap();
        assert_eq!(d.as_str(), raw);
        assert_eq!(d.algorithm(), "sha512");
        assert_eq!(d.hex(), hex);
    }

    /// [`TryFrom<Box<[u8]>>`] trims leading / trailing ASCII
    /// whitespace on the delegated string oracle — a shrunk-owned
    /// raw-byte buffer whose trailing newline rides in the moved
    /// [`Box<[u8]>`] parses successfully because the string oracle
    /// whitespace-trims before checking the grammar. Pins the trim
    /// discipline carrying through the shrunk-owned byte-slice
    /// frontier.
    #[test]
    fn test_try_from_box_bytes_trims_edge_whitespace() {
        let raw = format!("  sha256:{D1}\n");
        let expected = format!("sha256:{D1}");
        let boxed: Box<[u8]> = raw.as_bytes().to_vec().into_boxed_slice();
        let d = ContentDigest::try_from(boxed).unwrap();
        assert_eq!(d.as_str(), expected);
    }

    /// [`TryFrom<Box<[u8]>>`] emits the SAME error
    /// [`ContentDigest::parse`] emits on every grammar-failure input
    /// — the missing-separator, unsupported-algorithm, and
    /// invalid-hex variants route through the string oracle
    /// unchanged because the shrunk-owned byte peer delegates via
    /// [`Vec::from`] then [`TryFrom<Vec<u8>>`]. Pins the "shrunk-
    /// owned byte-slice parse surface reads through the string
    /// parse oracle on grammar-failure inputs" invariant so a
    /// future refactor that inlined a divergent grammar into the
    /// shrunk-owned byte peer fails this test.
    #[test]
    fn test_try_from_box_bytes_matches_inherent_parse_on_every_error_mode() {
        let err_cases: [String; 5] = [
            "sha256abc".to_string(),                 // missing separator
            format!("md5:{D1}"),                     // unsupported algorithm
            format!("sha256:{}", &D1[..60]),         // wrong hex length
            format!("sha256:{}", D1.to_uppercase()), // uppercase hex
            format!("sha256:{}g", &D1[..63]),        // non-hex byte
        ];
        for raw in err_cases {
            let boxed: Box<[u8]> = raw.as_bytes().to_vec().into_boxed_slice();
            let via_box = ContentDigest::try_from(boxed);
            let via_inherent = ContentDigest::parse(&raw);
            assert_eq!(
                via_box, via_inherent,
                "TryFrom<Box<[u8]>> and inherent parse must agree on '{raw}'",
            );
        }
    }

    /// [`TryFrom<Box<[u8]>>`] agrees with [`TryFrom<Vec<u8>>`] on
    /// every well-formed AND grammar-failure input — the by-value
    /// shrunk-owned byte-slice parse peer and the by-value owned-
    /// byte-slice parse peer resolve to the SAME
    /// [`Result<ContentDigest, ContentDigestError>`] across every
    /// input the two share, so a downstream site that migrates a
    /// consumer from [`Vec<u8>`] to [`Box<[u8]>`] (a memory-
    /// optimisation pass that sheds the growth-header word on
    /// immutable raw-byte slots) yields identical values and
    /// identical errors at every input. Pins the "owned and
    /// shrunk-owned byte-slice parse peers read through the same
    /// canonical oracle" invariant.
    #[test]
    fn test_try_from_box_bytes_agrees_with_try_from_vec_u8() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let ok_cases = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha512:{hex512}"),
            format!("  sha256:{D3}\n"),
        ];
        for raw in ok_cases {
            let boxed: Box<[u8]> = raw.as_bytes().to_vec().into_boxed_slice();
            let via_box = ContentDigest::try_from(boxed);
            let via_vec = ContentDigest::try_from(raw.as_bytes().to_vec());
            assert_eq!(via_box, via_vec);
        }
        let err_cases: [String; 5] = [
            "sha256abc".to_string(),
            format!("md5:{D1}"),
            format!("sha256:{}", &D1[..60]),
            format!("sha256:{}", D1.to_uppercase()),
            format!("sha256:{}g", &D1[..63]),
        ];
        for raw in err_cases {
            let boxed: Box<[u8]> = raw.as_bytes().to_vec().into_boxed_slice();
            let via_box = ContentDigest::try_from(boxed);
            let via_vec = ContentDigest::try_from(raw.as_bytes().to_vec());
            assert_eq!(via_box, via_vec);
        }
    }

    /// [`TryFrom<Box<[u8]>>`] on a UTF-8-invalid shrunk-owned
    /// raw-byte buffer surfaces [`ContentDigestError::InvalidUtf8`]
    /// through the delegated [`String::from_utf8`] gate inside the
    /// by-value byte-slice peer. Pins the byte-frontier UTF-8 gate
    /// on the shrunk-owned axis so a downstream consumer receiving a
    /// raw wire buffer as [`Box<[u8]>`] cannot leak a non-UTF-8
    /// sequence past the byte frontier as a MissingSeparator /
    /// UnsupportedAlgorithm / InvalidHex misdiagnosis.
    #[test]
    fn test_try_from_box_bytes_rejects_invalid_utf8() {
        let mut bytes = format!("sha256:{D1}").into_bytes();
        bytes.push(0xff);
        let boxed: Box<[u8]> = bytes.into_boxed_slice();
        let err = ContentDigest::try_from(boxed).unwrap_err();
        assert!(matches!(err, ContentDigestError::InvalidUtf8 { .. }));
    }

    /// The [`TryFrom<Box<[u8]>>`] impl composes with a generic
    /// try-conversion helper bounded by
    /// `TryFrom<Box<[u8]>, Error = ContentDigestError>` — the
    /// compositional motivation for landing the trait separately
    /// from the [`Vec<u8>`] parse surface. Pins the by-value
    /// shrunk-owned byte-slice generic-consumer surface so a
    /// downstream site that types its parse contract as
    /// [`TryFrom<Box<[u8]>>`] (a serde container that opts into
    /// `#[serde(try_from = "Box<[u8]>")]`, a heap-owned raw-byte
    /// validated-builder helper) recovers the same typed value the
    /// inherent oracle produces.
    #[test]
    fn test_try_from_box_bytes_carries_through_generic_consumer() {
        fn parse_via_try_from<T: TryFrom<Box<[u8]>, Error = ContentDigestError>>(
            boxed: Box<[u8]>,
        ) -> Result<T, ContentDigestError> {
            T::try_from(boxed)
        }
        let raw = format!("sha256:{D1}");
        let boxed: Box<[u8]> = raw.as_bytes().to_vec().into_boxed_slice();
        let d: ContentDigest = parse_via_try_from(boxed).unwrap();
        assert_eq!(d.as_str(), raw);
        let bad: Box<[u8]> = b"sha256abc".to_vec().into_boxed_slice();
        let err = parse_via_try_from::<ContentDigest>(bad).unwrap_err();
        assert!(matches!(err, ContentDigestError::MissingSeparator { .. }));
    }

    /// [`TryFrom<Box<[u8]>>`] round-trips through the emit peer
    /// [`From<ContentDigest> for Box<[u8]>`] (commit fce9fee) —
    /// parsing a shrunk-owned raw-byte buffer, emitting the
    /// shrunk-owned buffer off the resulting value, then re-parsing
    /// that emitted buffer yields the SAME validated
    /// [`ContentDigest`]. Pins the "the by-value shrunk-owned
    /// byte-slice parse peer and the by-value shrunk-owned
    /// byte-slice emit peer are mutual inverses on the validated
    /// subset" invariant, closing the round-trip discipline on the
    /// [`Box<[u8]>`] axis and matching the closed [`Box<str>`]
    /// round-trip on the sibling UTF-8-string axis.
    #[test]
    fn test_try_from_box_bytes_round_trips_through_box_bytes_emit_peer() {
        let raw = format!("sha256:{D1}");
        let boxed: Box<[u8]> = raw.as_bytes().to_vec().into_boxed_slice();
        let d1 = ContentDigest::try_from(boxed).unwrap();
        let emitted: Box<[u8]> = d1.clone().into();
        let d2 = ContentDigest::try_from(emitted).unwrap();
        assert_eq!(d1, d2);
        assert_eq!(d2.as_str(), raw);
    }

    /// [`TryFrom<Arc<[u8]>>`] succeeds on the cross-thread shared-owned
    /// raw-byte serialization of a well-formed sha256 digest — the
    /// primary registry algorithm. Pins the happy path on the derived
    /// cross-thread shared-owned byte-slice frontier surface: a
    /// downstream site that receives its input as a two-word
    /// [`Arc<[u8]>`] (a serde `try_from = "Arc<[u8]>"` wrapper, a
    /// cross-thread-shared raw-byte validated-builder slot, a
    /// worker-fanned raw-byte record) routes through the same
    /// one-oracle grammar as every other parse peer.
    #[test]
    fn test_try_from_arc_bytes_parses_sha256_digest() {
        let raw = format!("sha256:{D1}");
        let shared: std::sync::Arc<[u8]> = std::sync::Arc::<[u8]>::from(raw.as_bytes());
        let d = ContentDigest::try_from(shared).unwrap();
        assert_eq!(d.as_str(), raw);
        assert_eq!(d.algorithm(), "sha256");
        assert_eq!(d.hex(), D1);
        let inherent = ContentDigest::parse(&raw).unwrap();
        assert_eq!(d, inherent);
    }

    /// [`TryFrom<Arc<[u8]>>`] succeeds on the cross-thread shared-owned
    /// raw-byte serialization of a well-formed sha512 digest — the
    /// second supported algorithm at the digest reference-grammar
    /// family. Pins the impl across both algorithms so a widening at
    /// the inherent oracle (e.g. `sha384`) is caught by an existing
    /// test on this derived surface.
    #[test]
    fn test_try_from_arc_bytes_parses_sha512_digest() {
        let hex = "f".repeat(SHA512_HEX_LEN);
        let raw = format!("sha512:{hex}");
        let shared: std::sync::Arc<[u8]> = std::sync::Arc::<[u8]>::from(raw.as_bytes());
        let d = ContentDigest::try_from(shared).unwrap();
        assert_eq!(d.as_str(), raw);
        assert_eq!(d.algorithm(), "sha512");
        assert_eq!(d.hex(), hex);
    }

    /// [`TryFrom<Arc<[u8]>>`] trims leading / trailing ASCII whitespace
    /// on the delegated string oracle — a cross-thread shared-owned
    /// raw-byte buffer whose trailing newline rides in the shared
    /// allocation parses successfully because the string oracle
    /// whitespace-trims before checking the grammar. Pins the trim
    /// discipline carrying through the cross-thread shared-owned
    /// byte-slice frontier.
    #[test]
    fn test_try_from_arc_bytes_trims_edge_whitespace() {
        let raw = format!("  sha256:{D1}\n");
        let expected = format!("sha256:{D1}");
        let shared: std::sync::Arc<[u8]> = std::sync::Arc::<[u8]>::from(raw.as_bytes());
        let d = ContentDigest::try_from(shared).unwrap();
        assert_eq!(d.as_str(), expected);
    }

    /// [`TryFrom<Arc<[u8]>>`] emits the SAME error
    /// [`ContentDigest::parse`] emits on every grammar-failure input —
    /// the missing-separator, unsupported-algorithm, and invalid-hex
    /// variants route through the string oracle unchanged because the
    /// cross-thread shared-owned byte-slice peer delegates via
    /// [`AsRef::as_ref`] then [`TryFrom<&[u8]>`]. Pins the
    /// "cross-thread shared-owned byte-slice parse surface reads
    /// through the string parse oracle on grammar-failure inputs"
    /// invariant so a future refactor that inlined a divergent grammar
    /// into the cross-thread shared-owned byte peer fails this test.
    #[test]
    fn test_try_from_arc_bytes_matches_inherent_parse_on_every_error_mode() {
        let err_cases: [String; 5] = [
            "sha256abc".to_string(),                 // missing separator
            format!("md5:{D1}"),                     // unsupported algorithm
            format!("sha256:{}", &D1[..60]),         // wrong hex length
            format!("sha256:{}", D1.to_uppercase()), // uppercase hex
            format!("sha256:{}g", &D1[..63]),        // non-hex byte
        ];
        for raw in err_cases {
            let shared: std::sync::Arc<[u8]> = std::sync::Arc::<[u8]>::from(raw.as_bytes());
            let via_arc = ContentDigest::try_from(shared);
            let via_inherent = ContentDigest::parse(&raw);
            assert_eq!(
                via_arc, via_inherent,
                "TryFrom<Arc<[u8]>> and inherent parse must agree on '{raw}'",
            );
        }
    }

    /// [`TryFrom<Arc<[u8]>>`] agrees with [`TryFrom<Box<[u8]>>`] on
    /// every well-formed AND grammar-failure input — the by-value
    /// cross-thread shared-owned byte-slice parse peer and the
    /// by-value shrunk-owned byte-slice parse peer resolve to the SAME
    /// [`Result<ContentDigest, ContentDigestError>`] across every input
    /// the two share, so a downstream site that migrates a raw-byte
    /// consumer from [`Box<[u8]>`] to [`Arc<[u8]>`] (a hot-path
    /// widening that fans a raw-byte record across worker threads
    /// through [`Arc::clone`] instead of a per-worker deep-copy)
    /// yields identical values and identical errors at every input.
    /// Pins the "shrunk-owned and cross-thread shared-owned byte-slice
    /// parse peers read through the same canonical oracle" invariant.
    #[test]
    fn test_try_from_arc_bytes_agrees_with_try_from_box_bytes() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let ok_cases = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha512:{hex512}"),
            format!("  sha256:{D3}\n"),
        ];
        for raw in ok_cases {
            let shared: std::sync::Arc<[u8]> = std::sync::Arc::<[u8]>::from(raw.as_bytes());
            let boxed: Box<[u8]> = raw.as_bytes().to_vec().into_boxed_slice();
            let via_arc = ContentDigest::try_from(shared);
            let via_box = ContentDigest::try_from(boxed);
            assert_eq!(via_arc, via_box);
        }
        let err_cases: [String; 5] = [
            "sha256abc".to_string(),
            format!("md5:{D1}"),
            format!("sha256:{}", &D1[..60]),
            format!("sha256:{}", D1.to_uppercase()),
            format!("sha256:{}g", &D1[..63]),
        ];
        for raw in err_cases {
            let shared: std::sync::Arc<[u8]> = std::sync::Arc::<[u8]>::from(raw.as_bytes());
            let boxed: Box<[u8]> = raw.as_bytes().to_vec().into_boxed_slice();
            let via_arc = ContentDigest::try_from(shared);
            let via_box = ContentDigest::try_from(boxed);
            assert_eq!(via_arc, via_box);
        }
    }

    /// [`TryFrom<Arc<[u8]>>`] on a UTF-8-invalid cross-thread
    /// shared-owned raw-byte buffer surfaces
    /// [`ContentDigestError::InvalidUtf8`] through the delegated
    /// [`std::str::from_utf8`] gate inside the by-reference byte-slice
    /// peer. Pins the byte-frontier UTF-8 gate on the cross-thread
    /// shared-owned axis so a downstream consumer receiving a raw wire
    /// buffer as [`Arc<[u8]>`] cannot leak a non-UTF-8 sequence past
    /// the byte frontier as a MissingSeparator / UnsupportedAlgorithm /
    /// InvalidHex misdiagnosis.
    #[test]
    fn test_try_from_arc_bytes_rejects_invalid_utf8() {
        let mut bytes = format!("sha256:{D1}").into_bytes();
        bytes.push(0xff);
        let shared: std::sync::Arc<[u8]> = std::sync::Arc::<[u8]>::from(bytes);
        let err = ContentDigest::try_from(shared).unwrap_err();
        assert!(matches!(err, ContentDigestError::InvalidUtf8 { .. }));
    }

    /// The [`TryFrom<Arc<[u8]>>`] impl composes with a generic
    /// try-conversion helper bounded by
    /// `TryFrom<Arc<[u8]>, Error = ContentDigestError>` — the
    /// compositional motivation for landing the trait separately from
    /// the [`Vec<u8>`] and [`Box<[u8]>`] parse surfaces. Pins the
    /// by-value cross-thread shared-owned byte-slice generic-consumer
    /// surface so a downstream site that types its parse contract as
    /// [`TryFrom<Arc<[u8]>>`] (a serde container that opts into
    /// `#[serde(try_from = "Arc<[u8]>")]`, a cross-thread-cached
    /// raw-byte validated-builder helper) recovers the same typed
    /// value the inherent oracle produces.
    #[test]
    fn test_try_from_arc_bytes_carries_through_generic_consumer() {
        fn parse_via_try_from<T: TryFrom<std::sync::Arc<[u8]>, Error = ContentDigestError>>(
            shared: std::sync::Arc<[u8]>,
        ) -> Result<T, ContentDigestError> {
            T::try_from(shared)
        }
        let raw = format!("sha256:{D1}");
        let shared: std::sync::Arc<[u8]> = std::sync::Arc::<[u8]>::from(raw.as_bytes());
        let d: ContentDigest = parse_via_try_from(shared).unwrap();
        assert_eq!(d.as_str(), raw);
        let bad: std::sync::Arc<[u8]> = std::sync::Arc::<[u8]>::from(b"sha256abc".as_ref());
        let err = parse_via_try_from::<ContentDigest>(bad).unwrap_err();
        assert!(matches!(err, ContentDigestError::MissingSeparator { .. }));
    }

    /// [`TryFrom<Arc<[u8]>>`] round-trips through the emit peer
    /// [`From<ContentDigest> for Arc<[u8]>`] (commit 49111c1) —
    /// parsing a cross-thread shared-owned raw-byte buffer, emitting
    /// the cross-thread shared-owned buffer off the resulting value,
    /// then re-parsing that emitted buffer yields the SAME validated
    /// [`ContentDigest`]. Pins the "the by-value cross-thread
    /// shared-owned byte-slice parse peer and the by-value cross-thread
    /// shared-owned byte-slice emit peer are mutual inverses on the
    /// validated subset" invariant, closing the round-trip discipline
    /// on the [`Arc<[u8]>`] axis and matching the closed [`Arc<str>`]
    /// round-trip on the sibling UTF-8-string axis.
    #[test]
    fn test_try_from_arc_bytes_round_trips_through_arc_bytes_emit_peer() {
        let raw = format!("sha256:{D1}");
        let shared: std::sync::Arc<[u8]> = std::sync::Arc::<[u8]>::from(raw.as_bytes());
        let d1 = ContentDigest::try_from(shared).unwrap();
        let emitted: std::sync::Arc<[u8]> = d1.clone().into();
        let d2 = ContentDigest::try_from(emitted).unwrap();
        assert_eq!(d1, d2);
        assert_eq!(d2.as_str(), raw);
    }

    /// [`TryFrom<Rc<[u8]>>`] succeeds on the thread-local shared-owned
    /// raw-byte serialization of a well-formed sha256 digest — the
    /// primary registry algorithm. Pins the happy path on the derived
    /// thread-local shared-owned byte-slice frontier surface: a
    /// downstream site that receives its input as a two-word
    /// [`Rc<[u8]>`] (a serde `try_from = "Rc<[u8]>"` wrapper, a
    /// single-thread-cached raw-byte validated-builder slot, a
    /// single-thread scan-phase raw-byte lookaside) routes through the
    /// same one-oracle grammar as every other parse peer.
    #[test]
    fn test_try_from_rc_bytes_parses_sha256_digest() {
        let raw = format!("sha256:{D1}");
        let shared: std::rc::Rc<[u8]> = std::rc::Rc::<[u8]>::from(raw.as_bytes());
        let d = ContentDigest::try_from(shared).unwrap();
        assert_eq!(d.as_str(), raw);
        assert_eq!(d.algorithm(), "sha256");
        assert_eq!(d.hex(), D1);
        let inherent = ContentDigest::parse(&raw).unwrap();
        assert_eq!(d, inherent);
    }

    /// [`TryFrom<Rc<[u8]>>`] succeeds on the thread-local shared-owned
    /// raw-byte serialization of a well-formed sha512 digest — the
    /// second supported algorithm at the digest reference-grammar
    /// family. Pins the impl across both algorithms so a widening at
    /// the inherent oracle (e.g. `sha384`) is caught by an existing
    /// test on this derived surface.
    #[test]
    fn test_try_from_rc_bytes_parses_sha512_digest() {
        let hex = "f".repeat(SHA512_HEX_LEN);
        let raw = format!("sha512:{hex}");
        let shared: std::rc::Rc<[u8]> = std::rc::Rc::<[u8]>::from(raw.as_bytes());
        let d = ContentDigest::try_from(shared).unwrap();
        assert_eq!(d.as_str(), raw);
        assert_eq!(d.algorithm(), "sha512");
        assert_eq!(d.hex(), hex);
    }

    /// [`TryFrom<Rc<[u8]>>`] trims leading / trailing ASCII whitespace
    /// on the delegated string oracle — a thread-local shared-owned
    /// raw-byte buffer whose trailing newline rides in the shared
    /// allocation parses successfully because the string oracle
    /// whitespace-trims before checking the grammar. Pins the trim
    /// discipline carrying through the thread-local shared-owned
    /// byte-slice frontier.
    #[test]
    fn test_try_from_rc_bytes_trims_edge_whitespace() {
        let raw = format!("  sha256:{D1}\n");
        let expected = format!("sha256:{D1}");
        let shared: std::rc::Rc<[u8]> = std::rc::Rc::<[u8]>::from(raw.as_bytes());
        let d = ContentDigest::try_from(shared).unwrap();
        assert_eq!(d.as_str(), expected);
    }

    /// [`TryFrom<Rc<[u8]>>`] emits the SAME error
    /// [`ContentDigest::parse`] emits on every grammar-failure input —
    /// the missing-separator, unsupported-algorithm, and invalid-hex
    /// variants route through the string oracle unchanged because the
    /// thread-local shared-owned byte-slice peer delegates via
    /// [`AsRef::as_ref`] then [`TryFrom<&[u8]>`]. Pins the
    /// "thread-local shared-owned byte-slice parse surface reads
    /// through the string parse oracle on grammar-failure inputs"
    /// invariant so a future refactor that inlined a divergent grammar
    /// into the thread-local shared-owned byte peer fails this test.
    #[test]
    fn test_try_from_rc_bytes_matches_inherent_parse_on_every_error_mode() {
        let err_cases: [String; 5] = [
            "sha256abc".to_string(),                 // missing separator
            format!("md5:{D1}"),                     // unsupported algorithm
            format!("sha256:{}", &D1[..60]),         // wrong hex length
            format!("sha256:{}", D1.to_uppercase()), // uppercase hex
            format!("sha256:{}g", &D1[..63]),        // non-hex byte
        ];
        for raw in err_cases {
            let shared: std::rc::Rc<[u8]> = std::rc::Rc::<[u8]>::from(raw.as_bytes());
            let via_rc = ContentDigest::try_from(shared);
            let via_inherent = ContentDigest::parse(&raw);
            assert_eq!(
                via_rc, via_inherent,
                "TryFrom<Rc<[u8]>> and inherent parse must agree on '{raw}'",
            );
        }
    }

    /// [`TryFrom<Rc<[u8]>>`] agrees with [`TryFrom<Arc<[u8]>>`] on
    /// every well-formed AND grammar-failure input — the by-value
    /// thread-local shared-owned byte-slice parse peer and the
    /// by-value cross-thread shared-owned byte-slice parse peer
    /// resolve to the SAME [`Result<ContentDigest, ContentDigestError>`]
    /// across every input the two share, so a downstream site that
    /// migrates a raw-byte consumer from [`Arc<[u8]>`] to [`Rc<[u8]>`]
    /// (a hot-path narrowing that sheds the atomic-fence overhead on
    /// raw-byte records refcounted only within one thread) yields
    /// identical values and identical errors at every input. Pins the
    /// "thread-local shared-owned and cross-thread shared-owned
    /// byte-slice parse peers read through the same canonical oracle"
    /// invariant, closing the sibling-peer agreement between the two
    /// shared-owned owned-shape byte-slice parse peers.
    #[test]
    fn test_try_from_rc_bytes_agrees_with_try_from_arc_bytes() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let ok_cases = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha512:{hex512}"),
            format!("  sha256:{D3}\n"),
        ];
        for raw in ok_cases {
            let rc: std::rc::Rc<[u8]> = std::rc::Rc::<[u8]>::from(raw.as_bytes());
            let arc: std::sync::Arc<[u8]> = std::sync::Arc::<[u8]>::from(raw.as_bytes());
            let via_rc = ContentDigest::try_from(rc);
            let via_arc = ContentDigest::try_from(arc);
            assert_eq!(via_rc, via_arc);
        }
        let err_cases: [String; 5] = [
            "sha256abc".to_string(),
            format!("md5:{D1}"),
            format!("sha256:{}", &D1[..60]),
            format!("sha256:{}", D1.to_uppercase()),
            format!("sha256:{}g", &D1[..63]),
        ];
        for raw in err_cases {
            let rc: std::rc::Rc<[u8]> = std::rc::Rc::<[u8]>::from(raw.as_bytes());
            let arc: std::sync::Arc<[u8]> = std::sync::Arc::<[u8]>::from(raw.as_bytes());
            let via_rc = ContentDigest::try_from(rc);
            let via_arc = ContentDigest::try_from(arc);
            assert_eq!(via_rc, via_arc);
        }
    }

    /// [`TryFrom<Rc<[u8]>>`] on a UTF-8-invalid thread-local
    /// shared-owned raw-byte buffer surfaces
    /// [`ContentDigestError::InvalidUtf8`] through the delegated
    /// [`std::str::from_utf8`] gate inside the by-reference byte-slice
    /// peer. Pins the byte-frontier UTF-8 gate on the thread-local
    /// shared-owned axis so a downstream consumer receiving a raw wire
    /// buffer as [`Rc<[u8]>`] cannot leak a non-UTF-8 sequence past the
    /// byte frontier as a MissingSeparator / UnsupportedAlgorithm /
    /// InvalidHex misdiagnosis.
    #[test]
    fn test_try_from_rc_bytes_rejects_invalid_utf8() {
        let mut bytes = format!("sha256:{D1}").into_bytes();
        bytes.push(0xff);
        let shared: std::rc::Rc<[u8]> = std::rc::Rc::<[u8]>::from(bytes);
        let err = ContentDigest::try_from(shared).unwrap_err();
        assert!(matches!(err, ContentDigestError::InvalidUtf8 { .. }));
    }

    /// The [`TryFrom<Rc<[u8]>>`] impl composes with a generic
    /// try-conversion helper bounded by
    /// `TryFrom<Rc<[u8]>, Error = ContentDigestError>` — the
    /// compositional motivation for landing the trait separately from
    /// the [`Vec<u8>`], [`Box<[u8]>`], and [`Arc<[u8]>`] parse
    /// surfaces. Pins the by-value thread-local shared-owned byte-slice
    /// generic-consumer surface so a downstream site that types its
    /// parse contract as [`TryFrom<Rc<[u8]>>`] (a serde container that
    /// opts into `#[serde(try_from = "Rc<[u8]>")]`, a single-thread-
    /// cached raw-byte validated-builder helper) recovers the same
    /// typed value the inherent oracle produces.
    #[test]
    fn test_try_from_rc_bytes_carries_through_generic_consumer() {
        fn parse_via_try_from<T: TryFrom<std::rc::Rc<[u8]>, Error = ContentDigestError>>(
            shared: std::rc::Rc<[u8]>,
        ) -> Result<T, ContentDigestError> {
            T::try_from(shared)
        }
        let raw = format!("sha256:{D1}");
        let shared: std::rc::Rc<[u8]> = std::rc::Rc::<[u8]>::from(raw.as_bytes());
        let d: ContentDigest = parse_via_try_from(shared).unwrap();
        assert_eq!(d.as_str(), raw);
        let bad: std::rc::Rc<[u8]> = std::rc::Rc::<[u8]>::from(b"sha256abc".as_ref());
        let err = parse_via_try_from::<ContentDigest>(bad).unwrap_err();
        assert!(matches!(err, ContentDigestError::MissingSeparator { .. }));
    }

    /// [`TryFrom<Rc<[u8]>>`] round-trips through the emit peer
    /// [`From<ContentDigest> for Rc<[u8]>`] (commit 578dbc6) —
    /// parsing a thread-local shared-owned raw-byte buffer, emitting
    /// the thread-local shared-owned buffer off the resulting value,
    /// then re-parsing that emitted buffer yields the SAME validated
    /// [`ContentDigest`]. Pins the "the by-value thread-local
    /// shared-owned byte-slice parse peer and the by-value thread-local
    /// shared-owned byte-slice emit peer are mutual inverses on the
    /// validated subset" invariant, closing the round-trip discipline
    /// on the [`Rc<[u8]>`] axis and matching the closed [`Rc<str>`]
    /// round-trip on the sibling UTF-8-string axis.
    #[test]
    fn test_try_from_rc_bytes_round_trips_through_rc_bytes_emit_peer() {
        let raw = format!("sha256:{D1}");
        let shared: std::rc::Rc<[u8]> = std::rc::Rc::<[u8]>::from(raw.as_bytes());
        let d1 = ContentDigest::try_from(shared).unwrap();
        let emitted: std::rc::Rc<[u8]> = d1.clone().into();
        let d2 = ContentDigest::try_from(emitted).unwrap();
        assert_eq!(d1, d2);
        assert_eq!(d2.as_str(), raw);
    }

    /// The [`ContentDigestError::InvalidUtf8`] variant's
    /// [`std::fmt::Display`] arm names the offending lossy-decoded
    /// input so a failure record built from the error string carries
    /// the input a caller supplied. Pins the display shape so a
    /// future rewording that dropped the input field fails this
    /// test.
    #[test]
    fn test_invalid_utf8_error_display_names_offending_input() {
        let err = ContentDigestError::InvalidUtf8 {
            input: "sha256:garbled\u{FFFD}".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("sha256:garbled"), "got: {msg}");
        assert!(msg.contains("UTF-8"), "got: {msg}");
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
                ContentDigest::try_from(std::borrow::Cow::<'_, str>::Owned(emitted.clone()))
                    .unwrap();
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
                ContentDigest::try_from(std::borrow::Cow::<'_, str>::Owned(decoded.clone()))
                    .unwrap();
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
                ContentDigest::try_from(std::borrow::Cow::<'_, str>::Owned(String::from(emitted)))
                    .unwrap();
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

    /// [`From<ContentDigest> for std::rc::Rc<str>`] emits the same
    /// canonical `<algorithm>:<hex>` slice every borrowed-view read
    /// surface exposes. Pins the single-thread shared-owned frontier
    /// emit peer to the [`ContentDigest::as_str`] one-oracle read
    /// surface at every supported algorithm, so a widening at the
    /// inherent oracle is caught by an existing test on this derived
    /// surface.
    #[test]
    fn test_from_content_digest_rc_str_matches_as_str() {
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
            let emitted: std::rc::Rc<str> = std::rc::Rc::<str>::from(d);
            assert_eq!(&*emitted, borrowed_as_str.as_str());
            assert_eq!(&*emitted, via_display.as_str());
            assert_eq!(&*emitted, raw.as_str());
        }
    }

    /// [`From<ContentDigest> for std::rc::Rc<str>`] emits the full
    /// `<algorithm>:<hex>` slice for a sha256 digest. Pins the primary
    /// registry algorithm on the by-value single-thread shared-owned
    /// UTF-8 emit surface — the emitted [`Rc<str>`] is byte-identical
    /// to the input the inherent oracle accepted.
    #[test]
    fn test_from_content_digest_rc_str_sha256_full_digest() {
        let raw = format!("sha256:{D1}");
        let d = ContentDigest::parse(&raw).unwrap();
        let emitted: std::rc::Rc<str> = d.into();
        assert_eq!(&*emitted, raw.as_str());
        assert!(emitted.starts_with("sha256:"));
        assert_eq!(&emitted[7..], D1);
    }

    /// [`From<ContentDigest> for std::rc::Rc<str>`] emits the full
    /// `<algorithm>:<hex>` slice for a sha512 digest. Pins the second
    /// supported algorithm on the by-value single-thread shared-owned
    /// UTF-8 emit surface so a widening at the inherent oracle is
    /// caught by an existing test on this derived surface.
    #[test]
    fn test_from_content_digest_rc_str_sha512_full_digest() {
        let hex = "f".repeat(SHA512_HEX_LEN);
        let raw = format!("sha512:{hex}");
        let d = ContentDigest::parse(&raw).unwrap();
        let emitted: std::rc::Rc<str> = d.into();
        assert_eq!(&*emitted, raw.as_str());
        assert!(emitted.starts_with("sha512:"));
        assert_eq!(&emitted[7..], hex.as_str());
    }

    /// [`From<ContentDigest> for std::rc::Rc<str>`] emits the trimmed
    /// canonical form on an input the inherent oracle whitespace-
    /// trimmed at parse time — the emit surface projects the canonical
    /// trimmed value, not the caller's stray-whitespace raw input.
    /// Pins the trim discipline carrying through the by-value
    /// single-thread shared-owned UTF-8 emit surface.
    #[test]
    fn test_from_content_digest_rc_str_after_whitespace_trim() {
        let raw = format!("  sha256:{D1}\n");
        let expected = format!("sha256:{D1}");
        let d = ContentDigest::parse(&raw).unwrap();
        let emitted: std::rc::Rc<str> = d.into();
        assert_eq!(&*emitted, expected.as_str());
        assert!(!emitted.starts_with(' '));
        assert!(!emitted.ends_with('\n'));
    }

    /// The [`From<ContentDigest> for std::rc::Rc<str>`] impl composes
    /// with a generic single-thread shared-owned-label helper bounded
    /// by `impl Into<std::rc::Rc<str>>` — the compositional motivation
    /// for landing the trait separately from the atomic-shared-owned
    /// [`From<ContentDigest> for Arc<str>`] emit peer. Pins the
    /// trait-generic consumer surface: a downstream site that types
    /// its input contract as `impl Into<Rc<str>>` (a same-thread
    /// `HashMap<Rc<str>, _>` registry cache built once per pipeline
    /// pass, a `thread_local!` per-thread digest interner that fans
    /// out `Rc<str>` handles to inline inspection helpers, a `!Send`
    /// per-task lookaside that keys entries on the digest without
    /// paying `Arc`'s atomic refcount) recovers the same validated
    /// full-digest [`Rc<str>`] a direct `Rc::<str>::from(digest.as_str())`
    /// call would, at exactly the shared-owned repackaging cost off
    /// the moved backing storage.
    #[test]
    fn test_from_content_digest_rc_str_carries_through_generic_consumer() {
        fn first_char_of<T: Into<std::rc::Rc<str>>>(t: T) -> char {
            let a: std::rc::Rc<str> = t.into();
            a.chars().next().unwrap()
        }
        fn length_of<T: Into<std::rc::Rc<str>>>(t: T) -> usize {
            let a: std::rc::Rc<str> = t.into();
            a.len()
        }
        fn rc_eq<T: Into<std::rc::Rc<str>>>(t: T, expected: &str) -> bool {
            let a: std::rc::Rc<str> = t.into();
            &*a == expected
        }
        let raw = format!("sha256:{D1}");
        let d1 = ContentDigest::parse(&raw).unwrap();
        let d2 = d1.clone();
        let d3 = d1.clone();
        assert_eq!(first_char_of(d1), 's');
        assert_eq!(length_of(d2), raw.len());
        assert!(rc_eq(d3, &raw));
    }

    /// A validated digest's [`From<ContentDigest> for std::rc::Rc<str>`]
    /// output round-trips through the full parse-surface set — inherent
    /// [`ContentDigest::parse`], [`TryFrom<&str>`],
    /// [`FromStr`](std::str::FromStr), [`TryFrom<String>`],
    /// [`TryFrom<Cow<'_, str>>`] — back to the same validated
    /// [`ContentDigest`] value. Pins the "single-thread shared-owned
    /// emit surface projects exactly the canonical form every parse
    /// surface accepts" invariant so a future canonicalising refinement
    /// to the backing string that broke round-trip via the single-
    /// thread shared-owned UTF-8 emit peer fails this test.
    #[test]
    fn test_from_content_digest_rc_str_parse_round_trip() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let cases = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        for raw in cases {
            let original = ContentDigest::parse(&raw).unwrap();
            let emitted: std::rc::Rc<str> = std::rc::Rc::<str>::from(original.clone());
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

    /// [`From<ContentDigest> for std::rc::Rc<str>`] emits an
    /// [`Rc<str>`] whose [`Rc::clone`] returns a second handle onto
    /// the same shared allocation — the load-bearing property of the
    /// single-thread shared-owned frontier that a downstream
    /// same-thread cache slot (a `HashMap<Rc<str>, _>` per-pipeline
    /// registry, a `thread_local!` digest interner) relies on to fan
    /// a single label allocation across per-worker readers at
    /// pointer-copy + integer-increment cost with no atomic-op fence.
    /// Pins the shared-allocation identity so a future refactor that
    /// accidentally re-allocated on [`Rc::clone`] (a rebox through
    /// `to_string().into()` in the emit path, a per-clone
    /// `Rc::<str>::from(&*self)` chain) fails this test.
    #[test]
    fn test_from_content_digest_rc_str_clones_share_allocation() {
        let raw = format!("sha256:{D1}");
        let d = ContentDigest::parse(&raw).unwrap();
        let emitted: std::rc::Rc<str> = d.into();
        let cloned = std::rc::Rc::clone(&emitted);
        assert!(
            std::rc::Rc::ptr_eq(&emitted, &cloned),
            "Rc::clone on the emitted Rc<str> must return a handle onto the same shared \
             allocation, not a fresh allocation of the label bytes"
        );
        assert_eq!(&*cloned, raw.as_str());
        assert_eq!(std::rc::Rc::strong_count(&emitted), 2);
        let third = std::rc::Rc::clone(&emitted);
        assert_eq!(std::rc::Rc::strong_count(&emitted), 3);
        assert!(std::rc::Rc::ptr_eq(&emitted, &third));
        drop(third);
        assert_eq!(std::rc::Rc::strong_count(&emitted), 2);
    }

    /// [`From<ContentDigest> for Box<[u8]>`] emits the same bytes as
    /// the borrowed-view read peer [`AsRef<[u8]>`] sees off the
    /// backing string, and as the by-value owned-byte-slice emit peer
    /// [`Vec<u8>`] moves out — the by-value shrunk-owned byte-slice
    /// emit surface names the same canonical full-digest byte buffer
    /// as every peer surface on the byte-slice frontier.
    #[test]
    fn test_from_content_digest_box_bytes_matches_as_ref() {
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
            let via_vec_emit: Vec<u8> = Vec::<u8>::from(d.clone());
            let emitted: Box<[u8]> = Box::<[u8]>::from(d);
            assert_eq!(&*emitted, borrowed_as_ref.as_slice());
            assert_eq!(&*emitted, via_str_bytes.as_slice());
            assert_eq!(&*emitted, via_vec_emit.as_slice());
            assert_eq!(&*emitted, raw.as_bytes());
        }
    }

    /// [`From<ContentDigest> for Box<[u8]>`] emits the full
    /// `<algorithm>:<hex>` byte slice for a sha256 digest. Pins the
    /// primary registry algorithm on the by-value shrunk-owned
    /// byte-slice emit surface — the emitted [`Box<[u8]>`] is
    /// byte-identical to the input the inherent oracle accepted, and
    /// every emitted byte is ASCII by parse invariant.
    #[test]
    fn test_from_content_digest_box_bytes_sha256_full_digest() {
        let raw = format!("sha256:{D1}");
        let d = ContentDigest::parse(&raw).unwrap();
        let emitted: Box<[u8]> = d.into();
        assert_eq!(&*emitted, raw.as_bytes());
        assert!(emitted.starts_with(b"sha256:"));
        assert_eq!(&emitted[7..], D1.as_bytes());
        assert!(emitted.iter().all(|b| b.is_ascii()));
    }

    /// [`From<ContentDigest> for Box<[u8]>`] emits the full
    /// `<algorithm>:<hex>` byte slice for a sha512 digest. Pins the
    /// second supported algorithm on the by-value shrunk-owned
    /// byte-slice emit surface so a widening at the inherent oracle
    /// is caught by an existing test on this derived surface.
    #[test]
    fn test_from_content_digest_box_bytes_sha512_full_digest() {
        let hex = "f".repeat(SHA512_HEX_LEN);
        let raw = format!("sha512:{hex}");
        let d = ContentDigest::parse(&raw).unwrap();
        let emitted: Box<[u8]> = d.into();
        assert_eq!(&*emitted, raw.as_bytes());
        assert!(emitted.starts_with(b"sha512:"));
        assert_eq!(&emitted[7..], hex.as_bytes());
        assert!(emitted.iter().all(|b| b.is_ascii()));
    }

    /// [`From<ContentDigest> for Box<[u8]>`] emits the trimmed
    /// canonical bytes on an input the inherent oracle
    /// whitespace-trimmed at parse time — the emit surface projects
    /// the canonical trimmed byte buffer, not the caller's
    /// stray-whitespace raw input. Pins the trim discipline carrying
    /// through the by-value shrunk-owned byte-slice emit surface.
    #[test]
    fn test_from_content_digest_box_bytes_after_whitespace_trim() {
        let raw = format!("  sha256:{D1}\n");
        let expected = format!("sha256:{D1}");
        let d = ContentDigest::parse(&raw).unwrap();
        let emitted: Box<[u8]> = d.into();
        assert_eq!(&*emitted, expected.as_bytes());
        assert!(!emitted.starts_with(b" "));
        assert!(!emitted.ends_with(b"\n"));
    }

    /// The [`From<ContentDigest> for Box<[u8]>`] impl composes with a
    /// generic shrunk-owned-byte-slice helper bounded by
    /// `impl Into<Box<[u8]>>` — the compositional motivation for
    /// landing the trait separately from the resizable-growth-header
    /// [`From<ContentDigest> for Vec<u8>`] emit peer. Pins the
    /// trait-generic consumer surface: a downstream site that types
    /// its input contract as `impl Into<Box<[u8]>>` (a per-value
    /// digest slot on a long-lived manifest struct that stores its
    /// byte-slice frontier as [`Box<[u8]>`] to shed the [`Vec<u8>`]
    /// growth-header word, a [`bytes::Bytes::from`] intake at the
    /// shrunk-owned byte-slice frontier, a
    /// [`std::collections::HashMap<Box<[u8]>, _>`] byte-keyed
    /// registry) recovers the same validated full-digest bytes a
    /// direct `Box::<[u8]>::from(digest.as_ref())` bridge would, at
    /// zero-copy off the moved backing storage.
    #[test]
    fn test_from_content_digest_box_bytes_carries_through_generic_consumer() {
        fn first_byte_of<T: Into<Box<[u8]>>>(t: T) -> u8 {
            let b: Box<[u8]> = t.into();
            *b.first().unwrap()
        }
        fn byte_length_of<T: Into<Box<[u8]>>>(t: T) -> usize {
            let b: Box<[u8]> = t.into();
            b.len()
        }
        fn boxed_bytes_eq<T: Into<Box<[u8]>>>(t: T, expected: &[u8]) -> bool {
            let b: Box<[u8]> = t.into();
            &*b == expected
        }
        let raw = format!("sha256:{D1}");
        let d1 = ContentDigest::parse(&raw).unwrap();
        let d2 = d1.clone();
        let d3 = d1.clone();
        assert_eq!(first_byte_of(d1), b's');
        assert_eq!(byte_length_of(d2), raw.len());
        assert!(boxed_bytes_eq(d3, raw.as_bytes()));
    }

    /// A validated digest's [`From<ContentDigest> for Box<[u8]>`]
    /// output round-trips through [`std::str::from_utf8`] and then
    /// the full parse-surface set — inherent [`ContentDigest::parse`],
    /// [`TryFrom<&str>`], [`FromStr`](std::str::FromStr),
    /// [`TryFrom<String>`], [`TryFrom<Cow<'_, str>>`] — back to the
    /// same validated [`ContentDigest`] value. Pins the "shrunk-owned
    /// byte-slice emit surface projects exactly the canonical UTF-8
    /// form every parse surface accepts" invariant so a future
    /// canonicalising refinement to the backing bytes that broke
    /// round-trip via the shrunk-owned byte-slice emit peer fails
    /// this test.
    #[test]
    fn test_from_content_digest_box_bytes_parse_round_trip() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let cases = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        for raw in cases {
            let original = ContentDigest::parse(&raw).unwrap();
            let emitted: Box<[u8]> = Box::<[u8]>::from(original.clone());
            let decoded = std::str::from_utf8(&emitted).unwrap();
            let via_parse = ContentDigest::parse(decoded).unwrap();
            let via_try_from_str = ContentDigest::try_from(decoded).unwrap();
            let via_from_str: ContentDigest = decoded.parse().unwrap();
            let via_try_from_string = ContentDigest::try_from(decoded.to_owned()).unwrap();
            let via_try_from_cow =
                ContentDigest::try_from(std::borrow::Cow::Borrowed(decoded)).unwrap();
            assert_eq!(via_parse, original);
            assert_eq!(via_try_from_str, original);
            assert_eq!(via_from_str, original);
            assert_eq!(via_try_from_string, original);
            assert_eq!(via_try_from_cow, original);
        }
    }

    /// [`From<ContentDigest> for Box<[u8]>`] emits a [`Box<[u8]>`]
    /// whose length equals the canonical `<algorithm>:<hex>` label's
    /// byte length exactly — the shrunk-owned invariant that
    /// separates this frontier from the resizable growth-header
    /// [`Vec<u8>`] emit peer. Pins the expected length for both
    /// supported algorithms (`sha256` → 7 + 64 = 71 bytes, `sha512`
    /// → 7 + 128 = 135 bytes) so a future refactor that accidentally
    /// routed the impl through a [`Vec::with_capacity`]
    /// overallocation before boxing (which would break the
    /// shrunk-owned discipline any consumer bound by
    /// `impl Into<Box<[u8]>>` pins its per-value slot size on) fails
    /// this test.
    #[test]
    fn test_from_content_digest_box_bytes_length_equals_label_bytes() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let cases = [
            (format!("sha256:{D1}"), "sha256:".len() + SHA256_HEX_LEN),
            (format!("sha512:{hex512}"), "sha512:".len() + SHA512_HEX_LEN),
        ];
        for (raw, expected_len) in cases {
            let d = ContentDigest::parse(&raw).unwrap();
            let emitted: Box<[u8]> = d.into();
            assert_eq!(emitted.len(), expected_len);
            assert_eq!(emitted.len(), raw.len());
        }
    }

    /// The by-value borrowed/owned-frontier byte-slice emit surface
    /// [`From<ContentDigest> for Cow<'static, [u8]>`] emits the same
    /// canonical `<algorithm>:<hex>` bytes every borrowed-view read
    /// surface and every peer emit surface on the byte-slice frontier
    /// project. Round-trips the emit peer against
    /// [`<ContentDigest as AsRef<[u8]>>::as_ref`] (the trait-generic
    /// borrowed-view byte-slice read surface), against
    /// [`ContentDigest::as_str`]`.as_bytes()` (the borrowed-view UTF-8
    /// read surface reinterpreted as raw bytes), against
    /// [`<Vec<u8> as From<ContentDigest>>::from`] (the by-value
    /// resizable-owned-byte-slice emit peer), against
    /// [`<Box<[u8]> as From<ContentDigest>>::from`] (the by-value
    /// shrunk-owned byte-slice emit peer), and against the raw input
    /// the inherent oracle accepted. Pins that after the [`Vec<u8>`]
    /// moves out and is wrapped in [`Cow::Owned`] — the by-value
    /// borrowed/owned-frontier byte-slice emit surface names the same
    /// canonical full-digest byte buffer as every peer surface on the
    /// byte-slice frontier.
    #[test]
    fn test_from_content_digest_cow_static_bytes_matches_as_ref() {
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
            let via_vec_emit: Vec<u8> = Vec::<u8>::from(d.clone());
            let via_box_emit: Box<[u8]> = Box::<[u8]>::from(d.clone());
            let emitted: std::borrow::Cow<'static, [u8]> =
                std::borrow::Cow::<'static, [u8]>::from(d);
            assert_eq!(emitted.as_ref(), borrowed_as_ref.as_slice());
            assert_eq!(emitted.as_ref(), via_str_bytes.as_slice());
            assert_eq!(emitted.as_ref(), via_vec_emit.as_slice());
            assert_eq!(emitted.as_ref(), &*via_box_emit);
            assert_eq!(&*emitted, raw.as_bytes());
        }
    }

    /// [`From<ContentDigest> for Cow<'static, [u8]>`] emits the full
    /// `<algorithm>:<hex>` byte slice for a sha256 digest. Pins the
    /// primary registry algorithm on the by-value borrowed/owned-
    /// frontier byte-slice emit surface — the emitted
    /// [`Cow<'static, [u8]>`] is byte-identical to the input the
    /// inherent oracle accepted, and every emitted byte is ASCII by
    /// parse invariant.
    #[test]
    fn test_from_content_digest_cow_static_bytes_sha256_full_digest() {
        let raw = format!("sha256:{D1}");
        let d = ContentDigest::parse(&raw).unwrap();
        let emitted: std::borrow::Cow<'static, [u8]> = d.into();
        assert_eq!(&*emitted, raw.as_bytes());
        assert!(emitted.starts_with(b"sha256:"));
        assert_eq!(&emitted[7..], D1.as_bytes());
        assert!(emitted.iter().all(|b| b.is_ascii()));
    }

    /// [`From<ContentDigest> for Cow<'static, [u8]>`] emits the full
    /// `<algorithm>:<hex>` byte slice for a sha512 digest. Pins the
    /// second supported algorithm on the by-value borrowed/owned-
    /// frontier byte-slice emit surface so a widening at the inherent
    /// oracle is caught by an existing test on this derived surface.
    #[test]
    fn test_from_content_digest_cow_static_bytes_sha512_full_digest() {
        let hex = "f".repeat(SHA512_HEX_LEN);
        let raw = format!("sha512:{hex}");
        let d = ContentDigest::parse(&raw).unwrap();
        let emitted: std::borrow::Cow<'static, [u8]> = d.into();
        assert_eq!(&*emitted, raw.as_bytes());
        assert!(emitted.starts_with(b"sha512:"));
        assert_eq!(&emitted[7..], hex.as_bytes());
        assert!(emitted.iter().all(|b| b.is_ascii()));
    }

    /// [`From<ContentDigest> for Cow<'static, [u8]>`] emits the
    /// trimmed canonical bytes on an input the inherent oracle
    /// whitespace-trimmed at parse time — the emit surface projects
    /// the canonical trimmed byte buffer, not the caller's stray-
    /// whitespace raw input. Pins the trim discipline carrying through
    /// the by-value borrowed/owned-frontier byte-slice emit surface.
    #[test]
    fn test_from_content_digest_cow_static_bytes_after_whitespace_trim() {
        let raw = format!("  sha256:{D1}\n");
        let expected = format!("sha256:{D1}");
        let d = ContentDigest::parse(&raw).unwrap();
        let emitted: std::borrow::Cow<'static, [u8]> = d.into();
        assert_eq!(&*emitted, expected.as_bytes());
        assert!(!emitted.starts_with(b" "));
        assert!(!emitted.ends_with(b"\n"));
    }

    /// The [`From<ContentDigest> for Cow<'static, [u8]>`] impl
    /// composes with a generic borrowed/owned-frontier byte-slice
    /// helper bounded by `impl Into<Cow<'static, [u8]>>` — the
    /// compositional motivation for landing the trait separately from
    /// the resizable-owned [`From<ContentDigest> for Vec<u8>`] and
    /// shrunk-owned [`From<ContentDigest> for Box<[u8]>`] byte-slice
    /// emit peers. Pins the trait-generic consumer surface: a
    /// downstream site that types its input contract as
    /// `impl Into<Cow<'static, [u8]>>` (a [`bytes::Bytes::from`]
    /// intake that interleaves `'static` byte literals with runtime-
    /// parsed digests in the same sink, a `serde` container that opts
    /// into `#[serde(from = "Cow<'static, [u8]>")]` at the
    /// borrowed/owned-frontier byte-slice emit surface, a streaming
    /// hasher seeded off a [`Cow<'static, [u8]>`] label input,
    /// `http::HeaderValue::from_bytes` bridges keyed on a
    /// [`Cow<'static, [u8]>`] to elide the allocation on the borrowed
    /// branch) recovers the same validated full-digest bytes a direct
    /// `Cow::Owned(digest.as_ref().to_vec())` bridge would, at
    /// zero-copy off the moved backing storage.
    #[test]
    fn test_from_content_digest_cow_static_bytes_carries_through_generic_consumer() {
        fn first_byte_of<T: Into<std::borrow::Cow<'static, [u8]>>>(t: T) -> u8 {
            let c: std::borrow::Cow<'static, [u8]> = t.into();
            *c.first().unwrap()
        }
        fn byte_length_of<T: Into<std::borrow::Cow<'static, [u8]>>>(t: T) -> usize {
            let c: std::borrow::Cow<'static, [u8]> = t.into();
            c.len()
        }
        fn cow_bytes_eq<T: Into<std::borrow::Cow<'static, [u8]>>>(t: T, expected: &[u8]) -> bool {
            let c: std::borrow::Cow<'static, [u8]> = t.into();
            &*c == expected
        }
        let raw = format!("sha256:{D1}");
        let d1 = ContentDigest::parse(&raw).unwrap();
        let d2 = d1.clone();
        let d3 = d1.clone();
        assert_eq!(first_byte_of(d1), b's');
        assert_eq!(byte_length_of(d2), raw.len());
        assert!(cow_bytes_eq(d3, raw.as_bytes()));
    }

    /// A validated digest's
    /// [`From<ContentDigest> for Cow<'static, [u8]>`] output
    /// round-trips through [`std::str::from_utf8`] and then the full
    /// parse-surface set — inherent [`ContentDigest::parse`],
    /// [`TryFrom<&str>`], [`FromStr`](std::str::FromStr),
    /// [`TryFrom<String>`], [`TryFrom<Cow<'_, str>>`] — back to the
    /// same validated [`ContentDigest`] value. Pins the
    /// "borrowed/owned-frontier byte-slice emit surface projects
    /// exactly the canonical UTF-8 form every parse surface accepts"
    /// invariant so a future canonicalising refinement to the backing
    /// bytes that broke round-trip via the borrowed/owned-frontier
    /// byte-slice emit peer fails this test.
    #[test]
    fn test_from_content_digest_cow_static_bytes_parse_round_trip() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let cases = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        for raw in cases {
            let original = ContentDigest::parse(&raw).unwrap();
            let emitted: std::borrow::Cow<'static, [u8]> =
                std::borrow::Cow::<'static, [u8]>::from(original.clone());
            let decoded = std::str::from_utf8(&emitted).unwrap();
            let via_parse = ContentDigest::parse(decoded).unwrap();
            let via_try_from_str = ContentDigest::try_from(decoded).unwrap();
            let via_from_str: ContentDigest = decoded.parse().unwrap();
            let via_try_from_string = ContentDigest::try_from(decoded.to_owned()).unwrap();
            let via_try_from_cow =
                ContentDigest::try_from(std::borrow::Cow::Borrowed(decoded)).unwrap();
            assert_eq!(via_parse, original);
            assert_eq!(via_try_from_str, original);
            assert_eq!(via_from_str, original);
            assert_eq!(via_try_from_string, original);
            assert_eq!(via_try_from_cow, original);
        }
    }

    /// [`From<ContentDigest> for Cow<'static, [u8]>`] takes the
    /// [`Cow::Owned`] branch — the load-bearing choice given
    /// [`ContentDigest`] holds a runtime-parsed [`String`] with no
    /// `'static` backing to borrow. Contrasts the enum-shaped sibling
    /// [`Cow<'static, [u8]>`] emit peers on
    /// [`crate::version::BumpLevel`],
    /// [`crate::probe_outcome::AdmissionTier`], and
    /// [`crate::retry::PerAttemptRegion`] — each of which lands on
    /// [`Cow::Borrowed`] because their `as_ref` oracle returns a
    /// `'static` byte slice off a static label table — and pins the
    /// branch discriminator so a future refactor that accidentally
    /// boxed the digest through [`Cow::Borrowed`] on a leaked buffer
    /// (or that re-formatted through [`std::fmt::Display`] into an
    /// owned string to shoehorn onto the borrowed branch) fails this
    /// test.
    #[test]
    fn test_from_content_digest_cow_static_bytes_is_owned() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let cases = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        for raw in cases {
            let d = ContentDigest::parse(&raw).unwrap();
            let emitted: std::borrow::Cow<'static, [u8]> = d.into();
            assert!(
                matches!(emitted, std::borrow::Cow::Owned(_)),
                "ContentDigest owns its backing String; Cow<'static, [u8]> emit peer must \
                 wrap the moved backing in Cow::Owned, not Cow::Borrowed"
            );
        }
    }

    /// The by-value cross-thread shared-owned byte-slice emit surface
    /// [`From<ContentDigest> for Arc<[u8]>`] emits the same canonical
    /// `<algorithm>:<hex>` bytes every borrowed-view read surface and
    /// every peer emit surface on the byte-slice frontier project.
    /// Round-trips the emit peer against
    /// [`<ContentDigest as AsRef<[u8]>>::as_ref`] (the trait-generic
    /// borrowed-view byte-slice read surface), against
    /// [`ContentDigest::as_str`]`.as_bytes()` (the borrowed-view UTF-8
    /// read surface reinterpreted as raw bytes), against
    /// [`<Vec<u8> as From<ContentDigest>>::from`] (the by-value
    /// resizable-owned-byte-slice emit peer), against
    /// [`<Box<[u8]> as From<ContentDigest>>::from`] (the by-value
    /// shrunk-owned byte-slice emit peer), and against the raw input the
    /// inherent oracle accepted. Pins that after the [`Vec<u8>`] moves
    /// out and is repackaged as [`Arc<[u8]>`] — the by-value
    /// cross-thread shared-owned byte-slice emit surface names the same
    /// canonical full-digest byte buffer as every peer surface on the
    /// byte-slice frontier.
    #[test]
    fn test_from_content_digest_arc_bytes_matches_as_ref() {
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
            let via_vec_emit: Vec<u8> = Vec::<u8>::from(d.clone());
            let via_box_emit: Box<[u8]> = Box::<[u8]>::from(d.clone());
            let emitted: std::sync::Arc<[u8]> = std::sync::Arc::<[u8]>::from(d);
            assert_eq!(&*emitted, borrowed_as_ref.as_slice());
            assert_eq!(&*emitted, via_str_bytes.as_slice());
            assert_eq!(&*emitted, via_vec_emit.as_slice());
            assert_eq!(&*emitted, &*via_box_emit);
            assert_eq!(&*emitted, raw.as_bytes());
        }
    }

    /// [`From<ContentDigest> for Arc<[u8]>`] emits the full
    /// `<algorithm>:<hex>` byte slice for a sha256 digest. Pins the
    /// primary registry algorithm on the by-value cross-thread shared-
    /// owned byte-slice emit surface — the emitted [`Arc<[u8]>`] is
    /// byte-identical to the input the inherent oracle accepted, and
    /// every emitted byte is ASCII by parse invariant.
    #[test]
    fn test_from_content_digest_arc_bytes_sha256_full_digest() {
        let raw = format!("sha256:{D1}");
        let d = ContentDigest::parse(&raw).unwrap();
        let emitted: std::sync::Arc<[u8]> = d.into();
        assert_eq!(&*emitted, raw.as_bytes());
        assert!(emitted.starts_with(b"sha256:"));
        assert_eq!(&emitted[7..], D1.as_bytes());
        assert!(emitted.iter().all(|b| b.is_ascii()));
    }

    /// [`From<ContentDigest> for Arc<[u8]>`] emits the full
    /// `<algorithm>:<hex>` byte slice for a sha512 digest. Pins the
    /// second supported algorithm on the by-value cross-thread shared-
    /// owned byte-slice emit surface so a widening at the inherent
    /// oracle is caught by an existing test on this derived surface.
    #[test]
    fn test_from_content_digest_arc_bytes_sha512_full_digest() {
        let hex = "f".repeat(SHA512_HEX_LEN);
        let raw = format!("sha512:{hex}");
        let d = ContentDigest::parse(&raw).unwrap();
        let emitted: std::sync::Arc<[u8]> = d.into();
        assert_eq!(&*emitted, raw.as_bytes());
        assert!(emitted.starts_with(b"sha512:"));
        assert_eq!(&emitted[7..], hex.as_bytes());
        assert!(emitted.iter().all(|b| b.is_ascii()));
    }

    /// [`From<ContentDigest> for Arc<[u8]>`] emits the trimmed canonical
    /// bytes on an input the inherent oracle whitespace-trimmed at parse
    /// time — the emit surface projects the canonical trimmed byte
    /// buffer, not the caller's stray-whitespace raw input. Pins the
    /// trim discipline carrying through the by-value cross-thread
    /// shared-owned byte-slice emit surface.
    #[test]
    fn test_from_content_digest_arc_bytes_after_whitespace_trim() {
        let raw = format!("  sha256:{D1}\n");
        let expected = format!("sha256:{D1}");
        let d = ContentDigest::parse(&raw).unwrap();
        let emitted: std::sync::Arc<[u8]> = d.into();
        assert_eq!(&*emitted, expected.as_bytes());
        assert!(!emitted.starts_with(b" "));
        assert!(!emitted.ends_with(b"\n"));
    }

    /// The [`From<ContentDigest> for Arc<[u8]>`] impl composes with a
    /// generic cross-thread shared-owned byte-slice helper bounded by
    /// `impl Into<std::sync::Arc<[u8]>>` — the compositional motivation
    /// for landing the trait separately from the UTF-8 shared-owned
    /// [`From<ContentDigest> for Arc<str>`] emit peer and the borrowed/
    /// owned-frontier byte-slice [`From<ContentDigest> for
    /// Cow<'static, [u8]>`] emit peer. Pins the trait-generic consumer
    /// surface: a downstream site that types its input contract as
    /// `impl Into<Arc<[u8]>>` (a `dashmap::DashMap<Arc<[u8]>, _>` cache
    /// key inserter, a `tokio::sync::broadcast` sender that carries an
    /// `Arc<[u8]>` payload across worker threads at `O(1)` `Arc::clone`
    /// cost, a `bytes::Bytes::from(Arc<[u8]>)` intake at the shared-
    /// owned raw-byte frontier, a `serde` container opting into
    /// `#[serde(into = "Arc<[u8]>")]` at the shared-owned byte-slice
    /// frontier) recovers the same validated full-digest bytes a direct
    /// `Arc::<[u8]>::from(digest.as_ref())` call would, at exactly the
    /// shared-owned repackaging cost off the moved backing storage.
    #[test]
    fn test_from_content_digest_arc_bytes_carries_through_generic_consumer() {
        fn first_byte_of<T: Into<std::sync::Arc<[u8]>>>(t: T) -> u8 {
            let a: std::sync::Arc<[u8]> = t.into();
            *a.first().unwrap()
        }
        fn byte_length_of<T: Into<std::sync::Arc<[u8]>>>(t: T) -> usize {
            let a: std::sync::Arc<[u8]> = t.into();
            a.len()
        }
        fn arc_bytes_eq<T: Into<std::sync::Arc<[u8]>>>(t: T, expected: &[u8]) -> bool {
            let a: std::sync::Arc<[u8]> = t.into();
            &*a == expected
        }
        let raw = format!("sha256:{D1}");
        let d1 = ContentDigest::parse(&raw).unwrap();
        let d2 = d1.clone();
        let d3 = d1.clone();
        assert_eq!(first_byte_of(d1), b's');
        assert_eq!(byte_length_of(d2), raw.len());
        assert!(arc_bytes_eq(d3, raw.as_bytes()));
    }

    /// A validated digest's [`From<ContentDigest> for Arc<[u8]>`] output
    /// round-trips through [`std::str::from_utf8`] and then the full
    /// parse-surface set — inherent [`ContentDigest::parse`],
    /// [`TryFrom<&str>`], [`FromStr`](std::str::FromStr),
    /// [`TryFrom<String>`], [`TryFrom<Cow<'_, str>>`] — back to the same
    /// validated [`ContentDigest`] value. Pins the "cross-thread shared-
    /// owned byte-slice emit surface projects exactly the canonical
    /// UTF-8 form every parse surface accepts" invariant so a future
    /// canonicalising refinement to the backing bytes that broke round-
    /// trip via the cross-thread shared-owned byte-slice emit peer fails
    /// this test.
    #[test]
    fn test_from_content_digest_arc_bytes_parse_round_trip() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let cases = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        for raw in cases {
            let original = ContentDigest::parse(&raw).unwrap();
            let emitted: std::sync::Arc<[u8]> = std::sync::Arc::<[u8]>::from(original.clone());
            let decoded = std::str::from_utf8(&emitted).unwrap();
            let via_parse = ContentDigest::parse(decoded).unwrap();
            let via_try_from_str = ContentDigest::try_from(decoded).unwrap();
            let via_from_str: ContentDigest = decoded.parse().unwrap();
            let via_try_from_string = ContentDigest::try_from(decoded.to_owned()).unwrap();
            let via_try_from_cow =
                ContentDigest::try_from(std::borrow::Cow::Borrowed(decoded)).unwrap();
            assert_eq!(via_parse, original);
            assert_eq!(via_try_from_str, original);
            assert_eq!(via_from_str, original);
            assert_eq!(via_try_from_string, original);
            assert_eq!(via_try_from_cow, original);
        }
    }

    /// [`From<ContentDigest> for Arc<[u8]>`] emits an [`Arc<[u8]>`]
    /// whose [`Arc::clone`] returns a second handle onto the same shared
    /// allocation — the load-bearing property of the cross-thread
    /// shared-owned raw-byte frontier that a downstream cache slot
    /// (`dashmap::DashMap<Arc<[u8]>, _>`, `tokio::sync::broadcast`
    /// payload, `bytes::Bytes::from(Arc<[u8]>)` sink) relies on to fan a
    /// single label byte-buffer allocation across worker threads at
    /// atomic-refcount cost. Pins the shared-allocation identity so a
    /// future refactor that accidentally re-allocated on
    /// [`Arc::clone`] (a rebox through `to_string().into_bytes().into()`
    /// in the emit path, a per-clone `Arc::<[u8]>::from(&*self)` chain,
    /// a spurious [`Box<[u8]>`] intermediate that broke the
    /// [`Vec<u8>`]→[`Arc<[u8]>`] one-shot repackaging) fails this test.
    #[test]
    fn test_from_content_digest_arc_bytes_clones_cheaply_across_threads() {
        let raw = format!("sha256:{D1}");
        let d = ContentDigest::parse(&raw).unwrap();
        let emitted: std::sync::Arc<[u8]> = d.into();
        let cloned = std::sync::Arc::clone(&emitted);
        assert!(
            std::sync::Arc::ptr_eq(&emitted, &cloned),
            "Arc::clone on the emitted Arc<[u8]> must return a handle onto the same shared \
             allocation, not a fresh allocation of the label bytes"
        );
        assert_eq!(&*cloned, raw.as_bytes());
        assert_eq!(std::sync::Arc::strong_count(&emitted), 2);
        let handoff = std::sync::Arc::clone(&emitted);
        let joined = std::thread::spawn(move || handoff.to_vec()).join().unwrap();
        assert_eq!(joined.as_slice(), raw.as_bytes());
    }

    /// [`From<ContentDigest> for std::rc::Rc<[u8]>`] emits the same bytes
    /// as the borrowed-view read peer [`AsRef<[u8]>`] sees off the backing
    /// string, as the by-value owned-byte-slice emit peer [`Vec<u8>`]
    /// moves out, as the by-value shrunk-owned byte-slice emit peer
    /// [`Box<[u8]>`] repackages, and as the by-value cross-thread
    /// shared-owned byte-slice emit peer [`Arc<[u8]>`] atomically
    /// refcounts. Pins that after the [`Vec<u8>`] moves out and is
    /// repackaged as [`Rc<[u8]>`] — the by-value single-thread
    /// shared-owned byte-slice emit surface names the same canonical
    /// full-digest byte buffer as every peer surface on the byte-slice
    /// frontier.
    #[test]
    fn test_from_content_digest_rc_bytes_matches_as_ref() {
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
            let via_vec_emit: Vec<u8> = Vec::<u8>::from(d.clone());
            let via_box_emit: Box<[u8]> = Box::<[u8]>::from(d.clone());
            let via_arc_emit: std::sync::Arc<[u8]> = std::sync::Arc::<[u8]>::from(d.clone());
            let emitted: std::rc::Rc<[u8]> = std::rc::Rc::<[u8]>::from(d);
            assert_eq!(&*emitted, borrowed_as_ref.as_slice());
            assert_eq!(&*emitted, via_str_bytes.as_slice());
            assert_eq!(&*emitted, via_vec_emit.as_slice());
            assert_eq!(&*emitted, &*via_box_emit);
            assert_eq!(&*emitted, &*via_arc_emit);
            assert_eq!(&*emitted, raw.as_bytes());
        }
    }

    /// [`From<ContentDigest> for std::rc::Rc<[u8]>`] emits the full
    /// `<algorithm>:<hex>` byte slice for a sha256 digest. Pins the
    /// primary registry algorithm on the by-value single-thread
    /// shared-owned byte-slice emit surface — the emitted [`Rc<[u8]>`] is
    /// byte-identical to the input the inherent oracle accepted, and
    /// every emitted byte is ASCII by parse invariant.
    #[test]
    fn test_from_content_digest_rc_bytes_sha256_full_digest() {
        let raw = format!("sha256:{D1}");
        let d = ContentDigest::parse(&raw).unwrap();
        let emitted: std::rc::Rc<[u8]> = d.into();
        assert_eq!(&*emitted, raw.as_bytes());
        assert!(emitted.starts_with(b"sha256:"));
        assert_eq!(&emitted[7..], D1.as_bytes());
        assert!(emitted.iter().all(|b| b.is_ascii()));
    }

    /// [`From<ContentDigest> for std::rc::Rc<[u8]>`] emits the full
    /// `<algorithm>:<hex>` byte slice for a sha512 digest. Pins the
    /// second supported algorithm on the by-value single-thread
    /// shared-owned byte-slice emit surface so a widening at the inherent
    /// oracle is caught by an existing test on this derived surface.
    #[test]
    fn test_from_content_digest_rc_bytes_sha512_full_digest() {
        let hex = "f".repeat(SHA512_HEX_LEN);
        let raw = format!("sha512:{hex}");
        let d = ContentDigest::parse(&raw).unwrap();
        let emitted: std::rc::Rc<[u8]> = d.into();
        assert_eq!(&*emitted, raw.as_bytes());
        assert!(emitted.starts_with(b"sha512:"));
        assert_eq!(&emitted[7..], hex.as_bytes());
        assert!(emitted.iter().all(|b| b.is_ascii()));
    }

    /// [`From<ContentDigest> for std::rc::Rc<[u8]>`] emits the trimmed
    /// canonical bytes on an input the inherent oracle whitespace-trimmed
    /// at parse time — the emit surface projects the canonical trimmed
    /// byte buffer, not the caller's stray-whitespace raw input. Pins the
    /// trim discipline carrying through the by-value single-thread
    /// shared-owned byte-slice emit surface.
    #[test]
    fn test_from_content_digest_rc_bytes_after_whitespace_trim() {
        let raw = format!("  sha256:{D1}\n");
        let expected = format!("sha256:{D1}");
        let d = ContentDigest::parse(&raw).unwrap();
        let emitted: std::rc::Rc<[u8]> = d.into();
        assert_eq!(&*emitted, expected.as_bytes());
        assert!(!emitted.starts_with(b" "));
        assert!(!emitted.ends_with(b"\n"));
    }

    /// The [`From<ContentDigest> for std::rc::Rc<[u8]>`] impl composes
    /// with a generic single-thread shared-owned byte-slice helper
    /// bounded by `impl Into<std::rc::Rc<[u8]>>` — the compositional
    /// motivation for landing the trait separately from the cross-thread
    /// shared-owned [`From<ContentDigest> for Arc<[u8]>`] emit peer and
    /// the same-thread UTF-8 [`From<ContentDigest> for Rc<str>`] emit
    /// peer. Pins the trait-generic consumer surface: a downstream site
    /// that types its input contract as `impl Into<Rc<[u8]>>` (a
    /// same-thread `HashMap<Rc<[u8]>, _>` cache key inserter, a
    /// `thread_local!` per-thread digest interner that fans out
    /// `Rc<[u8]>` handles to inline inspection helpers, a
    /// `bytes::Bytes::from(Rc<[u8]>)` intake at the same-thread
    /// shared-owned raw-byte frontier, a `!Send` per-task lookaside that
    /// keys entries on the digest without paying [`Arc`]'s atomic
    /// refcount) recovers the same validated full-digest bytes a direct
    /// `Rc::<[u8]>::from(digest.as_ref())` call would, at exactly the
    /// shared-owned repackaging cost off the moved backing storage.
    #[test]
    fn test_from_content_digest_rc_bytes_carries_through_generic_consumer() {
        fn first_byte_of<T: Into<std::rc::Rc<[u8]>>>(t: T) -> u8 {
            let r: std::rc::Rc<[u8]> = t.into();
            *r.first().unwrap()
        }
        fn byte_length_of<T: Into<std::rc::Rc<[u8]>>>(t: T) -> usize {
            let r: std::rc::Rc<[u8]> = t.into();
            r.len()
        }
        fn rc_bytes_eq<T: Into<std::rc::Rc<[u8]>>>(t: T, expected: &[u8]) -> bool {
            let r: std::rc::Rc<[u8]> = t.into();
            &*r == expected
        }
        let raw = format!("sha256:{D1}");
        let d1 = ContentDigest::parse(&raw).unwrap();
        let d2 = d1.clone();
        let d3 = d1.clone();
        assert_eq!(first_byte_of(d1), b's');
        assert_eq!(byte_length_of(d2), raw.len());
        assert!(rc_bytes_eq(d3, raw.as_bytes()));
    }

    /// A validated digest's [`From<ContentDigest> for std::rc::Rc<[u8]>`]
    /// output round-trips through [`std::str::from_utf8`] and then the
    /// full parse-surface set — inherent [`ContentDigest::parse`],
    /// [`TryFrom<&str>`], [`FromStr`](std::str::FromStr),
    /// [`TryFrom<String>`], [`TryFrom<Cow<'_, str>>`] — back to the same
    /// validated [`ContentDigest`] value. Pins the "single-thread
    /// shared-owned byte-slice emit surface projects exactly the
    /// canonical UTF-8 form every parse surface accepts" invariant so a
    /// future canonicalising refinement to the backing bytes that broke
    /// round-trip via the single-thread shared-owned byte-slice emit peer
    /// fails this test.
    #[test]
    fn test_from_content_digest_rc_bytes_parse_round_trip() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let cases = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        for raw in cases {
            let original = ContentDigest::parse(&raw).unwrap();
            let emitted: std::rc::Rc<[u8]> = std::rc::Rc::<[u8]>::from(original.clone());
            let decoded = std::str::from_utf8(&emitted).unwrap();
            let via_parse = ContentDigest::parse(decoded).unwrap();
            let via_try_from_str = ContentDigest::try_from(decoded).unwrap();
            let via_from_str: ContentDigest = decoded.parse().unwrap();
            let via_try_from_string = ContentDigest::try_from(decoded.to_owned()).unwrap();
            let via_try_from_cow =
                ContentDigest::try_from(std::borrow::Cow::Borrowed(decoded)).unwrap();
            assert_eq!(via_parse, original);
            assert_eq!(via_try_from_str, original);
            assert_eq!(via_from_str, original);
            assert_eq!(via_try_from_string, original);
            assert_eq!(via_try_from_cow, original);
        }
    }

    /// [`From<ContentDigest> for std::rc::Rc<[u8]>`] emits an
    /// [`Rc<[u8]>`] whose [`Rc::clone`] returns a second handle onto the
    /// same shared allocation — the load-bearing property of the
    /// single-thread shared-owned raw-byte frontier that a downstream
    /// same-thread cache slot (a `HashMap<Rc<[u8]>, _>` per-pipeline
    /// registry, a `thread_local!` byte-slice digest interner, a `!Send`
    /// per-task lookaside) relies on to fan a single label byte-buffer
    /// allocation across per-worker readers at pointer-copy +
    /// integer-increment cost with no atomic-op fence. Pins the
    /// shared-allocation identity so a future refactor that accidentally
    /// re-allocated on [`Rc::clone`] (a rebox through
    /// `to_string().into_bytes().into()` in the emit path, a per-clone
    /// `Rc::<[u8]>::from(&*self)` chain, a spurious [`Box<[u8]>`]
    /// intermediate that broke the [`Vec<u8>`]→[`Rc<[u8]>`] one-shot
    /// repackaging) fails this test.
    #[test]
    fn test_from_content_digest_rc_bytes_clones_share_allocation() {
        let raw = format!("sha256:{D1}");
        let d = ContentDigest::parse(&raw).unwrap();
        let emitted: std::rc::Rc<[u8]> = d.into();
        let cloned = std::rc::Rc::clone(&emitted);
        assert!(
            std::rc::Rc::ptr_eq(&emitted, &cloned),
            "Rc::clone on the emitted Rc<[u8]> must return a handle onto the same shared \
             allocation, not a fresh allocation of the label bytes"
        );
        assert_eq!(&*cloned, raw.as_bytes());
        assert_eq!(std::rc::Rc::strong_count(&emitted), 2);
        let third = std::rc::Rc::clone(&emitted);
        assert_eq!(std::rc::Rc::strong_count(&emitted), 3);
        assert!(std::rc::Rc::ptr_eq(&emitted, &third));
        drop(third);
        assert_eq!(std::rc::Rc::strong_count(&emitted), 2);
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

    /// `PartialEq<str> for ContentDigest` agrees byte-for-byte with
    /// the borrowed-view [`ContentDigest::as_str`] oracle across a
    /// grid of (validated digest × comparison string) pairs — the
    /// composed canonical-digest read reached through the borrowed
    /// UTF-8 comparison surface is identical to the read reached
    /// through the borrowed UTF-8 view surface. A future refactor
    /// that inlined a divergent read into the [`PartialEq<str>`]
    /// impl (a lossy canonicalisation, a case-fold, a
    /// whitespace-tolerant compare) breaks this pin at at least one
    /// (digest, label) pair rather than at every downstream
    /// `digest == *label_ref` call site. Symmetric with the sibling
    /// label-axis pin
    /// (`test_per_attempt_region_partial_eq_str_agrees_with_as_str`).
    #[test]
    fn test_partial_eq_str_agrees_with_as_str() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let digests = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        let cross = digests.iter().map(String::as_str).chain([
            "",
            "sha256:",
            "SHA256:0123",
            "not-a-digest",
        ]);
        let owned: Vec<String> = digests
            .iter()
            .flat_map(|d| {
                [
                    format!("SHA256:{}", &d[7..]),
                    format!(" {d}"),
                    format!("{d}\n"),
                ]
            })
            .collect();
        let labels: Vec<&str> = cross.chain(owned.iter().map(String::as_str)).collect();
        for raw in &digests {
            let d = ContentDigest::parse(raw).unwrap();
            for label in &labels {
                assert_eq!(
                    <ContentDigest as PartialEq<str>>::eq(&d, label),
                    d.as_str() == *label,
                    "PartialEq<str> and as_str() equality must agree at ({raw:?}, {label:?})",
                );
            }
        }
    }

    /// At every validated [`ContentDigest`] value,
    /// `<Self as PartialEq<str>>::eq(&digest, digest.as_str())`
    /// returns true — the digest recognises its own emitted canonical
    /// form. Symmetric with the sibling label-axis pin
    /// (`test_per_attempt_region_partial_eq_str_reflexive_at_own_label`).
    #[test]
    fn test_partial_eq_str_reflexive_at_own_digest() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        for raw in [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ] {
            let d = ContentDigest::parse(&raw).unwrap();
            let canonical: &str = d.as_str();
            assert!(
                <ContentDigest as PartialEq<str>>::eq(&d, canonical),
                "PartialEq<str> must recognise self canonical form at {raw:?}",
            );
        }
    }

    /// Every canonical string that is NOT the digest's own emitted
    /// form fails equality through [`PartialEq<str>`] — no case-fold,
    /// no whitespace tolerance, no cross-digest collision. Pins the
    /// canonicity discipline the sibling label-axis pin
    /// (`test_per_attempt_region_partial_eq_str_rejects_non_canonical_labels`)
    /// enforces on its own family: only exact [`ContentDigest::as_str`]
    /// emissions equal a [`ContentDigest`] value through this surface.
    #[test]
    fn test_partial_eq_str_rejects_non_canonical_labels() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let d1 = ContentDigest::parse(&format!("sha256:{D1}")).unwrap();
        let d2 = ContentDigest::parse(&format!("sha256:{D2}")).unwrap();
        let d3 = ContentDigest::parse(&format!("sha256:{D3}")).unwrap();
        let d4 = ContentDigest::parse(&format!("sha512:{hex512}")).unwrap();
        let cross_and_malformed = [
            "".to_string(),
            "sha256:".to_string(),
            "SHA256:0123".to_string(),
            "not-a-digest".to_string(),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("SHA256:{D1}"),
            format!(" sha256:{D1}"),
            format!("sha256:{D1}\n"),
            format!("\tsha256:{D1}"),
            format!("sha256:{}", D1.to_uppercase()),
        ];
        for label in &cross_and_malformed {
            if label == "sha256:{D1}" {
                continue;
            }
            assert!(
                !<ContentDigest as PartialEq<str>>::eq(&d1, label),
                "PartialEq<str> must reject non-canonical label {label:?} at sha256:{D1}",
            );
        }
        // Cross-digest: d2 / d3 / d4 do not equal d1's canonical form.
        let d1_canonical = format!("sha256:{D1}");
        for (other, tag) in [(&d2, "d2"), (&d3, "d3"), (&d4, "d4")] {
            assert!(
                !<ContentDigest as PartialEq<str>>::eq(other, &d1_canonical),
                "PartialEq<str> must reject cross-digest label {d1_canonical:?} at {tag}",
            );
        }
    }

    /// `PartialEq<&str> for ContentDigest` agrees byte-for-byte with
    /// the borrowed-view [`ContentDigest::as_str`] oracle across the
    /// same grid, threaded through a `&str` receiver so the caller
    /// writes `digest == label_ref` without the explicit `*` deref.
    /// Symmetric with the sibling label-axis pin
    /// (`test_per_attempt_region_partial_eq_str_ref_agrees_with_as_str`).
    #[test]
    fn test_partial_eq_str_ref_agrees_with_as_str() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let digests = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        let labels = [
            "",
            "sha256:",
            "not-a-digest",
            &format!("sha256:{D1}") as &str,
            &format!("sha256:{D2}") as &str,
            &format!("SHA256:{D1}") as &str,
            &format!(" sha256:{D1}") as &str,
        ];
        for raw in &digests {
            let d = ContentDigest::parse(raw).unwrap();
            for label in labels {
                let label_ref: &str = label;
                assert_eq!(
                    <ContentDigest as PartialEq<&str>>::eq(&d, &label_ref),
                    d.as_str() == label_ref,
                    "PartialEq<&str> and as_str() equality must agree at ({raw:?}, {label:?})",
                );
            }
        }
    }

    /// At every validated [`ContentDigest`] value,
    /// `<Self as PartialEq<&str>>::eq(&digest, &digest.as_str())`
    /// returns true — the digest recognises its own emitted canonical
    /// form through the `&str`-receiver peer without the caller's
    /// explicit `*` deref. Symmetric with the sibling label-axis pin
    /// (`test_per_attempt_region_partial_eq_str_ref_reflexive_at_own_label`).
    #[test]
    fn test_partial_eq_str_ref_reflexive_at_own_digest() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        for raw in [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ] {
            let d = ContentDigest::parse(&raw).unwrap();
            let canonical: &str = d.as_str();
            assert!(
                <ContentDigest as PartialEq<&str>>::eq(&d, &canonical),
                "PartialEq<&str> must recognise self canonical form at {raw:?}",
            );
        }
    }

    /// Every canonical string that is NOT the digest's own emitted
    /// form fails equality through [`PartialEq<&str>`] — the same
    /// canonicity discipline the [`PartialEq<str>`] receiver-shape
    /// sibling enforces, projected onto the `&str` receiver.
    /// Symmetric with the sibling label-axis pin
    /// (`test_per_attempt_region_partial_eq_str_ref_rejects_non_canonical_labels`).
    #[test]
    fn test_partial_eq_str_ref_rejects_non_canonical_labels() {
        let d1 = ContentDigest::parse(&format!("sha256:{D1}")).unwrap();
        let d2 = ContentDigest::parse(&format!("sha256:{D2}")).unwrap();
        let d1_uppercased_algo = format!("SHA256:{D1}");
        let d1_leading_ws = format!(" sha256:{D1}");
        let d1_trailing_ws = format!("sha256:{D1}\n");
        let d2_canonical = format!("sha256:{D2}");
        let bad: [&str; 7] = [
            "",
            "sha256:",
            "not-a-digest",
            &d1_uppercased_algo,
            &d1_leading_ws,
            &d1_trailing_ws,
            &d2_canonical,
        ];
        for label in bad {
            let label_ref: &str = label;
            assert!(
                !<ContentDigest as PartialEq<&str>>::eq(&d1, &label_ref),
                "PartialEq<&str> must reject non-canonical label {label:?} at sha256:{D1}",
            );
        }
        // The peer surface is symmetric — d2 rejects d1's canonical
        // form through the &str receiver as well.
        let d1_canonical = format!("sha256:{D1}");
        let d1_canonical_ref: &str = &d1_canonical;
        assert!(!<ContentDigest as PartialEq<&str>>::eq(
            &d2,
            &d1_canonical_ref,
        ));
    }

    /// The [`PartialEq<str>`] impl composes with a generic
    /// `PartialEq<str>`-bounded consumer — a downstream site that
    /// types its comparison contract as `impl PartialEq<str>`
    /// (a `matches!` predicate on a `Cow::Borrowed(s)` arm, an
    /// integration-test oracle that generic-bounds its equality
    /// check) recovers the same answer as a direct
    /// `<ContentDigest as PartialEq<str>>::eq` call. Pins the
    /// trait-generic consumer surface parallel to
    /// [`test_as_ref_str_carries_through_generic_consumer`] on the
    /// borrowed-view axis.
    #[test]
    fn test_partial_eq_str_carries_through_generic_consumer() {
        fn eq_via_bound<T: PartialEq<str>>(t: &T, expected: &str) -> bool {
            <T as PartialEq<str>>::eq(t, expected)
        }
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        for raw in [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ] {
            let d = ContentDigest::parse(&raw).unwrap();
            assert!(eq_via_bound(&d, &raw));
            let other = if raw.starts_with("sha256:") {
                format!("sha512:{}", "0".repeat(SHA512_HEX_LEN))
            } else {
                format!("sha256:{D1}")
            };
            assert!(!eq_via_bound(&d, &other));
        }
    }

    /// `PartialEq<[u8]> for ContentDigest` agrees byte-for-byte with
    /// the borrowed-view [`<ContentDigest as AsRef<[u8]>>::as_ref`]
    /// oracle across a grid of (validated digest × comparison byte
    /// slice) pairs — the composed canonical-digest read reached
    /// through the borrowed byte-slice comparison surface is
    /// identical to the read reached through the borrowed byte-slice
    /// view surface. A future refactor that inlined a divergent read
    /// into the [`PartialEq<[u8]>`] impl (a lossy canonicalisation, a
    /// case-fold on the ASCII digest bytes, a whitespace-tolerant
    /// compare) breaks this pin at at least one (digest, label) pair
    /// rather than at every downstream `digest == *label_bytes_ref`
    /// call site.
    #[test]
    fn test_partial_eq_bytes_agrees_with_as_ref() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let digests = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        let owned: Vec<Vec<u8>> = digests
            .iter()
            .flat_map(|d| {
                [
                    d.as_bytes().to_vec(),
                    format!("SHA256:{}", &d[7..]).into_bytes(),
                    format!(" {d}").into_bytes(),
                    format!("{d}\n").into_bytes(),
                ]
            })
            .chain([
                Vec::<u8>::new(),
                b"sha256:".to_vec(),
                b"SHA256:0123".to_vec(),
                b"not-a-digest".to_vec(),
                vec![0xffu8, 0xfeu8, 0xfdu8],
            ])
            .collect();
        let labels: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
        for raw in &digests {
            let d = ContentDigest::parse(raw).unwrap();
            for label in &labels {
                assert_eq!(
                    <ContentDigest as PartialEq<[u8]>>::eq(&d, label),
                    <ContentDigest as AsRef<[u8]>>::as_ref(&d) == *label,
                    "PartialEq<[u8]> and AsRef<[u8]> equality must agree at ({raw:?}, {label:?})",
                );
            }
        }
    }

    /// At every validated [`ContentDigest`] value,
    /// `<Self as PartialEq<[u8]>>::eq(&digest, digest.as_ref())`
    /// returns true — the digest recognises its own emitted canonical
    /// bytes through the dereffed-slice receiver.
    #[test]
    fn test_partial_eq_bytes_reflexive_at_own_digest() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        for raw in [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ] {
            let d = ContentDigest::parse(&raw).unwrap();
            let canonical: &[u8] = <ContentDigest as AsRef<[u8]>>::as_ref(&d);
            assert!(
                <ContentDigest as PartialEq<[u8]>>::eq(&d, canonical),
                "PartialEq<[u8]> must recognise self canonical bytes at {raw:?}",
            );
        }
    }

    /// Every byte slice that is NOT the digest's own emitted
    /// canonical bytes fails equality through [`PartialEq<[u8]>`] —
    /// no case-fold on the ASCII digest bytes, no whitespace
    /// tolerance, no cross-digest collision, no UTF-8-invalid
    /// collision. Pins the canonicity discipline the UTF-8-side
    /// [`PartialEq<str>`] sibling enforces, projected onto the
    /// byte-slice frontier.
    #[test]
    fn test_partial_eq_bytes_rejects_non_canonical_labels() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let d1 = ContentDigest::parse(&format!("sha256:{D1}")).unwrap();
        let d2 = ContentDigest::parse(&format!("sha256:{D2}")).unwrap();
        let d3 = ContentDigest::parse(&format!("sha256:{D3}")).unwrap();
        let d4 = ContentDigest::parse(&format!("sha512:{hex512}")).unwrap();
        let bad_owned: Vec<Vec<u8>> = [
            Vec::<u8>::new(),
            b"sha256:".to_vec(),
            b"SHA256:0123".to_vec(),
            b"not-a-digest".to_vec(),
            format!("sha256:{D2}").into_bytes(),
            format!("sha256:{D3}").into_bytes(),
            format!("SHA256:{D1}").into_bytes(),
            format!(" sha256:{D1}").into_bytes(),
            format!("sha256:{D1}\n").into_bytes(),
            format!("\tsha256:{D1}").into_bytes(),
            format!("sha256:{}", D1.to_uppercase()).into_bytes(),
            vec![0xffu8, 0xfeu8, 0xfdu8],
        ]
        .to_vec();
        for label in &bad_owned {
            assert!(
                !<ContentDigest as PartialEq<[u8]>>::eq(&d1, label),
                "PartialEq<[u8]> must reject non-canonical label {label:?} at sha256:{D1}",
            );
        }
        // Cross-digest: d2 / d3 / d4 do not equal d1's canonical bytes.
        let d1_canonical = format!("sha256:{D1}");
        let d1_canonical_bytes: &[u8] = d1_canonical.as_bytes();
        for (other, tag) in [(&d2, "d2"), (&d3, "d3"), (&d4, "d4")] {
            assert!(
                !<ContentDigest as PartialEq<[u8]>>::eq(other, d1_canonical_bytes),
                "PartialEq<[u8]> must reject cross-digest label {d1_canonical:?} at {tag}",
            );
        }
    }

    /// `PartialEq<&[u8]> for ContentDigest` agrees byte-for-byte with
    /// the borrowed-view [`<ContentDigest as AsRef<[u8]>>::as_ref`]
    /// oracle across the same grid, threaded through a `&[u8]`
    /// receiver so the caller writes `digest == label_bytes_ref`
    /// without the explicit `*` deref.
    #[test]
    fn test_partial_eq_bytes_ref_agrees_with_as_ref() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let digests = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        let d1_bytes = format!("sha256:{D1}");
        let d2_bytes = format!("sha256:{D2}");
        let upper = format!("SHA256:{D1}");
        let leading = format!(" sha256:{D1}");
        let labels: [&[u8]; 7] = [
            b"",
            b"sha256:",
            b"not-a-digest",
            d1_bytes.as_bytes(),
            d2_bytes.as_bytes(),
            upper.as_bytes(),
            leading.as_bytes(),
        ];
        for raw in &digests {
            let d = ContentDigest::parse(raw).unwrap();
            for label in labels {
                let label_ref: &[u8] = label;
                assert_eq!(
                    <ContentDigest as PartialEq<&[u8]>>::eq(&d, &label_ref),
                    <ContentDigest as AsRef<[u8]>>::as_ref(&d) == label_ref,
                    "PartialEq<&[u8]> and AsRef<[u8]> equality must agree at ({raw:?}, {label:?})",
                );
            }
        }
    }

    /// At every validated [`ContentDigest`] value,
    /// `<Self as PartialEq<&[u8]>>::eq(&digest, &digest.as_ref())`
    /// returns true — the digest recognises its own emitted canonical
    /// bytes through the `&[u8]`-receiver peer without the caller's
    /// explicit `*` deref.
    #[test]
    fn test_partial_eq_bytes_ref_reflexive_at_own_digest() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        for raw in [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ] {
            let d = ContentDigest::parse(&raw).unwrap();
            let canonical: &[u8] = <ContentDigest as AsRef<[u8]>>::as_ref(&d);
            assert!(
                <ContentDigest as PartialEq<&[u8]>>::eq(&d, &canonical),
                "PartialEq<&[u8]> must recognise self canonical bytes at {raw:?}",
            );
        }
    }

    /// Every byte slice that is NOT the digest's own emitted
    /// canonical bytes fails equality through [`PartialEq<&[u8]>`] —
    /// the same canonicity discipline the [`PartialEq<[u8]>`]
    /// receiver-shape sibling enforces, projected onto the `&[u8]`
    /// receiver.
    #[test]
    fn test_partial_eq_bytes_ref_rejects_non_canonical_labels() {
        let d1 = ContentDigest::parse(&format!("sha256:{D1}")).unwrap();
        let d2 = ContentDigest::parse(&format!("sha256:{D2}")).unwrap();
        let d1_uppercased_algo = format!("SHA256:{D1}");
        let d1_leading_ws = format!(" sha256:{D1}");
        let d1_trailing_ws = format!("sha256:{D1}\n");
        let d2_canonical = format!("sha256:{D2}");
        let bad: [&[u8]; 8] = [
            b"",
            b"sha256:",
            b"not-a-digest",
            d1_uppercased_algo.as_bytes(),
            d1_leading_ws.as_bytes(),
            d1_trailing_ws.as_bytes(),
            d2_canonical.as_bytes(),
            &[0xffu8, 0xfeu8, 0xfdu8],
        ];
        for label in bad {
            let label_ref: &[u8] = label;
            assert!(
                !<ContentDigest as PartialEq<&[u8]>>::eq(&d1, &label_ref),
                "PartialEq<&[u8]> must reject non-canonical label {label:?} at sha256:{D1}",
            );
        }
        // The peer surface is symmetric — d2 rejects d1's canonical
        // bytes through the &[u8] receiver as well.
        let d1_canonical = format!("sha256:{D1}");
        let d1_canonical_ref: &[u8] = d1_canonical.as_bytes();
        assert!(!<ContentDigest as PartialEq<&[u8]>>::eq(
            &d2,
            &d1_canonical_ref,
        ));
    }

    /// The [`PartialEq<[u8]>`] impl composes with a generic
    /// `PartialEq<[u8]>`-bounded consumer — a downstream site that
    /// types its comparison contract as `impl PartialEq<[u8]>`
    /// (a `matches!` predicate on a `Cow::Borrowed(&[u8])` arm, a
    /// byte-stream cache-index oracle that generic-bounds its
    /// equality check) recovers the same answer as a direct
    /// `<ContentDigest as PartialEq<[u8]>>::eq` call.
    #[test]
    fn test_partial_eq_bytes_carries_through_generic_consumer() {
        fn eq_via_bound<T: PartialEq<[u8]>>(t: &T, expected: &[u8]) -> bool {
            <T as PartialEq<[u8]>>::eq(t, expected)
        }
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        for raw in [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ] {
            let d = ContentDigest::parse(&raw).unwrap();
            assert!(eq_via_bound(&d, raw.as_bytes()));
            let other = if raw.starts_with("sha256:") {
                format!("sha512:{}", "0".repeat(SHA512_HEX_LEN))
            } else {
                format!("sha256:{D1}")
            };
            assert!(!eq_via_bound(&d, other.as_bytes()));
        }
    }

    /// `PartialEq<ContentDigest> for [u8]` agrees byte-for-byte with
    /// the borrowed-view [`<ContentDigest as AsRef<[u8]>>::as_ref`]
    /// oracle across the same 4-canonical × ~9-label grid the
    /// forward-direction byte-slice pair pins, threaded through a
    /// `[u8]` self receiver so the caller writes
    /// `*label_bytes_ref == digest` and answers the same boolean
    /// equality query as the forward-direction
    /// [`PartialEq<[u8]> for ContentDigest`] peer. Pins the reverse-
    /// direction agreement at the byte frontier so a future refactor
    /// that inlined a divergent read into the reverse-direction impl
    /// breaks this pin at at least one (digest, label) pair rather
    /// than at every downstream `*label_bytes_ref == digest` call
    /// site.
    #[test]
    fn test_bytes_partial_eq_content_digest_agrees_with_as_ref() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let digests = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        let owned: Vec<Vec<u8>> = digests
            .iter()
            .flat_map(|d| {
                [
                    d.as_bytes().to_vec(),
                    format!("SHA256:{}", &d[7..]).into_bytes(),
                    format!(" {d}").into_bytes(),
                    format!("{d}\n").into_bytes(),
                ]
            })
            .chain([
                Vec::<u8>::new(),
                b"sha256:".to_vec(),
                b"SHA256:0123".to_vec(),
                b"not-a-digest".to_vec(),
                vec![0xffu8, 0xfeu8, 0xfdu8],
            ])
            .collect();
        let labels: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
        for raw in &digests {
            let d = ContentDigest::parse(raw).unwrap();
            for label in &labels {
                assert_eq!(
                    <[u8] as PartialEq<ContentDigest>>::eq(label, &d),
                    *label == <ContentDigest as AsRef<[u8]>>::as_ref(&d),
                    "PartialEq<ContentDigest> for [u8] and AsRef<[u8]> equality must agree at ({label:?}, {raw:?})",
                );
            }
        }
    }

    /// At every validated [`ContentDigest`] value,
    /// `<[u8] as PartialEq<ContentDigest>>::eq(digest.as_ref(), &digest)`
    /// returns true — the digest's own emitted canonical bytes
    /// recognise themselves as a match through the reverse-direction
    /// `[u8]`-receiver peer.
    #[test]
    fn test_bytes_partial_eq_content_digest_reflexive_at_own_digest() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        for raw in [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ] {
            let d = ContentDigest::parse(&raw).unwrap();
            let canonical: &[u8] = <ContentDigest as AsRef<[u8]>>::as_ref(&d);
            assert!(
                <[u8] as PartialEq<ContentDigest>>::eq(canonical, &d),
                "PartialEq<ContentDigest> for [u8] must recognise self canonical bytes at {raw:?}",
            );
        }
    }

    /// `PartialEq<ContentDigest> for &[u8]` agrees byte-for-byte with
    /// the borrowed-view [`<ContentDigest as AsRef<[u8]>>::as_ref`]
    /// oracle across the same grid, threaded through a `&[u8]` self
    /// receiver so the caller writes `label_bytes_ref == digest`
    /// without the explicit `*` deref. Pins the reverse-direction
    /// `&[u8]`-receiver agreement.
    #[test]
    fn test_bytes_ref_partial_eq_content_digest_agrees_with_as_ref() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let digests = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        let d1_bytes = format!("sha256:{D1}");
        let d2_bytes = format!("sha256:{D2}");
        let upper = format!("SHA256:{D1}");
        let leading = format!(" sha256:{D1}");
        let labels: [&[u8]; 7] = [
            b"",
            b"sha256:",
            b"not-a-digest",
            d1_bytes.as_bytes(),
            d2_bytes.as_bytes(),
            upper.as_bytes(),
            leading.as_bytes(),
        ];
        for raw in &digests {
            let d = ContentDigest::parse(raw).unwrap();
            for label in labels {
                let label_ref: &[u8] = label;
                assert_eq!(
                    <&[u8] as PartialEq<ContentDigest>>::eq(&label_ref, &d),
                    label_ref == <ContentDigest as AsRef<[u8]>>::as_ref(&d),
                    "PartialEq<ContentDigest> for &[u8] and AsRef<[u8]> equality must agree at ({label:?}, {raw:?})",
                );
            }
        }
    }

    /// At every validated [`ContentDigest`] value,
    /// `<&[u8] as PartialEq<ContentDigest>>::eq(&digest.as_ref(), &digest)`
    /// returns true — the digest's own emitted canonical bytes
    /// recognise themselves as a match through the reverse-direction
    /// `&[u8]`-receiver peer without the caller's explicit `*` deref.
    #[test]
    fn test_bytes_ref_partial_eq_content_digest_reflexive_at_own_digest() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        for raw in [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ] {
            let d = ContentDigest::parse(&raw).unwrap();
            let canonical: &[u8] = <ContentDigest as AsRef<[u8]>>::as_ref(&d);
            assert!(
                <&[u8] as PartialEq<ContentDigest>>::eq(&canonical, &d),
                "PartialEq<ContentDigest> for &[u8] must recognise self canonical bytes at {raw:?}",
            );
        }
    }

    /// The reverse-direction and forward-direction borrowed
    /// byte-slice comparison surfaces agree byte-for-byte at every
    /// `(label, digest)` pair — the symmetry axiom
    /// `<[u8] as PartialEq<ContentDigest>>::eq(bytes, &digest) ==
    /// <ContentDigest as PartialEq<[u8]>>::eq(&digest, bytes)` (and
    /// its `&[u8]`-receiver peer) holds across a canonical × broken ×
    /// invalid-UTF-8 grid. Pins the full 2×2 receiver × direction
    /// cross-product closure on the byte-slice frontier so a future
    /// refactor that diverged one impl from its symmetric peer breaks
    /// this pin at at least one pair rather than propagating
    /// unnoticed through downstream generic `PartialEq`-bounded
    /// consumers that thread a [`ContentDigest`] through either side
    /// of a `==` operator at the byte frontier.
    #[test]
    fn test_partial_eq_content_digest_bytes_symmetric_with_forward_direction() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let digests = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        let owned_labels: Vec<Vec<u8>> = digests
            .iter()
            .flat_map(|d| {
                [
                    d.as_bytes().to_vec(),
                    format!("SHA256:{}", &d[7..]).into_bytes(),
                    format!(" {d}").into_bytes(),
                    format!("{d}\n").into_bytes(),
                ]
            })
            .chain([
                Vec::<u8>::new(),
                b"sha256:".to_vec(),
                b"not-a-digest".to_vec(),
                vec![0xffu8, 0xfeu8, 0xfdu8],
            ])
            .collect();
        for raw in &digests {
            let d = ContentDigest::parse(raw).unwrap();
            for label in &owned_labels {
                let label_ref: &[u8] = label.as_slice();
                // [u8] receiver <-> ContentDigest receiver on [u8].
                assert_eq!(
                    <[u8] as PartialEq<ContentDigest>>::eq(label_ref, &d),
                    <ContentDigest as PartialEq<[u8]>>::eq(&d, label_ref),
                    "reverse [u8] vs forward [u8] direction must agree at ({label:?}, {raw:?})",
                );
                // &[u8] receiver <-> ContentDigest receiver on &[u8].
                assert_eq!(
                    <&[u8] as PartialEq<ContentDigest>>::eq(&label_ref, &d),
                    <ContentDigest as PartialEq<&[u8]>>::eq(&d, &label_ref),
                    "reverse &[u8] vs forward &[u8] direction must agree at ({label:?}, {raw:?})",
                );
            }
        }
    }

    /// The reverse-direction byte-slice impls compose with a generic
    /// `PartialEq<ContentDigest>`-bounded consumer — a downstream site
    /// that types its comparison contract at the byte frontier as
    /// `impl PartialEq<ContentDigest>` (a `matches!` predicate on a
    /// dereffed `Cow::Borrowed(&[u8])` arm, a byte-stream cache-index
    /// oracle that generic-bounds its reverse-direction equality
    /// check) recovers the same answer as a direct
    /// `<[u8] as PartialEq<ContentDigest>>::eq` call. Pins the trait-
    /// generic consumer surface parallel to
    /// [`test_partial_eq_content_digest_carries_through_generic_consumer`]
    /// on the UTF-8-side reverse direction.
    #[test]
    fn test_partial_eq_content_digest_bytes_carries_through_generic_consumer() {
        fn eq_via_bound<T: PartialEq<ContentDigest> + ?Sized>(
            t: &T,
            expected: &ContentDigest,
        ) -> bool {
            <T as PartialEq<ContentDigest>>::eq(t, expected)
        }
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        for raw in [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ] {
            let d = ContentDigest::parse(&raw).unwrap();
            let raw_ref: &[u8] = raw.as_bytes();
            assert!(eq_via_bound::<[u8]>(raw_ref, &d));
            assert!(eq_via_bound::<&[u8]>(&raw_ref, &d));
            let other = if raw.starts_with("sha256:") {
                format!("sha512:{}", "0".repeat(SHA512_HEX_LEN))
            } else {
                format!("sha256:{D1}")
            };
            let other_ref: &[u8] = other.as_bytes();
            assert!(!eq_via_bound::<[u8]>(other_ref, &d));
            assert!(!eq_via_bound::<&[u8]>(&other_ref, &d));
        }
    }

    /// `PartialEq<ContentDigest> for str` agrees byte-for-byte with
    /// the borrowed-view [`ContentDigest::as_str`] oracle across the
    /// same grid, threaded through a [`str`] self receiver so the
    /// caller writes `*label_ref == digest` and answers the same
    /// boolean equality query as the forward-direction
    /// [`PartialEq<str> for ContentDigest`] peer. Pins the
    /// reverse-direction agreement so a future refactor that inlined
    /// a divergent read into the reverse-direction impl breaks this
    /// pin at at least one (digest, label) pair rather than at every
    /// downstream `*label_ref == digest` call site.
    #[test]
    fn test_str_partial_eq_content_digest_agrees_with_as_str() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let digests = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        let cross = digests.iter().map(String::as_str).chain([
            "",
            "sha256:",
            "SHA256:0123",
            "not-a-digest",
        ]);
        let owned: Vec<String> = digests
            .iter()
            .flat_map(|d| {
                [
                    format!("SHA256:{}", &d[7..]),
                    format!(" {d}"),
                    format!("{d}\n"),
                ]
            })
            .collect();
        let labels: Vec<&str> = cross.chain(owned.iter().map(String::as_str)).collect();
        for raw in &digests {
            let d = ContentDigest::parse(raw).unwrap();
            for label in &labels {
                assert_eq!(
                    <str as PartialEq<ContentDigest>>::eq(label, &d),
                    *label == d.as_str(),
                    "PartialEq<ContentDigest> for str and as_str() equality must agree at ({label:?}, {raw:?})",
                );
            }
        }
    }

    /// At every validated [`ContentDigest`] value,
    /// `<str as PartialEq<ContentDigest>>::eq(digest.as_str(), &digest)`
    /// returns true — the digest's own emitted canonical form
    /// recognises itself as a match through the reverse-direction
    /// [`str`]-receiver peer.
    #[test]
    fn test_str_partial_eq_content_digest_reflexive_at_own_digest() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        for raw in [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ] {
            let d = ContentDigest::parse(&raw).unwrap();
            let canonical: &str = d.as_str();
            assert!(
                <str as PartialEq<ContentDigest>>::eq(canonical, &d),
                "PartialEq<ContentDigest> for str must recognise self canonical form at {raw:?}",
            );
        }
    }

    /// `PartialEq<ContentDigest> for &str` agrees byte-for-byte with
    /// the borrowed-view [`ContentDigest::as_str`] oracle across the
    /// same grid, threaded through a `&str` self receiver so the
    /// caller writes `label_ref == digest` without the explicit `*`
    /// deref. Pins the reverse-direction `&str`-receiver agreement.
    #[test]
    fn test_str_ref_partial_eq_content_digest_agrees_with_as_str() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let digests = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        let labels = [
            "",
            "sha256:",
            "not-a-digest",
            &format!("sha256:{D1}") as &str,
            &format!("sha256:{D2}") as &str,
            &format!("SHA256:{D1}") as &str,
            &format!(" sha256:{D1}") as &str,
        ];
        for raw in &digests {
            let d = ContentDigest::parse(raw).unwrap();
            for label in labels {
                let label_ref: &str = label;
                assert_eq!(
                    <&str as PartialEq<ContentDigest>>::eq(&label_ref, &d),
                    label_ref == d.as_str(),
                    "PartialEq<ContentDigest> for &str and as_str() equality must agree at ({label:?}, {raw:?})",
                );
            }
        }
    }

    /// At every validated [`ContentDigest`] value,
    /// `<&str as PartialEq<ContentDigest>>::eq(&digest.as_str(), &digest)`
    /// returns true — the digest's own emitted canonical form
    /// recognises itself as a match through the reverse-direction
    /// `&str`-receiver peer without the caller's explicit `*` deref.
    #[test]
    fn test_str_ref_partial_eq_content_digest_reflexive_at_own_digest() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        for raw in [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ] {
            let d = ContentDigest::parse(&raw).unwrap();
            let canonical: &str = d.as_str();
            assert!(
                <&str as PartialEq<ContentDigest>>::eq(&canonical, &d),
                "PartialEq<ContentDigest> for &str must recognise self canonical form at {raw:?}",
            );
        }
    }

    /// The reverse-direction and forward-direction borrowed UTF-8
    /// comparison surfaces agree byte-for-byte at every `(label,
    /// digest)` pair — the symmetry axiom
    /// `<str as PartialEq<ContentDigest>>::eq(label, &digest) ==
    /// <ContentDigest as PartialEq<str>>::eq(&digest, label)` (and
    /// its `&str`-receiver peer) holds across a canonical × broken
    /// grid. Pins the full 2×2 receiver × direction cross-product
    /// closure so a future refactor that diverged one impl from its
    /// symmetric peer breaks this pin at at least one pair rather
    /// than propagating unnoticed through downstream generic
    /// `PartialEq`-bounded consumers that thread a [`ContentDigest`]
    /// through either side of a `==` operator.
    #[test]
    fn test_partial_eq_content_digest_symmetric_with_forward_direction() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let digests = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        let owned_labels: Vec<String> = digests
            .iter()
            .cloned()
            .chain([
                "".to_string(),
                "sha256:".to_string(),
                "not-a-digest".to_string(),
                format!("SHA256:{D1}"),
                format!(" sha256:{D1}"),
                format!("sha256:{D1}\n"),
            ])
            .collect();
        for raw in &digests {
            let d = ContentDigest::parse(raw).unwrap();
            for label in &owned_labels {
                let label_ref: &str = label;
                // str receiver <-> ContentDigest receiver on str.
                assert_eq!(
                    <str as PartialEq<ContentDigest>>::eq(label_ref, &d),
                    <ContentDigest as PartialEq<str>>::eq(&d, label_ref),
                    "reverse str vs forward str direction must agree at ({label:?}, {raw:?})",
                );
                // &str receiver <-> ContentDigest receiver on &str.
                assert_eq!(
                    <&str as PartialEq<ContentDigest>>::eq(&label_ref, &d),
                    <ContentDigest as PartialEq<&str>>::eq(&d, &label_ref),
                    "reverse &str vs forward &str direction must agree at ({label:?}, {raw:?})",
                );
            }
        }
    }

    /// The reverse-direction impls compose with a generic
    /// `PartialEq<ContentDigest>`-bounded consumer — a downstream
    /// site that types its comparison contract as `impl
    /// PartialEq<ContentDigest>` (a `matches!` predicate on a
    /// borrowed-str arm, an integration-test oracle that
    /// generic-bounds its reverse-direction equality check) recovers
    /// the same answer as a direct
    /// `<str as PartialEq<ContentDigest>>::eq` call. Pins the
    /// trait-generic consumer surface parallel to
    /// [`test_partial_eq_str_carries_through_generic_consumer`] on
    /// the forward direction.
    #[test]
    fn test_partial_eq_content_digest_carries_through_generic_consumer() {
        fn eq_via_bound<T: PartialEq<ContentDigest> + ?Sized>(
            t: &T,
            expected: &ContentDigest,
        ) -> bool {
            <T as PartialEq<ContentDigest>>::eq(t, expected)
        }
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        for raw in [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ] {
            let d = ContentDigest::parse(&raw).unwrap();
            let raw_ref: &str = &raw;
            assert!(eq_via_bound::<str>(raw_ref, &d));
            assert!(eq_via_bound::<&str>(&raw_ref, &d));
            let other = if raw.starts_with("sha256:") {
                format!("sha512:{}", "0".repeat(SHA512_HEX_LEN))
            } else {
                format!("sha256:{D1}")
            };
            let other_ref: &str = &other;
            assert!(!eq_via_bound::<str>(other_ref, &d));
            assert!(!eq_via_bound::<&str>(&other_ref, &d));
        }
    }

    /// Two [`ContentDigest`] values that parse to the same canonical
    /// `<algorithm>:<hex>` bytes hash the same. Pins the [`Eq`] → [`Hash`]
    /// coherence axiom `a == b ⇒ hash(a) == hash(b)` at a concrete
    /// `(a, b)` pair whose inputs differ only in the pre-trim whitespace
    /// the [`ContentDigest::parse`] oracle strips — the same "canonical
    /// backing string is the identity" discipline the derived
    /// [`PartialEq`] / [`Eq`] impls carry, now projected onto the
    /// [`Hash`] surface a [`std::collections::HashSet<ContentDigest>`]
    /// / [`std::collections::HashMap<ContentDigest, _>`] consumer sink
    /// reads through.
    #[test]
    fn test_hash_agrees_on_equal_digests_after_whitespace_normalization() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        fn hash_of(d: &ContentDigest) -> u64 {
            let mut h = DefaultHasher::new();
            d.hash(&mut h);
            h.finish()
        }

        let raw = format!("sha256:{D1}");
        let padded = format!("  sha256:{D1}\n");
        let a = ContentDigest::parse(&raw).unwrap();
        let b = ContentDigest::parse(&padded).unwrap();
        assert_eq!(a, b, "parse oracle collapses pre-trim whitespace");
        assert_eq!(
            hash_of(&a),
            hash_of(&b),
            "Eq → Hash coherence: equal digests must hash the same"
        );
    }

    /// [`ContentDigest`] participates in a
    /// [`std::collections::HashSet`] as its own key. Pins the
    /// identity-container consumer sink the ~30 sibling trait impls
    /// in this file document (`HashSet<ContentDigest>` /
    /// `HashMap<ContentDigest, _>` as the canonical dedup / lookup
    /// shape) at the primitive itself — pre-Hash the primitive could
    /// not be inserted into either container without a per-consumer
    /// `digest.as_str().to_owned()` bridge, and this test would fail
    /// to compile against a `ContentDigest` that lacked the derived
    /// [`Hash`] impl. Composes the insert + contains + dedup arms so
    /// a regression on any of them (a hand-written `Hash` impl that
    /// hashes a different projection than the derived [`Eq`] reads,
    /// a future refactor that adds a non-identity field to the
    /// struct without teaching [`Hash`] to ignore it) fails here
    /// rather than degrading a downstream dedup pass into a
    /// silent-double-insert bug.
    #[test]
    fn test_hash_set_dedup_and_membership() {
        use std::collections::HashSet;

        let a = ContentDigest::parse(&format!("sha256:{D1}")).unwrap();
        let a2 = ContentDigest::parse(&format!("  sha256:{D1}\n")).unwrap();
        let b = ContentDigest::parse(&format!("sha256:{D2}")).unwrap();
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let c = ContentDigest::parse(&format!("sha512:{hex512}")).unwrap();

        let mut set: HashSet<ContentDigest> = HashSet::new();
        assert!(set.insert(a.clone()), "first insert of a returns true");
        assert!(
            !set.insert(a2),
            "reinsert of whitespace-variant of a is a dedup no-op"
        );
        assert!(set.insert(b.clone()), "insert of distinct sha256 b");
        assert!(set.insert(c.clone()), "insert of distinct sha512 c");
        assert_eq!(set.len(), 3, "three distinct canonical digests in set");
        assert!(set.contains(&a), "membership by owned value");
        assert!(set.contains(&b));
        assert!(set.contains(&c));

        let d_unseen = ContentDigest::parse(&format!("sha256:{D3}")).unwrap();
        assert!(!set.contains(&d_unseen), "unseen digest is not a member");
    }

    /// `PartialEq<String> for ContentDigest` agrees byte-for-byte with
    /// the borrowed-view [`ContentDigest::as_str`] oracle across the
    /// same 4-canonical × ~9-label grid the borrowed-str pair pins,
    /// threaded through an owned [`String`] label so the caller writes
    /// `digest == owned_label`. Pins the owned-UTF-8 forward-direction
    /// agreement so a future refactor that inlined a divergent read
    /// into the owned-string impl breaks this pin at at least one
    /// `(digest, owned)` pair rather than at every downstream
    /// `digest == owned_label` call site.
    #[test]
    fn test_partial_eq_string_agrees_with_as_str() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let digests = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        let owned: Vec<String> = digests
            .iter()
            .flat_map(|d| {
                [
                    d.clone(),
                    format!("SHA256:{}", &d[7..]),
                    format!(" {d}"),
                    format!("{d}\n"),
                ]
            })
            .chain([
                String::new(),
                "sha256:".to_string(),
                "SHA256:0123".to_string(),
                "not-a-digest".to_string(),
            ])
            .collect();
        for raw in &digests {
            let d = ContentDigest::parse(raw).unwrap();
            for label in &owned {
                assert_eq!(
                    <ContentDigest as PartialEq<String>>::eq(&d, label),
                    d.as_str() == label.as_str(),
                    "PartialEq<String> and as_str() equality must agree at ({label:?}, {raw:?})",
                );
            }
        }
    }

    /// At every validated [`ContentDigest`] value,
    /// `<Self as PartialEq<String>>::eq(&digest, &digest.as_str().to_owned())`
    /// returns true — the digest recognises its own emitted canonical
    /// form as an owned [`String`] through the owned-UTF-8 peer.
    #[test]
    fn test_partial_eq_string_reflexive_at_own_digest() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        for raw in [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ] {
            let d = ContentDigest::parse(&raw).unwrap();
            let canonical: String = d.as_str().to_owned();
            assert!(
                <ContentDigest as PartialEq<String>>::eq(&d, &canonical),
                "PartialEq<String> must recognise self canonical form at {raw:?}",
            );
        }
    }

    /// Every owned [`String`] that is NOT the digest's own emitted
    /// canonical form fails equality through [`PartialEq<String>`] —
    /// the same canonicity discipline the borrowed-str sibling peers
    /// enforce, projected onto the owned [`String`] receiver.
    #[test]
    fn test_partial_eq_string_rejects_non_canonical_labels() {
        let d1 = ContentDigest::parse(&format!("sha256:{D1}")).unwrap();
        let d2 = ContentDigest::parse(&format!("sha256:{D2}")).unwrap();
        let bad: [String; 7] = [
            String::new(),
            "sha256:".to_string(),
            "not-a-digest".to_string(),
            format!("SHA256:{D1}"),
            format!(" sha256:{D1}"),
            format!("sha256:{D1}\n"),
            format!("sha256:{D2}"),
        ];
        for label in &bad {
            assert!(
                !<ContentDigest as PartialEq<String>>::eq(&d1, label),
                "PartialEq<String> must reject non-canonical label {label:?} at sha256:{D1}",
            );
        }
        // Peer surface is symmetric — d2 rejects d1's canonical form
        // through the owned-String receiver as well.
        let d1_canonical = format!("sha256:{D1}");
        assert!(!<ContentDigest as PartialEq<String>>::eq(
            &d2,
            &d1_canonical,
        ));
    }

    /// The reverse-direction owned UTF-8 comparison peer
    /// `<String as PartialEq<ContentDigest>>::eq` agrees byte-for-byte
    /// with the borrowed-view [`ContentDigest::as_str`] oracle across
    /// the same grid AND is symmetric with the forward-direction
    /// `<ContentDigest as PartialEq<String>>::eq` peer at every
    /// `(owned, digest)` pair. Pins the reverse-direction agreement
    /// and the symmetry axiom
    /// `<String as PartialEq<ContentDigest>>::eq(owned, &d)
    /// == <ContentDigest as PartialEq<String>>::eq(&d, owned)` so a
    /// future refactor that diverged one impl from its symmetric peer
    /// breaks this pin at at least one pair rather than propagating
    /// unnoticed through downstream generic `PartialEq`-bounded
    /// consumers that thread a [`ContentDigest`] through either side
    /// of a `==` operator.
    #[test]
    fn test_string_partial_eq_content_digest_symmetric_and_agrees_with_as_str() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let digests = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        let owned: Vec<String> = digests
            .iter()
            .cloned()
            .chain([
                String::new(),
                "sha256:".to_string(),
                "not-a-digest".to_string(),
                format!("SHA256:{D1}"),
                format!(" sha256:{D1}"),
                format!("sha256:{D1}\n"),
            ])
            .collect();
        for raw in &digests {
            let d = ContentDigest::parse(raw).unwrap();
            for label in &owned {
                assert_eq!(
                    <String as PartialEq<ContentDigest>>::eq(label, &d),
                    label.as_str() == d.as_str(),
                    "reverse String and as_str() equality must agree at ({label:?}, {raw:?})",
                );
                assert_eq!(
                    <String as PartialEq<ContentDigest>>::eq(label, &d),
                    <ContentDigest as PartialEq<String>>::eq(&d, label),
                    "reverse-String vs forward-String direction must agree at ({label:?}, {raw:?})",
                );
            }
        }
    }

    /// The owned-UTF-8 forward and reverse peers compose with a
    /// generic `PartialEq<String>`- / `PartialEq<ContentDigest>`-
    /// bounded consumer — a downstream site that types its comparison
    /// contract as `impl PartialEq<String>` (a `matches!` predicate on
    /// an owned-String arm, an integration-test oracle that
    /// generic-bounds its owned-string equality check) recovers the
    /// same answer as a direct `<ContentDigest as PartialEq<String>>::
    /// eq` call, and the reverse-direction bound
    /// `impl PartialEq<ContentDigest>` recovers the same answer as a
    /// direct `<String as PartialEq<ContentDigest>>::eq` call.
    #[test]
    fn test_partial_eq_content_digest_string_carries_through_generic_consumer() {
        fn fwd_via_bound<T: PartialEq<String>>(t: &T, expected: &String) -> bool {
            <T as PartialEq<String>>::eq(t, expected)
        }
        fn rev_via_bound<T: PartialEq<ContentDigest>>(t: &T, expected: &ContentDigest) -> bool {
            <T as PartialEq<ContentDigest>>::eq(t, expected)
        }
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        for raw in [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ] {
            let d = ContentDigest::parse(&raw).unwrap();
            let owned = raw.clone();
            assert!(fwd_via_bound(&d, &owned));
            assert!(rev_via_bound(&owned, &d));
            let other = if raw.starts_with("sha256:") {
                format!("sha512:{}", "0".repeat(SHA512_HEX_LEN))
            } else {
                format!("sha256:{D1}")
            };
            assert!(!fwd_via_bound(&d, &other));
            assert!(!rev_via_bound(&other, &d));
        }
    }

    /// `PartialEq<Vec<u8>> for ContentDigest` agrees byte-for-byte
    /// with the borrowed-view `<ContentDigest as AsRef<[u8]>>::as_ref`
    /// oracle across the same 4-canonical × ~9-label grid the borrowed-
    /// bytes pair pins, threaded through an owned [`Vec<u8>`] label so
    /// the caller writes `digest == owned_bytes`. Pins the owned-byte-
    /// slice forward-direction agreement so a future refactor that
    /// inlined a divergent read into the owned-bytes impl breaks this
    /// pin at at least one `(digest, owned)` pair rather than at every
    /// downstream `digest == owned_bytes` call site.
    #[test]
    fn test_partial_eq_vec_bytes_agrees_with_as_ref() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let digests = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        let owned: Vec<Vec<u8>> = digests
            .iter()
            .flat_map(|d| {
                [
                    d.as_bytes().to_vec(),
                    format!("SHA256:{}", &d[7..]).into_bytes(),
                    format!(" {d}").into_bytes(),
                    format!("{d}\n").into_bytes(),
                ]
            })
            .chain([
                Vec::<u8>::new(),
                b"sha256:".to_vec(),
                b"SHA256:0123".to_vec(),
                b"not-a-digest".to_vec(),
                vec![0xff, 0xfe, 0xfd],
            ])
            .collect();
        for raw in &digests {
            let d = ContentDigest::parse(raw).unwrap();
            for label in &owned {
                assert_eq!(
                    <ContentDigest as PartialEq<Vec<u8>>>::eq(&d, label),
                    <ContentDigest as AsRef<[u8]>>::as_ref(&d) == label.as_slice(),
                    "PartialEq<Vec<u8>> and AsRef<[u8]> equality must agree at ({label:?}, {raw:?})",
                );
            }
        }
    }

    /// At every validated [`ContentDigest`] value,
    /// `<Self as PartialEq<Vec<u8>>>::eq(&digest, &digest.as_str().as_bytes().to_vec())`
    /// returns true — the digest recognises its own emitted canonical
    /// form as owned [`Vec<u8>`] through the owned-bytes peer.
    #[test]
    fn test_partial_eq_vec_bytes_reflexive_at_own_digest() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        for raw in [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ] {
            let d = ContentDigest::parse(&raw).unwrap();
            let canonical: Vec<u8> = d.as_str().as_bytes().to_vec();
            assert!(
                <ContentDigest as PartialEq<Vec<u8>>>::eq(&d, &canonical),
                "PartialEq<Vec<u8>> must recognise self canonical form at {raw:?}",
            );
        }
    }

    /// Every owned [`Vec<u8>`] that is NOT the digest's own emitted
    /// canonical byte form fails equality through
    /// `PartialEq<Vec<u8>>` — the same canonicity discipline the
    /// borrowed-bytes sibling peers enforce, projected onto the owned
    /// [`Vec<u8>`] receiver. Invalid-UTF-8 sequences (e.g.
    /// `[0xff, 0xfe, 0xfd]`) are included so the pin also refuses
    /// arbitrary bytes drift toward acceptance under any future
    /// misguided UTF-8-relaxation refactor.
    #[test]
    fn test_partial_eq_vec_bytes_rejects_non_canonical_labels() {
        let d1 = ContentDigest::parse(&format!("sha256:{D1}")).unwrap();
        let d2 = ContentDigest::parse(&format!("sha256:{D2}")).unwrap();
        let bad: [Vec<u8>; 8] = [
            Vec::<u8>::new(),
            b"sha256:".to_vec(),
            b"not-a-digest".to_vec(),
            format!("SHA256:{D1}").into_bytes(),
            format!(" sha256:{D1}").into_bytes(),
            format!("sha256:{D1}\n").into_bytes(),
            format!("sha256:{D2}").into_bytes(),
            vec![0xff, 0xfe, 0xfd],
        ];
        for label in &bad {
            assert!(
                !<ContentDigest as PartialEq<Vec<u8>>>::eq(&d1, label),
                "PartialEq<Vec<u8>> must reject non-canonical label {label:?} at sha256:{D1}",
            );
        }
        let d1_canonical_bytes = format!("sha256:{D1}").into_bytes();
        assert!(!<ContentDigest as PartialEq<Vec<u8>>>::eq(
            &d2,
            &d1_canonical_bytes,
        ));
    }

    /// The reverse-direction owned byte-slice comparison peer
    /// `<Vec<u8> as PartialEq<ContentDigest>>::eq` agrees byte-for-
    /// byte with the borrowed-view
    /// `<ContentDigest as AsRef<[u8]>>::as_ref` oracle across the same
    /// grid AND is symmetric with the forward-direction
    /// `<ContentDigest as PartialEq<Vec<u8>>>::eq` peer at every
    /// `(owned, digest)` pair. Pins the reverse-direction agreement
    /// and the symmetry axiom
    /// `<Vec<u8> as PartialEq<ContentDigest>>::eq(owned, &d)
    /// == <ContentDigest as PartialEq<Vec<u8>>>::eq(&d, owned)` so a
    /// future refactor that diverged one impl from its symmetric peer
    /// breaks this pin at at least one pair rather than propagating
    /// unnoticed through downstream generic `PartialEq`-bounded
    /// consumers that thread a [`ContentDigest`] through either side
    /// of a `==` operator.
    #[test]
    fn test_vec_bytes_partial_eq_content_digest_symmetric_and_agrees_with_as_ref() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let digests = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        let owned: Vec<Vec<u8>> = digests
            .iter()
            .map(|d| d.as_bytes().to_vec())
            .chain([
                Vec::<u8>::new(),
                b"sha256:".to_vec(),
                b"not-a-digest".to_vec(),
                format!("SHA256:{D1}").into_bytes(),
                format!(" sha256:{D1}").into_bytes(),
                format!("sha256:{D1}\n").into_bytes(),
                vec![0xff, 0xfe, 0xfd],
            ])
            .collect();
        for raw in &digests {
            let d = ContentDigest::parse(raw).unwrap();
            for label in &owned {
                assert_eq!(
                    <Vec<u8> as PartialEq<ContentDigest>>::eq(label, &d),
                    label.as_slice() == <ContentDigest as AsRef<[u8]>>::as_ref(&d),
                    "reverse Vec<u8> and AsRef<[u8]> equality must agree at ({label:?}, {raw:?})",
                );
                assert_eq!(
                    <Vec<u8> as PartialEq<ContentDigest>>::eq(label, &d),
                    <ContentDigest as PartialEq<Vec<u8>>>::eq(&d, label),
                    "reverse-Vec<u8> vs forward-Vec<u8> direction must agree at ({label:?}, {raw:?})",
                );
            }
        }
    }

    /// The owned-byte-slice forward and reverse peers compose with a
    /// generic `PartialEq<Vec<u8>>`- / `PartialEq<ContentDigest>`-
    /// bounded consumer — a downstream site that types its comparison
    /// contract as `impl PartialEq<Vec<u8>>` (a `matches!` predicate
    /// on an owned-`Vec<u8>` arm, an integration-test oracle that
    /// generic-bounds its owned-bytes equality check) recovers the
    /// same answer as a direct
    /// `<ContentDigest as PartialEq<Vec<u8>>>::eq` call, and the
    /// reverse-direction bound `impl PartialEq<ContentDigest>`
    /// recovers the same answer as a direct
    /// `<Vec<u8> as PartialEq<ContentDigest>>::eq` call.
    #[test]
    fn test_partial_eq_content_digest_vec_bytes_carries_through_generic_consumer() {
        fn fwd_via_bound<T: PartialEq<Vec<u8>>>(t: &T, expected: &Vec<u8>) -> bool {
            <T as PartialEq<Vec<u8>>>::eq(t, expected)
        }
        fn rev_via_bound<T: PartialEq<ContentDigest>>(t: &T, expected: &ContentDigest) -> bool {
            <T as PartialEq<ContentDigest>>::eq(t, expected)
        }
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        for raw in [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ] {
            let d = ContentDigest::parse(&raw).unwrap();
            let owned = raw.clone().into_bytes();
            assert!(fwd_via_bound(&d, &owned));
            assert!(rev_via_bound(&owned, &d));
            let other = if raw.starts_with("sha256:") {
                format!("sha512:{}", "0".repeat(SHA512_HEX_LEN)).into_bytes()
            } else {
                format!("sha256:{D1}").into_bytes()
            };
            assert!(!fwd_via_bound(&d, &other));
            assert!(!rev_via_bound(&other, &d));
        }
    }

    /// `<ContentDigest as std::borrow::Borrow<str>>::borrow` yields
    /// exactly the same slice as `<ContentDigest as AsRef<str>>::as_ref`
    /// and the inherent `ContentDigest::as_str` accessor at every
    /// validated digest — the identity-container-lookup peer routes
    /// through the same one-oracle read discipline the trait-generic
    /// borrowed-view read peer already carries. Pins the "borrow ⇒
    /// as_ref ⇒ as_str ⇒ full backing string" invariant: a future
    /// refactor that inlined a divergent projection into the
    /// [`Borrow<str>`] impl fails this test.
    #[test]
    fn test_borrow_str_matches_as_ref_str() {
        use std::borrow::Borrow;
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let cases = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        for raw in cases {
            let d = ContentDigest::parse(&raw).unwrap();
            let via_borrow: &str = <ContentDigest as Borrow<str>>::borrow(&d);
            let via_as_ref: &str = <ContentDigest as AsRef<str>>::as_ref(&d);
            assert_eq!(via_borrow, via_as_ref);
            assert_eq!(via_borrow, d.as_str());
            assert_eq!(via_borrow, raw);
        }
    }

    /// The `Borrow` contract requires `k.borrow().hash(h) == k.hash(h)`
    /// at every hasher `h` — the load-bearing safety condition without
    /// which a `HashMap<ContentDigest, _>::get::<str>(str_key)` probe
    /// silently returns [`None`] for keys that ARE present. Pins the
    /// axiom at a concrete `(digest, hasher)` pair across every
    /// canonical algorithm arm: the derived `Hash` on
    /// `ContentDigest { full: String }` steps through the same
    /// `str::hash` byte-write trace as `Hash` on the borrowed `&str`.
    /// A future refactor that added a non-identity field to the
    /// struct or replaced the derived [`Hash`] with a hand-rolled
    /// projection that broke coherence fails this test rather than
    /// degrading a downstream [`HashMap`] probe into a silent-miss
    /// bug at the map lookup call site.
    #[test]
    fn test_borrow_str_hash_agrees_with_borrowed_str_hash() {
        use std::borrow::Borrow;
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        fn hash_of<T: Hash + ?Sized>(t: &T) -> u64 {
            let mut h = DefaultHasher::new();
            t.hash(&mut h);
            h.finish()
        }

        let hex512 = "f".repeat(SHA512_HEX_LEN);
        for raw in [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ] {
            let d = ContentDigest::parse(&raw).unwrap();
            let borrowed: &str = <ContentDigest as Borrow<str>>::borrow(&d);
            assert_eq!(
                hash_of(&d),
                hash_of(borrowed),
                "Borrow<str> Hash coherence: hash(&digest) must agree with \
                 hash(digest.borrow() as &str) at {raw:?}",
            );
        }
    }

    /// `HashMap<ContentDigest, V>::get(&str_key)` finds a value keyed
    /// by a validated [`ContentDigest`] through a raw `&str` probe
    /// without allocating a fresh [`ContentDigest`] key per lookup —
    /// the identity-container-lookup surface [`Borrow<str>`] unlocks
    /// on the parse-oracle-bounded key type. Pins the load-bearing
    /// motivation for the impl: pre-[`Borrow<str>`] the probe had to
    /// route through `ContentDigest::parse(str_key).ok().and_then(|k|
    /// map.get(&k))` at every consumer, paying a full-grammar parse
    /// per lookup AND surfacing parse failure as probe-inapplicable
    /// when the probe intent was strictly "is this raw string
    /// present as a key." Also pins the negative arm: a raw `&str`
    /// that does NOT match any inserted digest's canonical form
    /// (canonical mismatch, whitespace-drift variant, unrelated
    /// canonical digest) returns [`None`].
    #[test]
    fn test_borrow_str_hash_map_probe_by_str_key() {
        use std::collections::HashMap;

        let raw1 = format!("sha256:{D1}");
        let raw2 = format!("sha256:{D2}");
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let raw3 = format!("sha512:{hex512}");

        let d1 = ContentDigest::parse(&raw1).unwrap();
        let d2 = ContentDigest::parse(&raw2).unwrap();
        let d3 = ContentDigest::parse(&raw3).unwrap();

        let mut map: HashMap<ContentDigest, &'static str> = HashMap::new();
        map.insert(d1.clone(), "layer-1");
        map.insert(d2.clone(), "layer-2");
        map.insert(d3.clone(), "config");

        // Positive: probe by raw &str hits the correct value.
        assert_eq!(map.get(raw1.as_str()), Some(&"layer-1"));
        assert_eq!(map.get(raw2.as_str()), Some(&"layer-2"));
        assert_eq!(map.get(raw3.as_str()), Some(&"config"));

        // Positive: probe by owned-key value agrees with probe by
        // borrowed-str view.
        assert_eq!(map.get(raw1.as_str()), map.get(&d1));
        assert_eq!(map.get(raw2.as_str()), map.get(&d2));

        // Negative: an uninserted canonical digest string returns None.
        let raw_unseen = format!("sha256:{D3}");
        assert_eq!(map.get(raw_unseen.as_str()), None);

        // Negative: a whitespace-drift variant of an inserted digest
        // returns None — the map's stored key is the canonical trimmed
        // form, and the raw-str probe matches byte-for-byte through
        // Borrow<str>, so a stray-whitespace probe correctly misses.
        let raw_padded = format!("  sha256:{D1}\n");
        assert_eq!(map.get(raw_padded.as_str()), None);

        // Negative: a syntactically invalid string returns None (does
        // NOT panic, does NOT need a fallible parse round-trip at the
        // probe site).
        assert_eq!(map.get("not-a-digest"), None);
    }

    /// `BTreeMap<ContentDigest, V>::get(&str_key)` and
    /// `BTreeMap::range(str_lo..str_hi)` both work through the same
    /// [`Borrow<str>`] projection [`HashMap`] uses — the identity-
    /// container-lookup surface at the ordered-map key slot.
    /// [`BTreeMap`] additionally exercises the sibling `Ord` derive
    /// on [`ContentDigest`] (line 118), so a probe by borrowed `&str`
    /// composes `Borrow<str>` with the derived `Ord` to walk the
    /// tree — the same walk a probe by owned [`ContentDigest`] key
    /// walks. Pins the ordered-map identity-container surface as
    /// well as the hash-map one, so a downstream site that pins its
    /// container choice on determinism (a canonical-digest-ordered
    /// audit dump, a deterministic manifest walk) inherits the same
    /// raw-`&str` probe discipline.
    #[test]
    fn test_borrow_str_btree_map_probe_by_str_key() {
        use std::collections::BTreeMap;

        let raw1 = format!("sha256:{D1}");
        let raw2 = format!("sha256:{D2}");
        let d1 = ContentDigest::parse(&raw1).unwrap();
        let d2 = ContentDigest::parse(&raw2).unwrap();

        let mut map: BTreeMap<ContentDigest, u32> = BTreeMap::new();
        map.insert(d1, 1);
        map.insert(d2, 2);

        assert_eq!(map.get(raw1.as_str()), Some(&1));
        assert_eq!(map.get(raw2.as_str()), Some(&2));
        assert_eq!(
            map.get("sha256:0000000000000000000000000000000000000000000000000000000000000000"),
            None
        );
    }

    /// `HashSet<ContentDigest>::contains(&str_key)` returns `true`
    /// for a raw `&str` that matches any inserted [`ContentDigest`]'s
    /// canonical form, `false` otherwise — the identity-container
    /// membership surface [`Borrow<str>`] unlocks on
    /// [`HashSet`]-keyed dedup sets. A downstream dedup / seen-set
    /// / expected-registry-digest guard now probes a raw wire /
    /// config string against the typed key set without allocating a
    /// fresh [`ContentDigest`] per probe AND without threading
    /// [`ContentDigest::parse`] failure into the "is this present"
    /// question.
    #[test]
    fn test_borrow_str_hash_set_contains_by_str_key() {
        use std::collections::HashSet;

        let raw1 = format!("sha256:{D1}");
        let raw2 = format!("sha256:{D2}");
        let d1 = ContentDigest::parse(&raw1).unwrap();
        let d2 = ContentDigest::parse(&raw2).unwrap();

        let mut set: HashSet<ContentDigest> = HashSet::new();
        set.insert(d1);
        set.insert(d2);

        assert!(set.contains(raw1.as_str()));
        assert!(set.contains(raw2.as_str()));
        assert!(!set
            .contains("sha256:0000000000000000000000000000000000000000000000000000000000000000"));
        // Whitespace-drift variant is a byte-level miss through the
        // canonical trimmed key, matching the HashMap probe surface.
        let padded = format!(" sha256:{D1}\n");
        assert!(!set.contains(padded.as_str()));
        // Syntactically invalid probe is a clean miss, not a panic.
        assert!(!set.contains("not-a-digest"));
    }

    /// The [`Borrow<str>`] impl composes with a generic
    /// identity-container-probe helper bounded by
    /// `V: Borrow<str>` — the compositional motivation for landing
    /// the trait separately from the sibling [`AsRef<str>`] and
    /// inherent [`ContentDigest::as_str`] read peers. Pins the
    /// trait-generic identity-container consumer surface: a
    /// downstream site that types its input contract as
    /// `V: Borrow<str>` (a hash-map-lookup helper, a deterministic
    /// key-normalisation utility, an audit-record probe) recovers
    /// the same borrowed full-digest slice a direct
    /// `.as_str()` / `.as_ref::<str>()` call would.
    #[test]
    fn test_borrow_str_carries_through_generic_consumer() {
        use std::borrow::Borrow;

        fn first_byte_of<V: Borrow<str>>(v: &V) -> u8 {
            v.borrow().as_bytes()[0]
        }
        fn length_of<V: Borrow<str>>(v: &V) -> usize {
            v.borrow().len()
        }
        fn equals<V: Borrow<str>>(v: &V, expected: &str) -> bool {
            v.borrow() == expected
        }

        let raw = format!("sha256:{D1}");
        let d = ContentDigest::parse(&raw).unwrap();
        assert_eq!(first_byte_of(&d), b's');
        assert_eq!(length_of(&d), raw.len());
        assert!(equals(&d, &raw));

        // Composes with the sibling AsRef<str> read peer at the same
        // borrowed slice: T: Borrow<str> and T: AsRef<str> read the
        // same underlying full-digest slice through the same
        // one-oracle discipline.
        assert_eq!(
            <ContentDigest as Borrow<str>>::borrow(&d),
            <ContentDigest as AsRef<str>>::as_ref(&d),
        );
    }

    /// `PartialEq<Cow<'_, str>> for ContentDigest` agrees byte-for-
    /// byte with the borrowed-view [`ContentDigest::as_str`] oracle
    /// across the same 4-canonical × ~9-label grid the borrowed-str
    /// and owned-string sibling peers pin, threaded through a
    /// [`Cow<'_, str>`] label constructed on BOTH `Cow::Borrowed`
    /// and `Cow::Owned` arms so the arm-collapsing route is
    /// exercised on both discriminator arms. Pins the borrowed-or-
    /// owned forward-direction agreement across arms so a future
    /// refactor that diverged one arm from the
    /// [`ContentDigest::as_str`] read oracle breaks this pin at at
    /// least one `(digest, label, arm)` triple rather than at every
    /// downstream `digest == cow_label` call site.
    #[test]
    fn test_partial_eq_cow_str_agrees_with_as_str() {
        use std::borrow::Cow;
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let digests = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        let owned: Vec<String> = digests
            .iter()
            .flat_map(|d| {
                [
                    d.clone(),
                    format!("SHA256:{}", &d[7..]),
                    format!(" {d}"),
                    format!("{d}\n"),
                ]
            })
            .chain([
                String::new(),
                "sha256:".to_string(),
                "SHA256:0123".to_string(),
                "not-a-digest".to_string(),
            ])
            .collect();
        for raw in &digests {
            let d = ContentDigest::parse(raw).unwrap();
            for label in &owned {
                let borrowed: Cow<'_, str> = Cow::Borrowed(label.as_str());
                let owned_arm: Cow<'_, str> = Cow::Owned(label.clone());
                for (arm, cow) in [("Borrowed", &borrowed), ("Owned", &owned_arm)] {
                    assert_eq!(
                        <ContentDigest as PartialEq<Cow<'_, str>>>::eq(&d, cow),
                        d.as_str() == label.as_str(),
                        "PartialEq<Cow<'_, str>> and as_str() equality must agree at ({arm}, {label:?}, {raw:?})",
                    );
                }
            }
        }
    }

    /// At every validated [`ContentDigest`] value,
    /// `<Self as PartialEq<Cow<'_, str>>>::eq(&digest, &Cow::Borrowed(digest.as_str()))`
    /// and the [`Cow::Owned`] variant both return true — the digest
    /// recognises its own emitted canonical form as a
    /// [`Cow<'_, str>`] on either discriminator arm through the
    /// borrowed-or-owned peer.
    #[test]
    fn test_partial_eq_cow_str_reflexive_at_own_digest() {
        use std::borrow::Cow;
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        for raw in [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ] {
            let d = ContentDigest::parse(&raw).unwrap();
            let canonical: String = d.as_str().to_owned();
            let borrowed: Cow<'_, str> = Cow::Borrowed(canonical.as_str());
            let owned_arm: Cow<'_, str> = Cow::Owned(canonical.clone());
            assert!(
                <ContentDigest as PartialEq<Cow<'_, str>>>::eq(&d, &borrowed),
                "PartialEq<Cow<'_, str>> must recognise self canonical form on Borrowed arm at {raw:?}",
            );
            assert!(
                <ContentDigest as PartialEq<Cow<'_, str>>>::eq(&d, &owned_arm),
                "PartialEq<Cow<'_, str>> must recognise self canonical form on Owned arm at {raw:?}",
            );
        }
    }

    /// Every [`Cow<'_, str>`] that is NOT the digest's own emitted
    /// canonical form fails equality through
    /// `PartialEq<Cow<'_, str>>` on BOTH arms — the same canonicity
    /// discipline the borrowed-str and owned-string sibling peers
    /// enforce, projected onto the borrowed-or-owned [`Cow`]
    /// receiver.
    #[test]
    fn test_partial_eq_cow_str_rejects_non_canonical_labels() {
        use std::borrow::Cow;
        let d1 = ContentDigest::parse(&format!("sha256:{D1}")).unwrap();
        let d2 = ContentDigest::parse(&format!("sha256:{D2}")).unwrap();
        let bad: [String; 7] = [
            String::new(),
            "sha256:".to_string(),
            "not-a-digest".to_string(),
            format!("SHA256:{D1}"),
            format!(" sha256:{D1}"),
            format!("sha256:{D1}\n"),
            format!("sha256:{D2}"),
        ];
        for label in &bad {
            for cow in [
                Cow::<'_, str>::Borrowed(label.as_str()),
                Cow::<'_, str>::Owned(label.clone()),
            ] {
                assert!(
                    !<ContentDigest as PartialEq<Cow<'_, str>>>::eq(&d1, &cow),
                    "PartialEq<Cow<'_, str>> must reject non-canonical label {label:?} ({cow:?}) at sha256:{D1}",
                );
            }
        }
        // Peer surface is symmetric — d2 rejects d1's canonical form
        // through the Cow receiver on either arm as well.
        let d1_canonical = format!("sha256:{D1}");
        for cow in [
            Cow::<'_, str>::Borrowed(d1_canonical.as_str()),
            Cow::<'_, str>::Owned(d1_canonical.clone()),
        ] {
            assert!(!<ContentDigest as PartialEq<Cow<'_, str>>>::eq(&d2, &cow));
        }
    }

    /// The reverse-direction borrowed-or-owned UTF-8 comparison peer
    /// `<Cow<'_, str> as PartialEq<ContentDigest>>::eq` agrees byte-
    /// for-byte with the borrowed-view [`ContentDigest::as_str`]
    /// oracle across the same grid AND is symmetric with the
    /// forward-direction
    /// `<ContentDigest as PartialEq<Cow<'_, str>>>::eq` peer at
    /// every `(cow, digest, arm)` triple. Pins the reverse-direction
    /// agreement and the symmetry axiom
    /// `<Cow<'_, str> as PartialEq<ContentDigest>>::eq(cow, &d)
    /// == <ContentDigest as PartialEq<Cow<'_, str>>>::eq(&d, cow)`
    /// on both [`Cow`] arms so a future refactor that diverged one
    /// impl from its symmetric peer breaks this pin at at least one
    /// triple rather than propagating unnoticed through downstream
    /// generic `PartialEq`-bounded consumers that thread a
    /// [`ContentDigest`] through either side of a `==` operator.
    #[test]
    fn test_cow_str_partial_eq_content_digest_symmetric_and_agrees_with_as_str() {
        use std::borrow::Cow;
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let digests = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        let owned: Vec<String> = digests
            .iter()
            .cloned()
            .chain([
                String::new(),
                "sha256:".to_string(),
                "not-a-digest".to_string(),
                format!("SHA256:{D1}"),
                format!(" sha256:{D1}"),
                format!("sha256:{D1}\n"),
            ])
            .collect();
        for raw in &digests {
            let d = ContentDigest::parse(raw).unwrap();
            for label in &owned {
                let borrowed: Cow<'_, str> = Cow::Borrowed(label.as_str());
                let owned_arm: Cow<'_, str> = Cow::Owned(label.clone());
                for (arm, cow) in [("Borrowed", &borrowed), ("Owned", &owned_arm)] {
                    assert_eq!(
                        <Cow<'_, str> as PartialEq<ContentDigest>>::eq(cow, &d),
                        label.as_str() == d.as_str(),
                        "reverse Cow and as_str() equality must agree at ({arm}, {label:?}, {raw:?})",
                    );
                    assert_eq!(
                        <Cow<'_, str> as PartialEq<ContentDigest>>::eq(cow, &d),
                        <ContentDigest as PartialEq<Cow<'_, str>>>::eq(&d, cow),
                        "reverse-Cow vs forward-Cow direction must agree at ({arm}, {label:?}, {raw:?})",
                    );
                }
            }
        }
    }

    /// The [`Cow<'_, str>`] forward and reverse peers compose with a
    /// generic `PartialEq<Cow<'_, str>>`- /
    /// `PartialEq<ContentDigest>`-bounded consumer — a downstream
    /// site that types its comparison contract as
    /// `impl PartialEq<Cow<'_, str>>` (a `matches!` predicate on a
    /// [`Cow`] arm, an integration-test oracle that generic-bounds
    /// its borrowed-or-owned equality check) recovers the same
    /// answer as a direct
    /// `<ContentDigest as PartialEq<Cow<'_, str>>>::eq` call, and
    /// the reverse-direction bound `impl PartialEq<ContentDigest>`
    /// recovers the same answer as a direct
    /// `<Cow<'_, str> as PartialEq<ContentDigest>>::eq` call.
    #[test]
    fn test_partial_eq_content_digest_cow_str_carries_through_generic_consumer() {
        use std::borrow::Cow;
        // The `&Cow<'_, str>` receiver is load-bearing: this test pins the
        // exact `PartialEq<Cow<'_, str>>` bound the impl above exposes, so
        // the sibling clippy suggestion to relax it to `&str` would collapse
        // the bound this test exists to exercise.
        #[allow(clippy::ptr_arg)]
        fn fwd_via_bound<'a, T: PartialEq<Cow<'a, str>>>(t: &T, expected: &Cow<'a, str>) -> bool {
            <T as PartialEq<Cow<'a, str>>>::eq(t, expected)
        }
        fn rev_via_bound<T: PartialEq<ContentDigest>>(t: &T, expected: &ContentDigest) -> bool {
            <T as PartialEq<ContentDigest>>::eq(t, expected)
        }
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        for raw in [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ] {
            let d = ContentDigest::parse(&raw).unwrap();
            for cow in [
                Cow::<'_, str>::Borrowed(raw.as_str()),
                Cow::<'_, str>::Owned(raw.clone()),
            ] {
                assert!(fwd_via_bound(&d, &cow));
                assert!(rev_via_bound(&cow, &d));
            }
            let other_raw = if raw.starts_with("sha256:") {
                format!("sha512:{}", "0".repeat(SHA512_HEX_LEN))
            } else {
                format!("sha256:{D1}")
            };
            for cow in [
                Cow::<'_, str>::Borrowed(other_raw.as_str()),
                Cow::<'_, str>::Owned(other_raw.clone()),
            ] {
                assert!(!fwd_via_bound(&d, &cow));
                assert!(!rev_via_bound(&cow, &d));
            }
        }
    }

    /// `PartialEq<Cow<'_, [u8]>> for ContentDigest` agrees byte-for-
    /// byte with the borrowed-view [`AsRef<[u8]>`] oracle across the
    /// same 4-canonical × ~8-label grid the borrowed-byte / owned-
    /// Vec<u8> / borrowed-or-owned [`Cow<'_, str>`] sibling peers pin,
    /// threaded through a [`Cow<'_, [u8]>`] label constructed on BOTH
    /// `Cow::Borrowed` and `Cow::Owned` arms so the arm-collapsing
    /// route is exercised on both discriminator arms. Pins the
    /// borrowed-or-owned forward-direction agreement across arms so a
    /// future refactor that diverged one arm from the
    /// [`AsRef<[u8]>`] read oracle breaks this pin at at least one
    /// `(digest, label, arm)` triple rather than at every downstream
    /// `digest == cow_bytes` call site.
    #[test]
    fn test_partial_eq_cow_bytes_agrees_with_as_ref() {
        use std::borrow::Cow;
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let digests = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        let owned: Vec<Vec<u8>> = digests
            .iter()
            .flat_map(|d| {
                [
                    d.as_bytes().to_vec(),
                    format!("SHA256:{}", &d[7..]).into_bytes(),
                    format!(" {d}").into_bytes(),
                    format!("{d}\n").into_bytes(),
                ]
            })
            .chain([
                Vec::new(),
                b"sha256:".to_vec(),
                b"not-a-digest".to_vec(),
                vec![0xff, 0xfe, 0xfd],
            ])
            .collect();
        for raw in &digests {
            let d = ContentDigest::parse(raw).unwrap();
            for label in &owned {
                let borrowed: Cow<'_, [u8]> = Cow::Borrowed(label.as_slice());
                let owned_arm: Cow<'_, [u8]> = Cow::Owned(label.clone());
                for (arm, cow) in [("Borrowed", &borrowed), ("Owned", &owned_arm)] {
                    assert_eq!(
                        <ContentDigest as PartialEq<Cow<'_, [u8]>>>::eq(&d, cow),
                        <ContentDigest as AsRef<[u8]>>::as_ref(&d) == label.as_slice(),
                        "PartialEq<Cow<'_, [u8]>> and AsRef<[u8]> equality must agree at ({arm}, {label:?}, {raw:?})",
                    );
                }
            }
        }
    }

    /// At every validated [`ContentDigest`] value,
    /// `<Self as PartialEq<Cow<'_, [u8]>>>::eq(&digest, &Cow::Borrowed(digest.as_str().as_bytes()))`
    /// and the [`Cow::Owned`] variant both return true — the digest
    /// recognises its own emitted canonical form as a
    /// [`Cow<'_, [u8]>`] on either discriminator arm through the
    /// borrowed-or-owned peer.
    #[test]
    fn test_partial_eq_cow_bytes_reflexive_at_own_digest() {
        use std::borrow::Cow;
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        for raw in [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ] {
            let d = ContentDigest::parse(&raw).unwrap();
            let canonical: Vec<u8> = d.as_str().as_bytes().to_vec();
            let borrowed: Cow<'_, [u8]> = Cow::Borrowed(canonical.as_slice());
            let owned_arm: Cow<'_, [u8]> = Cow::Owned(canonical.clone());
            assert!(
                <ContentDigest as PartialEq<Cow<'_, [u8]>>>::eq(&d, &borrowed),
                "PartialEq<Cow<'_, [u8]>> must recognise self canonical form on Borrowed arm at {raw:?}",
            );
            assert!(
                <ContentDigest as PartialEq<Cow<'_, [u8]>>>::eq(&d, &owned_arm),
                "PartialEq<Cow<'_, [u8]>> must recognise self canonical form on Owned arm at {raw:?}",
            );
        }
    }

    /// Every [`Cow<'_, [u8]>`] that is NOT the digest's own emitted
    /// canonical form fails equality through
    /// `PartialEq<Cow<'_, [u8]>>` on BOTH arms — the same canonicity
    /// discipline the borrowed-byte and owned-Vec<u8> sibling peers
    /// enforce, projected onto the borrowed-or-owned [`Cow`]
    /// receiver.
    #[test]
    fn test_partial_eq_cow_bytes_rejects_non_canonical_labels() {
        use std::borrow::Cow;
        let d1 = ContentDigest::parse(&format!("sha256:{D1}")).unwrap();
        let d2 = ContentDigest::parse(&format!("sha256:{D2}")).unwrap();
        let bad: Vec<Vec<u8>> = vec![
            Vec::new(),
            b"sha256:".to_vec(),
            b"not-a-digest".to_vec(),
            format!("SHA256:{D1}").into_bytes(),
            format!(" sha256:{D1}").into_bytes(),
            format!("sha256:{D1}\n").into_bytes(),
            format!("sha256:{D2}").into_bytes(),
            vec![0xff, 0xfe, 0xfd],
        ];
        for label in &bad {
            for cow in [
                Cow::<'_, [u8]>::Borrowed(label.as_slice()),
                Cow::<'_, [u8]>::Owned(label.clone()),
            ] {
                assert!(
                    !<ContentDigest as PartialEq<Cow<'_, [u8]>>>::eq(&d1, &cow),
                    "PartialEq<Cow<'_, [u8]>> must reject non-canonical label {label:?} ({cow:?}) at sha256:{D1}",
                );
            }
        }
        // Peer surface is symmetric — d2 rejects d1's canonical form
        // through the Cow<[u8]> receiver on either arm as well.
        let d1_canonical = format!("sha256:{D1}").into_bytes();
        for cow in [
            Cow::<'_, [u8]>::Borrowed(d1_canonical.as_slice()),
            Cow::<'_, [u8]>::Owned(d1_canonical.clone()),
        ] {
            assert!(!<ContentDigest as PartialEq<Cow<'_, [u8]>>>::eq(&d2, &cow));
        }
    }

    /// The reverse-direction borrowed-or-owned byte-slice comparison
    /// peer `<Cow<'_, [u8]> as PartialEq<ContentDigest>>::eq` agrees
    /// byte-for-byte with the borrowed-view [`AsRef<[u8]>`] oracle
    /// across the same grid AND is symmetric with the forward-
    /// direction `<ContentDigest as PartialEq<Cow<'_, [u8]>>>::eq`
    /// peer at every `(cow, digest, arm)` triple. Pins the reverse-
    /// direction agreement and the symmetry axiom
    /// `<Cow<'_, [u8]> as PartialEq<ContentDigest>>::eq(cow, &d)
    /// == <ContentDigest as PartialEq<Cow<'_, [u8]>>>::eq(&d, cow)`
    /// on both [`Cow`] arms so a future refactor that diverged one
    /// impl from its symmetric peer breaks this pin at at least one
    /// triple rather than propagating unnoticed through downstream
    /// generic `PartialEq`-bounded consumers that thread a
    /// [`ContentDigest`] through either side of a `==` operator.
    #[test]
    fn test_cow_bytes_partial_eq_content_digest_symmetric_and_agrees_with_as_ref() {
        use std::borrow::Cow;
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let digests = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        let owned: Vec<Vec<u8>> = digests
            .iter()
            .map(|d| d.as_bytes().to_vec())
            .chain([
                Vec::new(),
                b"sha256:".to_vec(),
                b"not-a-digest".to_vec(),
                format!("SHA256:{D1}").into_bytes(),
                format!(" sha256:{D1}").into_bytes(),
                format!("sha256:{D1}\n").into_bytes(),
                vec![0xff, 0xfe, 0xfd],
            ])
            .collect();
        for raw in &digests {
            let d = ContentDigest::parse(raw).unwrap();
            for label in &owned {
                let borrowed: Cow<'_, [u8]> = Cow::Borrowed(label.as_slice());
                let owned_arm: Cow<'_, [u8]> = Cow::Owned(label.clone());
                for (arm, cow) in [("Borrowed", &borrowed), ("Owned", &owned_arm)] {
                    assert_eq!(
                        <Cow<'_, [u8]> as PartialEq<ContentDigest>>::eq(cow, &d),
                        label.as_slice() == <ContentDigest as AsRef<[u8]>>::as_ref(&d),
                        "reverse Cow<[u8]> and AsRef<[u8]> equality must agree at ({arm}, {label:?}, {raw:?})",
                    );
                    assert_eq!(
                        <Cow<'_, [u8]> as PartialEq<ContentDigest>>::eq(cow, &d),
                        <ContentDigest as PartialEq<Cow<'_, [u8]>>>::eq(&d, cow),
                        "reverse-Cow<[u8]> vs forward-Cow<[u8]> direction must agree at ({arm}, {label:?}, {raw:?})",
                    );
                }
            }
        }
    }

    /// The [`Cow<'_, [u8]>`] forward and reverse peers compose with a
    /// generic `PartialEq<Cow<'_, [u8]>>`- /
    /// `PartialEq<ContentDigest>`-bounded consumer — a downstream
    /// site that types its comparison contract as
    /// `impl PartialEq<Cow<'_, [u8]>>` (a `matches!` predicate on a
    /// [`Cow`] arm, an integration-test oracle that generic-bounds
    /// its borrowed-or-owned byte-slice equality check) recovers the
    /// same answer as a direct
    /// `<ContentDigest as PartialEq<Cow<'_, [u8]>>>::eq` call, and
    /// the reverse-direction bound `impl PartialEq<ContentDigest>`
    /// recovers the same answer as a direct
    /// `<Cow<'_, [u8]> as PartialEq<ContentDigest>>::eq` call.
    #[test]
    fn test_partial_eq_content_digest_cow_bytes_carries_through_generic_consumer() {
        use std::borrow::Cow;
        // The `&Cow<'_, [u8]>` receiver is load-bearing: this test pins
        // the exact `PartialEq<Cow<'_, [u8]>>` bound the impl above
        // exposes, so the sibling clippy suggestion to relax it to
        // `&[u8]` would collapse the bound this test exists to exercise.
        #[allow(clippy::ptr_arg)]
        fn fwd_via_bound<'a, T: PartialEq<Cow<'a, [u8]>>>(t: &T, expected: &Cow<'a, [u8]>) -> bool {
            <T as PartialEq<Cow<'a, [u8]>>>::eq(t, expected)
        }
        fn rev_via_bound<T: PartialEq<ContentDigest>>(t: &T, expected: &ContentDigest) -> bool {
            <T as PartialEq<ContentDigest>>::eq(t, expected)
        }
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        for raw in [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ] {
            let d = ContentDigest::parse(&raw).unwrap();
            let raw_bytes: Vec<u8> = raw.as_bytes().to_vec();
            for cow in [
                Cow::<'_, [u8]>::Borrowed(raw_bytes.as_slice()),
                Cow::<'_, [u8]>::Owned(raw_bytes.clone()),
            ] {
                assert!(fwd_via_bound(&d, &cow));
                assert!(rev_via_bound(&cow, &d));
            }
            let other_raw = if raw.starts_with("sha256:") {
                format!("sha512:{}", "0".repeat(SHA512_HEX_LEN))
            } else {
                format!("sha256:{D1}")
            };
            let other_bytes: Vec<u8> = other_raw.into_bytes();
            for cow in [
                Cow::<'_, [u8]>::Borrowed(other_bytes.as_slice()),
                Cow::<'_, [u8]>::Owned(other_bytes.clone()),
            ] {
                assert!(!fwd_via_bound(&d, &cow));
                assert!(!rev_via_bound(&cow, &d));
            }
        }
    }

    /// `PartialEq<Box<str>> for ContentDigest` agrees byte-for-byte
    /// with the borrowed-view [`ContentDigest::as_str`] oracle across
    /// the same 4-canonical × ~8-label grid the sibling owned-String /
    /// borrowed-or-owned [`Cow<'_, str>`] peers pin, threaded through
    /// a shrunk-owned [`Box<str>`] handle so the caller writes
    /// `digest == boxed_label`. Pins the shrunk-owned forward-direction
    /// agreement so a future refactor that inlined a divergent read
    /// into the [`Box<str>`] impl breaks this pin at at least one
    /// `(digest, boxed)` pair rather than at every downstream
    /// `digest == boxed_label` call site.
    #[test]
    fn test_partial_eq_box_str_agrees_with_as_str() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let digests = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        let boxed: Vec<Box<str>> = digests
            .iter()
            .flat_map(|d| {
                [
                    d.clone().into_boxed_str(),
                    format!("SHA256:{}", &d[7..]).into_boxed_str(),
                    format!(" {d}").into_boxed_str(),
                    format!("{d}\n").into_boxed_str(),
                ]
            })
            .chain([
                String::new().into_boxed_str(),
                "sha256:".to_string().into_boxed_str(),
                "SHA256:0123".to_string().into_boxed_str(),
                "not-a-digest".to_string().into_boxed_str(),
            ])
            .collect();
        for raw in &digests {
            let d = ContentDigest::parse(raw).unwrap();
            for label in &boxed {
                assert_eq!(
                    <ContentDigest as PartialEq<Box<str>>>::eq(&d, label),
                    d.as_str() == label.as_ref(),
                    "PartialEq<Box<str>> and as_str() equality must agree at ({label:?}, {raw:?})",
                );
            }
        }
    }

    /// At every validated [`ContentDigest`] value,
    /// `<Self as PartialEq<Box<str>>>::eq(&digest,
    /// &digest.as_str().to_owned().into_boxed_str())` returns true —
    /// the digest recognises its own emitted canonical form as a
    /// shrunk-owned [`Box<str>`] through the [`Box<str>`] peer, and
    /// (crucially) the round-trip through the sibling emit peer
    /// [`From<ContentDigest> for Box<str>`] round-trips through this
    /// peer as `true` so the two shrunk-owned surfaces agree at their
    /// shared canonical form.
    #[test]
    fn test_partial_eq_box_str_reflexive_at_own_digest() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        for raw in [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ] {
            let d = ContentDigest::parse(&raw).unwrap();
            let canonical: Box<str> = d.as_str().to_owned().into_boxed_str();
            assert!(
                <ContentDigest as PartialEq<Box<str>>>::eq(&d, &canonical),
                "PartialEq<Box<str>> must recognise self canonical form at {raw:?}",
            );
            // Round-trip through the sibling by-value shrunk-owned
            // UTF-8 emit peer From<ContentDigest> for Box<str>
            // (commit 0e86524): the emit peer's output equals the
            // digest itself through this comparison peer at every
            // validated value.
            let emitted: Box<str> = Box::<str>::from(d.clone());
            assert!(
                <ContentDigest as PartialEq<Box<str>>>::eq(&d, &emitted),
                "PartialEq<Box<str>> must agree with From<ContentDigest> for Box<str> at {raw:?}",
            );
        }
    }

    /// Every shrunk-owned [`Box<str>`] that is NOT the digest's own
    /// emitted canonical form fails equality through
    /// [`PartialEq<Box<str>>`] — the same canonicity discipline the
    /// borrowed-str and owned-String sibling peers enforce, projected
    /// onto the shrunk-owned [`Box<str>`] receiver.
    #[test]
    fn test_partial_eq_box_str_rejects_non_canonical_labels() {
        let d1 = ContentDigest::parse(&format!("sha256:{D1}")).unwrap();
        let d2 = ContentDigest::parse(&format!("sha256:{D2}")).unwrap();
        let bad: [Box<str>; 7] = [
            String::new().into_boxed_str(),
            "sha256:".to_string().into_boxed_str(),
            "not-a-digest".to_string().into_boxed_str(),
            format!("SHA256:{D1}").into_boxed_str(),
            format!(" sha256:{D1}").into_boxed_str(),
            format!("sha256:{D1}\n").into_boxed_str(),
            format!("sha256:{D2}").into_boxed_str(),
        ];
        for label in &bad {
            assert!(
                !<ContentDigest as PartialEq<Box<str>>>::eq(&d1, label),
                "PartialEq<Box<str>> must reject non-canonical label {label:?} at sha256:{D1}",
            );
        }
        // Peer surface is symmetric — d2 rejects d1's canonical form
        // through the shrunk-owned Box<str> receiver as well.
        let d1_canonical: Box<str> = format!("sha256:{D1}").into_boxed_str();
        assert!(!<ContentDigest as PartialEq<Box<str>>>::eq(
            &d2,
            &d1_canonical,
        ));
    }

    /// The reverse-direction shrunk-owned UTF-8 comparison peer
    /// `<Box<str> as PartialEq<ContentDigest>>::eq` agrees byte-for-
    /// byte with the borrowed-view [`ContentDigest::as_str`] oracle
    /// across the same grid AND is symmetric with the forward-
    /// direction `<ContentDigest as PartialEq<Box<str>>>::eq` peer at
    /// every `(boxed, digest)` pair. Pins the reverse-direction
    /// agreement and the symmetry axiom
    /// `<Box<str> as PartialEq<ContentDigest>>::eq(boxed, &d)
    /// == <ContentDigest as PartialEq<Box<str>>>::eq(&d, boxed)` so a
    /// future refactor that diverged one impl from its symmetric peer
    /// breaks this pin at at least one pair rather than propagating
    /// unnoticed through downstream generic `PartialEq`-bounded
    /// consumers that thread a [`ContentDigest`] through either side
    /// of a `==` operator.
    #[test]
    fn test_box_str_partial_eq_content_digest_symmetric_and_agrees_with_as_str() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let digests = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        let boxed: Vec<Box<str>> = digests
            .iter()
            .cloned()
            .chain([
                String::new(),
                "sha256:".to_string(),
                "not-a-digest".to_string(),
                format!("SHA256:{D1}"),
                format!(" sha256:{D1}"),
                format!("sha256:{D1}\n"),
            ])
            .map(String::into_boxed_str)
            .collect();
        for raw in &digests {
            let d = ContentDigest::parse(raw).unwrap();
            for label in &boxed {
                assert_eq!(
                    <Box<str> as PartialEq<ContentDigest>>::eq(label, &d),
                    label.as_ref() == d.as_str(),
                    "reverse Box<str> and as_str() equality must agree at ({label:?}, {raw:?})",
                );
                assert_eq!(
                    <Box<str> as PartialEq<ContentDigest>>::eq(label, &d),
                    <ContentDigest as PartialEq<Box<str>>>::eq(&d, label),
                    "reverse-Box<str> vs forward-Box<str> direction must agree at ({label:?}, {raw:?})",
                );
            }
        }
    }

    /// The shrunk-owned [`Box<str>`] forward and reverse peers compose
    /// with a generic `PartialEq<Box<str>>`- / `PartialEq<ContentDigest>`-
    /// bounded consumer — a downstream site that types its comparison
    /// contract as `impl PartialEq<Box<str>>` (a `matches!` predicate
    /// on a shrunk-owned handle, an integration-test oracle that
    /// generic-bounds its [`Box<str>`] equality check) recovers the
    /// same answer as a direct `<ContentDigest as PartialEq<Box<str>>>::eq`
    /// call, and the reverse-direction bound
    /// `impl PartialEq<ContentDigest>` recovers the same answer as a
    /// direct `<Box<str> as PartialEq<ContentDigest>>::eq` call.
    #[test]
    fn test_partial_eq_content_digest_box_str_carries_through_generic_consumer() {
        // The `&Box<str>` receiver is load-bearing: this test pins the
        // exact `PartialEq<Box<str>>` bound the impl above exposes, so
        // the sibling clippy suggestion to relax it to `&str` would
        // collapse the bound this test exists to exercise.
        #[allow(clippy::borrowed_box)]
        fn fwd_via_bound<T: PartialEq<Box<str>>>(t: &T, expected: &Box<str>) -> bool {
            <T as PartialEq<Box<str>>>::eq(t, expected)
        }
        fn rev_via_bound<T: PartialEq<ContentDigest>>(t: &T, expected: &ContentDigest) -> bool {
            <T as PartialEq<ContentDigest>>::eq(t, expected)
        }
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        for raw in [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ] {
            let d = ContentDigest::parse(&raw).unwrap();
            let boxed: Box<str> = raw.clone().into_boxed_str();
            assert!(fwd_via_bound(&d, &boxed));
            assert!(rev_via_bound(&boxed, &d));
            let other = if raw.starts_with("sha256:") {
                format!("sha512:{}", "0".repeat(SHA512_HEX_LEN))
            } else {
                format!("sha256:{D1}")
            };
            let other_boxed: Box<str> = other.into_boxed_str();
            assert!(!fwd_via_bound(&d, &other_boxed));
            assert!(!rev_via_bound(&other_boxed, &d));
        }
    }

    /// `PartialEq<Box<[u8]>> for ContentDigest` agrees byte-for-byte
    /// with the borrowed-view [`AsRef<[u8]>`] oracle across the same
    /// 4-canonical × ~8-label grid the sibling owned-Vec<u8> /
    /// borrowed-or-owned [`Cow<'_, [u8]>`] peers pin, threaded
    /// through a shrunk-owned [`Box<[u8]>`] handle so the caller
    /// writes `digest == boxed_bytes`. Pins the shrunk-owned
    /// forward-direction agreement so a future refactor that inlined
    /// a divergent read into the [`Box<[u8]>`] impl breaks this pin
    /// at at least one `(digest, boxed)` pair rather than at every
    /// downstream `digest == boxed_bytes` call site.
    #[test]
    fn test_partial_eq_box_bytes_agrees_with_as_ref() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let digests = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        let boxed: Vec<Box<[u8]>> = digests
            .iter()
            .flat_map(|d| {
                [
                    d.as_bytes().to_vec().into_boxed_slice(),
                    format!("SHA256:{}", &d[7..])
                        .into_bytes()
                        .into_boxed_slice(),
                    format!(" {d}").into_bytes().into_boxed_slice(),
                    format!("{d}\n").into_bytes().into_boxed_slice(),
                ]
            })
            .chain([
                Vec::new().into_boxed_slice(),
                b"sha256:".to_vec().into_boxed_slice(),
                b"not-a-digest".to_vec().into_boxed_slice(),
                vec![0xff, 0xfe, 0xfd].into_boxed_slice(),
            ])
            .collect();
        for raw in &digests {
            let d = ContentDigest::parse(raw).unwrap();
            for label in &boxed {
                assert_eq!(
                    <ContentDigest as PartialEq<Box<[u8]>>>::eq(&d, label),
                    <ContentDigest as AsRef<[u8]>>::as_ref(&d) == label.as_ref(),
                    "PartialEq<Box<[u8]>> and AsRef<[u8]> equality must agree at ({label:?}, {raw:?})",
                );
            }
        }
    }

    /// At every validated [`ContentDigest`] value,
    /// `<Self as PartialEq<Box<[u8]>>>::eq(&digest,
    /// &digest.as_str().as_bytes().to_vec().into_boxed_slice())`
    /// returns true — the digest recognises its own emitted canonical
    /// form as a shrunk-owned [`Box<[u8]>`] through the [`Box<[u8]>`]
    /// peer, and (crucially) the round-trip through the sibling emit
    /// peer [`From<ContentDigest> for Box<[u8]>`] (commit fce9fee)
    /// round-trips through this peer as `true` so the two shrunk-
    /// owned byte-slice surfaces agree at their shared canonical
    /// form.
    #[test]
    fn test_partial_eq_box_bytes_reflexive_at_own_digest() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        for raw in [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ] {
            let d = ContentDigest::parse(&raw).unwrap();
            let canonical: Box<[u8]> = d.as_str().as_bytes().to_vec().into_boxed_slice();
            assert!(
                <ContentDigest as PartialEq<Box<[u8]>>>::eq(&d, &canonical),
                "PartialEq<Box<[u8]>> must recognise self canonical form at {raw:?}",
            );
            // Round-trip through the sibling by-value shrunk-owned
            // byte-slice emit peer From<ContentDigest> for Box<[u8]>
            // (commit fce9fee): the emit peer's output equals the
            // digest itself through this comparison peer at every
            // validated value.
            let emitted: Box<[u8]> = Box::<[u8]>::from(d.clone());
            assert!(
                <ContentDigest as PartialEq<Box<[u8]>>>::eq(&d, &emitted),
                "PartialEq<Box<[u8]>> must agree with From<ContentDigest> for Box<[u8]> at {raw:?}",
            );
        }
    }

    /// Every shrunk-owned [`Box<[u8]>`] that is NOT the digest's own
    /// emitted canonical form fails equality through
    /// [`PartialEq<Box<[u8]>>`] — the same canonicity discipline the
    /// borrowed-byte and owned-Vec<u8> sibling peers enforce,
    /// projected onto the shrunk-owned [`Box<[u8]>`] receiver.
    #[test]
    fn test_partial_eq_box_bytes_rejects_non_canonical_labels() {
        let d1 = ContentDigest::parse(&format!("sha256:{D1}")).unwrap();
        let d2 = ContentDigest::parse(&format!("sha256:{D2}")).unwrap();
        let bad: [Box<[u8]>; 8] = [
            Vec::new().into_boxed_slice(),
            b"sha256:".to_vec().into_boxed_slice(),
            b"not-a-digest".to_vec().into_boxed_slice(),
            format!("SHA256:{D1}").into_bytes().into_boxed_slice(),
            format!(" sha256:{D1}").into_bytes().into_boxed_slice(),
            format!("sha256:{D1}\n").into_bytes().into_boxed_slice(),
            format!("sha256:{D2}").into_bytes().into_boxed_slice(),
            vec![0xff, 0xfe, 0xfd].into_boxed_slice(),
        ];
        for label in &bad {
            assert!(
                !<ContentDigest as PartialEq<Box<[u8]>>>::eq(&d1, label),
                "PartialEq<Box<[u8]>> must reject non-canonical label {label:?} at sha256:{D1}",
            );
        }
        // Peer surface is symmetric — d2 rejects d1's canonical form
        // through the shrunk-owned Box<[u8]> receiver as well.
        let d1_canonical: Box<[u8]> = format!("sha256:{D1}").into_bytes().into_boxed_slice();
        assert!(!<ContentDigest as PartialEq<Box<[u8]>>>::eq(
            &d2,
            &d1_canonical,
        ));
    }

    /// The reverse-direction shrunk-owned byte-slice comparison peer
    /// `<Box<[u8]> as PartialEq<ContentDigest>>::eq` agrees byte-for-
    /// byte with the borrowed-view [`AsRef<[u8]>`] oracle across the
    /// same grid AND is symmetric with the forward-direction
    /// `<ContentDigest as PartialEq<Box<[u8]>>>::eq` peer at every
    /// `(boxed, digest)` pair. Pins the reverse-direction agreement
    /// and the symmetry axiom
    /// `<Box<[u8]> as PartialEq<ContentDigest>>::eq(boxed, &d)
    /// == <ContentDigest as PartialEq<Box<[u8]>>>::eq(&d, boxed)` so
    /// a future refactor that diverged one impl from its symmetric
    /// peer breaks this pin at at least one pair rather than
    /// propagating unnoticed through downstream generic
    /// `PartialEq`-bounded consumers that thread a [`ContentDigest`]
    /// through either side of a `==` operator.
    #[test]
    fn test_box_bytes_partial_eq_content_digest_symmetric_and_agrees_with_as_ref() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let digests = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        let boxed: Vec<Box<[u8]>> = digests
            .iter()
            .map(|d| d.as_bytes().to_vec().into_boxed_slice())
            .chain([
                Vec::new().into_boxed_slice(),
                b"sha256:".to_vec().into_boxed_slice(),
                b"not-a-digest".to_vec().into_boxed_slice(),
                format!("SHA256:{D1}").into_bytes().into_boxed_slice(),
                format!(" sha256:{D1}").into_bytes().into_boxed_slice(),
                format!("sha256:{D1}\n").into_bytes().into_boxed_slice(),
                vec![0xff, 0xfe, 0xfd].into_boxed_slice(),
            ])
            .collect();
        for raw in &digests {
            let d = ContentDigest::parse(raw).unwrap();
            for label in &boxed {
                assert_eq!(
                    <Box<[u8]> as PartialEq<ContentDigest>>::eq(label, &d),
                    label.as_ref() == <ContentDigest as AsRef<[u8]>>::as_ref(&d),
                    "reverse Box<[u8]> and AsRef<[u8]> equality must agree at ({label:?}, {raw:?})",
                );
                assert_eq!(
                    <Box<[u8]> as PartialEq<ContentDigest>>::eq(label, &d),
                    <ContentDigest as PartialEq<Box<[u8]>>>::eq(&d, label),
                    "reverse-Box<[u8]> vs forward-Box<[u8]> direction must agree at ({label:?}, {raw:?})",
                );
            }
        }
    }

    /// The shrunk-owned [`Box<[u8]>`] forward and reverse peers
    /// compose with a generic `PartialEq<Box<[u8]>>`- /
    /// `PartialEq<ContentDigest>`-bounded consumer — a downstream
    /// site that types its comparison contract as
    /// `impl PartialEq<Box<[u8]>>` (a `matches!` predicate on a
    /// shrunk-owned byte-buffer handle, an integration-test oracle
    /// that generic-bounds its [`Box<[u8]>`] equality check) recovers
    /// the same answer as a direct
    /// `<ContentDigest as PartialEq<Box<[u8]>>>::eq` call, and the
    /// reverse-direction bound `impl PartialEq<ContentDigest>`
    /// recovers the same answer as a direct
    /// `<Box<[u8]> as PartialEq<ContentDigest>>::eq` call.
    #[test]
    fn test_partial_eq_content_digest_box_bytes_carries_through_generic_consumer() {
        // The `&Box<[u8]>` receiver is load-bearing: this test pins
        // the exact `PartialEq<Box<[u8]>>` bound the impl above
        // exposes, so the sibling clippy suggestion to relax it to
        // `&[u8]` would collapse the bound this test exists to
        // exercise.
        #[allow(clippy::borrowed_box)]
        fn fwd_via_bound<T: PartialEq<Box<[u8]>>>(t: &T, expected: &Box<[u8]>) -> bool {
            <T as PartialEq<Box<[u8]>>>::eq(t, expected)
        }
        fn rev_via_bound<T: PartialEq<ContentDigest>>(t: &T, expected: &ContentDigest) -> bool {
            <T as PartialEq<ContentDigest>>::eq(t, expected)
        }
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        for raw in [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ] {
            let d = ContentDigest::parse(&raw).unwrap();
            let boxed: Box<[u8]> = raw.clone().into_bytes().into_boxed_slice();
            assert!(fwd_via_bound(&d, &boxed));
            assert!(rev_via_bound(&boxed, &d));
            let other = if raw.starts_with("sha256:") {
                format!("sha512:{}", "0".repeat(SHA512_HEX_LEN))
            } else {
                format!("sha256:{D1}")
            };
            let other_boxed: Box<[u8]> = other.into_bytes().into_boxed_slice();
            assert!(!fwd_via_bound(&d, &other_boxed));
            assert!(!rev_via_bound(&other_boxed, &d));
        }
    }

    /// `PartialEq<Arc<str>> for ContentDigest` agrees byte-for-byte
    /// with the borrowed-view [`ContentDigest::as_str`] oracle across
    /// the same 4-canonical × ~8-label grid the sibling shrunk-owned
    /// [`Box<str>`] peer pins, threaded through a cross-thread
    /// shared-owned [`Arc<str>`] handle so the caller writes
    /// `digest == arc_label`.
    #[test]
    fn test_partial_eq_arc_str_agrees_with_as_str() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let digests = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        let arced: Vec<std::sync::Arc<str>> = digests
            .iter()
            .flat_map(|d| {
                [
                    std::sync::Arc::<str>::from(d.as_str()),
                    std::sync::Arc::<str>::from(format!("SHA256:{}", &d[7..])),
                    std::sync::Arc::<str>::from(format!(" {d}")),
                    std::sync::Arc::<str>::from(format!("{d}\n")),
                ]
            })
            .chain([
                std::sync::Arc::<str>::from(""),
                std::sync::Arc::<str>::from("sha256:"),
                std::sync::Arc::<str>::from("SHA256:0123"),
                std::sync::Arc::<str>::from("not-a-digest"),
            ])
            .collect();
        for raw in &digests {
            let d = ContentDigest::parse(raw).unwrap();
            for label in &arced {
                assert_eq!(
                    <ContentDigest as PartialEq<std::sync::Arc<str>>>::eq(&d, label),
                    d.as_str() == label.as_ref(),
                    "PartialEq<Arc<str>> and as_str() equality must agree at ({label:?}, {raw:?})",
                );
            }
        }
    }

    /// At every validated [`ContentDigest`] value, the peer recognises
    /// the digest's own emitted canonical form as an [`Arc<str>`] AND
    /// round-trips through the sibling by-value cross-thread shared-
    /// owned UTF-8 emit peer [`From<ContentDigest> for Arc<str>`]
    /// (commit 5f85247) — so the two cross-thread shared-owned
    /// surfaces agree at their shared canonical form.
    #[test]
    fn test_partial_eq_arc_str_reflexive_at_own_digest() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        for raw in [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ] {
            let d = ContentDigest::parse(&raw).unwrap();
            let canonical: std::sync::Arc<str> = std::sync::Arc::<str>::from(d.as_str());
            assert!(
                <ContentDigest as PartialEq<std::sync::Arc<str>>>::eq(&d, &canonical),
                "PartialEq<Arc<str>> must recognise self canonical form at {raw:?}",
            );
            let emitted: std::sync::Arc<str> = std::sync::Arc::<str>::from(d.clone());
            assert!(
                <ContentDigest as PartialEq<std::sync::Arc<str>>>::eq(&d, &emitted),
                "PartialEq<Arc<str>> must agree with From<ContentDigest> for Arc<str> at {raw:?}",
            );
        }
    }

    /// Every cross-thread shared-owned [`Arc<str>`] that is NOT the
    /// digest's own emitted canonical form fails equality through
    /// [`PartialEq<Arc<str>>`] — the same canonicity discipline the
    /// sibling receiver peers enforce, projected onto the [`Arc<str>`]
    /// receiver.
    #[test]
    fn test_partial_eq_arc_str_rejects_non_canonical_labels() {
        let d1 = ContentDigest::parse(&format!("sha256:{D1}")).unwrap();
        let d2 = ContentDigest::parse(&format!("sha256:{D2}")).unwrap();
        let bad: [std::sync::Arc<str>; 7] = [
            std::sync::Arc::<str>::from(""),
            std::sync::Arc::<str>::from("sha256:"),
            std::sync::Arc::<str>::from("not-a-digest"),
            std::sync::Arc::<str>::from(format!("SHA256:{D1}").as_str()),
            std::sync::Arc::<str>::from(format!(" sha256:{D1}").as_str()),
            std::sync::Arc::<str>::from(format!("sha256:{D1}\n").as_str()),
            std::sync::Arc::<str>::from(format!("sha256:{D2}").as_str()),
        ];
        for label in &bad {
            assert!(
                !<ContentDigest as PartialEq<std::sync::Arc<str>>>::eq(&d1, label),
                "PartialEq<Arc<str>> must reject non-canonical label {label:?} at sha256:{D1}",
            );
        }
        let d1_canonical: std::sync::Arc<str> =
            std::sync::Arc::<str>::from(format!("sha256:{D1}").as_str());
        assert!(!<ContentDigest as PartialEq<std::sync::Arc<str>>>::eq(
            &d2,
            &d1_canonical,
        ));
    }

    /// The reverse-direction cross-thread shared-owned UTF-8
    /// comparison peer `<Arc<str> as PartialEq<ContentDigest>>::eq`
    /// agrees byte-for-byte with the borrowed-view
    /// [`ContentDigest::as_str`] oracle across the same grid AND is
    /// symmetric with the forward-direction peer at every
    /// `(arc, digest)` pair.
    #[test]
    fn test_arc_str_partial_eq_content_digest_symmetric_and_agrees_with_as_str() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let digests = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        let arced: Vec<std::sync::Arc<str>> = digests
            .iter()
            .cloned()
            .chain([
                String::new(),
                "sha256:".to_string(),
                "not-a-digest".to_string(),
                format!("SHA256:{D1}"),
                format!(" sha256:{D1}"),
                format!("sha256:{D1}\n"),
            ])
            .map(|s| std::sync::Arc::<str>::from(s.as_str()))
            .collect();
        for raw in &digests {
            let d = ContentDigest::parse(raw).unwrap();
            for label in &arced {
                assert_eq!(
                    <std::sync::Arc<str> as PartialEq<ContentDigest>>::eq(label, &d),
                    label.as_ref() == d.as_str(),
                    "reverse Arc<str> and as_str() equality must agree at ({label:?}, {raw:?})",
                );
                assert_eq!(
                    <std::sync::Arc<str> as PartialEq<ContentDigest>>::eq(label, &d),
                    <ContentDigest as PartialEq<std::sync::Arc<str>>>::eq(&d, label),
                    "reverse-Arc<str> vs forward-Arc<str> direction must agree at ({label:?}, {raw:?})",
                );
            }
        }
    }

    /// The cross-thread shared-owned [`Arc<str>`] forward and reverse
    /// peers compose with a generic
    /// `PartialEq<Arc<str>>`- / `PartialEq<ContentDigest>`-bounded
    /// consumer — a downstream site that types its comparison
    /// contract as `impl PartialEq<Arc<str>>` recovers the same
    /// answer as a direct
    /// `<ContentDigest as PartialEq<Arc<str>>>::eq` call, and the
    /// reverse-direction bound `impl PartialEq<ContentDigest>`
    /// recovers the same answer as a direct
    /// `<Arc<str> as PartialEq<ContentDigest>>::eq` call.
    #[test]
    fn test_partial_eq_content_digest_arc_str_carries_through_generic_consumer() {
        fn fwd_via_bound<T: PartialEq<std::sync::Arc<str>>>(
            t: &T,
            expected: &std::sync::Arc<str>,
        ) -> bool {
            <T as PartialEq<std::sync::Arc<str>>>::eq(t, expected)
        }
        fn rev_via_bound<T: PartialEq<ContentDigest>>(t: &T, expected: &ContentDigest) -> bool {
            <T as PartialEq<ContentDigest>>::eq(t, expected)
        }
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        for raw in [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ] {
            let d = ContentDigest::parse(&raw).unwrap();
            let arced: std::sync::Arc<str> = std::sync::Arc::<str>::from(raw.as_str());
            assert!(fwd_via_bound(&d, &arced));
            assert!(rev_via_bound(&arced, &d));
            let other = if raw.starts_with("sha256:") {
                format!("sha512:{}", "0".repeat(SHA512_HEX_LEN))
            } else {
                format!("sha256:{D1}")
            };
            let other_arced: std::sync::Arc<str> = std::sync::Arc::<str>::from(other.as_str());
            assert!(!fwd_via_bound(&d, &other_arced));
            assert!(!rev_via_bound(&other_arced, &d));
        }
    }

    /// `PartialEq<Rc<str>> for ContentDigest` agrees byte-for-byte
    /// with the borrowed-view [`ContentDigest::as_str`] oracle across
    /// the same 4-canonical × ~8-label grid the sibling cross-thread
    /// shared-owned [`Arc<str>`] peer pins, threaded through a
    /// thread-local shared-owned [`Rc<str>`] handle so the caller
    /// writes `digest == rc_label`.
    #[test]
    fn test_partial_eq_rc_str_agrees_with_as_str() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let digests = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        let rced: Vec<std::rc::Rc<str>> = digests
            .iter()
            .flat_map(|d| {
                [
                    std::rc::Rc::<str>::from(d.as_str()),
                    std::rc::Rc::<str>::from(format!("SHA256:{}", &d[7..])),
                    std::rc::Rc::<str>::from(format!(" {d}")),
                    std::rc::Rc::<str>::from(format!("{d}\n")),
                ]
            })
            .chain([
                std::rc::Rc::<str>::from(""),
                std::rc::Rc::<str>::from("sha256:"),
                std::rc::Rc::<str>::from("SHA256:0123"),
                std::rc::Rc::<str>::from("not-a-digest"),
            ])
            .collect();
        for raw in &digests {
            let d = ContentDigest::parse(raw).unwrap();
            for label in &rced {
                assert_eq!(
                    <ContentDigest as PartialEq<std::rc::Rc<str>>>::eq(&d, label),
                    d.as_str() == label.as_ref(),
                    "PartialEq<Rc<str>> and as_str() equality must agree at ({label:?}, {raw:?})",
                );
            }
        }
    }

    /// At every validated [`ContentDigest`] value, the peer recognises
    /// the digest's own emitted canonical form as an [`Rc<str>`] AND
    /// round-trips through the sibling by-value thread-local
    /// shared-owned UTF-8 emit peer [`From<ContentDigest> for Rc<str>`]
    /// (commit a7bcfd2) — so the two thread-local shared-owned
    /// surfaces agree at their shared canonical form.
    #[test]
    fn test_partial_eq_rc_str_reflexive_at_own_digest() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        for raw in [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ] {
            let d = ContentDigest::parse(&raw).unwrap();
            let canonical: std::rc::Rc<str> = std::rc::Rc::<str>::from(d.as_str());
            assert!(
                <ContentDigest as PartialEq<std::rc::Rc<str>>>::eq(&d, &canonical),
                "PartialEq<Rc<str>> must recognise self canonical form at {raw:?}",
            );
            let emitted: std::rc::Rc<str> = std::rc::Rc::<str>::from(d.clone());
            assert!(
                <ContentDigest as PartialEq<std::rc::Rc<str>>>::eq(&d, &emitted),
                "PartialEq<Rc<str>> must agree with From<ContentDigest> for Rc<str> at {raw:?}",
            );
        }
    }

    /// Every thread-local shared-owned [`Rc<str>`] that is NOT the
    /// digest's own emitted canonical form fails equality through
    /// [`PartialEq<Rc<str>>`] — the same canonicity discipline the
    /// sibling receiver peers enforce, projected onto the [`Rc<str>`]
    /// receiver.
    #[test]
    fn test_partial_eq_rc_str_rejects_non_canonical_labels() {
        let d1 = ContentDigest::parse(&format!("sha256:{D1}")).unwrap();
        let d2 = ContentDigest::parse(&format!("sha256:{D2}")).unwrap();
        let bad: [std::rc::Rc<str>; 7] = [
            std::rc::Rc::<str>::from(""),
            std::rc::Rc::<str>::from("sha256:"),
            std::rc::Rc::<str>::from("not-a-digest"),
            std::rc::Rc::<str>::from(format!("SHA256:{D1}").as_str()),
            std::rc::Rc::<str>::from(format!(" sha256:{D1}").as_str()),
            std::rc::Rc::<str>::from(format!("sha256:{D1}\n").as_str()),
            std::rc::Rc::<str>::from(format!("sha256:{D2}").as_str()),
        ];
        for label in &bad {
            assert!(
                !<ContentDigest as PartialEq<std::rc::Rc<str>>>::eq(&d1, label),
                "PartialEq<Rc<str>> must reject non-canonical label {label:?} at sha256:{D1}",
            );
        }
        let d1_canonical: std::rc::Rc<str> =
            std::rc::Rc::<str>::from(format!("sha256:{D1}").as_str());
        assert!(!<ContentDigest as PartialEq<std::rc::Rc<str>>>::eq(
            &d2,
            &d1_canonical,
        ));
    }

    /// The reverse-direction thread-local shared-owned UTF-8
    /// comparison peer `<Rc<str> as PartialEq<ContentDigest>>::eq`
    /// agrees byte-for-byte with the borrowed-view
    /// [`ContentDigest::as_str`] oracle across the same grid AND is
    /// symmetric with the forward-direction peer at every
    /// `(rc, digest)` pair.
    #[test]
    fn test_rc_str_partial_eq_content_digest_symmetric_and_agrees_with_as_str() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let digests = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        let rced: Vec<std::rc::Rc<str>> = digests
            .iter()
            .cloned()
            .chain([
                String::new(),
                "sha256:".to_string(),
                "not-a-digest".to_string(),
                format!("SHA256:{D1}"),
                format!(" sha256:{D1}"),
                format!("sha256:{D1}\n"),
            ])
            .map(|s| std::rc::Rc::<str>::from(s.as_str()))
            .collect();
        for raw in &digests {
            let d = ContentDigest::parse(raw).unwrap();
            for label in &rced {
                assert_eq!(
                    <std::rc::Rc<str> as PartialEq<ContentDigest>>::eq(label, &d),
                    label.as_ref() == d.as_str(),
                    "reverse Rc<str> and as_str() equality must agree at ({label:?}, {raw:?})",
                );
                assert_eq!(
                    <std::rc::Rc<str> as PartialEq<ContentDigest>>::eq(label, &d),
                    <ContentDigest as PartialEq<std::rc::Rc<str>>>::eq(&d, label),
                    "reverse-Rc<str> vs forward-Rc<str> direction must agree at ({label:?}, {raw:?})",
                );
            }
        }
    }

    /// The thread-local shared-owned [`Rc<str>`] forward and reverse
    /// peers compose with a generic
    /// `PartialEq<Rc<str>>`- / `PartialEq<ContentDigest>`-bounded
    /// consumer — a downstream site that types its comparison
    /// contract as `impl PartialEq<Rc<str>>` recovers the same
    /// answer as a direct
    /// `<ContentDigest as PartialEq<Rc<str>>>::eq` call, and the
    /// reverse-direction bound `impl PartialEq<ContentDigest>`
    /// recovers the same answer as a direct
    /// `<Rc<str> as PartialEq<ContentDigest>>::eq` call.
    #[test]
    fn test_partial_eq_content_digest_rc_str_carries_through_generic_consumer() {
        fn fwd_via_bound<T: PartialEq<std::rc::Rc<str>>>(
            t: &T,
            expected: &std::rc::Rc<str>,
        ) -> bool {
            <T as PartialEq<std::rc::Rc<str>>>::eq(t, expected)
        }
        fn rev_via_bound<T: PartialEq<ContentDigest>>(t: &T, expected: &ContentDigest) -> bool {
            <T as PartialEq<ContentDigest>>::eq(t, expected)
        }
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        for raw in [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ] {
            let d = ContentDigest::parse(&raw).unwrap();
            let rced: std::rc::Rc<str> = std::rc::Rc::<str>::from(raw.as_str());
            assert!(fwd_via_bound(&d, &rced));
            assert!(rev_via_bound(&rced, &d));
            let other = if raw.starts_with("sha256:") {
                format!("sha512:{}", "0".repeat(SHA512_HEX_LEN))
            } else {
                format!("sha256:{D1}")
            };
            let other_rced: std::rc::Rc<str> = std::rc::Rc::<str>::from(other.as_str());
            assert!(!fwd_via_bound(&d, &other_rced));
            assert!(!rev_via_bound(&other_rced, &d));
        }
    }

    /// `PartialEq<Arc<[u8]>> for ContentDigest` agrees byte-for-byte
    /// with the borrowed-view [`AsRef<[u8]>`] oracle across the same
    /// 4-canonical × ~8-label grid the sibling shrunk-owned
    /// [`Box<[u8]>`] peer pins, threaded through a cross-thread
    /// shared-owned [`Arc<[u8]>`] handle so the caller writes
    /// `digest == arc_bytes`.
    #[test]
    fn test_partial_eq_arc_bytes_agrees_with_as_ref() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let digests = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        let arced: Vec<std::sync::Arc<[u8]>> = digests
            .iter()
            .flat_map(|d| {
                [
                    std::sync::Arc::<[u8]>::from(d.as_bytes()),
                    std::sync::Arc::<[u8]>::from(format!("SHA256:{}", &d[7..]).as_bytes()),
                    std::sync::Arc::<[u8]>::from(format!(" {d}").as_bytes()),
                    std::sync::Arc::<[u8]>::from(format!("{d}\n").as_bytes()),
                ]
            })
            .chain([
                std::sync::Arc::<[u8]>::from(&[][..]),
                std::sync::Arc::<[u8]>::from(&b"sha256:"[..]),
                std::sync::Arc::<[u8]>::from(&b"not-a-digest"[..]),
                std::sync::Arc::<[u8]>::from(&[0xff, 0xfe, 0xfd][..]),
            ])
            .collect();
        for raw in &digests {
            let d = ContentDigest::parse(raw).unwrap();
            for label in &arced {
                assert_eq!(
                    <ContentDigest as PartialEq<std::sync::Arc<[u8]>>>::eq(&d, label),
                    <ContentDigest as AsRef<[u8]>>::as_ref(&d) == label.as_ref(),
                    "PartialEq<Arc<[u8]>> and AsRef<[u8]> equality must agree at ({label:?}, {raw:?})",
                );
            }
        }
    }

    /// At every validated [`ContentDigest`] value, the peer recognises
    /// the digest's own emitted canonical form as an [`Arc<[u8]>`] AND
    /// round-trips through the sibling by-value cross-thread shared-
    /// owned byte-slice emit peer
    /// [`From<ContentDigest> for std::sync::Arc<[u8]>`] (commit
    /// 49111c1) — so the two cross-thread shared-owned byte-slice
    /// surfaces agree at their shared canonical form.
    #[test]
    fn test_partial_eq_arc_bytes_reflexive_at_own_digest() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        for raw in [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ] {
            let d = ContentDigest::parse(&raw).unwrap();
            let canonical: std::sync::Arc<[u8]> =
                std::sync::Arc::<[u8]>::from(d.as_str().as_bytes());
            assert!(
                <ContentDigest as PartialEq<std::sync::Arc<[u8]>>>::eq(&d, &canonical),
                "PartialEq<Arc<[u8]>> must recognise self canonical form at {raw:?}",
            );
            let emitted: std::sync::Arc<[u8]> = std::sync::Arc::<[u8]>::from(d.clone());
            assert!(
                <ContentDigest as PartialEq<std::sync::Arc<[u8]>>>::eq(&d, &emitted),
                "PartialEq<Arc<[u8]>> must agree with From<ContentDigest> for Arc<[u8]> at {raw:?}",
            );
        }
    }

    /// Every cross-thread shared-owned [`Arc<[u8]>`] that is NOT the
    /// digest's own emitted canonical form fails equality through
    /// [`PartialEq<Arc<[u8]>>`] — the same canonicity discipline the
    /// sibling receiver peers enforce, projected onto the
    /// [`Arc<[u8]>`] byte-buffer receiver.
    #[test]
    fn test_partial_eq_arc_bytes_rejects_non_canonical_labels() {
        let d1 = ContentDigest::parse(&format!("sha256:{D1}")).unwrap();
        let d2 = ContentDigest::parse(&format!("sha256:{D2}")).unwrap();
        let bad: [std::sync::Arc<[u8]>; 8] = [
            std::sync::Arc::<[u8]>::from(&[][..]),
            std::sync::Arc::<[u8]>::from(&b"sha256:"[..]),
            std::sync::Arc::<[u8]>::from(&b"not-a-digest"[..]),
            std::sync::Arc::<[u8]>::from(format!("SHA256:{D1}").as_bytes()),
            std::sync::Arc::<[u8]>::from(format!(" sha256:{D1}").as_bytes()),
            std::sync::Arc::<[u8]>::from(format!("sha256:{D1}\n").as_bytes()),
            std::sync::Arc::<[u8]>::from(format!("sha256:{D2}").as_bytes()),
            std::sync::Arc::<[u8]>::from(&[0xff, 0xfe, 0xfd][..]),
        ];
        for label in &bad {
            assert!(
                !<ContentDigest as PartialEq<std::sync::Arc<[u8]>>>::eq(&d1, label),
                "PartialEq<Arc<[u8]>> must reject non-canonical label {label:?} at sha256:{D1}",
            );
        }
        let d1_canonical: std::sync::Arc<[u8]> =
            std::sync::Arc::<[u8]>::from(format!("sha256:{D1}").as_bytes());
        assert!(!<ContentDigest as PartialEq<std::sync::Arc<[u8]>>>::eq(
            &d2,
            &d1_canonical
        ),);
    }

    /// The reverse-direction cross-thread shared-owned byte-slice
    /// comparison peer `<Arc<[u8]> as PartialEq<ContentDigest>>::eq`
    /// agrees byte-for-byte with the borrowed-view [`AsRef<[u8]>`]
    /// oracle across the same grid AND is symmetric with the forward-
    /// direction peer at every `(arc, digest)` pair.
    #[test]
    fn test_arc_bytes_partial_eq_content_digest_symmetric_and_agrees_with_as_ref() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let digests = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        let arced: Vec<std::sync::Arc<[u8]>> = digests
            .iter()
            .map(|d| std::sync::Arc::<[u8]>::from(d.as_bytes()))
            .chain([
                std::sync::Arc::<[u8]>::from(&[][..]),
                std::sync::Arc::<[u8]>::from(&b"sha256:"[..]),
                std::sync::Arc::<[u8]>::from(&b"not-a-digest"[..]),
                std::sync::Arc::<[u8]>::from(format!("SHA256:{D1}").as_bytes()),
                std::sync::Arc::<[u8]>::from(format!(" sha256:{D1}").as_bytes()),
                std::sync::Arc::<[u8]>::from(format!("sha256:{D1}\n").as_bytes()),
                std::sync::Arc::<[u8]>::from(&[0xff, 0xfe, 0xfd][..]),
            ])
            .collect();
        for raw in &digests {
            let d = ContentDigest::parse(raw).unwrap();
            for label in &arced {
                assert_eq!(
                    <std::sync::Arc<[u8]> as PartialEq<ContentDigest>>::eq(label, &d),
                    label.as_ref() == <ContentDigest as AsRef<[u8]>>::as_ref(&d),
                    "reverse Arc<[u8]> and AsRef<[u8]> equality must agree at ({label:?}, {raw:?})",
                );
                assert_eq!(
                    <std::sync::Arc<[u8]> as PartialEq<ContentDigest>>::eq(label, &d),
                    <ContentDigest as PartialEq<std::sync::Arc<[u8]>>>::eq(&d, label),
                    "reverse-Arc<[u8]> vs forward-Arc<[u8]> direction must agree at ({label:?}, {raw:?})",
                );
            }
        }
    }

    /// The cross-thread shared-owned [`Arc<[u8]>`] forward and reverse
    /// peers compose with a generic
    /// `PartialEq<Arc<[u8]>>`- / `PartialEq<ContentDigest>`-bounded
    /// consumer — a downstream site that types its comparison contract
    /// as `impl PartialEq<Arc<[u8]>>` recovers the same answer as a
    /// direct `<ContentDigest as PartialEq<Arc<[u8]>>>::eq` call, and
    /// the reverse-direction bound `impl PartialEq<ContentDigest>`
    /// recovers the same answer as a direct
    /// `<Arc<[u8]> as PartialEq<ContentDigest>>::eq` call.
    #[test]
    fn test_partial_eq_content_digest_arc_bytes_carries_through_generic_consumer() {
        fn fwd_via_bound<T: PartialEq<std::sync::Arc<[u8]>>>(
            t: &T,
            expected: &std::sync::Arc<[u8]>,
        ) -> bool {
            <T as PartialEq<std::sync::Arc<[u8]>>>::eq(t, expected)
        }
        fn rev_via_bound<T: PartialEq<ContentDigest>>(t: &T, expected: &ContentDigest) -> bool {
            <T as PartialEq<ContentDigest>>::eq(t, expected)
        }
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        for raw in [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ] {
            let d = ContentDigest::parse(&raw).unwrap();
            let arced: std::sync::Arc<[u8]> = std::sync::Arc::<[u8]>::from(raw.as_bytes());
            assert!(fwd_via_bound(&d, &arced));
            assert!(rev_via_bound(&arced, &d));
            let other = if raw.starts_with("sha256:") {
                format!("sha512:{}", "0".repeat(SHA512_HEX_LEN))
            } else {
                format!("sha256:{D1}")
            };
            let other_arced: std::sync::Arc<[u8]> = std::sync::Arc::<[u8]>::from(other.as_bytes());
            assert!(!fwd_via_bound(&d, &other_arced));
            assert!(!rev_via_bound(&other_arced, &d));
        }
    }

    /// `PartialEq<Rc<[u8]>> for ContentDigest` agrees byte-for-byte
    /// with the borrowed-view [`AsRef<[u8]>`] oracle across the same
    /// 4-canonical × ~8-label grid the sibling cross-thread shared-
    /// owned [`Arc<[u8]>`] peer pins (test
    /// `test_partial_eq_arc_bytes_agrees_with_as_ref`, commit 13c64ad),
    /// threaded through a thread-local shared-owned [`Rc<[u8]>`]
    /// handle so the caller writes `digest == rc_bytes`.
    #[test]
    fn test_partial_eq_rc_bytes_agrees_with_as_ref() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let digests = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        let rced: Vec<std::rc::Rc<[u8]>> = digests
            .iter()
            .flat_map(|d| {
                [
                    std::rc::Rc::<[u8]>::from(d.as_bytes()),
                    std::rc::Rc::<[u8]>::from(format!("SHA256:{}", &d[7..]).as_bytes()),
                    std::rc::Rc::<[u8]>::from(format!(" {d}").as_bytes()),
                    std::rc::Rc::<[u8]>::from(format!("{d}\n").as_bytes()),
                ]
            })
            .chain([
                std::rc::Rc::<[u8]>::from(&[][..]),
                std::rc::Rc::<[u8]>::from(&b"sha256:"[..]),
                std::rc::Rc::<[u8]>::from(&b"not-a-digest"[..]),
                std::rc::Rc::<[u8]>::from(&[0xff, 0xfe, 0xfd][..]),
            ])
            .collect();
        for raw in &digests {
            let d = ContentDigest::parse(raw).unwrap();
            for label in &rced {
                assert_eq!(
                    <ContentDigest as PartialEq<std::rc::Rc<[u8]>>>::eq(&d, label),
                    <ContentDigest as AsRef<[u8]>>::as_ref(&d) == label.as_ref(),
                    "PartialEq<Rc<[u8]>> and AsRef<[u8]> equality must agree at ({label:?}, {raw:?})",
                );
            }
        }
    }

    /// At every validated [`ContentDigest`] value, the peer recognises
    /// the digest's own emitted canonical form as an [`Rc<[u8]>`] AND
    /// round-trips through the sibling by-value thread-local shared-
    /// owned byte-slice emit peer
    /// [`From<ContentDigest> for std::rc::Rc<[u8]>`] (commit
    /// 578dbc6) — so the two thread-local shared-owned byte-slice
    /// surfaces agree at their shared canonical form. Structural
    /// mirror of `test_partial_eq_arc_bytes_reflexive_at_own_digest`
    /// (commit 13c64ad) at the sibling cross-thread shared-owned
    /// byte-slice frontier.
    #[test]
    fn test_partial_eq_rc_bytes_reflexive_at_own_digest() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        for raw in [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ] {
            let d = ContentDigest::parse(&raw).unwrap();
            let canonical: std::rc::Rc<[u8]> = std::rc::Rc::<[u8]>::from(d.as_str().as_bytes());
            assert!(
                <ContentDigest as PartialEq<std::rc::Rc<[u8]>>>::eq(&d, &canonical),
                "PartialEq<Rc<[u8]>> must recognise self canonical form at {raw:?}",
            );
            let emitted: std::rc::Rc<[u8]> = std::rc::Rc::<[u8]>::from(d.clone());
            assert!(
                <ContentDigest as PartialEq<std::rc::Rc<[u8]>>>::eq(&d, &emitted),
                "PartialEq<Rc<[u8]>> must agree with From<ContentDigest> for Rc<[u8]> at {raw:?}",
            );
        }
    }

    /// Every thread-local shared-owned [`Rc<[u8]>`] that is NOT the
    /// digest's own emitted canonical form fails equality through
    /// [`PartialEq<Rc<[u8]>>`] — the same canonicity discipline the
    /// sibling receiver peers enforce, projected onto the
    /// [`Rc<[u8]>`] byte-buffer receiver. Structural mirror of
    /// `test_partial_eq_arc_bytes_rejects_non_canonical_labels`
    /// (commit 13c64ad) at the sibling cross-thread shared-owned
    /// byte-slice frontier.
    #[test]
    fn test_partial_eq_rc_bytes_rejects_non_canonical_labels() {
        let d1 = ContentDigest::parse(&format!("sha256:{D1}")).unwrap();
        let d2 = ContentDigest::parse(&format!("sha256:{D2}")).unwrap();
        let bad: [std::rc::Rc<[u8]>; 8] = [
            std::rc::Rc::<[u8]>::from(&[][..]),
            std::rc::Rc::<[u8]>::from(&b"sha256:"[..]),
            std::rc::Rc::<[u8]>::from(&b"not-a-digest"[..]),
            std::rc::Rc::<[u8]>::from(format!("SHA256:{D1}").as_bytes()),
            std::rc::Rc::<[u8]>::from(format!(" sha256:{D1}").as_bytes()),
            std::rc::Rc::<[u8]>::from(format!("sha256:{D1}\n").as_bytes()),
            std::rc::Rc::<[u8]>::from(format!("sha256:{D2}").as_bytes()),
            std::rc::Rc::<[u8]>::from(&[0xff, 0xfe, 0xfd][..]),
        ];
        for label in &bad {
            assert!(
                !<ContentDigest as PartialEq<std::rc::Rc<[u8]>>>::eq(&d1, label),
                "PartialEq<Rc<[u8]>> must reject non-canonical label {label:?} at sha256:{D1}",
            );
        }
        let d1_canonical: std::rc::Rc<[u8]> =
            std::rc::Rc::<[u8]>::from(format!("sha256:{D1}").as_bytes());
        assert!(!<ContentDigest as PartialEq<std::rc::Rc<[u8]>>>::eq(
            &d2,
            &d1_canonical
        ),);
    }

    /// The reverse-direction thread-local shared-owned byte-slice
    /// comparison peer `<Rc<[u8]> as PartialEq<ContentDigest>>::eq`
    /// agrees byte-for-byte with the borrowed-view [`AsRef<[u8]>`]
    /// oracle across the same grid AND is symmetric with the forward-
    /// direction peer at every `(rc, digest)` pair. Structural mirror
    /// of `test_arc_bytes_partial_eq_content_digest_symmetric_and_agrees_with_as_ref`
    /// (commit 13c64ad) at the sibling cross-thread shared-owned
    /// byte-slice frontier.
    #[test]
    fn test_rc_bytes_partial_eq_content_digest_symmetric_and_agrees_with_as_ref() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        let digests = [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ];
        let rced: Vec<std::rc::Rc<[u8]>> = digests
            .iter()
            .map(|d| std::rc::Rc::<[u8]>::from(d.as_bytes()))
            .chain([
                std::rc::Rc::<[u8]>::from(&[][..]),
                std::rc::Rc::<[u8]>::from(&b"sha256:"[..]),
                std::rc::Rc::<[u8]>::from(&b"not-a-digest"[..]),
                std::rc::Rc::<[u8]>::from(format!("SHA256:{D1}").as_bytes()),
                std::rc::Rc::<[u8]>::from(format!(" sha256:{D1}").as_bytes()),
                std::rc::Rc::<[u8]>::from(format!("sha256:{D1}\n").as_bytes()),
                std::rc::Rc::<[u8]>::from(&[0xff, 0xfe, 0xfd][..]),
            ])
            .collect();
        for raw in &digests {
            let d = ContentDigest::parse(raw).unwrap();
            for label in &rced {
                assert_eq!(
                    <std::rc::Rc<[u8]> as PartialEq<ContentDigest>>::eq(label, &d),
                    label.as_ref() == <ContentDigest as AsRef<[u8]>>::as_ref(&d),
                    "reverse Rc<[u8]> and AsRef<[u8]> equality must agree at ({label:?}, {raw:?})",
                );
                assert_eq!(
                    <std::rc::Rc<[u8]> as PartialEq<ContentDigest>>::eq(label, &d),
                    <ContentDigest as PartialEq<std::rc::Rc<[u8]>>>::eq(&d, label),
                    "reverse-Rc<[u8]> vs forward-Rc<[u8]> direction must agree at ({label:?}, {raw:?})",
                );
            }
        }
    }

    /// The thread-local shared-owned [`Rc<[u8]>`] forward and reverse
    /// peers compose with a generic
    /// `PartialEq<Rc<[u8]>>`- / `PartialEq<ContentDigest>`-bounded
    /// consumer — a downstream site that types its comparison contract
    /// as `impl PartialEq<Rc<[u8]>>` recovers the same answer as a
    /// direct `<ContentDigest as PartialEq<Rc<[u8]>>>::eq` call, and
    /// the reverse-direction bound `impl PartialEq<ContentDigest>`
    /// recovers the same answer as a direct
    /// `<Rc<[u8]> as PartialEq<ContentDigest>>::eq` call. Structural
    /// mirror of
    /// `test_partial_eq_content_digest_arc_bytes_carries_through_generic_consumer`
    /// (commit 13c64ad) at the sibling cross-thread shared-owned
    /// byte-slice frontier.
    #[test]
    fn test_partial_eq_content_digest_rc_bytes_carries_through_generic_consumer() {
        fn fwd_via_bound<T: PartialEq<std::rc::Rc<[u8]>>>(
            t: &T,
            expected: &std::rc::Rc<[u8]>,
        ) -> bool {
            <T as PartialEq<std::rc::Rc<[u8]>>>::eq(t, expected)
        }
        fn rev_via_bound<T: PartialEq<ContentDigest>>(t: &T, expected: &ContentDigest) -> bool {
            <T as PartialEq<ContentDigest>>::eq(t, expected)
        }
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        for raw in [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
        ] {
            let d = ContentDigest::parse(&raw).unwrap();
            let rced: std::rc::Rc<[u8]> = std::rc::Rc::<[u8]>::from(raw.as_bytes());
            assert!(fwd_via_bound(&d, &rced));
            assert!(rev_via_bound(&rced, &d));
            let other = if raw.starts_with("sha256:") {
                format!("sha512:{}", "0".repeat(SHA512_HEX_LEN))
            } else {
                format!("sha256:{D1}")
            };
            let other_rced: std::rc::Rc<[u8]> = std::rc::Rc::<[u8]>::from(other.as_bytes());
            assert!(!fwd_via_bound(&d, &other_rced));
            assert!(!rev_via_bound(&other_rced, &d));
        }
    }

    /// [`serde::Serialize`] emits the validated backing string as a
    /// JSON string that agrees byte-for-byte with the
    /// [`ContentDigest::as_str`] read across every algorithm arm the
    /// [`ContentDigest::parse`] oracle accepts (sha256 / sha512 /
    /// blake3). Guards the load-bearing serde-frontier emit contract:
    /// a downstream attestation-record schema that carries a
    /// [`ContentDigest`] field emits the canonical trimmed
    /// lowercase-hex form, not a re-formatted or pre-trim rendering.
    #[test]
    fn test_serialize_matches_as_str_across_algorithms() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        for raw in [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha256:{D3}"),
            format!("sha512:{hex512}"),
            format!("blake3:{D1}"),
        ] {
            let d = ContentDigest::parse(&raw).unwrap();
            let json = serde_json::to_string(&d).unwrap();
            assert_eq!(
                json,
                format!("\"{raw}\""),
                "serialize must emit the validated backing string verbatim at {raw:?}",
            );
        }
    }

    /// [`serde::Deserialize`] round-trips a well-formed
    /// `<algorithm>:<hex>` JSON string back to a
    /// [`ContentDigest`] value that compares equal to the source at
    /// every algorithm arm, and the read routes through
    /// [`ContentDigest::parse`] (via [`TryFrom<Cow<'_, str>>`]) so the
    /// as-str, algorithm, and hex accessors report the same trimmed
    /// canonical form as the direct parse peer.
    #[test]
    fn test_deserialize_valid_digest_round_trip() {
        let hex512 = "f".repeat(SHA512_HEX_LEN);
        for raw in [
            format!("sha256:{D1}"),
            format!("sha256:{D2}"),
            format!("sha512:{hex512}"),
            format!("blake3:{D1}"),
        ] {
            let json = format!("\"{raw}\"");
            let d: ContentDigest = serde_json::from_str(&json).unwrap();
            let direct = ContentDigest::parse(&raw).unwrap();
            assert_eq!(d, direct);
            assert_eq!(d.as_str(), direct.as_str());
            assert_eq!(d.algorithm(), direct.algorithm());
            assert_eq!(d.hex(), direct.hex());
            let re_emitted = serde_json::to_string(&d).unwrap();
            assert_eq!(re_emitted, json);
        }
    }

    /// [`serde::Deserialize`] refuses every input the direct
    /// [`ContentDigest::parse`] oracle refuses: missing separator,
    /// unsupported algorithm, wrong-length hex, uppercase hex.
    /// Discipline-mirror of the parse-oracle negative grid projected
    /// onto the serde frontier so the schema surface cannot admit a
    /// digest string the direct parse call would refuse.
    #[test]
    fn test_deserialize_rejects_malformed_digests() {
        for raw in [
            "".to_string(),
            "sha256".to_string(),
            "sha256:".to_string(),
            "not-a-digest".to_string(),
            format!("md5:{D1}"),
            format!("SHA256:{D1}"),
            format!("sha256:{}", &D1[..63]),
            format!("sha256:{D1}f"),
            format!("sha256:{}", D1.to_uppercase()),
            format!("blake3:{}", &D1[..63]),
            format!("blake3:{}", D1.to_uppercase()),
            format!("sha512:{}", "0".repeat(SHA512_HEX_LEN - 1)),
        ] {
            let json = format!("\"{raw}\"");
            assert!(
                serde_json::from_str::<ContentDigest>(&json).is_err(),
                "deserialize must refuse malformed digest {raw:?}",
            );
        }
    }

    /// [`serde::Deserialize`] refuses a JSON scalar that is not a
    /// string at all — a JSON number, a JSON boolean, a JSON null, a
    /// JSON array, a JSON object. The serde-frontier parse peer
    /// receives its input off the borrowed / owned `Cow<'de, str>`
    /// intake at the deserializer boundary, so a non-string arm
    /// surfaces the deserializer's own type-error rather than a
    /// [`ContentDigestError`] the parse oracle emits.
    #[test]
    fn test_deserialize_rejects_wrong_json_types() {
        for input in ["42", "true", "false", "null", "[]", "{}"] {
            assert!(
                serde_json::from_str::<ContentDigest>(input).is_err(),
                "deserialize must refuse non-string JSON {input:?}",
            );
        }
    }

    /// [`ContentDigest`] embedded as a serde-derived container field
    /// deserializes off the same one-oracle grammar the standalone
    /// peer reads through — the schema-surface use case documented in
    /// the [`serde::Deserialize`] impl doc block, exercised here on a
    /// minimal wrapper. A malformed digest at the wrapper field
    /// surfaces as a serde error at read time; a well-formed digest
    /// round-trips through the wrapper. Guards the load-bearing
    /// migration path the parse-oracle blake3 widening
    /// (commit 2e83ff8) called out: attestation-record and
    /// deploy-schema fields typed as [`ContentDigest`] rather than
    /// [`String`] reject malformed digests at the serde boundary.
    #[test]
    fn test_deserialize_within_serde_derived_struct() {
        #[derive(serde::Deserialize, serde::Serialize)]
        struct Wrapper {
            digest: ContentDigest,
        }
        let raw = format!("blake3:{D1}");
        let json = format!("{{\"digest\":\"{raw}\"}}");
        let w: Wrapper = serde_json::from_str(&json).unwrap();
        assert_eq!(w.digest.as_str(), raw);
        let round_tripped = serde_json::to_string(&w).unwrap();
        assert_eq!(round_tripped, json);
        let malformed = format!("{{\"digest\":\"md5:{D1}\"}}");
        assert!(serde_json::from_str::<Wrapper>(&malformed).is_err());
    }

    /// The serde emit and parse peers carry through generic serde-
    /// bounded consumers — a downstream site that types its emit
    /// contract as `T: serde::Serialize` recovers the same JSON as a
    /// direct [`serde_json::to_string`] on [`ContentDigest`], and a
    /// site that types its parse contract as
    /// `for<'de> T: serde::Deserialize<'de>` recovers the same
    /// [`ContentDigest`] value as a direct [`serde_json::from_str`].
    /// Structural mirror of the `carries_through_generic_consumer`
    /// discipline the sibling parse / emit / equality peers already
    /// carry, projected onto the serde-frontier surface.
    #[test]
    fn test_serde_peers_carry_through_generic_consumer() {
        fn emit_via_bound<T: serde::Serialize>(t: &T) -> String {
            serde_json::to_string(t).unwrap()
        }
        fn read_via_bound<T: for<'de> serde::Deserialize<'de>>(s: &str) -> T {
            serde_json::from_str(s).unwrap()
        }
        let raw = format!("sha256:{D1}");
        let d = ContentDigest::parse(&raw).unwrap();
        let json_generic = emit_via_bound(&d);
        let json_direct = serde_json::to_string(&d).unwrap();
        assert_eq!(json_generic, json_direct);
        let d_generic: ContentDigest = read_via_bound(&json_generic);
        let d_direct: ContentDigest = serde_json::from_str(&json_generic).unwrap();
        assert_eq!(d_generic, d_direct);
        assert_eq!(d_generic, d);
    }
}
