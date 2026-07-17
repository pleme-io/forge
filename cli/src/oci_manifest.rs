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
