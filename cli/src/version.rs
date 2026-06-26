//! Version parsing and manipulation utilities
//!
//! Provides semver parsing, bumping, and reading/writing version strings
//! from various manifest formats (Cargo.toml, build.zig.zon, Chart.yaml, package.json).

use anyhow::{bail, Context, Result};
use std::path::Path;
use std::str::FromStr;

/// Parse a semver version string into (major, minor, patch).
pub fn parse_semver(version: &str) -> Result<(u64, u64, u64)> {
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() != 3 {
        bail!("Invalid version format '{}' — expected X.Y.Z", version);
    }

    let major = parts[0].parse::<u64>().context("Invalid major version")?;
    let minor = parts[1].parse::<u64>().context("Invalid minor version")?;
    let patch = parts[2].parse::<u64>().context("Invalid patch version")?;

    Ok((major, minor, patch))
}

/// The three-variant typed sum naming which semver component
/// [`bump_semver_typed`] increments — the typed-primitive peer of the
/// `level: &str` parameter [`bump_semver`] previously accepted. Lifts the
/// `match level { "patch" | "minor" | "major" | _ => bail!(...) }` runtime
/// trap to an exhaustive `match self { Patch | Minor | Major }` the
/// compiler refuses the missing arm of.
///
/// Construction routes through the [`FromStr`] impl: `"patch"`, `"minor"`,
/// and `"major"` are the canonical lowercase strings (matching the prior
/// match arms exactly); any other string errors with the same wording the
/// prior `bump_semver` trap emitted. The [`Display`](std::fmt::Display)
/// impl is the inverse: each variant renders as its canonical lowercase
/// string, so a `BumpLevel::from_str(&level.to_string())` round-trip is the
/// identity at every variant — pinned by
/// [`tests::test_bump_level_display_round_trips_through_from_str`].
///
/// # Why the typed sum
///
/// The prior `bump_semver(version: &str, level: &str)` was a structurally
/// partial function over the level axis: the four-arm match (`patch` /
/// `minor` / `major` / `_ => bail!`) trades compile-time exhaustiveness
/// for a runtime trap whenever a caller passes an unrecognized string.
/// Routing every caller through the typed [`BumpLevel`] surface makes the
/// function TOTAL on the typed-level domain — every [`BumpLevel`] variant
/// is structurally a valid input, and the compiler refuses a future
/// `bump_semver_typed` match that drops a variant.
///
/// The grammar oracle (which strings parse to which variant) is named at
/// one site — the [`FromStr`] impl — so a future CLI surface that wants to
/// accept an aliased input (`"p"` → `BumpLevel::Patch`, `"prerelease"` →
/// a future fourth variant) extends the parser at this typed-primitive
/// site instead of retyping the alias matrix at every caller's
/// `match level { ... }` cascade. Same THEORY.md §VI.1 one-oracle
/// discipline the prior typed-method lifts established at the
/// [`crate::retry::RetryPolicy`] / [`crate::probe_outcome::AdmissionTier`]
/// surfaces, here applied to the version-bump axis.
///
/// THEORY.md §V.4 typed primitives: the level axis carries a typed sum
/// surface (one variant per semver component the bump increments), not a
/// `&str` shape that re-derives the partial function at every consumer.
/// THEORY.md §VI.1 one-oracle discipline: the level grammar is named at
/// one site (the [`FromStr`] impl), not retyped at every caller's
/// `match level { ... }` cascade.
///
/// # The magnitude ladder
///
/// [`BumpLevel`] carries a total order — `Patch < Minor < Major` — encoding
/// the **magnitude of the bump**: a major bump strictly subsumes a minor
/// bump, which strictly subsumes a patch bump, in the sense that the
/// release-pipeline policy "this change requires at least X" is a single
/// `>=` comparison rather than a three-arm disjunction at every caller. A
/// SLSA-style provenance gate that says "API-breaking changes require at
/// least a Major bump" reads `level >= BumpLevel::Major`; a public-surface
/// gate that says "any public addition requires at least a Minor bump"
/// reads `level >= BumpLevel::Minor`. The variant declaration order
/// (`Patch`, `Minor`, `Major`) is load-bearing — `#[derive(PartialOrd,
/// Ord)]` derives the ladder from the source order, so a future variant
/// extension (e.g., a `Prerelease` variant inserted between or beside
/// these) must consider where in the ladder it sits.
///
/// Same THEORY.md §V.5 total-order discipline the
/// [`crate::probe_outcome::AdmissionTier`] surface established at the
/// `Refused < StagingOnly < Strict` admission ladder, here applied to the
/// version-bump-magnitude axis. The compiler refuses any future
/// `match level { ... }` cascade that drops a variant, and the ladder is
/// derived from one source ordering rather than retyped at every
/// comparison site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BumpLevel {
    /// Increment the patch component (Z in X.Y.Z), preserving major and
    /// minor. Maps to the canonical lowercase string `"patch"` under
    /// [`FromStr`] and [`Display`](std::fmt::Display).
    Patch,
    /// Increment the minor component (Y in X.Y.Z), resetting patch to 0,
    /// preserving major. Maps to the canonical lowercase string
    /// `"minor"`.
    Minor,
    /// Increment the major component (X in X.Y.Z), resetting minor and
    /// patch to 0. Maps to the canonical lowercase string `"major"`.
    Major,
}

impl BumpLevel {
    /// Every [`BumpLevel`] variant, listed in magnitude-ladder order
    /// (`Patch < Minor < Major`) — the single-source enumeration of the
    /// typed sum. The named typed-primitive peer of the array-literal
    /// `[BumpLevel::Patch, BumpLevel::Minor, BumpLevel::Major]` that
    /// previously appeared at 17 sites inside this module's test cases
    /// (the per-variant `for level in [...] { ... }` traversal idiom).
    /// A consumer that needs to iterate every variant — exhaustive-cover
    /// property tests, CLI shell-completion tables, telemetry-label
    /// enumeration — reads `BumpLevel::ALL` once instead of restating the
    /// variant list at the call site.
    ///
    /// # Why the named const, not the array literal
    ///
    /// The array literal `[Patch, Minor, Major]` is a structural
    /// duplication of the enum's variant declaration: every time a
    /// caller restates it, a future variant insertion (`Prerelease`
    /// below `Patch`, `Epoch` above `Major`) leaves silent gaps at
    /// every restatement site — the literal carries no compile-time
    /// signal that it must be extended. A `for level in
    /// [BumpLevel::Patch, BumpLevel::Minor, BumpLevel::Major]` traversal
    /// that drove a fail-before / pass-after property test would
    /// continue to pass after the variant insertion, but only against
    /// the three legacy variants — the new variant would never be
    /// exercised by the property, and the property would silently
    /// degrade to a partial cover.
    ///
    /// Routing every traversal through [`BumpLevel::ALL`] makes the
    /// enumeration single-source: a future variant insertion forces
    /// the author to extend this one const (the test
    /// [`tests::test_bump_level_all_contains_every_variant`] uses an
    /// exhaustive `match` against the variant axis to refuse compilation
    /// until the new variant is added to `ALL`), and every property test
    /// that iterates `BumpLevel::ALL` automatically picks up the new
    /// variant without per-site edits. Same THEORY.md §VI.1
    /// generation-over-composition / three-times-rule discipline the
    /// prior typed-method-peer lifts established (`is_breaking` /
    /// `is_non_breaking` / `is_fix_only` / `is_minor_only` over the
    /// magnitude ladder), here applied to the variant-enumeration
    /// duplication that recurs across the per-variant traversal call
    /// sites: 17 occurrences of `[Patch, Minor, Major]` in the test
    /// module is far past the three-times threshold for
    /// archetype/backend extraction.
    ///
    /// # Ladder-order invariant
    ///
    /// The element order of [`BumpLevel::ALL`] coincides with the
    /// derived [`Ord`] ladder: `ALL[0] < ALL[1] < ALL[2]`. The pin
    /// [`tests::test_bump_level_all_is_canonical_ladder_order`] asserts
    /// `ALL.to_vec()` equals the result of `ALL.to_vec().sort()` so a
    /// future variant insertion or reordering that desynced the array
    /// from the source-order ladder lights up. A consumer that depends
    /// on iterating from least-to-greatest magnitude (e.g., a release-
    /// pipeline policy report enumerating bump levels in escalating
    /// review-stringency order) reads `BumpLevel::ALL` directly without
    /// a per-call-site sort.
    ///
    /// THEORY.md §V.4 typed primitives: the variant enumeration is a
    /// typed-primitive surface on `BumpLevel` itself (one named const),
    /// not a `&[BumpLevel]` shape restated at every traversal site that
    /// re-derives the enumeration. THEORY.md §VI.1 generation over
    /// composition (three-times rule): a structural pattern that recurs
    /// three or more times becomes a named primitive at one site —
    /// here, 17 array-literal restatements collapse to one const.
    #[allow(dead_code)]
    pub const ALL: [Self; 3] = [Self::Patch, Self::Minor, Self::Major];

    /// The canonical lowercase string each variant renders as under
    /// [`Display`](std::fmt::Display) and parses from under [`FromStr`].
    /// Const-callable so a `const ARGNAME: &str = BumpLevel::Patch.as_str();`
    /// table at a future CLI-completion site is admissible.
    #[allow(dead_code)]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Patch => "patch",
            Self::Minor => "minor",
            Self::Major => "major",
        }
    }

    /// True iff `self` sits at the top of the magnitude ladder
    /// (`BumpLevel::Major` or, structurally, any future variant inserted
    /// strictly above it) — the named typed-method peer of the
    /// `level >= BumpLevel::Major` comparison the prior commit (8c2bbd5,
    /// magnitude ladder lift) made admissible. A SLSA-style release-
    /// provenance gate that says "API-breaking changes require at least a
    /// Major bump" reads `level.is_breaking()` instead of a three-arm
    /// `match level { Major => true, Minor | Patch => false }` cascade at
    /// every policy site — the breaking-vs-non-breaking semantic role is
    /// named at the typed-primitive surface, not retyped at every consumer.
    ///
    /// # Why `>= Self::Major`, not `matches!(self, Self::Major)`
    ///
    /// The implementation reads `*self >= Self::Major`, not
    /// `matches!(self, Self::Major)`. The two coincide at the current
    /// three-variant ladder (`Patch < Minor < Major`), but the `>=` form
    /// makes the total-order discipline (commit 8c2bbd5) the load-bearing
    /// oracle: a future variant `BumpLevel::Epoch` inserted in source order
    /// strictly above `Major` (semver4 / `0ver`-style incompatible-by-
    /// design rewrites) is automatically `> Major` and so structurally
    /// classified as breaking — the same way `AdmissionTier::admits_relaxed`
    /// reads `self >= StagingOnly` rather than
    /// `matches!(self, StagingOnly | Strict)` so a future tier inserted
    /// above `StagingOnly` is admitted under the relaxed gate without
    /// retyping the predicate. The `matches!` form would silently classify
    /// the new top-of-ladder variant as non-breaking — a structural bug
    /// the `>=` form refuses by construction.
    ///
    /// THEORY.md §V.5 total-order discipline: the breaking-vs-non-breaking
    /// gate reads the derived `Ord` impl through a named typed-method peer
    /// at the typed-primitive surface, not retyped at every consumer's
    /// match cascade. THEORY.md §VI.1 one-oracle: the semantic role
    /// (breaking ⇔ at-or-above Major) is named at one site (this method's
    /// body), so a future ladder extension (an `Epoch` variant above
    /// `Major`) propagates through every consumer that reads
    /// `level.is_breaking()` without per-site reclassification.
    #[allow(dead_code)]
    pub fn is_breaking(&self) -> bool {
        *self >= Self::Major
    }

    /// True iff `self` sits strictly below the breaking-change threshold —
    /// i.e., `*self < Self::Major` under the derived [`Ord`] instance. The
    /// named typed-method De Morgan complement of [`is_breaking`]
    /// (`Self::is_breaking`) at the version-bump-magnitude surface: the
    /// third leg of the named-method gate trio over the breaking-change
    /// threshold, naming the "this bump preserves backward compatibility"
    /// reading that downstream consumers previously had to write as
    /// `!level.is_breaking()` (or `matches!(level, Patch | Minor)` against
    /// the variants directly). A SLSA-style release-provenance gate that
    /// says "a non-breaking change can ship to the stable channel without
    /// the API-review attestation" reads `level.is_non_breaking()` instead
    /// of `!level.is_breaking()` or a two-arm `match level { Patch | Minor
    /// => allow, Major => require_attestation }` cascade at every policy
    /// site — the backward-compatibility semantic role is named at the
    /// typed-primitive surface, not retyped at every consumer.
    ///
    /// # Why `< Self::Major`, not `!self.is_breaking()` or `matches!`
    ///
    /// Under the present three-variant ladder, `is_non_breaking` reduces
    /// to `matches!(self, Self::Patch | Self::Minor)` and to
    /// `!self.is_breaking()`, but the `<` form is the load-bearing one. It
    /// makes the total-order discipline (commit 8c2bbd5) the structural
    /// oracle for the backward-compatibility partition the same way the
    /// `>=` form does for [`is_breaking`]: a future variant
    /// `BumpLevel::Prerelease` inserted in source order strictly below
    /// `Patch` (release-candidate / staging-channel bump shapes) is
    /// automatically `< Major` and so structurally classified as
    /// non-breaking — without retyping the predicate at every consumer.
    /// The `matches!` form would silently misclassify the new floor variant
    /// (it would NOT match `Patch | Minor` and so would read as breaking),
    /// inheriting the same drift class
    /// [`crate::probe_outcome::AdmissionTier::refuses_relaxed`] avoids by
    /// reading `< StagingOnly` rather than `matches!(self, Refused)`. Same
    /// THEORY.md §V.5 total-order discipline at the version-bump surface as
    /// at the admission-gate surface.
    ///
    /// # De Morgan / XOR partition
    ///
    /// The De Morgan complementarity invariant
    /// `is_non_breaking() == !is_breaking()` is pinned by
    /// [`tests::test_bump_level_is_non_breaking_equals_negation_of_is_breaking`]:
    /// the two predicates are exact complements at every variant. The
    /// disjoint-and-covering partition pin
    /// [`tests::test_bump_level_is_non_breaking_xor_is_breaking_partitions_ladder`]
    /// nails `is_non_breaking() XOR is_breaking() == true` so a regression
    /// that broke either method body (e.g., a future hand-rolled
    /// `matches!(self, Self::Patch | Self::Minor)` body that drifted from
    /// the `<` form across a fourth-variant addition) surfaces as a
    /// partition gap or overlap at the new variant. Same partition shape
    /// the `AdmissionTier::refuses_relaxed` / `admits_relaxed` pair sealed
    /// at the admission-gate surface, here at the version-bump-magnitude
    /// surface.
    ///
    /// THEORY.md §V.5 total-order discipline: the backward-compatibility
    /// gate reads the derived `Ord` impl through a named typed-method peer
    /// at the typed-primitive surface, not retyped at every consumer's
    /// match cascade. THEORY.md §VI.1 one-oracle: the semantic role
    /// (non-breaking ⇔ strictly below Major) is named at one site (this
    /// method's body), so a future ladder extension (a `Prerelease` variant
    /// below `Patch`) propagates through every consumer that reads
    /// `level.is_non_breaking()` without per-site reclassification.
    #[allow(dead_code)]
    pub fn is_non_breaking(&self) -> bool {
        *self < Self::Major
    }

    /// True iff `self` is exactly [`BumpLevel::Patch`] — the named typed-
    /// method peer at the floor of the version-bump magnitude ladder. The
    /// "this bump is a fix-only patch" reading downstream consumers
    /// previously had to write as `matches!(level, BumpLevel::Patch)` or
    /// `*level == BumpLevel::Patch` per call site. A SLSA-style release-
    /// provenance gate that says "fix-only releases bypass the API-review
    /// queue and ship directly to the stable channel" reads
    /// `level.is_fix_only()` instead of `matches!(level, BumpLevel::Patch)`
    /// or a single-arm `match level { Patch => allow, _ => bail }` at every
    /// policy site — the fix-only semantic role is named at the typed-
    /// primitive surface, not retyped at every consumer.
    ///
    /// # Why `== Self::Patch`, not `<= Self::Patch` or `matches!`
    ///
    /// Unlike [`is_breaking`] (which reads `>= Self::Major` so a future
    /// `Epoch` variant inserted above `Major` is automatically classified
    /// as breaking) and [`is_non_breaking`] (which reads `< Self::Major`
    /// so a future `Prerelease` variant inserted below `Patch` is
    /// automatically classified as non-breaking), the fix-only band names
    /// a single variant by intent, not a half-open ray. A future
    /// `BumpLevel::Prerelease` variant inserted strictly below `Patch`
    /// (release-candidate / staging-channel bump shapes) is structurally
    /// NOT a fix — it is its own bump category — and so must NOT read as
    /// fix-only. The `<= Self::Patch` form would silently misclassify the
    /// new floor variant; the `*self == Self::Patch` form refuses by
    /// construction. The choice mirrors
    /// [`crate::probe_outcome::AdmissionTier::is_staging_only`] (commit
    /// e08b821) at the admission-gate surface, where naming a single
    /// middle band variant likewise reads through equality rather than a
    /// half-open ray to refuse silent reclassification across future
    /// ladder insertions either side of the band.
    ///
    /// # Implication into `is_non_breaking`, disjoint from `is_breaking`
    ///
    /// The implication invariant `is_fix_only() => is_non_breaking()` is
    /// pinned by
    /// [`tests::test_bump_level_is_fix_only_implies_is_non_breaking`]: a
    /// fix-only bump is structurally a non-breaking bump (every Patch is
    /// strictly below Major), so a downstream release-policy gate that
    /// already reads `is_non_breaking()` will admit every `is_fix_only()`
    /// bump automatically. The disjoint invariant `!(is_fix_only() &&
    /// is_breaking())` is pinned by
    /// [`tests::test_bump_level_is_fix_only_disjoint_from_is_breaking`]:
    /// no bump is simultaneously fix-only AND breaking — the two named
    /// predicates partition the magnitude ladder into non-overlapping
    /// extremes. With this and its sibling pins, the breaking /
    /// non-breaking / fix-only typed-method peer trio over the magnitude
    /// ladder is sealed against accidental overlap at the present three-
    /// variant ladder and against silent misclassification across future
    /// ladder extensions either side of the breaking-change threshold.
    ///
    /// THEORY.md §V.5 total-order discipline: the version-bump-magnitude
    /// ladder is consumed at named typed-method surfaces, not retyped at
    /// every consumer's match cascade — the floor predicate sits at the
    /// typed-primitive surface alongside the threshold and ceiling
    /// predicates. THEORY.md §VI.1 one-oracle: the fix-only semantic role
    /// (this bump is exactly the patch-level fix variant) is named at one
    /// site (this method's body), so a downstream policy gate that
    /// previously read `matches!(level, BumpLevel::Patch)` reads
    /// `level.is_fix_only()` once and is automatically refused — by the
    /// `==` form — across a future `Prerelease` insertion below `Patch`
    /// that the gate should NOT classify as fix-only.
    #[allow(dead_code)]
    pub fn is_fix_only(&self) -> bool {
        *self == Self::Patch
    }

    /// True iff `self` is exactly [`BumpLevel::Minor`] — the named typed-
    /// method peer at the middle band of the version-bump magnitude ladder.
    /// The "this bump is a backwards-compatible-addition minor bump" reading
    /// downstream consumers previously had to write as `matches!(level,
    /// BumpLevel::Minor)` or `*level == BumpLevel::Minor` per call site. A
    /// SLSA-style release-provenance gate that says "minor-only releases
    /// follow the additive-API attestation channel (distinct from the
    /// fix-only fast path and the breaking-change review queue)" reads
    /// `level.is_minor_only()` instead of `matches!(level, BumpLevel::Minor)`
    /// or a single-arm `match level { Minor => additive_channel, _ => bail }`
    /// at every policy site — the minor-only semantic role is named at the
    /// typed-primitive surface, not retyped at every consumer.
    ///
    /// # Why `== Self::Minor`, not `is_non_breaking() && !is_fix_only()`
    ///
    /// Like [`is_fix_only`] (which reads `*self == Self::Patch` so a future
    /// `Prerelease` variant inserted below `Patch` is structurally NOT a
    /// fix), the minor-only band names a single variant by intent — not the
    /// non-fix half of the non-breaking range. The decomposition form
    /// `is_non_breaking() && !is_fix_only()` would coincide with
    /// `*self == Self::Minor` at the present three-variant ladder, but a
    /// future variant inserted below `Patch` (e.g., a `Prerelease` release-
    /// candidate / staging-channel bump shape) would silently misclassify
    /// under the decomposition: `Prerelease` is non-breaking (`< Major`) and
    /// is NOT fix-only (`!= Patch`), so the decomposition would read it as
    /// minor-only — a structural bug. The `*self == Self::Minor` form
    /// refuses by construction; the future variant gets no classification
    /// from this predicate and so forces a deliberate decision at the
    /// typed-primitive surface rather than drifting silently through every
    /// consumer that branches on `is_minor_only()`. Same single-variant
    /// naming idiom [`is_fix_only`] established at the ladder floor and
    /// [`crate::probe_outcome::AdmissionTier::is_staging_only`] established
    /// at the admission-gate surface, here at the middle band of the
    /// version-bump-magnitude ladder.
    ///
    /// # Trio partition: fix-only / minor-only / breaking covers the ladder
    ///
    /// At the present three-variant ladder, the named-method trio
    /// `is_fix_only() XOR is_minor_only() XOR is_breaking()` is a disjoint
    /// cover — exactly one predicate reads `true` at every variant. Pinned
    /// by [`tests::test_bump_level_named_trio_xor_partitions_ladder`]: a
    /// regression that drifted any of the three method bodies such that
    /// some level read `true` for two predicates (overlap) or `false` for
    /// all three (gap) lights up. Same disjoint-XOR-cover seal
    /// `AdmissionTier::admits_strict XOR is_staging_only XOR
    /// refuses_relaxed` placed at the admission-gate surface (commit
    /// e08b821), here at the version-bump-magnitude surface.
    ///
    /// The disjoint pair `!(is_minor_only() && is_fix_only())` is pinned by
    /// [`tests::test_bump_level_is_minor_only_disjoint_from_is_fix_only`]:
    /// Patch and Minor are distinct ladder positions, so the floor and
    /// middle bands never overlap. The disjoint pair `!(is_minor_only() &&
    /// is_breaking())` is pinned by
    /// [`tests::test_bump_level_is_minor_only_disjoint_from_is_breaking`]:
    /// the middle band sits strictly below the breaking threshold. The
    /// implication `is_minor_only() => is_non_breaking()` is pinned by
    /// [`tests::test_bump_level_is_minor_only_implies_is_non_breaking`]:
    /// every Minor bump is structurally below Major, so a downstream
    /// release-policy gate that admits non-breaking automatically admits
    /// every minor-only bump.
    ///
    /// THEORY.md §V.5 total-order discipline: the version-bump-magnitude
    /// ladder is consumed at named typed-method surfaces, not retyped at
    /// every consumer's match cascade — the middle-band predicate sits at
    /// the typed-primitive surface alongside the floor and threshold
    /// predicates. THEORY.md §VI.1 one-oracle: the minor-only semantic role
    /// (this bump is exactly the additive-API minor variant) is named at
    /// one site (this method's body), so a downstream policy gate that
    /// previously read `matches!(level, BumpLevel::Minor)` reads
    /// `level.is_minor_only()` once and is automatically refused — by the
    /// `==` form — across a future variant insertion either side of the
    /// `Minor` position that the gate should NOT classify as minor-only.
    #[allow(dead_code)]
    pub fn is_minor_only(&self) -> bool {
        *self == Self::Minor
    }

    /// True iff `self` is exactly [`BumpLevel::Major`] — the named typed-
    /// method peer at the ceiling of the version-bump magnitude ladder. The
    /// "this bump is exactly the canonical breaking-change major variant"
    /// reading downstream consumers previously had to write as
    /// `matches!(level, BumpLevel::Major)` or `*level == BumpLevel::Major`
    /// per call site. A release-notes generator that says "the canonical
    /// major bump triggers the human-review queue and emits the breaking-
    /// change attestation channel" reads `level.is_major_only()` instead of
    /// `matches!(level, BumpLevel::Major)` or a single-arm `match level {
    /// Major => breaking_channel, _ => other }` cascade at every policy
    /// site — the major-only semantic role is named at the typed-primitive
    /// surface, not retyped at every consumer.
    ///
    /// Ceiling-identity peer of [`is_fix_only`](Self::is_fix_only) and
    /// [`is_minor_only`](Self::is_minor_only) at the [`BumpLevel`] sum
    /// surface. Closes the three-position variant-identity trio at the
    /// named-method surface — the floor identity
    /// ([`is_fix_only`](Self::is_fix_only)), the middle-band identity
    /// ([`is_minor_only`](Self::is_minor_only)), and the ceiling identity
    /// ([`is_major_only`](Self::is_major_only), this commit) — every ladder
    /// position now carries a named variant-identity reading distinct from
    /// the half-open-ray reading at the same ladder position
    /// ([`is_breaking`](Self::is_breaking),
    /// [`is_non_breaking`](Self::is_non_breaking)).
    ///
    /// Sibling lift of
    /// [`crate::probe_outcome::AdmissionTier::is_strict`] (commit 1775181)
    /// at the admission-tier ladder ceiling: same variant-identity `==`
    /// form, same single-variant naming idiom, here applied to the
    /// magnitude-ladder ceiling. With this commit, both repo-internal tier
    /// ladders ([`BumpLevel`] and
    /// [`crate::probe_outcome::AdmissionTier`]) carry the full identity
    /// trio at the named-method surface — establishing the third repo-
    /// internal instance of the variant-identity-typed-method idiom at the
    /// ladder ceiling and motivating the future lift to a shared
    /// `pleme-actions` trait or `macro_rules!` over the two tier ladders.
    ///
    /// # Why `== Self::Major`, not `>= Self::Major` or `matches!`
    ///
    /// Unlike [`is_breaking`](Self::is_breaking) (which reads
    /// `*self >= Self::Major` so a future variant inserted strictly above
    /// `Major` is automatically classified as breaking — a half-open ray
    /// on the ladder), the major-only ceiling identity names a single
    /// variant by intent, not a half-open ray. A future `BumpLevel::Epoch`
    /// variant inserted strictly above `Major` (a semver4-style API-
    /// generation bump distinct from the canonical breaking-change major
    /// variant — its own release coordinator, its own attestation channel)
    /// is structurally NOT the canonical `Major` variant — it is a
    /// strictly-stronger bump category — and so must NOT read as
    /// `is_major_only()`. The `>= Self::Major` form would silently
    /// reclassify the new ceiling variant as the canonical major bump; the
    /// `*self == Self::Major` form refuses by construction. The choice
    /// mirrors [`is_fix_only`](Self::is_fix_only) at the ladder floor and
    /// [`is_minor_only`](Self::is_minor_only) at the middle band, where
    /// naming a single variant likewise reads through equality rather than
    /// a half-open ray to refuse silent reclassification across future
    /// ladder insertions adjacent to the named variant.
    ///
    /// # Implication into `is_breaking`, disjoint from `is_fix_only`
    ///
    /// The implication invariant `is_major_only() => is_breaking()` is
    /// pinned by
    /// [`tests::test_bump_level_is_major_only_implies_is_breaking`]: the
    /// major ceiling is structurally a breaking bump (`Major >= Major`
    /// trivially), so a downstream release-policy gate that already reads
    /// `is_breaking()` admits every `is_major_only()` bump automatically.
    /// The disjoint invariant `!(is_major_only() && is_fix_only())` is
    /// pinned by
    /// [`tests::test_bump_level_is_major_only_disjoint_from_is_fix_only`]:
    /// no bump is simultaneously the major ceiling AND the fix-only floor
    /// — the two named predicates partition the ladder into non-
    /// overlapping extremes (ceiling-identity vs floor-identity). Sibling
    /// pin of
    /// [`crate::probe_outcome::tests::test_admission_tier_is_strict_disjoint_from_refuses_relaxed`]
    /// at the admission-tier surface.
    ///
    /// # Identity-trio partition of the ladder
    ///
    /// Together with [`is_fix_only`](Self::is_fix_only) and
    /// [`is_minor_only`](Self::is_minor_only), the major-ceiling identity
    /// closes the disjoint-and-covering XOR partition `is_fix_only() XOR
    /// is_minor_only() XOR is_major_only()` across the three-variant
    /// ladder — pinned by
    /// [`tests::test_bump_level_identity_trio_partitions_ladder`]. A
    /// downstream release-policy consumer that branches on the bump level
    /// (fix-channel / additive-channel / breaking-channel) reads the three
    /// identity predicates as a disjoint cover rather than a nested
    /// if-else cascade that would inherit a drift class on the day a
    /// fourth variant is added. The dual partition `is_fix_only XOR
    /// is_minor_only XOR is_breaking` (commit c12f211, pinned by
    /// [`tests::test_bump_level_named_trio_xor_partitions_ladder`]) rides
    /// the half-open-ray surface at the ceiling; this commit's identity-
    /// trio partition rides the variant-equality surface at the ceiling —
    /// together the two partitions seal the ladder against both half-
    /// open-ray drift AND variant-identity drift under future variant
    /// insertions above `Major`. Same dual-partition seal
    /// [`crate::probe_outcome::AdmissionTier`] already carries (the ray
    /// partition `admits_strict XOR is_staging_only XOR refuses_relaxed`
    /// at commit e08b821, the identity partition `is_refused XOR
    /// is_staging_only XOR is_strict` at commit 1775181).
    ///
    /// # Coincidence with `is_breaking` under the present ladder
    ///
    /// Under the present three-variant ladder, `is_major_only()` and
    /// `is_breaking()` coincide numerically at every variant: `Major` is
    /// both the unique == ceiling variant AND the unique >= ceiling
    /// variant. The coincidence is pinned by
    /// [`tests::test_bump_level_is_major_only_equals_is_breaking_under_present_ladder`]
    /// so the structural distinction between the two peers carries load
    /// even where they're numerically equal today. A future `Epoch`
    /// insertion above `Major` would surface the distinction: `Epoch` is
    /// breaking (`>= Major`) but is NOT the canonical major variant
    /// (`!= Major`), so `is_breaking()` would read `true` at `Epoch` while
    /// `is_major_only()` would read `false`. Same present-coincidence pin
    /// [`crate::probe_outcome::AdmissionTier::is_strict`] carries against
    /// `admits_strict` under the three-variant admission-tier ladder.
    ///
    /// THEORY.md §V.5 total-order discipline: the version-bump magnitude
    /// ladder is consumed at named typed-method surfaces, not retyped at
    /// every consumer's match cascade — the ceiling-identity predicate
    /// sits at the typed-primitive surface alongside the floor-identity
    /// ([`is_fix_only`](Self::is_fix_only)), the middle-band identity
    /// ([`is_minor_only`](Self::is_minor_only)), and the half-open-ray
    /// predicates ([`is_breaking`](Self::is_breaking),
    /// [`is_non_breaking`](Self::is_non_breaking)). THEORY.md §VI.1 one-
    /// oracle: the major-ceiling semantic role (this bump is exactly the
    /// canonical breaking-change major variant) is named at one site
    /// (this method's body), so a downstream policy gate that previously
    /// read `matches!(level, BumpLevel::Major)` reads
    /// `level.is_major_only()` once and is automatically refused — by the
    /// `==` form — across a future `Epoch` insertion above `Major` that
    /// the gate should NOT classify as the canonical major variant.
    #[allow(dead_code)]
    pub fn is_major_only(&self) -> bool {
        *self == Self::Major
    }

    /// True iff `self` sits at or above the lower magnitude threshold —
    /// i.e., `*self >= Self::Minor` under the derived [`Ord`] instance. The
    /// named typed-method peer at the Minor threshold of the version-bump
    /// magnitude ladder: the half-open-ray gate naming "this bump
    /// introduces user-visible change — a backward-compatible feature
    /// addition or a breaking API change" reading downstream consumers
    /// previously had to write as `!level.is_fix_only()` (or
    /// `matches!(level, BumpLevel::Minor | BumpLevel::Major)` against the
    /// variants directly). A release-notes generator that says "any non-fix
    /// bump requires a user-facing changelog entry and a release-notes
    /// section" reads `level.is_feature_or_breaking()` instead of
    /// `!level.is_fix_only()` or a two-arm `match level { Minor | Major =>
    /// require_changelog, Patch => skip }` cascade at every policy site —
    /// the user-visible-change semantic role is named at the typed-
    /// primitive surface, not retyped at every consumer.
    ///
    /// Sibling lift of [`is_breaking`](Self::is_breaking) (>=Major) at the
    /// upper threshold, here applied to the lower (Minor) threshold of the
    /// magnitude ladder. Together with [`is_breaking`] and the dual pair
    /// [`is_non_breaking`](Self::is_non_breaking), the named half-open-ray
    /// surface now carries one of the two ladder-gate readings at the
    /// lower threshold, closing the structural gap between the
    /// [`BumpLevel`] sum and the four-method admit/refuse × relaxed/strict
    /// gate matrix the [`crate::probe_outcome::AdmissionTier`] surface
    /// carries over its two thresholds (`>= StagingOnly`, `>= Strict`).
    ///
    /// # Why `>= Self::Minor`, not `!self.is_fix_only()` or `matches!`
    ///
    /// Under the present three-variant ladder, `is_feature_or_breaking`
    /// reduces to `!self.is_fix_only()` and to `matches!(self, Self::Minor
    /// | Self::Major)`, but the `>=` form is the load-bearing one. It
    /// makes the total-order discipline (commit 8c2bbd5) the structural
    /// oracle for the lower-threshold gate the same way the `>=` form
    /// does for [`is_breaking`] at the upper threshold: a future variant
    /// `BumpLevel::Epoch` inserted in source order strictly above `Major`
    /// (semver4 / `0ver`-style incompatible-by-design rewrites) is
    /// automatically `>= Minor` and so structurally classified as
    /// feature-or-breaking — the same way a future `BumpLevel::Prerelease`
    /// variant inserted strictly below `Patch` (release-candidate /
    /// staging-channel bump shapes) is automatically `< Minor` and so
    /// structurally classified as NOT feature-or-breaking. The
    /// `!is_fix_only()` form would silently misclassify `Prerelease` as
    /// feature-or-breaking (it is `!= Patch` and so reads `!is_fix_only()`
    /// as true), inheriting the same drift class
    /// [`crate::probe_outcome::AdmissionTier::admits_relaxed`] avoids by
    /// reading `>= StagingOnly` rather than `matches!(self, StagingOnly |
    /// Strict)`. The `matches!` form would silently misclassify a future
    /// `Epoch` variant above `Major` as NOT feature-or-breaking (it would
    /// not match `Minor | Major`), inheriting the dual drift class. The
    /// `>=` form refuses both by construction.
    ///
    /// # Implication chain and decomposition pins
    ///
    /// The implication invariant `is_breaking() => is_feature_or_breaking()`
    /// is pinned by
    /// [`tests::test_bump_level_is_breaking_implies_is_feature_or_breaking`]:
    /// every breaking bump is structurally feature-or-breaking (every
    /// `>= Major` is `>= Minor`), so a downstream release-notes gate that
    /// admits feature-or-breaking automatically admits every breaking
    /// bump. The De Morgan complementarity invariant
    /// `is_feature_or_breaking() == !is_fix_only()` under the present
    /// three-variant ladder is pinned by
    /// [`tests::test_bump_level_is_feature_or_breaking_equals_negation_of_is_fix_only_under_present_ladder`]:
    /// the two predicates are exact complements at every present variant.
    /// The partition pin
    /// [`tests::test_bump_level_is_feature_or_breaking_xor_is_fix_only_partitions_ladder`]
    /// nails the disjoint-and-covering invariant
    /// `is_feature_or_breaking() XOR is_fix_only() == true` so a regression
    /// that broke either method body (e.g., a future hand-rolled
    /// `matches!(self, Self::Minor | Self::Major)` body that drifted from
    /// the `>=` form across a fourth-variant addition) surfaces as a
    /// partition gap or overlap at the new variant. Same partition shape
    /// the `is_breaking` / `is_non_breaking` pair sealed at the upper
    /// threshold, here at the lower threshold of the same ladder.
    ///
    /// THEORY.md §V.5 total-order discipline: the version-bump-magnitude
    /// lower-threshold gate reads the derived `Ord` impl through a named
    /// typed-method peer at the typed-primitive surface, not retyped at
    /// every consumer's match cascade or De Morgan negation. THEORY.md
    /// §VI.1 one-oracle: the user-visible-change semantic role
    /// (feature-or-breaking ⇔ at-or-above Minor) is named at one site
    /// (this method's body), so a downstream policy gate that previously
    /// read `!level.is_fix_only()` reads `level.is_feature_or_breaking()`
    /// once and is automatically refined — by the `>=` form — across a
    /// future `Prerelease` insertion below `Patch` that the gate should
    /// NOT classify as user-visible.
    #[allow(dead_code)]
    pub fn is_feature_or_breaking(&self) -> bool {
        *self >= Self::Minor
    }

    /// True iff `self` sits strictly below the feature-or-breaking
    /// threshold — i.e., `*self < Self::Minor` under the derived [`Ord`]
    /// instance. The named typed-method De Morgan complement of
    /// [`is_feature_or_breaking`](Self::is_feature_or_breaking) at the
    /// version-bump-magnitude surface: the second leg of the named-method
    /// pair over the lower (Minor) threshold, naming the "this bump
    /// introduces no user-visible change — an internal-only fix release
    /// that does NOT require a user-facing changelog entry" reading that
    /// downstream consumers previously had to write as
    /// `!level.is_feature_or_breaking()` (or
    /// `matches!(level, BumpLevel::Patch)` against the variant directly).
    /// A SLSA-style release-provenance gate that says "internal-only fix
    /// releases can ship under an abbreviated provenance trail without a
    /// public changelog section" reads `level.is_below_feature_threshold()`
    /// instead of `!level.is_feature_or_breaking()` or a single-arm
    /// `match level { Patch => abbreviated, _ => full }` at every policy
    /// site — the internal-only / no-user-visible-change semantic role is
    /// named at the typed-primitive surface, not retyped at every
    /// consumer.
    ///
    /// Sibling lift of [`is_non_breaking`](Self::is_non_breaking) (<Major)
    /// at the upper threshold, here applied to the lower (Minor) threshold
    /// of the magnitude ladder. Together with
    /// [`is_feature_or_breaking`](Self::is_feature_or_breaking), the named
    /// half-open-ray surface now carries BOTH legs of the De Morgan pair
    /// at the lower threshold — closing the structural gap between the
    /// [`BumpLevel`] sum and the four-method admit/refuse × relaxed/strict
    /// gate matrix the [`crate::probe_outcome::AdmissionTier`] surface
    /// carries over its two thresholds (`>= StagingOnly` /
    /// `< StagingOnly`, `>= Strict` / `< Strict`). The [`BumpLevel`]
    /// surface now carries the parallel admit/refuse-shaped pair at both
    /// of its two thresholds: [`is_breaking`](Self::is_breaking) /
    /// [`is_non_breaking`](Self::is_non_breaking) at the upper (Major)
    /// threshold, and [`is_feature_or_breaking`](Self::is_feature_or_breaking)
    /// / `is_below_feature_threshold` at the lower (Minor) threshold.
    ///
    /// # Why `< Self::Minor`, not `!self.is_feature_or_breaking()` or `matches!`
    ///
    /// Under the present three-variant ladder, `is_below_feature_threshold`
    /// reduces to `*self == Self::Patch` (since `Patch` is the floor),
    /// to `matches!(self, Self::Patch)`, and to
    /// `!self.is_feature_or_breaking()`, but the `<` form is the
    /// load-bearing one. It makes the derived [`Ord`] discipline the
    /// structural oracle for the no-user-visible-change partition the
    /// same way the `<` form does for [`is_non_breaking`] at the upper
    /// threshold: a future variant `BumpLevel::Prerelease` inserted in
    /// source order strictly below `Patch` (release-candidate /
    /// staging-channel bump shapes) is automatically `< Minor` and so
    /// structurally classified as below the feature threshold — without
    /// retyping the predicate at every consumer. The `matches!(self,
    /// Self::Patch)` form would silently misclassify the new floor
    /// variant (it would NOT match `Patch` and so would read as
    /// feature-or-breaking), inheriting the same drift class
    /// [`crate::probe_outcome::AdmissionTier::refuses_relaxed`] avoids
    /// by reading `< StagingOnly` rather than `matches!(self, Refused)`.
    /// The `!self.is_feature_or_breaking()` form is byte-equivalent at
    /// every variant under the De Morgan complementarity invariant
    /// (pinned by
    /// [`tests::test_bump_level_is_below_feature_threshold_equals_negation_of_is_feature_or_breaking`]),
    /// but routing every consumer through a negated call surfaces a
    /// drift class on the day a third predicate joins the lower-
    /// threshold family (a future ladder refinement) where the negation
    /// can no longer compose without parens / precedence vigilance at
    /// every call site. Naming the positive role directly localises the
    /// reading at one method body.
    ///
    /// # De Morgan / XOR partition / implication chain
    ///
    /// The De Morgan complementarity invariant
    /// `is_below_feature_threshold() == !is_feature_or_breaking()` is
    /// pinned by
    /// [`tests::test_bump_level_is_below_feature_threshold_equals_negation_of_is_feature_or_breaking`]:
    /// the two predicates are exact complements at every variant. The
    /// disjoint-and-covering partition pin
    /// [`tests::test_bump_level_is_below_feature_threshold_xor_is_feature_or_breaking_partitions_ladder`]
    /// nails `is_below_feature_threshold() XOR is_feature_or_breaking()
    /// == true` so a regression that broke either method body (e.g., a
    /// future hand-rolled `matches!(self, Self::Patch)` body that
    /// drifted from the `<` form across a fourth-variant addition below
    /// `Patch`) surfaces here as a partition gap or overlap. Same
    /// partition shape the
    /// [`crate::probe_outcome::AdmissionTier::refuses_relaxed`] /
    /// [`crate::probe_outcome::AdmissionTier::admits_relaxed`] pair
    /// sealed at the admission-gate surface, here at the version-bump-
    /// magnitude lower threshold.
    ///
    /// The implication invariant
    /// `is_below_feature_threshold() => is_non_breaking()` is pinned by
    /// [`tests::test_bump_level_is_below_feature_threshold_implies_is_non_breaking`]:
    /// every bump strictly below the Minor threshold (every `< Minor`)
    /// is structurally also strictly below the Major threshold (every
    /// `< Major`), so a downstream provenance gate that admits
    /// `is_non_breaking()` automatically admits every
    /// `is_below_feature_threshold()` bump. Sibling pin of
    /// [`tests::test_bump_level_is_breaking_implies_is_feature_or_breaking`]
    /// at the dual implication chain (the implication runs upward at
    /// the upper-threshold gate; here it runs downward at the lower-
    /// threshold gate). The coincidence pin
    /// [`tests::test_bump_level_is_below_feature_threshold_equals_is_fix_only_under_present_ladder`]
    /// names the structural coincidence with [`is_fix_only`] under the
    /// present three-variant ladder, mirroring
    /// [`tests::test_bump_level_is_feature_or_breaking_equals_negation_of_is_fix_only_under_present_ladder`]
    /// at the complement side of the same threshold.
    ///
    /// THEORY.md §V.1 make invalid states unrepresentable: the
    /// no-user-visible-change band reads the derived [`Ord`] impl through
    /// a named typed-method peer at the typed-primitive surface, not
    /// retyped at every consumer's match cascade or De Morgan negation.
    /// THEORY.md §VI.1 one-oracle / generation-over-composition: the
    /// internal-only semantic role (below-feature-threshold ⇔ strictly
    /// below Minor) is named at one site (this method's body), so a
    /// downstream policy gate that previously read
    /// `!level.is_feature_or_breaking()` reads
    /// `level.is_below_feature_threshold()` once and is automatically
    /// refined — by the `<` form — across a future `Prerelease`
    /// insertion below `Patch` that the gate should classify as below
    /// the feature threshold.
    #[allow(dead_code)]
    pub fn is_below_feature_threshold(&self) -> bool {
        *self < Self::Minor
    }

    /// The lattice join over the version-bump magnitude ladder — the
    /// `BumpLevel` required to subsume BOTH `self` and `other`
    /// simultaneously. Reads `self.max(other)` at one named site, returning
    /// the higher of the two variants on the derived [`Ord`] ladder
    /// (`Patch < Minor < Major`). The named typed-method peer of the
    /// [`Ord::max`] reduction at the [`BumpLevel`] surface, the structural
    /// mirror of [`crate::probe_outcome::per_axis_admission_tier_ceiling`]
    /// at the [`crate::probe_outcome::AdmissionTier`] surface.
    ///
    /// # The release-aggregation reading
    ///
    /// A release containing changes at multiple per-commit bump magnitudes
    /// requires a release bump at least as large as the largest per-commit
    /// magnitude: a release that ships both a backward-compatible fix
    /// ([`BumpLevel::Patch`]) AND a backward-compatible feature
    /// ([`BumpLevel::Minor`]) requires a Minor release bump; a release that
    /// adds both a feature ([`BumpLevel::Minor`]) AND an API-breaking
    /// change ([`BumpLevel::Major`]) requires a Major release bump. The
    /// canonical release-pipeline aggregation idiom over a sequence of
    /// per-commit [`BumpLevel`] readings is the lattice join — the fold
    /// `commits.iter().fold(BumpLevel::Patch, |acc, c| acc.join(c.level))`
    /// returns the release-bump magnitude, with [`BumpLevel::Patch`] as
    /// the identity element (any per-commit bump joins with `Patch` to
    /// itself) and [`BumpLevel::Major`] as the absorbing element (any
    /// per-commit bump joined with `Major` collapses to `Major`). The
    /// identity and absorbing-element invariants are pinned by
    /// [`tests::test_bump_level_join_has_patch_as_identity`] and
    /// [`tests::test_bump_level_join_has_major_as_absorbing_element`] —
    /// the load-bearing structural facts a release-pipeline fold relies on
    /// at the seed and the early-exit step.
    ///
    /// # Why a named method, not raw `Ord::max`
    ///
    /// The body reads `self.max(other)`, and at every reachable `(self,
    /// other)` pair the two readings agree (pinned by
    /// [`tests::test_bump_level_join_agrees_with_max_at_every_pair`]). The
    /// named [`join`](Self::join) surface carries TWO load-bearing pieces
    /// of content the bare [`Ord::max`] call does not:
    ///
    /// 1. The release-aggregation semantic role: a release-pipeline
    ///    consumer reading `level_a.join(level_b)` reads "the release bump
    ///    that subsumes both changes" at the call site, where the same
    ///    consumer reading `level_a.max(level_b)` reads "the larger of the
    ///    two magnitudes" — the `max` form is a general lattice op shared
    ///    with arbitrary comparable types, the `join` form names the
    ///    release-aggregation reading at the typed-primitive surface.
    ///    Same THEORY.md §V.4 honesty-channel discipline the
    ///    [`crate::probe_outcome::per_axis_admission_tier_ceiling`] lift
    ///    established at the per-axis admission-tier surface: surfacing
    ///    "the best per-axis tier any axis admits at" as the load-bearing
    ///    reading distinct from a bare `Ord::max` reduction.
    /// 2. A one-oracle anchor for a future ladder refinement. The lattice
    ///    join over a total order coincides with [`Ord::max`] by
    ///    definition, but a future ladder extension that introduces
    ///    structural distinctions inside the magnitude axis (a
    ///    `Prerelease` variant strictly below `Patch` with refined
    ///    release-aggregation semantics — does
    ///    `Prerelease.join(Patch) == Patch`? does it propagate up to a
    ///    pre-release release-bump shape distinct from a stable release?)
    ///    extends this method body once, instead of retyping the release-
    ///    aggregation oracle at every consumer's inline `.max()` call.
    ///    Same THEORY.md §VI.1 one-oracle discipline the prior
    ///    typed-method-peer lifts established
    ///    ([`is_breaking`](Self::is_breaking) /
    ///    [`is_non_breaking`](Self::is_non_breaking) /
    ///    [`is_feature_or_breaking`](Self::is_feature_or_breaking) /
    ///    [`is_below_feature_threshold`](Self::is_below_feature_threshold))
    ///    over the half-open-ray gates, here applied to the lattice-join
    ///    surface over the same total-order ladder.
    ///
    /// # Algebraic invariants
    ///
    /// The lattice join over a total order is idempotent, commutative,
    /// and associative, with the ladder floor ([`BumpLevel::Patch`]) as
    /// the identity element and the ladder ceiling ([`BumpLevel::Major`])
    /// as the absorbing element — the load-bearing structural facts
    /// pinned by:
    /// * [`tests::test_bump_level_join_is_idempotent_at_every_variant`] —
    ///   `a.join(a) == a` at every variant.
    /// * [`tests::test_bump_level_join_is_commutative_at_every_pair`] —
    ///   `a.join(b) == b.join(a)` at every (a, b) over the 3×3 grid.
    /// * [`tests::test_bump_level_join_is_associative_at_every_triple`] —
    ///   `a.join(b.join(c)) == a.join(b).join(c)` at every (a, b, c) over
    ///   the 3×3×3 grid, the structural anchor a downstream release-
    ///   pipeline fold can reorder commits over without changing the
    ///   aggregated release bump.
    /// * [`tests::test_bump_level_join_bounded_below_by_both_arguments`]
    ///   — `a.join(b) >= a && a.join(b) >= b` at every (a, b), the
    ///   structural anchor a downstream provenance gate consumes ("the
    ///   release bump subsumes every per-commit bump") through one named
    ///   site.
    /// * [`tests::test_bump_level_join_returns_one_of_the_arguments`] —
    ///   `a.join(b) ∈ {a, b}` at every (a, b), the structural witness
    ///   that the lattice join over a total order is the identity-or-
    ///   other readback — distinct from a free-lattice join that could
    ///   return a third element.
    ///
    /// THEORY.md §V.5 total-order discipline: the release-aggregation
    /// reading is a lattice operation (`max`) on the derived [`Ord`]
    /// ladder, named at the typed-primitive surface so a downstream
    /// consumer reads `level_a.join(level_b)` once and is automatically
    /// updated across a future ladder refinement. THEORY.md §VI.1 one-
    /// oracle / generation-over-composition: the release-aggregation
    /// idiom is named at one site (this method's body), not retyped at
    /// every consumer's inline `.max()` call.
    ///
    /// Frontier inspiration: SLSA release-tier aggregation rules read the
    /// released-artifact tier as the join (`max`) over per-source
    /// attestation tiers — the "subsumes every contributing source" reading
    /// where the released artifact tier is bounded above by every
    /// contributing tier; conventional-commits release-aggregation lifts
    /// per-commit type tokens (fix / feat / breaking) into a release-level
    /// bump magnitude via the same max-fold, with `fix` as the floor /
    /// identity element and `breaking` as the ceiling / absorbing element.
    /// Translation: forge's [`BumpLevel`] sum now names the release-
    /// aggregation join at the typed-primitive surface so a downstream
    /// release-pipeline fold reads `levels.fold(BumpLevel::Patch, |acc, l|
    /// acc.join(l))` through one named oracle, rather than retyping
    /// `acc.max(l)` at every release-pipeline aggregation site.
    #[allow(dead_code)]
    pub fn join(self, other: Self) -> Self {
        self.max(other)
    }

    /// The lattice meet over the version-bump magnitude ladder — the
    /// `BumpLevel` BOTH `self` and `other` share at the per-commit floor.
    /// Reads `self.min(other)` at one named site, returning the lower of
    /// the two variants on the derived [`Ord`] ladder (`Patch < Minor <
    /// Major`). The named typed-method peer of the [`Ord::min`] reduction
    /// at the [`BumpLevel`] surface, the structural mirror of
    /// [`crate::probe_outcome::per_axis_admission_tier_floor`] at the
    /// [`crate::probe_outcome::AdmissionTier`] surface and the dual of
    /// [`join`](Self::join) at the same magnitude ladder.
    ///
    /// # The per-commit-floor reading
    ///
    /// Where [`join`](Self::join) names the release-aggregation idiom over
    /// a sequence of per-commit bump levels (the release bump SUBSUMES
    /// every per-commit bump), `meet` names the dual at the per-commit-
    /// floor surface — the magnitude every commit in a sequence is at
    /// least as large as. A SLSA-style strictest-common-baseline reading
    /// over a sequence of per-commit bump magnitudes — "every commit in
    /// this release is at least a feature change" — is the meet-fold
    /// `commits.iter().fold(BumpLevel::Major, |acc, c| acc.meet(c.level))`,
    /// with [`BumpLevel::Major`] as the identity element (any per-commit
    /// bump meets with `Major` to itself, by the duality `min(Major, x) =
    /// x`) and [`BumpLevel::Patch`] as the absorbing element (any per-
    /// commit bump met with `Patch` collapses to `Patch`, by the duality
    /// `min(Patch, x) = Patch`). The identity and absorbing-element
    /// invariants are pinned by
    /// [`tests::test_bump_level_meet_has_major_as_identity`] and
    /// [`tests::test_bump_level_meet_has_patch_as_absorbing_element`] —
    /// the load-bearing structural facts a per-commit-floor fold relies on
    /// at the seed and the early-exit step, mirror duals of the
    /// [`Patch`](BumpLevel::Patch)-identity / [`Major`](BumpLevel::Major)-
    /// absorbing pair pinned at the [`join`](Self::join) surface.
    ///
    /// # Why a named method, not raw `Ord::min`
    ///
    /// The body reads `self.min(other)`, and at every reachable `(self,
    /// other)` pair the two readings agree (pinned by
    /// [`tests::test_bump_level_meet_agrees_with_min_at_every_pair`]). The
    /// named [`meet`](Self::meet) surface carries TWO load-bearing pieces
    /// of content the bare [`Ord::min`] call does not:
    ///
    /// 1. The per-commit-floor semantic role: a per-commit-floor consumer
    ///    reading `level_a.meet(level_b)` reads "the bump magnitude both
    ///    commits share at the floor" at the call site, where the same
    ///    consumer reading `level_a.min(level_b)` reads "the smaller of
    ///    the two magnitudes" — the `min` form is a general lattice op
    ///    shared with arbitrary comparable types, the `meet` form names
    ///    the per-commit-floor reading at the typed-primitive surface.
    ///    Same THEORY.md §V.4 honesty-channel discipline the
    ///    [`crate::probe_outcome::per_axis_admission_tier_floor`] lift
    ///    established at the per-axis admission-tier surface: surfacing
    ///    "the strictest tier every axis admits at" as the load-bearing
    ///    reading distinct from a bare [`Ord::min`] reduction.
    /// 2. A one-oracle anchor for a future ladder refinement. The lattice
    ///    meet over a total order coincides with [`Ord::min`] by
    ///    definition, but a future ladder extension that introduces
    ///    structural distinctions inside the magnitude axis (a
    ///    `Prerelease` variant strictly below `Patch` with refined per-
    ///    commit-floor semantics — does `Prerelease.meet(Patch) ==
    ///    Prerelease`? does it propagate down to a pre-release floor shape
    ///    distinct from a stable floor?) extends this method body once,
    ///    instead of retyping the per-commit-floor oracle at every
    ///    consumer's inline `.min()` call. Same THEORY.md §VI.1 one-oracle
    ///    discipline the prior typed-method-peer lifts established
    ///    ([`is_breaking`](Self::is_breaking) /
    ///    [`is_non_breaking`](Self::is_non_breaking) /
    ///    [`is_feature_or_breaking`](Self::is_feature_or_breaking) /
    ///    [`is_below_feature_threshold`](Self::is_below_feature_threshold))
    ///    over the half-open-ray gates and [`join`](Self::join) at the
    ///    lattice-join surface, here applied to the lattice-meet surface
    ///    over the same total-order ladder — closing the lattice-operation
    ///    pair at the [`BumpLevel`] surface.
    ///
    /// # Algebraic invariants
    ///
    /// The lattice meet over a total order is idempotent, commutative,
    /// and associative, with the ladder ceiling ([`BumpLevel::Major`]) as
    /// the identity element and the ladder floor ([`BumpLevel::Patch`])
    /// as the absorbing element — the duals of the
    /// [`join`](Self::join) invariants on the same ladder. The lattice
    /// meet and join satisfy the absorption laws (`a.join(a.meet(b)) == a`
    /// and `a.meet(a.join(b)) == a`), pinned by
    /// [`tests::test_bump_level_meet_join_absorption_at_every_pair`] —
    /// the structural anchor that the meet/join pair forms a lattice in
    /// the algebraic sense, not merely two independent reductions over
    /// the same [`Ord`] ladder. The meet is bounded above by both
    /// arguments and below by the join over the same pair, pinned by
    /// [`tests::test_bump_level_meet_bounded_above_by_both_arguments`]
    /// and
    /// [`tests::test_bump_level_meet_le_join_at_every_pair`] — the
    /// structural witness that the meet–join interval brackets the
    /// magnitude range of the input pair, the per-pair mirror of
    /// `test_per_axis_admission_tier_floor_le_ceiling_across_cross_product`
    /// at the per-axis admission-tier surface.
    ///
    /// THEORY.md §V.5 total-order discipline: the per-commit-floor
    /// reading is a lattice operation (`min`) on the derived [`Ord`]
    /// ladder, named at the typed-primitive surface so a downstream
    /// consumer reads `level_a.meet(level_b)` once and is automatically
    /// updated across a future ladder refinement. THEORY.md §VI.1 one-
    /// oracle / generation-over-composition: the per-commit-floor idiom
    /// is named at one site (this method's body), not retyped at every
    /// consumer's inline `.min()` call. Together with
    /// [`join`](Self::join), this closes the lattice-operation pair at
    /// the [`BumpLevel`] surface — the structural mirror of the
    /// `per_axis_admission_tier_floor` /
    /// `per_axis_admission_tier_ceiling` pair at the per-axis admission-
    /// tier surface.
    ///
    /// Frontier inspiration: SLSA per-source attestation rules read the
    /// least-trusted source tier as the meet (`min`) over per-source
    /// tiers — the "every source admits at this floor" reading where
    /// the bound is the strictest baseline every contributing source
    /// honors; conventional-commits per-commit-floor analysis lifts a
    /// sequence of per-commit type tokens (fix / feat / breaking) into a
    /// floor magnitude via the same min-fold, with `fix` as the absorbing
    /// element (the floor of any sequence containing a fix is `fix`) and
    /// `breaking` as the identity element (a sequence of breaking changes
    /// shares the breaking floor). Translation: forge's [`BumpLevel`] sum
    /// now names the per-commit-floor meet at the typed-primitive surface
    /// so a downstream per-commit-floor fold reads
    /// `levels.fold(BumpLevel::Major, |acc, l| acc.meet(l))` through one
    /// named oracle, rather than retyping `acc.min(l)` at every per-
    /// commit-floor aggregation site, with the load-bearing algebraic
    /// invariants (`Major`-identity, `Patch`-absorbing, idempotence,
    /// commutativity, associativity, absorption with [`join`](Self::join))
    /// pinned at the typed-primitive site.
    #[allow(dead_code)]
    pub fn meet(self, other: Self) -> Self {
        self.min(other)
    }
}

impl std::fmt::Display for BumpLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for BumpLevel {
    type Err = anyhow::Error;

    /// Parse the canonical lowercase string (`"patch"`, `"minor"`,
    /// `"major"`) into a [`BumpLevel`] variant. Any other input errors
    /// with the same wording the prior [`bump_semver`] match-arm trap
    /// emitted, so a downstream caller that previously read the string
    /// error from [`bump_semver`] reads byte-identical text through the
    /// typed-primitive surface.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "patch" => Ok(Self::Patch),
            "minor" => Ok(Self::Minor),
            "major" => Ok(Self::Major),
            _ => bail!("Invalid bump level '{}' — use patch, minor, or major", s),
        }
    }
}

/// Bump a version by the given typed [`BumpLevel`] component. The typed-
/// primitive peer of [`bump_semver`]: the level axis carries a typed sum
/// surface, making the function TOTAL over the level domain — every
/// [`BumpLevel`] variant is structurally a valid input, the compiler
/// refuses a future match that drops a variant, and there is no runtime
/// trap on an unrecognized string at this entry point. The string-typed
/// entry point [`bump_semver`] retains its API and routes through this
/// typed primitive so the level grammar (which strings map to which
/// variant) is named at one site.
pub fn bump_semver_typed(version: &str, level: BumpLevel) -> Result<String> {
    let (major, minor, patch) = parse_semver(version)?;
    Ok(match level {
        BumpLevel::Patch => format!("{}.{}.{}", major, minor, patch + 1),
        BumpLevel::Minor => format!("{}.{}.0", major, minor + 1),
        BumpLevel::Major => format!("{}.0.0", major + 1),
    })
}

/// Bump a version by the given level (patch, minor, major).
///
/// Routes through the typed [`BumpLevel`] primitive: the level string is
/// parsed via [`BumpLevel::from_str`], then dispatched to
/// [`bump_semver_typed`]. The grammar oracle (which strings map to which
/// variant) lives in the [`FromStr`] impl, so a future alias extension
/// (e.g., `"p"` → [`BumpLevel::Patch`]) is added at the parser, not at
/// every match arm here. The error message on an unrecognized level
/// string is byte-identical to the prior `match level { ... _ =>
/// bail!(...) }` trap so existing callers reading the error text continue
/// to see the same wording.
pub fn bump_semver(version: &str, level: &str) -> Result<String> {
    let typed: BumpLevel = level.parse()?;
    bump_semver_typed(version, typed)
}

/// Read the version from a Cargo.toml file.
pub fn read_cargo_version(path: &Path) -> Result<String> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    let re = regex::Regex::new(r#"^\s*version\s*=\s*"(\d+\.\d+\.\d+)""#)
        .context("Failed to compile Cargo.toml version regex")?;

    for line in content.lines() {
        if let Some(caps) = re.captures(line) {
            return Ok(caps[1].to_string());
        }
    }

    bail!("No version field found in {}", path.display())
}

/// Read the version from a build.zig.zon file.
///
/// Matches `.version = "X.Y.Z"` in the zon format.
pub fn read_zig_version(path: &Path) -> Result<String> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    let re = regex::Regex::new(r#"\.version\s*=\s*"(\d+\.\d+\.\d+)""#)
        .context("Failed to compile zig version regex")?;

    let caps = re
        .captures(&content)
        .with_context(|| format!("No .version field found in {}", path.display()))?;

    Ok(caps[1].to_string())
}

/// Write a new version into a build.zig.zon file (in-place replacement).
pub fn write_zig_version(path: &Path, version: &str) -> Result<()> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    let re = regex::Regex::new(r#"(\.version\s*=\s*")(\d+\.\d+\.\d+)(")"#)
        .context("Failed to compile zig version regex")?;

    if !re.is_match(&content) {
        bail!("No .version field found in {}", path.display());
    }

    let new_content = re
        .replace(&content, format!("${{1}}{}${{3}}", version))
        .to_string();

    std::fs::write(path, &new_content)
        .with_context(|| format!("Failed to write {}", path.display()))?;

    Ok(())
}

/// Read the version from a Chart.yaml file.
pub fn read_chart_version(path: &Path) -> Result<String> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    let re = regex::Regex::new(r#"^version:\s*(\d+\.\d+\.\d+)"#)
        .context("Failed to compile Chart.yaml version regex")?;

    for line in content.lines() {
        if let Some(caps) = re.captures(line) {
            return Ok(caps[1].to_string());
        }
    }

    bail!("No version field found in {}", path.display())
}

/// Read the version from a package.json file.
pub fn read_package_json_version(path: &Path) -> Result<String> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    let json: serde_json::Value = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse {} as JSON", path.display()))?;

    json.get("version")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .with_context(|| format!("No version field found in {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_semver_valid() {
        assert_eq!(parse_semver("1.2.3").unwrap(), (1, 2, 3));
        assert_eq!(parse_semver("0.0.0").unwrap(), (0, 0, 0));
        assert_eq!(parse_semver("10.20.30").unwrap(), (10, 20, 30));
    }

    #[test]
    fn test_parse_semver_invalid() {
        assert!(parse_semver("1.2").is_err());
        assert!(parse_semver("1.2.3.4").is_err());
        assert!(parse_semver("abc").is_err());
    }

    #[test]
    fn test_bump_semver_patch() {
        assert_eq!(bump_semver("1.2.3", "patch").unwrap(), "1.2.4");
    }

    #[test]
    fn test_bump_semver_minor() {
        assert_eq!(bump_semver("1.2.3", "minor").unwrap(), "1.3.0");
    }

    #[test]
    fn test_bump_semver_major() {
        assert_eq!(bump_semver("1.2.3", "major").unwrap(), "2.0.0");
    }

    #[test]
    fn test_bump_semver_invalid_level() {
        assert!(bump_semver("1.2.3", "invalid").is_err());
    }

    #[test]
    fn test_read_cargo_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Cargo.toml");
        std::fs::write(
            &path,
            "[package]\nname = \"test\"\nversion = \"1.2.3\"\nedition = \"2021\"\n",
        )
        .unwrap();
        assert_eq!(read_cargo_version(&path).unwrap(), "1.2.3");
    }

    #[test]
    fn test_read_zig_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("build.zig.zon");
        std::fs::write(
            &path,
            ".{\n    .name = \"test\",\n    .version = \"0.3.1\",\n}\n",
        )
        .unwrap();
        assert_eq!(read_zig_version(&path).unwrap(), "0.3.1");
    }

    #[test]
    fn test_write_zig_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("build.zig.zon");
        std::fs::write(
            &path,
            ".{\n    .name = \"test\",\n    .version = \"0.3.1\",\n}\n",
        )
        .unwrap();
        write_zig_version(&path, "0.4.0").unwrap();
        assert_eq!(read_zig_version(&path).unwrap(), "0.4.0");
    }

    #[test]
    fn test_read_chart_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Chart.yaml");
        std::fs::write(
            &path,
            "apiVersion: v2\nname: mychart\nversion: 2.1.0\ntype: application\n",
        )
        .unwrap();
        assert_eq!(read_chart_version(&path).unwrap(), "2.1.0");
    }

    #[test]
    fn test_read_package_json_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("package.json");
        std::fs::write(&path, "{\"name\": \"test\", \"version\": \"3.0.1\"}").unwrap();
        assert_eq!(read_package_json_version(&path).unwrap(), "3.0.1");
    }

    #[test]
    fn test_parse_semver_non_numeric_component() {
        assert!(parse_semver("1.a.3").is_err());
        assert!(parse_semver("x.2.3").is_err());
        assert!(parse_semver("1.2.z").is_err());
    }

    #[test]
    fn test_parse_semver_empty_string() {
        assert!(parse_semver("").is_err());
    }

    #[test]
    fn test_bump_semver_from_zero() {
        assert_eq!(bump_semver("0.0.0", "patch").unwrap(), "0.0.1");
        assert_eq!(bump_semver("0.0.0", "minor").unwrap(), "0.1.0");
        assert_eq!(bump_semver("0.0.0", "major").unwrap(), "1.0.0");
    }

    #[test]
    fn test_bump_semver_resets_lower_components() {
        assert_eq!(bump_semver("1.5.9", "minor").unwrap(), "1.6.0");
        assert_eq!(bump_semver("3.7.2", "major").unwrap(), "4.0.0");
    }

    #[test]
    fn test_read_cargo_version_missing_file() {
        let path = Path::new("/nonexistent/Cargo.toml");
        assert!(read_cargo_version(path).is_err());
    }

    #[test]
    fn test_read_cargo_version_no_version_field() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Cargo.toml");
        std::fs::write(&path, "[package]\nname = \"test\"\nedition = \"2021\"\n").unwrap();
        assert!(read_cargo_version(&path).is_err());
    }

    #[test]
    fn test_read_zig_version_missing_file() {
        let path = Path::new("/nonexistent/build.zig.zon");
        assert!(read_zig_version(path).is_err());
    }

    #[test]
    fn test_write_zig_version_no_version_field() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("build.zig.zon");
        std::fs::write(&path, ".{\n    .name = \"test\",\n}\n").unwrap();
        assert!(write_zig_version(&path, "1.0.0").is_err());
    }

    #[test]
    fn test_read_chart_version_missing_file() {
        let path = Path::new("/nonexistent/Chart.yaml");
        assert!(read_chart_version(path).is_err());
    }

    #[test]
    fn test_read_chart_version_no_version_field() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Chart.yaml");
        std::fs::write(&path, "apiVersion: v2\nname: mychart\ntype: application\n").unwrap();
        assert!(read_chart_version(&path).is_err());
    }

    #[test]
    fn test_read_package_json_version_no_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("package.json");
        std::fs::write(&path, "{\"name\": \"test\"}").unwrap();
        assert!(read_package_json_version(&path).is_err());
    }

    #[test]
    fn test_read_package_json_version_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("package.json");
        std::fs::write(&path, "not json at all").unwrap();
        assert!(read_package_json_version(&path).is_err());
    }

    #[test]
    fn test_read_package_json_version_missing_file() {
        let path = Path::new("/nonexistent/package.json");
        assert!(read_package_json_version(path).is_err());
    }

    #[test]
    fn test_read_cargo_version_with_leading_whitespace() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Cargo.toml");
        std::fs::write(&path, "[package]\nname = \"test\"\n  version = \"2.0.1\"\n").unwrap();
        assert_eq!(read_cargo_version(&path).unwrap(), "2.0.1");
    }

    /// The three canonical lowercase strings parse to the three
    /// [`BumpLevel`] variants exactly — the grammar oracle every prior
    /// `match level { "patch" | "minor" | "major" | _ }` cascade now
    /// routes through.
    #[test]
    fn test_bump_level_from_str_canonical_strings() {
        assert_eq!("patch".parse::<BumpLevel>().unwrap(), BumpLevel::Patch);
        assert_eq!("minor".parse::<BumpLevel>().unwrap(), BumpLevel::Minor);
        assert_eq!("major".parse::<BumpLevel>().unwrap(), BumpLevel::Major);
    }

    /// Any other string errors with the same wording the prior
    /// `bump_semver` match-arm trap emitted, so a caller reading the
    /// error text continues to see byte-identical wording.
    #[test]
    fn test_bump_level_from_str_rejects_unknown() {
        let err = "invalid".parse::<BumpLevel>().unwrap_err().to_string();
        assert!(
            err.contains("Invalid bump level 'invalid'"),
            "error must name the offending input: {err}"
        );
        assert!(
            err.contains("use patch, minor, or major"),
            "error must echo the canonical grammar: {err}"
        );
        assert!("".parse::<BumpLevel>().is_err(), "empty string is rejected");
        assert!(
            "PATCH".parse::<BumpLevel>().is_err(),
            "uppercase is rejected — only canonical lowercase parses"
        );
        assert!(
            "  patch ".parse::<BumpLevel>().is_err(),
            "whitespace is not trimmed at this surface — caller's responsibility"
        );
    }

    /// Display renders each variant as the canonical lowercase string
    /// `FromStr` parses back, so the round-trip `BumpLevel ->
    /// to_string() -> FromStr` is the identity at every variant. A
    /// regression that drifted either side desynchronises this pin.
    #[test]
    fn test_bump_level_display_round_trips_through_from_str() {
        for level in BumpLevel::ALL {
            let s = level.to_string();
            assert_eq!(
                s.parse::<BumpLevel>().unwrap(),
                level,
                "Display→FromStr must round-trip at {level:?} (got {s:?})",
            );
            assert_eq!(
                s.as_str(),
                level.as_str(),
                "Display and as_str must agree at {level:?}",
            );
        }
    }

    /// At every [`BumpLevel`] variant, `bump_semver_typed` produces the
    /// same string `bump_semver` produces for the corresponding canonical
    /// level string — pinning the structural equivalence between the
    /// typed and string-typed entry points across the 3-way variant
    /// space. A future regression that desynced the two paths (e.g., a
    /// match-arm body change on one side, an alias extension on
    /// `FromStr` that bypassed the typed dispatch) lights up here.
    #[test]
    fn test_bump_semver_typed_agrees_with_bump_semver_at_every_variant() {
        let version = "1.2.3";
        for (level, level_str) in [
            (BumpLevel::Patch, "patch"),
            (BumpLevel::Minor, "minor"),
            (BumpLevel::Major, "major"),
        ] {
            let typed = bump_semver_typed(version, level).unwrap();
            let string_typed = bump_semver(version, level_str).unwrap();
            assert_eq!(
                typed, string_typed,
                "bump_semver_typed({version}, {level:?}) must equal \
                 bump_semver({version}, {level_str:?})",
            );
        }
    }

    /// `bump_semver` routes through the typed primitive, so a malformed
    /// level string surfaces the [`BumpLevel::from_str`] error — the
    /// grammar oracle is named at one site. The error wording is
    /// byte-identical to the prior in-line match-arm trap.
    #[test]
    fn test_bump_semver_routes_unknown_level_through_typed_grammar() {
        let err = bump_semver("1.2.3", "invalid").unwrap_err().to_string();
        assert!(
            err.contains("Invalid bump level 'invalid'"),
            "bump_semver must surface the typed-primitive error verbatim: {err}",
        );
        assert!(
            err.contains("use patch, minor, or major"),
            "bump_semver must surface the canonical grammar message: {err}",
        );
    }

    /// `bump_semver_typed` is total over the [`BumpLevel`] domain on a
    /// well-formed version string: every variant produces an `Ok`
    /// result. The structural pin that makes the typed entry point a
    /// total function — the property the prior string-typed
    /// `bump_semver` lacked at the `_ => bail!` arm.
    #[test]
    fn test_bump_semver_typed_total_over_bump_level_domain() {
        for level in BumpLevel::ALL {
            assert!(
                bump_semver_typed("0.0.0", level).is_ok(),
                "bump_semver_typed must be total at {level:?} on 0.0.0",
            );
            assert!(
                bump_semver_typed("9.9.9", level).is_ok(),
                "bump_semver_typed must be total at {level:?} on 9.9.9",
            );
        }
    }

    /// The magnitude ladder `Patch < Minor < Major` holds at every
    /// adjacent and end-to-end pair. The structural pin that lets a
    /// release-pipeline policy read `level >= BumpLevel::Minor` instead of
    /// a three-arm match cascade at every site. Same total-order
    /// discipline `AdmissionTier` (Refused < StagingOnly < Strict)
    /// established at the admission-gate surface, here at the
    /// version-bump-magnitude surface.
    #[test]
    fn test_bump_level_magnitude_ladder() {
        assert!(BumpLevel::Patch < BumpLevel::Minor);
        assert!(BumpLevel::Minor < BumpLevel::Major);
        assert!(BumpLevel::Patch < BumpLevel::Major);
        assert!(BumpLevel::Major > BumpLevel::Minor);
        assert!(BumpLevel::Minor > BumpLevel::Patch);
        assert!(BumpLevel::Major > BumpLevel::Patch);
    }

    /// The total order on [`BumpLevel`] is reflexive at every variant —
    /// `level <= level` and `level >= level` and `level == level`. The
    /// `PartialOrd` / `Ord` derive must agree with `PartialEq` / `Eq`,
    /// pinned here so a future hand-rolled impl that desynced equality
    /// from ordering lights up.
    #[test]
    fn test_bump_level_ordering_reflexive_at_every_variant() {
        for level in BumpLevel::ALL {
            assert!(level <= level, "{level:?} must be <= itself");
            assert!(level >= level, "{level:?} must be >= itself");
            assert_eq!(
                level.cmp(&level),
                std::cmp::Ordering::Equal,
                "{level:?}.cmp(&{level:?}) must be Equal",
            );
        }
    }

    /// The ladder is consistent with the canonical sort order: collecting
    /// the three variants into a `Vec` and sorting them yields
    /// `[Patch, Minor, Major]` — the source-order ladder. A regression
    /// that reordered the enum variants (and so reordered the derived
    /// ladder) lights up here. The pin makes the source-order load-
    /// bearing: future variant insertions are forced to consider their
    /// ladder position.
    #[test]
    fn test_bump_level_sort_yields_canonical_ladder() {
        let mut levels = vec![BumpLevel::Major, BumpLevel::Patch, BumpLevel::Minor];
        levels.sort();
        assert_eq!(
            levels,
            BumpLevel::ALL.to_vec(),
            "sorted variants must yield the Patch < Minor < Major ladder",
        );
    }

    /// [`BumpLevel::ALL`] lists the three variants in the source-order
    /// ladder `[Patch, Minor, Major]`. The fixed-shape pin: the const
    /// matches the canonical ladder at every position, so a downstream
    /// consumer that iterates `BumpLevel::ALL` reads from least-to-
    /// greatest magnitude without a per-site sort.
    #[test]
    fn test_bump_level_all_matches_canonical_ladder() {
        assert_eq!(
            BumpLevel::ALL,
            [BumpLevel::Patch, BumpLevel::Minor, BumpLevel::Major],
            "ALL must list Patch, Minor, Major in source-order ladder",
        );
    }

    /// [`BumpLevel::ALL`] is already in ascending [`Ord`] order: sorting
    /// the array yields the array itself. The structural pin that ties
    /// `ALL`'s element order to the derived [`Ord`] ladder (rather than
    /// to an arbitrary author-chosen order), so a future variant
    /// insertion that placed the new variant out of ladder order in
    /// `ALL` would light up here without depending on the more brittle
    /// fixed-shape pin in
    /// [`test_bump_level_all_matches_canonical_ladder`]. Same total-
    /// order discipline `test_bump_level_sort_yields_canonical_ladder`
    /// established for the unordered three-variant `Vec`, here lifted
    /// to the canonical `ALL` enumeration.
    #[test]
    fn test_bump_level_all_is_canonical_ladder_order() {
        let mut sorted = BumpLevel::ALL.to_vec();
        sorted.sort();
        assert_eq!(
            sorted,
            BumpLevel::ALL.to_vec(),
            "ALL must already be in ascending Ord order — sort is a no-op",
        );
    }

    /// Every [`BumpLevel`] variant appears in [`BumpLevel::ALL`]. The
    /// load-bearing structural pin: the test reads every variant
    /// through an exhaustive `match` (so the compiler refuses to compile
    /// the test until a future variant is added to the match), and the
    /// match body asserts the variant is contained in `ALL` — so a
    /// future variant insertion that forgot to extend `ALL` lights up
    /// at this one site. The compiler-enforced exhaustiveness is what
    /// makes the variant-enumeration single-source: a forgotten variant
    /// in `ALL` is structurally surfaced rather than silently degrading
    /// every property test that iterates the const.
    #[test]
    fn test_bump_level_all_contains_every_variant() {
        fn must_appear_in_all(level: BumpLevel) {
            match level {
                BumpLevel::Patch => {
                    assert!(
                        BumpLevel::ALL.contains(&BumpLevel::Patch),
                        "Patch must be in ALL",
                    );
                }
                BumpLevel::Minor => {
                    assert!(
                        BumpLevel::ALL.contains(&BumpLevel::Minor),
                        "Minor must be in ALL",
                    );
                }
                BumpLevel::Major => {
                    assert!(
                        BumpLevel::ALL.contains(&BumpLevel::Major),
                        "Major must be in ALL",
                    );
                }
            }
        }
        for level in BumpLevel::ALL {
            must_appear_in_all(level);
        }
    }

    /// [`BumpLevel::ALL`] lists each variant exactly once — no
    /// duplicates. Pairs with
    /// [`test_bump_level_all_contains_every_variant`] (which pins the
    /// "every variant appears" direction) to seal the bijection between
    /// the enum's variant set and the `ALL` const: a future copy-paste
    /// regression that duplicated a variant entry in `ALL` (e.g., a
    /// `[Patch, Minor, Minor]` typo on a variant insertion) lights up
    /// here as a length-vs-distinct mismatch, even though the
    /// exhaustive-match pin would still pass.
    #[test]
    fn test_bump_level_all_variants_distinct() {
        let mut sorted = BumpLevel::ALL.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            BumpLevel::ALL.len(),
            "ALL must list each variant exactly once — no duplicates",
        );
    }

    /// At every [`BumpLevel`] variant, `is_breaking()` returns the value
    /// it must under the breaking-vs-non-breaking semver semantic role:
    /// `Major` is breaking, `Patch` and `Minor` are not. A release-policy
    /// gate that today reads `match level { Major => bail!("breaking"), _
    /// => ok }` reads after this commit as `if level.is_breaking() {
    /// bail!("breaking") }` — the semantic role is named once, not retyped
    /// at every policy site.
    #[test]
    fn test_bump_level_is_breaking_named_at_top_of_ladder() {
        assert!(
            BumpLevel::Major.is_breaking(),
            "Major is breaking — the top of the magnitude ladder",
        );
        assert!(
            !BumpLevel::Minor.is_breaking(),
            "Minor is a backwards-compatible addition, not breaking",
        );
        assert!(
            !BumpLevel::Patch.is_breaking(),
            "Patch is a backwards-compatible fix, not breaking",
        );
    }

    /// `is_breaking()` agrees with `*self >= BumpLevel::Major` at every
    /// variant — the structural pin that makes the total-order discipline
    /// (commit 8c2bbd5) the load-bearing oracle for the breaking-vs-non-
    /// breaking gate. A regression that drifted the body to
    /// `matches!(self, Self::Major)` would still pass
    /// [`test_bump_level_is_breaking_named_at_top_of_ladder`] at the
    /// current three-variant ladder; this pin holds against future
    /// regressions that desynced the named-method peer from the derived
    /// `>=` comparison the prior commit lifted. Same idiom
    /// `AdmissionTier::admits_relaxed` established at the admission-gate
    /// surface — the typed-method peer reads `>=`, not `matches!`.
    #[test]
    fn test_bump_level_is_breaking_agrees_with_ge_major_at_every_variant() {
        for level in BumpLevel::ALL {
            assert_eq!(
                level.is_breaking(),
                level >= BumpLevel::Major,
                "is_breaking() must read the >= Major comparison at {level:?}",
            );
        }
    }

    /// `is_breaking()` partitions the three-variant ladder into exactly
    /// one breaking variant and two non-breaking variants. The pin
    /// surfaces a structural break if a future variant insertion (e.g., a
    /// `Prerelease` variant slotted below `Patch`) silently shifted which
    /// variants land on the breaking side without a deliberate decision
    /// at this typed-method surface.
    #[test]
    fn test_bump_level_is_breaking_partitions_ladder_into_one_breaking_variant() {
        let breaking_count = BumpLevel::ALL.iter().filter(|l| l.is_breaking()).count();
        assert_eq!(
            breaking_count, 1,
            "exactly one of {{Patch, Minor, Major}} is breaking at the current ladder",
        );
    }

    /// At every [`BumpLevel`] variant, `is_non_breaking()` returns the
    /// value it must under the backward-compatibility semver semantic
    /// role: `Patch` and `Minor` are non-breaking, `Major` is not. A
    /// release-policy gate that today reads `match level { Patch | Minor
    /// => allow, Major => bail!("breaking") }` reads after this commit as
    /// `if level.is_non_breaking() { allow } else { bail!("breaking") }`
    /// — the backward-compatibility semantic role is named once at the
    /// typed-primitive surface, not retyped at every policy site.
    #[test]
    fn test_bump_level_is_non_breaking_named_at_ladder_floor() {
        assert!(
            BumpLevel::Patch.is_non_breaking(),
            "Patch is a backwards-compatible fix — non-breaking",
        );
        assert!(
            BumpLevel::Minor.is_non_breaking(),
            "Minor is a backwards-compatible addition — non-breaking",
        );
        assert!(
            !BumpLevel::Major.is_non_breaking(),
            "Major sits at the breaking-change threshold — not non-breaking",
        );
    }

    /// `is_non_breaking()` agrees with `*self < BumpLevel::Major` at
    /// every variant — the structural pin that makes the total-order
    /// discipline (commit 8c2bbd5) the load-bearing oracle for the
    /// backward-compatibility gate. A regression that drifted the body
    /// to `matches!(self, Self::Patch | Self::Minor)` would still pass
    /// [`test_bump_level_is_non_breaking_named_at_ladder_floor`] at the
    /// current three-variant ladder; this pin holds against future
    /// regressions that desynced the named-method peer from the derived
    /// `<` comparison the prior commit (8c2bbd5, magnitude ladder lift)
    /// made admissible. Same idiom
    /// [`crate::probe_outcome::AdmissionTier::refuses_relaxed`]
    /// established at the admission-gate surface — the typed-method peer
    /// reads `<`, not `matches!`.
    #[test]
    fn test_bump_level_is_non_breaking_agrees_with_lt_major_at_every_variant() {
        for level in BumpLevel::ALL {
            assert_eq!(
                level.is_non_breaking(),
                level < BumpLevel::Major,
                "is_non_breaking() must read the < Major comparison at {level:?}",
            );
        }
    }

    /// The De Morgan complementarity invariant
    /// `is_non_breaking() == !is_breaking()` holds at every variant —
    /// the two predicates are exact complements over the
    /// breaking-change threshold. Same partition pin
    /// [`crate::probe_outcome::AdmissionTier::refuses_relaxed`] enforces
    /// against [`crate::probe_outcome::AdmissionTier::admits_relaxed`]
    /// at the admission-gate surface, here at the
    /// version-bump-magnitude surface. A future regression that drifted
    /// either method body (e.g., a hand-rolled `matches!` form on either
    /// side that desynced from the derived `<` / `>=` reading after a
    /// fourth-variant addition) lights up here.
    #[test]
    fn test_bump_level_is_non_breaking_equals_negation_of_is_breaking() {
        for level in BumpLevel::ALL {
            assert_eq!(
                level.is_non_breaking(),
                !level.is_breaking(),
                "is_non_breaking must equal !is_breaking at {level:?}",
            );
        }
    }

    /// The disjoint-and-covering partition invariant
    /// `is_non_breaking() XOR is_breaking() == true` holds at every
    /// variant — exactly one of the two named typed-method peers reads
    /// true at every level. The pin surfaces a structural break if a
    /// future variant insertion left a gap (a level neither side
    /// classified) or an overlap (a level both sides classified): same
    /// XOR-partition seal `AdmissionTier::refuses_relaxed XOR
    /// admits_relaxed` placed at the admission-gate surface, here at the
    /// version-bump-magnitude surface. With this pin and its sibling
    /// negation pin, the breaking / non-breaking typed-method peer pair
    /// over the magnitude ladder is sealed against gaps and overlaps.
    #[test]
    fn test_bump_level_is_non_breaking_xor_is_breaking_partitions_ladder() {
        for level in BumpLevel::ALL {
            assert!(
                level.is_non_breaking() ^ level.is_breaking(),
                "is_non_breaking XOR is_breaking must hold at {level:?}",
            );
        }
    }

    /// At every [`BumpLevel`] variant, `is_fix_only()` returns the value
    /// it must under the fix-only semver semantic role: `Patch` is
    /// fix-only; `Minor` and `Major` are not. A release-policy gate that
    /// today reads `match level { Patch => allow_direct_ship, _ =>
    /// queue_for_review }` reads after this commit as `if
    /// level.is_fix_only() { allow_direct_ship } else { queue_for_review }`
    /// — the fix-only semantic role is named once at the typed-primitive
    /// surface, not retyped at every policy site.
    #[test]
    fn test_bump_level_is_fix_only_named_at_ladder_floor() {
        assert!(
            BumpLevel::Patch.is_fix_only(),
            "Patch is the fix-only floor of the magnitude ladder",
        );
        assert!(
            !BumpLevel::Minor.is_fix_only(),
            "Minor is a backwards-compatible addition, not fix-only",
        );
        assert!(
            !BumpLevel::Major.is_fix_only(),
            "Major is a breaking bump, not fix-only",
        );
    }

    /// `is_fix_only()` agrees with `*self == BumpLevel::Patch` at every
    /// variant — the structural pin that makes the derived
    /// `PartialEq`/`Eq` impl (the magnitude-ladder typed-sum surface,
    /// commit b842b21) the load-bearing oracle for the fix-only band
    /// reading. A regression that drifted the body to `matches!(self,
    /// Self::Patch)` would still pass
    /// [`test_bump_level_is_fix_only_named_at_ladder_floor`] at the
    /// current three-variant ladder; this pin holds against future
    /// regressions that desynced the named-method peer from the derived
    /// `==` reading. Same idiom
    /// [`crate::probe_outcome::AdmissionTier::is_staging_only`] established
    /// at the admission-gate surface — the typed-method peer for a single
    /// band variant reads through the structural equality / decomposition
    /// surface, not a hand-rolled `matches!` cascade.
    #[test]
    fn test_bump_level_is_fix_only_agrees_with_eq_patch_at_every_variant() {
        for level in BumpLevel::ALL {
            assert_eq!(
                level.is_fix_only(),
                level == BumpLevel::Patch,
                "is_fix_only() must read the == Patch comparison at {level:?}",
            );
        }
    }

    /// The implication invariant `is_fix_only() => is_non_breaking()`
    /// holds at every variant — every fix-only bump is structurally a
    /// non-breaking bump (every `Patch` is strictly below `Major` on the
    /// magnitude ladder), but not every non-breaking bump is fix-only
    /// (`Minor` is non-breaking yet not fix-only). The pin makes the
    /// subset relation between the floor predicate and the
    /// below-threshold predicate structurally load-bearing: a downstream
    /// release-policy gate that admits `is_non_breaking()` automatically
    /// admits every `is_fix_only()` bump, with no per-site reclassification
    /// of the implication. Same subset-invariant pin
    /// `AdmissionTier::admits_strict() => AdmissionTier::admits_relaxed()`
    /// established at the admission-gate surface (strict eligibility
    /// implies relaxed eligibility), here at the version-bump-magnitude
    /// surface (fix-only implies non-breaking).
    #[test]
    fn test_bump_level_is_fix_only_implies_is_non_breaking() {
        for level in BumpLevel::ALL {
            assert!(
                !level.is_fix_only() || level.is_non_breaking(),
                "is_fix_only() must imply is_non_breaking() at {level:?}",
            );
        }
    }

    /// The disjoint invariant `!(is_fix_only() && is_breaking())` holds
    /// at every variant — no bump is simultaneously fix-only AND breaking.
    /// The fix-only floor (`Patch`) and the breaking threshold (`>= Major`)
    /// are disjoint extremes of the magnitude ladder: their conjunction is
    /// empty at every level. The pin closes the named-method trio over
    /// the ladder against accidental overlap, complementing the De Morgan
    /// pin between `is_breaking` and `is_non_breaking` already in place.
    /// A future variant insertion that drifted the floor or the threshold
    /// such that some level read true for both predicates lights up here
    /// — same disjoint-extremes pin `AdmissionTier::refuses_relaxed XOR
    /// admits_strict` placed at the admission-gate surface, here at the
    /// version-bump-magnitude surface.
    #[test]
    fn test_bump_level_is_fix_only_disjoint_from_is_breaking() {
        for level in BumpLevel::ALL {
            assert!(
                !(level.is_fix_only() && level.is_breaking()),
                "is_fix_only() AND is_breaking() must be empty at {level:?}",
            );
        }
    }

    /// At every [`BumpLevel`] variant, `is_minor_only()` returns the value
    /// it must under the minor-only semver semantic role: `Minor` is
    /// minor-only; `Patch` and `Major` are not. A release-policy gate that
    /// today reads `match level { Minor => additive_api_channel, _ =>
    /// other }` reads after this commit as `if level.is_minor_only() {
    /// additive_api_channel } else { other }` — the minor-only semantic
    /// role is named once at the typed-primitive surface, not retyped at
    /// every policy site.
    #[test]
    fn test_bump_level_is_minor_only_named_at_ladder_middle() {
        assert!(
            BumpLevel::Minor.is_minor_only(),
            "Minor is the additive-API middle band of the magnitude ladder",
        );
        assert!(
            !BumpLevel::Patch.is_minor_only(),
            "Patch is the fix-only floor, not minor-only",
        );
        assert!(
            !BumpLevel::Major.is_minor_only(),
            "Major is the breaking ceiling, not minor-only",
        );
    }

    /// `is_minor_only()` agrees with `*self == BumpLevel::Minor` at every
    /// variant — the structural pin that makes the derived
    /// `PartialEq`/`Eq` impl (the magnitude-ladder typed-sum surface,
    /// commit b842b21) the load-bearing oracle for the minor-only band
    /// reading. A regression that drifted the body to `matches!(self,
    /// Self::Minor)` would still pass
    /// [`test_bump_level_is_minor_only_named_at_ladder_middle`] at the
    /// current three-variant ladder; this pin holds against future
    /// regressions that desynced the named-method peer from the derived
    /// `==` reading. Same idiom [`is_fix_only`] established at the ladder
    /// floor — the typed-method peer for a single band variant reads
    /// through the structural equality surface, not a hand-rolled
    /// `matches!` cascade or the `is_non_breaking() && !is_fix_only()`
    /// decomposition (which would silently misclassify a future variant
    /// inserted below `Patch`).
    #[test]
    fn test_bump_level_is_minor_only_agrees_with_eq_minor_at_every_variant() {
        for level in BumpLevel::ALL {
            assert_eq!(
                level.is_minor_only(),
                level == BumpLevel::Minor,
                "is_minor_only() must read the == Minor comparison at {level:?}",
            );
        }
    }

    /// The implication invariant `is_minor_only() => is_non_breaking()`
    /// holds at every variant — every minor-only bump is structurally a
    /// non-breaking bump (every `Minor` is strictly below `Major` on the
    /// magnitude ladder), but not every non-breaking bump is minor-only
    /// (`Patch` is non-breaking yet not minor-only). The pin makes the
    /// subset relation between the middle predicate and the below-threshold
    /// predicate structurally load-bearing: a downstream release-policy
    /// gate that admits `is_non_breaking()` automatically admits every
    /// `is_minor_only()` bump. Same subset-invariant pin shape
    /// `is_fix_only() => is_non_breaking()` established at the floor, here
    /// at the middle band of the version-bump-magnitude ladder.
    #[test]
    fn test_bump_level_is_minor_only_implies_is_non_breaking() {
        for level in BumpLevel::ALL {
            assert!(
                !level.is_minor_only() || level.is_non_breaking(),
                "is_minor_only() must imply is_non_breaking() at {level:?}",
            );
        }
    }

    /// The disjoint invariant `!(is_minor_only() && is_fix_only())` holds
    /// at every variant — no bump is simultaneously minor-only AND fix-only.
    /// The middle band (`Minor`) and the floor band (`Patch`) are distinct
    /// ladder positions: their conjunction is empty at every level. The pin
    /// closes the floor / middle named-band pair against accidental overlap,
    /// complementing the floor / ceiling disjoint pin already in place
    /// between `is_fix_only` and `is_breaking`.
    #[test]
    fn test_bump_level_is_minor_only_disjoint_from_is_fix_only() {
        for level in BumpLevel::ALL {
            assert!(
                !(level.is_minor_only() && level.is_fix_only()),
                "is_minor_only() AND is_fix_only() must be empty at {level:?}",
            );
        }
    }

    /// The disjoint invariant `!(is_minor_only() && is_breaking())` holds
    /// at every variant — no bump is simultaneously minor-only AND breaking.
    /// The middle band (`Minor`) sits strictly below the breaking threshold
    /// (`>= Major`): their conjunction is empty at every level. The pin
    /// closes the middle / ceiling named-band pair against accidental
    /// overlap, complementing the floor / ceiling disjoint pin already in
    /// place between `is_fix_only` and `is_breaking`.
    #[test]
    fn test_bump_level_is_minor_only_disjoint_from_is_breaking() {
        for level in BumpLevel::ALL {
            assert!(
                !(level.is_minor_only() && level.is_breaking()),
                "is_minor_only() AND is_breaking() must be empty at {level:?}",
            );
        }
    }

    /// The disjoint-and-covering trio partition invariant
    /// `is_fix_only() XOR is_minor_only() XOR is_breaking() == true` holds
    /// at every variant — exactly one of the three named typed-method peers
    /// reads `true` at every level. The pin surfaces a structural break if
    /// any of the three method bodies drifted such that some level read
    /// `true` for two predicates (overlap) or `false` for all three (gap):
    /// same disjoint-XOR-cover seal `AdmissionTier::admits_strict XOR
    /// is_staging_only XOR refuses_relaxed` placed at the admission-gate
    /// surface (commit e08b821), here at the version-bump-magnitude
    /// surface. With this pin, the fix-only / minor-only / breaking
    /// named-method trio over the magnitude ladder is sealed against gaps
    /// and overlaps at the present three-variant ladder, and a future
    /// variant insertion that left some position uncovered or doubly-
    /// covered lights up here.
    #[test]
    fn test_bump_level_named_trio_xor_partitions_ladder() {
        for level in BumpLevel::ALL {
            assert!(
                level.is_fix_only() ^ level.is_minor_only() ^ level.is_breaking(),
                "fix-only XOR minor-only XOR breaking must hold at {level:?}",
            );
        }
    }

    /// At every [`BumpLevel`] variant, `is_major_only()` returns the value
    /// it must under the major-ceiling semver semantic role: `Major` is
    /// major-only; `Patch` and `Minor` are not. A release-policy gate that
    /// today reads `match level { Major => breaking_review_queue, _ =>
    /// other }` reads after this commit as `if level.is_major_only() {
    /// breaking_review_queue } else { other }` — the major-only semantic
    /// role is named once at the typed-primitive surface, not retyped at
    /// every policy site. Ceiling-sibling of
    /// [`test_bump_level_is_fix_only_named_at_ladder_floor`] at the dual
    /// extreme.
    #[test]
    fn test_bump_level_is_major_only_named_at_ladder_ceiling() {
        assert!(
            BumpLevel::Major.is_major_only(),
            "Major is the breaking-change ceiling of the magnitude ladder",
        );
        assert!(
            !BumpLevel::Patch.is_major_only(),
            "Patch is the fix-only floor, not major-only",
        );
        assert!(
            !BumpLevel::Minor.is_major_only(),
            "Minor is the additive-API middle band, not major-only",
        );
    }

    /// `is_major_only()` agrees with `*self == BumpLevel::Major` at every
    /// variant — the structural pin that makes the derived
    /// `PartialEq`/`Eq` impl (the magnitude-ladder typed-sum surface,
    /// commit b842b21) the load-bearing oracle for the major-ceiling
    /// identity reading. A regression that drifted the body to
    /// `matches!(self, Self::Major)` or to `self.is_breaking()` would still
    /// pass [`test_bump_level_is_major_only_named_at_ladder_ceiling`] at
    /// the current three-variant ladder; this pin holds against future
    /// regressions that desynced the named-method peer from the derived
    /// `==` reading. Same idiom [`is_fix_only`] and [`is_minor_only`]
    /// established at the floor and middle, here at the ceiling.
    #[test]
    fn test_bump_level_is_major_only_agrees_with_eq_major_at_every_variant() {
        for level in BumpLevel::ALL {
            assert_eq!(
                level.is_major_only(),
                level == BumpLevel::Major,
                "is_major_only() must read the == Major comparison at {level:?}",
            );
        }
    }

    /// The implication invariant `is_major_only() => is_breaking()` holds
    /// at every variant — every major-only bump is structurally a breaking
    /// bump (`Major >= Major` trivially), so a downstream release-policy
    /// gate that admits `is_breaking()` automatically admits every
    /// `is_major_only()` bump, with no per-site reclassification of the
    /// implication. Sibling pin of
    /// [`test_bump_level_is_fix_only_implies_is_non_breaking`] at the
    /// dual extreme (ceiling identity into ceiling ray, vs floor identity
    /// into below-ceiling ray) and of
    /// [`crate::probe_outcome::tests::test_admission_tier_is_strict_implies_admits_strict`]
    /// at the admission-tier surface.
    #[test]
    fn test_bump_level_is_major_only_implies_is_breaking() {
        for level in BumpLevel::ALL {
            assert!(
                !level.is_major_only() || level.is_breaking(),
                "is_major_only() must imply is_breaking() at {level:?}",
            );
        }
    }

    /// The disjoint invariant `!(is_major_only() && is_fix_only())` holds
    /// at every variant — no bump is simultaneously major-only AND
    /// fix-only. The major ceiling (`Major`) and the fix-only floor
    /// (`Patch`) are distinct ladder positions: their conjunction is empty
    /// at every level. The pin closes the floor-identity / ceiling-
    /// identity named-band pair against accidental overlap, complementing
    /// the existing disjoint pins between the named-method peers. Same
    /// disjoint-extremes pin
    /// [`crate::probe_outcome::tests::test_admission_tier_is_strict_disjoint_from_refuses_relaxed`]
    /// (ceiling identity vs floor ray) and
    /// [`crate::probe_outcome::tests::test_admission_tier_is_refused_disjoint_from_admits_relaxed`]
    /// (floor identity vs ceiling ray) at the admission-tier surface.
    #[test]
    fn test_bump_level_is_major_only_disjoint_from_is_fix_only() {
        for level in BumpLevel::ALL {
            assert!(
                !(level.is_major_only() && level.is_fix_only()),
                "is_major_only() AND is_fix_only() must be empty at {level:?}",
            );
        }
    }

    /// The disjoint-and-covering identity-trio partition invariant
    /// `is_fix_only() XOR is_minor_only() XOR is_major_only() == true`
    /// holds at every variant — exactly one of the three named variant-
    /// identity peers reads `true` at every level. Distinct from the
    /// ray-form trio
    /// [`test_bump_level_named_trio_xor_partitions_ladder`] which rides
    /// `is_breaking()` at the ceiling: under the present three-variant
    /// ladder the two trios coincide numerically, but under a future
    /// `Epoch` variant inserted above `Major` the ray-trio still
    /// partitions (`Epoch` reads `is_breaking() == true`, the other two
    /// false — exactly one true) while the identity-trio surfaces a gap
    /// (`Epoch` reads false for all three identity predicates — zero
    /// true). The dual partition sealing makes the structural drift class
    /// — silent reclassification of a future ceiling variant as either
    /// the canonical breaking ray reading OR the canonical major identity
    /// reading — load-bearing at the typed-primitive surface. Same dual-
    /// partition seal
    /// [`crate::probe_outcome::AdmissionTier`] already carries (ray
    /// partition at commit e08b821, identity partition at commit
    /// 1775181).
    #[test]
    fn test_bump_level_identity_trio_partitions_ladder() {
        for level in BumpLevel::ALL {
            assert!(
                level.is_fix_only() ^ level.is_minor_only() ^ level.is_major_only(),
                "fix-only XOR minor-only XOR major-only must hold at {level:?}",
            );
        }
    }

    /// Under the present three-variant ladder, `is_major_only()` coincides
    /// numerically with `is_breaking()` at every variant: `Major` is both
    /// the unique == ceiling variant AND the unique >= ceiling variant.
    /// The pin names the present coincidence explicitly so the structural
    /// distinction between the two peers carries load even where they're
    /// numerically equal today. A future `Epoch` insertion above `Major`
    /// would surface the distinction at this pin: `is_breaking()` would
    /// read `true` at `Epoch` (>= Major), while `is_major_only()` would
    /// read `false` (!= Major). Sibling pin of
    /// [`crate::probe_outcome::tests::test_admission_tier_is_strict_equals_admits_strict_under_present_ladder`]
    /// at the admission-tier surface.
    #[test]
    fn test_bump_level_is_major_only_equals_is_breaking_under_present_ladder() {
        for level in BumpLevel::ALL {
            assert_eq!(
                level.is_major_only(),
                level.is_breaking(),
                "under the present 3-variant ladder, is_major_only() and is_breaking() must coincide at {level:?}",
            );
        }
    }

    /// At every [`BumpLevel`] variant, `is_feature_or_breaking()` returns
    /// the value a downstream release-notes gate would have written as
    /// `level >= BumpLevel::Minor` at the consumer surface — `false` only
    /// at [`BumpLevel::Patch`] (the structural floor), `true` at the two
    /// strictly-greater variants (`Minor`, `Major`). The exact-shape
    /// per-variant pin that makes a release-notes generator that says
    /// "any non-fix bump requires a user-facing changelog entry" reads
    /// `if level.is_feature_or_breaking() { generate_changelog() }` at
    /// one site instead of `if !level.is_fix_only() { ... }` or a two-arm
    /// `match level { Minor | Major => ..., Patch => ... }` cascade.
    /// Floor-sibling of [`test_bump_level_is_breaking_named_at_threshold`]
    /// at the upper threshold.
    #[test]
    fn test_bump_level_is_feature_or_breaking_named_at_lower_threshold() {
        assert!(
            !BumpLevel::Patch.is_feature_or_breaking(),
            "Patch sits strictly below the Minor threshold and must NOT read as feature-or-breaking",
        );
        assert!(
            BumpLevel::Minor.is_feature_or_breaking(),
            "Minor sits at the lower threshold and must read as feature-or-breaking",
        );
        assert!(
            BumpLevel::Major.is_feature_or_breaking(),
            "Major sits strictly above the Minor threshold and must read as feature-or-breaking",
        );
    }

    /// `is_feature_or_breaking()` agrees with `*self >= BumpLevel::Minor`
    /// at every variant — the structural pin that makes the `>=` form (not
    /// the `!is_fix_only()` decomposition or the `matches!(self, Self::
    /// Minor | Self::Major)` arm cascade) the load-bearing oracle for the
    /// lower-threshold gate. A hand-rolled regression that drifted the
    /// method body to either decomposition would still pass
    /// [`test_bump_level_is_feature_or_breaking_named_at_lower_threshold`]
    /// at the present three-variant ladder but break this structural-
    /// equivalence pin at any future variant insertion below `Patch` or
    /// above `Major`. Same idiom
    /// [`test_bump_level_is_breaking_agrees_with_geq_major_at_every_variant`]
    /// established at the upper threshold of the same ladder.
    #[test]
    fn test_bump_level_is_feature_or_breaking_agrees_with_geq_minor_at_every_variant() {
        for level in BumpLevel::ALL {
            assert_eq!(
                level.is_feature_or_breaking(),
                level >= BumpLevel::Minor,
                "is_feature_or_breaking() must read the >= Minor comparison at {level:?}",
            );
        }
    }

    /// The implication invariant `is_breaking() => is_feature_or_breaking()`
    /// holds at every variant: every breaking bump is structurally feature-
    /// or-breaking (every `>= Major` is `>= Minor`). A downstream release-
    /// notes gate that admits `is_feature_or_breaking()` automatically
    /// admits every `is_breaking()` bump, with no per-site reclassification
    /// of the breaking ceiling. Sibling pin of
    /// [`test_bump_level_is_major_only_implies_is_breaking`] at the
    /// variant-identity / half-open-ray pair, here at the two half-open-
    /// ray surfaces of the same ladder.
    #[test]
    fn test_bump_level_is_breaking_implies_is_feature_or_breaking() {
        for level in BumpLevel::ALL {
            assert!(
                !level.is_breaking() || level.is_feature_or_breaking(),
                "is_breaking() must imply is_feature_or_breaking() at {level:?}",
            );
        }
    }

    /// Under the present three-variant ladder, `is_feature_or_breaking()`
    /// and `is_fix_only()` are exact De Morgan complements at every
    /// variant: `Patch` reads fix-only / not-feature-or-breaking, `Minor`
    /// and `Major` read not-fix-only / feature-or-breaking. The
    /// coincidence depends on the present ladder having only one variant
    /// strictly below `Minor` (`Patch`, which is also exactly the
    /// `is_fix_only` floor); a future `Prerelease` variant inserted
    /// strictly below `Patch` would surface the structural distinction —
    /// `Prerelease` would read `!is_feature_or_breaking()` (it sits below
    /// the Minor threshold) AND `!is_fix_only()` (it is not exactly
    /// `Patch`), so the De Morgan complementarity would no longer hold at
    /// the new variant. Same present-ladder-coincidence idiom
    /// [`test_bump_level_is_major_only_equals_is_breaking_under_present_ladder`]
    /// established at the upper threshold against the variant-identity
    /// surface.
    #[test]
    fn test_bump_level_is_feature_or_breaking_equals_negation_of_is_fix_only_under_present_ladder()
    {
        for level in BumpLevel::ALL {
            assert_eq!(
                level.is_feature_or_breaking(),
                !level.is_fix_only(),
                "under the present 3-variant ladder, is_feature_or_breaking() must equal !is_fix_only() at {level:?}",
            );
        }
    }

    /// Under the present three-variant ladder, `is_feature_or_breaking()`
    /// XOR `is_fix_only()` reads `true` at every variant — the disjoint-
    /// and-covering partition: no variant is simultaneously
    /// feature-or-breaking AND fix-only, and no variant is neither. A
    /// regression that broke either method body (e.g., a future hand-
    /// rolled `*self != Self::Patch` body for `is_feature_or_breaking`
    /// that drifted from the `>=` form across a fourth-variant addition
    /// below `Patch`) would surface here as a partition gap or overlap.
    /// Same partition shape
    /// [`test_bump_level_named_trio_xor_partitions_ladder`] established
    /// at the variant-identity / half-open-ray trio, here at the two-
    /// method pair across the lower threshold.
    #[test]
    fn test_bump_level_is_feature_or_breaking_xor_is_fix_only_partitions_ladder() {
        for level in BumpLevel::ALL {
            assert!(
                level.is_feature_or_breaking() ^ level.is_fix_only(),
                "is_feature_or_breaking() XOR is_fix_only() must read true at {level:?} \
                 — the lower-threshold gate and the floor-identity must partition the ladder",
            );
        }
    }

    /// Under the present three-variant ladder, `is_feature_or_breaking()`
    /// decomposes as `is_minor_only() || is_major_only()` — every variant
    /// that reads as feature-or-breaking is exactly one of the two non-
    /// floor variant identities. The pin that ties the half-open-ray
    /// surface at the lower threshold to the two variant-identity peers
    /// strictly above the floor, so a future regression that broke either
    /// side of the named-method composition lights up here. Same
    /// decomposition shape
    /// [`crate::probe_outcome::tests::test_admission_tier_admits_relaxed_decomposes_as_is_staging_only_or_is_strict`]
    /// (if any) carries at the admission-tier ladder; here at the
    /// magnitude-ladder lower threshold.
    #[test]
    fn test_bump_level_is_feature_or_breaking_decomposes_as_minor_or_major_identity() {
        for level in BumpLevel::ALL {
            assert_eq!(
                level.is_feature_or_breaking(),
                level.is_minor_only() || level.is_major_only(),
                "under the present 3-variant ladder, is_feature_or_breaking() must decompose as is_minor_only() || is_major_only() at {level:?}",
            );
        }
    }

    /// At every [`BumpLevel`] variant, `is_below_feature_threshold()`
    /// returns the value a downstream provenance gate would have written
    /// as `level < BumpLevel::Minor` at the consumer surface — `true`
    /// only at [`BumpLevel::Patch`] (the structural floor), `false` at
    /// the two strictly-greater variants (`Minor`, `Major`). The
    /// exact-shape per-variant pin that makes a release-pipeline gate
    /// saying "internal-only fix releases ship under an abbreviated
    /// provenance trail" read `if level.is_below_feature_threshold() {
    /// abbreviated_trail() }` at one site instead of
    /// `if !level.is_feature_or_breaking() { ... }` or a single-arm
    /// `match level { Patch => abbreviated, _ => full }` cascade.
    /// Floor-sibling of [`test_bump_level_is_non_breaking_pins_below_major`]
    /// at the upper threshold (if any), and complement-sibling of
    /// [`test_bump_level_is_feature_or_breaking_named_at_lower_threshold`]
    /// at the same threshold.
    #[test]
    fn test_bump_level_is_below_feature_threshold_named_at_lower_threshold() {
        assert!(
            BumpLevel::Patch.is_below_feature_threshold(),
            "Patch sits strictly below the Minor threshold and must read as below-feature-threshold",
        );
        assert!(
            !BumpLevel::Minor.is_below_feature_threshold(),
            "Minor sits at the lower threshold and must NOT read as below-feature-threshold",
        );
        assert!(
            !BumpLevel::Major.is_below_feature_threshold(),
            "Major sits strictly above the Minor threshold and must NOT read as below-feature-threshold",
        );
    }

    /// `is_below_feature_threshold()` agrees with `*self < BumpLevel::Minor`
    /// at every variant — the structural pin that makes the `<` form
    /// (not the `!is_feature_or_breaking()` decomposition or the
    /// `matches!(self, Self::Patch)` arm) the load-bearing oracle for
    /// the below-feature-threshold gate. A hand-rolled regression that
    /// drifted the method body to either decomposition would still pass
    /// [`test_bump_level_is_below_feature_threshold_named_at_lower_threshold`]
    /// at the present three-variant ladder but break this structural-
    /// equivalence pin at any future variant insertion below `Patch`
    /// (a `Prerelease` variant the `matches!` form would silently
    /// misclassify as NOT below the feature threshold). Same idiom
    /// [`test_bump_level_is_feature_or_breaking_agrees_with_geq_minor_at_every_variant`]
    /// established at the complement side of the same threshold.
    #[test]
    fn test_bump_level_is_below_feature_threshold_agrees_with_lt_minor_at_every_variant() {
        for level in BumpLevel::ALL {
            assert_eq!(
                level.is_below_feature_threshold(),
                level < BumpLevel::Minor,
                "is_below_feature_threshold() must read the < Minor comparison at {level:?}",
            );
        }
    }

    /// The De Morgan complementarity invariant
    /// `is_below_feature_threshold() == !is_feature_or_breaking()` holds
    /// at every variant — the two predicates are exact complements over
    /// the lower (Minor) threshold of the magnitude ladder. The
    /// structural pin that makes the two method bodies load-bearing
    /// duals of each other so a regression in either side surfaces here
    /// rather than drifting silently across the De Morgan boundary.
    /// Sibling pin of
    /// [`test_bump_level_is_non_breaking_equals_negation_of_is_breaking`]
    /// at the upper threshold of the same ladder, here at the lower
    /// threshold.
    #[test]
    fn test_bump_level_is_below_feature_threshold_equals_negation_of_is_feature_or_breaking() {
        for level in BumpLevel::ALL {
            assert_eq!(
                level.is_below_feature_threshold(),
                !level.is_feature_or_breaking(),
                "is_below_feature_threshold() must equal !is_feature_or_breaking() at {level:?}",
            );
        }
    }

    /// `is_below_feature_threshold()` XOR `is_feature_or_breaking()`
    /// reads `true` at every variant — the disjoint-and-covering
    /// partition over the lower (Minor) threshold: no variant is
    /// simultaneously below the feature threshold AND
    /// feature-or-breaking, and no variant is neither. A regression
    /// that broke either method body (e.g., a future hand-rolled
    /// `matches!(self, Self::Patch)` body for
    /// `is_below_feature_threshold` that drifted from the `<` form
    /// across a fourth-variant addition below `Patch`) would surface
    /// here as a partition gap or overlap. Same partition shape
    /// [`test_bump_level_is_non_breaking_xor_is_breaking_partitions_ladder`]
    /// established at the upper threshold of the same ladder, here at
    /// the lower threshold.
    #[test]
    fn test_bump_level_is_below_feature_threshold_xor_is_feature_or_breaking_partitions_ladder() {
        for level in BumpLevel::ALL {
            assert!(
                level.is_below_feature_threshold() ^ level.is_feature_or_breaking(),
                "is_below_feature_threshold() XOR is_feature_or_breaking() must read true at {level:?} \
                 — the lower-threshold De Morgan pair must partition the ladder",
            );
        }
    }

    /// The implication invariant
    /// `is_below_feature_threshold() => is_non_breaking()` holds at every
    /// variant: every bump strictly below the Minor threshold (every
    /// `< Minor`) is structurally also strictly below the Major
    /// threshold (every `< Major`), so a downstream provenance gate that
    /// admits `is_non_breaking()` automatically admits every
    /// `is_below_feature_threshold()` bump with no per-site
    /// reclassification. Sibling pin of
    /// [`test_bump_level_is_breaking_implies_is_feature_or_breaking`]
    /// at the dual implication: the implication runs upward at the
    /// upper-threshold gate (`is_breaking() => is_feature_or_breaking()`,
    /// every `>= Major` is `>= Minor`); here it runs downward at the
    /// lower-threshold gate (`is_below_feature_threshold() =>
    /// is_non_breaking()`, every `< Minor` is `< Major`). Together the
    /// two implications carry the structural fact that the four
    /// half-open-ray gates over the two thresholds form a nested chain
    /// — `is_breaking() ⊂ is_feature_or_breaking()` at the upper end,
    /// `is_below_feature_threshold() ⊂ is_non_breaking()` at the lower
    /// end — that downstream gates can compose without per-site arith
    /// over the variant identities.
    #[test]
    fn test_bump_level_is_below_feature_threshold_implies_is_non_breaking() {
        for level in BumpLevel::ALL {
            assert!(
                !level.is_below_feature_threshold() || level.is_non_breaking(),
                "is_below_feature_threshold() must imply is_non_breaking() at {level:?}",
            );
        }
    }

    /// Under the present three-variant ladder,
    /// `is_below_feature_threshold()` and `is_fix_only()` coincide at
    /// every variant: `Patch` reads both true (it is the floor AND it is
    /// strictly below `Minor`), `Minor` and `Major` read both false (they
    /// sit at or above the Minor threshold and they are not exactly
    /// `Patch`). The coincidence depends on the present ladder having
    /// only one variant strictly below `Minor` (`Patch`, which is also
    /// exactly the `is_fix_only` floor); a future `Prerelease` variant
    /// inserted strictly below `Patch` would surface the structural
    /// distinction — `Prerelease` would read `is_below_feature_threshold()`
    /// (it sits below the Minor threshold) AND NOT `is_fix_only()` (it
    /// is not exactly `Patch`), so the coincidence would no longer hold
    /// at the new variant. Same present-ladder-coincidence idiom
    /// [`test_bump_level_is_feature_or_breaking_equals_negation_of_is_fix_only_under_present_ladder`]
    /// established at the complement side of the same threshold, here
    /// at the positive side.
    #[test]
    fn test_bump_level_is_below_feature_threshold_equals_is_fix_only_under_present_ladder() {
        for level in BumpLevel::ALL {
            assert_eq!(
                level.is_below_feature_threshold(),
                level.is_fix_only(),
                "under the present 3-variant ladder, is_below_feature_threshold() must equal is_fix_only() at {level:?}",
            );
        }
    }

    /// Exact-shape per-(a,b) pin over the 3×3 grid: `join` returns the
    /// release-bump magnitude required to subsume both arguments at every
    /// reachable pair. Floor-sibling at the lattice-join surface of the
    /// per-variant pins
    /// (`test_bump_level_is_breaking_named_at_top_of_ladder` et al.) at the
    /// half-open-ray gate surface — the surface-witness pin a regression
    /// in the method body surfaces against.
    #[test]
    fn test_bump_level_join_named_at_release_aggregation_surface() {
        use BumpLevel::*;
        let cases = [
            (Patch, Patch, Patch),
            (Patch, Minor, Minor),
            (Patch, Major, Major),
            (Minor, Patch, Minor),
            (Minor, Minor, Minor),
            (Minor, Major, Major),
            (Major, Patch, Major),
            (Major, Minor, Major),
            (Major, Major, Major),
        ];
        for (a, b, expected) in cases {
            assert_eq!(
                a.join(b),
                expected,
                "join({a:?}, {b:?}) must return {expected:?}",
            );
        }
    }

    /// Structural-equivalence pin: `join` agrees with `Ord::max` at every
    /// pair over the 3×3 grid. The pin that makes the `max` form (not a
    /// hand-rolled match cascade) the load-bearing oracle, so a future
    /// variant insertion that desynced the method body from the derived
    /// `Ord` ladder would light up here rather than drifting silently
    /// through the lattice-join surface. Sibling of
    /// `test_bump_level_is_breaking_agrees_with_ge_major_at_every_variant`
    /// at the half-open-ray gate surface.
    #[test]
    fn test_bump_level_join_agrees_with_max_at_every_pair() {
        for a in BumpLevel::ALL {
            for b in BumpLevel::ALL {
                assert_eq!(
                    a.join(b),
                    a.max(b),
                    "join({a:?}, {b:?}) must equal max({a:?}, {b:?})",
                );
            }
        }
    }

    /// Idempotence invariant: `a.join(a) == a` at every variant. The
    /// load-bearing structural fact a release-pipeline fold over
    /// duplicate per-commit bump levels relies on (a release that contains
    /// two patch commits is still a patch release). Sibling of the
    /// reflexive-ordering pin
    /// `test_bump_level_ordering_reflexive_at_every_variant` at the
    /// derived-Ord surface, here at the lattice-join surface.
    #[test]
    fn test_bump_level_join_is_idempotent_at_every_variant() {
        for level in BumpLevel::ALL {
            assert_eq!(
                level.join(level),
                level,
                "join must be idempotent at {level:?}",
            );
        }
    }

    /// Commutativity invariant: `a.join(b) == b.join(a)` at every pair
    /// over the 3×3 grid. The load-bearing structural fact a release-
    /// pipeline fold relies on to be insensitive to per-commit ORDER —
    /// the release bump for [fix, feat] equals the release bump for
    /// [feat, fix]. A future hand-rolled match cascade that drifted from
    /// the symmetric `max` form across a fourth-variant addition would
    /// light up here as a per-(a,b) asymmetry.
    #[test]
    fn test_bump_level_join_is_commutative_at_every_pair() {
        for a in BumpLevel::ALL {
            for b in BumpLevel::ALL {
                assert_eq!(
                    a.join(b),
                    b.join(a),
                    "join must be commutative: join({a:?}, {b:?}) vs join({b:?}, {a:?})",
                );
            }
        }
    }

    /// Associativity invariant: `a.join(b.join(c)) == a.join(b).join(c)`
    /// at every triple over the 3×3×3 grid. The load-bearing structural
    /// anchor a release-pipeline fold relies on to be insensitive to
    /// per-commit GROUPING — the release bump for a fold over a
    /// per-commit sequence is well-defined regardless of how the sequence
    /// is partitioned into sub-folds.
    #[test]
    fn test_bump_level_join_is_associative_at_every_triple() {
        for a in BumpLevel::ALL {
            for b in BumpLevel::ALL {
                for c in BumpLevel::ALL {
                    assert_eq!(
                        a.join(b.join(c)),
                        a.join(b).join(c),
                        "join must be associative at ({a:?}, {b:?}, {c:?})",
                    );
                }
            }
        }
    }

    /// Identity-element invariant: `Patch` is the join identity at every
    /// variant — `Patch.join(a) == a.join(Patch) == a`. The load-bearing
    /// structural fact a release-pipeline fold seeds with: a fold seeded
    /// at `BumpLevel::Patch` over a sequence of per-commit bump levels
    /// returns the max of the sequence (or `Patch` if the sequence is
    /// empty — the no-op release shape).
    #[test]
    fn test_bump_level_join_has_patch_as_identity() {
        for level in BumpLevel::ALL {
            assert_eq!(
                BumpLevel::Patch.join(level),
                level,
                "Patch must be left-identity for join at {level:?}",
            );
            assert_eq!(
                level.join(BumpLevel::Patch),
                level,
                "Patch must be right-identity for join at {level:?}",
            );
        }
    }

    /// Absorbing-element invariant: `Major` is the join absorber at every
    /// variant — `Major.join(a) == a.join(Major) == Major`. The load-
    /// bearing structural fact a release-pipeline fold can early-exit on:
    /// once any per-commit bump reads `Major`, the release bump collapses
    /// to `Major` regardless of the remaining commits. A SLSA-style
    /// breaking-change-takes-priority discipline reads this invariant
    /// once at the typed-primitive surface rather than re-deriving it at
    /// every aggregation site.
    #[test]
    fn test_bump_level_join_has_major_as_absorbing_element() {
        for level in BumpLevel::ALL {
            assert_eq!(
                BumpLevel::Major.join(level),
                BumpLevel::Major,
                "Major must be left-absorbing for join at {level:?}",
            );
            assert_eq!(
                level.join(BumpLevel::Major),
                BumpLevel::Major,
                "Major must be right-absorbing for join at {level:?}",
            );
        }
    }

    /// Lower-bound invariant: `a.join(b) >= a && a.join(b) >= b` at every
    /// pair over the 3×3 grid. The load-bearing structural anchor a
    /// downstream provenance gate consumes ("the release bump subsumes
    /// every per-commit bump") through one named site, derived directly
    /// from the lattice-join surface rather than re-derived at every
    /// inline `.max()` call. A regression in the method body that
    /// returned a value below either argument lights up here as a
    /// bound-violation.
    #[test]
    fn test_bump_level_join_bounded_below_by_both_arguments() {
        for a in BumpLevel::ALL {
            for b in BumpLevel::ALL {
                let j = a.join(b);
                assert!(j >= a, "join({a:?}, {b:?}) = {j:?} must be >= {a:?}",);
                assert!(j >= b, "join({a:?}, {b:?}) = {j:?} must be >= {b:?}",);
            }
        }
    }

    /// Total-order witness: `a.join(b) ∈ {a, b}` at every pair over the
    /// 3×3 grid. The structural witness that the lattice join over a
    /// total order is the identity-or-other readback — distinct from a
    /// free-lattice join that could return a third element. A future
    /// ladder refinement that introduced a meet-irreducible variant where
    /// `a.join(b)` returned a strict upper bound of both arguments would
    /// light up here as a witness-set escape, surfacing the structural
    /// distinction at the lattice-join site rather than at every consumer.
    #[test]
    fn test_bump_level_join_returns_one_of_the_arguments() {
        for a in BumpLevel::ALL {
            for b in BumpLevel::ALL {
                let j = a.join(b);
                assert!(
                    j == a || j == b,
                    "join({a:?}, {b:?}) = {j:?} must be in {{ {a:?}, {b:?} }}",
                );
            }
        }
    }

    /// Exact-shape per-(a, b) pin over the 3×3 grid for [`BumpLevel::meet`]
    /// — the structural mirror of
    /// [`test_bump_level_join_named_at_release_aggregation_surface`] at
    /// the dual lattice-meet surface, naming the per-commit-floor reading
    /// at the typed-primitive site. Floor-sibling of the per-variant
    /// witness pins at the half-open-ray gate surface, the surface-witness
    /// pin a regression in the method body surfaces against.
    #[test]
    fn test_bump_level_meet_named_at_per_commit_floor_surface() {
        use BumpLevel::*;
        let cases = [
            (Patch, Patch, Patch),
            (Patch, Minor, Patch),
            (Patch, Major, Patch),
            (Minor, Patch, Patch),
            (Minor, Minor, Minor),
            (Minor, Major, Minor),
            (Major, Patch, Patch),
            (Major, Minor, Minor),
            (Major, Major, Major),
        ];
        for (a, b, expected) in cases {
            assert_eq!(
                a.meet(b),
                expected,
                "meet({a:?}, {b:?}) must return {expected:?}",
            );
        }
    }

    /// Structural-equivalence pin: `meet` agrees with [`Ord::min`] at
    /// every pair over the 3×3 grid. The pin that makes the `min` form
    /// (not a hand-rolled match cascade) the load-bearing oracle, so a
    /// future variant insertion that desynced the method body from the
    /// derived [`Ord`] ladder would light up here rather than drifting
    /// silently through the lattice-meet surface. Dual of
    /// [`test_bump_level_join_agrees_with_max_at_every_pair`] at the
    /// lattice-join surface.
    #[test]
    fn test_bump_level_meet_agrees_with_min_at_every_pair() {
        for a in BumpLevel::ALL {
            for b in BumpLevel::ALL {
                assert_eq!(
                    a.meet(b),
                    a.min(b),
                    "meet({a:?}, {b:?}) must equal min({a:?}, {b:?})",
                );
            }
        }
    }

    /// Idempotence invariant: `a.meet(a) == a` at every variant. The
    /// load-bearing structural fact a per-commit-floor fold over
    /// duplicate per-commit bump levels relies on (the floor of a
    /// sequence of patch commits is still a patch floor). Dual of
    /// [`test_bump_level_join_is_idempotent_at_every_variant`] at the
    /// lattice-join surface.
    #[test]
    fn test_bump_level_meet_is_idempotent_at_every_variant() {
        for level in BumpLevel::ALL {
            assert_eq!(
                level.meet(level),
                level,
                "meet must be idempotent at {level:?}",
            );
        }
    }

    /// Commutativity invariant: `a.meet(b) == b.meet(a)` at every pair
    /// over the 3×3 grid. The load-bearing structural fact a per-commit-
    /// floor fold relies on to be insensitive to per-commit ORDER —
    /// the per-commit-floor for [fix, feat] equals the per-commit-floor
    /// for [feat, fix]. Dual of
    /// [`test_bump_level_join_is_commutative_at_every_pair`] at the
    /// lattice-join surface.
    #[test]
    fn test_bump_level_meet_is_commutative_at_every_pair() {
        for a in BumpLevel::ALL {
            for b in BumpLevel::ALL {
                assert_eq!(
                    a.meet(b),
                    b.meet(a),
                    "meet must be commutative: meet({a:?}, {b:?}) vs meet({b:?}, {a:?})",
                );
            }
        }
    }

    /// Associativity invariant: `a.meet(b.meet(c)) == a.meet(b).meet(c)`
    /// at every triple over the 3×3×3 grid. The load-bearing structural
    /// anchor a per-commit-floor fold relies on to be insensitive to
    /// per-commit GROUPING. Dual of
    /// [`test_bump_level_join_is_associative_at_every_triple`] at the
    /// lattice-join surface.
    #[test]
    fn test_bump_level_meet_is_associative_at_every_triple() {
        for a in BumpLevel::ALL {
            for b in BumpLevel::ALL {
                for c in BumpLevel::ALL {
                    assert_eq!(
                        a.meet(b.meet(c)),
                        a.meet(b).meet(c),
                        "meet must be associative at ({a:?}, {b:?}, {c:?})",
                    );
                }
            }
        }
    }

    /// Identity-element invariant: `Major` is the meet identity at every
    /// variant — `Major.meet(a) == a.meet(Major) == a`. The load-bearing
    /// structural fact a per-commit-floor fold seeds with: a fold seeded
    /// at `BumpLevel::Major` over a sequence of per-commit bump levels
    /// returns the min of the sequence (or `Major` if the sequence is
    /// empty — the no-commits floor shape, dual to the empty-release
    /// `Patch` shape at the join surface).
    #[test]
    fn test_bump_level_meet_has_major_as_identity() {
        for level in BumpLevel::ALL {
            assert_eq!(
                BumpLevel::Major.meet(level),
                level,
                "Major must be left-identity for meet at {level:?}",
            );
            assert_eq!(
                level.meet(BumpLevel::Major),
                level,
                "Major must be right-identity for meet at {level:?}",
            );
        }
    }

    /// Absorbing-element invariant: `Patch` is the meet absorber at every
    /// variant — `Patch.meet(a) == a.meet(Patch) == Patch`. The load-
    /// bearing structural fact a per-commit-floor fold can early-exit on:
    /// once any per-commit bump reads `Patch`, the per-commit-floor
    /// collapses to `Patch` regardless of the remaining commits. The dual
    /// at the meet surface of the `Major`-absorbing fact at the join
    /// surface.
    #[test]
    fn test_bump_level_meet_has_patch_as_absorbing_element() {
        for level in BumpLevel::ALL {
            assert_eq!(
                BumpLevel::Patch.meet(level),
                BumpLevel::Patch,
                "Patch must be left-absorbing for meet at {level:?}",
            );
            assert_eq!(
                level.meet(BumpLevel::Patch),
                BumpLevel::Patch,
                "Patch must be right-absorbing for meet at {level:?}",
            );
        }
    }

    /// Upper-bound invariant: `a.meet(b) <= a && a.meet(b) <= b` at every
    /// pair over the 3×3 grid. The load-bearing structural anchor a
    /// downstream per-commit-floor reader consumes ("the per-commit floor
    /// is at or below every contributing commit") through one named site,
    /// derived directly from the lattice-meet surface rather than re-
    /// derived at every inline `.min()` call. A regression in the method
    /// body that returned a value above either argument lights up here as
    /// a bound-violation. Dual of
    /// [`test_bump_level_join_bounded_below_by_both_arguments`].
    #[test]
    fn test_bump_level_meet_bounded_above_by_both_arguments() {
        for a in BumpLevel::ALL {
            for b in BumpLevel::ALL {
                let m = a.meet(b);
                assert!(m <= a, "meet({a:?}, {b:?}) = {m:?} must be <= {a:?}",);
                assert!(m <= b, "meet({a:?}, {b:?}) = {m:?} must be <= {b:?}",);
            }
        }
    }

    /// Total-order witness: `a.meet(b) ∈ {a, b}` at every pair over the
    /// 3×3 grid. The structural witness that the lattice meet over a
    /// total order is the identity-or-other readback — distinct from a
    /// free-lattice meet that could return a third element. Dual of
    /// [`test_bump_level_join_returns_one_of_the_arguments`] at the
    /// lattice-meet surface.
    #[test]
    fn test_bump_level_meet_returns_one_of_the_arguments() {
        for a in BumpLevel::ALL {
            for b in BumpLevel::ALL {
                let m = a.meet(b);
                assert!(
                    m == a || m == b,
                    "meet({a:?}, {b:?}) = {m:?} must be in {{ {a:?}, {b:?} }}",
                );
            }
        }
    }

    /// Cross-surface order pin: `a.meet(b) <= a.join(b)` at every pair
    /// over the 3×3 grid. The structural witness that the meet-join
    /// interval brackets the magnitude range of the input pair — the
    /// per-pair mirror of
    /// `test_per_axis_admission_tier_floor_le_ceiling_across_cross_product`
    /// at the per-axis admission-tier surface, here at the [`BumpLevel`]
    /// magnitude ladder. Equality holds when the inputs coincide
    /// (`a.meet(a) == a == a.join(a)`); strict inequality holds at every
    /// asymmetric pair (the meet and join return the two distinct
    /// arguments respectively).
    #[test]
    fn test_bump_level_meet_le_join_at_every_pair() {
        for a in BumpLevel::ALL {
            for b in BumpLevel::ALL {
                let m = a.meet(b);
                let j = a.join(b);
                assert!(
                    m <= j,
                    "meet({a:?}, {b:?}) = {m:?} must be <= join({a:?}, {b:?}) = {j:?}",
                );
            }
        }
    }

    /// Absorption laws: `a.join(a.meet(b)) == a` and `a.meet(a.join(b))
    /// == a` at every pair over the 3×3 grid. The structural anchor that
    /// the meet/join pair forms a LATTICE in the algebraic sense — two
    /// reductions over the same [`Ord`] ladder, related by the absorption
    /// laws so that "join with one's own meet collapses" and "meet with
    /// one's own join collapses." A future ladder refinement that broke
    /// the absorption laws (e.g., a meet-irreducible variant inserted
    /// where `a.meet(b)` returned a strict lower bound of both arguments)
    /// would light up here, surfacing the structural distinction at the
    /// lattice-pair site rather than at every consumer. The load-bearing
    /// fact a downstream lattice-walk relies on to round-trip through the
    /// meet/join pair without unbounded drift.
    #[test]
    fn test_bump_level_meet_join_absorption_at_every_pair() {
        for a in BumpLevel::ALL {
            for b in BumpLevel::ALL {
                assert_eq!(
                    a.join(a.meet(b)),
                    a,
                    "join-meet absorption must hold: join({a:?}, meet({a:?}, {b:?})) must equal {a:?}",
                );
                assert_eq!(
                    a.meet(a.join(b)),
                    a,
                    "meet-join absorption must hold: meet({a:?}, join({a:?}, {b:?})) must equal {a:?}",
                );
            }
        }
    }

    /// Meet distributes over join:
    /// `a.meet(b.join(c)) == a.meet(b).join(a.meet(c))` at every
    /// `(a, b, c)` over the 3×3×3 grid (27 triples). The structural
    /// anchor that the meet/join pair forms a DISTRIBUTIVE lattice in
    /// the algebraic sense — every chain (totally-ordered lattice) is
    /// distributive, and the [`BumpLevel`] ladder (`Patch < Minor <
    /// Major`) inherits the distributive property from its derived
    /// [`Ord`] chain. The next algebraic-law pin beyond absorption
    /// ([`test_bump_level_meet_join_absorption_at_every_pair`]):
    /// absorption + distributivity together carry the full "distributive
    /// lattice" axioms a downstream lattice-walk relies on when reducing
    /// a meet/join expression to a normal form without retyping the
    /// distributive identity at every reduction site. A future ladder
    /// refinement that broke distributivity (e.g., inserting two
    /// incomparable variants in the same band — turning the chain into
    /// a non-distributive lattice like the diamond `M3` or the pentagon
    /// `N5`) would light up here, surfacing the structural distinction
    /// at the lattice-pair site rather than at every downstream consumer
    /// that silently relied on the distributive identity. THEORY.md
    /// §V.5: distributivity is the load-bearing axiom that distinguishes
    /// a chain-derived lattice from a general bounded lattice, and the
    /// structural witness the meet/join pair carries beyond mere absorption.
    #[test]
    fn test_bump_level_meet_distributes_over_join_at_every_triple() {
        for a in BumpLevel::ALL {
            for b in BumpLevel::ALL {
                for c in BumpLevel::ALL {
                    let lhs = a.meet(b.join(c));
                    let rhs = a.meet(b).join(a.meet(c));
                    assert_eq!(
                        lhs, rhs,
                        "meet distributes over join must hold: \
                         meet({a:?}, join({b:?}, {c:?})) = {lhs:?} \
                         must equal join(meet({a:?}, {b:?}), meet({a:?}, {c:?})) = {rhs:?}",
                    );
                }
            }
        }
    }

    /// Join distributes over meet:
    /// `a.join(b.meet(c)) == a.join(b).meet(a.join(c))` at every
    /// `(a, b, c)` over the 3×3×3 grid (27 triples). The lattice-dual
    /// of [`test_bump_level_meet_distributes_over_join_at_every_triple`]
    /// at the same magnitude ladder — in a distributive lattice the two
    /// distributive identities are equivalent, and pinning both closes
    /// the structural witness against a refactor that broke one but not
    /// the other (the structurally-asymmetric refactor a single-identity
    /// pin would miss). Together with the absorption-law pin
    /// ([`test_bump_level_meet_join_absorption_at_every_pair`]) and the
    /// lattice-bracket pin ([`test_bump_level_meet_le_join_at_every_pair`]),
    /// this closes the distributive-lattice axiom surface on the
    /// [`BumpLevel`] ladder at the typed-primitive site.
    #[test]
    fn test_bump_level_join_distributes_over_meet_at_every_triple() {
        for a in BumpLevel::ALL {
            for b in BumpLevel::ALL {
                for c in BumpLevel::ALL {
                    let lhs = a.join(b.meet(c));
                    let rhs = a.join(b).meet(a.join(c));
                    assert_eq!(
                        lhs, rhs,
                        "join distributes over meet must hold: \
                         join({a:?}, meet({b:?}, {c:?})) = {lhs:?} \
                         must equal meet(join({a:?}, {b:?}), join({a:?}, {c:?})) = {rhs:?}",
                    );
                }
            }
        }
    }
}
